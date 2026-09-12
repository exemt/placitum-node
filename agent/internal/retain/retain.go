/*
 * Архивация: обменник → архив, с подменой локаторов в записи аудита.
 *
 * Модуль не удаляет из обменника те объекты, которые маршрут велел сохранить, и
 * называет их в store.archive. Владение ключом с этого момента у агента: он
 * забирает объект, кладёт в архив, подменяет в записи адресацию на архивную,
 * публикует — и только потом чистит обменник.
 *
 * Порядок двух последних шагов принципиален. Падение между ними оставляет
 * верную запись и осиротевший ключ, который доберёт retain_ttl. В обратном
 * порядке теряется запись, а объект остаётся в архиве без единой ссылки на
 * себя — то есть навсегда и невидимо.
 *
 * PUT копятся в трёх корзинах — по виду объекта. Секции не ждут друг друга:
 * заголовки могут уехать, пока тело ещё набирает размер или таймаут. Запись
 * аудита публикуется, когда закрыта последняя её секция: раньше локаторы
 * врали бы.
 *
 * Работа уходит в ограниченную очередь, потому что handoff.Serve вызывает
 * обработчик синхронно в цикле чтения датаграмм, а у unixgram нет обратного
 * давления: задержка здесь — это переполненный буфер сокета и потерянные
 * записи там. Очередь полна — запись публикуется немедленно, с локаторами
 * overload, а ключи обменника уходят чистильщику: объект уже объявлен
 * недоступным, и ждать на нём retain_ttl некому. Теряется полезная нагрузка,
 * не событие.
 */

package retain

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/exemt/placitum-node/agent/internal/audit"
	"github.com/exemt/placitum-node/agent/internal/flow"
)

// Причины недоступности, которые проставляет агент. Остальные значения
// (oversize, store_error и прочие) ставит модуль, и агент их не трогает.
//
// Переполнение очереди отделено от отказа архива намеренно: первое лечится
// темпом и размером очереди, второе — хранилищем, и в записи это должно
// различаться, иначе по логу их не отличить.
const (
	reasonExpired  = "expired"       // ключа в обменнике уже нет
	reasonEmpty    = "empty"         // объект требовался и оказался пуст
	reasonOverload = "overload"      // очередь архивации переполнена
	reasonError    = "archive_error" // не удалось положить в архив
)

// Publisher — отправка записи на шину. Отдельным типом, чтобы пакет не знал
// ни про NATS, ни про то, что публикация вообще куда-то идёт.
type Publisher func(audit.Decision) error

type Pool struct {
	cfg     Config
	s3      *s3Client
	log     *slog.Logger
	publish Publisher
	io      *flow.Counter

	jobs chan audit.Decision
	wg   sync.WaitGroup

	baskets map[string]*basket

	// sweep — ключи записей, которые ушли деградированными. Отдельный канал,
	// а не очередь работы: Handle зовут из цикла чтения датаграмм, и DEL там
	// стоил бы ровно того, ради чего очередь и ограничена.
	sweep   chan []moved
	sweepWG sync.WaitGroup

	once sync.Once
}

// New поднимает пул. Пул нужен и тогда, когда архивация у агента не настроена:
// модуль всё равно может прислать store.archive, и кто-то должен честно
// сказать в записи, что объекта не будет.
func New(cfg Config, publish Publisher, log *slog.Logger) *Pool {
	return NewShared(cfg, publish, log, flow.New())
}

// NewShared — тот же пул со счётчиком темпа, взятым снаружи. Нужен смене
// настройки на лету (Switch): свой счётчик у нового пула означал бы, что
// канал `archive` в пульсе обнуляется на каждой раскатке, и провал в графике
// читался бы как остановка выгрузки, а не как её перенастройка.
func NewShared(
	cfg Config,
	publish Publisher,
	log *slog.Logger,
	io *flow.Counter,
) *Pool {
	cfg.normalize()

	if log == nil {
		log = slog.Default()
	}
	if io == nil {
		io = flow.New()
	}

	p := &Pool{
		cfg:     cfg,
		log:     log,
		publish: publish,
		io:      io,
		jobs:    make(chan audit.Decision, cfg.Queue),
		sweep:   make(chan []moved, cfg.Queue),
	}

	// Чистильщик один: DEL — это round-trip по локальной сети, и одного
	// соединения хватает на порядок больший темп, чем тот, на котором
	// переполняется очередь переноса.
	p.sweepWG.Add(1)
	go p.clean()

	if cfg.enabled() {
		p.s3 = &s3Client{
			endpoint: strings.TrimRight(cfg.S3.Endpoint, "/"),
			region:   cfg.S3.Region,
			access:   cfg.S3.Access,
			secret:   cfg.S3.Secret,
			http: &http.Client{
				Timeout: cfg.OpTimeout,
				Transport: &http.Transport{
					MaxIdleConnsPerHost: cfg.Workers,
					IdleConnTimeout:     90 * time.Second,
				},
			},
		}

		p.baskets = make(map[string]*basket, len(audit.Kinds))
		for _, kind := range audit.Kinds {
			p.baskets[kind] = newBasket(p, kind, cfg.Batch[kind])
		}

		for i := 0; i < cfg.Workers; i++ {
			p.wg.Add(1)
			go p.work()
		}
	}

	return p
}

// IO — темп канала `archive`: PUT объекта в S3, независимо от того, включена
// архивация или нет. Выключенная — это темп, который навсегда остаётся нулём,
// а не отсутствующий канал: producer решает форму кадра один раз, а не по
// текущей конфигурации.
func (p *Pool) IO() flow.Flow {
	return p.io.Snapshot()
}

// Handle — единственный вход. Быстрый путь (архивировать нечего) стоит ровно
// столько же, сколько стоил до появления архива: проверка длины карты.
func (p *Pool) Handle(d audit.Decision) {
	if len(d.Archive) == 0 {
		p.emit(d)
		return
	}

	if p.s3 == nil {
		p.degrade(d, reasonError, "archive is not configured")
		return
	}

	select {
	case p.jobs <- d:
	default:
		p.degrade(d, reasonOverload, "archive queue is full")
	}
}

// Close останавливает воркеров, дав им дописать очередь: в ней записи, которые
// иначе не будут опубликованы вовсе.
func (p *Pool) Close() {
	p.once.Do(func() {
		close(p.jobs)
		p.wg.Wait()
		for _, kind := range audit.Kinds {
			if b := p.baskets[kind]; b != nil {
				b.closeAndFlush()
			}
		}
		close(p.sweep)
		p.sweepWG.Wait()
	})
}

func (p *Pool) work() {
	defer p.wg.Done()

	for d := range p.jobs {
		p.enqueue(d)
	}
}

func (p *Pool) clean() {
	defer p.sweepWG.Done()

	store := newRedisPool(p.cfg.redisAuth())
	defer store.close()

	for batch := range p.sweep {
		for _, item := range batch {
			if err := store.del(item.addr, item.key); err != nil {
				p.log.Warn("archive: store cleanup failed",
					"key", item.key, "error", err.Error())
			}
		}
	}
}


// moved — след успешного переноса: чем объект стал в архиве, до какого момента
// он там жив, урезан ли он и что после него осталось прибрать в обменнике.
type moved struct {
	object  string
	expires int64
	key     string
	addr    string
	size    int
	trimmed bool
}

// move переносит один объект. Пустая причина — успех; иначе локатор в записи
// станет недоступным с этой причиной.
func (p *Pool) move(store *redisPool, d audit.Decision, section audit.Store,
	kind string, terms audit.Terms) (string, moved) {

	bucket := p.cfg.Bucket[kind]
	if bucket == "" {
		p.log.Warn("archive: no bucket for kind", "ray", d.Ray, "kind", kind)
		return reasonError, moved{}
	}

	loc, ok := section.Locate(kind)
	if !ok {
		p.log.Warn("archive: locator has no address", "ray", d.Ray, "kind", kind)
		return reasonError, moved{}
	}

	addr := p.cfg.node(loc.Hint)

	data, err := store.get(addr, loc.Key)
	if errors.Is(err, ErrMissing) {
		return reasonExpired, moved{}
	}
	if err != nil {
		p.log.Warn("archive: store read failed",
			"ray", d.Ray, "kind", kind, "node", addr, "error", err.Error())
		return reasonError, moved{}
	}

	// Пустой объект в архив не едет: пустышка в бакете стоит запроса на
	// листинге и ничего не отвечает тому, кто за ней придёт. Но объект
	// требовался, и запись обязана сказать, чем кончилось, — отсюда причина, а
	// не молчаливый пропуск.
	if len(data) == 0 {
		return reasonEmpty, moved{}
	}

	filtered, err := applyTerms(kind, data, terms)
	if err != nil {
		p.log.Warn("archive: list filter failed",
			"ray", d.Ray, "kind", kind, "error", err.Error())
		return reasonError, moved{}
	}
	data = filtered

	if len(data) == 0 {
		return reasonEmpty, moved{}
	}

	// Предел режется здесь, а не в модуле: в обменнике объект лежит целиком,
	// потому что его мог попросить инспектор.
	trimmed := false
	if terms.Limit > 0 && int64(len(data)) > terms.Limit {
		data = data[:terms.Limit]
		trimmed = true
	}

	object := objectName(d, kind)

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.OpTimeout)
	defer cancel()

	expires, err := p.s3.put(ctx, bucket, object, data, retainTag(terms.TTL))
	if err != nil {
		p.log.Warn("archive: put failed",
			"ray", d.Ray, "kind", kind, "bucket", bucket, "object", object,
			"error", err.Error())
		// Размер остаётся: read из Redis состоялся, канал должен видеть его
		// байты, даже если запись в S3 не удалась.
		return reasonError, moved{size: len(data)}
	}

	p.log.Info("archive: put ok",
		"ray", d.Ray, "kind", kind, "bucket", bucket, "object", object,
		"size", len(data), "trimmed", trimmed, "expires_at", expires)

	return "", moved{
		object:  object,
		expires: expires,
		key:     loc.Key,
		addr:    addr,
		size:    len(data),
		trimmed: trimmed,
	}
}

// degrade публикует запись, не пытаясь ничего перенести: адресация обменника из
// локаторов уходит всё равно. Оставить её значило бы обещать читателю объект,
// за которым уже никто не придёт и который вот-вот срежет TTL.
//
// Раз никто не придёт, ключ и держать незачем: он уходит чистильщику, а не
// доживает retain_ttl. Под нагрузкой это разница между обменником на несколько
// секунд трафика и обменником на пять минут -- переполнение очереди случается
// именно там, где темп высок.
func (p *Pool) degrade(d audit.Decision, reason, why string) {
	p.log.Warn("archive: skipped", "ray", d.Ray, "reason", why)

	section, err := audit.ParseStore(d.Raw)
	if err != nil {
		p.emit(d)
		return
	}

	var orphans []moved

	for _, kind := range audit.Kinds {
		if _, ok := d.Archive[kind]; !ok {
			continue
		}

		raw, ok := section.Locators[kind]
		if !ok {
			continue
		}

		// Адрес читается до mark: он же его из локатора и вычищает.
		if loc, ok := section.Locate(kind); ok {
			orphans = append(orphans, moved{
				key:  loc.Key,
				addr: p.cfg.node(loc.Hint),
			})
		}

		section.Locators[kind] = p.mark(raw, reason, d.Ray)
	}

	if value, err := section.Render(); err == nil {
		if raw, err := audit.SpliceStore(d.Raw, value); err == nil {
			d.Raw = raw
		}
	}

	p.emit(d)

	if len(orphans) == 0 {
		return
	}

	select {
	case p.sweep <- orphans:
	default:
		// Чистильщик не успевает -- ключи доберёт retain_ttl. Ждать здесь
		// нельзя по той же причине, по которой ограничена очередь переноса.
		p.log.Warn("archive: cleanup queue is full", "ray", d.Ray)
	}
}

func (p *Pool) emit(d audit.Decision) {
	if p.publish == nil {
		return
	}

	if err := p.publish(d); err != nil {
		p.log.Warn("audit publish failed", "ray", d.Ray, "error", err.Error())
	}
}

func (p *Pool) mark(raw json.RawMessage, reason, ray string) json.RawMessage {
	out, err := audit.Unreachable(raw, reason)
	if err != nil {
		p.log.Warn("archive: locator is unreadable",
			"ray", ray, "error", err.Error())
		return raw
	}

	return out
}

func (p *Pool) readdress(raw json.RawMessage, done moved, ray string) json.RawMessage {
	out, err := audit.Readdress(raw, "archive", "s3", done.object, done.expires)
	if err != nil {
		p.log.Warn("archive: locator is unreadable",
			"ray", ray, "error", err.Error())
		return raw
	}

	if !done.trimmed {
		return out
	}

	marked, err := audit.Trimmed(out, done.size)
	if err != nil {
		p.log.Warn("archive: locator is unreadable",
			"ray", ray, "error", err.Error())
		return out
	}

	return marked
}

// objectName — <yyyy>/<mm>/<dd>/<node>/<ray>[.<фаза>[.<сторона>.<номер>]].<hdr|arg|body>.
//
// Фаза в имени у всех фаз, кроме запроса: у запроса и ответа общий ray, и без
// неё тело ответа легло бы поверх тела запроса. Запрос остаётся без сегмента --
// так названы все объекты, положенные до фазы ответа. У кадра под тем же ray
// лежит всё соединение, и его объект различается ещё стороной и номером
// кадра -- тем же адресом, каким запись кадра ищется в журнале.
//
// Дата первым сегментом и дата события, а не момента переноса: иначе запросы
// последней минуты суток оказались бы в завтрашней папке, а перебор объектов
// за инцидент — двумя листингами вместо одного.
//
// Срока в имени нет. Он был там, пока архив различал классы хранения и правила
// бакета фильтровали по префиксу; теперь срок едет тегом, а тег — это то, по
// чему lifecycle-правило фильтрует, не разрезая пространство имён.
func objectName(d audit.Decision, kind string) string {
	ts, err := time.Parse(time.RFC3339, d.TS)
	if err != nil {
		ts = time.Now()
	}

	ts = ts.UTC()

	node := d.Node
	if node == "" {
		node = "unknown"
	}

	name := d.Ray
	if d.Phase != "" && d.Phase != "request" {
		name += "." + d.Phase
	}
	if d.Phase == "frame" && d.FrameDirection != "" {
		name += "." + d.FrameDirection + "." + strconv.FormatUint(d.FrameSeq, 10)
	}

	return ts.Format("2006/01/02") + "/" + node + "/" +
		name + "." + audit.Suffix[kind]
}

// retainTag — тег объекта, по которому бакет применяет lifecycle-правило.
// Секунды, как их назвал маршрут. Ноль -- хранить вечно, и тега тогда нет
// вовсе: правило не должно совпасть ни с чем, а "waf-retain-ttl=0" совпало бы
// с правилом, написанным неаккуратно.
func retainTag(ttl int64) string {
	if ttl <= 0 {
		return ""
	}

	return "waf-retain-ttl=" + strconv.FormatInt(ttl, 10)
}
