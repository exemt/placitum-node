/*
 * Провод активных наборов с keeper (docs/keeper.md).
 *
 * Единственное место модуля, которое знает subject-ы keeper и ключи объектов
 * в Redis. По подписке на subject набора приходят уведомления о пакетах и
 * тики -- сотня байт без состава; состав лежит во внутреннем Redis
 * (waf_sets_store) двоичными объектами: пакет изменений waf:diff:<набор>:<seq>
 * и снапшот по ссылке из ответа keeper на .snapshot. Применение объекта -- в
 * ngx_http_waf_dataset.c, здесь только конвейер:
 *
 *   IDLE      -> нет основания; ждём подключения или повтора
 *   SNAPSHOT  -> спросили ссылку на объект, ждём ответ keeper
 *   FETCH     -> читаем объект (снапшот либо пакет) из Redis
 *   READY     -> состав есть; уведомление с seq дальше своего -> пакеты
 *                свой+1.. по очереди, тик со своим seq -> сверка хеша
 *
 * Кто читает: снапшот -- один воркер на ноду по заявке в зоне
 * (ngx_http_waf_dataset_snapshot_claim), остальные видят результат в shm.
 * Пакеты читает каждый воркер, увидевший разрыв: они малы, а применение
 * идемпотентно по seq -- второй воркер с тем же пакетом получает «уже
 * применено» и идёт дальше. Пакета в Redis уже нет (срок вышел) -- снапшот.
 * Молчание keeper дольше трёх тиков -- WARN один раз на ноду, состав
 * продолжает отвечать.
 */

#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "body/ngx_http_waf_body.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_DS_ST_IDLE       0
#define NGX_HTTP_WAF_DS_ST_SNAPSHOT   1
#define NGX_HTTP_WAF_DS_ST_FETCH      2
#define NGX_HTTP_WAF_DS_ST_READY      3

#define NGX_HTTP_WAF_DS_FETCH_SNAPSHOT  1
#define NGX_HTTP_WAF_DS_FETCH_PACKAGE   2

/* Пауза перед повтором шага, который не удался или не получил ответа. */
#define NGX_HTTP_WAF_DS_RETRY         5000

/* Тик keeper раз в 2 с; три тика тишины -- keeper молчит. */
#define NGX_HTTP_WAF_DS_SILENCE       6000

/* Не чаще одного сеанса снапшота в этот период на набор (заявка в зоне). */
#define NGX_HTTP_WAF_DS_SNAPSHOT_WAIT 10000

/*
 * Потолки объектов из Redis. Снапшот -- 27 байт на запись IPv6 плюс
 * заголовок; у строк запись длиннее, но их в наборе на порядки меньше.
 * Пакет -- десятки записей, потолок с большим запасом.
 */
#define NGX_HTTP_WAF_DS_OBJECT_MAX    (512 * 1024 * 1024)
#define NGX_HTTP_WAF_DS_PACKAGE_MAX   (64 * 1024 * 1024)

#define NGX_HTTP_WAF_DS_KEY_MAX       256


typedef struct {
    ngx_http_waf_dataset_t    *ds;

    ngx_uint_t                 state;

    /* текущая выборка: пул живёт от запроса до ответа драйвера */
    ngx_pool_t                *pool;
    ngx_http_waf_body_op_t    *op;
    ngx_uint_t                 kind;
    uint64_t                   fetching;   /* seq пакета в полёте          */

    /* до какого seq догонять: максимум из увиденных уведомлений */
    uint64_t                   want;
    uint64_t                   want_hash;
    ngx_uint_t                 want_has_hash;

    ngx_event_t                timer;      /* повтор шага и надзор за тишиной */
} ngx_http_waf_ds_stream_t;


static void      ngx_http_waf_ds_stream_kick(ngx_http_waf_ds_stream_t *st);
static void      ngx_http_waf_ds_stream_reset(ngx_http_waf_ds_stream_t *st);
static ngx_int_t ngx_http_waf_ds_stream_snapshot(ngx_http_waf_ds_stream_t *st,
                     ngx_uint_t claim);
static ngx_int_t ngx_http_waf_ds_stream_request(ngx_http_waf_ds_stream_t *st,
                     const char *tail, ngx_str_t *body);
static ngx_int_t ngx_http_waf_ds_stream_fetch(ngx_http_waf_ds_stream_t *st,
                     ngx_str_t *key, ngx_uint_t kind, uint64_t seq);
static void      ngx_http_waf_ds_stream_fetched(ngx_http_waf_body_op_t *op);
static void      ngx_http_waf_ds_stream_catch_up(ngx_http_waf_ds_stream_t *st);
static void      ngx_http_waf_ds_stream_timer(ngx_event_t *ev);
static void      ngx_http_waf_ds_stream_watch(ngx_http_waf_ds_stream_t *st);
static void      ngx_http_waf_ds_stream_settle(ngx_http_waf_ds_stream_t *st);


static ngx_http_waf_ds_stream_t  *ngx_http_waf_ds_streams;
static ngx_uint_t                 ngx_http_waf_ds_nstreams;

/*
 * У набора два номера. Позиция в конфиге -- массив потоков и всё, что берёт
 * набор из wmcf->datasets (apply, state, seen, notice). Слот в зоне
 * (ds->index) -- сама память и заявка на снапшот. Слоты переживают reload и
 * раздаются по мере появления имён, поэтому после нового набора номера
 * расходятся: набор, вставший в середину конфига, получает слот в конце. На
 * провод выходит позиция: ею подписан sid набора и ею подписан ответ на
 * запрос воркера, по ней приём находит поток. Слот -- только там, где
 * адресуется зона.
 */
#define ngx_http_waf_ds_stream_pos(st)                                       \
    ((ngx_uint_t) ((st) - ngx_http_waf_ds_streams))


ngx_int_t
ngx_http_waf_ds_stream_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                 i;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->datasets == NULL) {
        return NGX_OK;
    }

    ngx_http_waf_ds_streams = ngx_pcalloc(cycle->pool,
                                          wmcf->datasets->nelts
                                          * sizeof(ngx_http_waf_ds_stream_t));
    if (ngx_http_waf_ds_streams == NULL) {
        return NGX_ERROR;
    }

    ngx_http_waf_ds_nstreams = wmcf->datasets->nelts;

    ds = wmcf->datasets->elts;

    for (i = 0; i < ngx_http_waf_ds_nstreams; i++) {
        ngx_http_waf_ds_streams[i].ds    = &ds[i];
        ngx_http_waf_ds_streams[i].state = NGX_HTTP_WAF_DS_ST_IDLE;

        ngx_http_waf_ds_streams[i].timer.handler = ngx_http_waf_ds_stream_timer;
        ngx_http_waf_ds_streams[i].timer.data    =
                                              &ngx_http_waf_ds_streams[i];
        ngx_http_waf_ds_streams[i].timer.log     = cycle->log;

        /*
         * cancelable обязателен: таймер перевзводится вечно, а завершающийся
         * воркер выходит только когда неотменяемых таймеров не осталось.
         */
        ngx_http_waf_ds_streams[i].timer.cancelable = 1;
    }

    return NGX_OK;
}


void
ngx_http_waf_ds_stream_ready(void)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_http_waf_ds_nstreams; i++) {

        if (ngx_http_waf_ds_streams[i].ds->mode
            != NGX_HTTP_WAF_DS_MODE_ACTIVE)
        {
            continue;
        }

        ngx_http_waf_ds_stream_reset(&ngx_http_waf_ds_streams[i]);
        ngx_http_waf_ds_stream_kick(&ngx_http_waf_ds_streams[i]);
    }
}


void
ngx_http_waf_ds_stream_lost(void)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_http_waf_ds_nstreams; i++) {

        ngx_http_waf_ds_stream_reset(&ngx_http_waf_ds_streams[i]);

        if (ngx_http_waf_ds_streams[i].timer.timer_set) {
            ngx_del_timer(&ngx_http_waf_ds_streams[i].timer);
        }
    }
}


/*
 * Сброс шага. Выборка в полёте бросается: с пулом уходит cleanup драйвера,
 * и ответ Redis, если придёт, будет выброшен конвейером.
 */
static void
ngx_http_waf_ds_stream_reset(ngx_http_waf_ds_stream_t *st)
{
    st->state = NGX_HTTP_WAF_DS_ST_IDLE;
    st->op    = NULL;
    st->kind  = 0;

    if (st->pool != NULL) {
        ngx_destroy_pool(st->pool);
        st->pool = NULL;
    }
}


/*
 * С чего начать после подключения. Основания в зоне ещё нет -- снапшот; есть
 * -- готовы: пропущенное, пока соединения не было, догонит первый же тик.
 */
static void
ngx_http_waf_ds_stream_kick(ngx_http_waf_ds_stream_t *st)
{
    uint64_t  epoch, seq;

    ngx_http_waf_dataset_state(ngx_http_waf_ds_stream_pos(st), &epoch, &seq);

    if (epoch == 0) {
        if (ngx_http_waf_ds_stream_snapshot(st, 1) == NGX_OK) {
            return;
        }

        /*
         * Не наша заявка либо шину сейчас не спросить: надзор попросит
         * снова, а сосед, взявший заявку, положит основание в зону.
         */
        st->state = NGX_HTTP_WAF_DS_ST_IDLE;
        ngx_http_waf_ds_stream_watch(st);
        return;
    }

    ngx_http_waf_ds_stream_settle(st);
}


/* В READY с надзором за тишиной. */
static void
ngx_http_waf_ds_stream_settle(ngx_http_waf_ds_stream_t *st)
{
    st->state = NGX_HTTP_WAF_DS_ST_READY;
    ngx_http_waf_ds_stream_watch(st);
}


static ngx_int_t
ngx_http_waf_ds_stream_snapshot(ngx_http_waf_ds_stream_t *st, ngx_uint_t claim)
{
    u_char                     payload[256];
    u_char                    *p;
    ngx_str_t                  body;
    ngx_http_waf_main_conf_t  *wmcf;

    /*
     * Снапшот, который сам не сошёлся, повторять бессмысленно: новый берётся
     * только с новой эпохой, а до неё состав отвечает как есть.
     */
    if (ngx_http_waf_dataset_snap_bad(ngx_http_waf_ds_stream_pos(st))) {
        return NGX_DECLINED;
    }

    if (claim
        && ngx_http_waf_dataset_snapshot_claim(st->ds->index,
                                               NGX_HTTP_WAF_DS_SNAPSHOT_WAIT)
           != NGX_OK)
    {
        return NGX_DECLINED;
    }

    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    p = ngx_slprintf(payload, payload + sizeof(payload),
                     "{\"from\":\"%V\"}", &wmcf->node_id);

    body.data = payload;
    body.len  = (size_t) (p - payload);

    ngx_http_waf_ds_stream_reset(st);

    if (ngx_http_waf_ds_stream_request(st, ".snapshot", &body) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "waf: requesting a snapshot of dataset \"%V\"",
                  &st->ds->name);

    st->state = NGX_HTTP_WAF_DS_ST_SNAPSHOT;

    return NGX_OK;
}


/* Запрос на <subject><tail> с ответом в <inbox>.js.<index>. */
static ngx_int_t
ngx_http_waf_ds_stream_request(ngx_http_waf_ds_stream_t *st, const char *tail,
    ngx_str_t *body)
{
    u_char              *p;
    u_char               subj[512], suffix[32];
    ngx_str_t            subject, reply;
    ngx_http_waf_bus_t  *bus;

    bus = ngx_http_waf_bus_current();

    if (bus == NULL || bus->request == NULL || !bus->connected(bus)) {
        return NGX_ERROR;
    }

    p = ngx_slprintf(subj, subj + sizeof(subj), "%V%s", &st->ds->subject, tail);
    if (p == subj + sizeof(subj)) {
        return NGX_ERROR;
    }

    subject.data = subj;
    subject.len  = (size_t) (p - subj);

    p = ngx_slprintf(suffix, suffix + sizeof(suffix), "%s.%ui",
                     NGX_HTTP_WAF_BUS_TOKEN_JS, ngx_http_waf_ds_stream_pos(st));

    reply.data = suffix;
    reply.len  = (size_t) (p - suffix);

    if (bus->request(bus, &subject, &reply, body) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Ответа ждём таймером: молчание -- повтор шага. */
    if (st->timer.timer_set) {
        ngx_del_timer(&st->timer);
    }

    ngx_add_timer(&st->timer, NGX_HTTP_WAF_DS_RETRY);

    return NGX_OK;
}


/* Надзор за тишиной в READY. */
static void
ngx_http_waf_ds_stream_watch(ngx_http_waf_ds_stream_t *st)
{
    if (st->timer.timer_set) {
        ngx_del_timer(&st->timer);
    }

    ngx_add_timer(&st->timer, NGX_HTTP_WAF_DS_SILENCE);
}


static void
ngx_http_waf_ds_stream_timer(ngx_event_t *ev)
{
    ngx_uint_t                 first;
    ngx_msec_int_t             age;
    ngx_http_waf_ds_stream_t  *st = ev->data;

    switch (st->state) {

    case NGX_HTTP_WAF_DS_ST_READY:
        age = ngx_http_waf_dataset_seen(ngx_http_waf_ds_stream_pos(st), 0,
                                        &first);

        if (age > NGX_HTTP_WAF_DS_SILENCE && first) {
            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "waf: keeper is silent on dataset \"%V\" for "
                          "%M ms, serving the last known state",
                          &st->ds->name, (ngx_msec_t) age);
        }

        ngx_http_waf_ds_stream_watch(st);
        return;

    case NGX_HTTP_WAF_DS_ST_SNAPSHOT:
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "waf: keeper did not answer for dataset \"%V\", retrying",
                      &st->ds->name);

        ngx_http_waf_ds_stream_reset(st);
        ngx_http_waf_ds_stream_kick(st);
        return;

    case NGX_HTTP_WAF_DS_ST_FETCH:
        /* Ответ драйвера приходит всегда -- по данным или по его таймауту. */
        return;

    default:
        ngx_http_waf_ds_stream_kick(st);
    }
}


/* Кадр с подписки: уведомление о пакете или тик. */
void
ngx_http_waf_ds_stream_message(ngx_uint_t index, ngx_str_t *payload)
{
    uint64_t                   epoch, seq;
    ngx_int_t                  rc;
    ngx_pool_t                *pool;
    ngx_http_waf_ds_stream_t  *st;
    ngx_http_waf_ds_notice_t   n;

    if (index >= ngx_http_waf_ds_nstreams || payload->len == 0) {
        return;
    }

    st = &ngx_http_waf_ds_streams[index];

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        return;
    }

    if (ngx_http_waf_dataset_notice(index, payload, pool, &n) != NGX_OK) {
        ngx_destroy_pool(pool);
        return;
    }

    ngx_destroy_pool(pool);

    (void) ngx_http_waf_dataset_seen(index, 1, NULL);

    if (n.op != NGX_HTTP_WAF_DS_OP_DIFF && n.op != NGX_HTTP_WAF_DS_OP_TICK) {
        return;
    }

    ngx_http_waf_dataset_state(index, &epoch, &seq);

    /*
     * Пока идёт выборка или ждём ссылку на снапшот, кадр только двигает цель:
     * догон продолжится с того seq, на котором закончится текущий шаг.
     */
    if (n.epoch == epoch && n.seq > st->want) {
        st->want          = n.seq;
        st->want_hash     = n.hash;
        st->want_has_hash = n.has_hash;
    }

    if (st->state == NGX_HTTP_WAF_DS_ST_SNAPSHOT
        || st->state == NGX_HTTP_WAF_DS_ST_FETCH)
    {
        return;
    }

    if (epoch == 0 || n.epoch != epoch) {
        if (epoch != 0) {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "waf: dataset \"%V\" got epoch %016xL, have %016xL, "
                          "snapshot required", &st->ds->name, n.epoch, epoch);
        }

        if (ngx_http_waf_ds_stream_snapshot(st, 1) != NGX_OK) {
            st->state = (epoch == 0) ? NGX_HTTP_WAF_DS_ST_IDLE
                                     : NGX_HTTP_WAF_DS_ST_READY;
            ngx_http_waf_ds_stream_watch(st);
        }

        return;
    }

    if (st->state == NGX_HTTP_WAF_DS_ST_IDLE) {
        ngx_http_waf_ds_stream_settle(st);
    }

    if (n.seq > seq) {
        ngx_http_waf_ds_stream_catch_up(st);
        return;
    }

    if (n.op == NGX_HTTP_WAF_DS_OP_TICK && n.seq == seq && n.has_hash) {
        rc = ngx_http_waf_dataset_verify(index, n.epoch, n.seq, n.hash);

        if (rc == NGX_HTTP_WAF_DS_DIVERGED || rc == NGX_HTTP_WAF_DS_FOREIGN) {
            (void) ngx_http_waf_ds_stream_snapshot(st, 1);
        }
    }
}


/* Ответ keeper на наш запрос: ссылка на объект снапшота либо отказ. */
void
ngx_http_waf_ds_stream_reply(ngx_uint_t index, ngx_str_t *payload)
{
    ngx_pool_t                *pool;
    ngx_http_waf_ds_stream_t  *st;
    ngx_http_waf_ds_notice_t   n;

    if (index >= ngx_http_waf_ds_nstreams) {
        return;
    }

    st = &ngx_http_waf_ds_streams[index];

    if (st->state != NGX_HTTP_WAF_DS_ST_SNAPSHOT) {
        return;                        /* ответ на шаг, который уже не наш */
    }

    if (payload->len == 0) {
        /* 503 без подписчиков: keeper не поднят. Повтор по таймеру. */
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: no responders for dataset \"%V\"; is keeper up?",
                      &st->ds->name);

        ngx_http_waf_ds_stream_reset(st);
        return;
    }

    (void) ngx_http_waf_dataset_seen(index, 1, NULL);

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        ngx_http_waf_ds_stream_reset(st);
        return;
    }

    if (ngx_http_waf_dataset_notice(index, payload, pool, &n) != NGX_OK) {
        ngx_destroy_pool(pool);
        ngx_http_waf_ds_stream_reset(st);
        return;
    }

    if (n.op != NGX_HTTP_WAF_DS_OP_SNAPSHOT || n.object.len == 0) {
        /* not_ready, unknown_set, store_unavailable -- повтор по таймеру */
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "waf: keeper refused a snapshot of dataset \"%V\": %V",
                      &st->ds->name, &n.reply);

        ngx_destroy_pool(pool);
        ngx_http_waf_ds_stream_reset(st);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "waf: dataset \"%V\" snapshot is %V: %ui entries, seq %uL, "
                  "lives %ui s", &st->ds->name, &n.object, n.count, n.seq,
                  n.ttl);

    if (ngx_http_waf_ds_stream_fetch(st, &n.object,
                                     NGX_HTTP_WAF_DS_FETCH_SNAPSHOT, n.seq)
        != NGX_OK)
    {
        ngx_http_waf_ds_stream_reset(st);
    }

    ngx_destroy_pool(pool);
}


/*
 * Чтение объекта из внутреннего Redis. Пул выборки живёт до ответа драйвера;
 * NGX_OK -- запрос ушёл (или ответ пришёл сразу и уже разобран).
 */
static ngx_int_t
ngx_http_waf_ds_stream_fetch(ngx_http_waf_ds_stream_t *st, ngx_str_t *key,
    ngx_uint_t kind, uint64_t seq)
{
    off_t                    max;
    ngx_int_t                rc;
    ngx_str_t                k;
    ngx_pool_t              *pool;
    ngx_http_waf_body_op_t  *op;

    if (key->len == 0 || key->len > NGX_HTTP_WAF_DS_KEY_MAX) {
        return NGX_ERROR;
    }

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    k.data = ngx_pnalloc(pool, key->len);
    if (k.data == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    ngx_memcpy(k.data, key->data, key->len);
    k.len = key->len;

    ngx_http_waf_ds_stream_reset(st);

    st->pool     = pool;
    st->kind     = kind;
    st->fetching = seq;
    st->state    = NGX_HTTP_WAF_DS_ST_FETCH;

    if (st->timer.timer_set) {
        ngx_del_timer(&st->timer);
    }

    max = (kind == NGX_HTTP_WAF_DS_FETCH_SNAPSHOT) ? NGX_HTTP_WAF_DS_OBJECT_MAX
                                                   : NGX_HTTP_WAF_DS_PACKAGE_MAX;

    rc = ngx_http_waf_sets_get(&k, max, pool, ngx_cycle->log,
                               ngx_http_waf_ds_stream_fetched, st, &op);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": no waf_sets_store to read %V from",
                      &st->ds->name, key);
        ngx_http_waf_ds_stream_reset(st);
        return NGX_ERROR;
    }

    st->op = op;

    if (rc == NGX_OK) {
        /* ответ уже известен: соединения нет */
        ngx_http_waf_ds_stream_fetched(op);
    }

    return NGX_OK;
}


/*
 * Догон: пакет свой+1 из Redis. Зовётся, когда цель дальше своего seq; по
 * ответу зовётся снова, пока не догоним.
 */
static void
ngx_http_waf_ds_stream_catch_up(ngx_http_waf_ds_stream_t *st)
{
    u_char     key[NGX_HTTP_WAF_DS_KEY_MAX];
    u_char    *p;
    uint64_t   epoch, seq;
    ngx_str_t  k;

    ngx_http_waf_dataset_state(ngx_http_waf_ds_stream_pos(st), &epoch, &seq);

    if (epoch == 0) {
        (void) ngx_http_waf_ds_stream_snapshot(st, 1);
        return;
    }

    if (seq >= st->want) {
        if (st->want_has_hash && seq == st->want) {
            (void) ngx_http_waf_dataset_verify(ngx_http_waf_ds_stream_pos(st),
                                               epoch, seq, st->want_hash);
        }

        ngx_http_waf_ds_stream_settle(st);
        return;
    }

    /* Ключ пакета -- контракт с keeper (keeper/internal/state). */
    p = ngx_slprintf(key, key + sizeof(key), "waf:diff:%V:%uL",
                     &st->ds->name, seq + 1);

    k.data = key;
    k.len  = (size_t) (p - key);

    if (ngx_http_waf_ds_stream_fetch(st, &k, NGX_HTTP_WAF_DS_FETCH_PACKAGE,
                                     seq + 1)
        != NGX_OK)
    {
        ngx_http_waf_ds_stream_settle(st);
    }
}


/* Ответ драйвера: объект прочитан, ключа нет либо сбой. */
static void
ngx_http_waf_ds_stream_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_int_t                  rc, status;
    ngx_str_t                  data;
    ngx_uint_t                 index, kind;
    ngx_http_waf_ds_stream_t  *st = op->data_ctx;

    if (st->op != op || st->state != NGX_HTTP_WAF_DS_ST_FETCH) {
        return;                        /* выборка уже брошена */
    }

    index  = ngx_http_waf_ds_stream_pos(st);
    kind   = st->kind;
    status = op->status;
    data   = op->data;

    /* пул выборки живёт до конца применения: данные лежат в нём */
    st->op    = NULL;
    st->state = NGX_HTTP_WAF_DS_ST_READY;

    if (status == NGX_DECLINED) {

        if (kind == NGX_HTTP_WAF_DS_FETCH_PACKAGE) {
            /* Пакет протух: отставали дольше журнала. */
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "waf: dataset \"%V\": package seq %uL is gone, "
                          "taking a snapshot", &st->ds->name, st->fetching);

        } else {
            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "waf: dataset \"%V\": snapshot object is already "
                          "gone", &st->ds->name);
        }

        ngx_http_waf_ds_stream_reset(st);

        if (ngx_http_waf_ds_stream_snapshot(st, kind == NGX_HTTP_WAF_DS_FETCH_PACKAGE) != NGX_OK) {
            ngx_http_waf_ds_stream_kick(st);
        }

        return;
    }

    if (status != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": reading %s from waf_sets_store "
                      "failed, retrying", &st->ds->name,
                      (kind == NGX_HTTP_WAF_DS_FETCH_PACKAGE) ? "a package"
                                                              : "the snapshot");

        ngx_http_waf_ds_stream_reset(st);

        if (st->timer.timer_set) {
            ngx_del_timer(&st->timer);
        }

        ngx_add_timer(&st->timer, NGX_HTTP_WAF_DS_RETRY);
        return;
    }

    if (kind == NGX_HTTP_WAF_DS_FETCH_SNAPSHOT) {
        rc = ngx_http_waf_dataset_apply_snapshot(index, &data);

        ngx_http_waf_ds_stream_reset(st);

        switch (rc) {

        case NGX_HTTP_WAF_DS_APPLIED:
        case NGX_HTTP_WAF_DS_DIVERGED:
        case NGX_HTTP_WAF_DS_BUSY:
            /* Что изменилось после seq объекта, догонит следующий кадр. */
            ngx_http_waf_ds_stream_settle(st);

            if (st->want != 0) {
                ngx_http_waf_ds_stream_catch_up(st);
            }

            return;

        default:
            /* порванный или чужой объект: попросить снова, но не сразу */
            if (st->timer.timer_set) {
                ngx_del_timer(&st->timer);
            }

            ngx_add_timer(&st->timer, NGX_HTTP_WAF_DS_RETRY);
            return;
        }
    }

    rc = ngx_http_waf_dataset_apply_package(index, &data);

    ngx_http_waf_ds_stream_reset(st);

    switch (rc) {

    case NGX_HTTP_WAF_DS_APPLIED:
    case NGX_HTTP_WAF_DS_STALE:
        ngx_http_waf_ds_stream_catch_up(st);
        return;

    case NGX_HTTP_WAF_DS_GAP:
        /*
         * Слот отстал от нас: сосед положил снапшот с меньшим seq, пока мы
         * читали. Догон начинается заново с того, что в зоне.
         */
        ngx_http_waf_ds_stream_catch_up(st);
        return;

    case NGX_HTTP_WAF_DS_BUSY:
        /* Снапшот ложится другим воркером: он и догонит. */
        ngx_http_waf_ds_stream_settle(st);
        return;

    default:
        /* FOREIGN, DIVERGED, MALFORMED: основание заново */
        if (ngx_http_waf_ds_stream_snapshot(st, 1) != NGX_OK) {
            ngx_http_waf_ds_stream_settle(st);
        }

        return;
    }
}
