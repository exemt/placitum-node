/*
 * Локальный слой: решение без единого сообщения на шину.
 *
 * Зачем он вообще: один клиентский запрос порождает несколько внутренних
 * сообщений, то есть шина усиливает трафик, и без отсечения на входе она сама
 * становится целью атаки. Поэтому счётчики частоты, наборы адресов и состояние
 * circuit breaker живут в разделяемой памяти и проверяются до публикации.
 *
 * Три правила, которым подчинено всё в этом каталоге:
 *
 * 1. Общее состояние -- в ngx_shm_zone, а не в памяти воркера. Иначе каждый
 *    воркер независимо переучивается, что инспектор недоступен, и отключает его
 *    в разное время, а наблюдаемость размазывается по процессам.
 *
 * 2. Читатель набора данных не берёт мьютекс. Набор неизменяем после
 *    публикации, подменяется целиком одним указателем, а освобождается только
 *    тогда, когда его отпустил последний читатель -- см. ngx_http_waf_set_t.
 *
 * 3. Форма разметки зоны не зависит от конфигурации: массивы слотов имеют
 *    фиксированную длину. При reload старые воркеры продолжают работать в той же
 *    зоне, и изменившаяся разметка означала бы чтение чужой памяти.
 *
 * Спецификация: docs/directives/list/list.md,
 * docs/inspectors.md#поставщик-данных, docs/execution-model.md#circuit-breaker.
 */

#ifndef _NGX_HTTP_WAF_LOCAL_H_INCLUDED_
#define _NGX_HTTP_WAF_LOCAL_H_INCLUDED_


#include "ngx_http_waf.h"


#define NGX_HTTP_WAF_DS_NAME_MAX        64


/* Пара имя/значение из строки запроса или Cookie под селекторы (select.c). */
typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  value;
} ngx_http_waf_pair_t;

/*
 * Предел длины одной записи набора. Нужен не для экономии, а чтобы разбор
 * снапшота из миллиона записей обходился без аллокации на запись: строка
 * раскрывается в буфер на стеке этого размера.
 *
 * Четыре килобайта -- не круглое число, а предел того, что вообще может
 * приехать: столько браузер отдаёт под одну cookie. Прежние 256 отсекали
 * подписанный токен сессии, а вместе с ним -- и любой набор, куда такой токен
 * попадал: длинная запись роняла разбор всего кадра, и набор оставался пустым
 * вместе со всеми проверками по нему.
 *
 * Длина в блобе двухбайтовая, так что запас формата остаётся шестнадцатикратным.
 */
#define NGX_HTTP_WAF_DS_ENTRY_MAX      4096

/* Число отставленных наборов на слот; освобождаются, когда их отпустят. */
#define NGX_HTTP_WAF_DS_RETIRED        4


/* --- состояние circuit breaker --------------------------------------------
 *
 * Все поля атомарные и меняются без мьютекса: на пути каждого ответа и каждой
 * публикации мьютекс, общий для воркеров, стоил бы дороже, чем даёт точность
 * доли таймаутов. Расхождение на границе окна здесь допустимо -- решение
 * принимается по доле на окне в секунды, а не по отдельному ответу.
 */
typedef struct {
    ngx_atomic_t               state;       /* 0 closed, 1 half-open, 2 open */
    ngx_atomic_t               epoch;       /* начало окна наблюдения, msec  */
    ngx_atomic_t               attempts;
    ngx_atomic_t               failures;    /* только таймауты               */
    ngx_atomic_t               probe_at;    /* когда пустить пробу, msec     */
} ngx_http_waf_breaker_t;


/* --- набор данных ---------------------------------------------------------
 *
 * Заголовок, общий для всех представлений. readers -- это не отладочный
 * счётчик, а единственное, что стоит между подменой набора и use-after-free:
 * освободить отставленный набор можно только после того, как его отпустил
 * последний читатель, а читателей у него столько, сколько воркеров.
 */
typedef struct {
    ngx_atomic_t               readers;
    ngx_uint_t                 entries;
    size_t                     size;        /* сколько занято в зоне         */
    uint64_t                   hash;        /* XOR SipHash по записям базы   */
} ngx_http_waf_set_t;


/*
 * Набор сетей. Префиксы CIDR либо не пересекаются, либо вложены один в другой,
 * поэтому сортировка по (начало возр., конец убыв.) даёт вложенность в виде
 * правильной скобочной структуры, а принадлежность адреса проверяется двоичным
 * поиском и одним сравнением: cover[i] -- максимум конца по всем записям до i
 * включительно, и он не меньше адреса тогда и только тогда, когда адрес покрыт.
 *
 * Радиксного дерева здесь нет намеренно: набор неизменяем, то есть дешёвая
 * вставка -- его единственное преимущество -- не нужна, а массив вчетверо
 * плотнее и обходится одним проходом по непрерывной памяти.
 */
typedef struct {
    ngx_http_waf_set_t         h;

    ngx_uint_t                 n4;
    uint32_t                  *v4_start;
    uint32_t                  *v4_end;
    uint32_t                  *v4_cover;

    ngx_uint_t                 n6;
    u_char                    *v6_start;    /* n6 * 16, big-endian           */
    u_char                    *v6_end;
    u_char                    *v6_cover;

    /*
     * Хеш каждой записи по её тексту с провода. База хранит адреса двоично, и
     * восстановить из них строку keeper байт в байт нельзя, а слияние с
     * дельтой обязано унести хеши старых записей в новый набор.
     */
    uint64_t                  *v4_h;
    uint64_t                  *v6_h;
} ngx_http_waf_cidr_set_t;


/*
 * Набор строк. Открытая адресация: таблица смещений в непрерывный blob, где
 * записи лежат как [длина][байты]. Blob перечислим последовательно, и это
 * требование дельт: чтобы применить add или remove, надо построить новый набор
 * из действующего.
 */
typedef struct {
    ngx_http_waf_set_t         h;

    ngx_uint_t                 mask;        /* размер таблицы минус один     */
    uint32_t                  *table;       /* смещение + 1; 0 -- пусто      */
    u_char                    *blob;
    size_t                     blob_len;
} ngx_http_waf_str_set_t;


/* --- слот набора в зоне --------------------------------------------------- */

/*
 * Overlay записей keeper со сроком: у активного набора это весь состав
 * (ngx_http_waf_ds_live.c). Своё дерево и свой замок на слот, не общие с
 * rate: проверка списка не должна делить мьютекс со счётчиками частоты.
 * lens -- сколько префиксов каждой длины маски по семействам: поиск адреса
 * пробует только присутствующие длины.
 */
typedef struct {
    ngx_rbtree_t               tree;
    ngx_rbtree_node_t          sentinel;
    ngx_uint_t                 n;
    ngx_uint_t                 max;
    uint32_t                   gen;         /* поколение снапшота            */
    uint32_t                   lens[2][129];
} ngx_http_waf_ds_live_t;


typedef struct {
    u_char                     name[NGX_HTTP_WAF_DS_NAME_MAX];
    size_t                     name_len;
    ngx_uint_t                 type;

    void                      *set;         /* база: только internal         */
    ngx_http_waf_ds_live_t    *live;        /* overlay; NULL до первой записи */
    ngx_uint_t                 live_max;

    /*
     * Замок overlay: читатели на пути запроса берут разделяемый, применение
     * пакета и снапшота -- исключительный. Порядок с мьютексом зоны один:
     * сначала замок слота, затем зона (внутри ngx_slab_alloc).
     */
    ngx_atomic_t               lock;

    uint64_t                   seq;         /* применённая последовательность */
    time_t                     updated;

    /*
     * Эпоха keeper и ключ SipHash этой эпохи: приезжают снапшотом, кадр чужой
     * эпохи означает, что всё известное недействительно. live_hash -- XOR
     * хешей overlay, у активного набора это и есть хеш состава, и он
     * сверяется с тем, что несёт каждый пакет и каждый тик (docs/keeper.md).
     */
    uint64_t                   epoch;
    u_char                     key[16];
    uint64_t                   live_hash;

    /* Последний кадр keeper по этому набору; тишина в три тика -- WARN. */
    ngx_msec_t                 seen;
    unsigned                   silent:1;

    /*
     * syncing -- снапшот ложится прямо сейчас: пакеты не применяются, догон
     * начнётся с seq объекта. snap_bad -- снапшот применён, а хеш с keeper
     * не сошёлся: зеркало не умеет какое-то значение или провод врёт, и
     * повторять снапшот бессмысленно -- новый берётся только с новой эпохой.
     */
    unsigned                   syncing:1;
    unsigned                   snap_bad:1;

    /*
     * Когда снапшот запрашивали в последний раз. Отметка общая, а не своя у
     * каждого воркера: просит и читает объект один воркер на ноду, остальные
     * видят результат в зоне -- на флоте из сотни узлов по двенадцать
     * воркеров иначе было бы тысяча чтений одного объекта.
     */
    ngx_msec_t                 snapshot_at;

    void                      *retired[NGX_HTTP_WAF_DS_RETIRED];

    unsigned                   bound:1;
} ngx_http_waf_ds_slot_t;


/* --- кеш вердикта кадров ---------------------------------------------------
 *
 * Открытая адресация фиксированного размера в зоне: запись -- хеш полезной
 * нагрузки с адресом маршрута, сторона, опкод и срок. Ни цепочек, ни LRU:
 * вытеснение -- запись с ближайшим сроком в окне пробы, и это намеренно
 * дёшево -- кеш сидит на пути каждого кадра, а промах стоит только инспекции,
 * которая и так была бы.
 *
 * Размер фиксирован (NGX_HTTP_WAF_FCACHE_ENTRIES): правило разметки зоны --
 * форма не зависит от конфигурации.
 */
#define NGX_HTTP_WAF_FCACHE_ENTRIES     4096
#define NGX_HTTP_WAF_FCACHE_PROBE       8

typedef struct {
    u_char                     digest[16];  /* половина sha256 нагрузки     */
    uint32_t                   route;       /* crc32 адреса маршрута        */
    uint8_t                    phase;       /* слот фазы: сторона кадра     */
    uint8_t                    opcode;
    uint16_t                   pad;
    ngx_msec_t                 expires;     /* 0 -- пусто                   */
} ngx_http_waf_fcache_entry_t;

typedef struct {
    ngx_atomic_t               hits;
    ngx_atomic_t               misses;
    ngx_atomic_t               inserts;
    ngx_http_waf_fcache_entry_t  entries[NGX_HTTP_WAF_FCACHE_ENTRIES];
} ngx_http_waf_fcache_t;


/* --- разметка зоны -------------------------------------------------------- */

typedef struct {
    ngx_slab_pool_t           *shpool;

    ngx_http_waf_breaker_t     breakers[NGX_HTTP_WAF_MAX_INSPECTORS];

    /* счётчики частоты: одно дерево на все правила, ключ несёт подпись */
    ngx_rbtree_t               rate;
    ngx_rbtree_node_t          rate_sentinel;
    ngx_queue_t                rate_lru;

    ngx_http_waf_ds_slot_t     datasets[NGX_HTTP_WAF_MAX_DATASETS];

    /*
     * Кеш вердикта кадров (waf_frame_cache). Указатель, а не массив: таблица
     * заводится в зоне только тогда, когда хоть один маршрут включил кеш, и
     * зона без него не платит за неё. Поле последнее: разметка выше
     * остаётся прежней для воркеров, не знающих о кеше.
     */
    ngx_http_waf_fcache_t     *fcache;
} ngx_http_waf_shm_t;


/* --- local/ngx_http_waf_shm.c --------------------------------------------- */

char      *ngx_http_waf_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);

/*
 * Проверка "локальные директивы есть, зоны нет". Отдельной функцией потому, что
 * директивы маршрута видны только при слиянии location conf, а waf_local_dataset
 * -- уже при init_main_conf.
 */
ngx_int_t  ngx_http_waf_shm_required(ngx_conf_t *cf, const char *directive);

/*
 * Влезают ли объявленные наборы в зону. Зовётся из init_main_conf, когда все
 * waf_local_dataset разобраны: список знает свой потолок, и место под него
 * обязано быть, иначе край молча пропустит хвост состава.
 */
ngx_int_t  ngx_http_waf_shm_fit(ngx_conf_t *cf);

/* Зона этого воркера; NULL, если waf_shm_zone не объявлена. */
ngx_http_waf_shm_t  *ngx_http_waf_shm(void);


/* --- local/ngx_http_waf_breaker.c ----------------------------------------- */

/*
 * Пустить ли запрос к инспектору. NGX_OK -- да; NGX_DECLINED -- breaker открыт,
 * ответа не будет, и волна обрабатывает это как таймаут.
 */
ngx_int_t  ngx_http_waf_breaker_allow(ngx_uint_t index,
               ngx_http_waf_inspector_t *insp);

/* Исход опроса: ответ получен либо не получен к дедлайну. */
void       ngx_http_waf_breaker_result(ngx_uint_t index,
               ngx_http_waf_inspector_t *insp, ngx_uint_t timed_out);


/* --- local/ngx_http_waf_rate.c -------------------------------------------- */

char      *ngx_http_waf_local_rate(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);

/* Вставка в дерево счётчиков; передаётся в ngx_rbtree_init при разметке зоны. */
void       ngx_http_waf_rate_insert_value(ngx_rbtree_node_t *temp,
               ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

/*
 * Проверка всех правил маршрута. NGX_OK -- пропустить, NGX_DECLINED -- отказать;
 * имя сработавшего правила и запись каталога остаются в *rule и *response.
 */
ngx_int_t  ngx_http_waf_rate_check(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule,
               ngx_str_t *response);

/* Учёт опубликованной волны при count=waves. Исхода не меняет. */
void       ngx_http_waf_rate_charge_wave(ngx_http_waf_ctx_t *ctx);


/* --- local/ngx_http_waf_dataset.c ----------------------------------------- */

char      *ngx_http_waf_local_dataset(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);
char      *ngx_http_waf_local_check(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);

ngx_http_waf_dataset_t  *ngx_http_waf_dataset_find(
                             ngx_http_waf_main_conf_t *wmcf, ngx_str_t *name);

/* Привязка объявленных наборов к слотам зоны; вызывается при инициализации. */
ngx_int_t  ngx_http_waf_dataset_bind(ngx_cycle_t *cycle);

/*
 * Кадр keeper на проводе (docs/keeper.md): уведомление о пакете, тик или
 * ответ на .snapshot. Состава в нём нет -- только ключи объектов в Redis.
 */
typedef enum {
    NGX_HTTP_WAF_DS_OP_DIFF     = 0,
    NGX_HTTP_WAF_DS_OP_TICK     = 1,
    NGX_HTTP_WAF_DS_OP_SNAPSHOT = 2,
    NGX_HTTP_WAF_DS_OP_OTHER    = 3   /* отказ: not_ready, unknown_set, ... */
} ngx_http_waf_ds_op_e;

typedef struct {
    ngx_uint_t                 op;
    uint64_t                   epoch;
    uint64_t                   seq;
    uint64_t                   hash;
    ngx_uint_t                 has_hash;
    ngx_str_t                  package;     /* ключ пакета waf:diff:...      */
    ngx_str_t                  object;      /* ключ объекта снапшота         */
    ngx_str_t                  reply;       /* op как текст, для отказов     */
    ngx_uint_t                 count;
    ngx_uint_t                 ttl;
} ngx_http_waf_ds_notice_t;

/* Разбор кадра; строки живут в pool. NGX_ERROR -- битый или чужой кадр. */
ngx_int_t  ngx_http_waf_dataset_notice(ngx_uint_t index, ngx_str_t *payload,
               ngx_pool_t *pool, ngx_http_waf_ds_notice_t *n);

/*
 * Итог применения объекта (пакета или снапшота) и сверки тика.
 */
#define NGX_HTTP_WAF_DS_APPLIED    0   /* применено, хеш сошёлся            */
#define NGX_HTTP_WAF_DS_STALE      1   /* seq не старше своего: уже было     */
#define NGX_HTTP_WAF_DS_GAP        2   /* seq дальше своего+1: нужен предыдущий */
#define NGX_HTTP_WAF_DS_FOREIGN    3   /* чужая эпоха, вид или тип: снапшот  */
#define NGX_HTTP_WAF_DS_DIVERGED   4   /* применено, хеш не сошёлся          */
#define NGX_HTTP_WAF_DS_MALFORMED  5   /* объект не разбирается             */
#define NGX_HTTP_WAF_DS_BUSY       6   /* снапшот ложится другим воркером    */

/* Пакет изменений из Redis: двоичный объект keeper. */
ngx_int_t  ngx_http_waf_dataset_apply_package(ngx_uint_t index,
               ngx_str_t *data);

/* Снапшот из Redis: пометка и выметание, состав отвечает всё время. */
ngx_int_t  ngx_http_waf_dataset_apply_snapshot(ngx_uint_t index,
               ngx_str_t *data);

/* Сверка тика: APPLIED, STALE, GAP, FOREIGN или DIVERGED. */
ngx_int_t  ngx_http_waf_dataset_verify(ngx_uint_t index, uint64_t epoch,
               uint64_t seq, uint64_t hash);

/* Состояние слота для запросов; epoch == 0 -- снапшота ещё не было. */
void       ngx_http_waf_dataset_state(ngx_uint_t index, uint64_t *epoch,
               uint64_t *seq);

/* Ограничитель: снапшот не сошёлся, новый не брать до новой эпохи. */
ngx_uint_t ngx_http_waf_dataset_snap_bad(ngx_uint_t index);

/* Отметить кадр keeper; вернуть возраст последнего и погасить/поднять silent. */
ngx_msec_int_t ngx_http_waf_dataset_seen(ngx_uint_t index, ngx_uint_t touch,
               ngx_uint_t *first_silence);

/*
 * Проверки маршрута по наборам. NGX_DECLINED -- смотреть следующие local,
 * NGX_OK -- пропустить мимо инспекции, NGX_DONE -- wave (rate ниже не
 * смотрим, идём в inspect), NGX_ERROR -- отказать; сработавшее правило и
 * запись каталога остаются в *rule и *response.
 */
ngx_int_t  ngx_http_waf_dataset_check(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule,
               ngx_str_t *response);

/*
 * Одно значение против одного набора: 1 -- есть, 0 -- нет. Смотрит overlay, за
 * ним базу снапшота. Набор, который ещё не приехал, -- это промах, а не ошибка:
 * узел, поднявшийся раньше контроллера, обязан обслуживать трафик.
 */
ngx_uint_t ngx_http_waf_dataset_hit(ngx_http_waf_dataset_t *ds,
               ngx_str_t *value);

/*
 * md5 значения в hex: ровно NGX_HTTP_WAF_MD5_HEX_LEN байт в out. Так хранит и
 * сравнивает значения набор с hash=md5; тем же считается ключ корзины
 * waf_local_rate … hash=md5. Одна функция на оба места намеренно: разойдись
 * они хоть в регистре hex, набор перестал бы совпадать с тем, что в него кладут.
 */
void       ngx_http_waf_md5_hex(ngx_str_t *in, u_char *out);

/*
 * Право запросить снапшот набора: NGX_OK -- запрашивать этому воркеру,
 * NGX_DECLINED -- в пределах периода запрос уже сделан кем-то. Отметка живёт в
 * зоне, потому что запрашивать должен один воркер за узел, а не каждый.
 */
ngx_int_t  ngx_http_waf_dataset_snapshot_claim(ngx_uint_t index,
               ngx_msec_t wait);

/*
 * Overlay (ngx_http_waf_ds_live.c). put и drop зовутся под исключительным
 * замком слота, который держит вызывающий; hit берёт разделяемый сам,
 * reset -- исключительный сам. Ключ -- материал записи: у адреса семейство,
 * биты, адрес под маской (ngx_http_waf_ds_material), у строки -- она сама.
 * expires -- по часам ngx_current_msec, 0 -- вечная.
 *
 * put: NGX_OK -- запись новая или срок изменён, NGX_DECLINED -- уже есть с
 * не меньшим сроком, NGX_ERROR -- потолок или зона.
 */
ngx_int_t  ngx_http_waf_ds_live_put(ngx_http_waf_ds_slot_t *slot,
               ngx_str_t *key, ngx_msec_t expires, uint64_t h, uint32_t gen);
ngx_int_t  ngx_http_waf_ds_live_drop(ngx_http_waf_ds_slot_t *slot,
               ngx_str_t *key);
ngx_uint_t ngx_http_waf_ds_live_hit(ngx_http_waf_dataset_t *ds,
               ngx_http_waf_ds_slot_t *slot, ngx_str_t *value);
void       ngx_http_waf_ds_live_reset(ngx_http_waf_ds_slot_t *slot);

/* Поколение под снапшот и текущее поколение (под замком). */
uint32_t   ngx_http_waf_ds_live_begin(ngx_http_waf_ds_slot_t *slot);
uint32_t   ngx_http_waf_ds_live_gen(ngx_http_waf_ds_slot_t *slot);

/* Выметание чужого поколения порциями: NGX_AGAIN -- звать ещё. */
ngx_int_t  ngx_http_waf_ds_live_sweep(ngx_http_waf_ds_slot_t *slot,
               uint32_t gen, ngx_uint_t batch, ngx_rbtree_node_t **cursor,
               ngx_uint_t *swept);

/* Материал значения; buf -- 18 байт от вызывающего. */
ngx_int_t  ngx_http_waf_ds_material(ngx_http_waf_dataset_t *ds,
               ngx_str_t *value, u_char *buf, ngx_str_t *key);

/* Автобан: overlay + событие на <subject>.event. */
ngx_int_t  ngx_http_waf_dataset_put(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_dataset_t *ds, ngx_str_t *value, ngx_uint_t ttl,
               ngx_str_t *reason);

/* Просьба ban: адрес клиента в названный живой набор. */
ngx_int_t  ngx_http_waf_ban_apply(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_action_t *action);


/* --- local/ngx_http_waf_frame_cache.c ------------------------------------- */

/*
 * Таблица кеша в зоне. Заводится при инициализации зоны, если хоть один
 * маршрут включил waf_frame_cache; при reload переиспользуется вместе с
 * зоной либо доводится, если прежняя конфигурация кеша не знала.
 */
ngx_int_t  ngx_http_waf_fcache_init(ngx_http_waf_shm_t *shm,
               ngx_shm_zone_t *zone);

/* Конфигурация включила кеш хоть на одном маршруте; сброс -- на разборе. */
void       ngx_http_waf_fcache_want(ngx_uint_t on);

/*
 * Поиск: NGX_OK -- вердикт allow известен и срок не вышел, NGX_DECLINED --
 * нет записи, кеш выключен на этом слоте или зоны нет.
 */
ngx_int_t  ngx_http_waf_fcache_lookup(uint32_t route, ngx_uint_t phase,
               ngx_uint_t opcode, u_char *sha256);

/* Вставка чистого allow на ttl миллисекунд. */
void       ngx_http_waf_fcache_insert(uint32_t route, ngx_uint_t phase,
               ngx_uint_t opcode, u_char *sha256, ngx_msec_t ttl);


/* --- local/ngx_http_waf_ds_stream.c --------------------------------------- */

/*
 * Провод наборов: уведомления и тики с подписки, ответ keeper на .snapshot,
 * чтение пакетов и объектов из внутреннего Redis (waf_sets_store). Живёт
 * отдельно от применения: остальному коду объект приезжает уже байтами.
 */
ngx_int_t  ngx_http_waf_ds_stream_init_worker(ngx_cycle_t *cycle);

/* Подключение к шине установлено либо потеряно; вызывается транспортом. */
void       ngx_http_waf_ds_stream_ready(void);
void       ngx_http_waf_ds_stream_lost(void);

/* Кадр набора с подписки и ответ на запрос воркера; вызываются транспортом. */
void       ngx_http_waf_ds_stream_message(ngx_uint_t index, ngx_str_t *payload);
void       ngx_http_waf_ds_stream_reply(ngx_uint_t index, ngx_str_t *payload);


#endif /* _NGX_HTTP_WAF_LOCAL_H_INCLUDED_ */
