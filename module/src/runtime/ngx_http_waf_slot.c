/*
 * Таблица слотов ожидания.
 *
 * Слот связывает rid на шине с запросом nginx и живёт в памяти воркера, а не в
 * r->pool. Ответ инспектора может прийти после дедлайна, после блокировки и
 * после освобождения пула запроса; указатель на ngx_http_request_t в колбэке
 * шины означал бы use-after-free.
 *
 * Слоты лежат в плотном массиве со свободным списком, а rid кодирует индекс и
 * поколение:
 *
 *     rid = (gen << 24) | index
 *
 * Поиск слота -- одна индексация и одно сравнение поколения. Спецификация
 * упоминает хеш-таблицу; прямая индексация строго дешевле и заодно даёт
 * жёсткую верхнюю границу на число запросов в полёте, которая иначе
 * отсутствует.
 *
 * Поколение увеличивается при каждом освобождении слота, поэтому поздний
 * ответ на уже завершённый запрос не находит ничего и отбрасывается со
 * счётчиком.
 */

#include "ngx_http_waf.h"

#include <ngx_md5.h>

#include <fcntl.h>
#include <unistd.h>

#if (NGX_LINUX)
#include <sys/random.h>
#endif


typedef struct {
    ngx_http_waf_slot_t   *slots;

    ngx_uint_t             nslots;
    ngx_uint_t             free_head;
    ngx_uint_t             used;

    uint64_t               seq;         /* источник поколений                 */
} ngx_http_waf_slot_table_t;


static ngx_http_waf_slot_table_t  ngx_http_waf_slots;


/*
 * ray -- UUID v4, не счётчик. Монотонный номер на проводе палит RPS тому, кто
 * видит аудит, лог или событие автобана. 16 байт на запрос из getrandom /
 * urandom; сид воркера нужен только если ядро не дало энтропию в полёте.
 */
static u_char    ngx_http_waf_ray_seed_bytes[16];
static uint64_t  ngx_http_waf_ray_fallback;
static int       ngx_http_waf_ray_fd = -1;


static void      ngx_http_waf_hex64(uint64_t v, u_char *dst);
static void      ngx_http_waf_uuid_fmt(const u_char *raw, u_char *dst);
static ngx_int_t ngx_http_waf_random16(u_char *dst);
static ngx_int_t ngx_http_waf_ray_seed(ngx_log_t *log);


ngx_int_t
ngx_http_waf_slot_table_init(ngx_cycle_t *cycle, ngx_uint_t nslots)
{
    ngx_uint_t                  i;
    ngx_http_waf_slot_table_t  *t = &ngx_http_waf_slots;

    if (nslots == 0 || nslots > NGX_HTTP_WAF_SLOT_INDEX_MASK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "waf: invalid slot table size %ui", nslots);
        return NGX_ERROR;
    }

    /*
     * Таблица берётся из пула цикла: она переживает любой r->pool и
     * освобождается вместе с воркером. Ответы инспекторов здесь не хранятся --
     * они относятся к фазе, а не к волне, и живут в ctx->ph->replies. Иначе на
     * 4096 слотов по 64 записи ответа пришлось бы держать десятки мегабайт на
     * воркер под данные, которые нужны только пока запрос жив.
     */
    t->slots = ngx_pcalloc(cycle->pool, nslots * sizeof(ngx_http_waf_slot_t));
    if (t->slots == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < nslots; i++) {
        t->slots[i].gen       = 0;
        t->slots[i].next_free = i + 1;
    }

    t->slots[nslots - 1].next_free = NGX_HTTP_WAF_SLOT_NIL;

    t->nslots      = nslots;
    t->free_head   = 0;
    t->used        = 0;

    /*
     * Поколения начинаются со случайного значения, разного в каждом воркере и
     * в каждом поколении конфигурации. Иначе после reload новый воркер выдаёт
     * те же rid, что и завершающийся, и вердикт для чужого запроса совпадает
     * по всем полям.
     */
    t->seq = (((uint64_t) ngx_random() << 32) ^ (uint64_t) ngx_pid)
             & NGX_HTTP_WAF_SLOT_GEN_MASK;

    if (ngx_http_waf_ray_seed(cycle->log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Следующее поколение. Ноль зарезервирован под признак свободного слота,
 * поэтому пропускается при переполнении счётчика.
 */
static ngx_inline uint64_t
ngx_http_waf_next_gen(ngx_http_waf_slot_table_t *t)
{
    uint64_t  gen;

    do {
        t->seq = (t->seq + 1) & NGX_HTTP_WAF_SLOT_GEN_MASK;
        gen = t->seq;
    } while (gen == 0);

    return gen;
}


ngx_http_waf_slot_t *
ngx_http_waf_slot_acquire(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                  index;
    ngx_pool_cleanup_t         *cln;
    ngx_http_waf_slot_t        *slot;
    ngx_http_waf_slot_table_t  *t = &ngx_http_waf_slots;

    if (t->free_head == NGX_HTTP_WAF_SLOT_NIL) {
        /*
         * Таблица исчерпана. Это не отказ шины, а превышение расчётного числа
         * запросов в полёте, и обрабатывать его надо отдельным счётчиком:
         * иначе авария выглядит как массовый таймаут инспекторов.
         */
        return NULL;
    }

    index = t->free_head;
    slot  = &t->slots[index];

    t->free_head = slot->next_free;
    t->used++;

    slot->next_free = NGX_HTTP_WAF_SLOT_NIL;
    slot->gen       = ngx_http_waf_next_gen(t);
    slot->ctx       = ctx;
    slot->wave      = ctx->ph->wave;
    slot->got       = 0;
    slot->denied    = 0;
    slot->awaited   = 0;
    slot->published = ngx_current_msec;

    ctx->slot = index;
    ctx->rid  = (slot->gen << NGX_HTTP_WAF_SLOT_INDEX_BITS) | index;
    ngx_http_waf_rid_hex(ctx->rid, ctx->rid_hex);

    /*
     * Связь ctx -> slot обязана разрываться при уничтожении пула запроса, а не
     * только на штатных путях завершения: nginx освобождает пул и при обрыве
     * соединения, и при внутреннем редиректе.
     */
    cln = ngx_pool_cleanup_add(ctx->request->pool, 0);
    if (cln == NULL) {
        ngx_http_waf_slot_release(slot);
        return NULL;
    }

    cln->handler = ngx_http_waf_slot_detach;
    cln->data    = ctx;

    return slot;
}


/*
 * rid без ожидания: фаза-журнал кладёт объекты в обменник, а ключ объекта
 * держит rid. Слот берётся ради поколения и тут же отпускается -- ждать
 * вердикта некому, а rid остаётся у запроса и по-прежнему уникален: поколение
 * у следующего владельца слота уже другое.
 */
ngx_int_t
ngx_http_waf_rid_assign(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_slot_t  *slot;

    if (ctx->slot != NGX_HTTP_WAF_SLOT_NIL) {
        return NGX_OK;
    }

    slot = ngx_http_waf_slot_acquire(ctx);

    if (slot == NULL) {
        return NGX_ERROR;
    }

    ngx_http_waf_slot_release(slot);

    return NGX_OK;
}


ngx_http_waf_slot_t *
ngx_http_waf_slot_lookup(uint64_t rid)
{
    ngx_uint_t                  index;
    ngx_http_waf_slot_t        *slot;
    ngx_http_waf_slot_table_t  *t = &ngx_http_waf_slots;

    index = (ngx_uint_t) (rid & NGX_HTTP_WAF_SLOT_INDEX_MASK);

    if (index >= t->nslots) {
        return NULL;
    }

    slot = &t->slots[index];

    if (slot->gen != (rid >> NGX_HTTP_WAF_SLOT_INDEX_BITS)) {
        return NULL;               /* поздний ответ на завершённый запрос */
    }

    if (slot->ctx == NULL) {
        return NULL;               /* запрос уже освобождён */
    }

    return slot;
}


void
ngx_http_waf_slot_release(ngx_http_waf_slot_t *slot)
{
    ngx_uint_t                  index;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_slot_table_t  *t = &ngx_http_waf_slots;

    if (slot->gen == 0) {
        return;                    /* уже свободен */
    }

    index = (ngx_uint_t) (slot - t->slots);
    ctx   = slot->ctx;

    /*
     * Обратная ссылка рвётся вместе с прямой. Между волнами слот освобождается
     * и берётся заново, и запрос, продолжающий указывать на освобождённый
     * индекс, увёл бы ngx_http_waf_ensure_slot() в поиск по мёртвому rid:
     * поколение слота уже обнулено, поиск не находит ничего, и следующая волна
     * не публикуется вовсе -- маршрут с двумя волнами отвечает отказом шины.
     */
    if (ctx != NULL && ctx->slot == index) {
        ctx->slot = NGX_HTTP_WAF_SLOT_NIL;
    }

    /*
     * Обнуление поколения ДО возврата в свободный список: между этими двумя
     * действиями слот не должен находиться поиском ни по старому rid, ни по
     * будущему.
     */
    slot->gen       = 0;
    slot->ctx       = NULL;
    slot->next_free = t->free_head;

    t->free_head = index;
    t->used--;
}


void
ngx_http_waf_slot_detach(void *data)
{
    ngx_http_waf_ctx_t         *ctx = data;
    ngx_http_waf_slot_t        *slot;
    ngx_http_waf_slot_table_t  *t = &ngx_http_waf_slots;

    if (ctx->deadline.timer_set) {
        ngx_del_timer(&ctx->deadline);
    }

    if (ctx->slot >= t->nslots) {
        return;
    }

    slot = &t->slots[ctx->slot];

    /*
     * Проверка поколения обязательна: слот мог быть освобождён и переиспользован
     * другим запросом до того, как этот пул дошёл до cleanup.
     */
    if (slot->gen == (ctx->rid >> NGX_HTTP_WAF_SLOT_INDEX_BITS)) {
        ngx_http_waf_slot_release(slot);
    }

    ctx->slot = NGX_HTTP_WAF_SLOT_NIL;
}


static void
ngx_http_waf_hex64(uint64_t v, u_char *dst)
{
    static const u_char  hex[] = "0123456789abcdef";

    ngx_int_t  i;

    for (i = 15; i >= 0; i--) {
        dst[i] = hex[v & 0xf];
        v >>= 4;
    }
}


void
ngx_http_waf_rid_hex(uint64_t rid, u_char *dst)
{
    ngx_http_waf_hex64(rid, dst);
}


static void
ngx_http_waf_uuid_fmt(const u_char *raw, u_char *dst)
{
    static const u_char  hex[] = "0123456789abcdef";
    ngx_uint_t           i, o;

    o = 0;

    for (i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            dst[o++] = '-';
        }

        dst[o++] = hex[raw[i] >> 4];
        dst[o++] = hex[raw[i] & 0x0f];
    }
}


static ngx_int_t
ngx_http_waf_random16(u_char *dst)
{
    ssize_t  n;

#if (NGX_LINUX)
    n = getrandom(dst, 16, 0);
    if (n == 16) {
        return NGX_OK;
    }
#endif

    if (ngx_http_waf_ray_fd != -1) {
        n = read(ngx_http_waf_ray_fd, dst, 16);
        if (n == 16) {
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_waf_ray_seed(ngx_log_t *log)
{
    ssize_t  n;

    if (ngx_http_waf_random16(ngx_http_waf_ray_seed_bytes) != NGX_OK) {
        ngx_http_waf_ray_fd = open("/dev/urandom", O_RDONLY);
        if (ngx_http_waf_ray_fd == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "waf: cannot seed ray (getrandom/urandom)");
            return NGX_ERROR;
        }

        n = read(ngx_http_waf_ray_fd, ngx_http_waf_ray_seed_bytes, 16);
        if (n != 16) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "waf: short urandom read while seeding ray");
            return NGX_ERROR;
        }
    } else if (ngx_http_waf_ray_fd == -1) {
        ngx_http_waf_ray_fd = open("/dev/urandom", O_RDONLY);
    }

    return NGX_OK;
}


void
ngx_http_waf_ray_next(u_char *dst)
{
    u_char     raw[16];
    ngx_md5_t  md5;

    if (ngx_http_waf_random16(raw) != NGX_OK) {
        /*
         * Ядро не дало энтропию. На провод всё равно не кладём сырой
         * счётчик: MD5(сид || n) не монотонен для того, кто видит UUID.
         */
        ngx_http_waf_ray_fallback++;
        ngx_md5_init(&md5);
        ngx_md5_update(&md5, ngx_http_waf_ray_seed_bytes, 16);
        ngx_md5_update(&md5, &ngx_http_waf_ray_fallback, sizeof(uint64_t));
        ngx_md5_final(raw, &md5);
    }

    raw[6] = (u_char) ((raw[6] & 0x0f) | 0x40);
    raw[8] = (u_char) ((raw[8] & 0x3f) | 0x80);
    ngx_http_waf_uuid_fmt(raw, dst);
}


ngx_int_t
ngx_http_waf_rid_parse(ngx_str_t *hex, uint64_t *rid)
{
    u_char     c;
    uint64_t   v;
    ngx_uint_t i;

    if (hex->len != NGX_HTTP_WAF_RID_HEX_LEN) {
        return NGX_ERROR;
    }

    v = 0;

    for (i = 0; i < NGX_HTTP_WAF_RID_HEX_LEN; i++) {
        c = hex->data[i];

        if (c >= '0' && c <= '9') {
            v = (v << 4) | (uint64_t) (c - '0');

        } else if (c >= 'a' && c <= 'f') {
            v = (v << 4) | (uint64_t) (c - 'a' + 10);

        } else {
            return NGX_ERROR;      /* верхний регистр не принимаем: rid
                                      генерируем мы, и он всегда нижний */
        }
    }

    *rid = v;

    return NGX_OK;
}
