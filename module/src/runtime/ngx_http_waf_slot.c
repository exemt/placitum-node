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

    uint64_t               seq;
} ngx_http_waf_slot_table_t;


static ngx_http_waf_slot_table_t  ngx_http_waf_slots;


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

    t->seq = (((uint64_t) ngx_random() << 32) ^ (uint64_t) ngx_pid)
             & NGX_HTTP_WAF_SLOT_GEN_MASK;

    if (ngx_http_waf_ray_seed(cycle->log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


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
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: all %ui wait slots are busy (waf_max_inflight), "
                      "ray %*s", t->nslots,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        return NULL;
    }

    index = t->free_head;
    slot  = &t->slots[index];

    t->free_head = slot->next_free;

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

    cln = ngx_pool_cleanup_add(ctx->request->pool, 0);
    if (cln == NULL) {
        ngx_http_waf_slot_release(slot);
        return NULL;
    }

    cln->handler = ngx_http_waf_slot_detach;
    cln->data    = ctx;

    return slot;
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
        return NULL;
    }

    if (slot->ctx == NULL) {
        return NULL;
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
        return;
    }

    index = (ngx_uint_t) (slot - t->slots);
    ctx   = slot->ctx;

    if (ctx != NULL && ctx->slot == index) {
        ctx->slot = NGX_HTTP_WAF_SLOT_NIL;
    }

    slot->gen       = 0;
    slot->ctx       = NULL;
    slot->next_free = t->free_head;

    t->free_head = index;
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
            return NGX_ERROR;
        }
    }

    *rid = v;

    return NGX_OK;
}
