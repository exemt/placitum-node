#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


static ngx_inline ngx_uint_t
ngx_http_waf_fcache_slot(u_char *digest)
{
    uint64_t  h;

    h = ((uint64_t) digest[0] << 56) | ((uint64_t) digest[1] << 48)
        | ((uint64_t) digest[2] << 40) | ((uint64_t) digest[3] << 32)
        | ((uint64_t) digest[4] << 24) | ((uint64_t) digest[5] << 16)
        | ((uint64_t) digest[6] << 8) | (uint64_t) digest[7];

    return (ngx_uint_t) (h & (NGX_HTTP_WAF_FCACHE_ENTRIES - 1));
}


static ngx_uint_t  ngx_http_waf_fcache_wanted;


void
ngx_http_waf_fcache_want(ngx_uint_t on)
{
    ngx_http_waf_fcache_wanted = on;
}


ngx_int_t
ngx_http_waf_fcache_init(ngx_http_waf_shm_t *shm, ngx_shm_zone_t *zone)
{
    if (!ngx_http_waf_fcache_wanted || shm->fcache != NULL) {
        return NGX_OK;
    }

    shm->fcache = ngx_slab_calloc(shm->shpool, sizeof(ngx_http_waf_fcache_t));

    if (shm->fcache == NULL) {
        ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0,
                      "waf: zone \"%V\" has no room for the frame verdict "
                      "cache (%uz bytes); enlarge waf_shm_zone",
                      &zone->shm.name, sizeof(ngx_http_waf_fcache_t));
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_fcache_lookup(uint32_t route, ngx_uint_t phase, ngx_uint_t opcode,
    u_char *sha256)
{
    ngx_uint_t                    i, slot;
    ngx_msec_t                    now;
    ngx_http_waf_shm_t           *shm;
    ngx_http_waf_fcache_t        *fc;
    ngx_http_waf_fcache_entry_t  *e;

    shm = ngx_http_waf_shm();

    if (shm == NULL || shm->fcache == NULL) {
        return NGX_DECLINED;
    }

    fc   = shm->fcache;
    slot = ngx_http_waf_fcache_slot(sha256);
    now  = ngx_current_msec;

    ngx_shmtx_lock(&shm->shpool->mutex);

    for (i = 0; i < NGX_HTTP_WAF_FCACHE_PROBE; i++) {
        e = &fc->entries[(slot + i) & (NGX_HTTP_WAF_FCACHE_ENTRIES - 1)];

        if (e->expires == 0) {
            continue;
        }

        if (e->route != route || e->phase != phase || e->opcode != opcode
            || ngx_memcmp(e->digest, sha256, 16) != 0)
        {
            continue;
        }

        if ((ngx_msec_int_t) (e->expires - now) <= 0) {
            e->expires = 0;
            continue;
        }

        (void) ngx_atomic_fetch_add(&fc->hits, 1);

        ngx_shmtx_unlock(&shm->shpool->mutex);

        return NGX_OK;
    }

    (void) ngx_atomic_fetch_add(&fc->misses, 1);

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_DECLINED;
}


void
ngx_http_waf_fcache_insert(uint32_t route, ngx_uint_t phase, ngx_uint_t opcode,
    u_char *sha256, ngx_msec_t ttl)
{
    ngx_uint_t                    i, slot;
    ngx_msec_t                    now;
    ngx_http_waf_shm_t           *shm;
    ngx_http_waf_fcache_t        *fc;
    ngx_http_waf_fcache_entry_t  *e, *victim, *empty, *soonest;

    shm = ngx_http_waf_shm();

    if (shm == NULL || shm->fcache == NULL || ttl == 0) {
        return;
    }

    fc      = shm->fcache;
    slot    = ngx_http_waf_fcache_slot(sha256);
    now     = ngx_current_msec;
    victim  = NULL;
    empty   = NULL;
    soonest = NULL;

    ngx_shmtx_lock(&shm->shpool->mutex);

    for (i = 0; i < NGX_HTTP_WAF_FCACHE_PROBE; i++) {
        e = &fc->entries[(slot + i) & (NGX_HTTP_WAF_FCACHE_ENTRIES - 1)];

        if (e->expires != 0 && e->route == route && e->phase == phase
            && e->opcode == opcode && ngx_memcmp(e->digest, sha256, 16) == 0)
        {
            victim = e;
            break;
        }

        if (e->expires == 0 || (ngx_msec_int_t) (e->expires - now) <= 0) {
            if (empty == NULL) {
                empty = e;
            }

            continue;
        }

        if (soonest == NULL
            || (ngx_msec_int_t) (e->expires - soonest->expires) < 0)
        {
            soonest = e;
        }
    }

    if (victim == NULL) {
        victim = (empty != NULL) ? empty : soonest;
    }

    ngx_memcpy(victim->digest, sha256, 16);
    victim->route   = route;
    victim->phase   = (uint8_t) phase;
    victim->opcode  = (uint8_t) opcode;
    victim->pad     = 0;
    victim->expires = now + ttl;

    (void) ngx_atomic_fetch_add(&fc->inserts, 1);

    ngx_shmtx_unlock(&shm->shpool->mutex);
}
