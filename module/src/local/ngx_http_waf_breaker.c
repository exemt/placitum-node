#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_BREAKER_CLOSED     0
#define NGX_HTTP_WAF_BREAKER_HALF       1
#define NGX_HTTP_WAF_BREAKER_OPEN       2

#define NGX_HTTP_WAF_BREAKER_MIN_SAMPLES  20


static ngx_http_waf_breaker_t *ngx_http_waf_breaker_get(ngx_uint_t index,
    ngx_http_waf_inspector_t *insp);
static void ngx_http_waf_breaker_open(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now);
static void ngx_http_waf_breaker_close(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now);


static ngx_http_waf_breaker_t *
ngx_http_waf_breaker_get(ngx_uint_t index, ngx_http_waf_inspector_t *insp)
{
    uint32_t                 tag;
    ngx_atomic_uint_t        old;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_breaker_t  *b;

    if (!insp->breaker || index >= NGX_HTTP_WAF_MAX_INSPECTORS) {
        return NULL;
    }

    shm = ngx_http_waf_shm();

    if (shm == NULL) {
        return NULL;
    }

    b   = &shm->breakers[index];
    tag = ngx_crc32_short(insp->name.data, insp->name.len);
    old = b->tag;

    /* the slot is keyed by position: another inspector there starts afresh */

    if (old != (ngx_atomic_uint_t) tag
        && ngx_atomic_cmp_set(&b->tag, old, (ngx_atomic_uint_t) tag))
    {
        b->state    = NGX_HTTP_WAF_BREAKER_CLOSED;
        b->probe_at = 0;
        b->epoch    = 0;
        b->attempts = 0;
        b->failures = 0;
    }

    return b;
}


ngx_int_t
ngx_http_waf_breaker_allow(ngx_uint_t index, ngx_http_waf_inspector_t *insp)
{
    ngx_msec_t               now, probe;
    ngx_http_waf_breaker_t  *b;

    b = ngx_http_waf_breaker_get(index, insp);

    if (b == NULL || b->state == NGX_HTTP_WAF_BREAKER_CLOSED) {
        return NGX_OK;
    }

    now   = ngx_current_msec;
    probe = (ngx_msec_t) b->probe_at;

    if ((ngx_msec_int_t) (now - probe) >= 0
        && ngx_atomic_cmp_set(&b->probe_at, (ngx_atomic_uint_t) probe,
                              (ngx_atomic_uint_t) (now + insp->breaker_probe)))
    {
        b->state = NGX_HTTP_WAF_BREAKER_HALF;

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "waf: circuit breaker probe for inspector \"%V\"",
                      &insp->name);

        return NGX_OK;
    }

    return NGX_DECLINED;
}


void
ngx_http_waf_breaker_result(ngx_uint_t index, ngx_http_waf_inspector_t *insp,
    ngx_uint_t timed_out)
{
    ngx_msec_t               now, epoch;
    ngx_uint_t               state, attempts, failures;
    ngx_http_waf_breaker_t  *b;

    b = ngx_http_waf_breaker_get(index, insp);

    if (b == NULL) {
        return;
    }

    now = ngx_current_msec;

    epoch = (ngx_msec_t) b->epoch;

    if ((ngx_msec_int_t) (now - epoch) >= (ngx_msec_int_t) insp->breaker_window
        && ngx_atomic_cmp_set(&b->epoch, (ngx_atomic_uint_t) epoch,
                              (ngx_atomic_uint_t) now))
    {
        b->attempts = 0;
        b->failures = 0;
    }

    (void) ngx_atomic_fetch_add(&b->attempts, 1);

    if (timed_out) {
        (void) ngx_atomic_fetch_add(&b->failures, 1);
    }

    state = (ngx_uint_t) b->state;

    if (state == NGX_HTTP_WAF_BREAKER_HALF) {

        if (timed_out) {
            ngx_http_waf_breaker_open(b, insp, now);

        } else {
            ngx_http_waf_breaker_close(b, insp, now);
        }

        return;
    }

    if (state == NGX_HTTP_WAF_BREAKER_OPEN) {
        return;
    }

    attempts = (ngx_uint_t) b->attempts;
    failures = (ngx_uint_t) b->failures;

    if (attempts < NGX_HTTP_WAF_BREAKER_MIN_SAMPLES || failures == 0) {
        return;
    }

    if (failures * 10000 / attempts >= insp->breaker_threshold) {
        ngx_http_waf_breaker_open(b, insp, now);
    }
}


static void
ngx_http_waf_breaker_open(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now)
{
    b->probe_at = (ngx_atomic_uint_t) (now + insp->breaker_probe);
    b->epoch    = (ngx_atomic_uint_t) now;
    b->attempts = 0;
    b->failures = 0;
    b->state    = NGX_HTTP_WAF_BREAKER_OPEN;

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "waf: circuit breaker opened for inspector \"%V\", "
                  "probing every %M ms", &insp->name, insp->breaker_probe);
}


static void
ngx_http_waf_breaker_close(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now)
{
    b->epoch    = (ngx_atomic_uint_t) now;
    b->attempts = 0;
    b->failures = 0;
    b->state    = NGX_HTTP_WAF_BREAKER_CLOSED;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "waf: circuit breaker closed for inspector \"%V\"",
                  &insp->name);
}
