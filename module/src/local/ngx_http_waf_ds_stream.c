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

#define NGX_HTTP_WAF_DS_RETRY         5000

#define NGX_HTTP_WAF_DS_SILENCE       6000

#define NGX_HTTP_WAF_DS_SNAPSHOT_WAIT 10000

#define NGX_HTTP_WAF_DS_OBJECT_MAX    (512 * 1024 * 1024)
#define NGX_HTTP_WAF_DS_PACKAGE_MAX   (64 * 1024 * 1024)

#define NGX_HTTP_WAF_DS_KEY_MAX       256


typedef struct {
    ngx_http_waf_dataset_t    *ds;

    ngx_uint_t                 state;

    ngx_pool_t                *pool;
    ngx_http_waf_body_op_t    *op;
    ngx_uint_t                 kind;
    ngx_uint_t                 fetch_seq;
    uint64_t                   fetching;

    uint64_t                   want_epoch;
    uint64_t                   want;
    uint64_t                   want_hash;
    ngx_uint_t                 want_has_hash;

    ngx_event_t                timer;
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


static void
ngx_http_waf_ds_stream_kick(ngx_http_waf_ds_stream_t *st)
{
    uint64_t  epoch, seq;

    ngx_http_waf_dataset_state(ngx_http_waf_ds_stream_pos(st), &epoch, &seq);

    if (epoch == 0) {
        if (ngx_http_waf_ds_stream_snapshot(st, 1) == NGX_OK) {
            return;
        }

        st->state = NGX_HTTP_WAF_DS_ST_IDLE;
        ngx_http_waf_ds_stream_watch(st);
        return;
    }

    ngx_http_waf_ds_stream_settle(st);
}


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

    if (st->timer.timer_set) {
        ngx_del_timer(&st->timer);
    }

    ngx_add_timer(&st->timer, NGX_HTTP_WAF_DS_RETRY);

    return NGX_OK;
}


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
                                        NGX_HTTP_WAF_DS_SILENCE, &first);

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
        return;

    default:
        ngx_http_waf_ds_stream_kick(st);
    }
}


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

    (void) ngx_http_waf_dataset_seen(index, 1, 0, NULL);

    if (n.op != NGX_HTTP_WAF_DS_OP_DIFF && n.op != NGX_HTTP_WAF_DS_OP_TICK) {
        return;
    }

    ngx_http_waf_dataset_state(index, &epoch, &seq);

    if (n.epoch != st->want_epoch || n.seq > st->want) {
        st->want_epoch    = n.epoch;
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

        if (rc == NGX_HTTP_WAF_DS_FOREIGN
            || (rc == NGX_HTTP_WAF_DS_DIVERGED
                && !ngx_http_waf_dataset_snap_bad(index)))
        {
            (void) ngx_http_waf_ds_stream_snapshot(st, 1);
        }
    }
}


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
        return;
    }

    if (payload->len == 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: no responders for dataset \"%V\"; is keeper up?",
                      &st->ds->name);

        ngx_http_waf_ds_stream_reset(st);
        return;
    }

    (void) ngx_http_waf_dataset_seen(index, 1, 0, NULL);

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


static ngx_int_t
ngx_http_waf_ds_stream_fetch(ngx_http_waf_ds_stream_t *st, ngx_str_t *key,
    ngx_uint_t kind, uint64_t seq)
{
    off_t                    max;
    ngx_int_t                rc;
    ngx_str_t                k;
    ngx_uint_t               seq_no;
    ngx_pool_t              *pool;

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

    seq_no = ++st->fetch_seq;

    if (st->timer.timer_set) {
        ngx_del_timer(&st->timer);
    }

    max = (kind == NGX_HTTP_WAF_DS_FETCH_SNAPSHOT) ? NGX_HTTP_WAF_DS_OBJECT_MAX
                                                   : NGX_HTTP_WAF_DS_PACKAGE_MAX;

    /* st->op is set before the driver runs: it may complete right away */

    rc = ngx_http_waf_sets_get(&k, max, pool, ngx_cycle->log,
                               ngx_http_waf_ds_stream_fetched, st, &st->op);

    if (st->fetch_seq != seq_no || st->state != NGX_HTTP_WAF_DS_ST_FETCH) {
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": no waf_sets_store to read %V from",
                      &st->ds->name, key);
        ngx_http_waf_ds_stream_reset(st);
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        ngx_http_waf_ds_stream_fetched(st->op);
    }

    return NGX_OK;
}


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

    if (st->want_epoch != epoch || seq >= st->want) {
        if (st->want_epoch == epoch && st->want_has_hash && seq == st->want) {
            (void) ngx_http_waf_dataset_verify(ngx_http_waf_ds_stream_pos(st),
                                               epoch, seq, st->want_hash);
        }

        ngx_http_waf_ds_stream_settle(st);
        return;
    }

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


static void
ngx_http_waf_ds_stream_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_int_t                  rc, status;
    ngx_str_t                  data;
    ngx_uint_t                 index, kind;
    ngx_http_waf_ds_stream_t  *st = op->data_ctx;

    if (st->op != op || st->state != NGX_HTTP_WAF_DS_ST_FETCH) {
        return;
    }

    index  = ngx_http_waf_ds_stream_pos(st);
    kind   = st->kind;
    status = op->status;
    data   = op->data;

    st->op    = NULL;
    st->state = NGX_HTTP_WAF_DS_ST_READY;

    if (status == NGX_DECLINED) {

        if (kind == NGX_HTTP_WAF_DS_FETCH_PACKAGE) {
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
        case NGX_HTTP_WAF_DS_STALE:
        case NGX_HTTP_WAF_DS_BUSY:
            ngx_http_waf_ds_stream_settle(st);

            if (st->want != 0) {
                ngx_http_waf_ds_stream_catch_up(st);
            }

            return;

        default:
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
        ngx_http_waf_ds_stream_catch_up(st);
        return;

    case NGX_HTTP_WAF_DS_BUSY:
        ngx_http_waf_ds_stream_settle(st);
        return;

    case NGX_HTTP_WAF_DS_DIVERGED:

        if (ngx_http_waf_dataset_snap_bad(index)) {
            ngx_http_waf_ds_stream_catch_up(st);
            return;
        }

        /* fall through */

    default:
        if (ngx_http_waf_ds_stream_snapshot(st, 1) != NGX_OK) {
            ngx_http_waf_ds_stream_settle(st);
        }

        return;
    }
}
