#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_WS_HEADER_MAX     14

#define NGX_HTTP_WAF_WS_CONTROL_MAX    125
#define NGX_HTTP_WAF_WS_REASON_MAX     123

#define NGX_HTTP_WAF_WS_OP_CONT        0x0
#define NGX_HTTP_WAF_WS_OP_TEXT        0x1
#define NGX_HTTP_WAF_WS_OP_BINARY      0x2
#define NGX_HTTP_WAF_WS_OP_CLOSE       0x8
#define NGX_HTTP_WAF_WS_OP_PING        0x9
#define NGX_HTTP_WAF_WS_OP_PONG        0xa

#define NGX_HTTP_WAF_WS_CLOSE_PROTOCOL 1002
#define NGX_HTTP_WAF_WS_CLOSE_POLICY   1008
#define NGX_HTTP_WAF_WS_CLOSE_TOO_BIG  1009
#define NGX_HTTP_WAF_WS_CLOSE_INTERNAL 1011

#define NGX_HTTP_WAF_FRAME_BUF_MIN     4096

#define NGX_HTTP_WAF_FRAME_PASS_BUF    16384

#define NGX_HTTP_WAF_FRAME_POOL        4096

#define NGX_HTTP_WAF_FRAME_SLACK       8


#define NGX_HTTP_WAF_FRAME_INSPECT     0
#define NGX_HTTP_WAF_FRAME_JOURNAL     1
#define NGX_HTTP_WAF_FRAME_PASS        2


typedef struct {
    ngx_uint_t                 phase;
    ngx_uint_t                 mode;

    ngx_buf_t                 *in;
    u_char                    *cleared;

    size_t                     held;
    off_t                      skip;
    size_t                     drop;
    ngx_buf_t                 *out;

    uint64_t                   seq;
    uint64_t                   inspected;
    uint64_t                   denied;
    uint64_t                   rewritten;
    off_t                      bytes;

    ngx_uint_t                 opcode;
    u_char                     mask[4];

    unsigned                   fin:1;
    unsigned                   masked:1;
    unsigned                   rsv_warned:1;

    uint64_t                   held_seq;
    ngx_uint_t                 fragments;

    unsigned                   msg:1;
    unsigned                   msg_skip:1;
    ngx_uint_t                 msg_opcode;
    size_t                     msg_hlen;
    size_t                     msg_len;
    ngx_uint_t                 msg_fragments;
    uint64_t                   msg_seq;
    u_char                     msg_key[4];
    uint64_t                   reassembled;

    ngx_uint_t                 ctrl_tokens;
    ngx_msec_t                 ctrl_last;
    uint64_t                   ctrl_dropped;
    unsigned                   ctrl_warned:1;

    uint64_t                   cached;
} ngx_http_waf_frame_dir_t;


typedef struct {
    ngx_http_request_t        *r;
    ngx_http_waf_ctx_t        *ctx;

    ngx_msec_t                 started;

    ngx_http_waf_frame_dir_t   c2s;
    ngx_http_waf_frame_dir_t   s2c;
    ngx_http_waf_frame_dir_t  *cur;

    ngx_pool_t                *pool;
    ngx_pool_t                *saved_pool;

    ngx_chain_t                body;
    ngx_buf_t                  body_buf;

    ngx_str_t                  subprotocol;
    u_char                     conn_id[NGX_HTTP_WAF_RAY_HEX_LEN];

    ngx_uint_t                 rewrite_index;

    ngx_uint_t                 close_code;
    u_char                     close_reason[NGX_HTTP_WAF_WS_REASON_MAX];
    size_t                     close_reason_len;
    const char                *close_why;

    unsigned                   settled:1;
    unsigned                   fetching:1;
    unsigned                   in_stack:1;
    unsigned                   closing:1;
    unsigned                   kick:1;

    uint32_t                   route_hash;
    u_char                     sha256[32];
    unsigned                   sha_set:1;
    unsigned                   cached:1;

    u_char                     size_buf[NGX_OFF_T_LEN];

    ngx_array_t               *saved_actions;

    ngx_array_t               *saved_markers;

    ngx_http_waf_control_t     conn_ctl[NGX_HTTP_WAF_NPHASE];

    ngx_http_waf_audit_ovr_t   conn_audit;
    unsigned                   ctl_init:1;
} ngx_http_waf_frame_t;


static void ngx_http_waf_frame_read_downstream(ngx_http_request_t *r);
static void ngx_http_waf_frame_write_downstream(ngx_http_request_t *r);
static void ngx_http_waf_frame_read_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_waf_frame_write_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_waf_frame_process(ngx_http_request_t *r,
    ngx_uint_t from_upstream);
static void ngx_http_waf_frame_run(ngx_http_waf_frame_t *fc);
static void ngx_http_waf_frame_pump(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d);
static ngx_int_t ngx_http_waf_frame_parse(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d);
static ngx_uint_t ngx_http_waf_frame_mode(ngx_http_request_t *r,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t phase);
static ngx_int_t ngx_http_waf_frame_begin(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d, u_char *payload, size_t len, u_char *key);
static ngx_int_t ngx_http_waf_frame_inspect(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d, u_char *payload, size_t len, u_char *key);
static ngx_uint_t ngx_http_waf_frame_journal_wanted(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d);
static ngx_int_t ngx_http_waf_frame_journal(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d, u_char *payload, size_t len, u_char *key);
static ngx_int_t ngx_http_waf_frame_outcome(ngx_http_waf_frame_t *fc,
    ngx_int_t rc);
static void ngx_http_waf_frame_apply(ngx_http_waf_frame_t *fc, ngx_int_t rc);
static void ngx_http_waf_frame_settle(ngx_http_waf_frame_t *fc, ngx_int_t rc);
static ngx_int_t ngx_http_waf_frame_rewrite(ngx_http_waf_frame_t *fc);
static void ngx_http_waf_frame_fetched(ngx_http_waf_body_op_t *op);
static ngx_int_t ngx_http_waf_frame_swap(ngx_http_waf_frame_t *fc,
    ngx_http_waf_body_op_t *op);
static void ngx_http_waf_frame_rewrite_fail(ngx_http_waf_frame_t *fc,
    const char *why);
static void ngx_http_waf_frame_end(ngx_http_waf_frame_t *fc);
static void ngx_http_waf_frame_deny_close(ngx_http_waf_frame_t *fc);
static void ngx_http_waf_frame_set_close(ngx_http_waf_frame_t *fc,
    ngx_uint_t code, const char *reason, size_t len, const char *why);
static void ngx_http_waf_frame_finalize(ngx_http_waf_frame_t *fc,
    ngx_int_t rc);
static void ngx_http_waf_frame_events(ngx_http_waf_frame_t *fc);
static void ngx_http_waf_frame_header_out(ngx_http_request_t *r,
    ngx_http_waf_frame_t *fc);
static ngx_int_t ngx_http_waf_frame_dir_init(ngx_http_request_t *r,
    ngx_http_waf_frame_dir_t *d, ngx_uint_t phase, ngx_uint_t mode,
    ngx_buf_t *seed);
static void ngx_http_waf_frame_ends(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d, ngx_connection_t **src,
    ngx_connection_t **dst);
static ngx_uint_t ngx_http_waf_frame_idle(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d);
static ngx_str_t *ngx_http_waf_frame_opcode_name(ngx_uint_t opcode);
static ngx_uint_t ngx_http_waf_frame_ctrl_allowed(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d);
static void ngx_http_waf_frame_cut(ngx_http_waf_frame_dir_t *d, u_char *p,
    size_t len);
static void ngx_http_waf_frame_hoist(ngx_http_waf_frame_dir_t *d, u_char *p,
    size_t len);
static void ngx_http_waf_frame_msg_append(ngx_http_waf_frame_dir_t *d,
    u_char *p, size_t hlen, size_t plen);
static size_t ngx_http_waf_frame_msg_seal(ngx_http_waf_frame_dir_t *d,
    ngx_uint_t fin);
static u_char *ngx_http_waf_frame_vars_save(ngx_http_waf_frame_t *fc);
static void ngx_http_waf_frame_vars_restore(ngx_http_waf_frame_t *fc,
    u_char *map);
static ngx_uint_t ngx_http_waf_frame_cacheable(ngx_http_waf_frame_t *fc);


static ngx_str_t  ngx_http_waf_frame_opcodes[] = {
    ngx_string("continuation"),
    ngx_string("text"),
    ngx_string("binary"),
};

static ngx_str_t  ngx_http_waf_frame_opcode_other = ngx_string("other");

static ngx_str_t  ngx_http_waf_frame_dir_c2s = ngx_string("c2s");
static ngx_str_t  ngx_http_waf_frame_dir_s2c = ngx_string("s2c");

static ngx_str_t  ngx_http_waf_frame_rewrite_fail_code =
                                                  ngx_string("REWRITE_FAILED");

static ngx_str_t  ngx_http_waf_frame_cache_rule = ngx_string("FRAME_CACHE");


ngx_uint_t
ngx_http_waf_frame_wanted(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (ngx_http_waf_phase_inspected(wlcf, NGX_HTTP_WAF_PHASE_FRAME_C2S)
        || ngx_http_waf_phase_inspected(wlcf, NGX_HTTP_WAF_PHASE_FRAME_S2C))
    {
        return 1;
    }

    return wlcf->enable
           && wlcf->audit_frames != NGX_HTTP_WAF_AUDIT_FRAMES_OFF
           && ngx_http_waf_audit_enabled();
}


static ngx_uint_t
ngx_http_waf_frame_mode(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (ngx_http_waf_phase_inspected(wlcf, phase)) {
        return NGX_HTTP_WAF_FRAME_INSPECT;
    }

    if (!ngx_http_waf_audit_enabled()
        || wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_OFF)
    {
        return NGX_HTTP_WAF_FRAME_PASS;
    }

    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_ALL
        || ctx->audit_ovr[NGX_HTTP_WAF_OVR_REQUEST].audit.set
           == NGX_HTTP_WAF_SET_ON)
    {
        return NGX_HTTP_WAF_FRAME_JOURNAL;
    }

    return NGX_HTTP_WAF_FRAME_PASS;
}


ngx_int_t
ngx_http_waf_frame_attach(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
    size_t                    rest;
    ngx_connection_t         *c = r->connection;
    ngx_http_upstream_t      *u = r->upstream;
    ngx_http_waf_frame_t     *fc;

    if (u == NULL || u->peer.connection == NULL) {
        return NGX_OK;
    }

    fc = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_frame_t));
    if (fc == NULL) {
        return NGX_ERROR;
    }

    fc->r       = r;
    fc->ctx     = ctx;
    fc->started = ngx_current_msec;

    ngx_memcpy(fc->conn_id, ctx->ray_hex, NGX_HTTP_WAF_RAY_HEX_LEN);

    ngx_http_waf_frame_header_out(r, fc);

    if (ngx_http_waf_frame_dir_init(r, &fc->c2s, NGX_HTTP_WAF_PHASE_FRAME_C2S,
                                    ngx_http_waf_frame_mode(r, ctx,
                                        NGX_HTTP_WAF_PHASE_FRAME_C2S),
                                    r->header_in)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_waf_frame_dir_init(r, &fc->s2c, NGX_HTTP_WAF_PHASE_FRAME_S2C,
                                    ngx_http_waf_frame_mode(r, ctx,
                                        NGX_HTTP_WAF_PHASE_FRAME_S2C),
                                    &u->buffer)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    fc->c2s.masked = 1;

    ctx->keep_pool = r->pool;

    {
        uint32_t                   crc;
        ngx_http_waf_loc_conf_t   *wlcf;
        ngx_http_core_srv_conf_t  *cscf;
        ngx_http_core_loc_conf_t  *clcf;

        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_crc32_init(crc);
        ngx_crc32_update(&crc, cscf->server_name.data, cscf->server_name.len);
        ngx_crc32_update(&crc, (u_char *) "|", 1);
        ngx_crc32_update(&crc, clcf->name.data, clcf->name.len);
        ngx_crc32_update(&crc, (u_char *) "|", 1);
        ngx_crc32_update(&crc, wlcf->route_id.data, wlcf->route_id.len);
        ngx_crc32_final(crc);

        fc->route_hash = crc;
    }

    ctx->frame = fc;

    r->read_event_handler  = ngx_http_waf_frame_read_downstream;
    r->write_event_handler = ngx_http_waf_frame_write_downstream;
    u->read_event_handler  = ngx_http_waf_frame_read_upstream;
    u->write_event_handler = ngx_http_waf_frame_write_upstream;

    c->read->ready = 0;
    fc->kick       = 1;

    ngx_post_event(c->read, &ngx_posted_events);

    rest = (size_t) (fc->s2c.in->last - fc->s2c.in->pos);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "waf: frame phase attached, subprotocol \"%V\", "
                  "buffers c2s %uz s2c %uz, %uz bytes after 101, conn %*s",
                  &fc->subprotocol,
                  (size_t) (fc->c2s.in->end - fc->c2s.in->start),
                  (size_t) (fc->s2c.in->end - fc->s2c.in->start), rest,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_frame_dir_init(ngx_http_request_t *r, ngx_http_waf_frame_dir_t *d,
    ngx_uint_t phase, ngx_uint_t mode, ngx_buf_t *seed)
{
    size_t                    size, rest;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (mode == NGX_HTTP_WAF_FRAME_PASS) {
        rest = (seed != NULL) ? (size_t) (seed->last - seed->pos) : 0;
        size = ngx_max(NGX_HTTP_WAF_FRAME_PASS_BUF,
                       rest + NGX_HTTP_WAF_FRAME_SLACK);

    } else {
        size = wlcf->body_limit[phase] + 2 * NGX_HTTP_WAF_WS_HEADER_MAX
               + NGX_HTTP_WAF_FRAME_SLACK;
    }

    if (size < NGX_HTTP_WAF_FRAME_BUF_MIN) {
        size = NGX_HTTP_WAF_FRAME_BUF_MIN;
    }

    d->phase = phase;
    d->mode  = mode;

    d->in = ngx_create_temp_buf(r->pool, size);
    if (d->in == NULL) {
        return NGX_ERROR;
    }

    d->cleared = d->in->start;

    rest = (seed != NULL) ? (size_t) (seed->last - seed->pos) : 0;

    if (rest != 0) {
        if (rest > size) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "waf: %uz bytes of %s frames arrived with the "
                          "handshake, more than the frame buffer holds; "
                          "closing",
                          rest,
                          phase == NGX_HTTP_WAF_PHASE_FRAME_C2S ? "client"
                                                                : "upstream");
            return NGX_ERROR;
        }

        ngx_memcpy(d->in->start, seed->pos, rest);
        d->in->last = d->in->start + rest;
        seed->pos   = seed->last;
    }

    return NGX_OK;
}


static void
ngx_http_waf_frame_header_out(ngx_http_request_t *r, ngx_http_waf_frame_t *fc)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_out.headers.part;
    h    = part->elts;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == sizeof("Sec-WebSocket-Protocol") - 1
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "Sec-WebSocket-Protocol",
                               h[i].key.len) == 0)
        {
            fc->subprotocol = h[i].value;
            continue;
        }

        if (h[i].key.len == sizeof("Sec-WebSocket-Extensions") - 1
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "Sec-WebSocket-Extensions",
                               h[i].key.len) == 0
            && h[i].value.len != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "waf: the application negotiated \"%V\"; frames "
                          "with rsv bits pass uninspected on this "
                          "connection, ray %*s", &h[i].value,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);
        }
    }
}


static void
ngx_http_waf_frame_read_downstream(ngx_http_request_t *r)
{
    ngx_http_waf_ctx_t    *ctx = ngx_http_waf_get_ctx(r);
    ngx_http_waf_frame_t  *fc;

    if (ctx == NULL || ctx->frame == NULL) {
        return;
    }

    fc = ctx->frame;

    if (fc->kick) {
        fc->kick = 0;
        r->connection->read->ready = 1;
    }

    ngx_http_waf_frame_process(r, 0);
}


static void
ngx_http_waf_frame_write_downstream(ngx_http_request_t *r)
{
    ngx_http_waf_frame_process(r, 1);
}


static void
ngx_http_waf_frame_read_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_http_waf_frame_process(r, 1);
}


static void
ngx_http_waf_frame_write_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_waf_frame_process(r, 0);
}


static void
ngx_http_waf_frame_process(ngx_http_request_t *r, ngx_uint_t from_upstream)
{
    ngx_connection_t      *c, *upstream;
    ngx_http_upstream_t   *u;
    ngx_http_waf_ctx_t    *ctx;
    ngx_http_waf_frame_t  *fc;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->frame == NULL) {
        return;
    }

    fc = ctx->frame;

    if (fc->closing) {
        return;
    }

    c        = r->connection;
    u        = r->upstream;
    upstream = u->peer.connection;

    if (c->write->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        fc->close_why = "client timed out";
        ngx_http_waf_frame_finalize(fc, NGX_ERROR);
        return;
    }

    if (upstream->read->timedout || upstream->write->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        fc->close_why = "upstream timed out";
        ngx_http_waf_frame_finalize(fc, NGX_ERROR);
        return;
    }

    ngx_http_waf_frame_pump(fc, from_upstream ? &fc->s2c : &fc->c2s);

    if (fc->closing) {
        ngx_http_waf_frame_finalize(fc, fc->close_code != 0 ? NGX_OK
                                                            : NGX_ERROR);
        return;
    }

    ngx_http_waf_frame_events(fc);
}


static void
ngx_http_waf_frame_run(ngx_http_waf_frame_t *fc)
{
    ngx_http_waf_frame_pump(fc, &fc->c2s);

    if (!fc->closing) {
        ngx_http_waf_frame_pump(fc, &fc->s2c);
    }

    if (fc->closing) {
        ngx_http_waf_frame_finalize(fc, fc->close_code != 0 ? NGX_OK
                                                            : NGX_ERROR);
        return;
    }

    ngx_http_waf_frame_events(fc);
}


static void
ngx_http_waf_frame_ends(ngx_http_waf_frame_t *fc, ngx_http_waf_frame_dir_t *d,
    ngx_connection_t **src, ngx_connection_t **dst)
{
    if (d == &fc->c2s) {
        *src = fc->r->connection;
        *dst = fc->r->upstream->peer.connection;

    } else {
        *src = fc->r->upstream->peer.connection;
        *dst = fc->r->connection;
    }
}


static void
ngx_http_waf_frame_pump(ngx_http_waf_frame_t *fc, ngx_http_waf_frame_dir_t *d)
{
    size_t                size, rest;
    ssize_t               n;
    ngx_int_t             rc;
    ngx_buf_t            *b = d->in;
    ngx_connection_t     *src, *dst;
    ngx_http_upstream_t  *u = fc->r->upstream;

    ngx_http_waf_frame_ends(fc, d, &src, &dst);

    for ( ;; ) {

        rc = NGX_AGAIN;

        if ((fc->cur == NULL || d->mode == NGX_HTTP_WAF_FRAME_PASS)
            && d->drop == 0
            && (d->out == NULL || d->out->pos == d->out->last))
        {
            rc = ngx_http_waf_frame_parse(fc, d);

            if (fc->closing) {
                return;
            }
        }

        size = d->cleared - b->pos;

        if (size && dst->write->ready) {

            n = dst->send(dst, b->pos, size);

            if (n == NGX_ERROR) {
                fc->close_why = (d == &fc->c2s) ? "upstream send failed"
                                                : "client send failed";
                fc->closing   = 1;
                return;
            }

            if (n > 0) {
                b->pos   += n;
                d->bytes += n;
            }
        }

        if (d->drop != 0 && b->pos == d->cleared) {
            b->pos    += d->drop;
            d->cleared = b->pos;
            d->drop    = 0;
        }

        if (d->drop == 0 && d->out != NULL && d->out->pos != d->out->last
            && dst->write->ready)
        {
            n = dst->send(dst, d->out->pos, d->out->last - d->out->pos);

            if (n == NGX_ERROR) {
                fc->close_why = (d == &fc->c2s) ? "upstream send failed"
                                                : "client send failed";
                fc->closing   = 1;
                return;
            }

            if (n > 0) {
                d->out->pos += n;
                d->bytes    += n;

                if (d->out->pos == d->out->last) {
                    d->out->pos  = d->out->start;
                    d->out->last = d->out->start;

                    continue;
                }
            }
        }

        if (b->pos == d->cleared && fc->cur != d && d->drop == 0
            && b->pos != b->start)
        {
            rest = (size_t) (b->last - b->pos);

            if (rest != 0) {
                ngx_memmove(b->start, b->pos, rest);
            }

            b->pos     = b->start;
            d->cleared = b->start;
            b->last    = b->start + rest;
        }

        size = (size_t) (b->end - b->last);
        size = (size > NGX_HTTP_WAF_FRAME_SLACK)
               ? size - NGX_HTTP_WAF_FRAME_SLACK : 0;

        if (size && src->read->ready) {

            n = src->recv(src, b->last, size);

            if (n > 0) {
                b->last += n;

                if (d == &fc->s2c && u->state != NULL) {
                    u->state->bytes_received += n;
                }

                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        if (rc == NGX_OK && fc->cur == NULL) {
            continue;
        }

        break;
    }
}


static ngx_int_t
ngx_http_waf_frame_parse(ngx_http_waf_frame_t *fc, ngx_http_waf_frame_dir_t *d)
{
    u_char                   *p, b0, b1;
    off_t                     take;
    size_t                    avail, hlen, limit, hold, total;
    uint64_t                  plen;
    ngx_uint_t                i, fin, rsv, opcode, masked, policy, assemble;
    ngx_buf_t                *b = d->in;
    ngx_log_t                *log = fc->r->connection->log;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf     = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);
    assemble = (wlcf->frame_reassemble
                && d->mode == NGX_HTTP_WAF_FRAME_INSPECT) ? 1 : 0;

    for ( ;; ) {
        hold  = d->msg ? d->msg_hlen + d->msg_len : 0;
        p     = d->cleared + hold;
        avail = (size_t) (b->last - p);

        if (d->skip > 0) {
            take = ngx_min(d->skip, (off_t) avail);

            d->cleared += take;
            d->skip    -= take;

            if (d->skip > 0) {
                return NGX_AGAIN;
            }

            continue;
        }

        if (avail < 2) {
            return NGX_AGAIN;
        }

        b0 = p[0];
        b1 = p[1];

        fin    = (b0 & 0x80) != 0;
        rsv    = (b0 & 0x70);
        opcode = (b0 & 0x0f);
        masked = (b1 & 0x80) != 0;
        plen   = (b1 & 0x7f);
        hlen   = 2;

        if (plen == 126) {
            hlen += 2;

        } else if (plen == 127) {
            hlen += 8;
        }

        if (masked) {
            hlen += 4;
        }

        if (avail < hlen) {
            return NGX_AGAIN;
        }

        if (plen == 126) {
            plen = ((uint64_t) p[2] << 8) | p[3];

        } else if (plen == 127) {
            plen = 0;

            for (i = 0; i < 8; i++) {
                plen = (plen << 8) | p[2 + i];
            }

            if (plen & 0x8000000000000000ULL) {
                ngx_http_waf_frame_set_close(fc,
                    NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                    "invalid length", sizeof("invalid length") - 1,
                    "frame length has the top bit set");
                return NGX_OK;
            }
        }

        if (masked != d->masked) {
            if (d->masked) {
                ngx_http_waf_frame_set_close(fc,
                    NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                    "unmasked frame", sizeof("unmasked frame") - 1,
                    "client frame is not masked");

            } else {
                ngx_http_waf_frame_set_close(fc,
                    NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                    "masked frame", sizeof("masked frame") - 1,
                    "upstream frame is masked");
            }

            return NGX_OK;
        }

        if (opcode >= 0x8) {
            if (!fin || plen > NGX_HTTP_WAF_WS_CONTROL_MAX
                || (opcode != NGX_HTTP_WAF_WS_OP_CLOSE
                    && opcode != NGX_HTTP_WAF_WS_OP_PING
                    && opcode != NGX_HTTP_WAF_WS_OP_PONG))
            {
                ngx_http_waf_frame_set_close(fc,
                    NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                    "bad control frame", sizeof("bad control frame") - 1,
                    "malformed control frame");
                return NGX_OK;
            }

            if (avail < hlen + plen) {
                return NGX_AGAIN;
            }

            d->seq++;

            if (opcode != NGX_HTTP_WAF_WS_OP_CLOSE
                && !ngx_http_waf_frame_ctrl_allowed(fc, d))
            {
                ngx_http_waf_frame_cut(d, p, hlen + (size_t) plen);
                continue;
            }

            if (hold != 0) {
                ngx_http_waf_frame_hoist(d, p, hlen + (size_t) plen);
            }

            d->cleared += hlen + plen;
            continue;
        }

        if (opcode > NGX_HTTP_WAF_WS_OP_BINARY) {
            ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                                         "reserved opcode",
                                         sizeof("reserved opcode") - 1,
                                         "reserved data opcode");
            return NGX_OK;
        }

        if (d->mode == NGX_HTTP_WAF_FRAME_PASS) {
            d->seq++;
            d->skip = (off_t) (hlen + plen);
            continue;
        }

        limit  = wlcf->body_limit[d->phase];
        policy = wlcf->body_limit_policy[d->phase];

        if (assemble && opcode == NGX_HTTP_WAF_WS_OP_CONT) {

            if (d->msg_skip) {
                if (fin) {
                    d->msg_skip = 0;
                }

                d->seq++;
                d->skip = (off_t) (hlen + plen);
                continue;
            }

            if (!d->msg) {
                ngx_http_waf_frame_set_close(fc,
                    NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                    "unexpected continuation",
                    sizeof("unexpected continuation") - 1,
                    "continuation frame without a message");
                return NGX_OK;
            }

        } else if (assemble && (d->msg || d->msg_skip)) {
            ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_PROTOCOL,
                                         "message interrupted",
                                         sizeof("message interrupted") - 1,
                                         "data frame inside a fragmented "
                                         "message");
            return NGX_OK;
        }

        total = (size_t) plen + (d->msg ? d->msg_len : 0);

        if (total > limit) {
            if (policy == NGX_HTTP_WAF_POLICY_BLOCK
                && d->mode == NGX_HTTP_WAF_FRAME_INSPECT)
            {
                ngx_log_error(NGX_LOG_INFO, log, 0,
                              "waf: %V %s of %uz bytes exceeds "
                              "waf_body_limit frame %uz, closing, conn %*s",
                              d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                            : &ngx_http_waf_frame_dir_s2c,
                              d->msg ? "message" : "frame", total, limit,
                              (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);

                if (d->msg) {
                    ngx_http_waf_frame_set_close(fc,
                        NGX_HTTP_WAF_WS_CLOSE_TOO_BIG,
                        "message too big", sizeof("message too big") - 1,
                        "message exceeds waf_body_limit");

                } else {
                    ngx_http_waf_frame_set_close(fc,
                        NGX_HTTP_WAF_WS_CLOSE_TOO_BIG,
                        "frame too big", sizeof("frame too big") - 1,
                        "frame exceeds waf_body_limit");
                }

                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "waf: %V %s of %uz bytes exceeds waf_body_limit "
                          "frame %uz, passed uninspected, conn %*s",
                          d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                        : &ngx_http_waf_frame_dir_s2c,
                          d->msg ? "message" : "frame", total, limit,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);

            if (d->msg) {
                d->cleared += ngx_http_waf_frame_msg_seal(d, 0) + d->msg_len;
                d->msg_skip = fin ? 0 : 1;

            } else if (assemble && !fin
                       && opcode != NGX_HTTP_WAF_WS_OP_CONT)
            {
                d->msg_skip = 1;
            }

            d->seq++;
            d->skip = (off_t) (hlen + plen);
            continue;
        }

        if (rsv != 0) {
            if (!d->rsv_warned) {
                d->rsv_warned = 1;

                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "waf: %V frame with rsv bits (extension data) "
                              "passed uninspected; strip the extension on "
                              "the handshake, conn %*s",
                              d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                            : &ngx_http_waf_frame_dir_s2c,
                              (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);
            }

            if (d->msg) {
                d->cleared += ngx_http_waf_frame_msg_seal(d, 0) + d->msg_len;
                d->msg_skip = fin ? 0 : 1;

            } else if (assemble && !fin
                       && opcode != NGX_HTTP_WAF_WS_OP_CONT)
            {
                d->msg_skip = 1;
            }

            d->seq++;
            d->skip = (off_t) (hlen + plen);
            continue;
        }

        if (avail < hlen + plen) {
            return NGX_AGAIN;
        }

        d->seq++;

        if (d->mode == NGX_HTTP_WAF_FRAME_JOURNAL) {

            if (!ngx_http_waf_frame_journal_wanted(fc, d)) {
                d->cleared += hlen + plen;
                continue;
            }

            d->held      = hlen + (size_t) plen;
            d->opcode    = opcode;
            d->fin       = fin ? 1 : 0;
            d->fragments = 1;
            d->held_seq  = d->seq;

            (void) ngx_http_waf_frame_journal(fc, d, p + hlen, (size_t) plen,
                                              masked ? p + hlen - 4 : NULL);

            return NGX_OK;
        }

        if (assemble && !fin && opcode != NGX_HTTP_WAF_WS_OP_CONT) {
            d->msg           = 1;
            d->msg_opcode    = opcode;
            d->msg_hlen      = hlen;
            d->msg_len       = (size_t) plen;
            d->msg_fragments = 1;
            d->msg_seq       = d->seq;

            if (masked) {
                ngx_memcpy(d->msg_key, p + hlen - 4, 4);
            }

            continue;
        }

        if (d->msg) {
            ngx_http_waf_frame_msg_append(d, p, hlen, (size_t) plen);

            if (!fin) {
                continue;
            }

            hlen   = ngx_http_waf_frame_msg_seal(d, 1);
            plen   = d->msg_len;
            opcode = d->msg_opcode;
            p      = d->cleared;

            d->held      = hlen + (size_t) plen;
            d->opcode    = opcode;
            d->fin       = 1;
            d->fragments = d->msg_fragments;
            d->held_seq  = d->msg_seq;
            d->reassembled++;

            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "waf: %V message of %uz bytes reassembled from %ui "
                          "frames, conn %*s",
                          d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                        : &ngx_http_waf_frame_dir_s2c,
                          (size_t) plen, d->msg_fragments,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);

            (void) ngx_http_waf_frame_inspect(fc, d, p + hlen, (size_t) plen,
                                              masked ? d->msg_key : NULL);

            return NGX_OK;
        }

        d->held      = hlen + (size_t) plen;
        d->opcode    = opcode;
        d->fin       = fin ? 1 : 0;
        d->fragments = 1;
        d->held_seq  = d->seq;

        (void) ngx_http_waf_frame_inspect(fc, d, p + hlen, (size_t) plen,
                                          masked ? p + hlen - 4 : NULL);

        return NGX_OK;
    }
}


static ngx_uint_t
ngx_http_waf_frame_ctrl_allowed(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d)
{
    ngx_uint_t                rate, add;
    ngx_msec_t                now;
    ngx_msec_int_t            ms;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);
    rate = wlcf->frame_control_rate;

    if (rate == 0) {
        return 1;
    }

    now = ngx_current_msec;

    if (d->ctrl_last == 0) {
        d->ctrl_tokens = rate;
        d->ctrl_last   = now;

    } else {
        ms  = (ngx_msec_int_t) (now - d->ctrl_last);
        add = (ms > 0) ? rate * (ngx_uint_t) ms / 1000 : 0;

        if (add != 0) {
            d->ctrl_tokens = ngx_min(d->ctrl_tokens + add, rate);
            d->ctrl_last   = now;
        }
    }

    if (d->ctrl_tokens >= 1000) {
        d->ctrl_tokens -= 1000;
        return 1;
    }

    d->ctrl_dropped++;

    if (!d->ctrl_warned) {
        d->ctrl_warned = 1;

        ngx_log_error(NGX_LOG_WARN, fc->r->connection->log, 0,
                      "waf: %V control frames above waf_frame_control_rate "
                      "are dropped on this connection, conn %*s",
                      d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                    : &ngx_http_waf_frame_dir_s2c,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);
    }

    return 0;
}


static void
ngx_http_waf_frame_cut(ngx_http_waf_frame_dir_t *d, u_char *p, size_t len)
{
    size_t      tail;
    ngx_buf_t  *b = d->in;

    tail = (size_t) (b->last - (p + len));

    if (tail != 0) {
        ngx_memmove(p, p + len, tail);
    }

    b->last -= len;
}


static void
ngx_http_waf_frame_hoist(ngx_http_waf_frame_dir_t *d, u_char *p, size_t len)
{
    u_char  ctrl[NGX_HTTP_WAF_WS_HEADER_MAX + NGX_HTTP_WAF_WS_CONTROL_MAX];
    size_t  hold;

    hold = (size_t) (p - d->cleared);

    ngx_memcpy(ctrl, p, len);
    ngx_memmove(d->cleared + len, d->cleared, hold);
    ngx_memcpy(d->cleared, ctrl, len);
}


static void
ngx_http_waf_frame_msg_append(ngx_http_waf_frame_dir_t *d, u_char *p,
    size_t hlen, size_t plen)
{
    u_char     *dst, *src, key[4];
    size_t      i, tail;
    ngx_buf_t  *b = d->in;

    dst = p;
    src = p + hlen;

    if (d->masked) {
        ngx_memcpy(key, p + hlen - 4, 4);

        for (i = 0; i < plen; i++) {
            dst[i] = src[i] ^ key[i & 3] ^ d->msg_key[(d->msg_len + i) & 3];
        }

    } else if (plen != 0) {
        ngx_memmove(dst, src, plen);
    }

    tail = (size_t) (b->last - (src + plen));

    if (tail != 0) {
        ngx_memmove(dst + plen, src + plen, tail);
    }

    b->last -= hlen;

    d->msg_len += plen;
    d->msg_fragments++;
}


static size_t
ngx_http_waf_frame_msg_seal(ngx_http_waf_frame_dir_t *d, ngx_uint_t fin)
{
    u_char     *p, *payload;
    size_t      i, len, hlen, tail;
    ngx_buf_t  *b = d->in;

    len  = d->msg_len;
    hlen = 2 + (len < 126 ? 0 : (len <= 65535 ? 2 : 8)) + (d->masked ? 4 : 0);

    payload = d->cleared + d->msg_hlen;

    if (hlen != d->msg_hlen) {
        tail = (size_t) (b->last - payload);
        ngx_memmove(d->cleared + hlen, payload, tail);
        b->last = b->last - d->msg_hlen + hlen;
    }

    p = d->cleared;

    p[0] = (u_char) ((fin ? 0x80 : 0) | d->msg_opcode);

    if (len < 126) {
        p[1] = (u_char) len;
        p += 2;

    } else if (len <= 65535) {
        p[1] = 126;
        p[2] = (u_char) (len >> 8);
        p[3] = (u_char) (len & 0xff);
        p += 4;

    } else {
        p[1] = 127;

        for (i = 0; i < 8; i++) {
            p[2 + i] = (u_char) (((uint64_t) len >> (8 * (7 - i))) & 0xff);
        }

        p += 10;
    }

    if (d->masked) {
        d->cleared[1] |= 0x80;
        ngx_memcpy(p, d->msg_key, 4);
    }

    d->msg = 0;

    return hlen;
}


static u_char *
ngx_http_waf_frame_vars_save(ngx_http_waf_frame_t *fc)
{
    u_char                     *map;
    ngx_uint_t                  i, n;
    ngx_http_variable_value_t  *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(fc->r, ngx_http_core_module);
    n    = cmcf->variables.nelts;

    map = ngx_pcalloc(fc->pool, (n + 7) / 8);
    if (map == NULL) {
        return NULL;
    }

    v = fc->r->variables;

    for (i = 0; i < n; i++) {
        if (v[i].valid) {
            map[i >> 3] |= (u_char) (1 << (i & 7));
        }
    }

    return map;
}


static void
ngx_http_waf_frame_vars_restore(ngx_http_waf_frame_t *fc, u_char *map)
{
    ngx_uint_t                  i, n;
    ngx_http_variable_value_t  *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(fc->r, ngx_http_core_module);
    n    = cmcf->variables.nelts;
    v    = fc->r->variables;

    for (i = 0; i < n; i++) {

        if (!v[i].valid) {
            continue;
        }

        if (map != NULL && (map[i >> 3] & (1 << (i & 7)))) {
            continue;
        }

        v[i].valid        = 0;
        v[i].not_found    = 0;
        v[i].no_cacheable = 0;
        v[i].len          = 0;
        v[i].data         = NULL;
    }
}


ngx_http_waf_control_t *
ngx_http_waf_frame_control(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_frame_t  *fc = ctx->frame;

    if (fc == NULL || fc->cur == NULL) {
        return NULL;
    }

    return fc->conn_ctl;
}


ngx_int_t
ngx_http_waf_frame_var(ngx_http_waf_ctx_t *ctx, ngx_uint_t which,
    ngx_str_t *out)
{
    ngx_http_waf_frame_t      *fc = ctx->frame;
    ngx_http_waf_frame_dir_t  *d;

    if (fc == NULL || fc->cur == NULL) {
        return NGX_DECLINED;
    }

    d = fc->cur;

    switch (which) {

    case NGX_HTTP_WAF_FRAME_VAR_OPCODE:
        *out = *ngx_http_waf_frame_opcode_name(d->opcode);
        return NGX_OK;

    case NGX_HTTP_WAF_FRAME_VAR_DIRECTION:
        *out = (d == &fc->c2s) ? ngx_http_waf_frame_dir_c2s
                               : ngx_http_waf_frame_dir_s2c;
        return NGX_OK;

    case NGX_HTTP_WAF_FRAME_VAR_SIZE:
        out->data = fc->size_buf;
        out->len  = ngx_sprintf(fc->size_buf, "%uz",
                                (size_t) (fc->body_buf.last
                                          - fc->body_buf.start))
                    - fc->size_buf;
        return NGX_OK;

    case NGX_HTTP_WAF_FRAME_VAR_CONN_ID:
        out->data = fc->conn_id;
        out->len  = NGX_HTTP_WAF_RAY_HEX_LEN;
        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_uint_t
ngx_http_waf_frame_cacheable(ngx_http_waf_frame_t *fc)
{
    ngx_uint_t                 index;
    ngx_http_waf_mask_t        mask;
    ngx_http_waf_ctx_t        *ctx = fc->ctx;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_phase_ctx_t  *ph = ctx->ph;

    if (fc->cached || !fc->sha_set || fc->closing || ctx->by_local
        || fc->cur == NULL || fc->cur->drop != 0)
    {
        return 0;
    }

    if (ph->verdict != NGX_HTTP_WAF_V_ALLOW || ph->score != 0
        || ph->shadow != 0 || ph->fail != NGX_HTTP_WAF_CODE_NONE
        || ph->fail_blocked || ph->skipped != 0 || ph->controlled != 0
        || ph->published == 0
        || ph->got != ph->published || ph->replies == NULL)
    {
        return 0;
    }

    mask = ph->published;

    while (mask) {
        index = ngx_http_waf_lowest_bit(mask);
        mask &= ~(1ULL << index);

        reply = &ph->replies[index];

        if (!reply->received || reply->no_cache || reply->rewrite_has
            || reply->verdict != NGX_HTTP_WAF_V_ALLOW
            || (reply->headers_set != NULL && reply->headers_set->nelts != 0)
            || (reply->headers_unset != NULL
                && reply->headers_unset->nelts != 0)
            || (reply->cookies != NULL && reply->cookies->nelts != 0)
            || (reply->actions != NULL && reply->actions->nelts != 0))
        {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_http_waf_frame_begin(ngx_http_waf_frame_t *fc, ngx_http_waf_frame_dir_t *d,
    u_char *payload, size_t len, u_char *key)
{
    u_char                    *p;
    size_t                     i;
    ngx_http_request_t        *r = fc->r;
    ngx_http_waf_ctx_t        *ctx = fc->ctx;
    ngx_http_waf_phase_ctx_t  *ph;

    fc->pool = ngx_create_pool(NGX_HTTP_WAF_FRAME_POOL, r->connection->log);
    if (fc->pool == NULL) {
        ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_INTERNAL,
                                     "internal error",
                                     sizeof("internal error") - 1,
                                     "frame pool allocation failed");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(fc->pool, len != 0 ? len : 1);
    if (p == NULL) {
        ngx_destroy_pool(fc->pool);
        fc->pool = NULL;

        ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_INTERNAL,
                                     "internal error",
                                     sizeof("internal error") - 1,
                                     "frame copy allocation failed");
        return NGX_ERROR;
    }

    if (key != NULL) {
        for (i = 0; i < len; i++) {
            p[i] = payload[i] ^ key[i & 3];
        }

        ngx_memcpy(d->mask, key, 4);

    } else if (len != 0) {
        ngx_memcpy(p, payload, len);
    }

    ngx_memzero(&fc->body_buf, sizeof(ngx_buf_t));

    fc->body_buf.start     = p;
    fc->body_buf.pos       = p;
    fc->body_buf.last      = p + len;
    fc->body_buf.end       = p + len;
    fc->body_buf.temporary = 1;
    fc->body_buf.last_buf  = 1;

    fc->body.buf  = &fc->body_buf;
    fc->body.next = NULL;

    fc->saved_pool = r->pool;
    r->pool        = fc->pool;

    ph = &ctx->phases[d->phase];

    ngx_memzero(ph, sizeof(ngx_http_waf_phase_ctx_t));

    ph->body_policy   = NGX_HTTP_WAF_POLICY_UNSET;
    ph->agent_settled = 1;
    ph->store_cleanup = 1;
    ph->attach_fd     = -1;

    ngx_http_waf_phase_enter(ctx, d->phase);

    ctx->state      = NGX_HTTP_WAF_ST_INIT;
    ctx->started    = ngx_current_msec;
    ctx->waiting    = 0;
    ctx->by_local   = 0;
    ctx->finish_how = NGX_HTTP_WAF_FINISH_APPLY;

    ngx_memset(ctx->rid_hex, '-', NGX_HTTP_WAF_RID_HEX_LEN);

    ngx_str_null(&ctx->local_rule);
    ngx_str_null(&ctx->local_response);
    ctx->local_retry = 0;

    fc->saved_actions = ctx->actions;
    ctx->actions      = NULL;

    fc->saved_markers = ctx->markers;
    ctx->markers      = NULL;

    if (!fc->ctl_init) {
        ngx_memcpy(fc->conn_ctl, ctx->ctl, sizeof(ctx->ctl));
        fc->conn_audit = ctx->audit_ovr[NGX_HTTP_WAF_OVR_REQUEST];
        fc->ctl_init   = 1;
    }

    ngx_memcpy(ctx->ctl, fc->conn_ctl, sizeof(ctx->ctl));
    ctx->audit_ovr[NGX_HTTP_WAF_OVR_REQUEST] = fc->conn_audit;

    if (fc->saved_actions != NULL && fc->saved_actions->nelts != 0) {
        ctx->actions = ngx_array_create(fc->pool, fc->saved_actions->nelts + 4,
                                        sizeof(ngx_http_waf_action_t));

        if (ctx->actions != NULL) {
            void  *dst;

            dst = ngx_array_push_n(ctx->actions, fc->saved_actions->nelts);

            if (dst != NULL) {
                ngx_memcpy(dst, fc->saved_actions->elts,
                           fc->saved_actions->nelts
                           * sizeof(ngx_http_waf_action_t));
            }
        }
    }

    if (fc->saved_markers != NULL && fc->saved_markers->nelts != 0) {
        ctx->markers = ngx_array_create(fc->pool, fc->saved_markers->nelts + 4,
                                        sizeof(ngx_str_t));

        if (ctx->markers != NULL) {
            void  *dst;

            dst = ngx_array_push_n(ctx->markers, fc->saved_markers->nelts);

            if (dst != NULL) {
                ngx_memcpy(dst, fc->saved_markers->elts,
                           fc->saved_markers->nelts * sizeof(ngx_str_t));
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_frame_inspect(ngx_http_waf_frame_t *fc, ngx_http_waf_frame_dir_t *d,
    u_char *payload, size_t len, u_char *key)
{
    u_char                   *vars;
    ngx_int_t                 rc;
    ngx_msec_t                ttl;
    ngx_http_request_t       *r = fc->r;
    ngx_http_waf_ctx_t       *ctx = fc->ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ngx_http_waf_frame_begin(fc, d, payload, len, key) != NGX_OK) {
        return NGX_ERROR;
    }

    fc->cur       = d;
    fc->settled   = 0;
    fc->fetching  = 0;
    fc->cached    = 0;
    fc->sha_set   = 0;
    fc->in_stack  = 1;
    d->inspected++;

    vars = ngx_http_waf_frame_vars_save(fc);
    rc   = ngx_http_waf_local_checks(ctx);
    ngx_http_waf_frame_vars_restore(fc, vars);

    if (rc != NGX_DECLINED) {
        fc->in_stack = 0;
        return ngx_http_waf_frame_outcome(fc, rc);
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ttl  = wlcf->frame_cache_ttl[d->phase];

    if (ttl != 0) {
        ngx_http_waf_sha256_t  sha;

        ngx_http_waf_sha256_init(&sha);
        ngx_http_waf_sha256_update(&sha, fc->body_buf.start, len);
        ngx_http_waf_sha256_final(&sha, fc->sha256);
        fc->sha_set = 1;

        if (ngx_http_waf_fcache_lookup(fc->route_hash, d->phase, d->opcode,
                                       fc->sha256)
            == NGX_OK)
        {
            fc->cached = 1;
            d->cached++;

            ctx->by_local    = 1;
            ctx->local_rule  = ngx_http_waf_frame_cache_rule;
            ctx->ph->verdict = NGX_HTTP_WAF_V_ALLOW;
            ctx->state       = NGX_HTTP_WAF_ST_DONE;

            rc = ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);

            fc->in_stack = 0;
            return ngx_http_waf_frame_outcome(fc, rc);
        }
    }

    rc = ngx_http_waf_wave_start(ctx, 0);

    fc->in_stack = 0;

    return ngx_http_waf_frame_outcome(fc, rc);
}


static ngx_uint_t
ngx_http_waf_frame_journal_wanted(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d)
{
    ngx_uint_t                set;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);

    set = fc->ctl_init
              ? fc->conn_audit.audit.set
              : fc->ctx->audit_ovr[NGX_HTTP_WAF_OVR_REQUEST].audit.set;

    if (set == NGX_HTTP_WAF_SET_ON) {
        return 1;
    }

    if (wlcf->audit_frames != NGX_HTTP_WAF_AUDIT_FRAMES_ALL
        || set == NGX_HTTP_WAF_SET_OFF)
    {
        return 0;
    }

    return wlcf->audit_frames_sample <= 1
           || (d->seq % wlcf->audit_frames_sample) == 0;
}


static ngx_int_t
ngx_http_waf_frame_journal(ngx_http_waf_frame_t *fc,
    ngx_http_waf_frame_dir_t *d, u_char *payload, size_t len, u_char *key)
{
    ngx_int_t            rc;
    ngx_http_waf_ctx_t  *ctx = fc->ctx;

    if (ngx_http_waf_frame_begin(fc, d, payload, len, key) != NGX_OK) {
        return NGX_ERROR;
    }

    fc->cur      = d;
    fc->settled  = 0;
    fc->fetching = 0;
    fc->cached   = 0;
    fc->sha_set  = 0;
    fc->in_stack = 1;

    d->cleared += d->held;
    d->held     = 0;

    ctx->ph->body_ready    = 1;
    ctx->ph->agent_settled = 1;
    ctx->state             = NGX_HTTP_WAF_ST_DONE;

    rc = ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);

    fc->in_stack = 0;

    return ngx_http_waf_frame_outcome(fc, rc);
}


static ngx_int_t
ngx_http_waf_frame_outcome(ngx_http_waf_frame_t *fc, ngx_int_t rc)
{
    if (rc == NGX_DONE) {
        return fc->settled ? NGX_OK : NGX_AGAIN;
    }

    if (fc->settled) {
        return NGX_OK;
    }

    ngx_http_waf_frame_apply(fc, rc);

    return fc->closing ? NGX_ERROR : NGX_OK;
}


ngx_int_t
ngx_http_waf_frame_body(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    ctx->ph->body_ready = 1;

    rc = ngx_http_waf_body_place(ctx);

    if (rc == NGX_AGAIN) {
        return NGX_DONE;
    }

    ngx_http_waf_body_resumed(ctx, rc);

    return NGX_DONE;
}


ngx_chain_t *
ngx_http_waf_frame_source(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_frame_t  *fc = ctx->frame;

    if (fc == NULL || fc->pool == NULL) {
        return NULL;
    }

    return &fc->body;
}


void
ngx_http_waf_frame_resume(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t              rc;
    ngx_http_waf_frame_t  *fc = ctx->frame;

    ctx->waiting = 0;

    if (fc == NULL || fc->settled || fc->cur == NULL) {
        return;
    }

    rc = ngx_http_waf_phase_resume(ctx);

    if (rc == NGX_DONE) {
        return;
    }

    ngx_http_waf_frame_apply(fc, rc);

    if (fc->in_stack || fc->fetching) {
        return;
    }

    ngx_http_waf_frame_run(fc);
}


static void
ngx_http_waf_frame_apply(ngx_http_waf_frame_t *fc, ngx_int_t rc)
{
    if (rc == NGX_OK || rc == NGX_DECLINED) {

        if (ngx_http_waf_frame_rewrite(fc) == NGX_AGAIN) {
            fc->fetching = 1;
            return;
        }

        ngx_http_waf_frame_settle(fc, fc->closing ? NGX_ERROR : NGX_OK);
        return;
    }

    ngx_http_waf_frame_settle(fc, rc);
}


static void
ngx_http_waf_frame_settle(ngx_http_waf_frame_t *fc, ngx_int_t rc)
{
    ngx_http_waf_frame_dir_t  *d = fc->cur;

    fc->settled  = 1;
    fc->fetching = 0;

    if (d == NULL) {
        return;
    }

    if (rc != NGX_OK) {
        if (fc->close_code == 0) {
            ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_INTERNAL,
                                         "internal error",
                                         sizeof("internal error") - 1,
                                         "frame wave failed");
        }

        d->denied++;
    }

    ngx_http_waf_audit_request(fc->ctx);

    if (rc == NGX_OK && ngx_http_waf_frame_cacheable(fc)) {
        ngx_http_waf_loc_conf_t  *wlcf;

        wlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);

        ngx_http_waf_fcache_insert(fc->route_hash, d->phase, d->opcode,
                                   fc->sha256, wlcf->frame_cache_ttl[d->phase]);
    }

    if (rc == NGX_OK) {
        d->cleared += d->held;
        d->held     = 0;
    }

    ngx_http_waf_frame_end(fc);
}


static ngx_int_t
ngx_http_waf_frame_rewrite(ngx_http_waf_frame_t *fc)
{
    off_t                      cap;
    ngx_int_t                  rc;
    ngx_uint_t                 found;
    ngx_http_waf_ctx_t        *ctx = fc->ctx;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_body_op_t    *op;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (fc->cur == NULL || ctx->ph->replies == NULL) {
        return NGX_DECLINED;
    }

    wmcf  = ngx_http_get_module_main_conf(fc->r, ngx_http_waf_module);
    insp  = wmcf->inspectors.elts;

    found = (ctx->ph->live != NULL)
                ? ctx->ph->rewrite_last : NGX_HTTP_WAF_MAX_INSPECTORS;

    if (found == NGX_HTTP_WAF_MAX_INSPECTORS) {
        return NGX_DECLINED;
    }

    reply             = &ctx->ph->replies[found];
    fc->rewrite_index = found;

    if (ctx->deadline.timer_set) {
        ngx_del_timer(&ctx->deadline);
    }

    wlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);

    if (ngx_http_waf_send_of(wlcf, fc->cur->phase, NGX_HTTP_WAF_OBJ_BODY)
        != NGX_HTTP_WAF_SEND_STORE)
    {
        ngx_log_error(NGX_LOG_INFO, fc->r->connection->log, 0,
                      "waf: frame rewrite by \"%V\" skipped: waf_send %V "
                      "body=original, conn %*s, ray %*s",
                      &insp[found].name,
                      ngx_http_waf_phase_name(fc->cur->phase),
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        return NGX_DECLINED;
    }

    cap = (off_t) wlcf->body_limit[fc->cur->phase];

    if (reply->rewrite_size > cap) {
        ngx_http_waf_frame_rewrite_fail(fc, "the object exceeds "
                                        "waf_body_limit frame");
        return NGX_DECLINED;
    }

    if (ctx->ph->locator != NULL && ctx->ph->locator->truncated) {
        reply->rewrite_partial = 1;

        ngx_http_waf_frame_rewrite_fail(fc, "the capture is a prefix of the "
                                        "frame and a slice cannot replace "
                                        "the whole; waf_send frame body="
                                        "store needs a whole capture");
        return NGX_DECLINED;
    }

    rc = ngx_http_waf_store_get(ctx, &reply->rewrite_key, cap,
                                ngx_http_waf_frame_fetched, &op);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK || op == NULL || op->status != NGX_OK) {
        ngx_http_waf_frame_rewrite_fail(fc, "the store cannot serve the "
                                        "object");
        return NGX_DECLINED;
    }

    if (ngx_http_waf_frame_swap(fc, op) != NGX_OK) {
        ngx_http_waf_frame_rewrite_fail(fc, "the object does not match its "
                                        "declaration");
    }

    return NGX_DECLINED;
}


static void
ngx_http_waf_frame_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_http_waf_ctx_t    *ctx = op->data_ctx;
    ngx_http_waf_frame_t  *fc = ctx->frame;

    if (fc == NULL || !fc->fetching || fc->cur == NULL) {
        return;
    }

    if (op->status == NGX_OK) {

        if (ngx_http_waf_frame_swap(fc, op) != NGX_OK) {
            ngx_http_waf_frame_rewrite_fail(fc, "the object does not match "
                                            "its declaration");
        }

    } else if (op->status == NGX_DECLINED) {
        ngx_http_waf_frame_rewrite_fail(fc, "no such key in the store");

    } else {
        ngx_http_waf_frame_rewrite_fail(fc, "store error or timeout");
    }

    ngx_http_waf_frame_settle(fc, fc->closing ? NGX_ERROR : NGX_OK);

    if (fc->in_stack) {
        return;
    }

    if (fc->closing) {
        ngx_http_waf_frame_finalize(fc, fc->close_code != 0 ? NGX_OK
                                                            : NGX_ERROR);
        return;
    }

    ngx_http_waf_frame_run(fc);
}


static void
ngx_http_waf_frame_rewrite_fail(ngx_http_waf_frame_t *fc, const char *why)
{
    ngx_uint_t                 deny;
    ngx_http_waf_ctx_t        *ctx = fc->ctx;
    ngx_http_waf_reply_t      *reply = &ctx->ph->replies[fc->rewrite_index];
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(fc->r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)
                                                          [fc->rewrite_index];

    deny = fc->cur != NULL
           && wlcf->exception[fc->cur->phase][NGX_HTTP_WAF_EXC_BODY]
              == NGX_HTTP_WAF_POLICY_BLOCK;

    ngx_log_error(NGX_LOG_WARN, fc->r->connection->log, 0,
                  "waf: frame rewrite by \"%V\" failed (%s); %s, conn %*s, "
                  "ray %*s",
                  &insp->name, why,
                  deny ? "closing per waf_exception body"
                       : "passing the original",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    if (!deny) {
        return;
    }

    reply->verdict     = NGX_HTTP_WAF_V_DENY;
    reply->reason_code = ngx_http_waf_frame_rewrite_fail_code;

    ngx_str_null(&reply->response_name);

    ctx->ph->verdict        = NGX_HTTP_WAF_V_DENY;
    ctx->ph->decisive       = reply;
    ctx->ph->decisive_index = fc->rewrite_index;
    ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;

    ctx->state = NGX_HTTP_WAF_ST_DENY;

    ngx_http_waf_frame_deny_close(fc);
}


static ngx_int_t
ngx_http_waf_frame_swap(ngx_http_waf_frame_t *fc, ngx_http_waf_body_op_t *op)
{
    u_char                    *p, digest[32];
    size_t                     i, len, hlen, size;
    ngx_buf_t                 *out;
    ngx_http_waf_ctx_t        *ctx = fc->ctx;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_sha256_t      sha;
    ngx_http_waf_frame_dir_t  *d = fc->cur;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    reply = &ctx->ph->replies[fc->rewrite_index];

    if (op->data.len != (size_t) reply->rewrite_size) {
        return NGX_ERROR;
    }

    if (reply->rewrite_sha256_set) {
        ngx_http_waf_sha256_init(&sha);
        ngx_http_waf_sha256_update(&sha, op->data.data, op->data.len);
        ngx_http_waf_sha256_final(&sha, digest);

        if (ngx_memcmp(digest, reply->rewrite_sha256, 32) != 0) {
            return NGX_ERROR;
        }
    }

    if (d->out == NULL) {
        wlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);
        size = wlcf->body_limit[d->phase] + NGX_HTTP_WAF_WS_HEADER_MAX;

        if (size < NGX_HTTP_WAF_FRAME_BUF_MIN) {
            size = NGX_HTTP_WAF_FRAME_BUF_MIN;
        }

        d->out = ngx_create_temp_buf(fc->saved_pool, size);
        if (d->out == NULL) {
            return NGX_ERROR;
        }
    }

    out  = d->out;
    len  = op->data.len;
    hlen = 2 + (len < 126 ? 0 : (len <= 65535 ? 2 : 8)) + (d->masked ? 4 : 0);

    if (hlen + len > (size_t) (out->end - out->start)) {
        return NGX_ERROR;
    }

    p = out->start;

    p[0] = (u_char) ((d->fin ? 0x80 : 0) | d->opcode);

    if (len < 126) {
        p[1] = (u_char) len;
        p += 2;

    } else if (len <= 65535) {
        p[1] = 126;
        p[2] = (u_char) (len >> 8);
        p[3] = (u_char) (len & 0xff);
        p += 4;

    } else {
        p[1] = 127;

        for (i = 0; i < 8; i++) {
            p[2 + i] = (u_char) (((uint64_t) len >> (8 * (7 - i))) & 0xff);
        }

        p += 10;
    }

    if (d->masked) {
        out->start[1] |= 0x80;
        ngx_memcpy(p, d->mask, 4);
        p += 4;

        for (i = 0; i < len; i++) {
            p[i] = op->data.data[i] ^ d->mask[i & 3];
        }

    } else if (len != 0) {
        ngx_memcpy(p, op->data.data, len);
    }

    out->pos  = out->start;
    out->last = p + len;

    d->drop = d->held;
    d->held = 0;
    d->rewritten++;

    {
        ngx_http_waf_loc_conf_t  *swlcf;
        size_t                    budget, keep;
        u_char                   *copy;

        swlcf = ngx_http_get_module_loc_conf(fc->r, ngx_http_waf_module);
        budget = swlcf->shoot[d->phase].preview[NGX_HTTP_WAF_OBJ_BODY];

        if (budget != 0
            && swlcf->shoot[d->phase].preview_source[NGX_HTTP_WAF_OBJ_BODY]
               == NGX_HTTP_WAF_SOURCE_SENT)
        {
            keep = op->data.len < budget ? op->data.len : budget;

            copy = ngx_pnalloc(fc->saved_pool, keep);
            if (copy != NULL) {
                ngx_memcpy(copy, op->data.data, keep);
                ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].data = copy;
                ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].len  = keep;
            }
        }
    }

    ngx_http_waf_store_del_key(ctx, &reply->rewrite_key);

    wmcf = ngx_http_get_module_main_conf(fc->r, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)
                                                          [fc->rewrite_index];

    ngx_log_error(NGX_LOG_INFO, fc->r->connection->log, 0,
                  "waf: %V frame payload rewritten by \"%V\", %uz -> %uz "
                  "bytes, conn %*s, ray %*s",
                  d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                : &ngx_http_waf_frame_dir_s2c,
                  &insp->name, (size_t) (d->drop - hlen), len,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return NGX_OK;
}


ngx_uint_t
ngx_http_waf_frame_audit(ngx_http_waf_ctx_t *ctx, ngx_http_waf_frame_audit_t *out)
{
    ngx_http_waf_frame_t      *fc = ctx->frame;
    ngx_http_waf_frame_dir_t  *d;

    if (fc == NULL || fc->cur == NULL || fc->pool == NULL) {
        return 0;
    }

    d = fc->cur;

    out->conn_id   = fc->conn_id;
    out->direction = d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                   : &ngx_http_waf_frame_dir_s2c;
    out->opcode    = ngx_http_waf_frame_opcode_name(d->opcode);
    out->seq       = d->held_seq;
    out->size      = (size_t) (fc->body_buf.last - fc->body_buf.start);
    out->payload   = fc->body_buf.start;
    out->fragments = d->fragments;
    out->fin       = d->fin;
    out->rewritten = d->drop != 0;
    out->cached    = fc->cached;

    return 1;
}


static void
ngx_http_waf_frame_end(ngx_http_waf_frame_t *fc)
{
    ngx_uint_t                 phase;
    ngx_http_request_t        *r = fc->r;
    ngx_http_waf_ctx_t        *ctx = fc->ctx;
    ngx_http_waf_frame_dir_t  *d = fc->cur;

    if (fc->pool == NULL || d == NULL) {
        fc->cur = NULL;
        return;
    }

    phase = d->phase;

    ngx_http_waf_body_frame_end(ctx);

    if (ctx->deadline.timer_set) {
        ngx_del_timer(&ctx->deadline);
    }

    r->pool = fc->saved_pool;

    ctx->actions      = fc->saved_actions;
    fc->saved_actions = NULL;

    ctx->markers      = fc->saved_markers;
    fc->saved_markers = NULL;

    ngx_destroy_pool(fc->pool);
    fc->pool = NULL;
    fc->cur  = NULL;

    ngx_memzero(&ctx->phases[phase], sizeof(ngx_http_waf_phase_ctx_t));

    ctx->phases[phase].body_policy   = NGX_HTTP_WAF_POLICY_UNSET;
    ctx->phases[phase].agent_settled = 1;
    ctx->phases[phase].store_cleanup = 1;
    ctx->phases[phase].attach_fd     = -1;
}


ngx_int_t
ngx_http_waf_frame_finish(ngx_http_waf_ctx_t *ctx, ngx_uint_t how)
{
    ngx_http_waf_frame_t  *fc = ctx->frame;

    ngx_http_waf_log_verdict(ctx);

    if (fc == NULL || fc->cur == NULL) {
        return NGX_OK;
    }

    switch (how) {

    case NGX_HTTP_WAF_FINISH_APPLY:

        if (ctx->ph->verdict == NGX_HTTP_WAF_V_DENY
            || ctx->ph->verdict == NGX_HTTP_WAF_V_REDIRECT)
        {
            ngx_http_waf_frame_deny_close(fc);
            return NGX_ABORT;
        }

        return NGX_OK;

    case NGX_HTTP_WAF_FINISH_OVERRIDES:
        return NGX_OK;

    default:
        ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_INTERNAL,
                                     "inspection unavailable",
                                     sizeof("inspection unavailable") - 1,
                                     "no verdict, policy block");
        return NGX_ABORT;
    }
}


static void
ngx_http_waf_frame_deny_close(ngx_http_waf_frame_t *fc)
{
    ngx_str_t                     *code;
    ngx_http_waf_ctx_t            *ctx = fc->ctx;
    ngx_http_waf_deny_response_t  *dr;

    dr = ngx_http_waf_deny_entry_pub(ctx);

    if (dr != NULL && dr->type == NGX_HTTP_WAF_DENY_TYPE_WEBSOCKET
        && dr->code != 0)
    {
        ngx_http_waf_frame_set_close(fc, dr->code, (const char *) dr->reason.data,
                                     dr->reason.len, "policy");
        return;
    }

    code = NULL;

    if (ctx->by_local && ctx->local_rule.len != 0) {
        code = &ctx->local_rule;

    } else if (ctx->ph->decisive != NULL
               && ctx->ph->decisive->reason_code.len != 0)
    {
        code = &ctx->ph->decisive->reason_code;
    }

    if (code != NULL) {
        ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_POLICY,
                                     (const char *) code->data, code->len,
                                     "policy");
        return;
    }

    ngx_http_waf_frame_set_close(fc, NGX_HTTP_WAF_WS_CLOSE_POLICY,
                                 "policy violation",
                                 sizeof("policy violation") - 1, "policy");
}


static void
ngx_http_waf_frame_set_close(ngx_http_waf_frame_t *fc, ngx_uint_t code,
    const char *reason, size_t len, const char *why)
{
    if (len > NGX_HTTP_WAF_WS_REASON_MAX) {
        len = NGX_HTTP_WAF_WS_REASON_MAX;
    }

    if (len != 0) {
        ngx_memcpy(fc->close_reason, reason, len);
    }

    fc->close_reason_len = len;
    fc->close_code       = code;
    fc->close_why        = why;
    fc->closing          = 1;
}


static void
ngx_http_waf_frame_finalize(ngx_http_waf_frame_t *fc, ngx_int_t rc)
{
    u_char                          frame[2 + 2 + NGX_HTTP_WAF_WS_REASON_MAX];
    size_t                          len;
    ngx_connection_t               *c;
    ngx_http_request_t             *r = fc->r;
    ngx_http_upstream_t            *u = r->upstream;
    ngx_http_waf_ctx_t             *ctx = fc->ctx;
    ngx_http_waf_session_audit_t    sess;

    c = r->connection;

    ngx_http_waf_frame_end(fc);

    sess.conn_id      = fc->conn_id;
    sess.frames_c2s   = fc->c2s.seq;
    sess.frames_s2c   = fc->s2c.seq;
    sess.bytes_c2s    = fc->c2s.bytes;
    sess.bytes_s2c    = fc->s2c.bytes;
    sess.denied       = fc->c2s.denied + fc->s2c.denied;
    sess.rewritten    = fc->c2s.rewritten + fc->s2c.rewritten;
    sess.cached       = fc->c2s.cached + fc->s2c.cached;
    sess.reassembled  = fc->c2s.reassembled + fc->s2c.reassembled;
    sess.control_dropped = fc->c2s.ctrl_dropped + fc->s2c.ctrl_dropped;
    sess.close_code   = fc->close_code;
    sess.close_why    = fc->close_why;
    sess.duration_ms  = ngx_current_msec - fc->started;
    sess.close_reason = fc->close_why == NULL ? "peer"
        : ngx_strcmp(fc->close_why, "policy") == 0 ? "waf_deny"
        : ngx_strstr(fc->close_why, "timed out") != NULL ? "timeout"
        : ngx_strstr(fc->close_why, "closed") != NULL ? "peer"
        : "error";

    ngx_http_waf_audit_session(ctx, &sess);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "waf: frame session closed (%s), close %ui, "
                  "frames c2s %uL s2c %uL, inspected %uL, denied %uL, "
                  "rewritten %uL, cached %uL, reassembled %uL, "
                  "control dropped %uL, bytes c2s %O s2c %O, conn %*s",
                  fc->close_why != NULL ? fc->close_why : "peer closed",
                  fc->close_code, fc->c2s.seq, fc->s2c.seq,
                  fc->c2s.inspected + fc->s2c.inspected,
                  fc->c2s.denied + fc->s2c.denied,
                  fc->c2s.rewritten + fc->s2c.rewritten,
                  sess.cached, sess.reassembled, sess.control_dropped,
                  fc->c2s.bytes, fc->s2c.bytes,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, fc->conn_id);

    if (fc->close_code != 0 && c->write->ready) {
        len = 2 + fc->close_reason_len;

        frame[0] = 0x80 | NGX_HTTP_WAF_WS_OP_CLOSE;
        frame[1] = (u_char) len;
        frame[2] = (u_char) (fc->close_code >> 8);
        frame[3] = (u_char) (fc->close_code & 0xff);

        if (fc->close_reason_len != 0) {
            ngx_memcpy(frame + 4, fc->close_reason, fc->close_reason_len);
        }

        (void) c->send(c, frame, 2 + len);
    }

    fc->closing = 1;
    ctx->frame  = NULL;

    if (u->cleanup != NULL) {
        *u->cleanup = NULL;
        u->cleanup  = NULL;
    }

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    if (u->peer.connection) {

#if (NGX_HTTP_SSL)
        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(u->peer.connection);
        }
#endif

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

    ngx_http_finalize_request(r, rc);
}


static ngx_uint_t
ngx_http_waf_frame_idle(ngx_http_waf_frame_t *fc, ngx_http_waf_frame_dir_t *d)
{
    return fc->cur != d && d->drop == 0
           && d->in->pos == d->cleared
           && (d->out == NULL || d->out->pos == d->out->last);
}


static void
ngx_http_waf_frame_events(ngx_http_waf_frame_t *fc)
{
    ngx_uint_t                 flags;
    ngx_connection_t          *downstream, *upstream;
    ngx_http_request_t        *r = fc->r;
    ngx_http_upstream_t       *u = r->upstream;
    ngx_http_core_loc_conf_t  *clcf;

    downstream = r->connection;
    upstream   = u->peer.connection;

    if ((upstream->read->eof && ngx_http_waf_frame_idle(fc, &fc->s2c))
        || (downstream->read->eof && ngx_http_waf_frame_idle(fc, &fc->c2s))
        || (downstream->read->eof && upstream->read->eof))
    {
        fc->close_why = "peer closed";
        ngx_http_waf_frame_finalize(fc, NGX_OK);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (ngx_handle_write_event(upstream->write, u->conf->send_lowat)
        != NGX_OK)
    {
        ngx_http_waf_frame_finalize(fc, NGX_ERROR);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        ngx_add_timer(upstream->write, u->conf->send_timeout);

    } else if (upstream->write->timer_set) {
        ngx_del_timer(upstream->write);
    }

    flags = (upstream->read->eof || upstream->read->error) ? NGX_CLOSE_EVENT
                                                           : 0;

    if (ngx_handle_read_event(upstream->read, flags) != NGX_OK) {
        ngx_http_waf_frame_finalize(fc, NGX_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        ngx_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        ngx_del_timer(upstream->read);
    }

    if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
        != NGX_OK)
    {
        ngx_http_waf_frame_finalize(fc, NGX_ERROR);
        return;
    }

    flags = (downstream->read->eof || downstream->read->error)
                ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(downstream->read, flags) != NGX_OK) {
        ngx_http_waf_frame_finalize(fc, NGX_ERROR);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        ngx_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        ngx_del_timer(downstream->write);
    }
}


static ngx_str_t *
ngx_http_waf_frame_opcode_name(ngx_uint_t opcode)
{
    if (opcode <= NGX_HTTP_WAF_WS_OP_BINARY) {
        return &ngx_http_waf_frame_opcodes[opcode];
    }

    return &ngx_http_waf_frame_opcode_other;
}


size_t
ngx_http_waf_msg_frame_size(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_frame_t  *fc = ctx->frame;

    if (!ngx_http_waf_phase_is_frame(ctx->phase) || fc == NULL) {
        return 0;
    }

    return sizeof(",\"conn_id\":\"\",\"seq\":,\"stream\":{\"protocol\":"
                  "\"websocket\",\"direction\":\"c2s\",\"opcode\":"
                  "\"continuation\",\"fin\":false,\"fragments\":,"
                  "\"subprotocol\":}")
           + NGX_HTTP_WAF_RAY_HEX_LEN + 2 * NGX_INT64_LEN
           + fc->subprotocol.len * 6 + 8;
}


void
ngx_http_waf_msg_frame(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_frame_t      *fc = ctx->frame;
    ngx_http_waf_frame_dir_t  *d;

    if (!ngx_http_waf_phase_is_frame(ctx->phase) || fc == NULL) {
        return;
    }

    d = fc->cur != NULL ? fc->cur : &fc->c2s;

    ngx_http_waf_jw_lit(jw, ",\"conn_id\":\"");
    ngx_http_waf_jw_raw(jw, fc->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(jw, "\",\"seq\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) d->held_seq);

    ngx_http_waf_jw_lit(jw, ",\"stream\":{\"protocol\":\"websocket\","
                            "\"direction\":");
    ngx_http_waf_jw_str(jw, d == &fc->c2s ? &ngx_http_waf_frame_dir_c2s
                                          : &ngx_http_waf_frame_dir_s2c);
    ngx_http_waf_jw_lit(jw, ",\"opcode\":");
    ngx_http_waf_jw_str(jw, ngx_http_waf_frame_opcode_name(d->opcode));
    ngx_http_waf_jw_lit(jw, ",\"fin\":");

    if (d->fin) {
        ngx_http_waf_jw_lit(jw, "true");

    } else {
        ngx_http_waf_jw_lit(jw, "false");
    }

    ngx_http_waf_jw_lit(jw, ",\"fragments\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) (d->fragments != 0 ? d->fragments
                                                            : 1));

    ngx_http_waf_jw_lit(jw, ",\"subprotocol\":");

    if (fc->subprotocol.len != 0) {
        ngx_http_waf_jw_str(jw, &fc->subprotocol);

    } else {
        ngx_http_waf_jw_lit(jw, "null");
    }

    ngx_http_waf_jw_lit(jw, "}");
}
