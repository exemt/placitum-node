#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "runtime/ngx_http_waf_preview.h"


static ngx_int_t ngx_http_waf_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_body_filter(ngx_http_request_t *r,
                     ngx_chain_t *in);
static ngx_uint_t ngx_http_waf_response_bypass(ngx_http_request_t *r,
                      ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_outcome(ngx_http_waf_ctx_t *ctx,
                     ngx_int_t rc);
static ngx_int_t ngx_http_waf_response_hold(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_release(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_deny(ngx_http_waf_ctx_t *ctx,
                     ngx_int_t status);
static ngx_int_t ngx_http_waf_hold_chain(ngx_http_waf_ctx_t *ctx,
                     ngx_chain_t *in);
static ngx_uint_t ngx_http_waf_response_body_ready(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_body_place(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_restore_accept_encoding(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_rewrite(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_rewrite_fetched(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_rewrite_fail(ngx_http_waf_ctx_t *ctx,
                     ngx_uint_t index, const char *why);
static ngx_int_t ngx_http_waf_rewrite_swap(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_body_op_t *op);
static ngx_uint_t ngx_http_waf_response_journal_wanted(ngx_http_request_t *r,
                      ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static ngx_int_t ngx_http_waf_response_journal_start(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_journal_body(ngx_http_waf_ctx_t *ctx,
                     ngx_chain_t *in);
static void ngx_http_waf_response_journal_finish(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_response_journal_resume(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_response_journal_cleanup(void *data);


static ngx_str_t  ngx_http_waf_rewrite_fail_code =
    ngx_string("REWRITE_UNAVAILABLE");


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


ngx_int_t
ngx_http_waf_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = ngx_http_waf_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter  = ngx_http_waf_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx != NULL) {
        ngx_http_waf_restore_accept_encoding(ctx);
    }

    if (ctx == NULL || ctx->rsp_entered) {
        if (ctx != NULL && ctx->rsp_denied) {
            (void) ngx_http_waf_apply_debug(ctx);
        }

        return ngx_http_next_header_filter(r);
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (!wlcf->enable) {
        return ngx_http_next_header_filter(r);
    }

    if (!ngx_http_waf_phase_inspected(wlcf, NGX_HTTP_WAF_PHASE_RESPONSE)) {
        if (ngx_http_waf_response_journal_wanted(r, ctx, wlcf)) {
            return ngx_http_waf_response_journal_start(ctx);
        }

        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_waf_response_bypass(r, ctx)) {
        ngx_http_waf_audit_flush_deferred(ctx);
        return ngx_http_next_header_filter(r);
    }

    ctx->rsp_entered = 1;
    ctx->hold_last   = &ctx->hold;
    ctx->rsp_status  = r->headers_out.status;

    if (ngx_http_waf_response_headers(ctx) == NULL) {
        ctx->rsp_entered = 0;
        return NGX_ERROR;
    }

    if (r->upstream != NULL && r->upstream->state != NULL) {
        ctx->upstream_ms = r->upstream->state->response_time;
    }

    ngx_http_waf_phase_enter(ctx, NGX_HTTP_WAF_PHASE_RESPONSE);

    ctx->started = ngx_current_msec;
    ctx->state   = NGX_HTTP_WAF_ST_INIT;

    rc = ngx_http_waf_wave_start(ctx, 0);

    return ngx_http_waf_response_outcome(ctx, rc);
}


static ngx_uint_t
ngx_http_waf_response_bypass(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
    if (r != r->main) {
        return 1;
    }

    if (r->header_only) {
        return 1;
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_NO_CONTENT:
    case NGX_HTTP_NOT_MODIFIED:
        return 1;

    case NGX_HTTP_SWITCHING_PROTOCOLS:
        return 1;

    default:
        break;
    }

    if (ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST].verdict == NGX_HTTP_WAF_V_DENY
        || ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST].fail_blocked)
    {
        return 1;
    }

    return 0;
}


ngx_array_t *
ngx_http_waf_response_headers(ngx_http_waf_ctx_t *ctx)
{
    u_char              *p;
    ngx_uint_t           i;
    ngx_keyval_t        *kv;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_headers != NULL) {
        return ctx->rsp_headers;
    }

    ctx->rsp_headers = ngx_array_create(r->pool, 16, sizeof(ngx_keyval_t));
    if (ctx->rsp_headers == NULL) {
        return NULL;
    }

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

        kv = ngx_array_push(ctx->rsp_headers);
        if (kv == NULL) {
            return NULL;
        }

        kv->key   = h[i].key;
        kv->value = h[i].value;
    }

    if (r->headers_out.content_type.len != 0) {
        kv = ngx_array_push(ctx->rsp_headers);
        if (kv == NULL) {
            return NULL;
        }

        ngx_str_set(&kv->key, "Content-Type");
        kv->value = r->headers_out.content_type;
    }

    if (r->headers_out.content_length_n >= 0
        && r->headers_out.content_length == NULL)
    {
        p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (p == NULL) {
            return NULL;
        }

        kv = ngx_array_push(ctx->rsp_headers);
        if (kv == NULL) {
            return NULL;
        }

        ngx_str_set(&kv->key, "Content-Length");
        kv->value.data = p;
        kv->value.len  = ngx_sprintf(p, "%O",
                                     r->headers_out.content_length_n) - p;
    }

    return ctx->rsp_headers;
}


void
ngx_http_waf_strip_accept_encoding(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                  strip;
    ngx_table_elt_t            *ae;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    ae = r->headers_in.accept_encoding;

    if (ae == NULL || ae->hash == 0) {
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh   = &wlcf->shoot[NGX_HTTP_WAF_PHASE_RESPONSE];

    strip = ((sh->capture | sh->archive)
             & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY)) != 0
            || sh->preview[NGX_HTTP_WAF_OBJ_BODY] != 0;

    if (wlcf->strip_accept_encoding != NGX_CONF_UNSET) {
        strip = (ngx_uint_t) wlcf->strip_accept_encoding;
    }

    if (!strip) {
        return;
    }

    ctx->accept_encoding = ae->value;

    ngx_str_set(&ae->value, "identity");
}


static void
ngx_http_waf_restore_accept_encoding(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->accept_encoding.data == NULL
        || r->headers_in.accept_encoding == NULL)
    {
        return;
    }

    r->headers_in.accept_encoding->value = ctx->accept_encoding;
    ctx->accept_encoding.data = NULL;
}


ngx_int_t
ngx_http_waf_response_body(ngx_http_waf_ctx_t *ctx)
{
    if (!ngx_http_waf_response_body_ready(ctx)) {
        ctx->rsp_wait_body = 1;
        return NGX_DONE;
    }

    return ngx_http_waf_response_body_place(ctx);
}


static ngx_uint_t
ngx_http_waf_response_body_ready(ngx_http_waf_ctx_t *ctx)
{
    size_t                      need;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    if (ctx->rsp_last) {
        return 1;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[NGX_HTTP_WAF_PHASE_RESPONSE];

    need = sh->capture_limit[NGX_HTTP_WAF_OBJ_BODY];

    if (need == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE) {
        return 0;
    }

    return ctx->hold_size >= need;
}


static ngx_int_t
ngx_http_waf_response_body_place(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    ctx->rsp_wait_body  = 0;
    ctx->ph->body_ready = 1;

    rc = ngx_http_waf_body_place(ctx);

    if (rc == NGX_AGAIN) {
        return NGX_DONE;
    }

    ngx_http_waf_body_resumed(ctx, rc);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_waf_response_outcome(ngx_http_waf_ctx_t *ctx, ngx_int_t rc)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    if (rc == NGX_DONE) {

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        if (wlcf->hold[NGX_HTTP_WAF_PHASE_RESPONSE]
            == NGX_HTTP_WAF_HOLD_MONITOR)
        {
            ctx->rsp_monitor = 1;
            return ngx_http_waf_response_release(ctx);
        }

        return ngx_http_waf_response_hold(ctx);
    }

    if (rc == NGX_OK || rc == NGX_DECLINED) {
        return ngx_http_waf_response_release(ctx);
    }

    if (rc == NGX_ERROR) {
        return ngx_http_waf_response_deny(ctx,
                                          NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    return ngx_http_waf_response_deny(ctx, rc);
}


static ngx_int_t
ngx_http_waf_response_hold(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_settled) {
        return NGX_OK;
    }

    ctx->rsp_holding = 1;

    r->buffered |= NGX_HTTP_WAF_BUFFERED;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_response_release(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t            rc;
    ngx_chain_t         *out;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_settled) {
        return NGX_OK;
    }

    ctx->rsp_settled = 1;
    ctx->rsp_holding = 0;
    r->buffered &= ~NGX_HTTP_WAF_BUFFERED;

    out            = ctx->hold;
    ctx->hold      = NULL;
    ctx->hold_last = &ctx->hold;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    if (out == NULL) {
        return rc;
    }

    return ngx_http_next_body_filter(r, out);
}


static ngx_int_t
ngx_http_waf_response_deny(ngx_http_waf_ctx_t *ctx, ngx_int_t status)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_settled) {
        return NGX_OK;
    }

    ctx->rsp_settled = 1;
    ctx->rsp_holding = 0;
    ctx->rsp_denied  = 1;

    ctx->hold      = NULL;
    ctx->hold_last = &ctx->hold;
    ctx->hold_size = 0;

    r->buffered &= ~NGX_HTTP_WAF_BUFFERED;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: response denied with %i, ray %*s", status,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return ngx_http_filter_finalize_request(r, &ngx_http_waf_module, status);
}


void
ngx_http_waf_response_resume(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t            rc;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_journal) {
        ngx_http_waf_response_journal_resume(ctx);
        return;
    }

    ctx->waiting = 0;

    if (ctx->state != NGX_HTTP_WAF_ST_NEXT_WAVE
        && !ctx->rsp_fetch_done
        && ngx_http_waf_response_rewrite(ctx) == NGX_AGAIN)
    {
        return;
    }

    rc = ngx_http_waf_phase_resume(ctx);

    if (rc == NGX_DONE) {
        return;
    }

    if (ctx->rsp_monitor) {

        if (rc != NGX_OK && rc != NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "waf: response phase denied a monitored response "
                          "with %i; the bytes are already out, cutting the "
                          "connection, ray %*s", rc,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

            ngx_http_finalize_request(r, NGX_ERROR);
        }

        return;
    }

    rc = ngx_http_waf_response_outcome(ctx, rc);

    if (ctx->rsp_last || rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_run_posted_requests(r->connection);
}


static ngx_int_t
ngx_http_waf_response_rewrite(ngx_http_waf_ctx_t *ctx)
{
    off_t                      cap;
    ngx_int_t                  rc;
    ngx_uint_t                 found;
    ngx_table_elt_t           *ce;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_body_op_t    *op;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->state != NGX_HTTP_WAF_ST_ALLOW || ctx->ph->replies == NULL) {
        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    insp  = wmcf->inspectors.elts;

    found = (ctx->ph->live != NULL)
                ? ctx->ph->rewrite_last : NGX_HTTP_WAF_MAX_INSPECTORS;

    if (found == NGX_HTTP_WAF_MAX_INSPECTORS) {
        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    reply = &ctx->ph->replies[found];
    ctx->rsp_rewrite_index = found;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (ngx_http_waf_send_of(wlcf, NGX_HTTP_WAF_PHASE_RESPONSE,
                             NGX_HTTP_WAF_OBJ_BODY)
        != NGX_HTTP_WAF_SEND_STORE)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: response body rewrite by \"%V\" skipped: "
                      "waf_send response body=original, ray %*s",
                      &insp[found].name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    if (ctx->rsp_settled) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: inspector \"%V\" asked to rewrite a response "
                      "that was already released; skipped, ray %*s",
                      &insp[found].name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    if (!ctx->rsp_last) {
        reply->rewrite_partial = 1;

        ngx_http_waf_rewrite_fail(ctx, found, "the capture is a prefix of "
                                  "the body and a slice cannot replace the "
                                  "whole; waf_send response body=store needs "
                                  "a whole capture");
        return NGX_DECLINED;
    }

    ce = r->headers_out.content_encoding;

    if (ce != NULL && ce->hash != 0 && ce->value.len != 0
        && !(ce->value.len == 8
             && ngx_strncasecmp(ce->value.data, (u_char *) "identity", 8)
                == 0))
    {
        ngx_http_waf_rewrite_fail(ctx, found,
                                  "the upstream response is encoded");
        return NGX_DECLINED;
    }

    cap = (off_t) wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE];

    if (reply->rewrite_size > cap) {
        ngx_http_waf_rewrite_fail(ctx, found,
                                  "the object exceeds waf_body_limit");
        return NGX_DECLINED;
    }

    rc = ngx_http_waf_store_get(ctx, &reply->rewrite_key, cap,
                                ngx_http_waf_rewrite_fetched, &op);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK || op == NULL || op->status != NGX_OK) {
        ngx_http_waf_rewrite_fail(ctx, found, "the store cannot serve the "
                                  "object");
        return NGX_DECLINED;
    }

    if (ngx_http_waf_rewrite_swap(ctx, op) != NGX_OK) {
        ngx_http_waf_rewrite_fail(ctx, found, "the object does not match its "
                                  "declaration");
    }

    return NGX_DECLINED;
}


static void
ngx_http_waf_rewrite_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_http_waf_ctx_t  *ctx = op->data_ctx;

    if (op->status == NGX_OK) {

        if (ngx_http_waf_rewrite_swap(ctx, op) != NGX_OK) {
            ngx_http_waf_rewrite_fail(ctx, ctx->rsp_rewrite_index,
                                      "the object does not match its "
                                      "declaration");
        }

    } else if (op->status == NGX_DECLINED) {
        ngx_http_waf_rewrite_fail(ctx, ctx->rsp_rewrite_index,
                                  "no such key in the store");

    } else {
        ngx_http_waf_rewrite_fail(ctx, ctx->rsp_rewrite_index,
                                  "store error or timeout");
    }

    ngx_http_waf_response_resume(ctx);
}


static void
ngx_http_waf_rewrite_fail(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    const char *why)
{
    ngx_uint_t                 deny;
    ngx_http_waf_reply_t      *reply = &ctx->ph->replies[index];
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    ctx->rsp_fetch_done = 1;

    deny = wlcf->exception[NGX_HTTP_WAF_PHASE_RESPONSE][NGX_HTTP_WAF_EXC_BODY]
           == NGX_HTTP_WAF_POLICY_BLOCK;

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: response rewrite by \"%V\" failed (%s); %s, ray %*s",
                  &insp->name, why,
                  deny ? "denying per waf_exception body"
                       : "passing the original",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    if (!deny) {
        return;
    }

    reply->verdict     = NGX_HTTP_WAF_V_DENY;
    reply->reason_code = ngx_http_waf_rewrite_fail_code;

    ngx_str_null(&reply->response_name);

    ctx->ph->verdict        = NGX_HTTP_WAF_V_DENY;
    ctx->ph->decisive       = reply;
    ctx->ph->decisive_index = index;
    ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;

    ctx->state = NGX_HTTP_WAF_ST_DENY;
}


static ngx_int_t
ngx_http_waf_rewrite_swap(ngx_http_waf_ctx_t *ctx, ngx_http_waf_body_op_t *op)
{
    u_char                 digest[32];
    size_t                 was;
    ngx_buf_t             *b;
    ngx_chain_t           *cl;
    ngx_http_request_t    *r = ctx->request;
    ngx_http_waf_reply_t  *reply;
    ngx_http_waf_sha256_t  sha;

    reply = &ctx->ph->replies[ctx->rsp_rewrite_index];

    if (op->data.len != (size_t) reply->rewrite_size) {
        return NGX_ERROR;
    }

    ngx_http_waf_sha256_init(&sha);
    ngx_http_waf_sha256_update(&sha, op->data.data, op->data.len);
    ngx_http_waf_sha256_final(&sha, digest);

    if (reply->rewrite_sha256_set
        && ngx_memcmp(digest, reply->rewrite_sha256, 32) != 0)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(reply->rewrite_sha256, digest, 32);
    reply->rewrite_digest = 1;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b->start    = op->data.data;
    b->pos      = op->data.data;
    b->last     = op->data.data + op->data.len;
    b->end      = b->last;
    b->memory   = 1;
    b->last_buf = 1;

    cl->buf  = b;
    cl->next = NULL;

    was = ctx->hold_size;

    ctx->hold      = cl;
    ctx->hold_last = &cl->next;
    ctx->hold_size = op->data.len;

    r->headers_out.content_length_n = (off_t) op->data.len;

    if (r->headers_out.content_length != NULL) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length       = NULL;
    }

    ctx->rsp_fetch_done = 1;
    ctx->rsp_rewritten  = 1;

    {
        ngx_http_waf_loc_conf_t  *wlcf;

        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

        if (wlcf->shoot[ctx->phase].preview_source[NGX_HTTP_WAF_OBJ_BODY]
            == NGX_HTTP_WAF_SOURCE_SENT)
        {
            ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY] = op->data;
        }
    }

    ngx_http_waf_store_del_key(ctx, &reply->rewrite_key);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: response body rewritten, %uz -> %uz bytes, ray %*s",
                  was, ctx->hold_size,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx != NULL && r->header_sent && r->upstream != NULL
        && r->upstream->upgrade && ngx_http_waf_frame_wanted(r, ctx))
    {
        if (ngx_http_waf_frame_attach(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx != NULL && ctx->rsp_journal && r == r->main) {
        return ngx_http_waf_response_journal_body(ctx, in);
    }

    if (ctx == NULL || r != r->main || !ctx->rsp_entered || ctx->rsp_settled) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in != NULL && ngx_http_waf_hold_chain(ctx, in) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->rsp_wait_body
        && !ctx->rsp_settled
        && ngx_http_waf_response_body_ready(ctx))
    {
        (void) ngx_http_waf_response_body_place(ctx);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_hold_chain(ngx_http_waf_ctx_t *ctx, ngx_chain_t *in)
{
    off_t                     size;
    u_char                   *p;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    for ( ; in != NULL; in = in->next) {

        if (in->buf->last_buf) {
            ctx->rsp_last = 1;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        *b = *in->buf;

        size = ngx_buf_size(in->buf);

        if (ngx_buf_in_memory(in->buf) && size > 0) {
            p = ngx_pnalloc(r->pool, (size_t) size);
            if (p == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(p, in->buf->pos, (size_t) size);

            b->start = b->pos = p;
            b->end   = b->last = p + size;
            b->memory = 1;
            b->temporary = 0;

            ctx->hold_size += (size_t) size;
        }

        in->buf->pos = in->buf->last;
        in->buf->file_pos = in->buf->file_last;

        cl->buf  = b;
        cl->next = NULL;

        *ctx->hold_last = cl;
        ctx->hold_last  = &cl->next;
    }

    if (ctx->hold_size > wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE]) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: response of %uz bytes passed the %uz byte hold "
                      "limit before the verdict; releasing it, ray %*s",
                      ctx->hold_size,
                      wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE],
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        return ngx_http_waf_response_release(ctx) == NGX_ERROR
                   ? NGX_ERROR : NGX_OK;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_response_journal_wanted(ngx_http_request_t *r,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_http_waf_audit_ovr_t  *ovr;

    if (!ngx_http_waf_audit_enabled()) {
        return 0;
    }

    if (r != r->main
        || r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS)
    {
        return 0;
    }

    if (ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST].verdict == NGX_HTTP_WAF_V_DENY
        || ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST].fail_blocked)
    {
        return 0;
    }

    if (ngx_http_waf_preview_room(wlcf, NGX_HTTP_WAF_PHASE_RESPONSE) != 0
        || wlcf->shoot[NGX_HTTP_WAF_PHASE_RESPONSE].archive != 0)
    {
        return 1;
    }

    ovr = &ctx->audit_ovr[NGX_HTTP_WAF_OVR_RESPONSE];

    return ovr->audit.set == NGX_HTTP_WAF_SET_ON
           || ovr->archive.set == NGX_HTTP_WAF_SET_ON;
}


static ngx_int_t
ngx_http_waf_response_journal_start(ngx_http_waf_ctx_t *ctx)
{
    size_t                     need, one;
    ngx_int_t                  rc;
    ngx_http_cleanup_t        *cln;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_loc_conf_t   *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return ngx_http_next_header_filter(r);
    }

    cln->handler = ngx_http_waf_response_journal_cleanup;
    cln->data    = ctx;

    ctx->rsp_status = r->headers_out.status;

    if (ngx_http_waf_response_headers(ctx) == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (r->upstream != NULL && r->upstream->state != NULL) {
        ctx->upstream_ms = r->upstream->state->response_time;
    }

    ngx_http_waf_phase_enter(ctx, NGX_HTTP_WAF_PHASE_RESPONSE);

    ctx->started     = ngx_current_msec;
    ctx->state       = NGX_HTTP_WAF_ST_INIT;
    ctx->ph->journal = 1;

    ctx->rsp_entered = 1;
    ctx->rsp_journal = 1;
    ctx->hold_last   = &ctx->hold;

    need = ngx_http_waf_preview_body_budget(ctx);
    one  = ngx_http_waf_archive_wants(ctx, NGX_HTTP_WAF_OBJ_BODY,
                                      NGX_HTTP_WAF_V_ALLOW);

    if (one > need) {
        need = one;
    }

    ctx->rsp_journal_need = ngx_min(need,
                                    wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE]);

    rc = ngx_http_next_header_filter(r);

    if (r->header_only && rc != NGX_ERROR) {
        ngx_http_waf_response_journal_finish(ctx);
    }

    return rc;
}


static ngx_int_t
ngx_http_waf_response_journal_body(ngx_http_waf_ctx_t *ctx, ngx_chain_t *in)
{
    off_t                size;
    size_t               take;
    u_char              *p;
    ngx_int_t            rc;
    ngx_uint_t           last;
    ngx_buf_t           *b;
    ngx_chain_t         *cl, *copy;
    ngx_http_request_t  *r = ctx->request;

    last = 0;

    for (cl = in; cl != NULL && !ctx->rsp_journal_done; cl = cl->next) {

        if (cl->buf->last_buf) {
            last = 1;
        }

        size = ngx_buf_size(cl->buf);

        if (size <= 0) {
            continue;
        }

        ctx->rsp_journal_total += size;

        if (ctx->hold_size >= ctx->rsp_journal_need) {
            continue;
        }

        take = (size_t) ngx_min(size,
                                (off_t) (ctx->rsp_journal_need
                                         - ctx->hold_size));

        b    = ngx_calloc_buf(r->pool);
        copy = ngx_alloc_chain_link(r->pool);
        p    = NULL;

        if (b != NULL && copy != NULL && ngx_buf_in_memory(cl->buf)) {
            p = ngx_pnalloc(r->pool, take);
        }

        if (b == NULL || copy == NULL
            || (ngx_buf_in_memory(cl->buf) && p == NULL))
        {
            ctx->rsp_journal_need = ctx->hold_size;
            continue;
        }

        if (p != NULL) {
            ngx_memcpy(p, cl->buf->pos, take);

            b->start  = p;
            b->pos    = p;
            b->last   = p + take;
            b->end    = p + take;
            b->memory = 1;

        } else {
            b->in_file   = 1;
            b->file      = cl->buf->file;
            b->file_pos  = cl->buf->file_pos;
            b->file_last = cl->buf->file_pos + (off_t) take;
        }

        copy->buf  = b;
        copy->next = NULL;

        *ctx->hold_last = copy;
        ctx->hold_last  = &copy->next;
        ctx->hold_size += take;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (last && !ctx->rsp_journal_done) {
        ctx->rsp_last = 1;
        ngx_http_waf_response_journal_finish(ctx);
    }

    return rc;
}


static void
ngx_http_waf_response_journal_finish(ngx_http_waf_ctx_t *ctx)
{
    ctx->rsp_journal_done  = 1;
    ctx->ph->body_ready    = 1;
    ctx->ph->agent_settled = 1;
    ctx->state             = NGX_HTTP_WAF_ST_DONE;

    ngx_http_waf_log_verdict(ctx);
}


static void
ngx_http_waf_response_journal_resume(ngx_http_waf_ctx_t *ctx)
{
    ctx->waiting = 0;
    ctx->state   = NGX_HTTP_WAF_ST_DONE;

    ngx_http_waf_log_verdict(ctx);
}


static void
ngx_http_waf_response_journal_cleanup(void *data)
{
    ngx_http_waf_ctx_t  *ctx = data;

    if (!ctx->rsp_journal || ctx->phases[NGX_HTTP_WAF_PHASE_RESPONSE].logged) {
        return;
    }

    ngx_http_waf_phase_enter(ctx, NGX_HTTP_WAF_PHASE_RESPONSE);
    ngx_http_waf_log_verdict(ctx);
}
