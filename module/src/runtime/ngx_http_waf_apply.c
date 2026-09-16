#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"


#define NGX_HTTP_WAF_DEBUG_HEADER  "X-WAF-Debug"

#define NGX_HTTP_WAF_LOG_VAR_MAX   128


static void ngx_http_waf_log_vars(ngx_http_waf_ctx_t *ctx, ngx_str_t *out);
static ngx_int_t ngx_http_waf_apply_headers(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_header_in_set(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_waf_header_out_set(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static void ngx_http_waf_header_out_unset(ngx_http_request_t *r,
    ngx_str_t *name);
static ngx_uint_t ngx_http_waf_header_listed(ngx_str_t *list, ngx_str_t *name);
static ngx_int_t ngx_http_waf_deny(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_deny_with_form(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t status);
static ngx_http_waf_reply_t *ngx_http_waf_form_reply(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_form_fetched(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_form_fail(ngx_http_waf_ctx_t *ctx, const char *why);
static ngx_uint_t ngx_http_waf_send_reply(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_int_t ngx_http_waf_send_issue(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static void ngx_http_waf_send_body_fetched(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_send_settled(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_body_op_t *op, ngx_uint_t obj);
static void ngx_http_waf_send_fail(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    const char *why);
static void ngx_http_waf_send_apply(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_send_verify(ngx_http_waf_body_op_t *op,
    off_t size, u_char *sha256, ngx_uint_t sha256_set);
static ngx_int_t ngx_http_waf_send_swap_body(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_body_op_t *op);
static ngx_int_t ngx_http_waf_redirect(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_cookies(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_cookie_set(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_cookie_t *ck);
static ngx_int_t ngx_http_waf_debug_header(ngx_http_waf_ctx_t *ctx);
static ngx_http_waf_deny_response_t *ngx_http_waf_deny_entry(
    ngx_http_waf_ctx_t *ctx);
ngx_http_waf_deny_response_t *ngx_http_waf_deny_entry_pub(
    ngx_http_waf_ctx_t *ctx);


static ngx_str_t  ngx_http_waf_score_code = ngx_string("SCORE_THRESHOLD");
static ngx_str_t  ngx_http_waf_no_code = ngx_string("-");
static ngx_str_t  ngx_http_waf_send_fail_code = ngx_string("REWRITE_FAILED");

static ngx_str_t  ngx_http_waf_rsp_forbid_set[] = {
    ngx_string("set-cookie"),
    ngx_string("location"),
    ngx_string("date"),
    ngx_null_string
};

static ngx_str_t  ngx_http_waf_rsp_forbid_unset[] = {
    ngx_string("content-type"),
    ngx_string("location"),
    ngx_string("date"),
    ngx_null_string
};
static ngx_str_t  ngx_http_waf_same_site[] = {
    ngx_null_string,
    ngx_string("Lax"),
    ngx_string("Strict"),
    ngx_string("None")
};


ngx_int_t
ngx_http_waf_apply(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    ngx_http_waf_send_apply(ctx);

    ngx_http_waf_log_verdict(ctx);

    rc = ngx_http_waf_apply_overrides(ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    switch (ctx->ph->verdict) {

    case NGX_HTTP_WAF_V_DENY:
        return ngx_http_waf_deny(ctx);

    case NGX_HTTP_WAF_V_REDIRECT:
        return ngx_http_waf_redirect(ctx);

    default:
        return NGX_DECLINED;
    }
}


ngx_int_t
ngx_http_waf_apply_overrides(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->replies != NULL) {
        wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
        n    = wmcf->inspectors.nelts;

        for (i = 0; i < n; i++) {
            reply = &ctx->ph->replies[i];

            if (!reply->received) {
                continue;
            }

            if (ngx_http_waf_apply_headers(ctx, i, reply) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (ngx_http_waf_cookies(ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_waf_debug_header(ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_waf_apply_debug(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_debug_header(ctx);
}


static ngx_int_t
ngx_http_waf_apply_headers(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    ngx_uint_t     i;
    ngx_str_t     *unset;
    ngx_keyval_t  *set;

    if (reply->passive || reply->vote) {
        return NGX_OK;
    }

    if (reply->headers_set != NULL || reply->headers_unset != NULL) {
        ngx_http_waf_loc_conf_t  *wlcf;

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        if (ngx_http_waf_send_of(wlcf, ctx->phase, NGX_HTTP_WAF_OBJ_HEADERS)
            == NGX_HTTP_WAF_SEND_ORIGINAL)
        {
            ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                          "waf: inspector %ui asked to change headers on the "
                          "%V phase; skipped, waf_send %V headers=original",
                          index, ngx_http_waf_phase_name(ctx->phase),
                          ngx_http_waf_phase_name(ctx->phase));
            return NGX_OK;
        }
    }

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {

        ngx_uint_t                 j;
        ngx_http_waf_inspector_t  *insp;
        ngx_http_waf_main_conf_t  *wmcf;

        if (reply->headers_set == NULL && reply->headers_unset == NULL) {
            return NGX_OK;
        }

        wmcf = ngx_http_get_module_main_conf(ctx->request,
                                             ngx_http_waf_module);
        insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

        if (ctx->phase != NGX_HTTP_WAF_PHASE_RESPONSE) {
            ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                          "waf: inspector %ui asked to change headers on the "
                          "%V phase; not supported", index,
                          ngx_http_waf_phase_name(ctx->phase));
            return NGX_OK;
        }

        if (reply->headers_unset != NULL) {
            unset = reply->headers_unset->elts;

            for (j = 0; j < reply->headers_unset->nelts; j++) {

                if (ngx_http_waf_header_listed(ngx_http_waf_rsp_forbid_unset,
                                               &unset[j]))
                {
                    ngx_log_error(NGX_LOG_WARN,
                                  ctx->request->connection->log, 0,
                                  "waf: inspector \"%V\" may not unset "
                                  "response header \"%V\"",
                                  &insp->name, &unset[j]);
                    continue;
                }

                ngx_http_waf_header_out_unset(ctx->request, &unset[j]);
            }
        }

        if (reply->headers_set != NULL) {
            set = reply->headers_set->elts;

            for (j = 0; j < reply->headers_set->nelts; j++) {

                if (ngx_http_waf_header_listed(ngx_http_waf_rsp_forbid_set,
                                               &set[j].key))
                {
                    ngx_log_error(NGX_LOG_WARN,
                                  ctx->request->connection->log, 0,
                                  "waf: inspector \"%V\" may not override "
                                  "response header \"%V\"",
                                  &insp->name, &set[j].key);
                    continue;
                }

                if (ngx_http_waf_header_out_set(ctx->request, &set[j].key,
                                                &set[j].value) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
        }

        return NGX_OK;
    }

    if (reply->headers_unset != NULL && reply->headers_unset->nelts != 0) {
        unset = reply->headers_unset->elts;

        for (i = 0; i < reply->headers_unset->nelts; i++) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspector %ui asked to unset request header "
                          "\"%V\"; not supported", index, &unset[i]);
        }
    }

    if (reply->headers_set == NULL) {
        return NGX_OK;
    }

    set = reply->headers_set->elts;

    for (i = 0; i < reply->headers_set->nelts; i++) {
        if (ngx_http_waf_header_in_set(ctx->request, &set[i].key, &set[i].value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_header_in_set(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
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

        if (h[i].hash == 0 || h[i].key.len != name->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0) {
            h[i].value = *value;
            return NGX_OK;
        }
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->lowcase_key = ngx_pnalloc(r->pool, name->len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, name->data, name->len);

    h->hash  = ngx_hash_key(h->lowcase_key, name->len);
    h->key   = *name;
    h->value = *value;

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_header_listed(ngx_str_t *list, ngx_str_t *name)
{
    ngx_uint_t  i;

    for (i = 0; list[i].len != 0; i++) {

        if (list[i].len == name->len
            && ngx_strncasecmp(list[i].data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_http_waf_header_out_set(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    if (name->len == sizeof("Content-Type") - 1
        && ngx_strncasecmp(name->data, (u_char *) "Content-Type", name->len)
           == 0)
    {
        r->headers_out.content_type          = *value;
        r->headers_out.content_type_len      = value->len;
        r->headers_out.content_type_lowcase  = NULL;

        ngx_str_null(&r->headers_out.charset);

        return NGX_OK;
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

        if (h[i].key.len != name->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0) {
            h[i].value = *value;

            if (h[i].hash == 0) {
                h[i].hash = 1;
            }

            return NGX_OK;
        }
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash  = 1;
    h->key   = *name;
    h->value = *value;

    if (name->len == sizeof("Server") - 1
        && ngx_strncasecmp(name->data, (u_char *) "Server", name->len) == 0)
    {
        r->headers_out.server = h;
    }

    return NGX_OK;
}


static void
ngx_http_waf_header_out_unset(ngx_http_request_t *r, ngx_str_t *name)
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

        if (h[i].hash == 0 || h[i].key.len != name->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0) {
            h[i].hash = 0;
        }
    }

    if (name->len == sizeof("Server") - 1
        && ngx_strncasecmp(name->data, (u_char *) "Server", name->len) == 0
        && r->headers_out.server == NULL)
    {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return;
        }

        h->hash = 0;
        ngx_str_set(&h->key, "Server");
        ngx_str_null(&h->value);

        r->headers_out.server = h;
    }
}


static ngx_http_waf_deny_response_t *
ngx_http_waf_deny_entry(ngx_http_waf_ctx_t *ctx)
{
    ngx_str_t                     *name;
    ngx_http_waf_loc_conf_t       *wlcf;
    ngx_http_waf_main_conf_t      *wmcf;
    ngx_http_waf_deny_response_t  *dr;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->exception_response.len != 0) {
        name = &ctx->exception_response;

    } else if (ctx->by_local) {
        name = (ctx->local_response.len != 0)
                   ? &ctx->local_response
                   : &wlcf->deny_response_default;

    } else if (ctx->ph->by_score) {
        name = (wlcf->score_deny_response[ctx->phase].len != 0)
                   ? &wlcf->score_deny_response[ctx->phase]
                   : &wlcf->deny_response_default;

    } else if (ctx->ph->decisive != NULL && ctx->ph->decisive->response_name.len != 0) {
        name = &ctx->ph->decisive->response_name;

    } else {
        name = &wlcf->deny_response_default;
    }

    dr = ngx_http_waf_deny_response_find(wmcf, name);

    if (dr == NULL && name != &wlcf->deny_response_default) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: deny response \"%V\" is not declared, "
                      "falling back to \"%V\"", name,
                      &wlcf->deny_response_default);

        dr = ngx_http_waf_deny_response_find(wmcf,
                                             &wlcf->deny_response_default);
    }

    return dr;
}


ngx_int_t
ngx_http_waf_fail_status(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_deny_response_t  *dr;

    if (ctx->exception_response.len == 0) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    dr = ngx_http_waf_deny_entry(ctx);

    if (dr == NULL || dr->type != NGX_HTTP_WAF_DENY_TYPE_HTTP) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: exception response \"%V\" is not usable here; "
                      "answering %d", &ctx->exception_response,
                      NGX_HTTP_SERVICE_UNAVAILABLE);

        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    return (ngx_int_t) dr->status;
}


ngx_http_waf_deny_response_t *
ngx_http_waf_deny_entry_pub(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_deny_entry(ctx);
}


static ngx_int_t
ngx_http_waf_deny(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_deny_response_t  *dr;

    dr = ngx_http_waf_deny_entry(ctx);

    if (dr == NULL) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (dr->type != NGX_HTTP_WAF_DENY_TYPE_HTTP) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: deny response \"%V\" has a non-http type; "
                      "denying with %d", &dr->name, NGX_HTTP_FORBIDDEN);

        return NGX_HTTP_FORBIDDEN;
    }

    if (ctx->form_op != NULL && !ctx->form_failed) {
        return ngx_http_waf_deny_with_form(ctx, dr->status);
    }

    return (ngx_int_t) dr->status;
}


static ngx_http_waf_reply_t *
ngx_http_waf_form_reply(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_reply_t  *reply;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST
        || ctx->ph->verdict != NGX_HTTP_WAF_V_DENY
        || ctx->by_local || ctx->ph->by_score)
    {
        return NULL;
    }

    reply = ctx->ph->decisive;

    if (reply == NULL || !reply->received || reply->passive || reply->vote
        || !reply->rewrite_has || !reply->rewrite_body)
    {
        return NULL;
    }

    return reply;
}


ngx_int_t
ngx_http_waf_form_fetch(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t                rc;
    ngx_http_waf_reply_t    *reply;
    ngx_http_waf_body_op_t  *op;

    if (ctx->form_fetched) {
        return NGX_OK;
    }

    ctx->form_fetched = 1;

    reply = ngx_http_waf_form_reply(ctx);

    if (reply == NULL) {
        return NGX_OK;
    }

    if (reply->rewrite_size > NGX_HTTP_WAF_FORM_MAX) {
        ngx_http_waf_form_fail(ctx, "the object exceeds the form limit");
        return NGX_OK;
    }

    rc = ngx_http_waf_store_get(ctx, &reply->rewrite_key,
                                NGX_HTTP_WAF_FORM_MAX,
                                ngx_http_waf_form_fetched, &op);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK || op == NULL || op->status != NGX_OK) {
        ngx_http_waf_form_fail(ctx, "the store cannot serve the object");
        return NGX_OK;
    }

    ctx->form_op = op;

    return NGX_OK;
}


static void
ngx_http_waf_form_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_http_waf_ctx_t  *ctx = op->data_ctx;

    if (op->status == NGX_OK) {
        ctx->form_op = op;

    } else if (op->status == NGX_DECLINED) {
        ngx_http_waf_form_fail(ctx, "no such key in the store");

    } else {
        ngx_http_waf_form_fail(ctx, "store error or timeout");
    }

    ngx_http_waf_form_resumed(ctx);
}


static void
ngx_http_waf_form_fail(ngx_http_waf_ctx_t *ctx, const char *why)
{
    ngx_str_t                 *name;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    static ngx_str_t  unknown = ngx_string("-");

    ctx->form_failed = 1;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    name = (ctx->ph->decisive != NULL)
               ? &insp[ctx->ph->decisive_index].name : &unknown;

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: deny body by \"%V\" failed (%s); denying with the "
                  "catalog page, ray %*s", name, why,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
}


static ngx_uint_t
ngx_http_waf_send_reply(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    if (ctx->ph->live == NULL) {
        return NGX_HTTP_WAF_MAX_INSPECTORS;
    }

    return ctx->ph->rewrite_last;
}


ngx_int_t
ngx_http_waf_send_fetch(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (ctx->send_fetched) {
        return NGX_OK;
    }

    if (!ctx->send_body_done) {
        ctx->send_body_done = 1;

        rc = ngx_http_waf_send_issue(ctx, NGX_HTTP_WAF_OBJ_BODY);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
    }

    ctx->send_fetched = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_send_issue(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    off_t                      cap;
    ngx_int_t                  rc;
    ngx_uint_t                 found;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_locator_t    *loc;
    ngx_http_waf_body_op_t    *op;
    ngx_http_waf_loc_conf_t   *wlcf;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST
        || ctx->ph->verdict != NGX_HTTP_WAF_V_ALLOW
        || ctx->by_local || ctx->ph->replies == NULL)
    {
        return NGX_OK;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (ngx_http_waf_send_of(wlcf, NGX_HTTP_WAF_PHASE_REQUEST, obj)
        != NGX_HTTP_WAF_SEND_STORE)
    {
        return NGX_OK;
    }

    found = ngx_http_waf_send_reply(ctx, obj);

    if (found == NGX_HTTP_WAF_MAX_INSPECTORS) {
        return NGX_OK;
    }

    reply = &ctx->ph->replies[found];
    ctx->send_body_index = found;

    loc = ctx->ph->locator;

    if (r->request_body == NULL || loc == NULL
        || loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
    {
        ngx_http_waf_send_fail(ctx, obj, "the request has no body object "
                               "in the store");
        return NGX_OK;
    }

    if (loc->truncated || !loc->complete) {
        reply->rewrite_partial = 1;

        ngx_http_waf_send_fail(ctx, obj, "the capture is a prefix of the "
                               "body and a slice cannot replace the whole; "
                               "waf_send request body=store needs a whole "
                               "capture");
        return NGX_OK;
    }

    cap = (off_t) wlcf->body_limit[NGX_HTTP_WAF_PHASE_REQUEST];

    if (reply->rewrite_size > cap) {
        ngx_http_waf_send_fail(ctx, obj, "the object exceeds the limit");
        return NGX_OK;
    }

    rc = ngx_http_waf_store_get(ctx, &reply->rewrite_key, cap,
                                ngx_http_waf_send_body_fetched, &op);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK || op == NULL) {
        ngx_http_waf_send_fail(ctx, obj, "the store cannot serve the object");
        return NGX_OK;
    }

    ngx_http_waf_send_settled(ctx, op, obj);

    return NGX_OK;
}


static void
ngx_http_waf_send_settled(ngx_http_waf_ctx_t *ctx, ngx_http_waf_body_op_t *op,
    ngx_uint_t obj)
{
    if (op->status == NGX_OK) {
        ctx->send_body_op = op;
        return;
    }

    ngx_http_waf_send_fail(ctx, obj,
                           op->status == NGX_DECLINED
                               ? "no such key in the store"
                               : "store error or timeout");
}


static void
ngx_http_waf_send_body_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_http_waf_ctx_t  *ctx = op->data_ctx;

    ngx_http_waf_send_settled(ctx, op, NGX_HTTP_WAF_OBJ_BODY);

    if (ngx_http_waf_send_fetch(ctx) == NGX_AGAIN) {
        return;
    }

    ngx_http_waf_form_resumed(ctx);
}


static void
ngx_http_waf_send_fail(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    const char *why)
{
    ngx_uint_t                 index, deny;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    index = ctx->send_body_index;

    wmcf  = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    wlcf  = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    insp  = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];
    reply = &ctx->ph->replies[index];

    ctx->send_body_failed = 1;

    deny = wlcf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_BODY]
           == NGX_HTTP_WAF_POLICY_BLOCK;

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: request %V rewrite by \"%V\" failed (%s); %s, "
                  "ray %*s",
                  ngx_http_waf_obj_name(obj), &insp->name, why,
                  deny ? "denying per waf_exception body"
                       : "passing the original",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    if (!deny || ctx->ph->verdict == NGX_HTTP_WAF_V_DENY) {
        return;
    }

    reply->verdict     = NGX_HTTP_WAF_V_DENY;
    reply->reason_code = ngx_http_waf_send_fail_code;

    ngx_str_null(&reply->response_name);

    ctx->ph->verdict        = NGX_HTTP_WAF_V_DENY;
    ctx->ph->decisive       = reply;
    ctx->ph->decisive_index = index;
    ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;
}


typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  value;
    unsigned                   has_eq:1;
    unsigned                   dead:1;
} ngx_http_waf_arg_pair_t;


static ngx_int_t
ngx_http_waf_args_split(ngx_http_request_t *r, ngx_array_t *pairs)
{
    u_char                   *p, *last, *eq, *amp;
    ngx_http_waf_arg_pair_t  *pair;

    if (r->args.len == 0) {
        return NGX_OK;
    }

    p    = r->args.data;
    last = p + r->args.len;

    for ( ;; ) {
        amp = ngx_strlchr(p, last, '&');
        if (amp == NULL) {
            amp = last;
        }

        pair = ngx_array_push(pairs);
        if (pair == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(pair, sizeof(ngx_http_waf_arg_pair_t));

        eq = ngx_strlchr(p, amp, '=');

        pair->name.data = p;

        if (eq == NULL) {
            pair->name.len = amp - p;

        } else {
            pair->name.len   = eq - p;
            pair->value.data = eq + 1;
            pair->value.len  = amp - eq - 1;
            pair->has_eq     = 1;
        }

        if (amp == last) {
            return NGX_OK;
        }

        p = amp + 1;
    }
}


static void
ngx_http_waf_args_unset(ngx_array_t *pairs, ngx_str_t *name)
{
    ngx_uint_t                i;
    ngx_http_waf_arg_pair_t  *pair = pairs->elts;

    for (i = 0; i < pairs->nelts; i++) {
        if (!pair[i].dead && pair[i].name.len == name->len
            && ngx_memcmp(pair[i].name.data, name->data, name->len) == 0)
        {
            pair[i].dead = 1;
        }
    }
}


static ngx_int_t
ngx_http_waf_args_set(ngx_array_t *pairs, ngx_keyval_t *kv)
{
    ngx_uint_t                i, found;
    ngx_http_waf_arg_pair_t  *pair;

    pair  = pairs->elts;
    found = pairs->nelts;

    for (i = 0; i < pairs->nelts; i++) {

        if (pair[i].dead || pair[i].name.len != kv->key.len
            || ngx_memcmp(pair[i].name.data, kv->key.data, kv->key.len) != 0)
        {
            continue;
        }

        if (found == pairs->nelts) {
            found = i;
            continue;
        }

        pair[i].dead = 1;
    }

    if (found != pairs->nelts) {
        pair[found].value  = kv->value;
        pair[found].has_eq = 1;
        return NGX_OK;
    }

    pair = ngx_array_push(pairs);
    if (pair == NULL) {
        return NGX_ERROR;
    }

    pair->name   = kv->key;
    pair->value  = kv->value;
    pair->has_eq = 1;
    pair->dead   = 0;

    return NGX_OK;
}


size_t
ngx_http_waf_args_cap(ngx_http_request_t *r)
{
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    return cscf->large_client_header_buffers.size;
}


static void
ngx_http_waf_args_apply(ngx_http_waf_ctx_t *ctx)
{
    size_t                     len, was, cap;
    u_char                    *p, *start;
    ngx_str_t                 *unset;
    ngx_uint_t                 i, j, n, first, authors;
    ngx_array_t               *pairs;
    ngx_keyval_t              *set;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_arg_pair_t   *pair;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST
        || ctx->ph->verdict != NGX_HTTP_WAF_V_ALLOW
        || ctx->by_local || ctx->ph->replies == NULL)
    {
        return;
    }

    wmcf    = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf    = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    insp    = wmcf->inspectors.elts;
    n       = wmcf->inspectors.nelts;
    pairs   = NULL;
    authors = 0;

    for (i = 0; i < n; i++) {
        reply = &ctx->ph->replies[i];

        if (!reply->received || reply->passive || reply->vote
            || (reply->args_set == NULL && reply->args_unset == NULL))
        {
            continue;
        }

        if (ngx_http_waf_send_of(wlcf, NGX_HTTP_WAF_PHASE_REQUEST,
                                 NGX_HTTP_WAF_OBJ_ARGS)
            != NGX_HTTP_WAF_SEND_STORE)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "waf: inspector \"%V\" asked to change the query "
                          "string; skipped, waf_send request args=original, "
                          "ray %*s",
                          &insp[i].name,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
            continue;
        }

        if (pairs == NULL) {
            pairs = ngx_array_create(r->pool, 8,
                                     sizeof(ngx_http_waf_arg_pair_t));
            if (pairs == NULL || ngx_http_waf_args_split(r, pairs) != NGX_OK) {
                goto nomem;
            }
        }

        if (reply->args_unset != NULL) {
            unset = reply->args_unset->elts;

            for (j = 0; j < reply->args_unset->nelts; j++) {
                ngx_http_waf_args_unset(pairs, &unset[j]);
            }
        }

        if (reply->args_set != NULL) {
            set = reply->args_set->elts;

            for (j = 0; j < reply->args_set->nelts; j++) {
                if (ngx_http_waf_args_set(pairs, &set[j]) != NGX_OK) {
                    goto nomem;
                }
            }
        }

        reply->args_applied = 1;
        authors++;
    }

    if (authors == 0) {
        return;
    }

    pair = pairs->elts;
    len  = 0;

    for (i = 0; i < pairs->nelts; i++) {
        if (pair[i].dead) {
            continue;
        }

        len += pair[i].name.len + 1;

        if (pair[i].has_eq) {
            len += 1 + pair[i].value.len;
        }
    }

    if (len != 0) {
        len--;
    }

    cap = ngx_http_waf_args_cap(r);

    if (len > cap) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: query string after inspector edits is %uz bytes, "
                      "over large_client_header_buffers %uz; the original "
                      "goes upstream, ray %*s",
                      len, cap,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        goto undo;
    }

    start = ngx_pnalloc(r->pool, len != 0 ? len : 1);
    if (start == NULL) {
        goto nomem;
    }

    p     = start;
    first = 1;

    for (i = 0; i < pairs->nelts; i++) {
        if (pair[i].dead) {
            continue;
        }

        if (!first) {
            *p++ = '&';
        }

        first = 0;

        p = ngx_cpymem(p, pair[i].name.data, pair[i].name.len);

        if (pair[i].has_eq) {
            *p++ = '=';
            p = ngx_cpymem(p, pair[i].value.data, pair[i].value.len);
        }
    }

    was = r->args.len;

    r->args.data          = start;
    r->args.len           = len;
    r->valid_unparsed_uri = 0;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: request query string rewritten by %ui inspector(s), "
                  "%uz -> %uz bytes, ray %*s",
                  authors, was, len,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
    return;

nomem:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "waf: query string edit failed: out of memory; the "
                  "original goes upstream, ray %*s",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

undo:

    for (i = 0; i < n; i++) {
        ctx->ph->replies[i].args_applied = 0;
    }
}


static void
ngx_http_waf_send_apply(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return;
    }

    if (ctx->send_body_op != NULL
        && ctx->ph->verdict == NGX_HTTP_WAF_V_ALLOW
        && ngx_http_waf_send_swap_body(ctx, ctx->send_body_op) != NGX_OK)
    {
        ngx_http_waf_send_fail(ctx, NGX_HTTP_WAF_OBJ_BODY,
                               "the object does not match its declaration");
    }

    ngx_http_waf_args_apply(ctx);
}


ngx_uint_t
ngx_http_waf_rewrite_applied(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    if (!(ctx->ph->rewrite_applied & (1ULL << index))) {
        return 0;
    }

    if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST) {
        return ctx->req_body_rewritten;
    }

    return ctx->rsp_rewritten;
}


static ngx_int_t
ngx_http_waf_send_verify(ngx_http_waf_body_op_t *op, off_t size,
    u_char *sha256, ngx_uint_t sha256_set)
{
    u_char                 digest[32];
    ngx_http_waf_sha256_t  sha;

    if (op->data.len != (size_t) size) {
        return NGX_ERROR;
    }

    if (sha256_set) {
        ngx_http_waf_sha256_init(&sha);
        ngx_http_waf_sha256_update(&sha, op->data.data, op->data.len);
        ngx_http_waf_sha256_final(&sha, digest);

        if (ngx_memcmp(digest, sha256, 32) != 0) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_send_swap_body(ngx_http_waf_ctx_t *ctx, ngx_http_waf_body_op_t *op)
{
    u_char                   *p;
    off_t                     was;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_reply_t     *reply;
    ngx_http_waf_sha256_t     sha;
    ngx_http_waf_loc_conf_t  *wlcf;
    ngx_http_request_body_t  *rb;

    reply = &ctx->ph->replies[ctx->send_body_index];
    rb    = r->request_body;

    if (rb == NULL
        || ngx_http_waf_send_verify(op, reply->rewrite_size,
                                    reply->rewrite_sha256,
                                    reply->rewrite_sha256_set)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b->start         = op->data.data;
    b->pos           = op->data.data;
    b->last          = op->data.data + op->data.len;
    b->end           = b->last;
    b->memory        = 1;
    b->last_buf      = 1;
    b->last_in_chain = 1;

    cl->buf  = b;
    cl->next = NULL;

    was      = r->headers_in.content_length_n;
    rb->bufs = cl;
    rb->rest = 0;

    r->headers_in.content_length_n = (off_t) op->data.len;

    if (r->headers_in.content_length != NULL) {
        p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        r->headers_in.content_length->value.len =
            ngx_sprintf(p, "%O", (off_t) op->data.len) - p;
        r->headers_in.content_length->value.data = p;
    }

    ctx->req_body_rewritten = 1;

    if (!reply->rewrite_sha256_set) {
        ngx_http_waf_sha256_init(&sha);
        ngx_http_waf_sha256_update(&sha, op->data.data, op->data.len);
        ngx_http_waf_sha256_final(&sha, reply->rewrite_sha256);
    }

    reply->rewrite_digest = 1;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->shoot[ctx->phase].preview_source_sent
        & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
    {
        ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY] = op->data;
    }

    ngx_http_waf_store_del_key(ctx, &reply->rewrite_key);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: request body rewritten, %O -> %uz bytes, ray %*s",
                  was, op->data.len,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_deny_with_form(ngx_http_waf_ctx_t *ctx, ngx_uint_t status)
{
    u_char                     digest[32];
    ngx_int_t                  rc;
    ngx_str_t                  ct;
    ngx_table_elt_t           *h;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_reply_t      *reply = ctx->ph->decisive;
    ngx_http_waf_sha256_t      sha;
    ngx_http_waf_body_op_t    *op = ctx->form_op;
    ngx_http_complex_value_t   cv;

    if (op->data.len != (size_t) reply->rewrite_size) {
        ngx_http_waf_form_fail(ctx, "the object does not match its "
                               "declared size");
        return (ngx_int_t) status;
    }

    if (reply->rewrite_sha256_set) {
        ngx_http_waf_sha256_init(&sha);
        ngx_http_waf_sha256_update(&sha, op->data.data, op->data.len);
        ngx_http_waf_sha256_final(&sha, digest);

        if (ngx_memcmp(digest, reply->rewrite_sha256, 32) != 0) {
            ngx_http_waf_form_fail(ctx, "the object does not match its "
                                   "declared sha256");
            return (ngx_int_t) status;
        }
    }

    if (!ctx->ph->body_ready && !ctx->ph->body_discarded) {
        ctx->ph->body_discarded = 1;
        (void) ngx_http_discard_request_body(r);
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Cache-Control");
    ngx_str_set(&h->value, "no-store");

    ctx->state = NGX_HTTP_WAF_ST_DONE;

    if (reply->rewrite_content_type.len != 0) {
        ct = reply->rewrite_content_type;

    } else {
        ngx_str_set(&ct, "text/html; charset=utf-8");
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));
    cv.value = op->data;

    rc = ngx_http_send_response(r, status, &ct, &cv);

    ngx_http_finalize_request(r, rc);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_waf_redirect(ngx_http_waf_ctx_t *ctx)
{
    ngx_table_elt_t       *h;
    ngx_http_request_t    *r = ctx->request;
    ngx_http_waf_reply_t  *reply = ctx->ph->decisive;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Location");
    h->value = reply->redirect_url;

    r->headers_out.location = h;

    return (ngx_int_t) reply->status;
}


ngx_uint_t
ngx_http_waf_result_status(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_deny_response_t  *dr;

    switch (ctx->ph->verdict) {

    case NGX_HTTP_WAF_V_DENY:
        dr = ngx_http_waf_deny_entry(ctx);
        if (dr == NULL) {
            return NGX_HTTP_FORBIDDEN;
        }

        return dr->status;

    case NGX_HTTP_WAF_V_REDIRECT:
        if (ctx->ph->decisive != NULL && ctx->ph->decisive->status != 0) {
            return ctx->ph->decisive->status;
        }

        return NGX_HTTP_MOVED_TEMPORARILY;

    default:
        return 0;
    }
}


static ngx_int_t
ngx_http_waf_cookies(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, j, n;
    ngx_http_waf_cookie_t     *ck;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->replies == NULL) {
        return NGX_OK;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    n    = wmcf->inspectors.nelts;

    for (i = 0; i < n; i++) {
        reply = &ctx->ph->replies[i];

        if (!reply->received || reply->passive || reply->vote
            || reply->cookies == NULL)
        {
            continue;
        }

        ck = reply->cookies->elts;

        for (j = 0; j < reply->cookies->nelts; j++) {
            if (ngx_http_waf_cookie_set(ctx, &ck[j]) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_cookie_set(ngx_http_waf_ctx_t *ctx, ngx_http_waf_cookie_t *ck)
{
    u_char                   *p;
    size_t                    len;
    ngx_str_t                *same_site;
    ngx_table_elt_t          *h;
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    same_site = &ngx_http_waf_same_site[wlcf->cookie_same_site
                                        <= NGX_HTTP_WAF_SAMESITE_NONE
                                            ? wlcf->cookie_same_site
                                            : NGX_HTTP_WAF_SAMESITE_UNSET];

    len = ck->name.len + 1 + ck->value.len
          + sizeof("; Path=") - 1 + ck->path.len
          + sizeof("; Max-Age=") - 1 + NGX_TIME_T_LEN
          + sizeof("; HttpOnly") - 1
          + sizeof("; Secure") - 1
          + sizeof("; SameSite=") - 1 + same_site->len;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Set-Cookie");
    h->value.data = p;

    p = ngx_cpymem(p, ck->name.data, ck->name.len);
    *p++ = '=';
    p = ngx_cpymem(p, ck->value.data, ck->value.len);

    if (ck->path.len != 0) {
        p = ngx_cpymem(p, "; Path=", sizeof("; Path=") - 1);
        p = ngx_cpymem(p, ck->path.data, ck->path.len);
    }

    if (ck->max_age_set) {
        p = ngx_cpymem(p, "; Max-Age=", sizeof("; Max-Age=") - 1);
        p = ngx_sprintf(p, "%T", ck->max_age);
    }

    if (wlcf->cookie_http_only) {
        p = ngx_cpymem(p, "; HttpOnly", sizeof("; HttpOnly") - 1);
    }

    if (wlcf->cookie_secure) {
        p = ngx_cpymem(p, "; Secure", sizeof("; Secure") - 1);
    }

    if (same_site->len != 0) {
        p = ngx_cpymem(p, "; SameSite=", sizeof("; SameSite=") - 1);
        p = ngx_cpymem(p, same_site->data, same_site->len);
    }

    h->value.len = (size_t) (p - h->value.data);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_debug_header(ngx_http_waf_ctx_t *ctx)
{
    u_char                    *p, *last;
    size_t                     len;
    ngx_uint_t                 i, n;
    ngx_table_elt_t           *h;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (!wlcf->debug_header) {
        return NGX_OK;
    }

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    n    = wmcf->inspectors.nelts;

    len = sizeof("rid= ray= v= score= shadow= wave=") + NGX_HTTP_WAF_RID_HEX_LEN
          + NGX_HTTP_WAF_RAY_HEX_LEN
          + 3 * NGX_INT_T_LEN + 8
          + sizeof(" by=score by=local fail=") + NGX_INT_T_LEN
          + sizeof(" rewrite=") + NGX_SIZE_T_LEN
          + NGX_HTTP_WAF_BODY_DEBUG_LEN;

    for (i = 0; i < n; i++) {
        len += insp[i].name.len + sizeof(" =:ms,passive,vote,skip") + 32;
        len += sizeof("/profile=") - 1 + wlcf->profiles[i].len;

        if (ctx->ph->replies != NULL) {
            len += ctx->ph->replies[i].reason_code.len;
        }
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, NGX_HTTP_WAF_DEBUG_HEADER);
    h->value.data = p;

    last = p + len;

    p = ngx_slprintf(p, last,
                     "rid=%*s ray=%*s v=%V score=%i shadow=%i wave=%ui",
                     (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex,
                     (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex,
                     ngx_http_waf_verdict_name(ctx->ph->verdict),
                     ctx->ph->score, ctx->ph->shadow, ctx->ph->wave);

    if (ctx->ph->by_score) {
        p = ngx_slprintf(p, last, " by=score");
    }

    if (ctx->by_local) {
        p = ngx_slprintf(p, last, " by=local");
    }

    if (ctx->ph->fail != NGX_HTTP_WAF_CODE_NONE) {
        p = ngx_slprintf(p, last, " fail=%V",
                         ngx_http_waf_code_name(ctx->ph->fail));
    }

    if (ctx->rsp_rewritten) {
        p = ngx_slprintf(p, last, " rewrite=%uz", ctx->hold_size);
    }

    p = ngx_http_waf_body_debug(ctx, p, last);

    for (i = 0; i < n; i++) {

        if (!(ctx->ph->published & (1ULL << i))) {
            continue;
        }

        p = ngx_slprintf(p, last, " %V=", &insp[i].name);

        if (ctx->ph->skipped & (1ULL << i)) {
            p = ngx_slprintf(p, last, "skip");
            continue;
        }

        reply = (ctx->ph->replies != NULL) ? &ctx->ph->replies[i] : NULL;

        if (reply == NULL || !reply->received) {
            p = ngx_slprintf(p, last, "none");
            continue;
        }

        p = ngx_slprintf(p, last, "%V", ngx_http_waf_verdict_name(
                                            reply->verdict));

        if (reply->score != 0) {
            p = ngx_slprintf(p, last, "/%i", reply->score);
        }

        if (reply->reason_code.len != 0) {
            p = ngx_slprintf(p, last, "/%V", &reply->reason_code);
        }

        p = ngx_slprintf(p, last, "/%Mms", reply->latency);

        if (reply->passive) {
            p = ngx_slprintf(p, last, "/passive");

        } else if (reply->vote) {
            p = ngx_slprintf(p, last, "/vote");
        }

        if (wlcf->profiles[i].len != 0) {
            p = ngx_slprintf(p, last, "/profile=%V", &wlcf->profiles[i]);
        }
    }

    h->value.len = (size_t) (p - h->value.data);

    return NGX_OK;
}


static void
ngx_http_waf_log_vars(ngx_http_waf_ctx_t *ctx, ngx_str_t *out)
{
    u_char                    *p;
    size_t                     len, n;
    ngx_uint_t                 i, j;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    ngx_str_null(out);

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->vars == NULL || wmcf->vars == NULL) {
        return;
    }

    var = wmcf->vars->elts;
    len = 0;

    for (i = 0; i < wmcf->vars->nelts; i++) {
        if (var[i].builtin || ctx->vars[i].len == 0) {
            continue;
        }

        n = ngx_min(ctx->vars[i].len, NGX_HTTP_WAF_LOG_VAR_MAX);

        len += var[i].name.len + n + sizeof(" =\"\"") - 1;
    }

    if (len == 0) {
        return;
    }

    p = ngx_pnalloc(ctx->request->pool, len);
    if (p == NULL) {
        return;
    }

    out->data = p;

    for (i = 0; i < wmcf->vars->nelts; i++) {
        if (var[i].builtin || ctx->vars[i].len == 0) {
            continue;
        }

        n = ngx_min(ctx->vars[i].len, NGX_HTTP_WAF_LOG_VAR_MAX);

        *p++ = ' ';
        p = ngx_cpymem(p, var[i].name.data, var[i].name.len);
        *p++ = '=';
        *p++ = '"';

        for (j = 0; j < n; j++) {
            u_char  c = ctx->vars[i].data[j];

            *p++ = (c < 0x20 || c == '"') ? '.' : c;
        }

        *p++ = '"';
    }

    out->len = (size_t) (p - out->data);
}


void
ngx_http_waf_log_verdict(ngx_http_waf_ctx_t *ctx)
{
    ngx_str_t                 *code, vars;
    ngx_uint_t                 i, n, level;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->logged) {
        return;
    }

    ctx->ph->logged = 1;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    n    = wmcf->inspectors.nelts;

    if (ctx->by_local && ctx->local_rule.len != 0) {
        code = &ctx->local_rule;

    } else if (ctx->ph->by_score) {
        code = &ngx_http_waf_score_code;

    } else if (ctx->ph->decisive != NULL && ctx->ph->decisive->reason_code.len != 0) {
        code = &ctx->ph->decisive->reason_code;

    } else {
        code = &ngx_http_waf_no_code;
    }

    level = (ctx->ph->verdict == NGX_HTTP_WAF_V_ALLOW) ? NGX_LOG_INFO
                                                   : NGX_LOG_NOTICE;

    ngx_http_waf_log_vars(ctx, &vars);

    if (ctx->ph->fail != NGX_HTTP_WAF_CODE_NONE) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: no verdict (%V) phase %V, rid %*s, ray %*s, "
                      "score %i, shadow %i, %M ms%V",
                      ngx_http_waf_code_name(ctx->ph->fail),
                      ngx_http_waf_phase_name(ctx->phase),
                      (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex,
                      ctx->ph->score, ctx->ph->shadow,
                      ngx_current_msec - ctx->started, &vars);

    } else {
        ngx_log_error(level, ctx->request->connection->log, 0,
                      "waf: %V phase %V, rid %*s, ray %*s, score %i, "
                      "shadow %i, reason \"%V\", %M ms%V",
                      ngx_http_waf_verdict_name(ctx->ph->verdict),
                      ngx_http_waf_phase_name(ctx->phase),
                      (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex,
                      ctx->ph->score, ctx->ph->shadow, code,
                      ngx_current_msec - ctx->started, &vars);
    }

    for (i = 0; i < n; i++) {

        if (!(ctx->ph->published & (1ULL << i))) {
            continue;
        }

        if (ctx->ph->skipped & (1ULL << i)) {
            ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" skipped, rid %*s",
                          &insp[i].name,
                          (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);
            continue;
        }

        reply = (ctx->ph->replies != NULL) ? &ctx->ph->replies[i] : NULL;

        if (reply == NULL || !reply->received) {
            ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" did not answer, rid %*s",
                          &insp[i].name,
                          (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);
            continue;
        }

        if (reply->verdict == NGX_HTTP_WAF_V_ALLOW && !reply->passive) {
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" %V%s score %i "
                      "reason \"%V\" in %M ms, ray %*s",
                      &insp[i].name,
                      ngx_http_waf_verdict_name(reply->verdict),
                      reply->passive ? " (passive)"
                                     : reply->vote ? " (vote)" : "",
                      reply->score,
                      &reply->reason_code, reply->latency,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
    }

    ngx_http_waf_audit_flush_deferred(ctx);

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
    } else if (ngx_http_waf_archive_pending(ctx)) {
        ngx_http_waf_audit_defer(ctx);

    } else {
        ngx_http_waf_audit_request(ctx);
    }

    ngx_http_waf_body_release(ctx);
}
