#include "ngx_http_waf.h"


static ngx_int_t ngx_http_waf_var_ray(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_rid(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_reason(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_name(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_message(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_ray(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_scope(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_subject(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_deny_retry(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_score(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_node_id(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_var_frame(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_http_variable_t  ngx_http_waf_variables[] = {

    { ngx_string("waf_ray"), NULL,
      ngx_http_waf_var_ray, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rid"), NULL,
      ngx_http_waf_var_rid, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_reason"), NULL,
      ngx_http_waf_var_reason, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_name"), NULL,
      ngx_http_waf_var_deny_name, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_status"), NULL,
      ngx_http_waf_var_deny_status, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_message"), NULL,
      ngx_http_waf_var_deny_message, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_ray"), NULL,
      ngx_http_waf_var_deny_ray, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_addr"), NULL,
      ngx_http_waf_var_deny_addr, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_scope"), NULL,
      ngx_http_waf_var_deny_scope, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_subject"), NULL,
      ngx_http_waf_var_deny_subject, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_deny_retry"), NULL,
      ngx_http_waf_var_deny_retry, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_score"), NULL,
      ngx_http_waf_var_score, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_node_id"), NULL,
      ngx_http_waf_var_node_id, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_frame_opcode"), NULL,
      ngx_http_waf_var_frame, NGX_HTTP_WAF_FRAME_VAR_OPCODE,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_frame_direction"), NULL,
      ngx_http_waf_var_frame, NGX_HTTP_WAF_FRAME_VAR_DIRECTION,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_frame_size"), NULL,
      ngx_http_waf_var_frame, NGX_HTTP_WAF_FRAME_VAR_SIZE,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_conn_id"), NULL,
      ngx_http_waf_var_frame, NGX_HTTP_WAF_FRAME_VAR_CONN_ID,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


ngx_int_t
ngx_http_waf_variables_init(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_waf_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data        = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_ray(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = NGX_HTTP_WAF_RAY_HEX_LEN;
    v->data         = ctx->ray_hex;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_rid(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = NGX_HTTP_WAF_RID_HEX_LEN;
    v->data         = ctx->rid_hex;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_reason(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_waf_ctx_t  *ctx;
    ngx_str_t           *reason;

    static ngx_str_t     score_reason = ngx_string("SCORE_THRESHOLD");
    static ngx_str_t     empty        = ngx_string("-");

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->by_local && ctx->local_rule.len != 0) {
        reason = &ctx->local_rule;

    } else if (ctx->ph->by_score) {
        reason = &score_reason;

    } else if (ctx->ph->decisive != NULL
               && ctx->ph->decisive->reason_code.len != 0)
    {
        reason = &ctx->ph->decisive->reason_code;

    } else {
        reason = &empty;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = reason->len;
    v->data         = reason->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_name(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                     *name;
    ngx_http_waf_ctx_t            *ctx;
    ngx_http_waf_loc_conf_t       *wlcf;
    ngx_http_waf_deny_response_t  *dr;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    dr = ngx_http_waf_deny_entry_pub(ctx);

    if (dr != NULL) {
        name = &dr->name;

    } else {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        name = &wlcf->deny_response_default;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = name->len;
    v->data         = name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                        *p;
    ngx_http_waf_ctx_t            *ctx;
    ngx_http_waf_deny_response_t  *dr;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    dr = ngx_http_waf_deny_entry_pub(ctx);

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->data         = p;

    if (dr != NULL) {
        v->len = ngx_sprintf(p, "%ui", dr->status) - p;
    } else {
        v->len = ngx_sprintf(p, "%ui", (ngx_uint_t) NGX_HTTP_FORBIDDEN) - p;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_message(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_waf_ctx_t            *ctx;
    ngx_http_waf_deny_response_t  *dr;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    dr = ngx_http_waf_deny_entry_pub(ctx);

    if (dr == NULL || dr->message.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = dr->message.len;
    v->data         = dr->message.data;

    return NGX_OK;
}


static ngx_http_waf_reply_t *
ngx_http_waf_deny_detail(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->by_local || ctx->ph->by_score) {
        return NULL;
    }

    return ctx->ph->decisive;
}


static ngx_uint_t
ngx_http_waf_deny_param_on(ngx_http_waf_ctx_t *ctx, ngx_uint_t bit)
{
    ngx_http_waf_deny_response_t  *dr;

    dr = ngx_http_waf_deny_entry_pub(ctx);

    if (dr == NULL || dr->params == 0) {
        return 1;
    }

    return (dr->params & bit) != 0;
}


static ngx_int_t
ngx_http_waf_var_deny_ray(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL
        || !ngx_http_waf_deny_param_on(ctx, NGX_HTTP_WAF_DENY_P_RAY))
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = NGX_HTTP_WAF_RAY_HEX_LEN;
    v->data         = ctx->ray_hex;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_addr(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL
        || !ngx_http_waf_deny_param_on(ctx, NGX_HTTP_WAF_DENY_P_ADDR))
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = r->connection->addr_text.len;
    v->data         = r->connection->addr_text.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_scope(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t             *name;
    ngx_http_waf_ctx_t    *ctx;
    ngx_http_waf_reply_t  *reply;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL
        || !ngx_http_waf_deny_param_on(ctx, NGX_HTTP_WAF_DENY_P_SCOPE))
    {
        v->not_found = 1;
        return NGX_OK;
    }

    reply = ngx_http_waf_deny_detail(ctx);

    if (reply == NULL || reply->reason_scope == NGX_HTTP_WAF_SCOPE_NONE) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (reply->reason_subject.len == 0
        && (reply->reason_scope == NGX_HTTP_WAF_SCOPE_ADDRESS
            || reply->reason_scope == NGX_HTTP_WAF_SCOPE_NETWORK
            || reply->reason_scope == NGX_HTTP_WAF_SCOPE_ASN))
    {
        v->not_found = 1;
        return NGX_OK;
    }

    name = ngx_http_waf_deny_scope_name(reply->reason_scope);

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = name->len;
    v->data         = name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_subject(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_waf_ctx_t    *ctx;
    ngx_http_waf_reply_t  *reply;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL
        || !ngx_http_waf_deny_param_on(ctx, NGX_HTTP_WAF_DENY_P_SUBJECT))
    {
        v->not_found = 1;
        return NGX_OK;
    }

    reply = ngx_http_waf_deny_detail(ctx);

    if (reply == NULL || reply->reason_subject.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = reply->reason_subject.len;
    v->data         = reply->reason_subject.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_deny_retry(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                *p;
    ngx_uint_t             retry;
    ngx_http_waf_ctx_t    *ctx;
    ngx_http_waf_reply_t  *reply;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL
        || !ngx_http_waf_deny_param_on(ctx, NGX_HTTP_WAF_DENY_P_RETRY))
    {
        v->not_found = 1;
        return NGX_OK;
    }

    reply = ngx_http_waf_deny_detail(ctx);
    retry = (reply != NULL) ? reply->reason_retry : ctx->local_retry;

    if (retry == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->data         = p;
    v->len          = ngx_sprintf(p, "%ui", retry) - p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_score(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char              *p;
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->data         = p;
    v->len          = ngx_sprintf(p, "%i", ctx->ph->score) - p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_node_id(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->node_id.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;
    v->len          = wmcf->node_id.len;
    v->data         = wmcf->node_id.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_var_frame(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t            value;
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL
        || ngx_http_waf_frame_var(ctx, (ngx_uint_t) data, &value) != NGX_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid        = 1;
    v->no_cacheable = 1;
    v->not_found    = 0;
    v->len          = value.len;
    v->data         = value.data;

    return NGX_OK;
}
