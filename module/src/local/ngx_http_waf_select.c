#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_SEL_PREFIX      "$waf_request_"
#define NGX_HTTP_WAF_SEL_PREFIX_LEN  (sizeof(NGX_HTTP_WAF_SEL_PREFIX) - 1)


static ngx_int_t ngx_http_waf_pairs_ready(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t object);
static ngx_int_t ngx_http_waf_pairs_args(ngx_http_waf_ctx_t *ctx,
    ngx_array_t *pairs);
static ngx_int_t ngx_http_waf_pairs_cookies(ngx_http_waf_ctx_t *ctx,
    ngx_array_t *pairs);
static ngx_int_t ngx_http_waf_cookie_split(ngx_array_t *pairs,
    ngx_str_t *value);
static ngx_int_t ngx_http_waf_pairs_headers(ngx_http_waf_ctx_t *ctx,
    ngx_array_t *pairs);
static ngx_int_t ngx_http_waf_unescape(ngx_pool_t *pool, ngx_str_t *src,
    ngx_str_t *out);
static ngx_uint_t ngx_http_waf_pair_named(ngx_http_waf_operand_t *op,
    ngx_http_waf_pair_t *pair);


static ngx_str_t  ngx_http_waf_sel_objects[] = {
    ngx_null_string,
    ngx_string("args"),
    ngx_string("cookies"),
    ngx_string("headers")
};


ngx_int_t
ngx_http_waf_operand_compile(ngx_conf_t *cf, ngx_str_t *token,
    ngx_http_waf_operand_t *op, ngx_uint_t all, const char *directive)
{
    u_char                            *dot, *p, *last;
    ngx_str_t                          object, name;
    ngx_uint_t                         i;
    ngx_http_compile_complex_value_t   ccv;

    ngx_memzero(op, sizeof(ngx_http_waf_operand_t));

    op->text   = *token;
    op->object = NGX_HTTP_WAF_SEL_VAR;
    op->binary = (token->len == sizeof("$binary_remote_addr") - 1
                  && ngx_strncmp(token->data, "$binary_remote_addr",
                                 token->len) == 0);

    if (token->len > 5 && ngx_strncmp(token->data, "$waf_", 5) == 0
        && ngx_strlchr(token->data, token->data + token->len, '.') != NULL
        && ngx_strncmp(token->data, NGX_HTTP_WAF_SEL_PREFIX,
                       NGX_HTTP_WAF_SEL_PREFIX_LEN) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown selector \"%V\" in %s; only "
                           "$waf_request_args / cookies / headers exist, "
                           "the response phase does not run yet",
                           token, directive);
        return NGX_ERROR;
    }

    if (token->len <= NGX_HTTP_WAF_SEL_PREFIX_LEN
        || ngx_strncmp(token->data, NGX_HTTP_WAF_SEL_PREFIX,
                       NGX_HTTP_WAF_SEL_PREFIX_LEN) != 0)
    {
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf            = cf;
        ccv.value         = token;
        ccv.complex_value = &op->value;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    p    = token->data + NGX_HTTP_WAF_SEL_PREFIX_LEN;
    last = token->data + token->len;
    dot  = ngx_strlchr(p, last, '.');

    if (dot == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: selector \"%V\" in %s needs a name: "
                           "$waf_request_cookies.sid or "
                           "$waf_request_cookies.*", token, directive);
        return NGX_ERROR;
    }

    object.data = p;
    object.len  = (size_t) (dot - p);

    name.data = dot + 1;
    name.len  = (size_t) (last - dot - 1);

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: selector \"%V\" in %s has an empty name",
                           token, directive);
        return NGX_ERROR;
    }

    for (i = 1; i < NGX_HTTP_WAF_SEL_COUNT; i++) {
        if (ngx_http_waf_sel_objects[i].len == object.len
            && ngx_strncmp(ngx_http_waf_sel_objects[i].data, object.data,
                           object.len) == 0)
        {
            op->object = i;
            break;
        }
    }

    if (op->object == NGX_HTTP_WAF_SEL_VAR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown selector object \"%V\" in %s; "
                           "expected args, cookies or headers",
                           &object, directive);
        return NGX_ERROR;
    }

    if (name.len == 1 && name.data[0] == '*') {
        if (!all) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: \"%V\" in %s cannot be a set; name the "
                               "pair, e.g. $waf_request_cookies.sid",
                               token, directive);
            return NGX_ERROR;
        }

        op->all = 1;
        return NGX_OK;
    }

    op->name = name;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_cond_parse(ngx_conf_t *cf, ngx_uint_t *i, ngx_array_t **conds,
    const char *directive)
{
    ngx_str_t                 *args, *value, *op_word, *set;
    ngx_uint_t                 negate, next;
    ngx_http_waf_cond_t       *cond;
    ngx_http_waf_main_conf_t  *wmcf;

    args = cf->args->elts;
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (*i + 3 >= cf->args->nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: \"if\" in %s expects "
                           "<value> in|not in <dataset>", directive);
        return NGX_ERROR;
    }

    value   = &args[*i + 1];
    op_word = &args[*i + 2];

    if (op_word->len == 3 && ngx_strncmp(op_word->data, "not", 3) == 0) {
        negate = 1;

        if (*i + 4 >= cf->args->nelts
            || args[*i + 3].len != 2
            || ngx_strncmp(args[*i + 3].data, "in", 2) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: \"if\" in %s expects \"not in\"",
                               directive);
            return NGX_ERROR;
        }

        set  = &args[*i + 4];
        next = *i + 4;

    } else if (op_word->len == 2 && ngx_strncmp(op_word->data, "in", 2) == 0) {
        negate = 0;
        set    = &args[*i + 3];
        next   = *i + 3;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: \"if\" in %s expects \"in\" or \"not in\", "
                           "got \"%V\"", directive, op_word);
        return NGX_ERROR;
    }

    if (*conds == NULL) {
        *conds = ngx_array_create(cf->pool, 2, sizeof(ngx_http_waf_cond_t));
        if (*conds == NULL) {
            return NGX_ERROR;
        }
    }

    cond = ngx_array_push(*conds);
    if (cond == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(cond, sizeof(ngx_http_waf_cond_t));

    cond->negate = negate ? 1 : 0;

    cond->dataset = ngx_http_waf_dataset_find(wmcf, set);

    if (cond->dataset == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: dataset \"%V\" in %s is not declared; "
                           "waf_local_dataset must come first", set, directive);
        return NGX_ERROR;
    }

    if (ngx_http_waf_operand_compile(cf, value, &cond->operand, 1, directive)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    *i = next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_pairs_ready(ngx_http_waf_ctx_t *ctx, ngx_uint_t object)
{
    ngx_int_t     rc;
    ngx_array_t  *pairs;

    if (ctx->pairs_parsed & (1 << object)) {
        return (ctx->pairs[object] != NULL) ? NGX_OK : NGX_ERROR;
    }

    ctx->pairs_parsed |= (1 << object);

    pairs = ngx_array_create(ngx_http_waf_ctx_pool(ctx), 8,
                             sizeof(ngx_http_waf_pair_t));
    if (pairs == NULL) {
        return NGX_ERROR;
    }

    switch (object) {

    case NGX_HTTP_WAF_SEL_ARGS:
        rc = ngx_http_waf_pairs_args(ctx, pairs);
        break;

    case NGX_HTTP_WAF_SEL_COOKIES:
        rc = ngx_http_waf_pairs_cookies(ctx, pairs);
        break;

    default:
        rc = ngx_http_waf_pairs_headers(ctx, pairs);
        break;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->pairs[object] = pairs;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_pairs_args(ngx_http_waf_ctx_t *ctx, ngx_array_t *pairs)
{
    u_char               *p, *last, *amp, *eq;
    ngx_str_t             raw_name, raw_value;
    ngx_http_waf_pair_t  *pair;

    p    = ctx->request->args.data;
    last = p + ctx->request->args.len;

    while (p < last) {

        amp = ngx_strlchr(p, last, '&');

        if (amp == NULL) {
            amp = last;
        }

        if (amp == p) {
            p++;
            continue;
        }

        eq = ngx_strlchr(p, amp, '=');

        if (eq == NULL) {
            raw_name.data  = p;
            raw_name.len   = (size_t) (amp - p);
            ngx_str_null(&raw_value);

        } else {
            raw_name.data  = p;
            raw_name.len   = (size_t) (eq - p);
            raw_value.data = eq + 1;
            raw_value.len  = (size_t) (amp - eq - 1);
        }

        pair = ngx_array_push(pairs);
        if (pair == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_waf_unescape(ngx_http_waf_ctx_pool(ctx), &raw_name, &pair->name)
                != NGX_OK
            || ngx_http_waf_unescape(ngx_http_waf_ctx_pool(ctx), &raw_value,
                                     &pair->value) != NGX_OK)
        {
            return NGX_ERROR;
        }

        p = amp + 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_pairs_cookies(ngx_http_waf_ctx_t *ctx, ngx_array_t *pairs)
{
    ngx_table_elt_t  *h;

#if (nginx_version >= 1023000)

    for (h = ctx->request->headers_in.cookie; h != NULL; h = h->next) {

        if (ngx_http_waf_cookie_split(pairs, &h->value) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#else

    ngx_uint_t         i;
    ngx_table_elt_t  **cookies;

    cookies = ctx->request->headers_in.cookies.elts;

    for (i = 0; i < ctx->request->headers_in.cookies.nelts; i++) {
        h = cookies[i];

        if (ngx_http_waf_cookie_split(pairs, &h->value) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_cookie_split(ngx_array_t *pairs, ngx_str_t *value)
{
    u_char               *p, *last, *semi, *eq, *start, *end;
    ngx_http_waf_pair_t  *pair;

    p    = value->data;
    last = p + value->len;

    while (p < last) {

        semi = ngx_strlchr(p, last, ';');

        if (semi == NULL) {
            semi = last;
        }

        eq = ngx_strlchr(p, semi, '=');

        if (eq == NULL) {
            p = semi + 1;
            continue;
        }

        pair = ngx_array_push(pairs);
        if (pair == NULL) {
            return NGX_ERROR;
        }

        start = p;
        end   = eq;

        while (start < end && (*start == ' ' || *start == '\t')) {
            start++;
        }

        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }

        pair->name.data = start;
        pair->name.len  = (size_t) (end - start);

        start = eq + 1;
        end   = semi;

        while (start < end && (*start == ' ' || *start == '\t')) {
            start++;
        }

        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }

        if (end - start >= 2 && *start == '"' && end[-1] == '"') {
            start++;
            end--;
        }

        pair->value.data = start;
        pair->value.len  = (size_t) (end - start);

        p = semi + 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_pairs_headers(ngx_http_waf_ctx_t *ctx, ngx_array_t *pairs)
{
    ngx_uint_t            i;
    ngx_list_part_t      *part;
    ngx_table_elt_t      *header;
    ngx_http_waf_pair_t  *pair;

    part   = &ctx->request->headers_in.headers.part;
    header = part->elts;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part   = part->next;
            header = part->elts;
            i      = 0;
        }

        pair = ngx_array_push(pairs);
        if (pair == NULL) {
            return NGX_ERROR;
        }

        pair->name  = header[i].key;
        pair->value = header[i].value;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_unescape(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *out)
{
    u_char  *buf, *dst, *d, *p, *q, *last;

    if (src->len == 0) {
        ngx_str_null(out);
        return NGX_OK;
    }

    buf = ngx_pnalloc(pool, src->len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p    = src->data;
    last = p + src->len;
    dst  = buf;

    while (p < last) {

        if (*p == '+') {
            *dst++ = ' ';
            p++;
            continue;
        }

        if (*p == '%' && last - p >= 3) {
            q = p;
            d = dst;

            ngx_unescape_uri(&d, &q, 3, 0);

            if (d != dst) {
                dst = d;
                p   = q;
                continue;
            }
        }

        *dst++ = *p++;
    }

    out->data = buf;
    out->len  = (size_t) (dst - buf);

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_pair_named(ngx_http_waf_operand_t *op, ngx_http_waf_pair_t *pair)
{
    if (op->all) {
        return 1;
    }

    if (pair->name.len != op->name.len) {
        return 0;
    }

    if (op->object == NGX_HTTP_WAF_SEL_HEADERS) {
        return ngx_strncasecmp(pair->name.data, op->name.data, op->name.len)
                   == 0;
    }

    return ngx_strncmp(pair->name.data, op->name.data, op->name.len) == 0;
}


ngx_int_t
ngx_http_waf_operand_single(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_operand_t *op, ngx_str_t *out)
{
    ngx_uint_t            i;
    ngx_array_t          *pairs;
    ngx_http_waf_pair_t  *pair;

    ngx_str_null(out);

    if (op->object == NGX_HTTP_WAF_SEL_VAR) {
        return ngx_http_complex_value(ctx->request, &op->value, out);
    }

    if (ngx_http_waf_pairs_ready(ctx, op->object) != NGX_OK) {
        return NGX_ERROR;
    }

    pairs = ctx->pairs[op->object];
    pair  = pairs->elts;

    for (i = 0; i < pairs->nelts; i++) {
        if (ngx_http_waf_pair_named(op, &pair[i])) {
            *out = pair[i].value;
            return NGX_OK;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_operand_hit(ngx_http_waf_ctx_t *ctx, ngx_http_waf_operand_t *op,
    ngx_http_waf_dataset_t *ds, ngx_str_t *matched)
{
    ngx_str_t             value;
    ngx_uint_t            i;
    ngx_array_t          *pairs;
    ngx_http_waf_pair_t  *pair;

    if (op->object == NGX_HTTP_WAF_SEL_VAR) {

        if (ngx_http_complex_value(ctx->request, &op->value, &value)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }

        if (ngx_http_waf_dataset_hit(ds, &value, op->binary)) {
            *matched = value;
            return NGX_OK;
        }

        return NGX_DECLINED;
    }

    if (ngx_http_waf_pairs_ready(ctx, op->object) != NGX_OK) {
        return NGX_DECLINED;
    }

    pairs = ctx->pairs[op->object];
    pair  = pairs->elts;

    for (i = 0; i < pairs->nelts; i++) {

        if (!ngx_http_waf_pair_named(op, &pair[i])) {
            continue;
        }

        if (pair[i].value.len == 0) {
            continue;
        }

        if (ngx_http_waf_dataset_hit(ds, &pair[i].value, 0)) {
            *matched = pair[i].value;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_waf_cond_test(ngx_http_waf_ctx_t *ctx, ngx_array_t *conds)
{
    ngx_str_t             matched;
    ngx_int_t             rc;
    ngx_uint_t            i;
    ngx_http_waf_cond_t  *cond;

    if (conds == NULL || conds->nelts == 0) {
        return NGX_OK;
    }

    cond = conds->elts;

    for (i = 0; i < conds->nelts; i++) {

        ngx_str_null(&matched);

        rc = ngx_http_waf_operand_hit(ctx, &cond[i].operand, cond[i].dataset,
                                      &matched);

        if (cond[i].negate) {
            if (rc == NGX_OK) {
                return NGX_DECLINED;
            }

        } else if (rc != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


ngx_http_waf_mask_t
ngx_http_waf_cond_off(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                i;
    ngx_array_t              *list;
    ngx_http_waf_binding_t   *b;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->ph->cond_settled) {
        return ctx->ph->cond_off;
    }

    ctx->ph->cond_settled = 1;
    ctx->ph->cond_off     = 0;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    list = wlcf->inspects[ctx->phase];

    if (list == NULL) {
        return 0;
    }

    b = list->elts;

    for (i = 0; i < list->nelts; i++) {

        if (b[i].conds == NULL) {
            continue;
        }

        if (ngx_http_waf_cond_test(ctx, b[i].conds) == NGX_OK) {
            continue;
        }

        ctx->ph->cond_off |= 1ULL << b[i].index;

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" skipped by if, ray %*s",
                      &b[i].name, (size_t) NGX_HTTP_WAF_RAY_HEX_LEN,
                      ctx->ray_hex);
    }

    return ctx->ph->cond_off;
}


ngx_uint_t
ngx_http_waf_waves_pending(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                i;
    ngx_array_t              *waves;
    ngx_http_waf_mask_t       off;
    ngx_http_waf_wave_t      *w;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    if (waves == NULL || waves->nelts == 0) {
        return 0;
    }

    off = ngx_http_waf_cond_off(ctx);

    if (off == 0) {
        return 1;
    }

    w = waves->elts;

    for (i = 0; i < waves->nelts; i++) {
        if ((w[i].all & ~off) != 0) {
            return 1;
        }
    }

    return 0;
}
