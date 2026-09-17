#include "codec/ngx_http_waf_codec.h"
#include "body/ngx_http_waf_body.h"


#define NGX_HTTP_WAF_MSG_OVERHEAD   1024


static size_t ngx_http_waf_msg_prior_size(ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf);
static void ngx_http_waf_msg_conn(ngx_http_waf_jw_t *jw,
    ngx_http_request_t *r);
static void ngx_http_waf_msg_http(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_msg_prior(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static void ngx_http_waf_msg_resume(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static void ngx_http_waf_msg_response(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx);
static size_t ngx_http_waf_msg_response_size(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_msg_sessions(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static size_t ngx_http_waf_msg_sessions_size(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index);
static void ngx_http_waf_msg_groups(ngx_http_waf_jw_t *jw, ngx_str_t *groups);


#define ngx_http_waf_msg_room(len)   ((len) * 6 + 8)

#define NGX_HTTP_WAF_PRIOR_REASON_MAX  64


ngx_int_t
ngx_http_waf_msg_request(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_str_t *out)
{
    size_t                     size;
    u_char                    *buf;
    ngx_msec_int_t             left;
    ngx_http_waf_jw_t          jw;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    size = NGX_HTTP_WAF_MSG_OVERHEAD
           + ngx_http_waf_msg_room(insp->name.len)
           + ngx_http_waf_msg_room(wmcf->node_id.len)
           + ngx_http_waf_msg_room(r->method_name.len)
           + ngx_http_waf_msg_room(r->headers_in.server.len)
           + ngx_http_waf_msg_room(r->uri.len)
           + ngx_http_waf_msg_room(r->http_protocol.len)
           + ngx_http_waf_msg_room(cscf->server_name.len)
           + ngx_http_waf_msg_room(clcf->name.len)
           + ngx_http_waf_msg_room(wlcf->profiles[index].len)
           + ngx_http_waf_msg_room(insp->audit_subject.len)
           + ngx_http_waf_msg_prior_size(wmcf, wlcf)
           + ngx_http_waf_msg_sessions_size(ctx, index)
           + ngx_http_waf_vars_size(ctx, insp->vars_mask)
           + ngx_http_waf_needs_size()
           + ngx_http_waf_store_size(ctx)
           + ngx_http_waf_msg_response_size(ctx)
           + ngx_http_waf_msg_frame_size(ctx)
           + sizeof(",\"resume\":{\"want\":true,\"require\":false,"
                    "\"token\":\"\"}")
           + NGX_HTTP_WAF_RAY_HEX_LEN;

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_http_waf_jw_init(&jw, buf, size);

    left = (ctx->ph->due != 0)
               ? (ngx_msec_int_t) (ctx->ph->due - ngx_current_msec)
               : (ngx_msec_int_t) wlcf->deadline[ctx->phase];
    if (left < 0) {
        left = 0;
    }

    {
        ngx_http_waf_binding_t  *bind;

        bind = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

        if (bind != NULL && bind->timeout != 0
            && (ngx_msec_t) left > bind->timeout)
        {
            left = (ngx_msec_int_t) bind->timeout;
        }
    }

    ngx_http_waf_jw_lit(&jw, "{\"v\":");
    ngx_http_waf_jw_int(&jw, NGX_HTTP_WAF_PROTOCOL_VERSION);

    ngx_http_waf_jw_lit(&jw, ",\"rid\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->rid_hex, NGX_HTTP_WAF_RID_HEX_LEN);

    ngx_http_waf_jw_lit(&jw, "\",\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->ray_hex, NGX_HTTP_WAF_RAY_HEX_LEN);

    ngx_http_waf_jw_lit(&jw, "\",\"phase\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_phase_name(ctx->phase));

    ngx_http_waf_jw_lit(&jw, ",\"wave\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) ctx->ph->wave);

    ngx_http_waf_jw_lit(&jw, ",\"inspector\":");
    ngx_http_waf_jw_str(&jw, &insp->name);

    ngx_http_waf_jw_lit(&jw, ",\"deadline_ms\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) left);

    ngx_http_waf_jw_lit(&jw, ",\"audit_subject\":");

    if (insp->audit_subject.len != 0) {
        ngx_http_waf_jw_str(&jw, &insp->audit_subject);

    } else {
        ngx_http_waf_jw_lit(&jw, "null");
    }

    ngx_http_waf_jw_lit(&jw, ",\"node\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);

    ngx_http_waf_msg_conn(&jw, r);
    ngx_http_waf_msg_http(&jw, ctx);

    ngx_http_waf_msg_frame(&jw, ctx);

    ngx_http_waf_vars_write(&jw, ctx, NGX_HTTP_WAF_VAR_MAX, insp->vars_mask);

    ngx_http_waf_needs_write(&jw, ctx);
    ngx_http_waf_store_write(&jw, ctx);

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        ngx_http_waf_store_write_phase(&jw, ctx, NGX_HTTP_WAF_PHASE_REQUEST,
                                       "request_store");
    }

    ngx_http_waf_msg_response(&jw, ctx);
    ngx_http_waf_msg_resume(&jw, ctx, index);

    ngx_http_waf_jw_lit(&jw, ",\"route\":{\"server_name\":");
    ngx_http_waf_jw_str(&jw, &cscf->server_name);
    ngx_http_waf_jw_lit(&jw, ",\"location\":");
    ngx_http_waf_jw_str(&jw, &clcf->name);
    ngx_http_waf_jw_lit(&jw, ",\"profile\":");

    if (wlcf->profiles[index].len != 0) {
        ngx_http_waf_jw_str(&jw, &wlcf->profiles[index]);

    } else {
        ngx_http_waf_jw_lit(&jw, "\"default\"");
    }

    ngx_http_waf_jw_lit(&jw, "}");

    ngx_http_waf_jw_lit(&jw, ",\"score\":{\"total\":");
    ngx_http_waf_jw_int(&jw, ctx->ph->score);
    ngx_http_waf_jw_lit(&jw, ",\"deny_at\":");
    ngx_http_waf_jw_int(&jw, ngx_http_waf_score_deny_at(ctx));
    ngx_http_waf_jw_lit(&jw, "}");

    ngx_http_waf_msg_prior(&jw, ctx, index);
    ngx_http_waf_msg_sessions(&jw, ctx, index);

    ngx_http_waf_jw_lit(&jw, "}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "waf: inspect message for \"%V\" does not fit %uz bytes",
                      &insp->name, size);
        return NGX_ERROR;
    }

    out->data = buf;
    out->len  = ngx_http_waf_jw_len(&jw);

    return NGX_OK;
}


static void
ngx_http_waf_msg_resume(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_http_waf_binding_t   *b;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST) {

        if (!ngx_http_waf_resume_wanted(wlcf, index, ctx->phase)) {
            return;
        }

        ngx_http_waf_jw_lit(jw, ",\"resume\":{\"want\":true,\"token\":\"");
        ngx_http_waf_jw_raw(jw, (const u_char *) ctx->ray_hex,
                            NGX_HTTP_WAF_RAY_HEX_LEN);
        ngx_http_waf_jw_lit(jw, "\"}");

        return;
    }

    b = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

    if (b == NULL || b->resume == NGX_HTTP_WAF_RESUME_OFF) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"resume\":{\"token\":\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) ctx->ray_hex,
                        NGX_HTTP_WAF_RAY_HEX_LEN);

    if (b->resume == NGX_HTTP_WAF_RESUME_REQUIRE) {
        ngx_http_waf_jw_lit(jw, "\",\"require\":true}");

    } else {
        ngx_http_waf_jw_lit(jw, "\",\"require\":false}");
    }
}


static void
ngx_http_waf_msg_response(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t     i, first;
    ngx_array_t   *headers;
    ngx_keyval_t  *h;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_RESPONSE) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"response\":{\"status\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ctx->rsp_status);

    ngx_http_waf_jw_lit(jw, ",\"upstream_ms\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ctx->upstream_ms);

    if (ngx_http_waf_store_locator_phase(ctx, NGX_HTTP_WAF_PHASE_RESPONSE,
                                         NGX_HTTP_WAF_OBJ_HEADERS) != NULL
        && ngx_http_waf_obj_visible_phase(ctx, NGX_HTTP_WAF_PHASE_RESPONSE,
                                          NGX_HTTP_WAF_OBJ_HEADERS))
    {
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"headers\":[");

    headers = ngx_http_waf_response_headers(ctx);
    first   = 1;

    for (i = 0; headers != NULL && i < headers->nelts; i++) {
        h = &((ngx_keyval_t *) headers->elts)[i];

        if (h->key.len == 10
            && ngx_strncasecmp(h->key.data, (u_char *) "Set-Cookie", 10) == 0)
        {
            continue;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, "[");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",[");
        }

        ngx_http_waf_jw_str(jw, &h->key);
        ngx_http_waf_jw_lit(jw, ",");
        ngx_http_waf_jw_str(jw, &h->value);
        ngx_http_waf_jw_lit(jw, "]");
    }

    ngx_http_waf_jw_lit(jw, "]}");
}


static size_t
ngx_http_waf_msg_response_size(ngx_http_waf_ctx_t *ctx)
{
    size_t         size;
    ngx_uint_t     i;
    ngx_array_t   *headers;
    ngx_keyval_t  *h;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_RESPONSE) {
        return 0;
    }

    size = sizeof(",\"response\":{\"status\":,\"upstream_ms\":,\"headers\":[]}")
           + 2 * NGX_INT_T_LEN;

    headers = ngx_http_waf_response_headers(ctx);

    for (i = 0; headers != NULL && i < headers->nelts; i++) {
        h = &((ngx_keyval_t *) headers->elts)[i];

        size += ngx_http_waf_msg_room(h->key.len)
                + ngx_http_waf_msg_room(h->value.len)
                + sizeof(",[,]");
    }

    return size;
}


char *
ngx_http_waf_msg_req_validate(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf)
{
    size_t                     base, size, client, name, profile, audit;
    ngx_uint_t                 i, phase;
    ngx_http_waf_var_t        *var;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_waf_inspector_t  *insp;

    if (!wlcf->enable) {
        return NGX_CONF_OK;
    }

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    client = cscf->large_client_header_buffers.size;

    name    = 0;
    profile = 0;
    audit   = 0;
    insp    = wmcf->inspectors.elts;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        if (insp[i].name.len > name) {
            name = insp[i].name.len;
        }

        if (insp[i].audit_subject.len > audit) {
            audit = insp[i].audit_subject.len;
        }

        if (wlcf->profiles[i].len > profile) {
            profile = wlcf->profiles[i].len;
        }
    }

    base = NGX_HTTP_WAF_MSG_OVERHEAD
           + ngx_http_waf_msg_room(name)
           + ngx_http_waf_msg_room(wmcf->node_id.len)
           + ngx_http_waf_msg_room(cscf->server_name.len)
           + ngx_http_waf_msg_room(clcf->name.len)
           + ngx_http_waf_msg_room(profile)
           + ngx_http_waf_msg_room(audit)
           + ngx_http_waf_msg_prior_size(wmcf, wlcf)
           + ngx_http_waf_needs_size()
           + ngx_http_waf_store_max_size(wmcf, client)
           + sizeof(",\"sessions\":[]")
           + NGX_HTTP_WAF_SESSIONS_MAX * NGX_HTTP_WAF_SESSION_JSON
           + sizeof(",\"resume\":{\"want\":true,\"require\":false,"
                    "\"token\":\"\"}")
           + NGX_HTTP_WAF_RAY_HEX_LEN;

    base += 2 * ngx_http_waf_msg_room(client);

    if (wmcf->vars != NULL) {
        var = wmcf->vars->elts;

        for (i = 0; i < wmcf->vars->nelts; i++) {
            base += ngx_http_waf_msg_room(var[i].name.len)
                    + ngx_http_waf_msg_room(NGX_HTTP_WAF_VAR_MAX) + 2;
        }
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!ngx_http_waf_phase_inspected(wlcf, phase)) {
            continue;
        }

        size = base;

        if (phase != NGX_HTTP_WAF_PHASE_REQUEST) {
            size += ngx_http_waf_store_max_size(wmcf, client);
        }

        /*
         * Response headers that are not captured travel inline; nginx gives
         * the module no bound for them, so the client header buffer does.
         */

        if (phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
            size += sizeof(",\"response\":{\"status\":,\"upstream_ms\":,"
                           "\"headers\":[]}")
                    + 2 * NGX_INT_T_LEN;

            if (!(wlcf->shoot[phase].capture
                  & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)))
            {
                size += 6 * client;
            }
        }

        if (ngx_http_waf_phase_is_frame(phase)) {
            size += 256 + NGX_HTTP_WAF_RAY_HEX_LEN
                    + ngx_http_waf_msg_room(client);
        }

        if (size <= wmcf->bus_payload_max) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: an inspect message of the %V phase on this "
                           "route may reach %uz bytes, which does not fit the "
                           "%uz byte bus payload limit; lower "
                           "large_client_header_buffers (%uz) or raise "
                           "payload_max= in waf_bus",
                           ngx_http_waf_phase_name(phase), size,
                           wmcf->bus_payload_max, client);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


size_t
ngx_http_waf_vars_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t mask)
{
    size_t                     size;
    ngx_uint_t                 i, n;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->vars == NULL || wmcf->vars == NULL || mask == 0) {
        return 0;
    }

    var  = wmcf->vars->elts;
    n    = wmcf->vars->nelts;
    size = sizeof(",\"vars\":{}") - 1;

    for (i = 0; i < n; i++) {
        if (!(mask & ((ngx_uint_t) 1 << i))) {
            continue;
        }

        size += ngx_http_waf_msg_room(var[i].name.len)
                + ngx_http_waf_msg_room(ctx->vars[i].len)
                + 2;
    }

    return size;
}


static size_t
ngx_http_waf_utf8_trim(u_char *data, size_t len)
{
    while (len > 0 && (data[len] & 0xc0) == 0x80) {
        len--;
    }

    return len;
}


void
ngx_http_waf_vars_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    size_t value_max, ngx_uint_t mask)
{
    ngx_str_t                  value;
    ngx_uint_t                 i, n, first;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->vars == NULL || wmcf->vars == NULL || mask == 0) {
        return;
    }

    var   = wmcf->vars->elts;
    n     = wmcf->vars->nelts;
    first = 1;

    for (i = 0; i < n; i++) {

        if (!(mask & ((ngx_uint_t) 1 << i))) {
            continue;
        }

        value = ctx->vars[i];

        if (value.len == 0) {
            continue;
        }

        if (value_max != 0 && value.len > value_max) {
            value.len = ngx_http_waf_utf8_trim(value.data, value_max);

            if (value.len == 0) {
                continue;
            }
        }

        if ((size_t) (jw->end - jw->pos)
            < value.len * 6 + var[i].name.len + 128)
        {
            break;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, ",\"vars\":{");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &var[i].name);
        ngx_http_waf_jw_lit(jw, ":");
        ngx_http_waf_jw_str(jw, &value);
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "}");
    }
}


static size_t
ngx_http_waf_msg_prior_size(ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf)
{
    size_t                     size;
    ngx_uint_t                 i;
    ngx_http_waf_inspector_t  *insp;

    insp = wmcf->inspectors.elts;
    size = 16;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        size += NGX_HTTP_WAF_NPHASE
                * (ngx_http_waf_msg_room(insp[i].name.len)
                   + sizeof(",{\"phase\":\"response\",\"wave\":,"
                            "\"inspector\":,\"verdict\":\"redirect\","
                            "\"score\":,"
                            "\"reason\":{\"code\":}}") - 1
                   + 2 * NGX_INT_T_LEN
                   + ngx_http_waf_msg_room(NGX_HTTP_WAF_PRIOR_REASON_MAX));
    }

    size += wlcf->actions_max
            * (wlcf->action_max
               + sizeof(",{\"do\":\"threshold\",\"apply\":\"session\","
                        "\"phase\":\"response\","
                        "\"code\":,\"delta\":,\"value\":,\"counter\":,"
                        "\"group\":,\"set\":\"off\"}") - 1
               + 2 * NGX_INT_T_LEN);

    return size;
}


static void
ngx_http_waf_msg_conn(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    u_char             buf[NGX_SOCKADDR_STRLEN];
    ngx_str_t          s;
    ngx_connection_t  *c = r->connection;

    ngx_http_waf_jw_lit(jw, ",\"conn\":{\"client_ip\":");
    ngx_http_waf_jw_str(jw, &c->addr_text);

    ngx_http_waf_jw_lit(jw, ",\"client_port\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_inet_get_port(c->sockaddr));

    if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) {
        s.data = buf;
        s.len  = ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf,
                               NGX_SOCKADDR_STRLEN, 0);

        ngx_http_waf_jw_lit(jw, ",\"server_ip\":");
        ngx_http_waf_jw_string(jw, s.data, s.len);

        ngx_http_waf_jw_lit(jw, ",\"server_port\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_inet_get_port(c->local_sockaddr));
    }

#if (NGX_SSL)
    if (c->ssl != NULL) {
        ngx_str_t  version, sni;

        ngx_http_waf_jw_lit(jw, ",\"tls\":{");

        if (ngx_ssl_get_protocol(c, r->pool, &version) == NGX_OK
            && version.len != 0)
        {
            ngx_http_waf_jw_lit(jw, "\"version\":");
            ngx_http_waf_jw_str(jw, &version);
        } else {
            ngx_http_waf_jw_lit(jw, "\"version\":null");
        }

        if (ngx_ssl_get_server_name(c, r->pool, &sni) == NGX_OK
            && sni.len != 0)
        {
            ngx_http_waf_jw_lit(jw, ",\"sni\":");
            ngx_http_waf_jw_str(jw, &sni);
        }

        ngx_http_waf_jw_lit(jw, "}");
    }
#endif

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_msg_http(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    ngx_http_waf_jw_lit(jw, ",\"http\":{\"method\":");
    ngx_http_waf_jw_str(jw, &r->method_name);

    ngx_http_waf_jw_lit(jw, ",\"scheme\":");

#if (NGX_SSL)
    if (r->connection->ssl != NULL) {
        ngx_http_waf_jw_lit(jw, "\"https\"");
    } else
#endif
    {
        ngx_http_waf_jw_lit(jw, "\"http\"");
    }

    if (r->headers_in.server.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"host\":");
        ngx_http_waf_jw_str(jw, &r->headers_in.server);
    }

    ngx_http_waf_jw_lit(jw, ",\"uri\":");
    ngx_http_waf_jw_str(jw, &r->uri);

    ngx_http_waf_jw_lit(jw, ",\"args_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) r->args.len);

    if (r->http_protocol.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"version\":");
        ngx_http_waf_jw_str(jw, &r->http_protocol);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_msg_prior_actions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_uint_t from, ngx_uint_t phase)
{
    ngx_uint_t              i, first;
    ngx_http_waf_action_t  *action;

    if (ctx->actions == NULL) {
        return;
    }

    action = ctx->actions->elts;
    first  = 1;

    for (i = 0; i < ctx->actions->nelts; i++) {

        if (action[i].from != from || action[i].phase != phase) {
            continue;
        }

        if (action[i].to != NGX_HTTP_WAF_ACTION_ALL && action[i].to != index) {
            continue;
        }

        if (ngx_http_waf_do_mark(action[i].verb)) {
            continue;
        }

        if (ngx_http_waf_do_score(action[i].verb)) {
            continue;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, ",\"actions\":[{\"do\":");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",{\"do\":");
        }

        ngx_http_waf_jw_str(jw, ngx_http_waf_do_name(action[i].verb));

        ngx_http_waf_jw_lit(jw, ",\"apply\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_apply_name(action[i].apply));

        if (action[i].to_phases != 0) {
            ngx_http_waf_jw_lit(jw, ",\"phase\":");
            ngx_http_waf_jw_str(jw,
                                ngx_http_waf_to_phase_name(action[i].to_phases));
        }

        if (action[i].code.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"code\":");
            ngx_http_waf_jw_str(jw, &action[i].code);
        }

        if (action[i].has_delta) {
            ngx_http_waf_jw_lit(jw, ",\"delta\":");
            ngx_http_waf_jw_int(jw, action[i].delta);
        }

        if (action[i].has_value) {
            ngx_http_waf_jw_lit(jw, ",\"value\":");
            ngx_http_waf_jw_int(jw, action[i].value);
        }

        if (action[i].counter.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"counter\":");
            ngx_http_waf_jw_str(jw, &action[i].counter);
        }

        if (action[i].group.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"group\":");
            ngx_http_waf_jw_str(jw, &action[i].group);
        }

        if (action[i].set == NGX_HTTP_WAF_SET_ON) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"on\"");

        } else if (action[i].set == NGX_HTTP_WAF_SET_OFF) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"off\"");
        }

        ngx_http_waf_action_archive_write(jw, &action[i]);

        ngx_http_waf_jw_lit(jw, "}");
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "]");
    }
}


static void
ngx_http_waf_msg_prior(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_uint_t                 i, p, first;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    inspectors = wmcf->inspectors.elts;
    first      = 1;

    for (p = 0; p < NGX_HTTP_WAF_NPHASE; p++) {

        if (ctx->phases[p].replies == NULL) {
            continue;
        }

        for (i = 0; i < wmcf->inspectors.nelts; i++) {

            if (i == index) {
                continue;
            }

            reply = &ctx->phases[p].replies[i];

            if (!reply->received) {
                continue;
            }

            if (reply->passive) {
                continue;
            }

            if (first) {
                ngx_http_waf_jw_lit(jw, ",\"prior\":[{\"phase\":");
                first = 0;

            } else {
                ngx_http_waf_jw_lit(jw, ",{\"phase\":");
            }

            ngx_http_waf_jw_str(jw, ngx_http_waf_phase_name(p));

            ngx_http_waf_jw_lit(jw, ",\"wave\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) reply->wave);

            ngx_http_waf_jw_lit(jw, ",\"inspector\":");
            ngx_http_waf_jw_str(jw, &inspectors[i].name);

            ngx_http_waf_jw_lit(jw, ",\"verdict\":");
            ngx_http_waf_jw_str(jw, ngx_http_waf_verdict_name(reply->verdict));

            if (reply->score != 0) {
                ngx_http_waf_jw_lit(jw, ",\"score\":");
                ngx_http_waf_jw_int(jw, reply->score);
            }

            if (reply->reason_code.len != 0
                && reply->reason_code.len <= NGX_HTTP_WAF_PRIOR_REASON_MAX)
            {
                ngx_http_waf_jw_lit(jw, ",\"reason\":{\"code\":");
                ngx_http_waf_jw_str(jw, &reply->reason_code);
                ngx_http_waf_jw_lit(jw, "}");
            }

            ngx_http_waf_msg_prior_actions(jw, ctx, index, i, p);

            ngx_http_waf_jw_lit(jw, "}");
        }
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "]");
    }
}


static void
ngx_http_waf_msg_sessions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_uint_t                 i, first;
    ngx_http_waf_session_t    *sess;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->sessions == NULL || ctx->sessions->nelts == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    inspectors = wmcf->inspectors.elts;
    sess       = ctx->sessions->elts;
    first      = 1;

    for (i = 0; i < ctx->sessions->nelts; i++) {

        if (sess[i].passive || sess[i].by == index) {
            continue;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, ",\"sessions\":[{\"inspector\":");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",{\"inspector\":");
        }

        ngx_http_waf_jw_str(jw, &inspectors[sess[i].by].name);

        ngx_http_waf_jw_lit(jw, ",\"source\":");
        ngx_http_waf_jw_str(jw, &sess[i].source);

        ngx_http_waf_jw_lit(jw, ",\"kind\":");
        ngx_http_waf_jw_str(jw, &sess[i].kind);

        ngx_http_waf_jw_lit(jw, ",\"user\":");
        ngx_http_waf_jw_str(jw, &sess[i].user);

        ngx_http_waf_jw_lit(jw, ",\"id\":");
        ngx_http_waf_jw_str(jw, &sess[i].id);

        if (sess[i].verified) {
            ngx_http_waf_jw_lit(jw, ",\"verified\":true");

        } else {
            ngx_http_waf_jw_lit(jw, ",\"verified\":false");
        }

        if (sess[i].groups.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"groups\":");
            ngx_http_waf_msg_groups(jw, &sess[i].groups);
        }

        if (sess[i].issued != 0) {
            ngx_http_waf_jw_lit(jw, ",\"issued\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].issued);
        }

        if (sess[i].expires != 0) {
            ngx_http_waf_jw_lit(jw, ",\"expires\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].expires);
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "]");
    }
}


static void
ngx_http_waf_msg_groups(ngx_http_waf_jw_t *jw, ngx_str_t *groups)
{
    u_char      *p, *end, *mark;
    ngx_uint_t   first;

    p     = groups->data;
    end   = groups->data + groups->len;
    first = 1;

    ngx_http_waf_jw_lit(jw, "[");

    for (mark = p; /* void */; p++) {

        if (p != end && *p != ',') {
            continue;
        }

        if (p != mark) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            ngx_http_waf_jw_string(jw, mark, (size_t) (p - mark));
            first = 0;
        }

        if (p == end) {
            break;
        }

        mark = p + 1;
    }

    ngx_http_waf_jw_lit(jw, "]");
}


static size_t
ngx_http_waf_msg_sessions_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    size_t                     size;
    ngx_uint_t                 i;
    ngx_http_waf_session_t    *sess;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->sessions == NULL || ctx->sessions->nelts == 0) {
        return 0;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    inspectors = wmcf->inspectors.elts;
    sess       = ctx->sessions->elts;
    size       = sizeof(",\"sessions\":[]");

    for (i = 0; i < ctx->sessions->nelts; i++) {

        if (sess[i].passive || sess[i].by == index) {
            continue;
        }

        size += ngx_http_waf_msg_room(inspectors[sess[i].by].name.len)
                + ngx_http_waf_msg_room(sess[i].source.len)
                + ngx_http_waf_msg_room(sess[i].kind.len)
                + ngx_http_waf_msg_room(sess[i].user.len)
                + ngx_http_waf_msg_room(sess[i].id.len)
                + ngx_http_waf_msg_room(sess[i].groups.len)
                + sizeof("{\"inspector\":,\"source\":,\"kind\":,\"user\":,"
                         "\"id\":,\"verified\":false,\"groups\":[],"
                         "\"issued\":,\"expires\":},")
                + 2 * NGX_INT_T_LEN;
    }

    return size;
}
