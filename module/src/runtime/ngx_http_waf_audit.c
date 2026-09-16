#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "codec/ngx_http_waf_codec.h"
#include "runtime/ngx_http_waf_preview.h"

#include <sys/socket.h>
#include <sys/un.h>


#define NGX_HTTP_WAF_AUDIT_SNDBUF  NGX_HTTP_WAF_AUDIT_DGRAM_MAX

static ngx_str_t  ngx_http_waf_audit_module = ngx_string("module");
static ngx_str_t  ngx_http_waf_audit_session_phase = ngx_string("session");

#define NGX_HTTP_WAF_AUDIT_FRAME_PREVIEW  256

static ngx_socket_t        ngx_http_waf_agent_fd = (ngx_socket_t) -1;
static struct sockaddr_un  ngx_http_waf_agent_addr;
static socklen_t           ngx_http_waf_agent_addrlen;

static ngx_uint_t          ngx_http_waf_agent_dropped;
static time_t              ngx_http_waf_agent_dropped_at;

static ssize_t ngx_http_waf_agent_send(ngx_http_waf_ctx_t *ctx, u_char *json,
    size_t len, int attach);


ngx_uint_t
ngx_http_waf_audit_verdict(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->fail_blocked) {
        return NGX_HTTP_WAF_V_DENY;
    }

    return (ctx->ph->verdict == NGX_HTTP_WAF_V_SCORE)
               ? NGX_HTTP_WAF_V_ALLOW
               : ctx->ph->verdict;
}


static ngx_uint_t
ngx_http_waf_audit_silent(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n, phase;
    ngx_http_waf_phase_ctx_t  *ph;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    n    = wmcf->inspectors.nelts;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        ph = &ctx->phases[phase];

        if (ph->replies == NULL) {
            continue;
        }

        for (i = 0; i < n; i++) {

            if (!(ph->published & (1ULL << i))) {
                continue;
            }

            if (!ph->replies[i].received) {
                return 1;
            }
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_waf_audit_evidence(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_route_verdict(ctx) != NGX_HTTP_WAF_V_ALLOW
           || ngx_http_waf_archive_mask(ctx) != 0
           || ngx_http_waf_audit_silent(ctx);
}


static ngx_uint_t
ngx_http_waf_audit_keep(ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_uint_t  set;

    set = ngx_http_waf_audit_ovr_cur(ctx)->audit.set;

    if (set == NGX_HTTP_WAF_SET_ON) {
        return 1;
    }

    if (set == NGX_HTTP_WAF_SET_OFF) {
        return ngx_http_waf_audit_evidence(ctx);
    }

    if (ctx->audit_sampled) {
        return ctx->audit_keep;
    }

    ctx->audit_sampled = 1;
    ctx->audit_keep    = 1;

    if (wlcf->audit_sample >= 100 || ngx_http_waf_audit_evidence(ctx)) {
        return 1;
    }

    if (wlcf->audit_sample <= 0
        || (ngx_int_t) (ngx_random() % 100) >= wlcf->audit_sample)
    {
        ctx->audit_keep = 0;
    }

    return ctx->audit_keep;
}


static ngx_uint_t
ngx_http_waf_phase_denied(ngx_http_waf_phase_ctx_t *ph)
{
    return ph->fail_blocked || ph->verdict == NGX_HTTP_WAF_V_DENY;
}


ngx_uint_t
ngx_http_waf_route_verdict(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  phase;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!ctx->phases[phase].logged) {
            continue;
        }

        if (ngx_http_waf_phase_denied(&ctx->phases[phase])) {
            return NGX_HTTP_WAF_V_DENY;
        }
    }

    return ngx_http_waf_audit_verdict(ctx);
}


static void
ngx_http_waf_audit_deferred_cleanup(void *data)
{
    ngx_http_waf_audit_flush_deferred(data);
}


void
ngx_http_waf_audit_defer(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_cleanup_t  *cln;

    ctx->ph->audit_deferred = 1;

    cln = ngx_http_cleanup_add(ctx->request, 0);

    if (cln != NULL) {
        cln->handler = ngx_http_waf_audit_deferred_cleanup;
        cln->data    = ctx;
    }
}


void
ngx_http_waf_audit_flush_deferred(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 saved_phase;
    ngx_http_waf_phase_ctx_t  *saved_ph, *ph;

    ph = &ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST];

    if (!ph->audit_deferred) {
        return;
    }

    ph->audit_deferred = 0;

    saved_phase = ctx->phase;
    saved_ph    = ctx->ph;

    ctx->phase = NGX_HTTP_WAF_PHASE_REQUEST;
    ctx->ph    = ph;

    ngx_http_waf_audit_request(ctx);

    ctx->phase = saved_phase;
    ctx->ph    = saved_ph;
}


static ngx_uint_t
ngx_http_waf_audit_status(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->fail_blocked) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    return ngx_http_waf_result_status(ctx);
}


static ngx_str_t *
ngx_http_waf_audit_by(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->code != NGX_HTTP_WAF_CODE_INSPECTOR || ctx->ph->decisive == NULL) {
        return &ngx_http_waf_audit_module;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->ph->decisive_index >= wmcf->inspectors.nelts) {
        return &ngx_http_waf_audit_module;
    }

    insp = wmcf->inspectors.elts;

    return &insp[ctx->ph->decisive_index].name;
}


static void
ngx_http_waf_audit_ts(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    u_char   buf[sizeof("2026-08-15T21:42:31.660Z") - 1];
    u_char  *p;
    ngx_tm_t tm;

    ngx_gmtime(r->start_sec, &tm);

    p = ngx_sprintf(buf, "%4d-%02d-%02dT%02d:%02d:%02d.%03MZ",
                    tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                    tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec,
                    r->start_msec);

    ngx_http_waf_jw_lit(jw, ",\"ts\":");
    ngx_http_waf_jw_string(jw, buf, (size_t) (p - buf));
}


static void
ngx_http_waf_audit_ts_now(ngx_http_waf_jw_t *jw)
{
    u_char      buf[sizeof("2026-08-15T21:42:31.660Z") - 1];
    u_char     *p;
    ngx_tm_t    tm;
    ngx_time_t *tp;

    tp = ngx_timeofday();

    ngx_gmtime(tp->sec, &tm);

    p = ngx_sprintf(buf, "%4d-%02d-%02dT%02d:%02d:%02d.%03MZ",
                    tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                    tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec,
                    (ngx_msec_t) tp->msec);

    ngx_http_waf_jw_lit(jw, ",\"ts\":");
    ngx_http_waf_jw_string(jw, buf, (size_t) (p - buf));
}


static void
ngx_http_waf_audit_frame(ngx_http_waf_jw_t *jw, ngx_http_waf_frame_audit_t *fa)
{
    size_t  n;

    ngx_http_waf_jw_lit(jw, ",\"frame\":{\"conn_id\":\"");
    ngx_http_waf_jw_raw(jw, fa->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(jw, "\",\"seq\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) fa->seq);
    ngx_http_waf_jw_lit(jw, ",\"direction\":");
    ngx_http_waf_jw_str(jw, fa->direction);
    ngx_http_waf_jw_lit(jw, ",\"opcode\":");
    ngx_http_waf_jw_str(jw, fa->opcode);
    ngx_http_waf_jw_lit(jw, ",\"fin\":");

    if (fa->fin) {
        ngx_http_waf_jw_lit(jw, "true");

    } else {
        ngx_http_waf_jw_lit(jw, "false");
    }

    ngx_http_waf_jw_lit(jw, ",\"size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) fa->size);
    ngx_http_waf_jw_lit(jw, ",\"rewritten\":");

    if (fa->rewritten) {
        ngx_http_waf_jw_lit(jw, "true");

    } else {
        ngx_http_waf_jw_lit(jw, "false");
    }

    if (fa->fragments > 1) {
        ngx_http_waf_jw_lit(jw, ",\"fragments\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) fa->fragments);
    }

    if (fa->cached) {
        ngx_http_waf_jw_lit(jw, ",\"cached\":true");
    }

    if (fa->payload != NULL && fa->size != 0) {
        n = ngx_min(fa->size, NGX_HTTP_WAF_AUDIT_FRAME_PREVIEW);

        ngx_http_waf_jw_lit(jw, ",\"payload_preview\":");
        ngx_http_waf_jw_string(jw, fa->payload, n);

        if (n < fa->size) {
            ngx_http_waf_jw_lit(jw, ",\"payload_truncated\":true");
        }
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_audit_conn(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    u_char             buf[NGX_SOCKADDR_STRLEN];
    size_t             len;
    ngx_connection_t  *c = r->connection;

    ngx_http_waf_jw_lit(jw, ",\"client_ip\":");
    ngx_http_waf_jw_str(jw, &c->addr_text);
    ngx_http_waf_jw_lit(jw, ",\"client_port\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_inet_get_port(c->sockaddr));

    if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) {
        len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf,
                            NGX_SOCKADDR_STRLEN, 0);

        ngx_http_waf_jw_lit(jw, ",\"server_ip\":");
        ngx_http_waf_jw_string(jw, buf, len);
        ngx_http_waf_jw_lit(jw, ",\"server_port\":");
        ngx_http_waf_jw_int(jw,
                            (ngx_int_t) ngx_inet_get_port(c->local_sockaddr));
    }

#if (NGX_SSL)
    if (c->ssl != NULL) {
        ngx_str_t  version, sni;

        if (ngx_ssl_get_protocol(c, r->pool, &version) == NGX_OK
            && version.len != 0)
        {
            ngx_http_waf_jw_lit(jw, ",\"tls\":{\"version\":");
            ngx_http_waf_jw_str(jw, &version);

            if (ngx_ssl_get_server_name(c, r->pool, &sni) == NGX_OK
                && sni.len != 0)
            {
                ngx_http_waf_jw_lit(jw, ",\"sni\":");
                ngx_http_waf_jw_str(jw, &sni);
            }

            ngx_http_waf_jw_lit(jw, "}");
        }
    }
#endif
}


static void
ngx_http_waf_audit_headers_size(ngx_http_waf_ctx_t *ctx, off_t *size,
    ngx_uint_t *count)
{
    ngx_uint_t     i;
    ngx_keyval_t  *kv;
    ngx_array_t   *pairs;

    *size  = 0;
    *count = 0;

    pairs = ngx_http_waf_header_pairs(ctx);
    if (pairs == NULL) {
        return;
    }

    kv = pairs->elts;

    for (i = 0; i < pairs->nelts; i++) {

        if (kv[i].key.len == 0) {
            continue;
        }

        *size += (off_t) (kv[i].key.len + kv[i].value.len
                          + sizeof(": \r\n") - 1);
        (*count)++;
    }
}


static void
ngx_http_waf_audit_content_type(ngx_http_waf_ctx_t *ctx, ngx_str_t *out)
{
    u_char              *p;
    ngx_http_request_t  *r = ctx->request;

    ngx_str_null(out);

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {

        if (r->headers_out.content_type.len == 0) {
            return;
        }

        *out = r->headers_out.content_type;

    } else {

        if (r->headers_in.content_type == NULL) {
            return;
        }

        *out = r->headers_in.content_type->value;
    }

    p = ngx_strlchr(out->data, out->data + out->len, ';');

    if (p != NULL) {
        out->len = (size_t) (p - out->data);
    }

    while (out->len != 0 && out->data[out->len - 1] == ' ') {
        out->len--;
    }
}


static void
ngx_http_waf_audit_http(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    off_t                headers_size;
    ngx_str_t            content_type;
    ngx_uint_t           headers_count;
    ngx_http_request_t  *r = ctx->request;

    ngx_http_waf_audit_headers_size(ctx, &headers_size, &headers_count);
    ngx_http_waf_audit_content_type(ctx, &content_type);

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

    ngx_http_waf_jw_lit(jw, ",\"host\":");
    ngx_http_waf_jw_str(jw, &r->headers_in.server);

    ngx_http_waf_jw_lit(jw, ",\"uri\":");
    ngx_http_waf_jw_str(jw, &r->uri);

    ngx_http_waf_jw_lit(jw, ",\"version\":");

    if (r->http_protocol.len != 0) {
        ngx_http_waf_jw_str(jw, &r->http_protocol);

    } else {
        ngx_http_waf_jw_lit(jw, "\"HTTP/0.9\"");
    }

    ngx_http_waf_jw_lit(jw, ",\"args_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) r->args.len);
    ngx_http_waf_jw_lit(jw, ",\"headers_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) headers_size);
    ngx_http_waf_jw_lit(jw, ",\"headers_count\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) headers_count);

    ngx_http_waf_jw_lit(jw, ",\"body_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_http_waf_body_seen(ctx));

    if (content_type.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"content_type\":");
        ngx_http_waf_jw_str(jw, &content_type);
    }

    ngx_http_waf_jw_lit(jw, ",\"status\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_http_waf_audit_status(ctx));

    if (ctx->rsp_status != 0) {
        ngx_http_waf_jw_lit(jw, ",\"upstream_status\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) ctx->rsp_status);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_audit_route(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_waf_loc_conf_t   *wlcf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    ngx_http_waf_jw_lit(jw, ",\"route\":{\"server_name\":");

    if (cscf->server_name.len != 0) {
        ngx_http_waf_jw_str(jw, &cscf->server_name);

    } else {
        ngx_http_waf_jw_lit(jw, "\"_\"");
    }

    ngx_http_waf_jw_lit(jw, ",\"location\":");

    if (clcf->name.len != 0) {
        ngx_http_waf_jw_str(jw, &clcf->name);

    } else {
        ngx_http_waf_jw_lit(jw, "\"/\"");
    }

    if (wlcf->route_id.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"id\":");
        ngx_http_waf_jw_str(jw, &wlcf->route_id);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static ngx_str_t *
ngx_http_waf_audit_role(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_inspector_t *insp,
    ngx_http_waf_reply_t *reply)
{
    static ngx_str_t         passive = ngx_string("passive");
    static ngx_str_t         active  = ngx_string("active");
    static ngx_str_t         vote    = ngx_string("vote");
    ngx_uint_t               was, is;
    ngx_http_waf_mask_t      bit;
    ngx_http_waf_binding_t  *bind;

    bind = ngx_http_waf_binding_find(wlcf, insp->index, ctx->phase);
    was  = (bind != NULL) ? bind->mode : NGX_HTTP_WAF_MODE_ACTIVE;
    bit  = (ngx_http_waf_mask_t) 1 << insp->index;

    if (reply != NULL && reply->received) {
        is = reply->passive ? NGX_HTTP_WAF_MODE_PASSIVE
             : reply->vote  ? NGX_HTTP_WAF_MODE_VOTE
                            : NGX_HTTP_WAF_MODE_ACTIVE;

    } else if (ctx->ctl[ctx->phase].active & bit) {
        is = NGX_HTTP_WAF_MODE_ACTIVE;

    } else if (ctx->ctl[ctx->phase].passive & bit) {
        is = NGX_HTTP_WAF_MODE_PASSIVE;

    } else if (ctx->ctl[ctx->phase].vote & bit) {
        is = NGX_HTTP_WAF_MODE_VOTE;

    } else {
        is = was;
    }

    if (is == NGX_HTTP_WAF_MODE_PASSIVE) {
        return &passive;
    }

    if (is == NGX_HTTP_WAF_MODE_VOTE) {
        return &vote;
    }

    return (was == NGX_HTTP_WAF_MODE_PASSIVE || was == NGX_HTTP_WAF_MODE_VOTE)
               ? &active : NULL;
}


static void
ngx_http_waf_audit_entry(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t verdict, ngx_http_waf_reply_t *reply,
    ngx_http_waf_inspector_t *insp)
{
    ngx_str_t                *role;
    ngx_uint_t                state;
    ngx_http_waf_loc_conf_t  *wlcf;

    ngx_http_waf_jw_lit(jw, "{");

    if (reply == NULL) {
        ngx_http_waf_jw_lit(jw, "\"verdict\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_verdict_name(verdict));
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (reply->received) {
        if (reply->verdict == NGX_HTTP_WAF_V_SCORE && reply->score > 0) {
            ngx_http_waf_jw_lit(jw, "\"verdict\":\"score\"");

        } else {
            ngx_http_waf_jw_lit(jw, "\"verdict\":");
            ngx_http_waf_jw_str(jw,
                ngx_http_waf_verdict_name(
                    (reply->verdict == NGX_HTTP_WAF_V_SCORE)
                        ? NGX_HTTP_WAF_V_ALLOW
                        : reply->verdict));
        }

        if (reply->score != 0) {
            ngx_http_waf_jw_lit(jw, ",\"score\":");
            ngx_http_waf_jw_int(jw, reply->score);
        }

        ngx_http_waf_jw_lit(jw, ",\"latency_ms\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) reply->latency);

    } else {
        state = (reply->state != NGX_HTTP_WAF_ENTRY_ANSWERED)
                    ? reply->state
                    : NGX_HTTP_WAF_ENTRY_TIMEOUT;

        ngx_http_waf_jw_lit(jw, "\"state\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_entry_state_name(state));

        if (state == NGX_HTTP_WAF_ENTRY_TIMEOUT && ctx->ph->wave_published != 0) {
            ngx_http_waf_jw_lit(jw, ",\"latency_ms\":");
            ngx_http_waf_jw_int(jw,
                (ngx_int_t) (ngx_current_msec - ctx->ph->wave_published));
        }
    }

    role = ngx_http_waf_audit_role(ctx, wlcf, insp, reply);

    if (role != NULL) {
        ngx_http_waf_jw_lit(jw, ",\"role\":");
        ngx_http_waf_jw_str(jw, role);
    }

    ngx_http_waf_jw_lit(jw, ",\"profile\":");

    if (wlcf->profiles[insp->index].len != 0) {
        ngx_http_waf_jw_str(jw, &wlcf->profiles[insp->index]);

    } else {
        ngx_http_waf_jw_lit(jw, "\"default\"");
    }

    if (reply != NULL && reply->received
        && (reply->rewrite_has || reply->args_set != NULL
            || reply->args_unset != NULL))
    {
        ngx_http_waf_jw_lit(jw, ",\"rewrite\":{\"applied\":");

        if (reply->rewrite_body) {

            if (ngx_http_waf_rewrite_applied(ctx, insp->index)) {
                ngx_http_waf_jw_lit(jw, "true");

            } else {
                ngx_http_waf_jw_lit(jw, "false");
            }

            ngx_http_waf_jw_lit(jw, ",\"size\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) reply->rewrite_size);

            if (reply->rewrite_digest) {
                u_char  hex[64];

                (void) ngx_hex_dump(hex, reply->rewrite_sha256, 32);

                ngx_http_waf_jw_lit(jw, ",\"sha256\":\"");
                ngx_http_waf_jw_raw(jw, hex, 64);
                ngx_http_waf_jw_lit(jw, "\"");
            }

            if (reply->rewrite_partial) {
                ngx_http_waf_jw_lit(jw, ",\"partial\":true");
            }

        } else if (reply->passive || reply->vote) {
            ngx_http_waf_jw_lit(jw, "false");

        } else if (reply->rewrite_has) {
            ngx_http_waf_jw_lit(jw, "true");

        } else if (reply->args_applied) {
            ngx_http_waf_jw_lit(jw, "true");

        } else {
            ngx_http_waf_jw_lit(jw, "false");
        }

        if (reply->args_set != NULL || reply->args_unset != NULL) {
            ngx_http_waf_jw_lit(jw, ",\"args\":{\"applied\":");

            if (reply->args_applied) {
                ngx_http_waf_jw_lit(jw, "true");

            } else {
                ngx_http_waf_jw_lit(jw, "false");
            }

            ngx_http_waf_jw_lit(jw, ",\"set\":");
            ngx_http_waf_jw_int(jw, reply->args_set != NULL
                                        ? (ngx_int_t) reply->args_set->nelts
                                        : 0);
            ngx_http_waf_jw_lit(jw, ",\"unset\":");
            ngx_http_waf_jw_int(jw, reply->args_unset != NULL
                                        ? (ngx_int_t) reply->args_unset->nelts
                                        : 0);
            ngx_http_waf_jw_lit(jw, "}");
        }

        if (reply->rewrite_groups != NULL
            && reply->rewrite_groups->nelts != 0)
        {
            ngx_str_t   *group = reply->rewrite_groups->elts;
            ngx_uint_t   g;

            ngx_http_waf_jw_lit(jw, ",\"groups\":[");

            for (g = 0; g < reply->rewrite_groups->nelts; g++) {
                if (g != 0) {
                    ngx_http_waf_jw_lit(jw, ",");
                }

                ngx_http_waf_jw_str(jw, &group[g]);
            }

            ngx_http_waf_jw_lit(jw, "]");
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_audit_inspectors(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t verdict)
{
    ngx_uint_t                 i, n;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    n    = wmcf->inspectors.nelts;

    ngx_http_waf_jw_lit(jw, ",\"inspectors\":{");
    ngx_http_waf_jw_str(jw, &ngx_http_waf_audit_module);
    ngx_http_waf_jw_lit(jw, ":");
    ngx_http_waf_audit_entry(jw, ctx, verdict, NULL, NULL);

    if (ctx->ph->replies == NULL) {
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    for (i = 0; i < n; i++) {

        if (!((ctx->ph->published | ctx->ph->controlled) & (1ULL << i))) {
            continue;
        }

        ngx_http_waf_jw_lit(jw, ",");
        ngx_http_waf_jw_str(jw, &insp[i].name);
        ngx_http_waf_jw_lit(jw, ":");
        ngx_http_waf_audit_entry(jw, ctx, verdict, &ctx->ph->replies[i], &insp[i]);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_audit_actions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t frame)
{
    ngx_uint_t                 i, n, printed;
    ngx_http_waf_action_t     *action;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->actions == NULL || ctx->actions->nelts == 0) {
        return;
    }

    wmcf   = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp   = wmcf->inspectors.elts;
    n      = wmcf->inspectors.nelts;
    action = ctx->actions->elts;

    printed = 0;

    for (i = 0; i < ctx->actions->nelts; i++) {
        if (!frame || ngx_http_waf_phase_is_frame(action[i].phase)) {
            printed++;
        }
    }

    if (printed == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"actions\":[");
    printed = 0;

    for (i = 0; i < ctx->actions->nelts; i++) {

        if (frame && !ngx_http_waf_phase_is_frame(action[i].phase)) {
            continue;
        }

        if (printed++ != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_lit(jw, "{\"from\":");

        if (action[i].from < n) {
            ngx_http_waf_jw_str(jw, &insp[action[i].from].name);

        } else {
            ngx_http_waf_jw_lit(jw, "null");
        }

        if (action[i].to != NGX_HTTP_WAF_ACTION_ALL && action[i].to < n) {
            ngx_http_waf_jw_lit(jw, ",\"to\":");
            ngx_http_waf_jw_str(jw, &insp[action[i].to].name);
        }

        if (action[i].to_phases != 0) {
            ngx_http_waf_jw_lit(jw, ",\"to_phase\":");
            ngx_http_waf_jw_str(jw,
                                ngx_http_waf_to_phase_name(action[i].to_phases));
        }

        ngx_http_waf_jw_lit(jw, ",\"do\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_do_name(action[i].verb));

        ngx_http_waf_jw_lit(jw, ",\"apply\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_apply_name(action[i].apply));

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

        if (action[i].marker.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"marker\":");
            ngx_http_waf_jw_str(jw, &action[i].marker);
        }

        if (action[i].set == NGX_HTTP_WAF_SET_ON) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"on\"");

        } else if (action[i].set == NGX_HTTP_WAF_SET_OFF) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"off\"");
        }

        ngx_http_waf_action_archive_write(jw, &action[i]);

        ngx_http_waf_jw_lit(jw, ",\"phase\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_phase_name(action[i].phase));

        if (action[i].passive) {
            ngx_http_waf_jw_lit(jw, ",\"passive\":true");

        } else {
            ngx_http_waf_jw_lit(jw, ",\"passive\":false");
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "]");
}


static void
ngx_http_waf_audit_markers(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i;
    ngx_str_t  *m;

    if (ctx->markers == NULL || ctx->markers->nelts == 0) {
        return;
    }

    m = ctx->markers->elts;

    ngx_http_waf_jw_lit(jw, ",\"markers\":[");

    for (i = 0; i < ctx->markers->nelts; i++) {

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &m[i]);
    }

    ngx_http_waf_jw_lit(jw, "]");
}


static void
ngx_http_waf_audit_sessions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n;
    ngx_http_waf_session_t    *sess;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->sessions == NULL || ctx->sessions->nelts == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    n    = wmcf->inspectors.nelts;
    sess = ctx->sessions->elts;

    ngx_http_waf_jw_lit(jw, ",\"sessions\":[");

    for (i = 0; i < ctx->sessions->nelts; i++) {

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_lit(jw, "{\"by\":");

        if (sess[i].by < n) {
            ngx_http_waf_jw_str(jw, &insp[sess[i].by].name);

        } else {
            ngx_http_waf_jw_lit(jw, "null");
        }

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

        if (sess[i].issued != 0) {
            ngx_http_waf_jw_lit(jw, ",\"issued\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].issued);
        }

        if (sess[i].expires != 0) {
            ngx_http_waf_jw_lit(jw, ",\"expires\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].expires);
        }

        if (sess[i].groups.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"groups\":");
            ngx_http_waf_jw_str(jw, &sess[i].groups);
        }

        if (sess[i].passive) {
            ngx_http_waf_jw_lit(jw, ",\"passive\":true");
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "]");
}


static ngx_uint_t
ngx_http_waf_frame_audit_policy(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_frame_audit_t *fa)
{
    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_OFF
        || !ngx_http_waf_frame_audit(ctx, fa))
    {
        return 0;
    }

    if (ngx_http_waf_audit_ovr_cur(ctx)->audit.set == NGX_HTTP_WAF_SET_ON) {
        return 1;
    }

    if ((wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_DENY
         || ngx_http_waf_audit_ovr_cur(ctx)->audit.set == NGX_HTTP_WAF_SET_OFF)
        && ngx_http_waf_audit_verdict(ctx) == NGX_HTTP_WAF_V_ALLOW
        && !fa->rewritten && ctx->ph->score == 0)
    {
        return 0;
    }

    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_ALL
        && wlcf->audit_frames_sample > 1
        && (fa->seq % wlcf->audit_frames_sample) != 0)
    {
        return 0;
    }

    return 1;
}


ngx_uint_t
ngx_http_waf_audit_enabled(void)
{
    return ngx_http_waf_agent_fd != (ngx_socket_t) -1;
}


ngx_uint_t
ngx_http_waf_frame_audit_wanted(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t     *wlcf;
    ngx_http_waf_frame_audit_t   fa;

    if (ngx_http_waf_agent_fd == (ngx_socket_t) -1) {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return ngx_http_waf_frame_audit_policy(ctx, wlcf, &fa);
}


static void
ngx_http_waf_audit_store(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i, bit, flags, used, keep;

    used = (ngx_http_waf_archive_mask(ctx) != 0);

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT && !used; i++) {
        if (ngx_http_waf_store_locator(ctx, i) != NULL) {
            used = 1;
        }
    }

    if (!used) {
        return;
    }

    (void) ngx_http_waf_attach_prepare(ctx);

    keep = ngx_http_waf_archive_mask(ctx);

    ngx_http_waf_jw_lit(jw, ",\"store\":{");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit   = NGX_HTTP_WAF_OBJ_BIT(i);
        flags = (i == NGX_HTTP_WAF_OBJ_BODY) ? NGX_HTTP_WAF_LOC_BODY : 0;

        if (ctx->ph->attached & bit) {
            flags |= NGX_HTTP_WAF_LOC_ATTACH;

        } else if (keep & bit) {
            flags |= NGX_HTTP_WAF_LOC_ADDRESS;
        }

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, ngx_http_waf_obj_name(i));
        ngx_http_waf_jw_lit(jw, ":");
        ngx_http_waf_locator_write(jw, ngx_http_waf_audit_locator(ctx, i),
                                   flags);
    }

    if (keep != 0) {
        ngx_http_waf_archive_write(jw, ctx, keep);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


ngx_int_t
ngx_http_waf_audit_init_worker(ngx_cycle_t *cycle)
{
    int                        sndbuf;
    socklen_t                  len;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_socket_t               s;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    ngx_http_waf_agent_fd = (ngx_socket_t) -1;

    if (wmcf == NULL || wmcf->agent_socket.len == 0) {
        return NGX_OK;
    }

    if (wmcf->agent_socket.len >= sizeof(ngx_http_waf_agent_addr.sun_path)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "waf: waf_agent_socket is too long");
        return NGX_ERROR;
    }

    s = ngx_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "waf: socket(AF_UNIX, SOCK_DGRAM) failed");
        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "waf: nonblocking agent socket failed");
        ngx_close_socket(s);
        return NGX_ERROR;
    }

    sndbuf = NGX_HTTP_WAF_AUDIT_SNDBUF;

    if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const void *) &sndbuf,
                   sizeof(int)) == -1)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_socket_errno,
                      "waf: SO_SNDBUF %d on the agent socket failed; large "
                      "previews may not fit a datagram", sndbuf);

    } else {
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *) &sndbuf, &len) == 0
            && sndbuf / 2 < NGX_HTTP_WAF_AUDIT_SNDBUF)
        {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "waf: the kernel capped the agent socket send "
                          "buffer at %d bytes, below the %d a record with "
                          "previews may need; raise net.core.wmem_max",
                          sndbuf / 2, NGX_HTTP_WAF_AUDIT_SNDBUF);
        }
    }

    ngx_memzero(&ngx_http_waf_agent_addr, sizeof(ngx_http_waf_agent_addr));
    ngx_http_waf_agent_addr.sun_family = AF_UNIX;
    ngx_cpystrn((u_char *) ngx_http_waf_agent_addr.sun_path,
                wmcf->agent_socket.data,
                sizeof(ngx_http_waf_agent_addr.sun_path));
    ngx_http_waf_agent_addrlen = (socklen_t)
        (offsetof(struct sockaddr_un, sun_path) + wmcf->agent_socket.len + 1);

    ngx_http_waf_agent_fd = s;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "waf: agent socket \"%V\"", &wmcf->agent_socket);

    return NGX_OK;
}


void
ngx_http_waf_audit_exit_worker(ngx_cycle_t *cycle)
{
    if (ngx_http_waf_agent_fd != (ngx_socket_t) -1) {
        ngx_close_socket(ngx_http_waf_agent_fd);
        ngx_http_waf_agent_fd = (ngx_socket_t) -1;
    }

    (void) cycle;
}


void
ngx_http_waf_audit_request(ngx_http_waf_ctx_t *ctx)
{
    u_char                    *json;
    size_t                     size;
    ngx_int_t                  deny_at;
    ngx_http_waf_jw_t          jw;
    ngx_http_request_t        *r;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_uint_t                 verdict, frame;
    ssize_t                    n;
    ngx_http_waf_frame_audit_t fa;

    if (ngx_http_waf_agent_fd == (ngx_socket_t) -1) {
        return;
    }

    r = ctx->request;

    if (r->pool == NULL) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    frame = 0;

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {

        if (!ngx_http_waf_frame_audit_policy(ctx, wlcf, &fa)) {
            return;
        }

        frame = 1;

    } else if (!ngx_http_waf_audit_keep(ctx, wlcf)) {
        return;
    }

    size = NGX_HTTP_WAF_AUDIT_JSON
           + ngx_http_waf_preview_room_ctx(ctx)
           + wlcf->actions_max * (wlcf->action_max + 128)
           + (frame ? 0 : NGX_HTTP_WAF_SESSIONS_MAX * NGX_HTTP_WAF_SESSION_JSON)
           + NGX_HTTP_WAF_MARKERS_JSON
           + wlcf->route_id.len
           + (frame ? 256 + NGX_HTTP_WAF_AUDIT_FRAME_PREVIEW * 6 : 0);

    json = ngx_pnalloc(r->pool, size);
    if (json == NULL) {
        return;
    }

    verdict = ngx_http_waf_audit_verdict(ctx);
    deny_at = ngx_http_waf_score_deny_at(ctx);

    ngx_http_waf_jw_init(&jw, json, size);

    ngx_http_waf_jw_lit(&jw, "{\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->ray_hex, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\",\"node\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);
    ngx_http_waf_jw_lit(&jw, ",\"phase\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_phase_name(ctx->phase));

    if (frame) {
        ngx_http_waf_audit_ts_now(&jw);

    } else {
        ngx_http_waf_audit_ts(&jw, r);
    }

    ngx_http_waf_audit_conn(&jw, r);
    ngx_http_waf_audit_http(&jw, ctx);
    ngx_http_waf_audit_route(&jw, r);

    if (frame) {
        ngx_http_waf_audit_frame(&jw, &fa);
    }

    ngx_http_waf_jw_lit(&jw, ",\"verdict\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_verdict_name(verdict));

    if (verdict != NGX_HTTP_WAF_V_ALLOW
        && ctx->ph->code != NGX_HTTP_WAF_CODE_NONE)
    {
        ngx_http_waf_jw_lit(&jw, ",\"code\":");
        ngx_http_waf_jw_str(&jw, ngx_http_waf_code_name(ctx->ph->code));
    }

    ngx_http_waf_jw_lit(&jw, ",\"by\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_audit_by(ctx));

    if (deny_at > 0) {
        ngx_http_waf_jw_lit(&jw, ",\"score\":{\"total\":");
        ngx_http_waf_jw_int(&jw, ctx->ph->score);
        ngx_http_waf_jw_lit(&jw, ",\"deny_at\":");
        ngx_http_waf_jw_int(&jw, deny_at);

        if (ctx->ph->shadow > 0) {
            ngx_http_waf_jw_lit(&jw, ",\"shadow\":");
            ngx_http_waf_jw_int(&jw, ctx->ph->shadow);
        }

        ngx_http_waf_jw_lit(&jw, "}");
    }

    ngx_http_waf_audit_inspectors(&jw, ctx, verdict);

    ngx_http_waf_audit_actions(&jw, ctx, frame);

    if (!frame) {
        ngx_http_waf_audit_sessions(&jw, ctx);
    }

    ngx_http_waf_audit_markers(&jw, ctx);

    ngx_http_waf_vars_write(&jw, ctx, NGX_HTTP_WAF_VAR_MAX,
                            NGX_HTTP_WAF_VARS_ALL);
    ngx_http_waf_audit_store(&jw, ctx);

    ngx_http_waf_preview_write(&jw, ctx);

    ngx_http_waf_jw_lit(&jw, ",\"waf_latency_us\":");
    ngx_http_waf_jw_int(&jw,
                        (ngx_int_t) (ngx_current_msec - ctx->started) * 1000);
    ngx_http_waf_jw_lit(&jw, "}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: agent event overflow, ray %*s",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        ngx_http_waf_attach_close(ctx);
        return;
    }

    n = ngx_http_waf_agent_send(ctx, json, ngx_http_waf_jw_len(&jw),
                                ngx_http_waf_attach_fd(ctx));

    ngx_http_waf_attach_close(ctx);

    if (n == -1) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "waf: agent verdict %uz bytes", (size_t) n);
}


/*
 * One datagram per record. The attachment file, when there is one, goes in
 * the ancillary data of the same message, so the record and its objects reach
 * the agent together or not at all. A drop is counted and reported once a
 * second: a queue the agent does not drain loses evidence, not just a line.
 */

static ssize_t
ngx_http_waf_agent_send(ngx_http_waf_ctx_t *ctx, u_char *json, size_t len,
    int attach)
{
    ssize_t          n;
    time_t           now;
    struct iovec     iov;
    struct msghdr    msg;
#if (NGX_LINUX)
    struct cmsghdr  *cmsg;
    union {
        struct cmsghdr  align;
        u_char          data[CMSG_SPACE(sizeof(int))];
    } control;
#endif

    iov.iov_base = json;
    iov.iov_len  = len;

    ngx_memzero(&msg, sizeof(struct msghdr));

    msg.msg_name    = &ngx_http_waf_agent_addr;
    msg.msg_namelen = ngx_http_waf_agent_addrlen;
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

#if (NGX_LINUX)
    if (attach != -1) {
        ngx_memzero(&control, sizeof(control));

        msg.msg_control    = control.data;
        msg.msg_controllen = sizeof(control.data);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type  = SCM_RIGHTS;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
        ngx_memcpy(CMSG_DATA(cmsg), &attach, sizeof(int));
    }
#else
    (void) attach;
#endif

    n = sendmsg(ngx_http_waf_agent_fd, &msg, MSG_DONTWAIT);

    if (n != -1) {
        return n;
    }

    if (ngx_socket_errno == EMSGSIZE) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                      ngx_socket_errno,
                      "waf: agent event of %uz bytes does not fit a "
                      "datagram; lower the preview budgets", len);
        return -1;
    }

    now = ngx_time();
    ngx_http_waf_agent_dropped++;

    if (now != ngx_http_waf_agent_dropped_at) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                      ngx_socket_errno,
                      "waf: agent socket dropped %ui record(s) since the "
                      "last note; the agent is not draining its socket",
                      ngx_http_waf_agent_dropped);

        ngx_http_waf_agent_dropped    = 0;
        ngx_http_waf_agent_dropped_at = now;
    }

    return -1;
}


void
ngx_http_waf_audit_session(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_session_audit_t *sess)
{
    u_char                    *json;
    size_t                     size;
    ssize_t                    n;
    ngx_str_t                  why;
    ngx_http_waf_jw_t          jw;
    ngx_http_request_t        *r;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ngx_http_waf_agent_fd == (ngx_socket_t) -1) {
        return;
    }

    r    = ctx->request;
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_OFF) {
        return;
    }

    size = NGX_HTTP_WAF_AUDIT_JSON + wlcf->route_id.len + 512;

    json = ngx_pnalloc(r->pool, size);
    if (json == NULL) {
        return;
    }

    ngx_http_waf_jw_init(&jw, json, size);

    ngx_http_waf_jw_lit(&jw, "{\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, sess->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\",\"node\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);
    ngx_http_waf_jw_lit(&jw, ",\"phase\":");
    ngx_http_waf_jw_str(&jw, &ngx_http_waf_audit_session_phase);

    ngx_http_waf_audit_ts_now(&jw);

    ngx_http_waf_audit_conn(&jw, r);
    ngx_http_waf_audit_http(&jw, ctx);
    ngx_http_waf_audit_route(&jw, r);

    ngx_http_waf_jw_lit(&jw, ",\"verdict\":");

    if (ngx_strcmp(sess->close_reason, "waf_deny") == 0) {
        ngx_http_waf_jw_lit(&jw, "\"deny\",\"code\":\"ws_close\"");

    } else {
        ngx_http_waf_jw_lit(&jw, "\"allow\"");
    }

    ngx_http_waf_jw_lit(&jw, ",\"by\":");
    ngx_http_waf_jw_str(&jw, &ngx_http_waf_audit_module);

    ngx_http_waf_jw_lit(&jw, ",\"inspectors\":{}");

    ngx_http_waf_jw_lit(&jw, ",\"session\":{\"conn_id\":\"");
    ngx_http_waf_jw_raw(&jw, sess->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\",\"protocol\":\"websocket\",\"frames_c2s\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->frames_c2s);
    ngx_http_waf_jw_lit(&jw, ",\"frames_s2c\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->frames_s2c);
    ngx_http_waf_jw_lit(&jw, ",\"bytes_c2s\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->bytes_c2s);
    ngx_http_waf_jw_lit(&jw, ",\"bytes_s2c\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->bytes_s2c);
    ngx_http_waf_jw_lit(&jw, ",\"frames_denied\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->denied);
    ngx_http_waf_jw_lit(&jw, ",\"frames_rewritten\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->rewritten);
    ngx_http_waf_jw_lit(&jw, ",\"frames_cached\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->cached);
    ngx_http_waf_jw_lit(&jw, ",\"messages_reassembled\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->reassembled);
    ngx_http_waf_jw_lit(&jw, ",\"control_dropped\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->control_dropped);
    ngx_http_waf_jw_lit(&jw, ",\"close_code\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->close_code);
    ngx_http_waf_jw_lit(&jw, ",\"close_reason\":");

    why.data = (u_char *) sess->close_reason;
    why.len  = ngx_strlen(sess->close_reason);
    ngx_http_waf_jw_str(&jw, &why);

    if (sess->close_why != NULL) {
        ngx_http_waf_jw_lit(&jw, ",\"close_why\":");
        why.data = (u_char *) sess->close_why;
        why.len  = ngx_strlen(sess->close_why);
        ngx_http_waf_jw_str(&jw, &why);
    }

    ngx_http_waf_jw_lit(&jw, ",\"duration_ms\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->duration_ms);
    ngx_http_waf_jw_lit(&jw, "}");

    ngx_http_waf_jw_lit(&jw, ",\"waf_latency_us\":0}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: agent session event overflow, conn %*s",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, sess->conn_id);
        return;
    }

    n = sendto(ngx_http_waf_agent_fd, json, ngx_http_waf_jw_len(&jw),
               MSG_DONTWAIT,
               (struct sockaddr *) &ngx_http_waf_agent_addr,
               ngx_http_waf_agent_addrlen);

    if (n == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_socket_errno,
                       "waf: agent session send dropped");
    }
}
