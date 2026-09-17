#include "codec/ngx_http_waf_codec.h"
#include "body/ngx_http_waf_body.h"


typedef struct {
    ngx_str_t   name;
    ngx_uint_t  value;
} ngx_http_waf_kw_t;


typedef struct {
    ngx_str_t   scheme;
    ngx_str_t   host;
    ngx_str_t   path;
    in_port_t   port;
} ngx_http_waf_url_t;


#define NGX_HTTP_WAF_SHOWN_MAX  64
#define NGX_HTTP_WAF_SHOWN_LEN  (NGX_HTTP_WAF_SHOWN_MAX * 4 + 3)


static ngx_int_t ngx_http_waf_reply_continue(ngx_http_waf_jp_t *jp,
    ngx_str_t *subject, ngx_int_t *ttl);
static ngx_int_t ngx_http_waf_reply_resume(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_str_t *subject, ngx_int_t ttl);
static ngx_int_t ngx_http_waf_reply_reason(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_optional(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, const char *field);
static ngx_int_t ngx_http_waf_reply_response(ngx_http_waf_jp_t *jp,
    ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_redirect(ngx_http_waf_jp_t *jp,
    ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_headers(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_args(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_uint_t ngx_http_waf_arg_clean(ngx_str_t *s, ngx_uint_t name);
static ngx_int_t ngx_http_waf_reply_rewrite(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_object_spec(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ovr_part_t *spec, ngx_uint_t obj, ngx_str_t *err);
static ngx_int_t ngx_http_waf_reply_actions(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply,
    ngx_str_t *err);
static ngx_uint_t ngx_http_waf_group_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_rewrite_key_clean(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj, ngx_str_t *key);
static ngx_uint_t ngx_http_waf_code_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_counter_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_marker_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_apply_allowed(ngx_uint_t verb, ngx_uint_t axis);
static ngx_int_t ngx_http_waf_reply_cookies(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_sessions(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_uint_t ngx_http_waf_text_clean(ngx_str_t *s, size_t max);
static ngx_uint_t ngx_http_waf_cookie_value_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_cookie_path_clean(ngx_str_t *s);
static size_t ngx_http_waf_shown(u_char *buf, ngx_str_t *s);

static ngx_uint_t ngx_http_waf_header_forbidden(ngx_str_t *name);
static ngx_uint_t ngx_http_waf_token_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_subject_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_url_clean(ngx_str_t *url, size_t max);
static ngx_int_t ngx_http_waf_url_parse(ngx_str_t *url,
    ngx_http_waf_url_t *parsed);
static ngx_uint_t ngx_http_waf_redirect_allowed(ngx_http_waf_loc_conf_t *wlcf,
    ngx_str_t *url);
static ngx_uint_t ngx_http_waf_host_matches(
    ngx_http_waf_redirect_allow_t *allow, ngx_str_t *host);
static ngx_uint_t ngx_http_waf_prefix_bounded(ngx_str_t *s, ngx_str_t *prefix);
static ngx_int_t ngx_http_waf_keyword(ngx_http_waf_kw_t *kw, ngx_str_t *name,
    ngx_uint_t *value);


static ngx_http_waf_kw_t  ngx_http_waf_verdicts[] = {
    { ngx_string("allow"),    NGX_HTTP_WAF_V_ALLOW    },
    { ngx_string("score"),    NGX_HTTP_WAF_V_SCORE    },
    { ngx_string("redirect"), NGX_HTTP_WAF_V_REDIRECT },
    { ngx_string("deny"),     NGX_HTTP_WAF_V_DENY     },
    { ngx_string("error"),    NGX_HTTP_WAF_V_ERROR    },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_do_verbs[] = {
    { ngx_string("challenge"), NGX_HTTP_WAF_DO_CHALLENGE },
    { ngx_string("threshold"), NGX_HTTP_WAF_DO_THRESHOLD },
    { ngx_string("skip"),      NGX_HTTP_WAF_DO_SKIP      },
    { ngx_string("reauth"),    NGX_HTTP_WAF_DO_REAUTH    },
    { ngx_string("note"),      NGX_HTTP_WAF_DO_NOTE      },
    { ngx_string("mutate"),    NGX_HTTP_WAF_DO_MUTATE    },
    { ngx_string("active"),    NGX_HTTP_WAF_DO_ACTIVE    },
    { ngx_string("passive"),   NGX_HTTP_WAF_DO_PASSIVE   },
    { ngx_string("off"),       NGX_HTTP_WAF_DO_OFF       },
    { ngx_string("vote"),      NGX_HTTP_WAF_DO_VOTE      },
    { ngx_string("audit"),     NGX_HTTP_WAF_DO_AUDIT     },
    { ngx_string("archive"),   NGX_HTTP_WAF_DO_ARCHIVE   },
    { ngx_string("mark"),      NGX_HTTP_WAF_DO_MARK      },
    { ngx_string("score"),     NGX_HTTP_WAF_DO_SCORE     },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_apply_axes[] = {
    { ngx_string("request"), NGX_HTTP_WAF_APPLY_REQUEST },
    { ngx_string("ip"),      NGX_HTTP_WAF_APPLY_IP      },
    { ngx_string("asn"),     NGX_HTTP_WAF_APPLY_ASN     },
    { ngx_string("session"), NGX_HTTP_WAF_APPLY_SESSION },
    { ngx_string("conn"),    NGX_HTTP_WAF_APPLY_CONN    },
    { ngx_string("response"), NGX_HTTP_WAF_APPLY_RESPONSE },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_to_phases[] = {
    { ngx_string("request"),
      NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)  },
    { ngx_string("response"),
      NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_RESPONSE) },
    { ngx_string("frame"),    NGX_HTTP_WAF_PH_FRAME    },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_same_site[] = {
    { ngx_string("Lax"),    NGX_HTTP_WAF_SAMESITE_LAX    },
    { ngx_string("Strict"), NGX_HTTP_WAF_SAMESITE_STRICT },
    { ngx_string("None"),   NGX_HTTP_WAF_SAMESITE_NONE   },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_http_waf_forbidden_headers[] = {
    ngx_string("host"),
    ngx_string("authorization"),
    ngx_string("cookie"),
    ngx_string("content-length"),
    ngx_string("transfer-encoding"),
    ngx_string("content-encoding"),
    ngx_string("connection"),
    ngx_string("upgrade"),
    ngx_string("keep-alive"),
    ngx_string("proxy-authenticate"),
    ngx_string("proxy-authorization"),
    ngx_string("te"),
    ngx_string("trailer"),
    ngx_null_string
};


#define ngx_http_waf_reply_reject(err, text)                                  \
    do {                                                                      \
        (err)->data = (u_char *) text;                                        \
        (err)->len  = sizeof(text) - 1;                                        \
        return NGX_ERROR;                                                     \
    } while (0)


ngx_int_t
ngx_http_waf_msg_reply(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_str_t *payload, ngx_http_waf_reply_t *reply, ngx_str_t *err)
{
    ngx_str_t                  key, value, cont;
    ngx_int_t                  rc, n, cont_ttl;
    ngx_uint_t                 verdict, version;
    ngx_http_waf_jp_t          jp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (index >= wmcf->inspectors.nelts) {
        ngx_http_waf_reply_reject(err, "reply names no declared inspector");
    }

    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (payload->len > wmcf->reply_max) {
        ngx_http_waf_reply_reject(err, "reply exceeds waf_reply_max");
    }

    ngx_memzero(reply, sizeof(ngx_http_waf_reply_t));

    reply->verdict = NGX_HTTP_WAF_V_ALLOW;
    reply->score   = -1;

    version = 0;
    verdict = NGX_CONF_UNSET_UINT;

    ngx_str_null(&cont);
    cont_ttl = 0;

    ngx_http_waf_jp_init(&jp, payload, ctx->request->pool);

    if (ngx_http_waf_jp_object(&jp) != NGX_OK) {
        ngx_http_waf_reply_reject(err, "reply is not a JSON object");
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(&jp, &key);

        if (rc == NGX_DONE) {
            break;
        }

        if (rc != NGX_OK) {
            ngx_http_waf_reply_reject(err, "malformed JSON");
        }

        if (key.len == 1 && key.data[0] == 'v') {
            if (ngx_http_waf_jp_int(&jp, &n) != NGX_OK || n <= 0) {
                ngx_http_waf_reply_reject(err, "field v is not a version");
            }

            version = (ngx_uint_t) n;
            continue;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "rid", 3) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "field rid is not a string");
            }

            if (value.len != NGX_HTTP_WAF_RID_HEX_LEN
                || ngx_memcmp(value.data, ctx->rid_hex,
                              NGX_HTTP_WAF_RID_HEX_LEN) != 0)
            {
                ngx_http_waf_reply_reject(err, "rid does not echo the request");
            }

            continue;
        }

        if (key.len == 9 && ngx_strncmp(key.data, "inspector", 9) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK) {
                ngx_http_waf_reply_reject(err,
                                          "field inspector is not a string");
            }

            if (value.len != insp->name.len
                || ngx_memcmp(value.data, insp->name.data, value.len) != 0)
            {
                ngx_http_waf_reply_reject(err, "reply impersonates another "
                                               "inspector");
            }

            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "verdict", 7) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "field verdict is not a string");
            }

            if (ngx_http_waf_keyword(ngx_http_waf_verdicts, &value, &verdict)
                != NGX_OK)
            {
                ngx_http_waf_reply_reject(err, "unknown verdict");
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "score", 5) == 0) {
            if (ngx_http_waf_jp_int(&jp, &n) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "field score is not an integer");
            }

            if (n < 0 || n > NGX_HTTP_WAF_SCORE_MAX) {
                ngx_http_waf_reply_reject(err, "field score is out of range");
            }

            reply->score = n;
            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "reason", 6) == 0) {
            if (ngx_http_waf_reply_reason(&jp, ctx, index, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed reason");
            }

            continue;
        }

        if (key.len == 8 && ngx_strncmp(key.data, "response", 8) == 0) {
            if (ngx_http_waf_reply_response(&jp, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed response reference");
            }

            continue;
        }

        if (key.len == 8 && ngx_strncmp(key.data, "redirect", 8) == 0) {
            if (ngx_http_waf_reply_redirect(&jp, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed redirect section");
            }

            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "headers", 7) == 0) {
            if (ngx_http_waf_reply_headers(&jp, ctx, index, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed headers section");
            }

            continue;
        }

        if (key.len == 4 && ngx_strncmp(key.data, "args", 4) == 0) {
            if (ngx_http_waf_reply_args(&jp, ctx, index, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed args section");
            }

            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "rewrite", 7) == 0) {
            if (ngx_http_waf_reply_rewrite(&jp, ctx, index, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed rewrite section");
            }

            continue;
        }

        if (key.len == 8 && ngx_strncmp(key.data, "continue", 8) == 0) {
            if (ngx_http_waf_reply_continue(&jp, &cont, &cont_ttl) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed continue section");
            }

            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "cookies", 7) == 0) {
            if (ngx_http_waf_reply_cookies(&jp, ctx, index, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed cookies section");
            }

            continue;
        }

        if (key.len == 8 && ngx_strncmp(key.data, "sessions", 8) == 0) {
            if (ngx_http_waf_reply_sessions(&jp, ctx, index, reply) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "malformed sessions section");
            }

            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "actions", 7) == 0) {
            if (ngx_http_waf_reply_actions(&jp, ctx, index, reply, err)
                != NGX_OK)
            {
                if (err->len == 0) {
                    ngx_http_waf_reply_reject(err, "malformed actions section");
                }

                return NGX_ERROR;
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "cache", 5) == 0) {
            ngx_uint_t  cacheable;

            if (ngx_http_waf_jp_bool(&jp, &cacheable) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "field cache is not a boolean");
            }

            reply->no_cache = cacheable ? 0 : 1;
            continue;
        }

        if (ngx_http_waf_jp_skip(&jp) != NGX_OK) {
            ngx_http_waf_reply_reject(err, "malformed JSON");
        }
    }

    if (ngx_http_waf_jp_end(&jp) != NGX_OK) {
        ngx_http_waf_reply_reject(err, "trailing data after the reply object");
    }

    if (version == 0) {
        ngx_http_waf_reply_reject(err, "field v is missing");
    }

    if (version != NGX_HTTP_WAF_PROTOCOL_VERSION) {
        ngx_http_waf_reply_reject(err, "unsupported schema version");
    }

    if (verdict == NGX_CONF_UNSET_UINT) {
        ngx_http_waf_reply_reject(err, "field verdict is missing");
    }

    if (verdict == NGX_HTTP_WAF_V_REDIRECT
        && ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" redirects on the %V phase, where "
                      "nobody is left to redirect; taken as allow",
                      &insp->name, ngx_http_waf_phase_name(ctx->phase));

        verdict = NGX_HTTP_WAF_V_ALLOW;
    }

    reply->verdict = verdict;

    if (verdict == NGX_HTTP_WAF_V_ERROR) {

        if (reply->reason_code.len == 0) {
            ngx_http_waf_reply_reject(err, "verdict error without reason.code");
        }

        reply->score = 0;

        ngx_str_null(&reply->response_name);
        ngx_str_null(&reply->redirect_url);
        ngx_str_null(&reply->rewrite_key);
        ngx_str_null(&reply->rewrite_content_type);

        reply->status          = 0;
        reply->rewrite_has     = 0;
        reply->rewrite_body    = 0;
        reply->rewrite_size    = 0;
        reply->rewrite_groups  = NULL;
        reply->headers_set     = NULL;
        reply->headers_unset   = NULL;
        reply->args_set        = NULL;
        reply->args_unset      = NULL;
        reply->cookies         = NULL;

        if (reply->actions != NULL) {
            ngx_http_waf_action_t  *a = reply->actions->elts;
            ngx_uint_t              i, kept = 0;

            for (i = 0; i < reply->actions->nelts; i++) {

                if (!ngx_http_waf_do_module(a[i].verb)
                    || ngx_http_waf_do_score(a[i].verb))
                {
                    continue;
                }

                a[kept++] = a[i];
            }

            reply->actions->nelts = kept;

            if (kept == 0) {
                reply->actions = NULL;
            }
        }

        return NGX_OK;
    }

    if (verdict == NGX_HTTP_WAF_V_SCORE) {
        if (reply->score < 0) {
            ngx_http_waf_reply_reject(err, "verdict score without score");
        }

    } else {
        reply->score = 0;
    }

    if (verdict == NGX_HTTP_WAF_V_REDIRECT) {
        if (reply->redirect_url.len == 0) {
            ngx_http_waf_reply_reject(err, "verdict redirect without "
                                           "redirect.url");
        }

        if (!ngx_http_waf_url_clean(&reply->redirect_url,
                                    wmcf->header_value_max))
        {
            ngx_http_waf_reply_reject(err, "redirect url is not a valid "
                                           "header value");
        }

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        if (!ngx_http_waf_redirect_allowed(wlcf, &reply->redirect_url)) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" redirects to \"%V\", which no "
                          "waf_redirect_allow pattern permits",
                          &insp->name, &reply->redirect_url);

            ngx_http_waf_reply_reject(err, "redirect url is not allowed by "
                                           "waf_redirect_allow");
        }

    } else {
        reply->status = 0;
        ngx_str_null(&reply->redirect_url);
    }

    if (cont.len != 0 && cont_ttl > 0
        && ngx_http_waf_reply_resume(ctx, index, &cont, cont_ttl) != NGX_OK)
    {
        ngx_http_waf_reply_reject(err, "continuation could not be kept");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_reply_continue(ngx_http_waf_jp_t *jp, ngx_str_t *subject,
    ngx_int_t *ttl)
{
    ngx_int_t  rc;
    ngx_str_t  key;

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "subject", 7) == 0) {
            if (ngx_http_waf_jp_string(jp, subject) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "ttl_ms", 6) == 0) {
            if (ngx_http_waf_jp_int(jp, ttl) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


static ngx_int_t
ngx_http_waf_reply_resume(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_str_t *subject, ngx_int_t ttl)
{
    u_char                     shown[NGX_HTTP_WAF_SHOWN_LEN];
    ngx_uint_t                 i;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" offered a continuation on the "
                      "%V phase, which only the request phase hands over; "
                      "ignored",
                      &insp->name, ngx_http_waf_phase_name(ctx->phase));

        return NGX_OK;
    }

    for (i = 0; i < subject->len; i++) {
        if (subject->data[i] <= ' ' || subject->data[i] == '*'
            || subject->data[i] == '>' || subject->data[i] == 0x7f)
        {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" offered a continuation "
                          "subject that is not publishable; ignored",
                          &insp->name);

            return NGX_OK;
        }
    }

    if (subject->len <= insp->subject.len
        || ngx_memcmp(subject->data, insp->subject.data, insp->subject.len)
           != 0
        || subject->data[insp->subject.len] != '.')
    {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" offered continuation on \"%*s\", "
                      "outside its own subject; ignored", &insp->name,
                      ngx_http_waf_shown(shown, subject), shown);

        return NGX_OK;
    }

    return ngx_http_waf_resume_keep(ctx, index, subject, (ngx_msec_t) ttl);
}


static ngx_int_t
ngx_http_waf_reply_reason(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    u_char     *save;
    ngx_str_t   key, value;
    ngx_int_t   rc, n;

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 4 && ngx_strncmp(key.data, "code", 4) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (!ngx_http_waf_text_clean(&value, NGX_MAX_SIZE_T_VALUE)) {
                return NGX_ERROR;
            }

            reply->reason_code = value;
            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "class", 5) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (value.len == 8 && ngx_strncmp(value.data, "overload", 8) == 0) {
                reply->overload = 1;
            }

            continue;
        }

        save = jp->pos;

        if (key.len == 5 && ngx_strncmp(key.data, "scope", 5) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                jp->pos = save;

                if (ngx_http_waf_reply_optional(jp, ctx, index, "scope")
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            reply->reason_scope = ngx_http_waf_deny_scope_parse(&value);
            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "subject", 7) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                jp->pos = save;

                if (ngx_http_waf_reply_optional(jp, ctx, index, "subject")
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (ngx_http_waf_subject_clean(&value)) {
                reply->reason_subject = value;
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "retry", 5) == 0) {
            if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                jp->pos = save;

                if (ngx_http_waf_reply_optional(jp, ctx, index, "retry")
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (n > 0 && n <= NGX_HTTP_WAF_DENY_RETRY_MAX) {
                reply->reason_retry = (ngx_uint_t) n;
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


static ngx_int_t
ngx_http_waf_reply_optional(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, const char *field)
{
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    jp->error = NULL;

    if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: inspector \"%V\" sent reason.%s of a wrong type; "
                  "dropped", &insp->name, field);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_reply_response(ngx_http_waf_jp_t *jp, ngx_http_waf_reply_t *reply)
{
    ngx_str_t  key, value;
    ngx_int_t  rc;

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 4 && ngx_strncmp(key.data, "name", 4) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (!ngx_http_waf_token_clean(&value)) {
                return NGX_ERROR;
            }

            reply->response_name = value;
            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


static ngx_int_t
ngx_http_waf_reply_redirect(ngx_http_waf_jp_t *jp, ngx_http_waf_reply_t *reply)
{
    ngx_str_t  key, value;
    ngx_int_t  rc, n;

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            if (reply->status == 0) {
                reply->status = NGX_HTTP_SEE_OTHER;
            }

            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "url", 3) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            reply->redirect_url = value;
            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "status", 6) == 0) {
            if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                return NGX_ERROR;
            }

            if (n != NGX_HTTP_MOVED_TEMPORARILY && n != NGX_HTTP_SEE_OTHER
                && n != NGX_HTTP_TEMPORARY_REDIRECT)
            {
                return NGX_ERROR;
            }

            reply->status = (ngx_uint_t) n;
            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


static ngx_int_t
ngx_http_waf_reply_args(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    ngx_str_t                 *unset, key, name, value;
    ngx_int_t                  rc;
    ngx_keyval_t              *kv;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            break;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "set", 3) == 0) {

            if (ngx_http_waf_jp_object(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            for ( ;; ) {
                rc = ngx_http_waf_jp_member(jp, &name);

                if (rc == NGX_DONE) {
                    break;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_arg_clean(&name, 1)
                    || !ngx_http_waf_arg_clean(&value, 0)
                    || value.len > ngx_http_waf_args_cap(ctx->request))
                {
                    return NGX_ERROR;
                }

                if (reply->args_set == NULL) {
                    reply->args_set = ngx_array_create(ctx->request->pool, 4,
                                                       sizeof(ngx_keyval_t));
                    if (reply->args_set == NULL) {
                        return NGX_ERROR;
                    }
                }

                kv = ngx_array_push(reply->args_set);
                if (kv == NULL) {
                    return NGX_ERROR;
                }

                kv->key   = name;
                kv->value = value;
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "unset", 5) == 0) {

            if (ngx_http_waf_jp_array(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            for ( ;; ) {
                rc = ngx_http_waf_jp_element(jp);

                if (rc == NGX_DONE) {
                    break;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_jp_string(jp, &name) != NGX_OK
                    || !ngx_http_waf_arg_clean(&name, 1))
                {
                    return NGX_ERROR;
                }

                if (reply->args_unset == NULL) {
                    reply->args_unset = ngx_array_create(ctx->request->pool,
                                                         4,
                                                         sizeof(ngx_str_t));
                    if (reply->args_unset == NULL) {
                        return NGX_ERROR;
                    }
                }

                unset = ngx_array_push(reply->args_unset);
                if (unset == NULL) {
                    return NGX_ERROR;
                }

                *unset = name;
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (reply->args_set == NULL && reply->args_unset == NULL) {
        return NGX_OK;
    }

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" asked to change the query "
                      "string on the %V phase; not supported",
                      &insp->name, ngx_http_waf_phase_name(ctx->phase));

        reply->args_set   = NULL;
        reply->args_unset = NULL;

        return NGX_OK;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_arg_clean(ngx_str_t *s, ngx_uint_t name)
{
    size_t  i;
    u_char  c;

    if (name && s->len == 0) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        c = s->data[i];

        if (c <= ' ' || c == 0x7f || c == '&' || c == '#'
            || (name && c == '='))
        {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_http_waf_reply_headers(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    ngx_str_t                 *unset, key, name, value;
    ngx_int_t                  rc;
    ngx_keyval_t              *kv;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "set", 3) == 0) {

            if (ngx_http_waf_jp_object(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            for ( ;; ) {
                rc = ngx_http_waf_jp_member(jp, &name);

                if (rc == NGX_DONE) {
                    break;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_token_clean(&name)) {
                    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                                  0, "waf: inspector \"%V\" sent a malformed "
                                  "header name", &insp->name);
                    continue;
                }

                if (ngx_http_waf_header_forbidden(&name)) {
                    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                                  0, "waf: inspector \"%V\" may not override "
                                  "header \"%V\"", &insp->name, &name);
                    continue;
                }

                if (!ngx_http_waf_value_clean(&value)
                    || value.len > wmcf->header_value_max)
                {
                    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                                  0, "waf: inspector \"%V\" sent an invalid "
                                  "value for header \"%V\"",
                                  &insp->name, &name);
                    continue;
                }

                if (reply->headers_set == NULL) {
                    reply->headers_set = ngx_array_create(ctx->request->pool, 4,
                                                          sizeof(ngx_keyval_t));
                    if (reply->headers_set == NULL) {
                        return NGX_ERROR;
                    }
                }

                kv = ngx_array_push(reply->headers_set);
                if (kv == NULL) {
                    return NGX_ERROR;
                }

                kv->key   = name;
                kv->value = value;
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "unset", 5) == 0) {

            if (ngx_http_waf_jp_array(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            for ( ;; ) {
                rc = ngx_http_waf_jp_element(jp);

                if (rc == NGX_DONE) {
                    break;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_jp_string(jp, &name) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_token_clean(&name)) {
                    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                                  0, "waf: inspector \"%V\" sent a malformed "
                                  "header name", &insp->name);
                    continue;
                }

                if (ngx_http_waf_header_forbidden(&name)) {
                    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log,
                                  0,
                                  "waf: inspector \"%V\" is not allowed to "
                                  "unset header \"%V\"", &insp->name, &name);
                    continue;
                }

                if (reply->headers_unset == NULL) {
                    reply->headers_unset = ngx_array_create(ctx->request->pool,
                                                            4,
                                                            sizeof(ngx_str_t));
                    if (reply->headers_unset == NULL) {
                        return NGX_ERROR;
                    }
                }

                unset = ngx_array_push(reply->headers_unset);
                if (unset == NULL) {
                    return NGX_ERROR;
                }

                *unset = name;
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


static ngx_int_t
ngx_http_waf_reply_rewrite(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    u_char                     shown[NGX_HTTP_WAF_SHOWN_LEN];
    ngx_str_t                  key, value, *group;
    ngx_int_t                  rc, n;
    ngx_uint_t                 i, body, has_key, has_size;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    body     = 0;
    has_key  = 0;
    has_size = 0;

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            break;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 4 && ngx_strncmp(key.data, "body", 4) == 0) {

            if (ngx_http_waf_jp_object(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            body = 1;

            for ( ;; ) {
                rc = ngx_http_waf_jp_member(jp, &key);

                if (rc == NGX_DONE) {
                    break;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                if (key.len == 3 && ngx_strncmp(key.data, "key", 3) == 0) {
                    if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                        return NGX_ERROR;
                    }

                    if (!ngx_http_waf_rewrite_key_clean(
                            ctx, NGX_HTTP_WAF_OBJ_BODY, &value))
                    {
                        ngx_log_error(NGX_LOG_WARN,
                                      ctx->request->connection->log, 0,
                                      "waf: inspector \"%V\" sent rewrite "
                                      "key \"%*s\", expected "
                                      "%V:%*s:%V:<suffix>",
                                      &insp->name,
                                      ngx_http_waf_shown(shown, &value), shown,
                                      &wmcf->node_id,
                                      (size_t) NGX_HTTP_WAF_RID_HEX_LEN,
                                      ctx->rid_hex,
                                      ngx_http_waf_body_phase_tag_name(
                                          ctx->phase));
                        return NGX_ERROR;
                    }

                    reply->rewrite_key = value;
                    has_key = 1;
                    continue;
                }

                if (key.len == 4 && ngx_strncmp(key.data, "size", 4) == 0) {
                    if (ngx_http_waf_jp_int(jp, &n) != NGX_OK || n < 0) {
                        return NGX_ERROR;
                    }

                    reply->rewrite_size = (off_t) n;
                    reply->rewrite_body = 1;
                    has_size = 1;
                    continue;
                }

                if (key.len == 6 && ngx_strncmp(key.data, "sha256", 6) == 0) {
                    if (ngx_http_waf_jp_string(jp, &value) != NGX_OK
                        || value.len != 64)
                    {
                        return NGX_ERROR;
                    }

                    for (i = 0; i < 32; i++) {
                        n = ngx_hextoi(value.data + i * 2, 2);
                        if (n == NGX_ERROR) {
                            return NGX_ERROR;
                        }

                        reply->rewrite_sha256[i] = (u_char) n;
                    }

                    reply->rewrite_sha256_set = 1;
                    continue;
                }

                if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
                    return NGX_ERROR;
                }
            }

            continue;
        }

        if (key.len == 12 && ngx_strncmp(key.data, "content_type", 12) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK
                || value.len == 0
                || !ngx_http_waf_text_clean(&value, 128))
            {
                return NGX_ERROR;
            }

            reply->rewrite_content_type = value;
            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "groups", 6) == 0) {

            if (ngx_http_waf_jp_array(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            for ( ;; ) {
                rc = ngx_http_waf_jp_element(jp);

                if (rc == NGX_DONE) {
                    break;
                }

                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK
                    || !ngx_http_waf_group_clean(&value))
                {
                    return NGX_ERROR;
                }

                if (reply->rewrite_groups == NULL) {
                    reply->rewrite_groups =
                        ngx_array_create(ctx->request->pool, 4,
                                         sizeof(ngx_str_t));
                    if (reply->rewrite_groups == NULL) {
                        return NGX_ERROR;
                    }
                }

                if (reply->rewrite_groups->nelts
                    >= NGX_HTTP_WAF_MUTATE_GROUPS_MAX)
                {
                    return NGX_ERROR;
                }

                group = ngx_array_push(reply->rewrite_groups);
                if (group == NULL) {
                    return NGX_ERROR;
                }

                *group = value;
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (body && !(has_key && has_size)) {
        return NGX_ERROR;
    }

    reply->rewrite_has = 1;

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_group_clean(ngx_str_t *s)
{
    u_char  c;
    size_t  i;

    if (s->len == 0 || s->len > NGX_HTTP_WAF_MUTATE_NAME_MAX) {
        return 0;
    }

    if (!((s->data[0] >= 'a' && s->data[0] <= 'z') || s->data[0] == '_')) {
        return 0;
    }

    for (i = 1; i < s->len; i++) {
        c = s->data[i];

        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '_' || c == '-')
        {
            continue;
        }

        return 0;
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_rewrite_key_clean(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    ngx_str_t *key)
{
    u_char                    *p, c;
    size_t                     i, prefix;
    ngx_str_t                 *tag, suffix;
    ngx_http_waf_locator_t    *loc;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    loc = ngx_http_waf_store_locator_live(ctx, ctx->phase, obj);

    if (loc != NULL && loc->key.len != 0
        && key->len > loc->key.len + 1 && key->len <= loc->key.len + 1 + 32
        && ngx_memcmp(key->data, loc->key.data, loc->key.len) == 0
        && key->data[loc->key.len] == ':')
    {
        for (i = loc->key.len + 1; i < key->len; i++) {
            c = key->data[i];

            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '_' || c == '-')
            {
                continue;
            }

            return 0;
        }

        suffix.data = key->data + loc->key.len + 1;
        suffix.len  = key->len - loc->key.len - 1;

        return !ngx_http_waf_obj_suffix_reserved(&suffix);
    }

    tag  = ngx_http_waf_body_phase_tag_name(ctx->phase);

    prefix = wmcf->node_id.len + 1 + NGX_HTTP_WAF_RID_HEX_LEN + 1
             + tag->len + 1;

    if (key->len <= prefix || key->len > prefix + 32) {
        return 0;
    }

    p = key->data;

    if (ngx_memcmp(p, wmcf->node_id.data, wmcf->node_id.len) != 0) {
        return 0;
    }

    p += wmcf->node_id.len;

    if (*p++ != ':') {
        return 0;
    }

    if (ngx_memcmp(p, ctx->rid_hex, NGX_HTTP_WAF_RID_HEX_LEN) != 0) {
        return 0;
    }

    p += NGX_HTTP_WAF_RID_HEX_LEN;

    if (*p++ != ':') {
        return 0;
    }

    if (ngx_memcmp(p, tag->data, tag->len) != 0) {
        return 0;
    }

    p += tag->len;

    if (*p++ != ':') {
        return 0;
    }

    for (i = prefix; i < key->len; i++) {
        c = key->data[i];

        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '_' || c == '-')
        {
            continue;
        }

        return 0;
    }

    suffix.data = key->data + prefix;
    suffix.len  = key->len - prefix;

    return !ngx_http_waf_obj_suffix_reserved(&suffix);
}


static ngx_int_t
ngx_http_waf_reply_actions(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply, ngx_str_t *err)
{
    u_char                    *begin, shown[NGX_HTTP_WAF_SHOWN_LEN];
    ngx_str_t                  key, value, to;
    ngx_int_t                  rc, n;
    ngx_uint_t                 verb_set, apply_set, wave, obj;
    ngx_http_waf_action_t     *slot, action;
    ngx_http_waf_binding_t    *self;
    ngx_http_waf_inspector_t  *insp, *dst;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    self = ngx_http_waf_binding_find(wlcf, index, ctx->phase);
    wave = self != NULL ? self->wave : 0;

    if (wlcf->actions_max == 0) {
        return ngx_http_waf_jp_skip(jp);
    }

    if (ngx_http_waf_jp_array(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_element(jp);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        begin = jp->pos;

        if (ngx_http_waf_jp_object(jp) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memzero(&action, sizeof(ngx_http_waf_action_t));

        action.to   = NGX_HTTP_WAF_ACTION_ALL;
        action.from = index;

        ngx_str_null(&to);
        verb_set  = 0;
        apply_set = 0;

        for ( ;; ) {
            rc = ngx_http_waf_jp_member(jp, &key);

            if (rc == NGX_DONE) {
                break;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            if (key.len == 2 && ngx_strncmp(key.data, "do", 2) == 0) {
                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_keyword(ngx_http_waf_do_verbs, &value,
                                         &action.verb) != NGX_OK)
                {
                    ngx_http_waf_reply_reject(err, "unknown action verb");
                }

                verb_set = 1;
                continue;
            }

            if (key.len == 2 && ngx_strncmp(key.data, "to", 2) == 0) {
                if (ngx_http_waf_jp_string(jp, &to) != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "code", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &action.code) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_code_clean(&action.code)) {
                    ngx_http_waf_reply_reject(err, "action code is not a code");
                }

                continue;
            }

            if (key.len == 5 && ngx_strncmp(key.data, "apply", 5) == 0) {
                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_keyword(ngx_http_waf_apply_axes, &value,
                                         &action.apply) != NGX_OK)
                {
                    ngx_http_waf_reply_reject(err, "unknown action axis");
                }

                apply_set = 1;
                continue;
            }

            if (key.len == 5 && ngx_strncmp(key.data, "phase", 5) == 0) {
                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (ngx_http_waf_keyword(ngx_http_waf_to_phases, &value,
                                         &action.to_phases) != NGX_OK)
                {
                    ngx_http_waf_reply_reject(err, "unknown action phase");
                }

                continue;
            }

            if (key.len == 5 && ngx_strncmp(key.data, "delta", 5) == 0) {
                if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (n < -NGX_HTTP_WAF_DELTA_MAX || n > NGX_HTTP_WAF_DELTA_MAX) {
                    ngx_http_waf_reply_reject(err,
                                              "action delta is out of range");
                }

                action.delta     = n;
                action.has_delta = 1;
                continue;
            }

            if (key.len == 5 && ngx_strncmp(key.data, "value", 5) == 0) {
                if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (n < -NGX_HTTP_WAF_VALUE_MAX || n > NGX_HTTP_WAF_VALUE_MAX) {
                    ngx_http_waf_reply_reject(err,
                                              "action value is out of range");
                }

                action.value     = n;
                action.has_value = 1;
                continue;
            }

            if (key.len == 7 && ngx_strncmp(key.data, "counter", 7) == 0) {
                if (ngx_http_waf_jp_string(jp, &action.counter) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_counter_clean(&action.counter)) {
                    ngx_http_waf_reply_reject(err,
                                              "action counter is not a name");
                }

                continue;
            }

            if (key.len == 5 && ngx_strncmp(key.data, "group", 5) == 0) {
                if (ngx_http_waf_jp_string(jp, &action.group) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_counter_clean(&action.group)) {
                    ngx_http_waf_reply_reject(err,
                                              "action group is not a name");
                }

                continue;
            }

            if (key.len == 6 && ngx_strncmp(key.data, "marker", 6) == 0) {
                if (ngx_http_waf_jp_string(jp, &action.marker) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (!ngx_http_waf_marker_clean(&action.marker)) {
                    ngx_http_waf_reply_reject(err, "action marker is not a marker");
                }

                continue;
            }

            if (key.len == 3 && ngx_strncmp(key.data, "set", 3) == 0) {
                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (value.len == 2 && ngx_strncmp(value.data, "on", 2) == 0) {
                    action.set = NGX_HTTP_WAF_SET_ON;

                } else if (value.len == 3
                           && ngx_strncmp(value.data, "off", 3) == 0)
                {
                    action.set = NGX_HTTP_WAF_SET_OFF;

                } else {
                    ngx_http_waf_reply_reject(err,
                                              "action set must be on or off");
                }

                continue;
            }

            if (key.len == 3 && ngx_strncmp(key.data, "ttl", 3) == 0) {
                if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                    return NGX_ERROR;
                }

                if (n < 0 || n > NGX_HTTP_WAF_ACTION_TTL_MAX) {
                    ngx_http_waf_reply_reject(err, "action ttl is out of range");
                }

                action.spec.ttl     = (time_t) n;
                action.spec.has_ttl = 1;
                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "when", 4) == 0) {
                if (ngx_http_waf_jp_array(jp) != NGX_OK) {
                    return NGX_ERROR;
                }

                action.spec.when = 0;

                for ( ;; ) {
                    rc = ngx_http_waf_jp_element(jp);

                    if (rc == NGX_DONE) {
                        break;
                    }

                    if (rc != NGX_OK) {
                        return NGX_ERROR;
                    }

                    if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                        return NGX_ERROR;
                    }

                    if (value.len == 5
                        && ngx_strncmp(value.data, "allow", 5) == 0)
                    {
                        action.spec.when |= 1u << NGX_HTTP_WAF_V_ALLOW;

                    } else if (value.len == 4
                               && ngx_strncmp(value.data, "deny", 4) == 0)
                    {
                        action.spec.when |= 1u << NGX_HTTP_WAF_V_DENY;

                    } else {
                        ngx_http_waf_reply_reject(err,
                            "action when accepts only allow and deny");
                    }
                }

                if (action.spec.when == 0) {
                    ngx_http_waf_reply_reject(err,
                        "action when names no outcome; omit it to archive "
                        "every outcome");
                }

                action.spec.has_when = 1;
                continue;
            }

            if (ngx_http_waf_obj_find(&key, &obj) == NGX_OK) {
                if (ngx_http_waf_reply_object_spec(jp, &action.spec, obj, err)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (!verb_set) {
            ngx_http_waf_reply_reject(err, "action without a verb");
        }

        if (!apply_set) {
            ngx_http_waf_reply_reject(err, "action without an axis");
        }

        if (!ngx_http_waf_apply_allowed(action.verb, action.apply)) {
            ngx_http_waf_reply_reject(err, "action axis does not fit the verb");
        }

        if (action.verb == NGX_HTTP_WAF_DO_THRESHOLD && !action.has_delta) {
            ngx_http_waf_reply_reject(err, "threshold without delta");
        }

        if (action.counter.len != 0
            && action.verb != NGX_HTTP_WAF_DO_NOTE)
        {
            ngx_http_waf_reply_reject(err, "counter is only for note");
        }

        if (action.marker.len != 0 && !ngx_http_waf_do_mark(action.verb)) {
            ngx_http_waf_reply_reject(err, "marker is only for mark");
        }

        if (action.verb == NGX_HTTP_WAF_DO_MUTATE) {
            if (action.group.len == 0 || action.set == NGX_HTTP_WAF_SET_NONE) {
                ngx_http_waf_reply_reject(err, "mutate without group or set");
            }

        } else if (action.group.len != 0) {
            ngx_http_waf_reply_reject(err, "group is only for mutate");

        } else if (ngx_http_waf_do_audit(action.verb)) {
            if (action.set == NGX_HTTP_WAF_SET_NONE) {
                ngx_http_waf_reply_reject(err, "audit verb without set");
            }

            if (action.set == NGX_HTTP_WAF_SET_OFF
                && (action.spec.has_ttl || action.spec.has_when
                    || action.spec.named != 0))
            {
                ngx_http_waf_reply_reject(err,
                    "ttl, when and objects are only for set on");
            }

            if (action.verb == NGX_HTTP_WAF_DO_AUDIT
                && (action.spec.has_ttl || action.spec.has_when))
            {
                ngx_http_waf_reply_reject(err,
                    "ttl and when are only for archive");
            }

            if (action.apply == NGX_HTTP_WAF_APPLY_RESPONSE
                && (action.spec.named & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS)))
            {
                ngx_http_waf_reply_reject(err,
                    "args has no meaning for the response record");
            }

            if (to.len != 0) {
                ngx_http_waf_reply_reject(err, "audit verb takes no addressee");
            }

        } else if (ngx_http_waf_do_mark(action.verb)) {
            if (action.marker.len == 0) {
                ngx_http_waf_reply_reject(err, "mark without a marker");
            }

            if (to.len != 0) {
                ngx_http_waf_reply_reject(err, "mark takes no addressee");
            }

            if (action.set != NGX_HTTP_WAF_SET_NONE || action.spec.has_ttl
                || action.spec.has_when || action.spec.named != 0)
            {
                ngx_http_waf_reply_reject(err,
                    "set, ttl, when and objects are only for audit and archive");
            }

        } else if (ngx_http_waf_do_score(action.verb)) {
            if (!action.has_value || action.value == 0) {
                ngx_http_waf_reply_reject(err, "score without value");
            }

            if (action.value < -NGX_HTTP_WAF_POINTS_MAX
                || action.value > NGX_HTTP_WAF_POINTS_MAX)
            {
                ngx_http_waf_reply_reject(err, "score value is out of range");
            }

            if (to.len != 0) {
                ngx_http_waf_reply_reject(err, "score takes no addressee");
            }

            if (action.set != NGX_HTTP_WAF_SET_NONE || action.spec.has_ttl
                || action.spec.has_when || action.spec.named != 0)
            {
                ngx_http_waf_reply_reject(err,
                    "set, ttl, when and objects are only for audit and archive");
            }

        } else if (action.set != NGX_HTTP_WAF_SET_NONE) {
            ngx_http_waf_reply_reject(err,
                                      "set is only for mutate, audit and archive");

        } else if (action.spec.has_ttl || action.spec.has_when
                   || action.spec.named != 0)
        {
            ngx_http_waf_reply_reject(err,
                "ttl, when and objects are only for audit and archive");
        }

        if (ngx_http_waf_do_control(action.verb)) {
            if (to.len == 0) {
                ngx_http_waf_reply_reject(err, "control verb without to");
            }

            if (action.apply == NGX_HTTP_WAF_APPLY_CONN
                && !ngx_http_waf_phase_is_frame(ctx->phase))
            {
                ngx_http_waf_reply_reject(err, "apply conn outside frames");
            }

            if (action.apply == NGX_HTTP_WAF_APPLY_CONN
                && action.to_phases != 0
                && (action.to_phases & NGX_HTTP_WAF_PH_FRAME) == 0)
            {
                ngx_http_waf_reply_reject(err,
                                          "apply conn needs phase frame");
            }

        } else if (action.to_phases != 0) {
            ngx_http_waf_reply_reject(err, "phase is only for control verbs");
        }

        if ((size_t) (jp->pos - begin) > wlcf->action_max) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: action from inspector \"%V\" dropped: "
                          "longer than waf_action_max", &insp->name);
            continue;
        }

        if (to.len != 0) {
            dst = ngx_http_waf_inspector_find(wmcf, &to);

            if (dst == NULL) {
                ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                              "waf: action from inspector \"%V\" dropped: "
                              "unknown addressee \"%*s\"", &insp->name,
                              ngx_http_waf_shown(shown, &to), shown);
                continue;
            }

            action.to = (ngx_uint_t)
                        (dst - (ngx_http_waf_inspector_t *)
                               wmcf->inspectors.elts);

            if (!wlcf->dead_action_warned
                && !ngx_http_waf_do_control(action.verb)
                && !ngx_http_waf_action_deliverable(wlcf, action.to,
                                                    ctx->phase, wave))
            {
                wlcf->dead_action_warned = 1;

                ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                              "waf: action from inspector \"%V\" to \"%V\" "
                              "has no receiver on this route: addressee is "
                              "not asked after the sender (reported once)",
                              &insp->name, &to);
            }
        }

        if (reply->actions == NULL) {
            reply->actions = ngx_array_create(ctx->request->pool, 2,
                                              sizeof(ngx_http_waf_action_t));
            if (reply->actions == NULL) {
                return NGX_ERROR;
            }
        }

        slot = ngx_array_push(reply->actions);
        if (slot == NULL) {
            return NGX_ERROR;
        }

        *slot = action;
    }
}


static ngx_int_t
ngx_http_waf_reply_object_spec(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ovr_part_t *spec, ngx_uint_t obj, ngx_str_t *err)
{
    ngx_int_t   rc, n;
    ngx_str_t   key, value;
    ngx_uint_t  bit = NGX_HTTP_WAF_OBJ_BIT(obj);

    if (ngx_http_waf_jp_object(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    spec->named |= bit;

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(jp, &key);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "set", 3) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (value.len == 3 && ngx_strncmp(value.data, "off", 3) == 0) {
                spec->off |= bit;

            } else if (!(value.len == 2
                         && ngx_strncmp(value.data, "on", 2) == 0))
            {
                ngx_http_waf_reply_reject(err, "object set must be on or off");
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "limit", 5) == 0) {
            if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                return NGX_ERROR;
            }

            if (n < 0 || n > NGX_HTTP_WAF_ACTION_LIMIT_MAX) {
                ngx_http_waf_reply_reject(err, "object limit is out of range");
            }

            if (n != 0) {
                spec->limit[obj]  = (size_t) n;
                spec->has_limit  |= bit;
            }

            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "source", 6) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (value.len == 5 && ngx_strncmp(value.data, "store", 5) == 0) {
                spec->source[obj] = NGX_HTTP_WAF_SOURCE_STORE;

            } else if (value.len == 8
                       && ngx_strncmp(value.data, "original", 8) == 0)
            {
                spec->source[obj] = NGX_HTTP_WAF_SOURCE_ORIGINAL;

            } else {
                ngx_http_waf_reply_reject(err,
                                          "object source must be store or original");
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


static ngx_uint_t
ngx_http_waf_counter_clean(ngx_str_t *s)
{
    size_t  i;
    u_char  c;

    if (s->len == 0 || s->len > NGX_HTTP_WAF_ACTION_CNT_MAX) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        c = s->data[i];

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9'))
        {
            continue;
        }

        if (i > 0 && (c == '.' || c == '_' || c == '-')) {
            continue;
        }

        return 0;
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_code_clean(ngx_str_t *s)
{
    size_t  i;

    if (s->len == 0 || s->len > NGX_HTTP_WAF_ACTION_CODE_MAX) {
        return 0;
    }

    if (s->data[0] < 'A' || s->data[0] > 'Z') {
        return 0;
    }

    for (i = 1; i < s->len; i++) {
        if ((s->data[i] >= 'A' && s->data[i] <= 'Z')
            || (s->data[i] >= '0' && s->data[i] <= '9')
            || s->data[i] == '_')
        {
            continue;
        }

        return 0;
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_marker_clean(ngx_str_t *s)
{
    if (s->len == 0
        || !ngx_http_waf_text_clean(s, NGX_HTTP_WAF_ACTION_MARKER_MAX))
    {
        return 0;
    }

    if (s->data[0] == ' ' || s->data[s->len - 1] == ' ') {
        return 0;
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_apply_allowed(ngx_uint_t verb, ngx_uint_t axis)
{
    switch (verb) {

    case NGX_HTTP_WAF_DO_REAUTH:
        return axis == NGX_HTTP_WAF_APPLY_SESSION;

    case NGX_HTTP_WAF_DO_NOTE:
        return axis <= NGX_HTTP_WAF_APPLY_SESSION;

    case NGX_HTTP_WAF_DO_ACTIVE:
    case NGX_HTTP_WAF_DO_PASSIVE:
    case NGX_HTTP_WAF_DO_OFF:
    case NGX_HTTP_WAF_DO_VOTE:
        return axis == NGX_HTTP_WAF_APPLY_REQUEST
               || axis == NGX_HTTP_WAF_APPLY_CONN;

    case NGX_HTTP_WAF_DO_AUDIT:
    case NGX_HTTP_WAF_DO_ARCHIVE:
        return axis == NGX_HTTP_WAF_APPLY_REQUEST
               || axis == NGX_HTTP_WAF_APPLY_RESPONSE;

    default:
        return axis == NGX_HTTP_WAF_APPLY_REQUEST;
    }
}


static ngx_int_t
ngx_http_waf_reply_cookies(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    ngx_str_t                  key, value;
    ngx_int_t                  rc, n;
    ngx_uint_t                 b, allowed;
    ngx_http_waf_cookie_t     *ck, cookie;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ngx_http_waf_jp_array(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_element(jp);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_waf_jp_object(jp) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memzero(&cookie, sizeof(ngx_http_waf_cookie_t));

        for ( ;; ) {
            rc = ngx_http_waf_jp_member(jp, &key);

            if (rc == NGX_DONE) {
                break;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "name", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &cookie.name) != NGX_OK
                    || !ngx_http_waf_token_clean(&cookie.name))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 5 && ngx_strncmp(key.data, "value", 5) == 0) {
                if (ngx_http_waf_jp_string(jp, &cookie.value) != NGX_OK
                    || !ngx_http_waf_cookie_value_clean(&cookie.value))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "path", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &cookie.path) != NGX_OK
                    || !ngx_http_waf_cookie_path_clean(&cookie.path))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 6 && ngx_strncmp(key.data, "domain", 6) == 0) {
                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 7 && ngx_strncmp(key.data, "max_age", 7) == 0) {
                if (ngx_http_waf_jp_int(jp, &n) != NGX_OK || n < 0) {
                    return NGX_ERROR;
                }

                cookie.max_age     = (time_t) n;
                cookie.max_age_set = 1;
                continue;
            }

            if ((key.len == 9 && ngx_strncmp(key.data, "http_only", 9) == 0)
                || (key.len == 6 && ngx_strncmp(key.data, "secure", 6) == 0))
            {
                if (ngx_http_waf_jp_bool(jp, &b) != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 9 && ngx_strncmp(key.data, "same_site", 9) == 0) {
                ngx_uint_t  unused;

                if (ngx_http_waf_jp_string(jp, &value) != NGX_OK
                    || ngx_http_waf_keyword(ngx_http_waf_same_site, &value,
                                            &unused) != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        allowed = cookie.name.len != 0;

        if (!allowed) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" sent a cookie without a name",
                          &insp->name);
            continue;
        }

        if (reply->cookies == NULL) {
            reply->cookies = ngx_array_create(ctx->request->pool, 2,
                                              sizeof(ngx_http_waf_cookie_t));
            if (reply->cookies == NULL) {
                return NGX_ERROR;
            }
        }

        ck = ngx_array_push(reply->cookies);
        if (ck == NULL) {
            return NGX_ERROR;
        }

        *ck = cookie;
    }
}


static ngx_int_t
ngx_http_waf_reply_sessions(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    u_char                    *buf, *p;
    ngx_str_t                  key, item;
    ngx_int_t                  rc, n;
    ngx_uint_t                 b;
    ngx_http_waf_session_t    *slot, sess;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ngx_http_waf_jp_array(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        rc = ngx_http_waf_jp_element(jp);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (reply->sessions != NULL
            && reply->sessions->nelts >= NGX_HTTP_WAF_SESSIONS_REPLY_MAX)
        {
            return NGX_ERROR;
        }

        if (ngx_http_waf_jp_object(jp) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memzero(&sess, sizeof(ngx_http_waf_session_t));

        for ( ;; ) {
            rc = ngx_http_waf_jp_member(jp, &key);

            if (rc == NGX_DONE) {
                break;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            if (key.len == 6 && ngx_strncmp(key.data, "source", 6) == 0) {
                if (ngx_http_waf_jp_string(jp, &sess.source) != NGX_OK
                    || !ngx_http_waf_text_clean(&sess.source,
                                                NGX_HTTP_WAF_SESSION_SOURCE_MAX))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "kind", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &sess.kind) != NGX_OK
                    || !ngx_http_waf_text_clean(&sess.kind,
                                                NGX_HTTP_WAF_SESSION_KIND_MAX))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "user", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &sess.user) != NGX_OK
                    || !ngx_http_waf_text_clean(&sess.user,
                                                NGX_HTTP_WAF_SESSION_USER_MAX))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 2 && ngx_strncmp(key.data, "id", 2) == 0) {
                if (ngx_http_waf_jp_string(jp, &sess.id) != NGX_OK
                    || !ngx_http_waf_text_clean(&sess.id,
                                                NGX_HTTP_WAF_SESSION_ID_MAX))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 8 && ngx_strncmp(key.data, "verified", 8) == 0) {
                if (ngx_http_waf_jp_bool(jp, &b) != NGX_OK) {
                    return NGX_ERROR;
                }

                sess.verified = b ? 1 : 0;
                continue;
            }

            if (key.len == 6 && ngx_strncmp(key.data, "issued", 6) == 0) {
                if (ngx_http_waf_jp_int(jp, &n) != NGX_OK || n < 0) {
                    return NGX_ERROR;
                }

                sess.issued = (time_t) n;
                continue;
            }

            if (key.len == 7 && ngx_strncmp(key.data, "expires", 7) == 0) {
                if (ngx_http_waf_jp_int(jp, &n) != NGX_OK || n < 0) {
                    return NGX_ERROR;
                }

                sess.expires = (time_t) n;
                continue;
            }

            if (key.len == 6 && ngx_strncmp(key.data, "groups", 6) == 0) {
                if (ngx_http_waf_jp_array(jp) != NGX_OK) {
                    return NGX_ERROR;
                }

                buf = ngx_pnalloc(ctx->request->pool,
                                  NGX_HTTP_WAF_SESSION_GROUPS_MAX);
                if (buf == NULL) {
                    return NGX_ERROR;
                }

                p = buf;

                for ( ;; ) {
                    rc = ngx_http_waf_jp_element(jp);

                    if (rc == NGX_DONE) {
                        break;
                    }

                    if (rc != NGX_OK
                        || ngx_http_waf_jp_string(jp, &item) != NGX_OK
                        || !ngx_http_waf_text_clean(&item,
                                                NGX_HTTP_WAF_SESSION_GROUPS_MAX)
                        || item.len == 0
                        || ngx_strlchr(item.data, item.data + item.len, ',')
                           != NULL)
                    {
                        return NGX_ERROR;
                    }

                    if ((size_t) (buf + NGX_HTTP_WAF_SESSION_GROUPS_MAX - p)
                        < item.len + (p != buf ? 1 : 0))
                    {
                        return NGX_ERROR;
                    }

                    if (p != buf) {
                        *p++ = ',';
                    }

                    p = ngx_cpymem(p, item.data, item.len);
                }

                sess.groups.data = buf;
                sess.groups.len  = p - buf;
                continue;
            }

            if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (sess.source.len == 0 || sess.kind.len == 0) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" sent a session without "
                          "source or kind", &insp->name);
            continue;
        }

        if (reply->sessions == NULL) {
            reply->sessions = ngx_array_create(ctx->request->pool, 2,
                                               sizeof(ngx_http_waf_session_t));
            if (reply->sessions == NULL) {
                return NGX_ERROR;
            }
        }

        slot = ngx_array_push(reply->sessions);
        if (slot == NULL) {
            return NGX_ERROR;
        }

        *slot = sess;
    }
}


static ngx_uint_t
ngx_http_waf_text_clean(ngx_str_t *s, size_t max)
{
    size_t  i;

    if (s->len > max) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        if (s->data[i] < 0x20 || s->data[i] == 0x7f) {
            return 0;
        }
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_cookie_value_clean(ngx_str_t *s)
{
    u_char  c, *p, *last;

    p    = s->data;
    last = s->data + s->len;

    if (s->len >= 2 && p[0] == '"' && last[-1] == '"') {
        p++;
        last--;
    }

    /* RFC 6265 cookie-octet */

    for ( /* void */ ; p < last; p++) {
        c = *p;

        if (c <= 0x20 || c >= 0x7f || c == '"' || c == ',' || c == ';'
            || c == '\\')
        {
            return 0;
        }
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_cookie_path_clean(ngx_str_t *s)
{
    u_char  c;
    size_t  i;

    for (i = 0; i < s->len; i++) {
        c = s->data[i];

        if (c < 0x20 || c >= 0x7f || c == ';') {
            return 0;
        }
    }

    return 1;
}


static size_t
ngx_http_waf_shown(u_char *buf, ngx_str_t *s)
{
    u_char               c, *p;
    size_t               i;
    static const u_char  hex[] = "0123456789abcdef";

    p = buf;

    for (i = 0; i < s->len && i < NGX_HTTP_WAF_SHOWN_MAX; i++) {
        c = s->data[i];

        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') {
            *p++ = c;
            continue;
        }

        *p++ = '\\';
        *p++ = 'x';
        *p++ = hex[c >> 4];
        *p++ = hex[c & 0xf];
    }

    if (i < s->len) {
        p = ngx_cpymem(p, "...", 3);
    }

    return (size_t) (p - buf);
}


static ngx_uint_t
ngx_http_waf_header_forbidden(ngx_str_t *name)
{
    ngx_uint_t  i;

    for (i = 0; ngx_http_waf_forbidden_headers[i].len != 0; i++) {
        if (ngx_http_waf_forbidden_headers[i].len == name->len
            && ngx_strncasecmp(ngx_http_waf_forbidden_headers[i].data,
                               name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_waf_token_clean(ngx_str_t *s)
{
    u_char  c;
    size_t  i;

    if (s->len == 0 || s->len > 128) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        c = s->data[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~')
        {
            continue;
        }

        return 0;
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_subject_clean(ngx_str_t *s)
{
    u_char  c;
    size_t  i;

    if (s->len == 0 || s->len > NGX_HTTP_WAF_DENY_SUBJECT_MAX) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        c = s->data[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == ':' || c == '/')
        {
            continue;
        }

        return 0;
    }

    return 1;
}


static ngx_uint_t
ngx_http_waf_url_clean(ngx_str_t *url, size_t max)
{
    u_char  c;
    size_t  i;

    if (url->len == 0 || url->len > max) {
        return 0;
    }

    for (i = 0; i < url->len; i++) {
        c = url->data[i];

        if (c <= ' ' || c >= 0x7f) {
            return 0;
        }

        if (c == '\\' || c == '"' || c == '<' || c == '>' || c == '^'
            || c == '`' || c == '{' || c == '}' || c == '|')
        {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_http_waf_url_parse(ngx_str_t *url, ngx_http_waf_url_t *parsed)
{
    u_char     *p, *last, *host, *colon;
    ngx_int_t   n;

    ngx_memzero(parsed, sizeof(ngx_http_waf_url_t));

    if (url->len == 0) {
        return NGX_ERROR;
    }

    p    = url->data;
    last = url->data + url->len;

    if (p[0] == '/') {
        if (url->len > 1 && p[1] == '/') {
            return NGX_ERROR;
        }

        parsed->path = *url;
        return NGX_OK;
    }

    if (url->len > 7 && ngx_strncasecmp(p, (u_char *) "http://", 7) == 0) {
        ngx_str_set(&parsed->scheme, "http");
        parsed->port = 80;
        p += 7;

    } else if (url->len > 8
               && ngx_strncasecmp(p, (u_char *) "https://", 8) == 0)
    {
        ngx_str_set(&parsed->scheme, "https");
        parsed->port = 443;
        p += 8;

    } else {
        return NGX_ERROR;
    }

    host = p;

    while (p < last && *p != '/' && *p != '?' && *p != '#') {
        if (*p == '@') {
            return NGX_ERROR;
        }

        p++;
    }

    parsed->host.data = host;
    parsed->host.len  = (size_t) (p - host);

    if (parsed->host.len == 0 || host[0] == '[') {
        return NGX_ERROR;
    }

    colon = ngx_strlchr(parsed->host.data,
                        parsed->host.data + parsed->host.len, ':');

    if (colon != NULL) {
        n = ngx_atoi(colon + 1, (size_t) (parsed->host.data + parsed->host.len
                                          - colon - 1));
        if (n < 1 || n > 65535) {
            return NGX_ERROR;
        }

        parsed->port     = (in_port_t) n;
        parsed->host.len = (size_t) (colon - parsed->host.data);

        if (parsed->host.len == 0) {
            return NGX_ERROR;
        }
    }

    if (p == last) {
        ngx_str_set(&parsed->path, "/");
        return NGX_OK;
    }

    parsed->path.data = p;
    parsed->path.len  = (size_t) (last - p);

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_redirect_allowed(ngx_http_waf_loc_conf_t *wlcf, ngx_str_t *url)
{
    ngx_uint_t                      i;
    ngx_http_waf_url_t              u;
    ngx_http_waf_redirect_allow_t  *allow;

    if (wlcf->redirect_allow == NULL) {
        return 0;
    }

    if (ngx_http_waf_url_parse(url, &u) != NGX_OK) {
        return 0;
    }

    allow = wlcf->redirect_allow->elts;

    for (i = 0; i < wlcf->redirect_allow->nelts; i++) {
        if ((allow[i].scheme.len == 0) != (u.scheme.len == 0)) {
            continue;
        }

        if (u.scheme.len != 0
            && (allow[i].scheme.len != u.scheme.len
                || ngx_memcmp(allow[i].scheme.data, u.scheme.data,
                              u.scheme.len) != 0
                || allow[i].port != u.port
                || !ngx_http_waf_host_matches(&allow[i], &u.host)))
        {
            continue;
        }

        if (ngx_http_waf_prefix_bounded(&u.path, &allow[i].path)) {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_waf_host_matches(ngx_http_waf_redirect_allow_t *allow, ngx_str_t *host)
{
    size_t  n;

    if (!allow->wildcard) {
        return allow->host.len == host->len
               && ngx_strncasecmp(allow->host.data, host->data,
                                  host->len) == 0;
    }

    if (host->len <= allow->host.len + 1) {
        return 0;
    }

    n = host->len - allow->host.len;

    return host->data[n - 1] == '.'
           && ngx_strncasecmp(allow->host.data, host->data + n,
                              allow->host.len) == 0;
}


static ngx_uint_t
ngx_http_waf_prefix_bounded(ngx_str_t *s, ngx_str_t *prefix)
{
    u_char  c;

    if (prefix->len == 0) {
        return 1;
    }

    if (s->len < prefix->len
        || ngx_memcmp(s->data, prefix->data, prefix->len) != 0)
    {
        return 0;
    }

    if (s->len == prefix->len) {
        return 1;
    }

    if (prefix->data[prefix->len - 1] == '/') {
        return 1;
    }

    c = s->data[prefix->len];

    return c == '/' || c == '?' || c == '#';
}


static ngx_int_t
ngx_http_waf_keyword(ngx_http_waf_kw_t *kw, ngx_str_t *name, ngx_uint_t *value)
{
    ngx_uint_t  i;

    for (i = 0; kw[i].name.len != 0; i++) {
        if (kw[i].name.len == name->len
            && ngx_memcmp(kw[i].name.data, name->data, name->len) == 0)
        {
            *value = kw[i].value;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}
