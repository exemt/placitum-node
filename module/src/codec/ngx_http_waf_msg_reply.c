/*
 * Разбор ответа инспектора и проверка ограничений канала.
 *
 * Инспектор, который может подставить произвольный заголовок, cookie и код
 * ответа, -- это удалённый редактор вашего трафика. Поэтому здесь проверяется
 * всё, а не то, что кажется опасным: версия схемы, эхо rid, собственное имя,
 * диапазон счёта, белые списки заголовков и cookie, безусловные запреты, CR, LF
 * и NUL в значениях, код редиректа и его цель по waf_redirect_allow.
 *
 * Различие между двумя видами отказа существенно и зафиксировано
 * спецификацией: нарушение в служебных полях отбраковывает ответ целиком, а
 * недопустимое переопределение выбрасывается по одному и не задевает вердикт --
 * переопределения валидны или невалидны сами по себе.
 */

#include "codec/ngx_http_waf_codec.h"
#include "body/ngx_http_waf_body.h"


typedef struct {
    ngx_str_t   name;
    ngx_uint_t  value;
} ngx_http_waf_kw_t;


typedef struct {
    ngx_str_t   scheme;      /* пусто у локального пути                     */
    ngx_str_t   host;
    ngx_str_t   path;        /* вместе с query: сверяется только префикс    */
    in_port_t   port;
} ngx_http_waf_url_t;


static ngx_int_t ngx_http_waf_reply_continue(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static ngx_int_t ngx_http_waf_reply_reason(ngx_http_waf_jp_t *jp,
    ngx_http_waf_reply_t *reply);
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
static ngx_uint_t ngx_http_waf_content_type_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_code_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_counter_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_marker_clean(ngx_str_t *s);
static ngx_uint_t ngx_http_waf_apply_allowed(ngx_uint_t verb, ngx_uint_t axis);
static ngx_int_t ngx_http_waf_reply_cookies(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_int_t ngx_http_waf_reply_sessions(ngx_http_waf_jp_t *jp,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index, ngx_http_waf_reply_t *reply);
static ngx_uint_t ngx_http_waf_text_clean(ngx_str_t *s, size_t max);

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
    /*
     * "Проверить не смог". Не вердикт: счёт, переопределения и просьбы при нём
     * не читаются -- инспектор, не выполнивший работу, не вправе и просить.
     */
    { ngx_string("error"),    NGX_HTTP_WAF_V_ERROR    },
    { ngx_null_string, 0 }
};


/*
 * Словарь глаголов. Короткий намеренно: глагол называет намерение, понятное
 * всему контуру, а частности живут в code, которого модуль не толкует.
 * Глагола "заблокировать" здесь нет и не будет -- блокировка это вердикт.
 */
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
    { ngx_string("ban"),       NGX_HTTP_WAF_DO_BAN       },
    { ngx_null_string, 0 }
};


/*
 * Оси. Выбор настоящий только у note; у остальных глаголов ось одна, но пишется
 * всё равно -- одна форма записи, одна проверка здесь, одна строка в аудите.
 */
static ngx_http_waf_kw_t  ngx_http_waf_apply_axes[] = {
    { ngx_string("request"), NGX_HTTP_WAF_APPLY_REQUEST },
    { ngx_string("ip"),      NGX_HTTP_WAF_APPLY_IP      },
    { ngx_string("asn"),     NGX_HTTP_WAF_APPLY_ASN     },
    { ngx_string("session"), NGX_HTTP_WAF_APPLY_SESSION },
    { ngx_string("conn"),    NGX_HTTP_WAF_APPLY_CONN    },
    { ngx_string("response"), NGX_HTTP_WAF_APPLY_RESPONSE },
    { ngx_null_string, 0 }
};


/*
 * Фаза вызова адресата у управляющих глаголов (поле phase). Значение -- маска
 * слотов, как у первого слова waf_inspect: "frame" -- обе стороны кадров.
 * Без поля режим ставится всем вызовам имени.
 */
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


/*
 * Запрещены независимо от белого списка. Каждый из этих заголовков меняет не
 * содержание запроса, а правила его разбора или доверия к нему: подменённый
 * Host уводит запрос на другой маршрут, Content-Length рассинхронизирует тело,
 * Authorization подменяет личность.
*/

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
    ngx_str_t                  key, value;
    ngx_int_t                  rc, n;
    ngx_uint_t                 verdict, version;
    ngx_http_waf_jp_t          jp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (payload->len > wmcf->reply_max) {
        ngx_http_waf_reply_reject(err, "reply exceeds waf_reply_max");
    }

    ngx_memzero(reply, sizeof(ngx_http_waf_reply_t));

    reply->verdict = NGX_HTTP_WAF_V_ALLOW;
    reply->score   = -1;

    version = 0;
    verdict = NGX_CONF_UNSET_UINT;              /* признак "не задан" */

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

            /*
             * Эхо rid проверяется, хотя слот уже найден по subject инбокса:
             * иначе инспектор, отвечающий по чужому reply-to, попадает в чужой
             * запрос.
             */
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

            /*
             * Ответ за другого. Имя обязано совпадать с тем инспектором, чей
             * reply-to использован: скомпрометированный инспектор не должен
             * уметь выносить вердикт от чужого имени.
             */
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
            /*
             * Разбор недоверенного числа. Дробное, отрицательное и выходящее за
             * границу отбраковывают ответ целиком: подрезка до границы
             * превращает ошибку инспектора в тихо неверное решение, а
             * отрицательный вклад ломает монотонность суммы, на которой держится
             * замыкание фазы.
             */
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
            if (ngx_http_waf_reply_reason(&jp, reply) != NGX_OK) {
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
            if (ngx_http_waf_reply_continue(&jp, ctx, index) != NGX_OK) {
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

        /*
         * "cache": false -- вердикт не по содержимому, по хешу кадра его не
         * повторять (waf_frame_cache). true и отсутствие поля равнозначны.
         */
        if (key.len == 5 && ngx_strncmp(key.data, "cache", 5) == 0) {
            ngx_uint_t  cacheable;

            if (ngx_http_waf_jp_bool(&jp, &cacheable) != NGX_OK) {
                ngx_http_waf_reply_reject(err, "field cache is not a boolean");
            }

            reply->no_cache = cacheable ? 0 : 1;
            continue;
        }

        /* audit и любое незнакомое поле: правило совместимости требует пропуска */
        if (ngx_http_waf_jp_skip(&jp) != NGX_OK) {
            ngx_http_waf_reply_reject(err, "malformed JSON");
        }
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

    reply->verdict = verdict;

    /*
     * error -- признанное отсутствие вердикта, и всё, что при вердикте
     * применяется, при нём выбрасывается: счёт, переопределения заголовков и
     * строки запроса, подмена, cookie, продолжение, просьбы соседям. Инспектор,
     * не выполнивший работу, не вправе и просить о чужой; а половина ответа,
     * применённая от сломанного сервиса, -- это худший из возможных исходов.
     *
     * Причина остаётся: по ней разбирают, что именно сломалось, и без неё
     * событие неотличимо от молчания в журнале. Секция sessions тоже: она
     * ничего не применяет, а "кого видели" остаётся правдой и при сбое.
     */
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

        /*
         * Просьбы соседям выбрасываются, а глаголы, которые исполняет модуль,
         * остаются: "не вправе просить о чужой работе" -- это про соседа, а о
         * себе сказать можно. Сброшенный на входе инспектор именно это и
         * делает: просит забанить клиента (ban) и не звать его до конца
         * транзакции (off). Очки -- исключение: вклада в сумму у ответа без
         * вердикта нет, и score снят выше вместе со счётом.
         */
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
        /* при остальных вердиктах поле score не имеет смысла и игнорируется */
        reply->score = 0;
    }

    if (verdict == NGX_HTTP_WAF_V_REDIRECT) {
        /*
         * Куда вести клиента, решает сервис, а не модуль, поэтому адрес
         * приезжает с провода. Здесь он проходит три проверки: есть ли он
         * вообще, годится ли в значение заголовка и разрешён ли маршрутом.
         * Ответ, не прошедший любую из них, отбрасывается целиком: применить
         * половину редиректа нельзя, а домыслить цель за сервис -- значит
         * вернуть модулю решение, которое у него забрали.
         */
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
        /*
         * Код в вердикте deny не принимается вовсе: он живёт в каталоге
         * waf_deny_response, и это единственный способ гарантировать, что
         * "отказ" не окажется двухсотым. Цель редиректа при остальных
         * вердиктах бессмысленна и до применения не доходит.
         */
        reply->status = 0;
        ngx_str_null(&reply->redirect_url);
    }

    reply->received = 1;

    return NGX_OK;
}


/*
 * Продолжение: личный subject экземпляра и срок, на который он обещает держать
 * состояние.
 *
 * Липкость -- оптимизация, поэтому непригодная секция не отвергает вердикт: без
 * продолжения следующая фаза просто пойдёт в групповой subject. Отвергается
 * только сломанный JSON -- он означает, что дальше по сообщению разбирать
 * нечего.
 *
 * Subject приезжает с провода, а публиковать по нему будет модуль, поэтому он
 * проверяется, а не принимается: обязан лежать внутри пространства имён самого
 * инспектора. Иначе скомпрометированный инспектор перенаправлял бы запросы
 * маршрута к чужому -- то же самое, что отвечать от чужого имени.
 */
static ngx_int_t
ngx_http_waf_reply_continue(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_int_t                  rc, n, ttl;
    ngx_str_t                  key, subject;
    ngx_uint_t                 i;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    ngx_str_null(&subject);
    ttl = 0;

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

        if (key.len == 7 && ngx_strncmp(key.data, "subject", 7) == 0) {
            if (ngx_http_waf_jp_string(jp, &subject) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "ttl_ms", 6) == 0) {
            if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                return NGX_ERROR;
            }

            ttl = n;
            continue;
        }

        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /*
     * Ключ в ответе не нужен и не читается: его назвал сам модуль в вопросе.
     * Здесь остаётся адрес экземпляра -- единственное, чего модуль знать не
     * может, -- и срок, на который экземпляр его обещает.
     */
    if (subject.len == 0 || ttl <= 0) {
        return NGX_OK;                 /* нечего запоминать */
    }

    /*
     * Пространство имён инспектора: его собственный subject плюс точка. Так
     * личный адрес экземпляра остаётся адресом этого же инспектора, и реестр
     * присутствия по-прежнему описывает то, что модуль спрашивает.
     */
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    insp = &insp[index];

    if (subject.len <= insp->subject.len
        || ngx_memcmp(subject.data, insp->subject.data, insp->subject.len) != 0
        || subject.data[insp->subject.len] != '.')
    {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" offered continuation on \"%V\", "
                      "outside its own subject; ignored",
                      &insp->name, &subject);

        return NGX_OK;
    }

    /* Адрес публикации: пробелы и подстановки NATS в нём недопустимы. */
    for (i = 0; i < subject.len; i++) {
        if (subject.data[i] <= ' ' || subject.data[i] == '*'
            || subject.data[i] == '>' || subject.data[i] == 0x7f)
        {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspector \"%V\" offered a continuation "
                          "subject that is not publishable; ignored",
                          &insp->name);

            return NGX_OK;
        }
    }

    if (ngx_http_waf_resume_keep(ctx, index, &subject,
                                 (ngx_msec_t) ttl) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_reply_reason(ngx_http_waf_jp_t *jp, ngx_http_waf_reply_t *reply)
{
    ngx_str_t  key, value;
    ngx_int_t  rc, n;

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

            /*
             * Код клиенту не печатается, но попадает в лог ошибок и в аудит, а
             * туда управляющие символы пускать нельзя ровно по той же причине,
             * по какой их нельзя пускать в заголовок.
             */
            if (!ngx_http_waf_value_clean(&value)) {
                return NGX_ERROR;
            }

            reply->reason_code = value;
            continue;
        }

        /*
         * class -- какого рода отсутствие вердикта. Слово одно, "overload":
         * инспектор сбросил запрос на входе. Всё прочее -- обычный error, и
         * незнакомое слово не роняет ответ: класс выбирает политику, а не
         * вердикт, и разъехавшаяся версия инспектора не должна ронять волну.
         */
        if (key.len == 5 && ngx_strncmp(key.data, "class", 5) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (value.len == 8 && ngx_strncmp(value.data, "overload", 8) == 0) {
                reply->overload = 1;
            }

            continue;
        }

        /*
         * scope / subject / retry -- публичная сторона причины: страница
         * отказа печатает их клиенту (docs/deny-pages.md). Поэтому проверка
         * здесь строже, чем у кода, а непрошедшее поле не роняет ответ, а
         * молча остаётся пустым: инспектор, ошибшийся в объяснении, не должен
         * отменять сам вердикт.
         */
        if (key.len == 5 && ngx_strncmp(key.data, "scope", 5) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            reply->reason_scope = ngx_http_waf_deny_scope_parse(&value);
            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "subject", 7) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ngx_http_waf_subject_clean(&value)) {
                reply->reason_subject = value;
            }

            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "retry", 5) == 0) {
            if (ngx_http_waf_jp_int(jp, &n) != NGX_OK) {
                return NGX_ERROR;
            }

            if (n > 0 && n <= NGX_HTTP_WAF_DENY_RETRY_MAX) {
                reply->reason_retry = (ngx_uint_t) n;
            }

            continue;
        }

        /*
         * text и rule сюда больше не приезжают. Подробности находки -- дело
         * события kind=inspector: там у них есть форма, потребитель и место в
         * инциденте, а здесь они только раздували ответ на горячем пути.
         * Присланные -- пропускаются как любое незнакомое поле.
         */
        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }
}


/*
 * Секция response относится только к вердикту deny: код и страницу отдаёт сам
 * nginx, поэтому с провода принимается одно символьное имя записи каталога.
 * Присланный здесь status в расчёт не идёт и попадает в общий пропуск
 * незнакомых полей -- код отказа берётся из waf_deny_response, иначе "отказ"
 * рано или поздно окажется двухсотым.
 */
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


/*
 * Секция redirect: цель и код. Сама строка проверяется в вызывающем -- там
 * известен маршрут, а значит и список разрешённых целей.
 */
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

            /*
             * Белый список, а не диапазон: 200 в редиректе превращает его в
             * тихий пропуск, а 301 остаётся в кэше браузера навсегда, и
             * снявший челлендж клиент туда уже не вернётся.
             */
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


/*
 * Секция args: правка строки запроса по именам, как заголовки -- set меняет
 * значение имени или дописывает пару, unset снимает все пары имени. Байты
 * едут в проводном виде: модуль строку запроса не декодирует, а режет по '&'
 * и сравнивает имена побайтно, поэтому '&' в имени или значении и '=' в
 * имени -- битая форма, и весь ответ отбраковывается, как у headers.
 *
 * Права на правку в реестре нет (mutate= снят): секция принимается от любой
 * декларации, а принимает ли её маршрут -- waf_send request args. Вне фазы
 * запроса секция выбрасывается со строкой INFO: к ответу строка уже ушла
 * апстриму, у кадра её нет.
 */
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

    /*
     * Строка запроса есть только у запроса: к ответу она уже ушла апстриму,
     * у кадра её нет. Секция принимается по форме и выбрасывается со
     * строкой INFO -- инспектор ничего не нарушил, ему просто нечего править.
     */
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


/*
 * Имя или значение пары строки запроса в проводном виде: без управляющих
 * символов, пробела, '&' и '#'; у имени ещё без '=' и не пустое. Остальное --
 * дело инспектора: percent-encoding модуль не проверяет и не навязывает,
 * строка уйдёт апстриму байт в байт.
 */
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

                /*
                 * Отброшено одно переопределение, вердикт остаётся в силе.
                 * Уровень warn, а не info: попытка подставить запрещённый
                 * заголовок -- это либо ошибка инспектора, либо его
                 * компрометация, и то и другое должно быть видно.
                 *
                 * Причина называется своим словом: "нельзя" и "прислал CRLF в
                 * значении" исправляются по-разному, и разбираться, что именно
                 * не понравилось, по одному сообщению на четыре проверки
                 * пришлось бы гаданием.
                 */
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

                if (!ngx_http_waf_token_clean(&name)
                    || ngx_http_waf_header_forbidden(&name))
                {
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


/*
 * Секция rewrite: подмена тела ответа объектом обменника. Байт тела в реплае нет
 * -- только ключ, и ключ обязан лежать внутри пространства этого же запроса
 * (<node>:<rid>:rsp:*): реплай не может назвать чужой объект и отдать одному
 * клиенту ответ другого.
 *
 * Секция валидна или нет целиком: применить подмену наполовину нельзя, а
 * молча принять битую -- значит отдать оригинал там, где инспектор просил
 * маску. Поэтому нарушение формы отбраковывает весь ответ, как у headers.
 *
 * Секция принимается от любой декларации (mutate= снят). Принятая подмена
 * становится актуальной версией объекта фазы: следующая волна получает её
 * локатор и наращивает ключ на нём, а получателю уходит последнее звено
 * цепочки. Две секции на одной волне -- не конкурс, а исключение класса body:
 * инспекторы волны видели один объект, и выбор любого из двух молча терял бы
 * чужую правку (ngx_http_waf_wave_settle).
 */
static ngx_int_t
ngx_http_waf_reply_rewrite(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply)
{
    ngx_str_t                  key, value, *group;
    ngx_int_t                  rc, n;
    ngx_uint_t                 i;
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

        if (key.len == 4 && ngx_strncmp(key.data, "body", 4) == 0) {

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

                if (key.len == 3 && ngx_strncmp(key.data, "key", 3) == 0) {
                    if (ngx_http_waf_jp_string(jp, &value) != NGX_OK) {
                        return NGX_ERROR;
                    }

                    /*
                     * Чужой или кривой ключ -- единственная причина отказа,
                     * которую по одному слову "malformed" не разобрать:
                     * ключ называется целиком, вместе с тем, что ждали.
                     */
                    if (!ngx_http_waf_rewrite_key_clean(
                            ctx, NGX_HTTP_WAF_OBJ_BODY, &value))
                    {
                        ngx_log_error(NGX_LOG_WARN,
                                      ctx->request->connection->log, 0,
                                      "waf: inspector \"%V\" sent rewrite "
                                      "key \"%V\", expected %V:%*s:%V:<suffix>",
                                      &insp->name, &value, &wmcf->node_id,
                                      (size_t) NGX_HTTP_WAF_RID_HEX_LEN,
                                      ctx->rid_hex,
                                      ngx_http_waf_body_phase_tag_name(
                                          ctx->phase));
                        return NGX_ERROR;
                    }

                    reply->rewrite_key = value;
                    continue;
                }

                if (key.len == 4 && ngx_strncmp(key.data, "size", 4) == 0) {
                    if (ngx_http_waf_jp_int(jp, &n) != NGX_OK || n < 0) {
                        return NGX_ERROR;
                    }

                    reply->rewrite_size = (off_t) n;
                    reply->rewrite_body = 1;
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

        /*
         * Тип содержимого объекта -- для тела отказа фазы запроса: там
         * заголовков ответа апстрима нет, и брать тип больше неоткуда. На
         * фазе ответа тип правит секция headers, и это поле не читается.
         */
        if (key.len == 12 && ngx_strncmp(key.data, "content_type", 12) == 0) {
            if (ngx_http_waf_jp_string(jp, &value) != NGX_OK
                || !ngx_http_waf_content_type_clean(&value))
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

        /*
         * on_error и response с провода больше не принимаются: несостоявшаяся
         * подмена -- это сбой обработки запроса, и распоряжается им политика
         * фазы (waf_exception … body), а не инспектор. Ключи пропускаются
         * молча, как всякое незнакомое поле.
         */
        if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* body без ключа или без размера применить нельзя */
    if (reply->rewrite_body
        && (reply->rewrite_key.len == 0 || reply->rewrite_size < 0))
    {
        return NGX_ERROR;
    }

    if (reply->rewrite_key.len != 0 && !reply->rewrite_body) {
        return NGX_ERROR;
    }

    /*
     * Фаза ответа -- подмена удержанного тела; фаза запроса -- тело своего
     * отказа (применяется только у deny, см. ngx_http_waf_form_fetch()).
     * Обе фазы секцию принимают, поэтому проверки фазы здесь больше нет.
     */
    reply->rewrite_has = 1;

    return NGX_OK;
}


/*
 * Тип содержимого из реплая: одна строка заголовка без управляющих символов,
 * не длиннее 128 байт. Это ровно то, что пойдёт в Content-Type ответа, и
 * перевод строки внутри был бы инъекцией заголовка.
 */
static ngx_uint_t
ngx_http_waf_content_type_clean(ngx_str_t *s)
{
    u_char  c;
    size_t  i;

    if (s->len == 0 || s->len > 128) {
        return 0;
    }

    for (i = 0; i < s->len; i++) {
        c = s->data[i];

        if (c < 0x20 || c == 0x7f) {
            return 0;
        }
    }

    return 1;
}


/* Имя группы модификаторов: алфавит имён профилей контроллера. */
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


/*
 * Ключ rewrite-объекта: строго <node>:<rid>:rsp:<суффикс>. Префикс сверяется
 * с node и rid текущего запроса -- это единственное, что мешает реплаю
 * адресовать объект чужого запроса. Суффикс -- короткий токен: имя выбирает
 * инспектор, но читают его глазами при разборе инцидентов.
 */
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

    /*
     * Производная от объекта, который инспектор получил: <ключ>:<суффикс>.
     * Каждая волна берёт свой слот и свой rid, а объект разместился на
     * первой из них -- инспектор второй волны строит ключ от локатора,
     * который получил, и по текущему rid он бы не сошёлся. Ключ объекта --
     * та же гарантия принадлежности: он выдан этому запросу и только ему.
     * У тела локатор свой, у строки запроса -- метаобъект.
     *
     * После принятой подмены полученный локатор -- уже её объект, и ключ
     * следующей версии наращивается на нём (":rsp:out:mask"). Длину цепочки
     * держит REWRITE_MAX_DEPTH, иначе росла бы сама строка ключа.
     */
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

        /*
         * Ключ тела плюс ":hdr" -- это ключ заголовков того же запроса, и
         * подъём "подмены" прочитал бы и удалил их раньше, чем придёт агент.
         * Суффиксы своих объектов модуль инспектору не отдаёт.
         */
        suffix.data = key->data + loc->key.len + 1;
        suffix.len  = key->len - loc->key.len - 1;

        return !ngx_http_waf_obj_suffix_reserved(&suffix);
    }

    /*
     * Тег фазы -- текущей: объект фазы запроса лежит под req, ответа -- под
     * rsp. Реплай фазы запроса с ключом rsp адресовал бы то, чего ещё нет.
     */
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


/*
 * Секция actions: о чём инспектор просит соседей. Модуль просьбы не исполняет,
 * но форму проверяет, и проверяет строго -- принять действие, которого не
 * понимает ни модуль, ни получатель, значит потратить бюджет запроса на мусор.
 *
 * Ответ целиком отбраковывают: незнакомый глагол, повод не в алфавите, число
 * вне границ, threshold без delta. Одно действие отбрасывают со строкой в лог:
 * незнакомый адресат -- доставить его некому ни на одном маршруте, и молчание
 * скрывало бы опечатку в конфигурации инспектора; и превышение
 * waf_action_max -- предела того маршрута, на котором пишется сообщение.
 */
static ngx_int_t
ngx_http_waf_reply_actions(ngx_http_waf_jp_t *jp, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_http_waf_reply_t *reply, ngx_str_t *err)
{
    u_char                    *begin;
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

    /*
     * Волна отправителя: адресат обязан стоять позже неё, иначе просьбу некому
     * поднять. Отвечающий инспектор на маршруте есть по построению, но искать
     * его строку всё равно надо -- волна живёт на вызове, а не в реестре.
     */
    self = ngx_http_waf_binding_find(wlcf, index, ctx->phase);
    wave = self != NULL ? self->wave : 0;

    /*
     * Канал выключен на маршруте. Секция проверяется на форму и выбрасывается
     * целиком: ответ остаётся годным -- переписываться здесь просто не с кем.
     */
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

        /* Длина действия на проводе: от первого байта объекта до последнего. */
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

            /*
             * Фаза вызова адресата: режим ставят вызову, а не процессу, и у
             * имени, стоящего на двух фазах, вызова два. Без поля -- обоим.
             */
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

                /*
                 * Единственное поле канала со знаком: проценты коэффициента
                 * к измерению получателя, плюс -- строже, минус -- скидка.
                 * Модуль проверяет только форму (целое в +-1000); осмысленный
                 * диапазон -100..+900 держат загрузчики обеих сторон. Выход за
                 * границу отбраковывает ответ, а не подрезается: подрезка
                 * превращает ошибку инспектора в тихо неверное решение.
                 */
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

                /*
                 * Знак разрешён формой, как у delta: направление изменения
                 * счётчика получателя выбирает отправитель, а цена доступа --
                 * правило с именем отправителя в профиле получателя. Модуль
                 * семантику не толкует.
                 */
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

                /*
                 * Имя шкалы получателя: селектор поверх правила приёма. Модуль
                 * в декларации не заглядывает -- имя проверяется на форму
                 * (алфавит имён счётчиков), а есть ли такая шкала и дают ли
                 * отправителю её трогать, решает правило получателя.
                 */
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

                /*
                 * Имя группы модификаторов получателя: тот же алфавит, что у
                 * корзины. Есть ли такая группа, знает только получатель.
                 */
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

                /*
                 * Метка события: строку пишет оператор, и модуль её не
                 * толкует -- проверяет только форму. Длиннее предела, с
                 * управляющим символом или с крайним пробелом -- отбраковка
                 * ответа: подрезать чужую метку значило бы разложить один
                 * маркер по двум в журнале.
                 */
                if (!ngx_http_waf_marker_clean(&action.marker)) {
                    ngx_http_waf_reply_reject(err, "action marker is not a marker");
                }

                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "list", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &action.list) != NGX_OK) {
                    return NGX_ERROR;
                }

                /*
                 * Имя набора: форма проверяется здесь, существование -- на
                 * исполнении. Токен, как имя инспектора: набора с
                 * управляющим символом в имени не бывает, и такое поле --
                 * признак битого отправителя, а не опечатки оператора.
                 */
                if (!ngx_http_waf_token_clean(&action.list)) {
                    ngx_http_waf_reply_reject(err, "action list is not a name");
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

                /*
                 * Срок в архиве секундами, как ttl= у waf_archive; ноль --
                 * хранить вечно. Только у archive с set on -- проверяется
                 * ниже, когда глагол известен.
                 */
                if (n < 0 || n > NGX_HTTP_WAF_ACTION_TTL_MAX) {
                    ngx_http_waf_reply_reject(err, "action ttl is out of range");
                }

                action.spec.ttl     = (time_t) n;
                action.spec.has_ttl = 1;
                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "when", 4) == 0) {

                /*
                 * Исходы, на которых просьба архива исполняется, -- те же два
                 * слова, что у when= директивы, и тем же множеством: массив,
                 * а не строка с запятыми, потому что множество на проводе
                 * пишется массивом. Пустой -- не "любой", а просьба ни о чём:
                 * "любой" пишется отсутствием ключа, как и у директивы.
                 */
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

            /*
             * Объекты просьбы записи -- как строки директив, объект за
             * объектом: headers / args / body со своей стороной, размером и
             * источником.
             */
            if (ngx_http_waf_obj_find(&key, &obj) == NGX_OK) {
                if (ngx_http_waf_reply_object_spec(jp, &action.spec, obj, err)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            /*
             * from, phase и wave с провода не принимаются: их проставляет
             * модуль. Разбираются и выбрасываются -- по той же причине, по
             * какой выбрасывается domain у cookie.
             *
             * Здесь же выбрасывается force: канал рекомендательный, и что
             * делать с просьбой -- решает получатель. Отправитель, который
             * ещё его печатает, не должен из-за этого получать отказ на весь
             * ответ, поэтому ключ не отвергается, а игнорируется.
             */
            if (ngx_http_waf_jp_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (!verb_set) {
            ngx_http_waf_reply_reject(err, "action without a verb");
        }

        /*
         * Ось обязательна даже там, где она одна: умолчание означало бы, что
         * "про кого это сказано" иногда написано, а иногда угадано, -- а
         * угадывать субъекта по поводу и предлагалось не делать.
         */
        if (!apply_set) {
            ngx_http_waf_reply_reject(err, "action without an axis");
        }

        if (!ngx_http_waf_apply_allowed(action.verb, action.apply)) {
            ngx_http_waf_reply_reject(err, "action axis does not fit the verb");
        }

        /*
         * Дельта -- единственное, чем сосед двигает чужую политику числом.
         * threshold без неё не действие, а полуфраза, и молча пропустить её
         * значит оставить получателя гадать, на сколько двигать.
         */
        if (action.verb == NGX_HTTP_WAF_DO_THRESHOLD && !action.has_delta) {
            ngx_http_waf_reply_reject(err, "threshold without delta");
        }

        /*
         * Параметр принадлежит своему глаголу: counter -- только у note.
         * «threshold с counter» -- не половина смысла, а признак того, что
         * отправитель имел в виду не то, что написал.
         */
        if (action.counter.len != 0
            && action.verb != NGX_HTTP_WAF_DO_NOTE)
        {
            ngx_http_waf_reply_reject(err, "counter is only for note");
        }

        /* Метка -- только у mark, и у mark она обязательна. */
        if (action.marker.len != 0 && !ngx_http_waf_do_mark(action.verb)) {
            ngx_http_waf_reply_reject(err, "marker is only for mark");
        }

        /*
         * Набор -- только у ban, и у ban он обязателен: "забань" без имени
         * набора не просьба, а полуфраза, и угадывать набор за отправителя
         * модуль не станет. Адресат -- набор самого маршрута, поэтому
         * названный сосед здесь битая форма, как у mark и score.
         */
        if (ngx_http_waf_do_ban(action.verb)) {
            if (action.list.len == 0) {
                ngx_http_waf_reply_reject(err, "ban without a list");
            }

            if (to.len != 0) {
                ngx_http_waf_reply_reject(err, "ban takes no addressee");
            }

        } else if (action.list.len != 0) {
            ngx_http_waf_reply_reject(err, "list is only for ban");
        }

        /*
         * Группа и сторона -- только у mutate, и у mutate -- обе: что именно
         * переключить и куда, называет отправитель, как корзину у note.
         * Правило приёма получателя решает, дают ли ему это, а не что.
         */
        if (action.verb == NGX_HTTP_WAF_DO_MUTATE) {
            if (action.group.len == 0 || action.set == NGX_HTTP_WAF_SET_NONE) {
                ngx_http_waf_reply_reject(err, "mutate without group or set");
            }

        } else if (action.group.len != 0) {
            ngx_http_waf_reply_reject(err, "group is only for mutate");

        } else if (ngx_http_waf_do_audit(action.verb)) {

            /*
             * Глаголы записи: сторона обязательна -- "переопределить" без
             * "как" не просьба, а полуфраза. Объекты, предел и источник --
             * только при set on: выключенным журналу и архиву нечего
             * назначать; срок -- только у archive. Объекты у audit без
             * предела и источника ничего не меняют -- отбраковка, а не
             * молчаливый пропуск.
             */
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

            /* У записи ответа строки запроса нет: назвать её -- битая форма. */
            if (action.apply == NGX_HTTP_WAF_APPLY_RESPONSE
                && (action.spec.named & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS)))
            {
                ngx_http_waf_reply_reject(err,
                    "args has no meaning for the response record");
            }

            /*
             * Адресат -- запись самого маршрута: to здесь не "всем", а
             * отсутствие поля. Названный адресат -- признак строки профиля
             * не про то: соседу нечего исполнять.
             */
            if (to.len != 0) {
                ngx_http_waf_reply_reject(err, "audit verb takes no addressee");
            }

        } else if (ngx_http_waf_do_mark(action.verb)) {

            /*
             * Маркер: адресат тот же, что у глаголов записи -- запись самого
             * маршрута, -- поэтому названный сосед здесь битая форма. Метка
             * обязательна: "пометить" без метки не просьба, а полуфраза.
             * Стороны, срока и объектов у маркера не бывает: он ничего не
             * переопределяет, а добавляет строку в множество.
             */
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

        } else if (ngx_http_waf_do_ban(action.verb)) {

            /*
             * Срок записи: тот же ttl секундами, что у archive. Не прислан --
             * возьмётся срок самого набора; нет и там -- запись не состоится,
             * и это видно в логе края.
             */
            if (action.set != NGX_HTTP_WAF_SET_NONE || action.spec.has_when
                || action.spec.named != 0)
            {
                ngx_http_waf_reply_reject(err,
                    "set, when and objects are only for audit and archive");
            }

        } else if (ngx_http_waf_do_score(action.verb)) {

            /*
             * Очки: адресат -- сумма самого маршрута, названный сосед здесь
             * та же битая форма, что у записи. value обязателен и со знаком:
             * ноль на проводе не отличим от отсутствия, а "ничего не менять"
             * пишется не строкой, а её отсутствием. Форма value общая с note
             * (+-1000), осмысленная граница у очков своя -- вклад одного
             * инспектора не больше сотни, и просьба сверх неё -- опечатка, а
             * не щедрость.
             */
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

        /*
         * Управляющий глагол без адресата -- не просьба, а бессмыслица:
         * режим ставят одному вызову, не "всем". Ось conn -- до конца
         * соединения -- есть только у кадров; на запросе она не "примерно
         * request", а признак строки профиля не той фазы.
         */
        if (ngx_http_waf_do_control(action.verb)) {
            if (to.len == 0) {
                ngx_http_waf_reply_reject(err, "control verb without to");
            }

            if (action.apply == NGX_HTTP_WAF_APPLY_CONN
                && !ngx_http_waf_phase_is_frame(ctx->phase))
            {
                ngx_http_waf_reply_reject(err, "apply conn outside frames");
            }

            /*
             * До конца соединения живут только кадры: режим вызову фазы
             * запроса или ответа с осью conn ставить уже некому.
             */
            if (action.apply == NGX_HTTP_WAF_APPLY_CONN
                && action.to_phases != 0
                && (action.to_phases & NGX_HTTP_WAF_PH_FRAME) == 0)
            {
                ngx_http_waf_reply_reject(err,
                                          "apply conn needs phase frame");
            }

        } else if (action.to_phases != 0) {
            /* Фаза вызова -- адрес управляющего глагола, у прочих её нет. */
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
                              "unknown addressee \"%V\"", &insp->name, &to);
                continue;
            }

            action.to = (ngx_uint_t)
                        (dst - (ngx_http_waf_inspector_t *)
                               wmcf->inspectors.elts);

            /*
             * Имя нашлось в реестре, но на этом маршруте адресата не
             * спрашивают -- либо его тут нет вовсе, либо он стоит не позже
             * отправителя. Просьба остаётся в ответе и в аудите (её высказали,
             * и это факт), но поднять её будет некому.
             *
             * Молчать здесь нельзя. Это ровно тот класс ошибки, где обе
             * стороны выглядят исправными: отправитель пишет "asks", получатель
             * -- штатный вердикт без prior, и расхождение видно только сверкой
             * двух логов по одному rid. Типовая причина -- второе имя процесса:
             * профиль писали от имени процесса ("captcha"), а на маршруте стоит
             * объявление со своим профилем ("captcha-guard"), и адрес на
             * проводе -- это имя объявления.
             */
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


/*
 * Объект просьбы записи: {"set": on|off, "limit": байты, "source":
 * store|original}, каждое необязательно. Как у строки директивы: названный
 * объект входит в набор, set off его исключает, размер и источник -- свои.
 * Незнакомый ключ внутри выбрасывается, как везде в действии.
 */
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

            /* Байты; ноль -- весь объект, как без поля. */
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


/*
 * Имя шкалы у note: алфавит имён счётчиков получателя. Требование той же
 * строгости, что у повода: имя попадает в аудит и в правило профиля
 * получателя, произвольные байты туда пускать нельзя.
 */
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


/*
 * Повод действия: тот же алфавит, что у reason.code. Требование жёсткое,
 * потому что повод попадает в аудит и в правило профиля получателя, а туда
 * произвольные байты пускать нельзя.
 */
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


/*
 * Допустима ли ось при этом глаголе. Матрица зашита здесь, а не в конфигурации:
 * "challenge про ASN" -- не политика маршрута, а бессмыслица, и принимать её,
 * чтобы отбросить у получателя, значит разносить одну проверку по двум местам.
 */
/*
 * Метка события (do: mark). Свободная строка -- в отличие от повода и имени
 * корзины, у неё нет алфавита: её читает человек в журнале, а не загрузчик
 * профиля. Проверяется ровно то, что мешало бы ей быть строкой журнала:
 * пустота, длина, управляющие символы и крайние пробелы (маркер с хвостовым
 * пробелом и без него -- две разные строки в группировке, и это была бы не
 * метка оператора, а его опечатка, размноженная колонкой).
 */
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
        /* Управление: до конца транзакции либо, на кадрах, соединения. */
        return axis == NGX_HTTP_WAF_APPLY_REQUEST
               || axis == NGX_HTTP_WAF_APPLY_CONN;

    case NGX_HTTP_WAF_DO_BAN:
        /*
         * Бан -- про адрес клиента: другого субъекта у модуля и нет. Ни
         * системы, ни сессии он не знает -- это к инспекторам, у которых
         * есть кодер и зеркало списка сессий.
         */
        return axis == NGX_HTTP_WAF_APPLY_IP;

    case NGX_HTTP_WAF_DO_AUDIT:
    case NGX_HTTP_WAF_DO_ARCHIVE:
        /*
         * Запись: ось называет, какую -- запроса (на кадрах -- этого
         * кадра) либо ответа этой транзакции. Оси соединения нет: запись
         * у каждого кадра своя, а просьба с рукопожатия и так действует на
         * все кадры соединения.
         */
        return axis == NGX_HTTP_WAF_APPLY_REQUEST
               || axis == NGX_HTTP_WAF_APPLY_RESPONSE;

    default:
        /*
         * challenge, threshold, skip, mutate -- только про этот запрос; mark
         * -- тоже: помечают событие, а не адрес, и оси субъекта у метки нет.
         */
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
                    || !ngx_http_waf_value_clean(&cookie.value))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 4 && ngx_strncmp(key.data, "path", 4) == 0) {
                if (ngx_http_waf_jp_string(jp, &cookie.path) != NGX_OK
                    || !ngx_http_waf_value_clean(&cookie.path))
                {
                    return NGX_ERROR;
                }

                continue;
            }

            if (key.len == 6 && ngx_strncmp(key.data, "domain", 6) == 0) {
                /*
                 * Домен с провода не принимается: он ограничен текущим
                 * server_name, иначе инспектор ставит cookie на чужой домен.
                 * Поле разбирается и выбрасывается.
                 */
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

            /*
             * secure, http_only и same_site разбираются и выбрасываются по той
             * же причине, что и domain: их форсирует waf_cookie_defaults
             * независимо от присланного. Разбор всё равно строгий -- мусор в
             * значении отбраковывает ответ целиком, а не остаётся незамеченным
             * потому, что поле всё равно не применяется.
             */
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


/*
 * Секция sessions: массив объектов {source, kind, user, id, verified, issued,
 * expires, groups}. Обязательны source и kind -- без них запись не про что;
 * user и id могут быть пустыми: сессия есть, а кто это, отправитель не знает.
 *
 * Разбор строгий: строка длиннее своего предела, управляющий символ в ней,
 * пятая запись -- порча реплая целиком, а не молчаливая подрезка. Запись без
 * source или kind, как cookie без имени, -- WARN и пропуск: это ошибка одной
 * записи, а не формы.
 *
 * Модуль ничего из этого не применяет: секция едет в аудит, и только туда.
 */
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
                /*
                 * Массив имён -- одной строкой через запятую: в аудите группы
                 * читают, а не фильтруют, и массив строк в записи стоил бы
                 * ещё одного массива в структуре ради того же текста.
                 */
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
                        || item.len == 0)
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


/*
 * Текст записи sessions: не длиннее предела и без управляющих символов. Это
 * не token -- логин бывает с пробелом и точкой, id -- с двоеточием, -- но и
 * не произвольные байты: строка уезжает в журнал, и перевод строки в ней
 * ломал бы чтение записи глазами.
 */
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


/*
 * Имя заголовка, cookie или записи каталога: только token-символы RFC 9110 без
 * пробелов и разделителей. Строгость здесь дешевле разбирательств: все
 * осмысленные имена в неё укладываются.
 */
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


/*
 * Название закрытого объекта для страницы отказа: адрес, сеть в CIDR, код
 * страны, номер автономной системы.
 *
 * Строже token_clean на две вещи -- разрешены ':' и '/', без которых не
 * записать ни IPv6, ни префикс, -- и строже её же по длине: строка уезжает в
 * чужой браузер, и всё, что длиннее короткого названия, там не объяснение, а
 * место для чужого текста. Экранирование SSI это не отменяет: одного барьера
 * на пути к клиенту мало.
 */
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


/*
 * Пригодность строки в значение заголовка Location. Управляющие символы, пробел
 * и всё вне печатного ASCII отбраковываются целиком, а не экранируются: CR и LF
 * здесь означают расщепление ответа, а остальному в URI место только в
 * процентной записи.
 *
 * Обратный слеш запрещён отдельной проверкой -- браузеры нормализуют его в
 * прямой, парсеры обычно нет, и ровно на этом расхождении строится обход
 * проверки хоста.
 */
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


/*
 * Разбор присланной цели на схему, хост, порт и путь. Задача не в полноте
 * поддержки RFC 3986, а в том, чтобы модуль и браузер поняли строку одинаково:
 * любая форма, где они могут разойтись, отбраковывается.
 */
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
        /*
         * "//host/path" -- абсолютный адрес без схемы: браузер уйдёт на чужой
         * хост, а проверка префикса пути этого не заметит. Форма отбраковывается,
         * а не разбирается: разрешить её значит просить администратора помнить
         * про этот случай при каждом шаблоне.
         */
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
        /* Ни путь, ни http(s): "javascript:", "data:" и прочее сюда же. */
        return NGX_ERROR;
    }

    host = p;

    while (p < last && *p != '/' && *p != '?' && *p != '#') {
        /*
         * userinfo: "https://good.example.com@evil.example.com/" ведёт на
         * evil, а невнимательная проверка видит good. Запрещено целиком.
         */
        if (*p == '@') {
            return NGX_ERROR;
        }

        p++;
    }

    parsed->host.data = host;
    parsed->host.len  = (size_t) (p - host);

    /* IPv6-литерал не поддерживается: у цели челленджа есть имя. */
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

    /*
     * Список не задан -- редиректы на маршруте запрещены. Обратное значило бы,
     * что маршрут, про который никто ничего не сказал, разрешает уводить своих
     * клиентов куда угодно.
     */
    if (wlcf->redirect_allow == NULL) {
        return 0;
    }

    if (ngx_http_waf_url_parse(url, &u) != NGX_OK) {
        return 0;
    }

    allow = wlcf->redirect_allow->elts;

    for (i = 0; i < wlcf->redirect_allow->nelts; i++) {

        /* Локальный шаблон и абсолютный адрес друг другу не подходят. */
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

    /*
     * "*.example.com" покрывает поддомены, но не сам example.com: апекс обычно
     * отдаёт приложение, и разрешать редирект туда заодно с сервисом челленджа
     * никто не просил.
     */
    if (host->len <= allow->host.len + 1) {
        return 0;
    }

    n = host->len - allow->host.len;

    return host->data[n - 1] == '.'
           && ngx_strncasecmp(allow->host.data, host->data + n,
                              allow->host.len) == 0;
}


/*
 * Префикс пути с проверкой границы: шаблон /waf/captcha разрешает /waf/captcha
 * и /waf/captcha?rd=..., но не /waf/captchaevil, который обрабатывает уже
 * что-то другое. Пустой префикс разрешает на хосте всё.
 */
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

    /* Шаблон, кончающийся слешем, границу задал сам. */
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
