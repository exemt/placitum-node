/*
 * Разбор директив: объявление инспекторов, наборы и режимы, каталоги ответов,
 * пороги счёта, адреса шины.
 *
 * Всё, что можно проверить при загрузке конфигурации, проверяется здесь и даёт
 * ошибку с именем файла и номером строки. Ошибка конфигурации, обнаруженная на
 * живом трафике, стоит дороже любой проверки.
 */

#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "local/ngx_http_waf_local.h"


typedef struct {
    ngx_str_t   name;
    ngx_uint_t  value;
} ngx_http_waf_kw_t;


static ngx_int_t ngx_http_waf_kw_lookup(ngx_http_waf_kw_t *kw,
    ngx_str_t *value, ngx_uint_t *out);
static ngx_int_t ngx_http_waf_opt_keyword(ngx_conf_t *cf,
    ngx_http_waf_kw_t *kw, ngx_str_t *value, ngx_uint_t *out);
static ngx_int_t ngx_http_waf_opt_flags(ngx_conf_t *cf, ngx_http_waf_kw_t *kw,
    ngx_str_t *value, ngx_uint_t *out);
static ngx_int_t ngx_http_waf_opt_fraction(ngx_conf_t *cf, ngx_str_t *value,
    ngx_uint_t scale, ngx_uint_t max, ngx_uint_t *out);
static char *ngx_http_waf_preview_names(ngx_conf_t *cf, ngx_str_t *directive,
    ngx_str_t *spec, ngx_array_t **list, u_char all);
static char *ngx_http_waf_preview_set(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t phases);
static char *ngx_http_waf_preview_spec(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t obj, ngx_str_t *spec);
static void ngx_http_waf_capture_none(ngx_http_waf_shoot_conf_t *sh);
static ngx_int_t ngx_http_waf_obj_list(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t kind);
static void ngx_http_waf_archive_reset(ngx_http_waf_shoot_conf_t *sh);
static char *ngx_http_waf_archive_apply(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t mask, ngx_uint_t off,
    ngx_uint_t when, time_t ttl, size_t *limits);
static char *ngx_http_waf_archive_reload(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh);
static char *ngx_http_waf_preview_reload(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh);
static ngx_int_t ngx_http_waf_obj_bit(ngx_str_t *name, ngx_uint_t *bit);
static ngx_uint_t ngx_http_waf_bit_obj(ngx_uint_t bit);
static ngx_int_t ngx_http_waf_arg_phase(ngx_conf_t *cf, ngx_str_t *arg,
    ngx_uint_t *phases);
static char *ngx_http_waf_no_reload_in(ngx_conf_t *cf, ngx_str_t *dir,
    ngx_uint_t phases);
static char *ngx_http_waf_obj_in_phase(ngx_conf_t *cf, ngx_str_t *dir,
    ngx_uint_t phases, ngx_uint_t obj);


/*
 * Фаза первым словом. Значение -- маска слотов, а не индекс: у кадров
 * направление живёт в том же слове, и строка "frame" настраивает оба слота
 * сразу. Разворачивать её в две строки пришлось бы каждому вызывающему.
 */
static ngx_http_waf_kw_t  ngx_http_waf_kw_phase[] = {
    { ngx_string("request"),
      NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)   },
    { ngx_string("response"),
      NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_RESPONSE)  },
    { ngx_string("frame"),     NGX_HTTP_WAF_PH_FRAME    },
    { ngx_string("frame:c2s"),
      NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_FRAME_C2S) },
    { ngx_string("frame:s2c"),
      NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_FRAME_S2C) },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_hold[] = {
    { ngx_string("gate"),    NGX_HTTP_WAF_HOLD_GATE    },
    { ngx_string("monitor"), NGX_HTTP_WAF_HOLD_MONITOR },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_resume[] = {
    { ngx_string("off"),     NGX_HTTP_WAF_RESUME_OFF     },
    { ngx_string("prefer"),  NGX_HTTP_WAF_RESUME_PREFER  },
    { ngx_string("require"), NGX_HTTP_WAF_RESUME_REQUIRE },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_deny_mode[] = {
    { ngx_string("fast"),          NGX_HTTP_WAF_DENY_FAST          },
    { ngx_string("deterministic"), NGX_HTTP_WAF_DENY_DETERMINISTIC },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_mode[] = {
    { ngx_string("active"),  NGX_HTTP_WAF_MODE_ACTIVE  },
    { ngx_string("passive"), NGX_HTTP_WAF_MODE_PASSIVE },
    { ngx_string("off"),     NGX_HTTP_WAF_MODE_OFF     },
    { ngx_string("vote"),    NGX_HTTP_WAF_MODE_VOTE    },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_http_waf_profile_default = ngx_string("default");


static ngx_http_waf_kw_t  ngx_http_waf_kw_deny_type[] = {
    { ngx_string("http"),      NGX_HTTP_WAF_DENY_TYPE_HTTP      },
    { ngx_string("grpc"),      NGX_HTTP_WAF_DENY_TYPE_GRPC      },
    { ngx_string("websocket"), NGX_HTTP_WAF_DENY_TYPE_WEBSOCKET },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_flag[] = {
    { ngx_string("on"),  1 },
    { ngx_string("off"), 0 },
    { ngx_null_string, 0 }
};



static ngx_http_waf_kw_t  ngx_http_waf_kw_same_site[] = {
    { ngx_string("Lax"),    NGX_HTTP_WAF_SAMESITE_LAX    },
    { ngx_string("Strict"), NGX_HTTP_WAF_SAMESITE_STRICT },
    { ngx_string("None"),   NGX_HTTP_WAF_SAMESITE_NONE   },
    { ngx_null_string, 0 }
};


/*
 * Объекты обменника по именам. Одни и те же слова в обеих осях -- в waf_capture
 * маршрута и в needs= инспектора: это одно и то же множество, названное с двух
 * сторон, и разные словари для него только сбивали бы с толку.
 */
static ngx_http_waf_kw_t  ngx_http_waf_kw_obj[] = {
    { ngx_string("headers"),
      NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS) },
    { ngx_string("args"), NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS) },
    { ngx_string("body"), NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY) },
    { ngx_null_string, 0 }
};


/*
 * На каких исходах объект сохраняется. Множество, а не одно слово: "все
 * отказы" -- это deny и redirect вместе, и требовать ради этого двух директив
 * незачем.
 */
static ngx_http_waf_kw_t  ngx_http_waf_kw_archive_when[] = {
    { ngx_string("allow"), 1u << NGX_HTTP_WAF_V_ALLOW },
    { ngx_string("deny"),  1u << NGX_HTTP_WAF_V_DENY  },
    { ngx_null_string, 0 }
};


/*
 * Откуда отдать объект получателю (waf_send). Два слова, как у источника
 * записи и архива: оригинал модуля либо версия инспектора из обменника.
 */
static ngx_http_waf_kw_t  ngx_http_waf_kw_send[] = {
    { ngx_string("original"), NGX_HTTP_WAF_SEND_ORIGINAL },
    { ngx_string("store"),    NGX_HTTP_WAF_SEND_STORE    },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_body_policy[] = {
    { ngx_string("pass"),  NGX_HTTP_WAF_POLICY_PASS  },
    { ngx_string("block"), NGX_HTTP_WAF_POLICY_BLOCK },
    { ngx_string("trim"),  NGX_HTTP_WAF_POLICY_TRIM  },
    { ngx_null_string, 0 }
};


/*
 * Имя вида объекта по его индексу. Слова живут в ngx_http_waf_kw_obj и берутся
 * оттуда же: третий список тех же трёх строк однажды разошёлся бы с первыми
 * двумя.
 */
ngx_str_t *
ngx_http_waf_obj_name(ngx_uint_t obj)
{
    ngx_http_waf_kw_t  *kw;

    for (kw = ngx_http_waf_kw_obj; kw->name.len != 0; kw++) {
        if (kw->value == NGX_HTTP_WAF_OBJ_BIT(obj)) {
            return &kw->name;
        }
    }

    return &ngx_http_waf_kw_obj[0].name;
}


static void
ngx_http_waf_capture_none(ngx_http_waf_shoot_conf_t *sh)
{
    ngx_uint_t  i;

    sh->capture         = 0;
    sh->capture_set     = 0;
    sh->capture_cleared = 1;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        sh->capture_limit[i] = NGX_CONF_UNSET_SIZE;
    }

    ngx_memzero(sh->lists[NGX_HTTP_WAF_LIST_CAPTURE],
                sizeof(sh->lists[NGX_HTTP_WAF_LIST_CAPTURE]));
}


static void
ngx_http_waf_archive_reset(ngx_http_waf_shoot_conf_t *sh)
{
    ngx_uint_t  i;

    sh->archive_reload  = 0;
    sh->archive_set     = 0;
    sh->archive_cleared = 1;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        sh->archive_when[i]         = NGX_CONF_UNSET_UINT;
        sh->archive_ttl[i]          = NGX_CONF_UNSET;
        sh->archive_limit[i]        = NGX_CONF_UNSET_SIZE;
        sh->archive_reload_limit[i] = NGX_CONF_UNSET_SIZE;
    }

    ngx_memzero(sh->lists[NGX_HTTP_WAF_LIST_ARCHIVE],
                sizeof(sh->lists[NGX_HTTP_WAF_LIST_ARCHIVE]));
}


/*
 * Отдельная строка списков: waf_* <фаза> headers|args allow=|mask=|deny=.
 * NGX_DECLINED -- это не она, разбирает набор. Список выбирается тройкой
 * "вид, объект, ось" в каждом слоте фазы: строка frame настраивает оба
 * направления, и списки у них свои.
 */
static ngx_int_t
ngx_http_waf_obj_list(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t kind)
{
    ngx_str_t    *args, name, value;
    ngx_uint_t    bit, obj, ph, phases, axis;
    ngx_array_t **list;
    u_char        all;
    const char   *who;

    args = cf->args->elts;

    if (cf->args->nelts != 4
        || ngx_http_waf_split(&args[2], &name, &value) == NGX_OK
        || ngx_http_waf_obj_bit(&args[2], &bit) != NGX_OK
        || ngx_http_waf_split(&args[3], &name, &value) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (name.len == 5 && ngx_strncmp(name.data, "allow", 5) == 0) {
        if (kind == NGX_HTTP_WAF_LIST_CAPTURE) {
            return NGX_DECLINED;
        }

        axis = NGX_HTTP_WAF_AXIS_ALLOW;
        all  = '*';

    } else if (name.len == 4 && ngx_strncmp(name.data, "mask", 4) == 0) {
        axis = NGX_HTTP_WAF_AXIS_MASK;
        all  = 'n';

    } else if (name.len == 4 && ngx_strncmp(name.data, "deny", 4) == 0) {
        axis = NGX_HTTP_WAF_AXIS_DENY;
        all  = 'n';

    } else {
        return NGX_DECLINED;
    }

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Списки снимка живут вместе со снимком: где фаза снимает, там же она их и
     * применяет. Словарь объектов у фазы свой: у кадра ни заголовков, ни
     * строки запроса, и список на них отвергается словарём, а не отдельной
     * заглушкой.
     */
    obj = ngx_http_waf_bit_obj(bit);

    if (ngx_http_waf_obj_in_phase(cf, &args[0], phases, obj) != NGX_CONF_OK) {
        return NGX_ERROR;
    }
    who = (kind == NGX_HTTP_WAF_LIST_CAPTURE) ? "waf_capture"
        : (kind == NGX_HTTP_WAF_LIST_ARCHIVE) ? "waf_archive"
        : "waf_preview";

    if (obj == NGX_HTTP_WAF_OBJ_BODY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s body: takes no allow=, mask= or deny=; "
                           "the object is a single prefix", who);
        return NGX_ERROR;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        list = &wlcf->shoot[ph].lists[kind][obj][axis];

        if (ngx_http_waf_preview_names(cf, &args[0], &value, list, all)
            != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_obj_bit(ngx_str_t *name, ngx_uint_t *bit)
{
    ngx_http_waf_kw_t  *kw;

    for (kw = ngx_http_waf_kw_obj; kw->name.len != 0; kw++) {
        if (kw->name.len == name->len
            && ngx_strncmp(kw->name.data, name->data, name->len) == 0)
        {
            *bit = kw->value;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


static ngx_uint_t
ngx_http_waf_bit_obj(ngx_uint_t bit)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        if (NGX_HTTP_WAF_OBJ_BIT(i) == bit) {
            return i;
        }
    }

    return NGX_HTTP_WAF_OBJ_COUNT;
}


static ngx_int_t
ngx_http_waf_arg_phase(ngx_conf_t *cf, ngx_str_t *arg, ngx_uint_t *phases)
{
    ngx_http_waf_kw_t  *kw;

    for (kw = ngx_http_waf_kw_phase; kw->name.len != 0; kw++) {
        if (kw->name.len == arg->len
            && ngx_strncmp(kw->name.data, arg->data, arg->len) == 0)
        {
            *phases = kw->value;

            return NGX_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: write request, response, frame, frame:c2s or "
                       "frame:s2c as the first word; \"%V\" is not a phase",
                       arg);
    return NGX_ERROR;
}


/*
 * reload на фазе кадров. reload -- это про запрос: он до-кладывает оригинал
 * за маской и укороченным снимком. У кадра ни того, ни другого: масок на сырой
 * нагрузке нет, а весь кадр и так лежит в буфере до вердикта. Поэтому архив и
 * превью кадра расширяются прямо своим размером (waf_archive frame body=... в
 * пределах waf_body_limit), а reload остаётся словом без работы.
 */
static char *
ngx_http_waf_no_reload_in(ngx_conf_t *cf, ngx_str_t *dir, ngx_uint_t phases)
{
    if ((phases & (NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_FRAME_C2S)
                   | NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_FRAME_S2C)))
        == 0)
    {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "%V reload: a frame has no masks and its whole payload "
                       "is buffered; size the archive or preview directly "
                       "(waf_archive frame body=..., up to waf_body_limit) "
                       "instead of reload", dir);
    return NGX_CONF_ERROR;
}


/*
 * Словарь объектов у каждой фазы свой: у ответа нет строки запроса, у кадра
 * нет ни её, ни заголовков. Третьего словаря при этом не заводим -- одно и то
 * же множество слов, суженное фазой.
 */
static char *
ngx_http_waf_obj_in_phase(ngx_conf_t *cf, ngx_str_t *dir, ngx_uint_t phases,
    ngx_uint_t obj)
{
    ngx_uint_t  ph, allowed;

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        switch (ph) {

        case NGX_HTTP_WAF_PHASE_REQUEST:
            allowed = NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
                      | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS)
                      | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY);
            break;

        case NGX_HTTP_WAF_PHASE_RESPONSE:
            allowed = NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
                      | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY);
            break;

        default:
            allowed = NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY);
            break;
        }

        if (allowed & NGX_HTTP_WAF_OBJ_BIT(obj)) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V: phase \"%V\" has no object \"%V\"", dir,
                           ngx_http_waf_phase_name(ph),
                           ngx_http_waf_obj_name(obj));
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* --- поиск по каталогам --------------------------------------------------- */

ngx_http_waf_inspector_t *
ngx_http_waf_inspector_find(ngx_http_waf_main_conf_t *wmcf, ngx_str_t *name)
{
    ngx_uint_t                 i;
    ngx_http_waf_inspector_t  *insp;

    insp = wmcf->inspectors.elts;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        if (insp[i].name.len == name->len
            && ngx_memcmp(insp[i].name.data, name->data, name->len) == 0)
        {
            return &insp[i];
        }
    }

    return NULL;
}


ngx_http_waf_deny_response_t *
ngx_http_waf_deny_response_find(ngx_http_waf_main_conf_t *wmcf,
    ngx_str_t *name)
{
    ngx_uint_t                     i;
    ngx_http_waf_deny_response_t  *dr;

    if (wmcf->deny_responses == NULL || name->len == 0) {
        return NULL;
    }

    dr = wmcf->deny_responses->elts;

    for (i = 0; i < wmcf->deny_responses->nelts; i++) {
        if (dr[i].name.len == name->len
            && ngx_memcmp(dr[i].name.data, name->data, name->len) == 0)
        {
            return &dr[i];
        }
    }

    return NULL;
}


/* --- waf_inspector -------------------------------------------------------- */

/*
 * Опции, которых на waf_inspector больше нет: снимок переехал в waf_capture,
 * конвейер -- в waf_inspect. Имя из этого списка -- ошибка с подсказкой, а не
 * "unknown option": иначе читать changelog.
 */
static ngx_str_t  ngx_http_waf_inspector_gone[] = {
    ngx_string("after"),
    ngx_string("sample"),
    ngx_string("placement"),
    ngx_string("role"),
    ngx_string("timeout"),
    ngx_string("phase"),
    ngx_string("headers"),
    ngx_string("body"),
    ngx_string("needs"),
    ngx_null_string
};


static ngx_uint_t
ngx_http_waf_inspector_option_gone(ngx_str_t *name)
{
    ngx_str_t  *gone;

    for (gone = ngx_http_waf_inspector_gone; gone->len != 0; gone++) {
        if (gone->len == name->len
            && ngx_strncmp(gone->data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


char *
ngx_http_waf_inspector(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_str_t                 *args, name, value;
    ngx_uint_t                 i, audit_set, profile_set;
    ngx_http_waf_inspector_t  *insp;

    args        = cf->args->elts;
    audit_set   = 0;
    profile_set = 0;

    if (wmcf->inspectors.nelts >= NGX_HTTP_WAF_MAX_INSPECTORS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: at most %d inspectors may be declared",
                           NGX_HTTP_WAF_MAX_INSPECTORS);
        return NGX_CONF_ERROR;
    }

    if (ngx_strlchr(args[1].data, args[1].data + args[1].len, ':') != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: inspector name \"%V\" must not contain ':'",
                           &args[1]);
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_inspector_find(wmcf, &args[1]) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: inspector \"%V\" is already declared",
                           &args[1]);
        return NGX_CONF_ERROR;
    }

    insp = ngx_array_push(&wmcf->inspectors);
    if (insp == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(insp, sizeof(ngx_http_waf_inspector_t));

    insp->name              = args[1];
    insp->index             = wmcf->inspectors.nelts - 1;
    insp->profile           = ngx_http_waf_profile_default;
    insp->breaker           = 1;
    insp->breaker_threshold = 5000;
    insp->breaker_window    = 10000;
    insp->breaker_probe     = 5000;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in waf_inspector, "
                               "expected key=value", &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 7 && ngx_strncmp(name.data, "subject", 7) == 0) {
            insp->subject = value;
            continue;
        }

        if (name.len == 7 && ngx_strncmp(name.data, "profile", 7) == 0) {

            if (!ngx_http_waf_value_clean(&value)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid profile \"%V\": control "
                                   "characters are not allowed", &value);
                return NGX_CONF_ERROR;
            }

            insp->profile = value;
            profile_set   = 1;
            continue;
        }

        /*
         * Куда публиковать подробности. Умолчание считается ниже, после
         * разбора всех опций: имя инспектора к этому моменту уже известно, а
         * порядок опций в директиве значения иметь не должен.
         */
        if (name.len == 5 && ngx_strncmp(name.data, "audit", 5) == 0) {
            audit_set = 1;

            if (value.len == 3 && ngx_strncmp(value.data, "off", 3) == 0) {
                ngx_str_null(&insp->audit_subject);

            } else {
                insp->audit_subject = value;
            }

            continue;
        }

        if (name.len == 7 && ngx_strncmp(name.data, "breaker", 7) == 0) {
            insp->breaker = (value.len == 2
                             && ngx_strncmp(value.data, "on", 2) == 0);
            continue;
        }

        /*
         * Какие поля секции vars везти этому имени. Только запоминается:
         * имена разрешаются в init_main_conf, когда все waf_var известны.
         */
        if (name.len == 4 && ngx_strncmp(name.data, "vars", 4) == 0) {
            insp->vars_spec = value;
            continue;
        }

        /*
         * mutate= снят: право подменить объект больше не выражается строкой
         * реестра, его выражает публикация новой ссылки. Ключ терпится одно
         * поколение и с любым значением -- контроллер и края раскатываются
         * порознь, и модуль, приехавший первым, не должен ронять пак на слове,
         * которое сам же перестал понимать. Следующим поколением -- в общий
         * разбор неизвестных ключей, то есть nginx -t.
         */
        if (name.len == 6 && ngx_strncmp(name.data, "mutate", 6) == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "waf: \"mutate=%V\" on inspector \"%V\" is "
                               "retired and ignored: any declaration may "
                               "publish a new version of the object",
                               &value, &insp->name);
            continue;
        }

        if (name.len == 17
            && ngx_strncmp(name.data, "breaker_threshold", 17) == 0)
        {
            if (ngx_http_waf_opt_fraction(cf, &value, 10000, 10000,
                                          &insp->breaker_threshold) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (name.len == 14 && ngx_strncmp(name.data, "breaker_window", 14) == 0) {
            insp->breaker_window = ngx_parse_time(&value, 0);
            continue;
        }

        if (name.len == 13 && ngx_strncmp(name.data, "breaker_probe", 13) == 0) {
            insp->breaker_probe = ngx_parse_time(&value, 0);
            continue;
        }

        /* Веса нет нигде: ни на реестре, ни на вызове. */
        if (name.len == 6 && ngx_strncmp(name.data, "weight", 6) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: weight= is gone; the score counts as "
                               "sent (0..100), tune waf_score_deny instead");
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_inspector_option_gone(&name)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: option \"%V\" is no longer on "
                               "waf_inspector; capture is waf_capture, "
                               "pipeline is waf_inspect", &name);
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_inspector",
                           &name);
        return NGX_CONF_ERROR;
    }

    if (insp->subject.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: inspector \"%V\" has no subject=",
                           &insp->name);
        return NGX_CONF_ERROR;
    }

    if (!profile_set) {
        insp->profile = ngx_http_waf_profile_default;
    }

    if (!audit_set) {
        u_char  *p;
        size_t   len;

        len = sizeof(NGX_HTTP_WAF_AUDIT_PREFIX) - 1 + insp->name.len;

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        insp->audit_subject.data = p;
        insp->audit_subject.len  = len;

        p = ngx_cpymem(p, NGX_HTTP_WAF_AUDIT_PREFIX,
                       sizeof(NGX_HTTP_WAF_AUDIT_PREFIX) - 1);
        ngx_memcpy(p, insp->name.data, insp->name.len);
    }

    return NGX_CONF_OK;
}


/* --- waf_inspect ---------------------------------------------------------- */

char *
ngx_http_waf_inspect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t   *wlcf = conf;
    ngx_http_waf_main_conf_t  *wmcf;

    ngx_str_t                 *args, name, value;
    ngx_int_t                  wave;
    ngx_uint_t                 i, phase, phases, wave_set;
    ngx_array_t               *list;
    ngx_http_waf_binding_t     b, *slot, *exist;
    ngx_http_waf_inspector_t  *insp;

    args = cf->args->elts;
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3
        && args[2].len == 4 && ngx_strncmp(args[2].data, "none", 4) == 0)
    {
        for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

            if (!(phases & NGX_HTTP_WAF_PH_BIT(phase))) {
                continue;
            }

            if (wlcf->inspects[phase] != NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_inspect %V none cannot mix with "
                                   "named inspectors of the same phase",
                                   &args[1]);
                return NGX_CONF_ERROR;
            }

            wlcf->inspects[phase] = ngx_array_create(cf->pool, 1,
                                              sizeof(ngx_http_waf_binding_t));
            if (wlcf->inspects[phase] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        return NGX_CONF_OK;
    }

    insp = ngx_http_waf_inspector_find(wmcf, &args[2]);
    if (insp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown inspector \"%V\"", &args[2]);
        return NGX_CONF_ERROR;
    }

    /*
     * Вызов разбирается один раз в стековую запись и только потом
     * раскладывается по слотам фазы: строка "frame" настраивает два слота, и
     * разбирать её опции дважды значило бы однажды разойтись между сторонами.
     */
    ngx_memzero(&b, sizeof(ngx_http_waf_binding_t));

    b.name    = args[2];
    b.index   = insp->index;
    b.timeout = 0;
    b.mode    = NGX_HTTP_WAF_MODE_ACTIVE;
    b.resume  = NGX_HTTP_WAF_RESUME_OFF;
    wave_set  = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        /*
         * Условие -- не опция: у него три-четыре слова, и записать его как
         * key=value значило бы завести в конфигурации второй язык внутри
         * значения.
         */
        if (args[i].len == 2 && ngx_strncmp(args[i].data, "if", 2) == 0) {

            if (ngx_http_waf_cond_parse(cf, &i, &b.conds, "waf_inspect")
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in waf_inspect, "
                               "expected key=value", &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 5 && ngx_strncmp(name.data, "phase", 5) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: phase= is gone; write the phase as the "
                               "first word (waf_inspect request %V wave=0)",
                               &b.name);
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "wave", 4) == 0) {
            wave = ngx_atoi(value.data, value.len);
            if (wave == NGX_ERROR || wave < 0
                || wave > NGX_HTTP_WAF_MAX_WAVE)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid wave \"%V\", expected 0..%d",
                                   &value, NGX_HTTP_WAF_MAX_WAVE);
                return NGX_CONF_ERROR;
            }

            b.wave   = (ngx_uint_t) wave;
            wave_set = 1;
            continue;
        }

        if (name.len == 7 && ngx_strncmp(name.data, "timeout", 7) == 0) {
            b.timeout = ngx_parse_time(&value, 0);
            if (b.timeout == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid timeout \"%V\"", &value);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        /*
         * Множителя к счёту больше нет: очки ложатся в сумму как присланы,
         * а сколько их нужно на отказ, говорит waf_score_deny. Инспектору,
         * который должен считать, а не решать, -- mode=vote.
         */
        if (name.len == 6 && ngx_strncmp(name.data, "weight", 6) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: weight= is gone; the score counts as "
                               "sent (0..100), tune waf_score_deny instead, "
                               "and for an inspector that only counts write "
                               "mode=vote");
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "mode", 4) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_mode, &value,
                                         &b.mode) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "resume", 6) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_resume, &value,
                                         &b.resume) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "keep", 4) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_flag, &value,
                                         &b.keep) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "when", 4) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: when= is gone; a call that waits to be "
                               "switched on is mode=off");
            return NGX_CONF_ERROR;
        }

        /*
         * control= снят: управляющие глаголы принимает любой вызов на
         * маршруте, и называть отправителей больше негде. Строка со старой
         * опцией -- это конфигурация, собранная контроллером прежней версии;
         * молча съесть её нельзя, оператор ждёт от неё гранта.
         */
        if (name.len == 7 && ngx_strncmp(name.data, "control", 7) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: control= is gone; any inspector asked on "
                               "the route may change this call's mode");
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_inspect",
                           &name);
        return NGX_CONF_ERROR;
    }

    if (!wave_set) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_inspect \"%V\" requires wave=",
                           &b.name);
        return NGX_CONF_ERROR;
    }

    /*
     * Продолжение выдаёт фаза запроса, а потребляет следующая. resume= на
     * запросе означал бы, что кто-то ждёт от него состояния, которого ещё нет.
     * keep= -- обратная сторона той же договорённости: держать состояние
     * просят ту фазу, которая его выдаёт, и только её. Сходится ли пара на
     * маршруте, проверяется после слияния (ngx_http_waf_check_resume_pairs):
     * здесь видна одна строка, а вторая может стоять уровнем выше.
     */
    if (b.resume != NGX_HTTP_WAF_RESUME_OFF
        && (phases & NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: resume= belongs to the phase that consumes "
                           "the continuation (response), not to request");
        return NGX_CONF_ERROR;
    }

    /*
     * Кадры инспектируются каждый сам по себе: инспектор видит полезную
     * нагрузку и заголовки рукопожатия как контекст, транзакцию рукопожатия
     * он не продолжает -- у GET с апгрейдом нет тела, а кадр не его часть.
     * resume= здесь лишь прибил бы кадры к экземпляру и держал транзакцию
     * рукопожатия впустую до срока. Продолжение потребляет только ответ.
     */
    if (b.resume != NGX_HTTP_WAF_RESUME_OFF
        && (phases & NGX_HTTP_WAF_PH_FRAME))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: resume= belongs to the response phase; "
                           "frames are inspected on their own and do not "
                           "continue the handshake transaction");
        return NGX_CONF_ERROR;
    }

    if (b.keep && !(phases & NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST))) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: keep= belongs to the request phase, which "
                           "hands the state over; %V consumes it with "
                           "resume=", &args[1]);
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(phase))) {
            continue;
        }

        list = wlcf->inspects[phase];

        if (list != NULL && list->nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_inspect %V none cannot mix with "
                               "named inspectors of the same phase",
                               &args[1]);
            return NGX_CONF_ERROR;
        }

        if (list == NULL) {
            list = ngx_array_create(cf->pool, 4,
                                    sizeof(ngx_http_waf_binding_t));
            if (list == NULL) {
                return NGX_CONF_ERROR;
            }

            wlcf->inspects[phase] = list;
        }

        exist = list->elts;

        for (i = 0; i < list->nelts; i++) {
            if (exist[i].index == b.index) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: inspector \"%V\" is already bound on "
                                   "this route for the same phase", &b.name);
                return NGX_CONF_ERROR;
            }
        }

        slot = ngx_array_push(list);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }

        *slot       = b;
        slot->phase = phase;
    }

    return NGX_CONF_OK;
}


/*
 * Значение: без CR, LF и NUL -- иначе получается расщепление ответа/JSON.
 * Общая с разбором ответа инспектора (codec/): правило одно на оба входа.
 */
ngx_uint_t
ngx_http_waf_value_clean(ngx_str_t *s)
{
    size_t  i;

    for (i = 0; i < s->len; i++) {
        if (s->data[i] == CR || s->data[i] == LF || s->data[i] == '\0') {
            return 0;
        }
    }

    return 1;
}


/* --- waf_deny_response ---------------------------------------------------- */

/*
 * params= -- что записи разрешено отдать клиенту: перечень слов через запятую
 * в биты NGX_HTTP_WAF_DENY_P_*. Слова -- хвосты имён переменных $waf_deny_*.
 *
 * Незнакомое слово -- ошибка конфигурации, а не пропуск: перечень пишется
 * ради того, чтобы наружу не ушло лишнее, и опечатка, молча открывшая всё,
 * была бы ровно той дырой, от которой перечень заводили.
 */
static ngx_int_t
ngx_http_waf_deny_params(ngx_conf_t *cf, ngx_str_t *value, ngx_uint_t *mask)
{
    u_char     *p, *last, *comma;
    ngx_str_t   word;

    static struct {
        ngx_str_t   name;
        ngx_uint_t  bit;
    } words[] = {
        { ngx_string("ray"),     NGX_HTTP_WAF_DENY_P_RAY     },
        { ngx_string("addr"),    NGX_HTTP_WAF_DENY_P_ADDR    },
        { ngx_string("scope"),   NGX_HTTP_WAF_DENY_P_SCOPE   },
        { ngx_string("subject"), NGX_HTTP_WAF_DENY_P_SUBJECT },
        { ngx_string("retry"),   NGX_HTTP_WAF_DENY_P_RETRY   },
        { ngx_null_string, 0 }
    };

    ngx_uint_t  i, found;

    p = value->data;
    last = value->data + value->len;

    while (p < last) {
        comma = ngx_strlchr(p, last, ',');

        word.data = p;
        word.len = (comma == NULL ? last : comma) - p;
        p = (comma == NULL) ? last : comma + 1;

        if (word.len == 0) {
            continue;
        }

        found = 0;

        for (i = 0; words[i].name.len != 0; i++) {
            if (word.len == words[i].name.len
                && ngx_strncmp(word.data, words[i].name.data, word.len) == 0)
            {
                *mask |= words[i].bit;
                found = 1;
                break;
            }
        }

        if (!found) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown word \"%V\" in params= of "
                               "waf_deny_response; expected ray, addr, "
                               "scope, subject or retry", &word);
            return NGX_ERROR;
        }
    }

    if (*mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: empty params= in waf_deny_response; drop "
                           "the option to expose everything");
        return NGX_ERROR;
    }

    return NGX_OK;
}


char *
ngx_http_waf_deny_response(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_str_t                     *args, name, value;
    ngx_int_t                      n;
    ngx_uint_t                     i;
    ngx_http_waf_deny_response_t  *dr;

    args = cf->args->elts;

    if (wmcf->deny_responses == NULL) {
        wmcf->deny_responses = ngx_array_create(cf->pool, 4,
                                   sizeof(ngx_http_waf_deny_response_t));
        if (wmcf->deny_responses == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_http_waf_deny_response_find(wmcf, &args[1]) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: deny response \"%V\" is already declared",
                           &args[1]);
        return NGX_CONF_ERROR;
    }

    dr = ngx_array_push(wmcf->deny_responses);
    if (dr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(dr, sizeof(ngx_http_waf_deny_response_t));

    dr->name   = args[1];
    dr->type   = NGX_HTTP_WAF_DENY_TYPE_HTTP;
    dr->status = NGX_HTTP_FORBIDDEN;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in "
                               "waf_deny_response", &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "type", 4) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_deny_type, &value,
                                         &dr->type) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "status", 6) == 0) {
            n = ngx_atoi(value.data, value.len);
            if (n == NGX_ERROR || n < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid status \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            dr->status = (ngx_uint_t) n;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "page", 4) == 0) {
            if (value.len == 0 || value.data[0] != '@') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: page= expects a named location, "
                                   "got \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            dr->page = value;
            continue;
        }

        if (name.len == 7 && ngx_strncmp(name.data, "message", 7) == 0) {
            dr->message = value;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "code", 4) == 0) {
            n = ngx_atoi(value.data, value.len);
            if (n == NGX_ERROR || n < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid close code \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            dr->code = (ngx_uint_t) n;
            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "reason", 6) == 0) {
            dr->reason = value;
            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "params", 6) == 0) {
            if (ngx_http_waf_deny_params(cf, &value, &dr->params) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_deny_response",
                           &name);
        return NGX_CONF_ERROR;
    }

    /*
     * Двухсотый и триста какой-нибудь в отказе превращают блокировку в тихий
     * пропуск, поэтому проверяется здесь, а не при применении: конфигурация,
     * которую нельзя выполнить безопасно, не должна загружаться.
     */
    if (dr->type == NGX_HTTP_WAF_DENY_TYPE_HTTP
        && (dr->status < 400 || dr->status > 599))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: deny response \"%V\" has status %ui; 2xx and "
                           "3xx turn a denial into a silent pass",
                           &dr->name, dr->status);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* --- waf_redirect_allow ---------------------------------------------------- */

/*
 * Куда сервису разрешено уводить клиента. Цель редиректа приезжает с провода,
 * потому что знать про жизненный цикл челленджа может только тот, кто его
 * ведёт; здесь задаётся граница, за которую он не выйдет.
 *
 * Две формы шаблона:
 *
 *     /waf/captcha                 -- локальный путь, только он и ниже
 *     https://chal.example.com/c/  -- схема, хост, порт и префикс пути
 *
 * Хост во второй форме может начинаться с "*." -- тогда подходит любой
 * поддомен, но не сам домен.
 */
char *
ngx_http_waf_redirect_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    u_char                         *p, *last, *colon;
    ngx_str_t                      *args, pattern;
    ngx_int_t                       n;
    ngx_uint_t                      i;
    ngx_http_waf_redirect_allow_t  *allow;

    args = cf->args->elts;

    if (wlcf->redirect_allow == NULL) {
        wlcf->redirect_allow = ngx_array_create(cf->pool, 2,
                                   sizeof(ngx_http_waf_redirect_allow_t));
        if (wlcf->redirect_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        pattern = args[i];

        allow = ngx_array_push(wlcf->redirect_allow);
        if (allow == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(allow, sizeof(ngx_http_waf_redirect_allow_t));

        p    = pattern.data;
        last = pattern.data + pattern.len;

        if (pattern.len != 0 && p[0] == '/') {
            if (pattern.len > 1 && p[1] == '/') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: pattern \"%V\" starts with \"//\", "
                                   "which is an absolute address without a "
                                   "scheme, not a local path", &pattern);
                return NGX_CONF_ERROR;
            }

            allow->path = pattern;
            continue;
        }

        if (pattern.len > 7 && ngx_strncmp(p, "http://", 7) == 0) {
            ngx_str_set(&allow->scheme, "http");
            allow->port = 80;
            p += 7;

        } else if (pattern.len > 8 && ngx_strncmp(p, "https://", 8) == 0) {
            ngx_str_set(&allow->scheme, "https");
            allow->port = 443;
            p += 8;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: pattern \"%V\" is neither a local path "
                               "starting with \"/\" nor an http:// or https:// "
                               "address", &pattern);
            return NGX_CONF_ERROR;
        }

        if (last - p > 2 && p[0] == '*' && p[1] == '.') {
            allow->wildcard = 1;
            p += 2;
        }

        allow->host.data = p;

        while (p < last && *p != '/') {
            p++;
        }

        allow->host.len = (size_t) (p - allow->host.data);

        if (allow->host.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: pattern \"%V\" has no host", &pattern);
            return NGX_CONF_ERROR;
        }

        colon = ngx_strlchr(allow->host.data,
                            allow->host.data + allow->host.len, ':');

        if (colon != NULL) {
            n = ngx_atoi(colon + 1, (size_t) (allow->host.data
                                              + allow->host.len - colon - 1));
            if (n < 1 || n > 65535) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: pattern \"%V\" has an invalid port",
                                   &pattern);
                return NGX_CONF_ERROR;
            }

            allow->port     = (in_port_t) n;
            allow->host.len = (size_t) (colon - allow->host.data);

            if (allow->host.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: pattern \"%V\" has no host",
                                   &pattern);
                return NGX_CONF_ERROR;
            }
        }

        /*
         * Хост сравнивается без учёта регистра, поэтому приводить его к нижнему
         * здесь не нужно; а вот пустой префикс пути означает "весь хост", и это
         * осознанная форма, а не упущение.
         */
        allow->path.data = p;
        allow->path.len  = (size_t) (last - p);
    }

    return NGX_CONF_OK;
}


/* --- waf_audit_sample ----------------------------------------------------- */

/*
 * Доля разрешённых запросов, попадающих в аудит, в процентах.
 *
 * Прорежается только то, что нечем объяснить: отказ, редирект, сорванная
 * политикой волна и запрос, отдавший объекты в архив, пишутся при любом
 * значении. Сэмпл, который умеет потерять блокировку, не сэмпл, а дыра в
 * расследовании.
 */
char *
ngx_http_waf_audit_sample(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t  *args = cf->args->elts;
    ngx_int_t   n;

    if (wlcf->audit_sample != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_atoi(args[1].data, args[1].len);

    if (n == NGX_ERROR || n < 0 || n > 100) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid waf_audit_sample \"%V\", "
                           "expected a percentage 0..100", &args[1]);

        return NGX_CONF_ERROR;
    }

    wlcf->audit_sample = n;

    return NGX_CONF_OK;
}


/* --- waf_score_deny ------------------------------------------------------- */

char *
ngx_http_waf_score_deny(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value, page;
    ngx_int_t    n;
    ngx_uint_t   i, phase, phases;

    args = cf->args->elts;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(phase))
            && wlcf->score_deny[phase] != NGX_CONF_UNSET)
        {
            return "is duplicate";
        }
    }

    n = ngx_atoi(args[2].data, args[2].len);
    if (n == NGX_ERROR || n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid threshold \"%V\"", &args[2]);
        return NGX_CONF_ERROR;
    }

    ngx_str_null(&page);

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK
            || name.len != 8 || ngx_strncmp(name.data, "response", 8) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown option \"%V\" in waf_score_deny",
                               &args[i]);
            return NGX_CONF_ERROR;
        }

        page = value;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(phase))) {
            continue;
        }

        wlcf->score_deny[phase] = n;

        if (page.len != 0) {
            wlcf->score_deny_response[phase] = page;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_exception <фаза> [<класс>] pass|deny [response=<имя>];
 *
 * Что делать, когда вердикта нет. Одна директива на все причины: раньше их
 * было четыре -- политика вторым словом waf_deadline и три waf_on_*, -- и
 * каждая новая причина тянула за собой пятую. Класс остался, потому что
 * события разной природы: пропущенный дедлайн -- это перегрузка, пустой
 * subject -- ошибка развёртывания, и одна политика на оба означала бы, что
 * одна из двух настроена неверно всегда.
 *
 * Строка без класса задаёт все классы фазы. Класс, названный на уровне
 * дважды -- в том числе один раз строкой без класса, -- ошибка: широкая и
 * узкая строка рядом читаются по порядку, а порядок строк в nginx.conf не
 * должен ничего решать. Уточняют уровнем ниже, как у waf_deadline frame.
 *
 * response= -- запись каталога waf_deny_response, которой отвечать на deny.
 * Не названа -- 503 без каталога: до этой директивы модуль отвечал так на
 * любой сорванной волне, и молча менять код на чужой странице нельзя.
 */
static ngx_http_waf_kw_t  ngx_http_waf_kw_exception[] = {
    { ngx_string("pass"), NGX_HTTP_WAF_POLICY_PASS  },
    { ngx_string("deny"), NGX_HTTP_WAF_POLICY_BLOCK },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_exc_class[] = {
    { ngx_string("timeout"), NGX_HTTP_WAF_EXC_TIMEOUT },
    { ngx_string("absent"),  NGX_HTTP_WAF_EXC_ABSENT  },
    { ngx_string("bus"),     NGX_HTTP_WAF_EXC_BUS     },
    { ngx_string("body"),      NGX_HTTP_WAF_EXC_BODY      },
    { ngx_string("inspector"), NGX_HTTP_WAF_EXC_INSPECTOR },
    { ngx_string("overload"),  NGX_HTTP_WAF_EXC_OVERLOAD  },
    { ngx_null_string, 0 }
};


char *
ngx_http_waf_exception(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value, page;
    ngx_uint_t   i, ph, exc, phases, policy, classes, first;

    args = cf->args->elts;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    classes = 0;
    first   = 2;

    if (ngx_http_waf_kw_lookup(ngx_http_waf_kw_exc_class, &args[2], &exc)
        == NGX_OK)
    {
        classes = 1 << exc;
        first   = 3;

        if (cf->args->nelts < 4) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_exception: class \"%V\" needs pass or "
                               "deny after it", &args[2]);
            return NGX_CONF_ERROR;
        }
    }

    /* Класс не назван -- строка про все классы этой фазы. */
    if (classes == 0) {
        for (exc = 0; exc < NGX_HTTP_WAF_EXC_COUNT; exc++) {
            classes |= 1 << exc;
        }
    }

    if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_exception, &args[first],
                                 &policy) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_str_null(&page);

    for (i = first + 1; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK
            || name.len != 8
            || ngx_strncmp(name.data, "response", 8) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_exception: \"%V\" is not response=<name>",
                               &args[i]);
            return NGX_CONF_ERROR;
        }

        if (value.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_exception: response= needs a name of a "
                               "waf_deny_response entry");
            return NGX_CONF_ERROR;
        }

        if (page.len != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_exception: response= is listed twice");
            return NGX_CONF_ERROR;
        }

        page = value;
    }

    if (policy == NGX_HTTP_WAF_POLICY_PASS && page.len != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_exception: response= has no meaning with "
                           "pass -- the request goes through, and there is "
                           "no page to answer with");
        return NGX_CONF_ERROR;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        for (exc = 0; exc < NGX_HTTP_WAF_EXC_COUNT; exc++) {

            if (!(classes & (1 << exc))) {
                continue;
            }

            if (wlcf->exception[ph][exc] != NGX_CONF_UNSET_UINT) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_exception: \"%V\" of phase \"%V\" is "
                                   "already set on this level",
                                   ngx_http_waf_exc_name(exc),
                                   ngx_http_waf_phase_name(ph));
                return NGX_CONF_ERROR;
            }

            wlcf->exception[ph][exc] = policy;

            if (page.len != 0) {
                wlcf->exception_response[ph][exc] = page;
            }
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_send <фаза> <obj>=original|store ...;
 *
 * Откуда отдать объект получателю: как пришёл либо версию инспектора из
 * обменника. Четвёртая ось той же таблицы, что waf_capture / waf_preview /
 * waf_archive: фаза первым словом, словарь объектов фазы, строки одного
 * уровня складываются по объекту. Неполный снимок store не отдаёт -- это
 * не настройка, а факт, и опции «отдать кусок» здесь нет.
 *
 * Своего рычага на случай несостоявшейся подмены у директивы нет: сорванный
 * подъём -- сбой обработки запроса, и распоряжается им политика фазы
 * waf_exception … body, как и всякой другой недоступностью объекта.
 */
char *
ngx_http_waf_send(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value;
    ngx_uint_t   i, ph, obj, bit, phases, how, seen;
    ngx_uint_t   send[NGX_HTTP_WAF_OBJ_COUNT];

    args = cf->args->elts;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    seen = 0;

    for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {
        send[obj] = NGX_HTTP_WAF_SEND_ORIGINAL;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_send: \"%V\" is not "
                               "<object>=original|store", &args[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_obj_bit(&name, &bit) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown option \"%V\" in waf_send",
                               &name);
            return NGX_CONF_ERROR;
        }

        obj = ngx_http_waf_bit_obj(bit);

        if (ngx_http_waf_obj_in_phase(cf, &args[0], phases, obj)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (seen & bit) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_send: \"%V\" is already listed", &name);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_send, &value, &how)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        seen     |= bit;
        send[obj] = how;
    }

    if (seen == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_send: nothing to set; write "
                           "<object>=original|store after the phase");
        return NGX_CONF_ERROR;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {

            if (!(seen & NGX_HTTP_WAF_OBJ_BIT(obj))) {
                continue;
            }

            /*
             * Один объект одной фазы называется на уровне один раз: строка
             * "frame body=store" уже заняла оба слота кадров, и
             * "frame:c2s body=original" рядом с ней -- противоречие, а не
             * уточнение.
             */
            if (wlcf->send[ph][obj] != NGX_CONF_UNSET_UINT) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_send: \"%V\" of phase \"%V\" is "
                                   "already set on this level",
                                   ngx_http_waf_obj_name(obj),
                                   ngx_http_waf_phase_name(ph));
                return NGX_CONF_ERROR;
            }

            wlcf->send[ph][obj] = send[obj];
        }
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_phase_deny_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args = cf->args->elts;
    ngx_uint_t   phase, phases, mode;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(phase))
            && wlcf->deny_mode[phase] != NGX_CONF_UNSET_UINT)
        {
            return "is duplicate";
        }
    }

    if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_deny_mode, &args[2],
                                 &mode) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if (phases & NGX_HTTP_WAF_PH_BIT(phase)) {
            wlcf->deny_mode[phase] = mode;
        }
    }

    return NGX_CONF_OK;
}


/* --- waf_cookie_defaults -------------------------------------------------- */

char *
ngx_http_waf_cookie_defaults(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value;
    ngx_uint_t   i, flag;

    args = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in "
                               "waf_cookie_defaults", &args[i]);
            return NGX_CONF_ERROR;
        }

        /*
         * Опечатка в значении -- это отказ конфигурации, а не тихое off:
         * значения ниже решают, дойдёт ли cookie челленджа до браузера, и
         * молча ослабленный атрибут искать потом дороже всего.
         */
        if (name.len == 6 && ngx_strncmp(name.data, "secure", 6) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_flag, &value,
                                         &flag) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            wlcf->cookie_secure = (ngx_flag_t) flag;
            continue;
        }

        if (name.len == 9 && ngx_strncmp(name.data, "http_only", 9) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_flag, &value,
                                         &flag) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            wlcf->cookie_http_only = (ngx_flag_t) flag;
            continue;
        }

        if (name.len == 9 && ngx_strncmp(name.data, "same_site", 9) == 0) {
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_same_site, &value,
                                         &wlcf->cookie_same_site) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_cookie_defaults",
                           &name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* --- waf_capture ----------------------------------------------------------
 *
 * Что вообще разрешено снять с запроса ради инспекторов:
 *
 *     waf_capture request none | <headers|args|body>[=<size>|none] ...;
 *     waf_capture off;
 *
 * Ось оператора, и она не спорит с needs= инспектора, а ограничивает его
 * сверху: сервис заявляет, что ему нужно, оператор решает, что отдать.
 *
 * Область первым словом, как у архива: фаза ответа появится, и молчаливое
 * "request" пришлось бы тогда либо ломать, либо оставлять умолчанием.
 *
 * Размер -- потолок тому, что волна кладёт инспектору. Без "=" -- весь
 * объект; =none -- этот вид выкл. Архив и превью этой оси не подчинены.
 *
 * Строки одного уровня складываются по объекту. Своя строка на location
 * перекрывает только названный вид.
 */

char *
ngx_http_waf_capture(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ssize_t                     size;
    ngx_int_t                   rc;
    ngx_str_t                  *args, name, value;
    ngx_uint_t                  i, ph, bit, obj, mask, off, phases;
    size_t                      limits[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_shoot_conf_t  *sh;

    args = cf->args->elts;

    rc = ngx_http_waf_obj_list(cf, wlcf, NGX_HTTP_WAF_LIST_CAPTURE);
    if (rc == NGX_OK) {
        return NGX_CONF_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    mask = 0;
    off  = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        limits[i] = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {

            if ((args[i].len == 4 && ngx_strncmp(args[i].data, "none", 4) == 0)
                || (args[i].len == 3
                    && ngx_strncmp(args[i].data, "off", 3) == 0))
            {
                if (cf->args->nelts != 3) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf_capture: \"none\" cannot be "
                                       "combined with anything else");
                    return NGX_CONF_ERROR;
                }

                for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {
                    if (phases & NGX_HTTP_WAF_PH_BIT(ph)) {
                        ngx_http_waf_capture_none(&wlcf->shoot[ph]);
                    }
                }

                return NGX_CONF_OK;
            }

            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_obj, &args[i],
                                         &bit) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_waf_obj_in_phase(cf, &args[0], phases,
                                          ngx_http_waf_bit_obj(bit))
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            if ((mask | off) & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_capture: \"%V\" is already listed",
                                   &args[i]);
                return NGX_CONF_ERROR;
            }

            mask |= bit;
            continue;
        }

        if ((name.len == 4 && ngx_strncmp(name.data, "mask", 4) == 0)
            || (name.len == 4 && ngx_strncmp(name.data, "deny", 4) == 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_capture: mask= and deny= are their own "
                               "lines (waf_capture request headers "
                               "deny=x-api-key)");
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_obj_bit(&name, &bit) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown option \"%V\" in waf_capture",
                               &name);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_obj_in_phase(cf, &args[0], phases,
                                      ngx_http_waf_bit_obj(bit))
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if ((mask | off) & bit) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_capture: \"%V\" is already listed",
                               &name);
            return NGX_CONF_ERROR;
        }

        if (value.len == 4 && ngx_strncmp(value.data, "none", 4) == 0) {
            off |= bit;
            continue;
        }

        size = ngx_parse_size(&value);

        if (size == NGX_ERROR || size <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_capture: invalid size \"%V\" for \"%V\"; "
                               "write \"none\" to turn the object off, or omit "
                               "\"=\" to capture it whole",
                               &value, &name);
            return NGX_CONF_ERROR;
        }

        obj = ngx_http_waf_bit_obj(bit);
        mask |= bit;
        limits[obj] = (size_t) size;
    }

    if (mask == 0 && off == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_capture: no objects listed; say \"off\" to "
                           "turn capture off");
        return NGX_CONF_ERROR;
    }

    /*
     * Слоты фазы: строка frame настраивает оба направления, и набор у них
     * общий ровно потому, что написан одной строкой. Своя строка frame:c2s
     * ниже перекроет своё направление.
     */
    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        sh = &wlcf->shoot[ph];

        if (sh->capture == NGX_CONF_UNSET_UINT) {
            sh->capture = 0;
        }

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            bit = NGX_HTTP_WAF_OBJ_BIT(i);

            if (!((mask | off) & bit)) {
                continue;
            }

            if (sh->capture_set & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_capture: \"%V\" is already configured "
                                   "on this level", ngx_http_waf_obj_name(i));
                return NGX_CONF_ERROR;
            }

            sh->capture_set |= bit;

            if (off & bit) {
                sh->capture &= ~bit;
                sh->capture_limit[i] = NGX_CONF_UNSET_SIZE;
                continue;
            }

            sh->capture |= bit;
            sh->capture_limit[i] = limits[i];
        }
    }

    return NGX_CONF_OK;
}


/* --- снятая директива ------------------------------------------------------
 *
 * Молчаливо игнорировать имя, которого больше нет, нельзя: конфигурация
 * выглядела бы применённой. Отдельный обработчик вместо отсутствия директивы
 * -- чтобы в сообщении стояло, чем её заменили: "unknown directive" отправляет
 * читать changelog, а здесь ответ уже есть.
 */
char *
ngx_http_waf_retired(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *args = cf->args->elts;

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: \"%V\" no longer exists; use \"%s\" instead",
                       &args[0], (char *) cmd->post);

    return NGX_CONF_ERROR;
}


/* --- waf_archive ----------------------------------------------------------
 *
 * Что из обменника не удалять, а передать агенту:
 *
 *     waf_archive request none
 *               | <headers|args|body>[=<size>|none] ...
 *                 [ttl=<time>] [when=allow|deny];
 *
 * Область называется первым словом. Пока она одна, но писать её обязательно:
 * фаза ответа появится, и молчаливое "request" пришлось бы тогда либо ломать,
 * либо оставлять умолчанием, о котором никто не помнит.
 *
 * Имени назначения здесь нет намеренно. Куда именно уедет объект, знает агент:
 * бакеты и реквизиты живут в его конфигурации. Модуль про S3 не знает вовсе --
 * и не должен, иначе доступ к архиву всего контура лежал бы в файле, который
 * читают все, кому нужен маршрут.
 *
 * На проводе едет срок хранения, а не класс. Класс требовал реестра, который
 * пришлось бы держать согласованным у модуля, у агента и в lifecycle-правилах
 * бакета, -- три места, где опечатка означает молча потерянный архив. Срок не
 * требует ничего: он читается там же, где применяется.
 *
 * Размер пишется на объекте (body=8k), а не общим limit=: иначе одна строка
 * с заголовками и телом не могла бы резать только тело. Без "=" -- весь
 * объект; =none -- этот вид выкл, не трогая остальные слова строки.
 *
 * when= -- только allow и deny. Слов always и redirect нет: первое совпадало
 * с умолчанием (нет when= -- любой исход, включая redirect), второе отдельно
 * почти никто не архивирует. Редирект по-прежнему попадает в архив, когда
 * when= не назван.
 *
 * Строка настраивает только названные в ней виды, и строки одного уровня
 * складываются. ttl= и when= привязаны к видам той же строки.
 *
 * Директива ни у кого не спрашивает разрешения. Названный здесь объект будет
 * снят и передан агенту, даже если его не просит ни waf_capture, ни один
 * инспектор: это требование хранить, а не показывать. Ограничить его может
 * только абсолютный предел чтения.
 */
char *
ngx_http_waf_archive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    time_t      ttl;
    ssize_t     size;
    ngx_int_t   rc, secs;
    ngx_str_t  *args, name, value;
    ngx_uint_t  i, ph, bit, obj, mask, off, when, phases;
    size_t      limits[NGX_HTTP_WAF_OBJ_COUNT];

    args = cf->args->elts;

    rc = ngx_http_waf_obj_list(cf, wlcf, NGX_HTTP_WAF_LIST_ARCHIVE);
    if (rc == NGX_OK) {
        return NGX_CONF_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * Архив есть у каждой фазы, где есть снимок: у запроса, у ответа и у
     * кадра. Запись аудита у каждой своя, объекты кладёт снимок той же фазы.
     * У кадра нет только reload: оригинала у него нет.
     */
    if (cf->args->nelts >= 3
        && args[2].len == 6
        && ngx_strncmp(args[2].data, "reload", 6) == 0)
    {
        if (ngx_http_waf_no_reload_in(cf, &args[0], phases) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

            if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
                continue;
            }

            if (ngx_http_waf_archive_reload(cf, &wlcf->shoot[ph])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        return NGX_CONF_OK;
    }

    mask = 0;
    off  = 0;
    when = NGX_CONF_UNSET_UINT;
    ttl  = NGX_CONF_UNSET;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        limits[i] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {

            if (args[i].len == 4
                && ngx_strncmp(args[i].data, "none", 4) == 0)
            {
                /*
                 * Явное пустое множество. Отличается от отсутствия директивы:
                 * оно наследуется вниз и перекрывает родителя, иначе выключить
                 * архивацию на одном server при включённой в http было бы
                 * нечем. Написанное после других строк того же уровня -- стирает
                 * их: читается как "здесь ничего", и половинчатый набор после
                 * такого слова был бы сюрпризом.
                 */
                if (cf->args->nelts != 3) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf_archive: \"none\" cannot be "
                                       "combined with anything else");
                    return NGX_CONF_ERROR;
                }

                for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

                    if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
                        continue;
                    }

                    ngx_http_waf_archive_reset(&wlcf->shoot[ph]);
                    wlcf->shoot[ph].archive        = 0;
                    wlcf->shoot[ph].archive_reload = 0;
                }

                return NGX_CONF_OK;
            }

            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_obj, &args[i],
                                         &bit) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if ((mask | off) & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: \"%V\" is already listed",
                                   &args[i]);
                return NGX_CONF_ERROR;
            }

            obj = ngx_http_waf_bit_obj(bit);
            mask |= bit;
            limits[obj] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
            continue;
        }

        if (ngx_http_waf_obj_bit(&name, &bit) == NGX_OK) {

            if ((mask | off) & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: \"%V\" is already listed",
                                   &name);
                return NGX_CONF_ERROR;
            }

            if (value.len == 4 && ngx_strncmp(value.data, "none", 4) == 0) {
                off |= bit;
                continue;
            }

            /*
             * Сколько байт объекта уедет в архив. Режет агент: в обменнике объект
             * лежит целиком, потому что его мог попросить инспектор, и урезать
             * общий объект ради настройки архива модуль не вправе.
             */
            size = ngx_parse_size(&value);

            if (size == NGX_ERROR || size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: invalid size \"%V\" for "
                                   "\"%V\"; write \"none\" to turn the object "
                                   "off, or omit \"=\" to archive it whole",
                                   &value, &name);
                return NGX_CONF_ERROR;
            }

            obj = ngx_http_waf_bit_obj(bit);
            mask |= bit;
            limits[obj] = (size_t) size;
            continue;
        }

        if (name.len == 3 && ngx_strncmp(name.data, "ttl", 3) == 0) {

            /*
             * Срок в секундах: точнее архиву не нужно, а ngx_parse_time с
             * секундами понимает и "180d", и "24600" -- вторая форма в
             * конфигурации встречается там, где срок пришёл из чужой системы.
             */
            secs = ngx_parse_time(&value, 1);

            if (secs == NGX_ERROR || secs <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: invalid ttl \"%V\"; omit it "
                                   "to keep objects forever", &value);
                return NGX_CONF_ERROR;
            }

            ttl = (time_t) secs;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "when", 4) == 0) {

            ngx_str_t   word;
            u_char     *p, *last;

            /*
             * always совпадало с "нет when=", redirect отдельно почти не
             * архивируют. Оба слова сняты, чтобы when= читался как фильтр
             * исхода, а не как ещё одно имя для умолчания.
             */
            p    = value.data;
            last = value.data + value.len;

            while (p < last) {
                word.data = p;

                while (p < last && *p != ',') {
                    p++;
                }

                word.len = (size_t) (p - word.data);

                if (p < last) {
                    p++;
                }

                if ((word.len == 6 && ngx_strncmp(word.data, "always", 6) == 0)
                    || (word.len == 8
                        && ngx_strncmp(word.data, "redirect", 8) == 0))
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf_archive: when= accepts only allow "
                                       "and deny; omit when= to archive every "
                                       "outcome");
                    return NGX_CONF_ERROR;
                }
            }

            when = 0;

            if (ngx_http_waf_opt_flags(cf, ngx_http_waf_kw_archive_when,
                                       &value, &when) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (when == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: when= names no outcome; say "
                                   "\"none\" to turn archiving off");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 5 && ngx_strncmp(name.data, "limit", 5) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_archive: limit= is gone; write the size on "
                               "the object (body=8k), or omit it to archive "
                               "the whole object");
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_archive", &name);
        return NGX_CONF_ERROR;
    }

    if (mask == 0 && off == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_archive: no objects listed; say \"none\" to "
                           "turn archiving off");
        return NGX_CONF_ERROR;
    }

    /* Словарь объектов у фазы свой: у кадра только body. */
    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (((mask | off) & NGX_HTTP_WAF_OBJ_BIT(i))
            && ngx_http_waf_obj_in_phase(cf, &args[0], phases, i)
               != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        if (ngx_http_waf_archive_apply(cf, &wlcf->shoot[ph], mask, off, when,
                                       ttl, limits)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * Набор архива в слот одной фазы. Отдельной функцией, потому что строка
 * waf_archive frame настраивает оба направления: разбор один, применений
 * столько, сколько названо слотов.
 */
static char *
ngx_http_waf_archive_apply(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t mask, ngx_uint_t off, ngx_uint_t when, time_t ttl,
    size_t *limits)
{
    ngx_uint_t  i;

    if (sh->archive == NGX_CONF_UNSET_UINT) {
        sh->archive = 0;
    }

    if (sh->archive_reload == NGX_CONF_UNSET_UINT) {
        sh->archive_reload = 0;
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(off & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (sh->archive_set & NGX_HTTP_WAF_OBJ_BIT(i)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_archive: \"%V\" is already configured on "
                               "this level", ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        sh->archive_set |= NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive &= ~NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive_reload &= ~NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive_when[i]  = NGX_CONF_UNSET_UINT;
        sh->archive_ttl[i]   = NGX_CONF_UNSET;
        sh->archive_limit[i] = NGX_CONF_UNSET_SIZE;
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (sh->archive_set & NGX_HTTP_WAF_OBJ_BIT(i)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_archive: \"%V\" is already configured on "
                               "this level", ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        sh->archive_set |= NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive |= NGX_HTTP_WAF_OBJ_BIT(i);

        sh->archive_when[i]  = when;
        sh->archive_ttl[i]   = ttl;
        sh->archive_limit[i] = limits[i];
    }


    return NGX_CONF_OK;
}


static char *
ngx_http_waf_archive_reload(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh)
{
    time_t      ttl;
    ssize_t     size;
    ngx_int_t   secs;
    ngx_str_t  *args, name, value;
    ngx_uint_t  i, bit, obj, mask, when;
    size_t      limits[NGX_HTTP_WAF_OBJ_COUNT];

    args = cf->args->elts;
    mask = 0;
    when = NGX_CONF_UNSET_UINT;
    ttl  = NGX_CONF_UNSET;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        limits[i] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
    }

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {

            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_obj, &args[i],
                                         &bit) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (mask & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: \"%V\" is already listed",
                                   &args[i]);
                return NGX_CONF_ERROR;
            }

            obj = ngx_http_waf_bit_obj(bit);
            mask |= bit;
            limits[obj] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
            continue;
        }

        if (ngx_http_waf_obj_bit(&name, &bit) == NGX_OK) {

            if (mask & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: \"%V\" is already listed",
                                   &name);
                return NGX_CONF_ERROR;
            }

            obj = ngx_http_waf_bit_obj(bit);

            if (value.len == 7
                && ngx_strncmp(value.data, "capture", 7) == 0)
            {
                mask |= bit;
                limits[obj] = NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE;
                continue;
            }

            size = ngx_parse_size(&value);

            if (size == NGX_ERROR || size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: invalid size \"%V\" for "
                                   "reload \"%V\"; write \"=capture\", "
                                   "a size, or omit \"=\" for the whole "
                                   "object",
                                   &value, &name);
                return NGX_CONF_ERROR;
            }

            mask |= bit;
            limits[obj] = (size_t) size;
            continue;
        }

        if (name.len == 3 && ngx_strncmp(name.data, "ttl", 3) == 0) {
            secs = ngx_parse_time(&value, 1);

            if (secs == NGX_ERROR || secs <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: invalid ttl \"%V\"; omit it "
                                   "to keep objects forever", &value);
                return NGX_CONF_ERROR;
            }

            ttl = (time_t) secs;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "when", 4) == 0) {
            when = 0;

            if (ngx_http_waf_opt_flags(cf, ngx_http_waf_kw_archive_when,
                                       &value, &when) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (when == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: when= names no outcome; say "
                                   "\"none\" to turn archiving off");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_archive", &name);
        return NGX_CONF_ERROR;
    }

    if (mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_archive: reload names no objects");
        return NGX_CONF_ERROR;
    }

    if (sh->archive == NGX_CONF_UNSET_UINT) {
        sh->archive = 0;
    }

    if (sh->archive_reload == NGX_CONF_UNSET_UINT) {
        sh->archive_reload = 0;
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (sh->archive_reload & NGX_HTTP_WAF_OBJ_BIT(i)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_archive: reload \"%V\" is already "
                               "configured on this level",
                               ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        sh->archive_set |= NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive |= NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive_reload |= NGX_HTTP_WAF_OBJ_BIT(i);
        sh->archive_reload_limit[i] = limits[i];

        if (limits[i] != NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE) {
            sh->archive_limit[i] = limits[i];
        }

        if (when != NGX_CONF_UNSET_UINT) {
            sh->archive_when[i] = when;
        }

        if (ttl != NGX_CONF_UNSET) {
            sh->archive_ttl[i] = ttl;
        }
    }

    return NGX_CONF_OK;
}


/* --- превью для записи аудита ---------------------------------------------
 *
 *     waf_preview headers=64k/2k args=64k/2k body=128k
 *                 [allow=<names>] [deny=<names>];
 *     waf_preview headers=none;
 *     waf_preview none;
 *
 * Размер пишется на объекте. Без "=" бюджетом становился весь объект -- это
 * молча раздувало датаграмму до client_max_body_size, и узнать об этом можно
 * было только по обрезанной записи. Теперь размер обязателен: =none выключает
 * секцию, =size задаёт бюджет JSON, =size/size -- бюджет и потолок одной пары.
 * У тела второго размера нет: там и так префикс.
 *
 * Строка настраивает названные виды, строки уровня складываются. allow= и
 * deny= -- отдельные строки (waf_preview headers deny=...), у headers и args.
 *
 * force снят. Заданное превью само означает "извлечь объект ради записи".
 */
static char *
ngx_http_waf_preview_spec(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t obj, ngx_str_t *spec)
{
    u_char     *slash;
    ssize_t     size;
    ngx_str_t   budget, item;

    if (sh->preview[obj] != NGX_CONF_UNSET_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: \"%V\" is already configured on this "
                           "level", ngx_http_waf_obj_name(obj));
        return NGX_CONF_ERROR;
    }

    if (spec->len == 4 && ngx_strncmp(spec->data, "none", 4) == 0) {
        sh->preview[obj] = 0;
        return NGX_CONF_OK;
    }

    slash = ngx_strlchr(spec->data, spec->data + spec->len, '/');

    if (slash != NULL) {

        if (obj == NGX_HTTP_WAF_OBJ_BODY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview body: takes no per-item cap; the "
                               "section is a single prefix");
            return NGX_CONF_ERROR;
        }

        budget.data = spec->data;
        budget.len  = (size_t) (slash - spec->data);

        item.data = slash + 1;
        item.len  = (size_t) (spec->data + spec->len - item.data);

        if (budget.len == 0 || item.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview %V: invalid size \"%V\"",
                               ngx_http_waf_obj_name(obj), spec);
            return NGX_CONF_ERROR;
        }

        size = ngx_parse_size(&item);

        if (size == NGX_ERROR || size <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview %V: invalid per-item cap \"%V\"",
                               ngx_http_waf_obj_name(obj), &item);
            return NGX_CONF_ERROR;
        }

        sh->preview_item[obj] = (size_t) size;

    } else {
        budget = *spec;
    }

    size = ngx_parse_size(&budget);

    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview %V: invalid size \"%V\"",
                           ngx_http_waf_obj_name(obj), &budget);
        return NGX_CONF_ERROR;
    }

    sh->preview[obj] = (size_t) size;

    return NGX_CONF_OK;
}


/* --- allow= и deny= превью заголовков -------------------------------------
 *
 * Какие заголовки вправе попасть в превью. Запрет сильнее разрешения: список
 * разрешённых -- это про удобство разбора, список запрещённых -- про секреты, и
 * ошибка в первом не должна вскрывать второе.
 *
 * Заданный запрет складывается со встроенным списком секретов, а не заменяет
 * его: оператор, добавляющий имя, добавляет правило, а не снимает четыре
 * чужих. Снять их целиком можно только словом "none" -- и это видно в конфиге.
 *
 * Имена перечисляются через запятую в одном аргументе: allow= и deny= стоят
 * рядом с бюджетом той же секции, и раскладывать их по отдельным словам
 * означало бы не отличить второй список от третьей опции.
 *
 * У каждого списка есть слово, означающее "правило не действует": для
 * разрешения это "*", для запрета -- "none". Оба дают пустой массив, но
 * пишутся разными словами, потому что читаются по-разному: "*" разрешает всё,
 * "none" не запрещает ничего. Перепутанное слово -- ошибка, а не синоним:
 * "deny=*" почти наверняка означало "off", и молча понять его как "ничего не
 * запрещать" значило бы выдать в базу ровно то, что прятали.
 */
static char *
ngx_http_waf_preview_names(ngx_conf_t *cf, ngx_str_t *directive,
    ngx_str_t *spec, ngx_array_t **list, u_char all)
{
    u_char     *p, *last, c;
    size_t      j;
    ngx_str_t   item, *name;

    if (*list != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V: the list is already set on this level",
                           directive);
        return NGX_CONF_ERROR;
    }

    *list = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (*list == NULL) {
        return NGX_CONF_ERROR;
    }

    if (all == '*') {
        if (spec->len == 1 && spec->data[0] == '*') {
            return NGX_CONF_OK;
        }

    } else if (spec->len == 4 && ngx_strncmp(spec->data, "none", 4) == 0) {
        return NGX_CONF_OK;
    }

    if ((spec->len == 1 && spec->data[0] == '*')
        || (spec->len == 4 && ngx_strncmp(spec->data, "none", 4) == 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V: \"%V\" means an empty section here; say "
                           "\"off\" instead", directive, spec);
        return NGX_CONF_ERROR;
    }

    p    = spec->data;
    last = spec->data + spec->len;

    while (p < last) {

        item.data = p;

        while (p < last && *p != ',') {
            p++;
        }

        item.len = (size_t) (p - item.data);

        if (p < last) {
            p++;                       /* запятая */
        }

        if (item.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%V: empty name in \"%V\"",
                               directive, spec);
            return NGX_CONF_ERROR;
        }

        for (j = 0; j < item.len; j++) {
            c = item.data[j];

            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '-' || c == '_'
                || c == '.')
            {
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%V: \"%V\" is not a name", directive,
                               &item);
            return NGX_CONF_ERROR;
        }

        name = ngx_array_push(*list);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        *name = item;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_preview(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_int_t   rc;
    ngx_str_t  *args;
    ngx_uint_t  ph, phases;

    args = cf->args->elts;

    rc = ngx_http_waf_obj_list(cf, wlcf, NGX_HTTP_WAF_LIST_PREVIEW);
    if (rc == NGX_OK) {
        return NGX_CONF_OK;
    }

    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * Превью есть у каждой фазы, где есть снимок: у запроса, у ответа и у
     * кадра -- срез кадра ложится в ту же body_preview записи, что и срез
     * тела, и по ней же ищется. У кадра нет только reload: оригинала у него
     * нет.
     */
    if (cf->args->nelts >= 3
        && args[2].len == 6
        && ngx_strncmp(args[2].data, "reload", 6) == 0
        && ngx_http_waf_no_reload_in(cf, &args[0], phases) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /*
     * Слоты фазы: строка frame настраивает оба направления. Разбор один и тот
     * же, применений столько, сколько названо слотов.
     */
    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        if (cf->args->nelts >= 3
            && args[2].len == 6
            && ngx_strncmp(args[2].data, "reload", 6) == 0)
        {
            if (ngx_http_waf_preview_reload(cf, &wlcf->shoot[ph])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_http_waf_preview_set(cf, &wlcf->shoot[ph], phases)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * Бюджеты превью в слот одной фазы: разбор аргументов строки и применение.
 */
static char *
ngx_http_waf_preview_set(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t phases)
{
    ngx_str_t  *args, name, value;
    ngx_uint_t  i, bit, obj, seen;

    args = cf->args->elts;
    seen = 0;

    if (cf->args->nelts == 3
        && args[2].len == 4
        && ngx_strncmp(args[2].data, "none", 4) == 0)
    {
        sh->preview_reload = 0;

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            sh->preview[i]              = 0;
            sh->preview_item[i]         = NGX_CONF_UNSET_SIZE;
            sh->preview_reload_limit[i] = NGX_CONF_UNSET_SIZE;
        }

        return NGX_CONF_OK;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview: write the size on the object "
                               "(headers=64k or headers=64k/2k); omitting it "
                               "is no longer allowed");
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_obj_bit(&name, &bit) == NGX_OK) {
            obj = ngx_http_waf_bit_obj(bit);

            /* Словарь объектов у фазы свой: у кадра только body. */
            if (ngx_http_waf_obj_in_phase(cf, &args[0], phases, obj)
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_waf_preview_spec(cf, sh, obj, &value)
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (sh->preview_reload == NGX_CONF_UNSET_UINT) {
                sh->preview_reload = 0;
            }

            seen = 1;
            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "source", 6) == 0) {

            /*
             * source=sent|original: что показать в записи, когда инспектор
             * подменил тело. sent -- доставленную получателю версию, original
             * (умолчание) -- оригинал, как и раньше. Ось у body всех фаз:
             * ответ и кадр подменяет секция rewrite, запрос -- waf_send
             * request body=store, и апстрим получает версию инспектора.
             */
            if (sh->preview_source_sent == NGX_CONF_UNSET_UINT) {
                sh->preview_source_sent = 0;
            }

            if (value.len == 4 && ngx_strncmp(value.data, "sent", 4) == 0) {
                sh->preview_source_sent |=
                    NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY);

            } else if (value.len == 8
                       && ngx_strncmp(value.data, "original", 8) == 0)
            {
                sh->preview_source_sent &=
                    ~NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY);

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_preview: source= is \"sent\" or "
                                   "\"original\", not \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            seen = 1;
            continue;
        }

        if ((name.len == 5 && ngx_strncmp(name.data, "allow", 5) == 0)
            || (name.len == 4 && ngx_strncmp(name.data, "mask", 4) == 0)
            || (name.len == 4 && ngx_strncmp(name.data, "deny", 4) == 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview: allow=, mask= and deny= are "
                               "their own lines (waf_preview request headers "
                               "deny=x-api-key)");
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_preview", &name);
        return NGX_CONF_ERROR;
    }

    if (!seen) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: no objects listed; say \"none\" to "
                           "turn previews off");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_preview_reload(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh)
{
    ssize_t     size;
    ngx_str_t  *args, name, value;
    ngx_uint_t  i, bit, obj, mask;
    size_t      limits[NGX_HTTP_WAF_OBJ_COUNT];

    args = cf->args->elts;
    mask = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        limits[i] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
    }

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {

            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_obj, &args[i],
                                         &bit) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (mask & bit) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_preview: \"%V\" is already listed",
                                   &args[i]);
                return NGX_CONF_ERROR;
            }

            obj = ngx_http_waf_bit_obj(bit);
            mask |= bit;
            limits[obj] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
            continue;
        }

        if (ngx_http_waf_obj_bit(&name, &bit) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown option \"%V\" in waf_preview",
                               &name);
            return NGX_CONF_ERROR;
        }

        if (mask & bit) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview: \"%V\" is already listed",
                               &name);
            return NGX_CONF_ERROR;
        }

        obj = ngx_http_waf_bit_obj(bit);

        if (value.len == 7 && ngx_strncmp(value.data, "capture", 7) == 0) {
            mask |= bit;
            limits[obj] = NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE;
            continue;
        }

        size = ngx_parse_size(&value);

        if (size == NGX_ERROR || size <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview: invalid size \"%V\" for reload "
                               "\"%V\"", &value, &name);
            return NGX_CONF_ERROR;
        }

        mask |= bit;
        limits[obj] = (size_t) size;
    }

    if (mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: reload names no objects");
        return NGX_CONF_ERROR;
    }

    if (sh->preview_reload == NGX_CONF_UNSET_UINT) {
        sh->preview_reload = 0;
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (sh->preview_reload & NGX_HTTP_WAF_OBJ_BIT(i)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview: reload \"%V\" is already "
                               "configured on this level",
                               ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        sh->preview_reload |= NGX_HTTP_WAF_OBJ_BIT(i);
        sh->preview_reload_limit[i] = limits[i];

        if (sh->preview[i] == NGX_CONF_UNSET_SIZE) {
            if (limits[i] == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE
                || limits[i] == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE)
            {
                sh->preview[i] = 1;
            } else {
                sh->preview[i] = limits[i];
            }
        }
    }

    return NGX_CONF_OK;
}


/* --- waf_hold, waf_deadline и waf_body_limit -------------------------------
 *
 *     waf_hold       <фаза> gate|monitor;
 *     waf_deadline   <фаза> <time> [pass|block];
 *     waf_body_limit <фаза> <size> [pass|block|trim];
 *
 * Мера и политика одной строкой. Фаза -- первое слово, и строка "frame"
 * настраивает оба направления сразу.
 */
char *
ngx_http_waf_hold(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args = cf->args->elts;
    ngx_uint_t   phase, phases, hold;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(phase))
            && wlcf->hold[phase] != NGX_CONF_UNSET_UINT)
        {
            return "is duplicate";
        }
    }

    if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_hold, &args[2], &hold)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /*
     * Отпущенный запрос -- это не наблюдение, а отсутствие фазы: вердикт
     * приезжает, когда применять его уже некуда. Наблюдение без гейта
     * называется mode=passive и настраивается на вызове инспектора.
     */
    if (hold == NGX_HTTP_WAF_HOLD_MONITOR
        && (phases & NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_hold: the request phase is always gate; "
                           "for watching without gating write mode=passive "
                           "on waf_inspect");
        return NGX_CONF_ERROR;
    }

    /*
     * monitor на кадрах клиента -- несколько кадров в полёте на одно
     * соединение, а машина слотов держит один. Принять и исполнять как gate
     * значило бы молча удерживать то, что просили не держать.
     */
    if (hold == NGX_HTTP_WAF_HOLD_MONITOR
        && (phases & NGX_HTTP_WAF_PH_FRAME))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_hold: monitor on frames is not "
                           "implemented yet; both directions run as gate");
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if (phases & NGX_HTTP_WAF_PH_BIT(phase)) {
            wlcf->hold[phase] = hold;
        }
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_deadline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args = cf->args->elts;
    ngx_msec_t   msec;
    ngx_uint_t   phase, phases;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(phase))
            && wlcf->deadline[phase] != NGX_CONF_UNSET_MSEC)
        {
            return "is duplicate";
        }
    }

    msec = ngx_parse_time(&args[2], 0);

    if (msec == (ngx_msec_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V: invalid budget \"%V\"", &args[0], &args[2]);
        return NGX_CONF_ERROR;
    }

    /*
     * Политика вторым словом снята: что делать с пропущенным дедлайном,
     * говорит waf_exception <фаза> timeout pass|deny. Бюджет и исход -- разные
     * вопросы, и держать исход в хвосте бюджета значило бы, что у одного
     * класса события рычаг свой, а у трёх остальных общий.
     */
    if (cf->args->nelts > 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V: \"%V\" is not a budget; the policy moved to "
                           "\"waf_exception %V timeout pass|deny\"",
                           &args[0], &args[3], &args[1]);
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (phases & NGX_HTTP_WAF_PH_BIT(phase)) {
            wlcf->deadline[phase] = msec;
        }
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_body_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ssize_t      size;
    ngx_str_t   *args = cf->args->elts;
    ngx_uint_t   phase, phases, policy, policy_set;

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(phase))
            && wlcf->body_limit[phase] != NGX_CONF_UNSET_SIZE)
        {
            return "is duplicate";
        }
    }

    size = ngx_parse_size(&args[2]);

    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_body_limit: invalid size \"%V\"", &args[2]);
        return NGX_CONF_ERROR;
    }

    policy     = NGX_CONF_UNSET_UINT;
    policy_set = 0;

    if (cf->args->nelts > 3) {

        if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_body_policy, &args[3],
                                     &policy) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        policy_set = 1;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(phase))) {
            continue;
        }

        wlcf->body_limit[phase] = (size_t) size;

        if (policy_set) {
            wlcf->body_limit_policy[phase] = policy;
        }
    }

    return NGX_CONF_OK;
}


/* --- waf_var -------------------------------------------------------------- */

/*
 * Стандартный набор: поля, которых у сообщения нет своих и которые нужны
 * почти каждому, кто профилирует клиента. Только ядро nginx: $http_* читает
 * любой заголовок, $content_type и $request_id -- ngx_http_core. Ничего из
 * ngx_http_ssl_module: без TLS такой переменной нет вовсе, и nginx -t падал
 * бы на конфигурации, где ssl не собран.
 *
 * Cookie и Authorization сюда не попадут никогда: к заголовкам в обменнике
 * маршрут применяет mask= и deny=, а секция vars едет инлайном мимо них.
 */
static struct {
    ngx_str_t  name;
    ngx_str_t  value;
} ngx_http_waf_std_vars[NGX_HTTP_WAF_STD_VARS] = {
    { ngx_string("user_agent"),      ngx_string("$http_user_agent")      },
    { ngx_string("referer"),         ngx_string("$http_referer")         },
    { ngx_string("xff"),             ngx_string("$http_x_forwarded_for") },
    { ngx_string("accept_language"), ngx_string("$http_accept_language") },
    { ngx_string("origin"),          ngx_string("$http_origin")          },
    { ngx_string("content_type"),    ngx_string("$content_type")         },
    { ngx_string("accept"),          ngx_string("$http_accept")          },
    { ngx_string("request_id"),      ngx_string("$request_id")           },
};


static ngx_int_t
ngx_http_waf_std_var_find(ngx_str_t *name)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_STD_VARS; i++) {
        if (ngx_http_waf_std_vars[i].name.len == name->len
            && ngx_strncmp(ngx_http_waf_std_vars[i].name.data, name->data,
                           name->len) == 0)
        {
            return (ngx_int_t) i;
        }
    }

    return NGX_ERROR;
}


char *
ngx_http_waf_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_str_t                        *args;
    ngx_uint_t                        i;
    ngx_http_waf_var_t               *var;
    ngx_http_compile_complex_value_t  ccv;

    args = cf->args->elts;

    /*
     * Имя едет ключом в JSON и токеном в строке лога. Разбирать потом кавычки
     * и пробелы в имени поля никто не станет, поэтому набор символов сужен до
     * того, что переживает оба формата без экранирования.
     */
    for (i = 0; i < args[1].len; i++) {
        u_char  c = args[1].data[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')
        {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid waf_var name \"%V\": only letters, "
                           "digits and \"_.-\" are allowed", &args[1]);
        return NGX_CONF_ERROR;
    }

    /*
     * Имя стандартного поля занято: оно едет само, и второй источник под тем
     * же ключом означал бы, что одно и то же имя в аудите значит разное на
     * разных узлах.
     */
    if (ngx_http_waf_std_var_find(&args[1]) != NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: \"%V\" is a built-in field and is sent as "
                           "is; pick another waf_var name", &args[1]);
        return NGX_CONF_ERROR;
    }

    if (wmcf->vars == NULL) {
        wmcf->vars = ngx_array_create(cf->pool, 4,
                                      sizeof(ngx_http_waf_var_t));
        if (wmcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    var = wmcf->vars->elts;

    for (i = 0; i < wmcf->vars->nelts; i++) {
        if (var[i].name.len == args[1].len
            && ngx_strncmp(var[i].name.data, args[1].data, args[1].len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: duplicate waf_var \"%V\"", &args[1]);
            return NGX_CONF_ERROR;
        }
    }

    if (wmcf->vars->nelts >= NGX_HTTP_WAF_MAX_VARS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: too many waf_var, maximum is %d",
                           NGX_HTTP_WAF_MAX_VARS);
        return NGX_CONF_ERROR;
    }

    var = ngx_array_push(wmcf->vars);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(var, sizeof(ngx_http_waf_var_t));

    var->name = args[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf            = cf;
    ccv.value         = &args[2];
    ccv.complex_value = &var->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * vars= объявления в маску. Слова через запятую: имена полей набора либо
 * "all". Незнакомое слово -- ошибка, а не пропуск: опечатка в имени молча
 * оставила бы инспектора без поля, на которое он рассчитывает.
 */
static ngx_int_t
ngx_http_waf_vars_mask(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_inspector_t *insp)
{
    u_char              *p, *last, *comma;
    ngx_str_t            word;
    ngx_uint_t           i, n;
    ngx_http_waf_var_t  *var;

    var = wmcf->vars->elts;
    n   = wmcf->vars->nelts;

    p    = insp->vars_spec.data;
    last = insp->vars_spec.data + insp->vars_spec.len;

    while (p < last) {
        comma = ngx_strlchr(p, last, ',');

        word.data = p;
        word.len  = (comma == NULL ? last : comma) - p;
        p         = (comma == NULL) ? last : comma + 1;

        if (word.len == 0) {
            continue;
        }

        if (word.len == 3 && ngx_strncmp(word.data, "all", 3) == 0) {
            insp->vars_mask |= ((ngx_uint_t) 1 << n) - 1;
            continue;
        }

        for (i = 0; i < n; i++) {
            if (var[i].name.len == word.len
                && ngx_strncmp(var[i].name.data, word.data, word.len) == 0)
            {
                insp->vars_mask |= (ngx_uint_t) 1 << i;
                break;
            }
        }

        if (i == n) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown field \"%V\" in vars= of "
                               "inspector \"%V\"; expected a built-in field, "
                               "a waf_var name or \"all\"",
                               &word, &insp->name);
            return NGX_ERROR;
        }
    }

    if (insp->vars_mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: empty vars= on inspector \"%V\"; drop the "
                           "option to send no fields", &insp->name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


char *
ngx_http_waf_vars_init(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf)
{
    ngx_uint_t                        i, n;
    ngx_array_t                      *vars;
    ngx_http_waf_var_t               *var, *own;
    ngx_http_waf_inspector_t         *insp;
    ngx_http_compile_complex_value_t  ccv;

    n = (wmcf->vars != NULL) ? wmcf->vars->nelts : 0;

    vars = ngx_array_create(cf->pool, NGX_HTTP_WAF_STD_VARS + n,
                            sizeof(ngx_http_waf_var_t));
    if (vars == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * Стандартный набор компилируется здесь, а не при создании main conf: в
     * create_main_conf cf->ctx ещё не указывает на http {}, и переменные
     * ядра там не найти.
     */
    for (i = 0; i < NGX_HTTP_WAF_STD_VARS; i++) {
        var = ngx_array_push(vars);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(var, sizeof(ngx_http_waf_var_t));

        var->name    = ngx_http_waf_std_vars[i].name;
        var->builtin = 1;

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf            = cf;
        ccv.value         = &ngx_http_waf_std_vars[i].value;
        ccv.complex_value = &var->value;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (n != 0) {
        own = wmcf->vars->elts;

        for (i = 0; i < n; i++) {
            var = ngx_array_push(vars);
            if (var == NULL) {
                return NGX_CONF_ERROR;
            }

            *var = own[i];
        }
    }

    wmcf->vars = vars;

    insp = wmcf->inspectors.elts;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        if (insp[i].vars_spec.len == 0) {
            continue;
        }

        if (ngx_http_waf_vars_mask(cf, wmcf, &insp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/* --- waf_bus -------------------------------------------------------------- */

char *
ngx_http_waf_bus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_str_t   *args, name, value, host;
    ngx_url_t    u;
    ngx_addr_t  *addr;
    ngx_uint_t   i, j;
    u_char      *p, *last;

    args = cf->args->elts;

    if (wmcf->bus_servers != NULL) {
        return "is duplicate";
    }

    wmcf->bus_servers = ngx_array_create(cf->pool, 2, sizeof(ngx_addr_t));
    if (wmcf->bus_servers == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * Адреса разрешаются при загрузке конфигурации, а не при подключении:
     * воркеру резолвер недоступен, а откладывать разрешение имени до первого
     * запроса значит добавлять блокирующий getaddrinfo в цикл событий.
     */
    p    = args[1].data;
    last = args[1].data + args[1].len;

    while (p < last) {
        host.data = p;

        while (p < last && *p != ',') {
            p++;
        }

        host.len = (size_t) (p - host.data);

        if (p < last) {
            p++;                                   /* запятая */
        }

        if (host.len > 7 && ngx_strncmp(host.data, "nats://", 7) == 0) {
            host.data += 7;
            host.len  -= 7;
        }

        if (host.len == 0) {
            continue;
        }

        ngx_memzero(&u, sizeof(ngx_url_t));

        u.url           = host;
        u.default_port  = 4222;
        u.no_resolve    = 0;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: %s in bus address \"%V\"",
                               u.err ? u.err : "error", &host);
            return NGX_CONF_ERROR;
        }

        for (j = 0; j < u.naddrs; j++) {
            addr = ngx_array_push(wmcf->bus_servers);
            if (addr == NULL) {
                return NGX_CONF_ERROR;
            }

            *addr = u.addrs[j];
        }
    }

    if (wmcf->bus_servers->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_bus has no usable address");
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in waf_bus",
                               &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "name", 4) == 0) {
            wmcf->bus_name = value;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "user", 4) == 0) {
            wmcf->bus_user = value;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "pass", 4) == 0) {
            wmcf->bus_pass = value;
            continue;
        }

        if (name.len == 5 && ngx_strncmp(name.data, "token", 5) == 0) {
            wmcf->bus_token = value;
            continue;
        }

        if (name.len == 15
            && ngx_strncmp(name.data, "connect_timeout", 15) == 0)
        {
            wmcf->bus_connect_timeout = ngx_parse_time(&value, 0);
            continue;
        }

        if (name.len == 14
            && ngx_strncmp(name.data, "reconnect_wait", 14) == 0)
        {
            wmcf->bus_reconnect_wait = ngx_parse_time(&value, 0);
            continue;
        }

        if (name.len == 13 && ngx_strncmp(name.data, "ping_interval", 13) == 0) {
            wmcf->bus_ping_interval = ngx_parse_time(&value, 0);
            continue;
        }

        if (name.len == 11 && ngx_strncmp(name.data, "pending_max", 11) == 0) {
            wmcf->bus_pending_max = ngx_parse_size(&value);
            if (wmcf->bus_pending_max == (size_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid pending_max \"%V\"", &value);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (name.len == 11 && ngx_strncmp(name.data, "payload_max", 11) == 0) {
            wmcf->bus_payload_max = ngx_parse_size(&value);
            if (wmcf->bus_payload_max == (size_t) NGX_ERROR
                || wmcf->bus_payload_max == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid payload_max \"%V\"", &value);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        /*
         * TLS и credentials объявлены спецификацией, но не реализованы: молча
         * игнорировать их нельзя -- конфигурация выглядела бы защищённой,
         * оставаясь открытой.
         */
        if ((name.len == 3 && ngx_strncmp(name.data, "tls", 3) == 0)
            || (name.len > 4 && ngx_strncmp(name.data, "tls_", 4) == 0)
            || (name.len == 5 && ngx_strncmp(name.data, "creds", 5) == 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_bus option \"%V\" is not implemented "
                               "yet", &name);
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_bus", &name);
        return NGX_CONF_ERROR;
    }

    wmcf->bus = ngx_http_waf_bus_nats_create(cf);
    if (wmcf->bus == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* --- разбор значений ------------------------------------------------------ */

ngx_int_t
ngx_http_waf_split(ngx_str_t *arg, ngx_str_t *name, ngx_str_t *value)
{
    u_char  *p;

    p = ngx_strlchr(arg->data, arg->data + arg->len, '=');

    if (p == NULL) {
        return NGX_ERROR;
    }

    name->data  = arg->data;
    name->len   = (size_t) (p - arg->data);

    value->data = p + 1;
    value->len  = (size_t) (arg->data + arg->len - p - 1);

    if (name->len == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_kw_lookup(ngx_http_waf_kw_t *kw, ngx_str_t *value,
    ngx_uint_t *out)
{
    ngx_uint_t  i;

    for (i = 0; kw[i].name.len != 0; i++) {
        if (kw[i].name.len == value->len
            && ngx_strncmp(kw[i].name.data, value->data, value->len) == 0)
        {
            *out = kw[i].value;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


/*
 * То же со строкой в лог. Тихий вариант нужен там, где слово необязательно и
 * его отсутствие -- не ошибка: класс у waf_exception.
 */
static ngx_int_t
ngx_http_waf_opt_keyword(ngx_conf_t *cf, ngx_http_waf_kw_t *kw,
    ngx_str_t *value, ngx_uint_t *out)
{
    if (ngx_http_waf_kw_lookup(kw, value, out) == NGX_OK) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: invalid value \"%V\"",
                       value);

    return NGX_ERROR;
}


/*
 * Список ключевых слов через запятую в битовую маску. Слово "none" даёт
 * пустую маску и потому не смешивается с остальными: "none,body" -- это не
 * уточнение, а противоречие, и молча выбирать одну из половин хуже, чем
 * отказаться грузиться.
 */
static ngx_int_t
ngx_http_waf_opt_flags(ngx_conf_t *cf, ngx_http_waf_kw_t *kw, ngx_str_t *value,
    ngx_uint_t *out)
{
    ngx_str_t   item;
    u_char     *p, *last;
    ngx_uint_t  bit, mask, none;

    mask = 0;
    none = 0;
    p    = value->data;
    last = value->data + value->len;

    while (p < last) {
        item.data = p;

        while (p < last && *p != ',') {
            p++;
        }

        item.len = (size_t) (p - item.data);

        if (p < last) {
            p++;
        }

        if (item.len == 0) {
            continue;
        }

        if ((item.len == 4 && ngx_strncmp(item.data, "none", 4) == 0)
            || (item.len == 3 && ngx_strncmp(item.data, "off", 3) == 0))
        {
            none = 1;
            continue;
        }

        if (ngx_http_waf_opt_keyword(cf, kw, &item, &bit) != NGX_OK) {
            return NGX_ERROR;
        }

        mask |= bit;
    }

    if (none && mask != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: \"%V\" mixes none with named items", value);
        return NGX_ERROR;
    }

    *out = mask;

    return NGX_OK;
}


/*
 * Дробное значение конфигурации в целое с фиксированной точкой: 0.5 при
 * scale=1000 даёт 500. Никаких double: вес и доли участвуют в вычислениях на
 * горячем пути, а плавающая арифметика там означала бы разные решения на
 * разных сборках.
 */
static ngx_int_t
ngx_http_waf_opt_fraction(ngx_conf_t *cf, ngx_str_t *value, ngx_uint_t scale,
    ngx_uint_t max, ngx_uint_t *out)
{
    u_char      c;
    size_t      i;
    ngx_uint_t  whole, frac, div;

    whole = 0;
    frac  = 0;
    div   = 1;

    for (i = 0; i < value->len; i++) {
        c = value->data[i];

        if (c == '.') {
            i++;
            break;
        }

        if (c < '0' || c > '9') {
            goto invalid;
        }

        whole = whole * 10 + (ngx_uint_t) (c - '0');

        if (whole > max) {
            goto invalid;
        }
    }

    for ( /* void */ ; i < value->len; i++) {
        c = value->data[i];

        if (c < '0' || c > '9') {
            goto invalid;
        }

        if (div * 10 > scale) {
            continue;                      /* лишние разряды отбрасываются */
        }

        frac = frac * 10 + (ngx_uint_t) (c - '0');
        div *= 10;
    }

    *out = whole * scale + frac * (scale / div);

    if (*out > max) {
        goto invalid;
    }

    return NGX_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: invalid fractional value \"%V\"", value);

    return NGX_ERROR;
}




/* --- рукопожатие websocket-пути -------------------------------------------- */

/*
 * waf_require_upgrade on|off [response=<name>];
 *
 * Путь, объявленный под WebSocket, обычный GET получать не должен: без
 * `Upgrade: websocket` запрос отказывается локальным слоем, до шины не
 * доходя. Запись отказа -- своя (426 в каталоге контроллера), иначе умолчание.
 */
char *
ngx_http_waf_require_upgrade(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value;
    ngx_uint_t   i;

    args = cf->args->elts;

    if (wlcf->require_upgrade != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (args[1].len == 2 && ngx_strncmp(args[1].data, "on", 2) == 0) {
        wlcf->require_upgrade = 1;

    } else if (args[1].len == 3 && ngx_strncmp(args[1].data, "off", 3) == 0) {
        wlcf->require_upgrade = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_require_upgrade: expected on or off, got \"%V\"",
                           &args[1]);
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK
            || name.len != 8 || ngx_strncmp(name.data, "response", 8) != 0
            || value.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_require_upgrade: unknown option \"%V\"; "
                               "only response=<name>", &args[i]);
            return NGX_CONF_ERROR;
        }

        wlcf->require_upgrade_response = value;
    }

    return NGX_CONF_OK;
}


/*
 * waf_ws_strip_extensions <name> [<name>...] | all | off;
 *
 * Снимает названные расширения из Sec-WebSocket-Extensions рукопожатия, и
 * приложение их не согласует. Согласованное расширение -- это кадры с
 * rsv-битами (permessage-deflate -- сжатые), которые обработчик кадров не
 * разбирает; не дать согласовать дешевле, чем распаковывать в воркере.
 */
char *
ngx_http_waf_ws_strip_extensions(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, *item;
    ngx_uint_t   i;

    args = cf->args->elts;

    if (wlcf->ws_strip_ext != NULL) {
        return "is duplicate";
    }

    wlcf->ws_strip_ext = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                          sizeof(ngx_str_t));
    if (wlcf->ws_strip_ext == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2
        && args[1].len == 3 && ngx_strncmp(args[1].data, "off", 3) == 0)
    {
        return NGX_CONF_OK;            /* пустой массив: снято здесь */
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (args[i].len == 0 || ngx_strlchr(args[i].data,
                                            args[i].data + args[i].len, ',')
            || ngx_strlchr(args[i].data, args[i].data + args[i].len, ';'))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_ws_strip_extensions: \"%V\" is not an "
                               "extension name; one name per word", &args[i]);
            return NGX_CONF_ERROR;
        }

        item = ngx_array_push(wlcf->ws_strip_ext);
        if (item == NULL) {
            return NGX_CONF_ERROR;
        }

        *item = args[i];
    }

    return NGX_CONF_OK;
}


/*
 * waf_audit_frames off|deny|all [sample=<n>];
 *
 * Запись на каждый кадр по объёму сопоставима с трафиком, поэтому умолчание
 * -- deny: кадр с отказом, подменой или счётом. all пишет каждый sample-й
 * спрошенный кадр (по номеру кадра, а не случайно: поток кадров одного
 * соединения выбирается ровно). Запись на сессию при закрытии -- всегда,
 * кроме off.
 */
char *
ngx_http_waf_audit_frames(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value;
    ngx_int_t    n;
    ngx_uint_t   i;

    args = cf->args->elts;

    if (wlcf->audit_frames != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (args[1].len == 3 && ngx_strncmp(args[1].data, "off", 3) == 0) {
        wlcf->audit_frames = NGX_HTTP_WAF_AUDIT_FRAMES_OFF;

    } else if (args[1].len == 4 && ngx_strncmp(args[1].data, "deny", 4) == 0) {
        wlcf->audit_frames = NGX_HTTP_WAF_AUDIT_FRAMES_DENY;

    } else if (args[1].len == 3 && ngx_strncmp(args[1].data, "all", 3) == 0) {
        wlcf->audit_frames = NGX_HTTP_WAF_AUDIT_FRAMES_ALL;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_audit_frames: expected off, deny or all, "
                           "got \"%V\"", &args[1]);
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK
            || name.len != 6 || ngx_strncmp(name.data, "sample", 6) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_audit_frames: unknown option \"%V\"; "
                               "only sample=<n>", &args[i]);
            return NGX_CONF_ERROR;
        }

        n = ngx_atoi(value.data, value.len);

        if (n == NGX_ERROR || n < 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_audit_frames: sample=%V is not a positive "
                               "number", &value);
            return NGX_CONF_ERROR;
        }

        if (wlcf->audit_frames != NGX_HTTP_WAF_AUDIT_FRAMES_ALL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_audit_frames: sample= is only for all");
            return NGX_CONF_ERROR;
        }

        wlcf->audit_frames_sample = (ngx_uint_t) n;
    }

    return NGX_CONF_OK;
}


/*
 * waf_frame_control_rate <n>r/s|<n>r/m|off;
 *
 * Ping и pong сверх частоты не пересылаются. Единица обязательна по той же
 * причине, что у waf_local_rate: голое число неоднозначно. Хранится в
 * тысячных кадра в секунду; off -- ноль.
 */
char *
ngx_http_waf_frame_control_rate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, digits;
    ngx_int_t    n;
    ngx_uint_t   scale;

    args = cf->args->elts;

    if (wlcf->frame_control_rate != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (args[1].len == 3 && ngx_strncmp(args[1].data, "off", 3) == 0) {
        wlcf->frame_control_rate = 0;
        return NGX_CONF_OK;
    }

    digits = args[1];

    if (digits.len > 3
        && ngx_strncmp(digits.data + digits.len - 3, "r/s", 3) == 0)
    {
        scale = 1;

    } else if (digits.len > 3
               && ngx_strncmp(digits.data + digits.len - 3, "r/m", 3) == 0)
    {
        scale = 60;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_frame_control_rate: expected <n>r/s, <n>r/m "
                           "or off, got \"%V\"", &args[1]);
        return NGX_CONF_ERROR;
    }

    digits.len -= 3;

    n = ngx_atoi(digits.data, digits.len);

    if (n == NGX_ERROR || n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_frame_control_rate: invalid rate \"%V\"",
                           &args[1]);
        return NGX_CONF_ERROR;
    }

    wlcf->frame_control_rate = (ngx_uint_t) n * 1000 / scale;

    if (wlcf->frame_control_rate == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_frame_control_rate: \"%V\" rounds down to "
                           "zero", &args[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_frame_cache frame|frame:c2s|frame:s2c ttl=<time>;
 * waf_frame_cache off;
 *
 * Кеш вердикта по хешу полезной нагрузки, на сторону кадра. Только кадры:
 * запрос и ответ одинаковыми не бывают настолько, чтобы это окупалось, а
 * их вердикт зависит от заголовков и адреса, которых в ключе нет. Зона
 * обязательна: таблица общая для воркеров. Срок ограничен часом -- дольше
 * память о том, что кадр был чист, стоит меньше, чем риск, что правила
 * изменились.
 */
char *
ngx_http_waf_frame_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t                 *args, name, value;
    ngx_int_t                  ttl;
    ngx_uint_t                 i, ph, phases;
    ngx_http_waf_main_conf_t  *wmcf;

    args = cf->args->elts;

    if (cf->args->nelts == 2
        && args[1].len == 3 && ngx_strncmp(args[1].data, "off", 3) == 0)
    {
        for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {
            if (!(NGX_HTTP_WAF_PH_FRAME & NGX_HTTP_WAF_PH_BIT(ph))) {
                continue;
            }

            if (wlcf->frame_cache_ttl[ph] != NGX_CONF_UNSET_MSEC) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_frame_cache off cannot mix with a "
                                   "cache on the same level");
                return NGX_CONF_ERROR;
            }

            wlcf->frame_cache_ttl[ph] = 0;
        }

        return NGX_CONF_OK;
    }

    if (ngx_http_waf_arg_phase(cf, &args[1], &phases) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (phases & ~NGX_HTTP_WAF_PH_FRAME) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_frame_cache: only frames are cached; write "
                           "frame, frame:c2s or frame:s2c");
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_shm_required(cf, "waf_frame_cache") != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ttl = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK
            || name.len != 3 || ngx_strncmp(name.data, "ttl", 3) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_frame_cache: unknown option \"%V\"; "
                               "only ttl=<time>", &args[i]);
            return NGX_CONF_ERROR;
        }

        ttl = ngx_parse_time(&value, 0);

        if (ttl == NGX_ERROR || ttl <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_frame_cache: invalid ttl \"%V\"", &value);
            return NGX_CONF_ERROR;
        }

        if (ttl > 3600000) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_frame_cache: ttl=%V is longer than an "
                               "hour", &value);
            return NGX_CONF_ERROR;
        }
    }

    if (ttl == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_frame_cache requires ttl=<time>");
        return NGX_CONF_ERROR;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        if (wlcf->frame_cache_ttl[ph] != NGX_CONF_UNSET_MSEC) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_frame_cache: %V is already set on this "
                               "level", ngx_http_waf_phase_name(ph));
            return NGX_CONF_ERROR;
        }

        wlcf->frame_cache_ttl[ph] = (ngx_msec_t) ttl;
    }

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    wmcf->frame_cache_used = 1;

    ngx_http_waf_fcache_want(1);

    return NGX_CONF_OK;
}
