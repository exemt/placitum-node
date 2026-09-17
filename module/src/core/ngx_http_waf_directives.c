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
static ngx_int_t ngx_http_waf_opt_msec(ngx_conf_t *cf, const char *what,
    ngx_str_t *value, ngx_msec_t *out);
static char *ngx_http_waf_preview_names(ngx_conf_t *cf, ngx_str_t *directive,
    ngx_str_t *spec, ngx_array_t **list, u_char all);
static char *ngx_http_waf_preview_set(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t phases, ngx_uint_t phase);
static char *ngx_http_waf_preview_spec(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t obj, ngx_str_t *spec);
static void ngx_http_waf_capture_none(ngx_http_waf_shoot_conf_t *sh);
static ngx_int_t ngx_http_waf_obj_list(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t kind);
static void ngx_http_waf_archive_reset(ngx_http_waf_shoot_conf_t *sh);
static char *ngx_http_waf_archive_apply(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t mask, ngx_uint_t off,
    ngx_uint_t when, time_t ttl, size_t *limits);
static ngx_int_t ngx_http_waf_arg_phase(ngx_conf_t *cf, ngx_str_t *arg,
    ngx_uint_t *phases);
static char *ngx_http_waf_obj_in_phase(ngx_conf_t *cf, ngx_str_t *dir,
    ngx_uint_t phases, ngx_uint_t obj);
static ngx_uint_t ngx_http_waf_shoot_named(ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t kind);
static ngx_uint_t ngx_http_waf_shoot_cleared(ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t kind);
static char *ngx_http_waf_none_mix(ngx_conf_t *cf, ngx_str_t *dir,
    ngx_uint_t phase);


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


static ngx_http_waf_kw_t  ngx_http_waf_kw_obj[] = {
    { ngx_string("headers"),
      NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS) },
    { ngx_string("args"), NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS) },
    { ngx_string("body"), NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY) },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_source[] = {
    { ngx_string("original"), NGX_HTTP_WAF_SOURCE_ORIGINAL },
    { ngx_string("sent"),     NGX_HTTP_WAF_SOURCE_SENT     },
    { ngx_null_string, 0 }
};


static ngx_http_waf_kw_t  ngx_http_waf_kw_archive_when[] = {
    { ngx_string("allow"), 1u << NGX_HTTP_WAF_V_ALLOW },
    { ngx_string("deny"),  1u << NGX_HTTP_WAF_V_DENY  },
    { ngx_null_string, 0 }
};


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

    sh->archive_set     = 0;
    sh->archive_cleared = 1;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        sh->archive_when[i]  = NGX_CONF_UNSET_UINT;
        sh->archive_ttl[i]   = NGX_CONF_UNSET;
        sh->archive_limit[i] = NGX_CONF_UNSET_SIZE;
    }

    ngx_memzero(sh->lists[NGX_HTTP_WAF_LIST_ARCHIVE],
                sizeof(sh->lists[NGX_HTTP_WAF_LIST_ARCHIVE]));
}


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
        || ngx_http_waf_kw_lookup(ngx_http_waf_kw_obj, &args[2], &bit)
           != NGX_OK
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

    obj = ngx_http_waf_lowest_bit(bit);

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

        if (ngx_http_waf_shoot_cleared(&wlcf->shoot[ph], kind)) {
            (void) ngx_http_waf_none_mix(cf, &args[0], ph);
            return NGX_ERROR;
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
ngx_http_waf_arg_phase(ngx_conf_t *cf, ngx_str_t *arg, ngx_uint_t *phases)
{
    if (ngx_http_waf_kw_lookup(ngx_http_waf_kw_phase, arg, phases) == NGX_OK) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: write request, response, frame, frame:c2s or "
                       "frame:s2c as the first word; \"%V\" is not a phase",
                       arg);
    return NGX_ERROR;
}


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


static ngx_uint_t
ngx_http_waf_shoot_named(ngx_http_waf_shoot_conf_t *sh, ngx_uint_t kind)
{
    ngx_uint_t  obj, axis;

    switch (kind) {

    case NGX_HTTP_WAF_LIST_CAPTURE:
        if (sh->capture_set != 0) {
            return 1;
        }

        break;

    case NGX_HTTP_WAF_LIST_ARCHIVE:
        if (sh->archive_set != 0) {
            return 1;
        }

        break;

    default:
        for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {
            if (sh->preview[obj] != NGX_CONF_UNSET_SIZE) {
                return 1;
            }
        }

        break;
    }

    for (obj = 0; obj < NGX_HTTP_WAF_META_COUNT; obj++) {
        for (axis = 0; axis < NGX_HTTP_WAF_AXIS_COUNT; axis++) {
            if (sh->lists[kind][obj][axis] != NULL) {
                return 1;
            }
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_waf_shoot_cleared(ngx_http_waf_shoot_conf_t *sh, ngx_uint_t kind)
{
    switch (kind) {

    case NGX_HTTP_WAF_LIST_CAPTURE:
        return sh->capture_cleared;

    case NGX_HTTP_WAF_LIST_ARCHIVE:
        return sh->archive_cleared;

    default:
        return sh->preview_cleared;
    }
}


static char *
ngx_http_waf_none_mix(ngx_conf_t *cf, ngx_str_t *dir, ngx_uint_t phase)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "%V %V none cannot be combined with other %V %V "
                       "lines on the same level",
                       dir, ngx_http_waf_phase_name(phase),
                       dir, ngx_http_waf_phase_name(phase));
    return NGX_CONF_ERROR;
}


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


char *
ngx_http_waf_inspector(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_str_t                 *args, name, value;
    ngx_uint_t                 i, audit_set, flag;
    ngx_http_waf_inspector_t  *insp;

    args      = cf->args->elts;
    audit_set = 0;

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
            continue;
        }

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
            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_flag, &value,
                                         &flag)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            insp->breaker = flag ? 1 : 0;
            insp->breaker_named |= insp->breaker;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "vars", 4) == 0) {
            if (value.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: empty vars= on inspector \"%V\"; "
                                   "drop the option to send no fields",
                                   &insp->name);
                return NGX_CONF_ERROR;
            }

            insp->vars_spec = value;
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

            insp->breaker_named = 1;
            continue;
        }

        if (name.len == 14 && ngx_strncmp(name.data, "breaker_window", 14) == 0) {
            if (ngx_http_waf_opt_msec(cf, "breaker_window", &value,
                                      &insp->breaker_window)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            insp->breaker_named = 1;
            continue;
        }

        if (name.len == 13 && ngx_strncmp(name.data, "breaker_probe", 13) == 0) {
            if (ngx_http_waf_opt_msec(cf, "breaker_probe", &value,
                                      &insp->breaker_probe)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            insp->breaker_named = 1;
            continue;
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

    ngx_memzero(&b, sizeof(ngx_http_waf_binding_t));

    b.name    = args[2];
    b.index   = insp->index;
    b.timeout = 0;
    b.mode    = NGX_HTTP_WAF_MODE_ACTIVE;
    b.resume  = NGX_HTTP_WAF_RESUME_OFF;
    wave_set  = 0;

    for (i = 3; i < cf->args->nelts; i++) {
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

    if (b.resume != NGX_HTTP_WAF_RESUME_OFF
        && (phases & NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: resume= belongs to the phase that consumes "
                           "the continuation (response), not to request");
        return NGX_CONF_ERROR;
    }

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
            if (n == NGX_ERROR
                || !((n >= 1000 && n <= 1003) || (n >= 1007 && n <= 1014)
                     || (n >= 3000 && n <= 4999)))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid close code \"%V\", expected "
                                   "1000-1003, 1007-1014 or 3000-4999",
                                   &value);
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

        allow->path.data = p;
        allow->path.len  = (size_t) (last - p);
    }

    return NGX_CONF_OK;
}


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

    ngx_str_set(&page, "");

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

        wlcf->score_deny[phase]          = n;
        wlcf->score_deny_response[phase] = page;
        wlcf->named[phase]              |= NGX_HTTP_WAF_NAMED_SCORE_DENY;
    }

    return NGX_CONF_OK;
}


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

    ngx_str_set(&page, "");

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

            wlcf->exception[ph][exc]          = policy;
            wlcf->exception_response[ph][exc] = page;
            wlcf->named[ph] |= NGX_HTTP_WAF_NAMED_EXCEPTION(exc);
        }
    }

    return NGX_CONF_OK;
}


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

        if (ngx_http_waf_kw_lookup(ngx_http_waf_kw_obj, &name, &bit)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown option \"%V\" in waf_send",
                               &name);
            return NGX_CONF_ERROR;
        }

        obj = ngx_http_waf_lowest_bit(bit);

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

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {

            if (!(seen & NGX_HTTP_WAF_OBJ_BIT(obj))) {
                continue;
            }

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
            wlcf->named[phase]    |= NGX_HTTP_WAF_NAMED_DENY_MODE;
        }
    }

    return NGX_CONF_OK;
}


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

                    if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
                        continue;
                    }

                    sh = &wlcf->shoot[ph];

                    if (!sh->capture_cleared
                        && ngx_http_waf_shoot_named(sh,
                                                    NGX_HTTP_WAF_LIST_CAPTURE))
                    {
                        return ngx_http_waf_none_mix(cf, &args[0], ph);
                    }

                    ngx_http_waf_capture_none(sh);
                }

                return NGX_CONF_OK;
            }

            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_obj, &args[i],
                                         &bit) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_waf_obj_in_phase(cf, &args[0], phases,
                                          ngx_http_waf_lowest_bit(bit))
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

        if (ngx_http_waf_kw_lookup(ngx_http_waf_kw_obj, &name, &bit)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: unknown option \"%V\" in waf_capture",
                               &name);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_obj_in_phase(cf, &args[0], phases,
                                      ngx_http_waf_lowest_bit(bit))
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

        obj = ngx_http_waf_lowest_bit(bit);
        mask |= bit;
        limits[obj] = (size_t) size;
    }

    if (mask == 0 && off == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_capture: no objects listed; say \"off\" to "
                           "turn capture off");
        return NGX_CONF_ERROR;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        sh = &wlcf->shoot[ph];

        if (sh->capture_cleared) {
            return ngx_http_waf_none_mix(cf, &args[0], ph);
        }

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

    if (cf->args->nelts >= 3
        && args[2].len == 6
        && ngx_strncmp(args[2].data, "reload", 6) == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_archive: \"reload\" is gone; write the size "
                           "on the object (body=64k) and name the archive's "
                           "own lists (waf_archive request headers "
                           "mask=authorization): whatever the capture cannot "
                           "give rides to the agent with the record");
        return NGX_CONF_ERROR;
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

                    if (!wlcf->shoot[ph].archive_cleared
                        && ngx_http_waf_shoot_named(&wlcf->shoot[ph],
                                                    NGX_HTTP_WAF_LIST_ARCHIVE))
                    {
                        return ngx_http_waf_none_mix(cf, &args[0], ph);
                    }

                    ngx_http_waf_archive_reset(&wlcf->shoot[ph]);
                    wlcf->shoot[ph].archive = 0;
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

            obj = ngx_http_waf_lowest_bit(bit);
            mask |= bit;
            limits[obj] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
            continue;
        }

        if (ngx_http_waf_kw_lookup(ngx_http_waf_kw_obj, &name, &bit)
            == NGX_OK)
        {

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

            size = ngx_parse_size(&value);

            if (size == NGX_ERROR || size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_archive: invalid size \"%V\" for "
                                   "\"%V\"; write \"none\" to turn the object "
                                   "off, or omit \"=\" to archive it whole",
                                   &value, &name);
                return NGX_CONF_ERROR;
            }

            obj = ngx_http_waf_lowest_bit(bit);
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

        if (name.len == 6 && ngx_strncmp(name.data, "source", 6) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_archive: source= is not an option; the "
                               "archive masks by its own lists "
                               "(waf_archive request headers "
                               "mask=authorization, or mask=none for none), "
                               "and the module takes the original whenever "
                               "those lists need it");
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

        if (wlcf->shoot[ph].archive_cleared) {
            return ngx_http_waf_none_mix(cf, &args[0], ph);
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


static char *
ngx_http_waf_archive_apply(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t mask, ngx_uint_t off, ngx_uint_t when, time_t ttl,
    size_t *limits)
{
    ngx_uint_t  i;

    if (sh->archive == NGX_CONF_UNSET_UINT) {
        sh->archive = 0;
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

    sh->preview_item[obj] = NGX_HTTP_WAF_PREVIEW_ITEM_NONE;

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
                           "%V: \"%V\" is not a list of names; allow= takes "
                           "names or *, mask= and deny= take names or none",
                           directive, spec);
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
            p++;
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

    if (cf->args->nelts >= 3
        && args[2].len == 6
        && ngx_strncmp(args[2].data, "reload", 6) == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: \"reload\" is gone; the record is "
                           "cut from the request itself at any size, and its "
                           "own lists (waf_preview request headers "
                           "mask=cookie) replace the capture lists");
        return NGX_CONF_ERROR;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(ph))) {
            continue;
        }

        if (ngx_http_waf_preview_set(cf, &wlcf->shoot[ph], phases, ph)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_preview_set(ngx_conf_t *cf, ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t phases, ngx_uint_t phase)
{
    ngx_str_t  *args, name, value;
    ngx_uint_t  i, bit, obj, named, source;

    args   = cf->args->elts;
    named  = 0;
    source = NGX_CONF_UNSET_UINT;

    if (cf->args->nelts == 3
        && args[2].len == 4
        && ngx_strncmp(args[2].data, "none", 4) == 0)
    {
        if (!sh->preview_cleared
            && ngx_http_waf_shoot_named(sh, NGX_HTTP_WAF_LIST_PREVIEW))
        {
            return ngx_http_waf_none_mix(cf, &args[0], phase);
        }

        sh->preview_cleared = 1;

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            sh->preview[i]        = 0;
            sh->preview_item[i]   = NGX_HTTP_WAF_PREVIEW_ITEM_NONE;
            sh->preview_source[i] = NGX_CONF_UNSET_UINT;
        }

        return NGX_CONF_OK;
    }

    if (sh->preview_cleared) {
        return ngx_http_waf_none_mix(cf, &args[0], phase);
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf_preview: write the size on the object "
                               "(headers=64k or headers=64k/2k)");
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_kw_lookup(ngx_http_waf_kw_obj, &name, &bit)
            == NGX_OK)
        {
            obj = ngx_http_waf_lowest_bit(bit);

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

            if (sh->preview[obj] != 0) {
                named |= bit;
            }

            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "source", 6) == 0) {

            if (source != NGX_CONF_UNSET_UINT) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf_preview: source= is named twice");
                return NGX_CONF_ERROR;
            }

            if (ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_source, &value,
                                         &source)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

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

    if (named == 0 && source == NGX_CONF_UNSET_UINT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: no objects listed; say \"none\" to "
                           "turn previews off");
        return NGX_CONF_ERROR;
    }

    if (source == NGX_CONF_UNSET_UINT) {
        return NGX_CONF_OK;
    }

    if (named == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: source= applies to the objects "
                           "named on the same line, and this line names "
                           "none");
        return NGX_CONF_ERROR;
    }

    /*
     * The source is a property of the body alone: the delivered version after
     * a rewrite, or what came in. Headers and the query string have no second
     * version, and what the record shows of them is set by its lists.
     */

    if (named != NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_preview: source= is for the body alone "
                           "(body=8k source=sent); headers and args take "
                           "their own name lists instead");
        return NGX_CONF_ERROR;
    }

    sh->preview_source[NGX_HTTP_WAF_OBJ_BODY] = source;

    return NGX_CONF_OK;
}


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

    if (hold == NGX_HTTP_WAF_HOLD_MONITOR
        && (phases & NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_hold: the request phase is always gate; "
                           "for watching without gating write mode=passive "
                           "on waf_inspect");
        return NGX_CONF_ERROR;
    }

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
            wlcf->hold[phase]   = hold;
            wlcf->named[phase] |= NGX_HTTP_WAF_NAMED_HOLD;
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

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (phases & NGX_HTTP_WAF_PH_BIT(phase)) {
            wlcf->deadline[phase] = msec;
            wlcf->named[phase]   |= NGX_HTTP_WAF_NAMED_DEADLINE;
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
    ngx_uint_t   phase, phases, policy;

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

    policy = NGX_HTTP_WAF_POLICY_BLOCK;

    if (cf->args->nelts > 3
        && ngx_http_waf_opt_keyword(cf, ngx_http_waf_kw_body_policy, &args[3],
                                    &policy)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!(phases & NGX_HTTP_WAF_PH_BIT(phase))) {
            continue;
        }

        wlcf->body_limit[phase]        = (size_t) size;
        wlcf->body_limit_policy[phase] = policy;
        wlcf->named[phase]            |= NGX_HTTP_WAF_NAMED_BODY_LIMIT;
    }

    return NGX_CONF_OK;
}


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

    p    = args[1].data;
    last = args[1].data + args[1].len;

    while (p < last) {
        host.data = p;

        while (p < last && *p != ',') {
            p++;
        }

        host.len = (size_t) (p - host.data);

        if (p < last) {
            p++;
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
            if (ngx_http_waf_opt_msec(cf, "connect_timeout", &value,
                                      &wmcf->bus_connect_timeout)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 14
            && ngx_strncmp(name.data, "reconnect_wait", 14) == 0)
        {
            if (ngx_http_waf_opt_msec(cf, "reconnect_wait", &value,
                                      &wmcf->bus_reconnect_wait)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 13 && ngx_strncmp(name.data, "ping_interval", 13) == 0) {
            if (ngx_http_waf_opt_msec(cf, "ping_interval", &value,
                                      &wmcf->bus_ping_interval)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 11 && ngx_strncmp(name.data, "pending_max", 11) == 0) {
            wmcf->bus_pending_max = ngx_parse_size(&value);
            if (wmcf->bus_pending_max == (size_t) NGX_ERROR
                || wmcf->bus_pending_max == 0)
            {
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


static ngx_int_t
ngx_http_waf_opt_fraction(ngx_conf_t *cf, ngx_str_t *value, ngx_uint_t scale,
    ngx_uint_t max, ngx_uint_t *out)
{
    u_char      c;
    size_t      i;
    ngx_uint_t  whole, frac, div, digits;

    whole  = 0;
    frac   = 0;
    div    = 1;
    digits = 0;

    for (i = 0; i < value->len; i++) {
        c = value->data[i];

        if (c == '.') {
            i++;
            break;
        }

        if (c < '0' || c > '9') {
            goto invalid;
        }

        digits++;
        whole = whole * 10 + (ngx_uint_t) (c - '0');

        if (whole > max) {
            goto invalid;
        }
    }

    for ( ; i < value->len; i++) {
        c = value->data[i];

        if (c < '0' || c > '9') {
            goto invalid;
        }

        digits++;

        if (div * 10 > scale) {
            continue;
        }

        frac = frac * 10 + (ngx_uint_t) (c - '0');
        div *= 10;
    }

    if (digits == 0) {
        goto invalid;
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


static ngx_int_t
ngx_http_waf_opt_msec(ngx_conf_t *cf, const char *what, ngx_str_t *value,
    ngx_msec_t *out)
{
    ngx_int_t  n;

    n = ngx_parse_time(value, 0);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid %s \"%V\", expected a time above "
                           "zero", what, value);
        return NGX_ERROR;
    }

    *out = (ngx_msec_t) n;

    return NGX_OK;
}




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

    ngx_str_set(&wlcf->require_upgrade_response, "");

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
        return NGX_CONF_OK;
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

    wlcf->audit_frames_sample = 1;

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


char *
ngx_http_waf_frame_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t   *args, name, value;
    ngx_int_t    ttl;
    ngx_uint_t   i, ph, phases;

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

    ngx_http_waf_fcache_want(1);

    return NGX_CONF_OK;
}
