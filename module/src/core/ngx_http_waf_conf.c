#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "bus/ngx_http_waf_bus.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"
#include "runtime/ngx_http_waf_preview.h"


#define NGX_HTTP_WAF_DEFAULT_DEADLINE          50
#define NGX_HTTP_WAF_DEFAULT_INFLIGHT        4096
#define NGX_HTTP_WAF_DEFAULT_REPLY_MAX       8192
#define NGX_HTTP_WAF_DEFAULT_HEADER_VALUE   4096

#define NGX_HTTP_WAF_DEFAULT_ACTION_MAX       192
#define NGX_HTTP_WAF_DEFAULT_ACTIONS_MAX       16

#define NGX_HTTP_WAF_DEFAULT_BODY_LIMIT      (1024 * 1024)
#define NGX_HTTP_WAF_DEFAULT_BODY_HOLDS      1000

static ngx_str_t  ngx_http_waf_default_deny = ngx_string("blocked");


static void
ngx_http_waf_merge_lists(ngx_http_waf_shoot_conf_t *sh,
    ngx_http_waf_shoot_conf_t *psh, ngx_uint_t kind)
{
    ngx_uint_t  obj, axis;

    for (obj = 0; obj < NGX_HTTP_WAF_META_COUNT; obj++) {
        for (axis = 0; axis < NGX_HTTP_WAF_AXIS_COUNT; axis++) {
            if (sh->lists[kind][obj][axis] == NULL) {
                sh->lists[kind][obj][axis] = psh->lists[kind][obj][axis];
            }
        }
    }
}


static char *ngx_http_waf_merge_waves(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *conf);
static char *ngx_http_waf_check_exception(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *conf);
static char *ngx_http_waf_check_send(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *conf);
static char *ngx_http_waf_check_scoring(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *conf);
static void  ngx_http_waf_merge_capture(ngx_http_waf_shoot_conf_t *sh,
    ngx_http_waf_shoot_conf_t *psh, ngx_uint_t def);
static void  ngx_http_waf_merge_archive(ngx_http_waf_shoot_conf_t *sh,
    ngx_http_waf_shoot_conf_t *psh);
static char *ngx_http_waf_merge_preview(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *conf,
    ngx_http_waf_loc_conf_t *prev, ngx_uint_t phase);
static char *ngx_http_waf_check_body_limit(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf);
static char *ngx_http_waf_check_capture_limit(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase);
static char *ngx_http_waf_reload_wider(ngx_conf_t *cf, ngx_uint_t phase,
    const char *dir, ngx_uint_t obj, size_t limit, size_t cap);
static char *ngx_http_waf_check_archive_reload(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase);
static char *ngx_http_waf_check_preview_reload(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase);
static char *ngx_http_waf_check_lists_over_capture(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t kind, ngx_uint_t named,
    ngx_uint_t reload, const char *dir);
static char *ngx_http_waf_check_size_ceiling(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase, const char *dir,
    ngx_uint_t obj, size_t limit);
static size_t ngx_http_waf_read_ceiling(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase);
static size_t ngx_http_waf_preview_ceiling(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase, ngx_uint_t obj);
static char *ngx_http_waf_preview_budget(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase, ngx_uint_t obj,
    ngx_uint_t named);


void *
ngx_http_waf_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));
    if (wmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&wmcf->inspectors, cf->pool, 8,
                       sizeof(ngx_http_waf_inspector_t))
        != NGX_OK)
    {
        return NULL;
    }

    wmcf->max_inflight     = NGX_CONF_UNSET_UINT;
    wmcf->ctx_var_index    = NGX_CONF_UNSET_UINT;
    wmcf->reply_max        = NGX_CONF_UNSET_SIZE;
    wmcf->header_value_max = NGX_CONF_UNSET_SIZE;

    wmcf->body_max_holds = NGX_CONF_UNSET_UINT;

    wmcf->bus_connect_timeout = NGX_CONF_UNSET_MSEC;
    wmcf->bus_reconnect_wait  = NGX_CONF_UNSET_MSEC;
    wmcf->bus_ping_interval   = NGX_CONF_UNSET_MSEC;
    wmcf->bus_pending_max     = NGX_CONF_UNSET_SIZE;
    wmcf->bus_payload_max     = NGX_CONF_UNSET_SIZE;

    ngx_http_waf_fcache_want(0);

    return wmcf;
}


char *
ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_conf_init_uint_value(wmcf->max_inflight, NGX_HTTP_WAF_DEFAULT_INFLIGHT);
    ngx_conf_init_size_value(wmcf->reply_max, NGX_HTTP_WAF_DEFAULT_REPLY_MAX);
    ngx_conf_init_size_value(wmcf->header_value_max,
                             NGX_HTTP_WAF_DEFAULT_HEADER_VALUE);

    ngx_conf_init_uint_value(wmcf->body_max_holds,
                             NGX_HTTP_WAF_DEFAULT_BODY_HOLDS);

    ngx_conf_init_msec_value(wmcf->bus_connect_timeout, 1000);
    ngx_conf_init_msec_value(wmcf->bus_reconnect_wait, 100);
    ngx_conf_init_msec_value(wmcf->bus_ping_interval, 10000);
    ngx_conf_init_size_value(wmcf->bus_pending_max, 8 * 1024 * 1024);

    ngx_conf_init_size_value(wmcf->bus_payload_max, 1024 * 1024);

    if (wmcf->bus_name.len == 0) {
        u_char  *p;
        size_t   len;

        len = sizeof("waf-") - 1 + ngx_cycle->hostname.len;

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        wmcf->bus_name.data = p;
        wmcf->bus_name.len  = (size_t) (ngx_sprintf(p, "waf-%V",
                                                    &ngx_cycle->hostname) - p);
    }

    if (wmcf->max_inflight > NGX_HTTP_WAF_SLOT_INDEX_MASK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_max_inflight must not exceed %uL",
                           NGX_HTTP_WAF_SLOT_INDEX_MASK);
        return NGX_CONF_ERROR;
    }

    if (wmcf->node_id.len == 0) {
        wmcf->node_id = ngx_cycle->hostname;
    }

    if (ngx_http_waf_shm_fit(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (wmcf->datasets != NULL && wmcf->sets_store == NULL) {
        ngx_uint_t               i;
        ngx_http_waf_dataset_t  *ds = wmcf->datasets->elts;

        for (i = 0; i < wmcf->datasets->nelts; i++) {
            if (ds[i].mode == NGX_HTTP_WAF_DS_MODE_ACTIVE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: active dataset \"%V\" needs "
                                   "waf_sets_store (the internal Redis)",
                                   &ds[i].name);
                return NGX_CONF_ERROR;
            }
        }
    }

    if (wmcf->inspectors.nelts > NGX_HTTP_WAF_MAX_INSPECTORS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: %ui inspectors declared, maximum is %d",
                           wmcf->inspectors.nelts,
                           NGX_HTTP_WAF_MAX_INSPECTORS);
        return NGX_CONF_ERROR;
    }

    if (wmcf->bus == NULL && wmcf->inspectors.nelts != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: inspectors are declared but waf_bus is not "
                           "configured");
        return NGX_CONF_ERROR;
    }

    return ngx_http_waf_vars_init(cf, wmcf);
}


void *
ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_uint_t                  i, ph;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    wlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (wlcf == NULL) {
        return NULL;
    }

    wlcf->enable               = NGX_CONF_UNSET;
    wlcf->debug_header         = NGX_CONF_UNSET;
    wlcf->strip_accept_encoding = NGX_CONF_UNSET;
    wlcf->require_upgrade      = NGX_CONF_UNSET;
    wlcf->audit_frames         = NGX_CONF_UNSET_UINT;
    wlcf->audit_frames_sample  = NGX_CONF_UNSET_UINT;
    wlcf->frame_reassemble     = NGX_CONF_UNSET;
    wlcf->frame_control_rate   = NGX_CONF_UNSET_UINT;

    wlcf->cookie_secure        = NGX_CONF_UNSET;
    wlcf->cookie_http_only     = NGX_CONF_UNSET;
    wlcf->cookie_same_site     = NGX_CONF_UNSET_UINT;

    wlcf->action_max           = NGX_CONF_UNSET_SIZE;
    wlcf->actions_max          = NGX_CONF_UNSET_UINT;
    wlcf->audit_sample         = NGX_CONF_UNSET;

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        wlcf->deadline[i]              = NGX_CONF_UNSET_MSEC;
        wlcf->deny_mode[i]             = NGX_CONF_UNSET_UINT;

        {
            ngx_uint_t  exc;

            for (exc = 0; exc < NGX_HTTP_WAF_EXC_COUNT; exc++) {
                wlcf->exception[i][exc] = NGX_CONF_UNSET_UINT;
            }
        }

        {
            ngx_uint_t  obj;

            for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {
                wlcf->send[i][obj] = NGX_CONF_UNSET_UINT;
            }
        }
        wlcf->score_deny[i]            = NGX_CONF_UNSET;
        wlcf->hold[i]                  = NGX_CONF_UNSET_UINT;
        wlcf->body_limit[i]            = NGX_CONF_UNSET_SIZE;
        wlcf->body_limit_policy[i]     = NGX_CONF_UNSET_UINT;
        wlcf->frame_cache_ttl[i]       = NGX_CONF_UNSET_MSEC;
    }

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {
        sh = &wlcf->shoot[ph];

        sh->capture        = NGX_CONF_UNSET_UINT;
        sh->archive        = NGX_CONF_UNSET_UINT;
        sh->archive_reload = NGX_CONF_UNSET_UINT;
        sh->preview_reload = NGX_CONF_UNSET_UINT;
        sh->preview_source_sent = NGX_CONF_UNSET_UINT;

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            sh->capture_limit[i]        = NGX_CONF_UNSET_SIZE;
            sh->preview[i]              = NGX_CONF_UNSET_SIZE;
            sh->preview_item[i]         = NGX_CONF_UNSET_SIZE;
            sh->archive_when[i]         = NGX_CONF_UNSET_UINT;
            sh->archive_ttl[i]          = NGX_CONF_UNSET;
            sh->archive_limit[i]        = NGX_CONF_UNSET_SIZE;
            sh->archive_reload_limit[i] = NGX_CONF_UNSET_SIZE;
            sh->preview_reload_limit[i] = NGX_CONF_UNSET_SIZE;
        }
    }

    return wlcf;
}


char *
ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t  *prev = parent;
    ngx_http_waf_loc_conf_t  *conf = child;

    char                      *rv;
    ngx_uint_t                 i;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    prev->has_children = 1;

    {
        ngx_http_core_loc_conf_t  *clcf;
        ngx_http_waf_loc_conf_t  **slot;

        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        conf->name = clcf->name;

        if (wmcf->loc_confs == NULL) {
            wmcf->loc_confs = ngx_array_create(cf->pool, 16,
                                        sizeof(ngx_http_waf_loc_conf_t *));
            if (wmcf->loc_confs == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        slot = ngx_array_push(wmcf->loc_confs);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }

        *slot = conf;
    }

    if (conf->enable && wmcf->agent_socket.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_agent_socket is required when waf is on; "
                           "without it audit and preview never leave the "
                           "worker");
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        ngx_http_waf_merge_capture(&conf->shoot[i], &prev->shoot[i],
                                   i == NGX_HTTP_WAF_PHASE_REQUEST
                                       ? NGX_HTTP_WAF_OBJ_BIT(
                                             NGX_HTTP_WAF_OBJ_HEADERS)
                                         | NGX_HTTP_WAF_OBJ_BIT(
                                             NGX_HTTP_WAF_OBJ_ARGS)
                                       : 0);
    }

    ngx_conf_merge_value(conf->debug_header, prev->debug_header, 0);

    ngx_conf_merge_value(conf->strip_accept_encoding,
                         prev->strip_accept_encoding, NGX_CONF_UNSET);

    ngx_conf_merge_value(conf->cookie_secure, prev->cookie_secure, 1);
    ngx_conf_merge_value(conf->cookie_http_only, prev->cookie_http_only, 1);
    ngx_conf_merge_uint_value(conf->cookie_same_site, prev->cookie_same_site,
                              NGX_HTTP_WAF_SAMESITE_LAX);

    ngx_conf_merge_size_value(conf->action_max, prev->action_max,
                              NGX_HTTP_WAF_DEFAULT_ACTION_MAX);
    ngx_conf_merge_value(conf->audit_sample, prev->audit_sample, 100);

    ngx_conf_merge_uint_value(conf->actions_max, prev->actions_max,
                              NGX_HTTP_WAF_DEFAULT_ACTIONS_MAX);

    if (conf->actions_max > NGX_HTTP_WAF_ACTIONS_LIMIT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_actions_max must not exceed %d: the count is a "
                           "multiplier in the message budget",
                           NGX_HTTP_WAF_ACTIONS_LIMIT);
        return NGX_CONF_ERROR;
    }

    if (conf->actions_max != 0
        && conf->action_max < NGX_HTTP_WAF_ACTION_CODE_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_action_max must be at least %d: shorter than a "
                           "reason code",
                           NGX_HTTP_WAF_ACTION_CODE_MAX);
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_msec_value(conf->deadline[NGX_HTTP_WAF_PHASE_REQUEST],
                              prev->deadline[NGX_HTTP_WAF_PHASE_REQUEST],
                              NGX_HTTP_WAF_DEFAULT_DEADLINE);
    ngx_conf_merge_uint_value(
        conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_TIMEOUT],
        prev->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_TIMEOUT],
        NGX_HTTP_WAF_POLICY_BLOCK);
    ngx_conf_merge_uint_value(
        conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_ABSENT],
        prev->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_ABSENT],
        NGX_HTTP_WAF_POLICY_BLOCK);
    ngx_conf_merge_uint_value(
        conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_BUS],
        prev->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_BUS],
        NGX_HTTP_WAF_POLICY_PASS);
    ngx_conf_merge_uint_value(
        conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_BODY],
        prev->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_BODY],
        NGX_HTTP_WAF_POLICY_BLOCK);
    ngx_conf_merge_uint_value(
        conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_INSPECTOR],
        prev->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_INSPECTOR],
        NGX_HTTP_WAF_POLICY_BLOCK);
    ngx_conf_merge_uint_value(
        conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_OVERLOAD],
        prev->exception[NGX_HTTP_WAF_PHASE_REQUEST][NGX_HTTP_WAF_EXC_OVERLOAD],
        NGX_HTTP_WAF_POLICY_BLOCK);

    {
        ngx_uint_t  exc;

        for (exc = 0; exc < NGX_HTTP_WAF_EXC_COUNT; exc++) {
            ngx_conf_merge_str_value(
                conf->exception_response[NGX_HTTP_WAF_PHASE_REQUEST][exc],
                prev->exception_response[NGX_HTTP_WAF_PHASE_REQUEST][exc], "");
        }
    }
    ngx_conf_merge_uint_value(conf->deny_mode[NGX_HTTP_WAF_PHASE_REQUEST],
                              prev->deny_mode[NGX_HTTP_WAF_PHASE_REQUEST],
                              NGX_HTTP_WAF_DENY_FAST);
    ngx_conf_merge_value(conf->score_deny[NGX_HTTP_WAF_PHASE_REQUEST],
                         prev->score_deny[NGX_HTTP_WAF_PHASE_REQUEST], 0);
    ngx_conf_merge_str_value(
        conf->score_deny_response[NGX_HTTP_WAF_PHASE_REQUEST],
        prev->score_deny_response[NGX_HTTP_WAF_PHASE_REQUEST], "");
    ngx_conf_merge_uint_value(conf->hold[NGX_HTTP_WAF_PHASE_REQUEST],
                              prev->hold[NGX_HTTP_WAF_PHASE_REQUEST],
                              NGX_HTTP_WAF_HOLD_GATE);
    ngx_conf_merge_size_value(conf->body_limit[NGX_HTTP_WAF_PHASE_REQUEST],
                              prev->body_limit[NGX_HTTP_WAF_PHASE_REQUEST],
                              NGX_HTTP_WAF_DEFAULT_BODY_LIMIT);
    ngx_conf_merge_uint_value(
        conf->body_limit_policy[NGX_HTTP_WAF_PHASE_REQUEST],
        prev->body_limit_policy[NGX_HTTP_WAF_PHASE_REQUEST],
        NGX_HTTP_WAF_POLICY_BLOCK);

    for (i = NGX_HTTP_WAF_PHASE_REQUEST + 1; i < NGX_HTTP_WAF_NPHASE; i++) {

        ngx_conf_merge_msec_value(conf->deadline[i], prev->deadline[i],
                                  conf->deadline[NGX_HTTP_WAF_PHASE_REQUEST]);
        {
            ngx_uint_t  exc;

            for (exc = 0; exc < NGX_HTTP_WAF_EXC_COUNT; exc++) {
                ngx_conf_merge_uint_value(
                    conf->exception[i][exc], prev->exception[i][exc],
                    conf->exception[NGX_HTTP_WAF_PHASE_REQUEST][exc]);
                if (conf->exception_response[i][exc].data == NULL) {
                    conf->exception_response[i][exc] =
                        (prev->exception_response[i][exc].data != NULL)
                            ? prev->exception_response[i][exc]
                            : conf->exception_response
                                  [NGX_HTTP_WAF_PHASE_REQUEST][exc];
                }
            }
        }
        {
            ngx_uint_t  obj;

            for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {
                ngx_conf_merge_uint_value(conf->send[i][obj],
                                          prev->send[i][obj],
                                          NGX_CONF_UNSET_UINT);
            }
        }

        ngx_conf_merge_uint_value(
            conf->deny_mode[i], prev->deny_mode[i],
            conf->deny_mode[NGX_HTTP_WAF_PHASE_REQUEST]);
        ngx_conf_merge_value(conf->score_deny[i], prev->score_deny[i],
                             conf->score_deny[NGX_HTTP_WAF_PHASE_REQUEST]);
        ngx_conf_merge_uint_value(conf->hold[i], prev->hold[i],
                                  conf->hold[NGX_HTTP_WAF_PHASE_REQUEST]);
        ngx_conf_merge_size_value(
            conf->body_limit[i], prev->body_limit[i],
            conf->body_limit[NGX_HTTP_WAF_PHASE_REQUEST]);
        ngx_conf_merge_uint_value(
            conf->body_limit_policy[i], prev->body_limit_policy[i],
            conf->body_limit_policy[NGX_HTTP_WAF_PHASE_REQUEST]);

        ngx_conf_merge_str_value(conf->score_deny_response[i],
                                 prev->score_deny_response[i], "");

        if (conf->score_deny_response[i].len == 0) {
            conf->score_deny_response[i] =
                conf->score_deny_response[NGX_HTTP_WAF_PHASE_REQUEST];
        }
    }

    ngx_conf_merge_str_value(conf->deny_response_default,
                             prev->deny_response_default, "blocked");

    ngx_conf_merge_str_value(conf->route_id, prev->route_id, "");

    if (conf->redirect_allow == NULL) {
        conf->redirect_allow = prev->redirect_allow;
    }

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        if (conf->inspects[i] == NULL) {
            conf->inspects[i] = prev->inspects[i];
        }
    }

    ngx_memcpy(conf->profiles, prev->profiles, sizeof(conf->profiles));

    if (conf->local_rates == NULL) {
        conf->local_rates = prev->local_rates;
    }

    if (conf->local_checks == NULL) {
        conf->local_checks = prev->local_checks;
    }

    ngx_conf_merge_value(conf->require_upgrade, prev->require_upgrade, 0);
    ngx_conf_merge_str_value(conf->require_upgrade_response,
                             prev->require_upgrade_response, "");

    if (conf->ws_strip_ext == NULL) {
        conf->ws_strip_ext = prev->ws_strip_ext;
    }

    ngx_conf_merge_uint_value(conf->audit_frames, prev->audit_frames,
                              NGX_HTTP_WAF_AUDIT_FRAMES_DENY);
    ngx_conf_merge_uint_value(conf->audit_frames_sample,
                              prev->audit_frames_sample, 1);

    ngx_conf_merge_value(conf->frame_reassemble, prev->frame_reassemble, 0);
    ngx_conf_merge_uint_value(conf->frame_control_rate,
                              prev->frame_control_rate,
                              NGX_HTTP_WAF_DEFAULT_CONTROL_RATE);

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        ngx_conf_merge_msec_value(conf->frame_cache_ttl[i],
                                  prev->frame_cache_ttl[i], 0);
    }

    rv = ngx_http_waf_check_body_limit(cf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {

        rv = ngx_http_waf_check_capture_limit(cf, conf, i);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        ngx_http_waf_merge_archive(&conf->shoot[i], &prev->shoot[i]);

        rv = ngx_http_waf_merge_preview(cf, wmcf, conf, prev, i);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    rv = ngx_http_waf_merge_waves(cf, wmcf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {

        rv = ngx_http_waf_check_archive_reload(cf, conf, i);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        rv = ngx_http_waf_check_preview_reload(cf, conf, i);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    rv = ngx_http_waf_check_scoring(cf, wmcf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    rv = ngx_http_waf_check_exception(cf, wmcf, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    rv = ngx_http_waf_check_send(cf, wmcf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    rv = ngx_http_waf_body_validate(cf, wmcf, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return ngx_http_waf_msg_req_validate(cf, wmcf, conf);
}


static char *
ngx_http_waf_merge_waves(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *conf)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        conf->waves[i] = ngx_http_waf_waves_build(cf, wmcf, conf, i);

        if (conf->waves[i] == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


ngx_uint_t
ngx_http_waf_send_of(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_uint_t  how = wlcf->send[phase][obj];

    if (how != NGX_CONF_UNSET_UINT) {
        return how;
    }

    return NGX_HTTP_WAF_SEND_STORE;
}


static char *
ngx_http_waf_check_send(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *conf)
{
    ngx_uint_t                  ph, obj;
    ngx_http_waf_shoot_conf_t  *sh;

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {
        sh = &conf->shoot[ph];

        for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {

            if (conf->send[ph][obj] != NGX_HTTP_WAF_SEND_STORE) {
                continue;
            }

            if (!(sh->capture & NGX_HTTP_WAF_OBJ_BIT(obj))) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_send %V %V=store, but the "
                                   "object is not captured on this route; "
                                   "there is nothing to lift -- add "
                                   "\"waf_capture %V %V\" or send the "
                                   "original",
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj));
                return NGX_CONF_ERROR;
            }
        }

    }

    (void) wmcf;

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_check_exception(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *conf)
{
    ngx_uint_t  ph, exc;
    ngx_str_t  *name;

    for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {

        for (exc = 0; exc < NGX_HTTP_WAF_EXC_COUNT; exc++) {

            name = &conf->exception_response[ph][exc];

            if (name->len == 0) {
                continue;
            }

            if (ngx_http_waf_deny_response_find(wmcf, name) == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_exception %V %V response=%V: "
                                   "waf_deny_response \"%V\" is not declared",
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_exc_name(exc), name, name);
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_check_scoring(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *conf)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        if (conf->score_deny_response[i].len != 0
            && ngx_http_waf_deny_response_find(wmcf,
                                              &conf->score_deny_response[i])
               == NULL)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_deny_response \"%V\" is not declared",
                               &conf->score_deny_response[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_http_waf_deny_response_find(wmcf, &conf->deny_response_default)
        == NULL)
    {
        if (conf->deny_response_default.len != ngx_http_waf_default_deny.len
            || ngx_memcmp(conf->deny_response_default.data,
                          ngx_http_waf_default_deny.data,
                          ngx_http_waf_default_deny.len) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_deny_response \"%V\" is not declared",
                               &conf->deny_response_default);
            return NGX_CONF_ERROR;
        }

        if (conf->enable
            && conf->waves[NGX_HTTP_WAF_PHASE_REQUEST] != NULL && conf->waves[NGX_HTTP_WAF_PHASE_REQUEST]->nelts != 0)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "waf: waf_deny_response \"%V\" is not declared; "
                               "denials will fall back to a bare %d",
                               &conf->deny_response_default,
                               NGX_HTTP_FORBIDDEN);
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_check_body_limit(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->client_max_body_size <= 0) {
        return NGX_CONF_OK;
    }

    if ((off_t) conf->body_limit[NGX_HTTP_WAF_PHASE_REQUEST]
        > clcf->client_max_body_size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_body_limit request %uz exceeds "
                           "client_max_body_size %O",
                           conf->body_limit[NGX_HTTP_WAF_PHASE_REQUEST],
                           clcf->client_max_body_size);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static size_t
ngx_http_waf_read_ceiling(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *conf,
    ngx_uint_t phase)
{
    size_t                     ceiling;
    ngx_http_core_loc_conf_t  *clcf;

    ceiling = conf->body_limit[phase];

    if (phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return ceiling;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->client_max_body_size > 0
        && (off_t) ceiling > clcf->client_max_body_size)
    {
        ceiling = (size_t) clcf->client_max_body_size;
    }

    return ceiling;
}


static char *
ngx_http_waf_check_capture_limit(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *conf,
    ngx_uint_t phase)
{
    size_t                      ceiling, limit;
    ngx_uint_t                  i;
    ngx_http_waf_shoot_conf_t  *sh = &conf->shoot[phase];

    ceiling = ngx_http_waf_read_ceiling(cf, conf, phase);

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(sh->capture & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        limit = sh->capture_limit[i];

        if (limit == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE) {
            continue;
        }

        if (limit > ceiling) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_capture %V %uz exceeds the %uz bytes "
                               "this object the WAF reads at all; lower it or "
                               "raise waf_body_limit / client_max_body_size",
                               ngx_http_waf_obj_name(i), limit, ceiling);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_check_size_ceiling(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *conf,
    ngx_uint_t phase, const char *dir, ngx_uint_t obj, size_t limit)
{
    size_t  ceiling;

    if (limit == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE
        || limit == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE)
    {
        return NGX_CONF_OK;
    }

    ceiling = ngx_http_waf_read_ceiling(cf, conf, phase);

    if (limit > ceiling) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: %s %V %uz exceeds the %uz bytes "
                           "this object the WAF reads at all; lower it or "
                           "raise waf_body_limit / client_max_body_size",
                           dir, ngx_http_waf_obj_name(obj), limit, ceiling);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_reload_wider(ngx_conf_t *cf, ngx_uint_t phase, const char *dir,
    ngx_uint_t obj, size_t limit, size_t cap)
{
    if (phase == NGX_HTTP_WAF_PHASE_REQUEST) {
        return NGX_CONF_OK;
    }

    if (limit == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE) {
        return NGX_CONF_OK;
    }

    if (limit != NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE
        && cap != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
        && limit <= cap)
    {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: %s reload %V is wider than capture, and outside "
                       "the request phase there is nothing to reload from: "
                       "write reload %V=capture or widen waf_capture %V",
                       dir, ngx_http_waf_obj_name(obj),
                       ngx_http_waf_obj_name(obj),
                       ngx_http_waf_phase_name(phase));
    return NGX_CONF_ERROR;
}


static char *
ngx_http_waf_check_archive_reload(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase)
{
    ngx_uint_t                  i, bit, captured, reloading, inspected;
    size_t                      limit, cap;
    ngx_http_waf_shoot_conf_t  *sh = &conf->shoot[phase];

    inspected = ngx_http_waf_phase_inspected(conf, phase);

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit = NGX_HTTP_WAF_OBJ_BIT(i);

        if (!(sh->archive & bit)) {
            continue;
        }

        captured = (sh->capture & bit) != 0;
        reloading = (sh->archive_reload & bit) != 0;
        limit = sh->archive_limit[i];
        cap = sh->capture_limit[i];

        if (reloading) {
            limit = sh->archive_reload_limit[i];

            if (limit == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE && !captured) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_archive reload %V=capture needs "
                                   "that object in waf_capture",
                                   ngx_http_waf_obj_name(i));
                return NGX_CONF_ERROR;
            }

            if (ngx_http_waf_check_size_ceiling(cf, conf, phase, "waf_archive",
                                                i, limit)
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            if (inspected
                && ngx_http_waf_reload_wider(cf, phase, "waf_archive", i,
                                             limit, cap)
                   != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (!inspected) {

            if (ngx_http_waf_check_size_ceiling(cf, conf, phase, "waf_archive",
                                                i, limit)
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (!captured) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive %V is wider than capture; "
                               "write reload %V=... or keep it within capture",
                               ngx_http_waf_obj_name(i),
                               ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        if (!ngx_http_waf_phase_is_frame(phase)
            && limit != NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE
            && cap != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
            && limit > cap)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive %V is wider than capture; "
                               "write reload %V=... or keep it within capture",
                               ngx_http_waf_obj_name(i),
                               ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_check_size_ceiling(cf, conf, phase, "waf_archive", i,
                                            limit)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_http_waf_check_lists_over_capture(cf, sh,
                                                 NGX_HTTP_WAF_LIST_ARCHIVE,
                                                 sh->archive,
                                                 sh->archive_reload,
                                                 "waf_archive");
}


static char *
ngx_http_waf_check_lists_over_capture(ngx_conf_t *cf,
    ngx_http_waf_shoot_conf_t *sh, ngx_uint_t kind, ngx_uint_t named,
    ngx_uint_t reload, const char *dir)
{
    ngx_str_t     *name, *hit;
    ngx_uint_t     i, n, axis;
    ngx_array_t   *own, *deny;
    const char    *word;

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (!(named & NGX_HTTP_WAF_OBJ_BIT(i))
            || (reload & NGX_HTTP_WAF_OBJ_BIT(i)))
        {
            continue;
        }

        deny = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][i][NGX_HTTP_WAF_AXIS_DENY];

        if (deny == NULL || deny->nelts == 0) {
            continue;
        }

        for (axis = NGX_HTTP_WAF_AXIS_ALLOW; axis <= NGX_HTTP_WAF_AXIS_MASK;
             axis++)
        {
            own = sh->lists[kind][i][axis];

            if (own == NULL || own->nelts == 0) {
                continue;
            }

            name = own->elts;
            hit  = deny->elts;

            for (n = 0; n < own->nelts; n++) {
                ngx_uint_t  d;

                for (d = 0; d < deny->nelts; d++) {

                    if (name[n].len != hit[d].len
                        || ngx_strncasecmp(name[n].data, hit[d].data,
                                           name[n].len) != 0)
                    {
                        continue;
                    }

                    word = (axis == NGX_HTTP_WAF_AXIS_ALLOW) ? "allow" : "mask";

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf: %s %V %s= names \"%V\", which "
                                       "waf_capture deny= drops before the "
                                       "store; write %s reload %V=capture "
                                       "to take the original, or drop the "
                                       "name from the list",
                                       dir, ngx_http_waf_obj_name(i), word,
                                       &name[n], dir,
                                       ngx_http_waf_obj_name(i));
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_check_preview_reload(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *conf, ngx_uint_t phase)
{
    ngx_uint_t                  i, bit, captured, reloading, inspected;
    size_t                      cap;
    ngx_http_waf_shoot_conf_t  *sh = &conf->shoot[phase];

    inspected = ngx_http_waf_phase_inspected(conf, phase);

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit = NGX_HTTP_WAF_OBJ_BIT(i);

        if (sh->preview[i] == 0) {
            continue;
        }

        captured = (sh->capture & bit) != 0;
        reloading = (sh->preview_reload & bit) != 0;
        cap = sh->capture_limit[i];

        if (reloading) {
            if (sh->preview_reload_limit[i]
                    == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE
                && !captured)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_preview reload %V=capture needs "
                                   "that object in waf_capture",
                                   ngx_http_waf_obj_name(i));
                return NGX_CONF_ERROR;
            }

            if (inspected
                && ngx_http_waf_reload_wider(cf, phase, "waf_preview", i,
                                             sh->preview_reload_limit[i], cap)
                   != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (!inspected) {
            continue;
        }

        if (!captured) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_preview %V is wider than capture; "
                               "write reload %V=... or keep it within capture",
                               ngx_http_waf_obj_name(i),
                               ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }

        if (ngx_http_waf_phase_is_frame(phase)) {

            if (ngx_http_waf_check_size_ceiling(cf, conf, phase, "waf_preview",
                                                i, sh->preview[i])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (cap != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
            && sh->preview[i] > cap)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_preview %V is wider than capture; "
                               "write reload %V=... or keep it within capture",
                               ngx_http_waf_obj_name(i),
                               ngx_http_waf_obj_name(i));
            return NGX_CONF_ERROR;
        }
    }

    {
        ngx_uint_t  named = 0;

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            if (sh->preview[i] != 0) {
                named |= NGX_HTTP_WAF_OBJ_BIT(i);
            }
        }

        return ngx_http_waf_check_lists_over_capture(cf, sh,
                                                     NGX_HTTP_WAF_LIST_PREVIEW,
                                                     named, sh->preview_reload,
                                                     "waf_preview");
    }
}


static size_t
ngx_http_waf_preview_ceiling(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *conf,
    ngx_uint_t phase, ngx_uint_t obj)
{
    off_t                       client_max;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_loc_conf_t   *clcf;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    switch (obj) {

    case NGX_HTTP_WAF_OBJ_HEADERS:
        return cscf->large_client_header_buffers.num
               * cscf->large_client_header_buffers.size;

    case NGX_HTTP_WAF_OBJ_ARGS:
        return cscf->large_client_header_buffers.size;

    default:
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        if (phase != NGX_HTTP_WAF_PHASE_REQUEST) {
            return conf->body_limit[phase];
        }

        client_max = clcf->client_max_body_size;

        if (client_max <= 0 || (off_t) conf->body_limit[phase] < client_max) {
            return conf->body_limit[phase];
        }

        return (size_t) client_max;
    }
}


static char *
ngx_http_waf_preview_budget(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *conf,
    ngx_uint_t phase, ngx_uint_t obj, ngx_uint_t named)
{
    size_t   ceiling = ngx_http_waf_preview_ceiling(cf, conf, phase, obj);
    size_t  *budget  = &conf->shoot[phase].preview[obj];

    if (*budget <= ceiling) {
        return NGX_CONF_OK;
    }

    if (named) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_preview %V %uz is over the %uz bytes of "
                           "this object the WAF reads at all; lower it or "
                           "raise the read limit",
                           ngx_http_waf_obj_name(obj), *budget, ceiling);
        return NGX_CONF_ERROR;
    }

    *budget = ceiling;

    return NGX_CONF_OK;
}


static void
ngx_http_waf_merge_capture(ngx_http_waf_shoot_conf_t *sh,
    ngx_http_waf_shoot_conf_t *psh, ngx_uint_t def)
{
    ngx_uint_t  i, bit, parent_on;

    if (sh->capture == NGX_CONF_UNSET_UINT && !sh->capture_cleared
        && sh->capture_set == 0)
    {
        if (psh->capture == NGX_CONF_UNSET_UINT) {
            sh->capture = def;

            for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
                sh->capture_limit[i] = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
            }

        } else {
            sh->capture = psh->capture;

            for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
                sh->capture_limit[i] = psh->capture_limit[i];
            }
        }

    } else {

        if (sh->capture == NGX_CONF_UNSET_UINT) {
            sh->capture = 0;
        }

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            bit = NGX_HTTP_WAF_OBJ_BIT(i);

            if (sh->capture_set & bit) {
                if (sh->capture_limit[i] == NGX_CONF_UNSET_SIZE) {
                    sh->capture_limit[i] = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
                }

                continue;
            }

            if (sh->capture_cleared) {
                sh->capture &= ~bit;
                sh->capture_limit[i] = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
                continue;
            }

            if (psh->capture == NGX_CONF_UNSET_UINT) {
                parent_on = (def & bit) != 0;
            } else {
                parent_on = (psh->capture & bit) != 0;
            }

            if (parent_on) {
                sh->capture |= bit;

                if (psh->capture == NGX_CONF_UNSET_UINT) {
                    sh->capture_limit[i] = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;

                } else {
                    sh->capture_limit[i] = psh->capture_limit[i];
                }

            } else {
                sh->capture &= ~bit;
                sh->capture_limit[i] = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
            }
        }
    }

    if (sh->capture_cleared) {
        return;
    }

    ngx_http_waf_merge_lists(sh, psh, NGX_HTTP_WAF_LIST_CAPTURE);
}


static void
ngx_http_waf_merge_archive(ngx_http_waf_shoot_conf_t *sh,
    ngx_http_waf_shoot_conf_t *psh)
{
    ngx_uint_t  i, bit;

    if (sh->archive == NGX_CONF_UNSET_UINT && !sh->archive_cleared
        && sh->archive_set == 0)
    {
        if (psh->archive == NGX_CONF_UNSET_UINT) {
            sh->archive        = 0;
            sh->archive_reload = 0;

            for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
                sh->archive_when[i]         = NGX_HTTP_WAF_ARCHIVE_WHEN_ALL;
                sh->archive_ttl[i]          = NGX_HTTP_WAF_ARCHIVE_TTL_FOREVER;
                sh->archive_limit[i]        = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
                sh->archive_reload_limit[i] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
            }

        } else {
            sh->archive        = psh->archive;
            sh->archive_reload = psh->archive_reload;

            for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
                sh->archive_when[i]         = psh->archive_when[i];
                sh->archive_ttl[i]          = psh->archive_ttl[i];
                sh->archive_limit[i]        = psh->archive_limit[i];
                sh->archive_reload_limit[i] = psh->archive_reload_limit[i];
            }
        }

    } else {

        if (sh->archive == NGX_CONF_UNSET_UINT) {
            sh->archive = 0;
        }

        if (sh->archive_reload == NGX_CONF_UNSET_UINT) {
            sh->archive_reload = 0;
        }

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            bit = NGX_HTTP_WAF_OBJ_BIT(i);

            if (sh->archive_set & bit) {
                if (sh->archive_when[i] == NGX_CONF_UNSET_UINT) {
                    sh->archive_when[i] = NGX_HTTP_WAF_ARCHIVE_WHEN_ALL;
                }

                if (sh->archive_ttl[i] == NGX_CONF_UNSET) {
                    sh->archive_ttl[i] = NGX_HTTP_WAF_ARCHIVE_TTL_FOREVER;
                }

                if (sh->archive_limit[i] == NGX_CONF_UNSET_SIZE) {
                    sh->archive_limit[i] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
                }

                if (sh->archive_reload_limit[i] == NGX_CONF_UNSET_SIZE) {
                    sh->archive_reload_limit[i] =
                        NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
                }

                continue;
            }

            if (sh->archive_cleared
                || psh->archive == NGX_CONF_UNSET_UINT)
            {
                sh->archive &= ~bit;
                sh->archive_reload &= ~bit;
                sh->archive_when[i]         = NGX_HTTP_WAF_ARCHIVE_WHEN_ALL;
                sh->archive_ttl[i]          = NGX_HTTP_WAF_ARCHIVE_TTL_FOREVER;
                sh->archive_limit[i]        = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
                sh->archive_reload_limit[i] = NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE;
                continue;
            }

            if (psh->archive & bit) {
                sh->archive |= bit;
            } else {
                sh->archive &= ~bit;
            }

            if (psh->archive_reload & bit) {
                sh->archive_reload |= bit;
            } else {
                sh->archive_reload &= ~bit;
            }

            sh->archive_when[i]         = psh->archive_when[i];
            sh->archive_ttl[i]          = psh->archive_ttl[i];
            sh->archive_limit[i]        = psh->archive_limit[i];
            sh->archive_reload_limit[i] = psh->archive_reload_limit[i];
        }
    }

    if (sh->archive_cleared) {
        return;
    }

    ngx_http_waf_merge_lists(sh, psh, NGX_HTTP_WAF_LIST_ARCHIVE);
}


static char *
ngx_http_waf_merge_preview(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *conf, ngx_http_waf_loc_conf_t *prev,
    ngx_uint_t phase)
{
    size_t                      room;
    char                       *rv;
    ngx_uint_t                  i, named[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_shoot_conf_t  *sh  = &conf->shoot[phase];
    ngx_http_waf_shoot_conf_t  *psh = &prev->shoot[phase];

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        named[i] = (sh->preview[i] != NGX_CONF_UNSET_SIZE);
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        ngx_conf_merge_size_value(sh->preview[i], psh->preview[i],
                                  NGX_HTTP_WAF_DEFAULT_PREVIEW);
        ngx_conf_merge_size_value(sh->preview_item[i], psh->preview_item[i],
                                  NGX_HTTP_WAF_PREVIEW_ITEM_NONE);
        ngx_conf_merge_size_value(sh->preview_reload_limit[i],
                                  psh->preview_reload_limit[i],
                                  NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE);
    }

    if (sh->preview_reload == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(sh->preview_reload, psh->preview_reload,
                                  0);
    } else {
        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            if (named[i]) {
                continue;
            }

            if (psh->preview_reload & NGX_HTTP_WAF_OBJ_BIT(i)) {
                sh->preview_reload |= NGX_HTTP_WAF_OBJ_BIT(i);
            }
        }
    }

    ngx_conf_merge_uint_value(sh->preview_source_sent,
                              psh->preview_source_sent, 0);

    ngx_http_waf_merge_lists(sh, psh, NGX_HTTP_WAF_LIST_PREVIEW);

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        rv = ngx_http_waf_preview_budget(cf, conf, phase, i, named[i]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    room = ngx_http_waf_preview_room(conf, phase);

    if (room > NGX_HTTP_WAF_PREVIEW_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: previews add up to %uz bytes, over the %d "
                           "bytes a single agent datagram leaves them; name "
                           "the sizes explicitly", room,
                           NGX_HTTP_WAF_PREVIEW_MAX);
        return NGX_CONF_ERROR;
    }

    (void) wmcf;

    return NGX_CONF_OK;
}
