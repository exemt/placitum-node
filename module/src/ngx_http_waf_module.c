#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "bus/ngx_http_waf_bus.h"
#include "local/ngx_http_waf_local.h"


static ngx_int_t ngx_http_waf_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_init_worker(ngx_cycle_t *cycle);
static void      ngx_http_waf_exit_worker(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, enable),
      NULL },

    { ngx_string("waf_node_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, node_id),
      NULL },

    { ngx_string("waf_agent_socket"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, agent_socket),
      NULL },

    { ngx_string("waf_bus"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_bus,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_reply_max"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, reply_max),
      NULL },

    { ngx_string("waf_header_value_max"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, header_value_max),
      NULL },

    { ngx_string("waf_var"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_var,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_inspector"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_waf_inspector,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_inspect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_inspect,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_max_inflight"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, max_inflight),
      NULL },

    { ngx_string("waf_hold"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_hold,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_deadline"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_waf_deadline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_exception"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_exception,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_send"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_send,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_deny_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_phase_deny_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_score_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
          |NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_waf_score_deny,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_deny_response"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_waf_deny_response,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_deny_response_default"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, deny_response_default),
      NULL },

    { ngx_string("waf_route_id"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, route_id),
      NULL },

    { ngx_string("waf_redirect_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_redirect_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_cookie_defaults"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_cookie_defaults,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_action_max"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, action_max),
      NULL },

    { ngx_string("waf_actions_max"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, actions_max),
      NULL },

    { ngx_string("waf_strip_accept_encoding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, strip_accept_encoding),
      NULL },

    { ngx_string("waf_debug_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, debug_header),
      NULL },

    { ngx_string("waf_capture"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_capture,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_shm_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_shm_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_local_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_local_rate,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_local_dataset"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_waf_local_dataset,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_local_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_local_check,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_require_upgrade"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_require_upgrade,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_ws_strip_extensions"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_ws_strip_extensions,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_audit_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_audit_frames,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_frame_reassemble"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, frame_reassemble),
      NULL },

    { ngx_string("waf_frame_control_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_frame_control_rate,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_frame_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_frame_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_store"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_store_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_sets_store"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_sets_store_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_body_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_waf_body_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_body_max_holds"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, body_max_holds),
      NULL },

    { ngx_string("waf_archive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_archive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_audit_sample"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_audit_sample,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_preview"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_preview,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_module_ctx = {
    ngx_http_waf_preconfiguration,
    ngx_http_waf_postconfiguration,

    ngx_http_waf_create_main_conf,
    ngx_http_waf_init_main_conf,

    NULL,
    NULL,

    ngx_http_waf_create_loc_conf,
    ngx_http_waf_merge_loc_conf
};


ngx_module_t  ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,
    ngx_http_waf_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_waf_init_worker,
    NULL,
    NULL,
    ngx_http_waf_exit_worker,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_waf_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_waf_body_drivers_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_waf_ctx_var_init(cf);
}


static ngx_int_t
ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_waf_main_conf_t   *wmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (ngx_http_waf_body_validate_main(cf, wmcf) != NGX_CONF_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_check_resume_pairs(cf, wmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_check_send_routes(cf, wmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_access_handler;

    if (ngx_http_waf_variables_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_filter_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return NGX_OK;
    }

    if (ngx_http_waf_slot_table_init(cycle, wmcf->max_inflight) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_dataset_bind(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_ds_stream_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_body_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_audit_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (wmcf->bus != NULL) {
        ngx_http_waf_bus_t  *bus = wmcf->bus;

        if (ngx_http_waf_bus_inbox_build(bus, cycle, &wmcf->node_id) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_waf_presence_init(bus, cycle) != NGX_OK) {
            return NGX_ERROR;
        }

        if (bus->init_worker(bus, cycle) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_http_waf_exit_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return;
    }

    ngx_http_waf_body_exit_worker(cycle);
    ngx_http_waf_audit_exit_worker(cycle);

    if (wmcf->bus == NULL) {
        return;
    }

    ngx_http_waf_presence_stop(wmcf->bus);

    ((ngx_http_waf_bus_t *) wmcf->bus)->exit_worker(wmcf->bus, cycle);
}
