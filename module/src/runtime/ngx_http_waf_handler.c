#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "bus/ngx_http_waf_bus.h"
#include "local/ngx_http_waf_local.h"


static ngx_int_t ngx_http_waf_ctx_variable(ngx_http_request_t *r,
                     ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_waf_access(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_handshake_guard(ngx_http_waf_ctx_t *ctx);
static void      ngx_http_waf_ws_strip(ngx_http_waf_ctx_t *ctx,
                     ngx_array_t *strip);
static ngx_uint_t ngx_http_waf_ws_strip_one(ngx_http_waf_ctx_t *ctx,
                     ngx_table_elt_t *ext, ngx_array_t *strip, ngx_uint_t all,
                     ngx_uint_t *kept);
static ngx_int_t ngx_http_waf_local_deny(ngx_http_waf_ctx_t *ctx,
                     ngx_str_t *rule, ngx_str_t *response, ngx_uint_t code);
static void      ngx_http_waf_breaker_account(ngx_http_waf_slot_t *slot,
                     uint64_t mask, ngx_uint_t timed_out);
static void      ngx_http_waf_on_deadline(ngx_event_t *ev);
static void      ngx_http_waf_deadline_arm(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_deadline_stop(ngx_http_waf_ctx_t *ctx);
static void      ngx_http_waf_expire(ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_fail(ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_body_ready(ngx_http_request_t *r);

static ngx_uint_t ngx_http_waf_exception_policy(ngx_http_waf_ctx_t *ctx,
                     ngx_uint_t *exc);
static void      ngx_http_waf_fail_pass(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_fail_policy(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_wave_needs_body(ngx_http_waf_ctx_t *ctx,
                     ngx_uint_t wave);
static ngx_http_waf_slot_t *ngx_http_waf_ensure_slot(ngx_http_waf_ctx_t *ctx);
static void      ngx_http_waf_slot_drop(ngx_http_waf_ctx_t *ctx);
static void      ngx_http_waf_discard_body(ngx_http_waf_ctx_t *ctx);
static ngx_uint_t ngx_http_waf_wave_closed(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static ngx_uint_t ngx_http_waf_wave_advances(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_settle(ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_conclude(ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_rewrite_settle(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_return_to_phases(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_finish_done(ngx_http_waf_ctx_t *ctx);


static ngx_str_t  ngx_http_waf_ctx_var_name = ngx_string("waf_internal_ctx");

/* resumes nested in the access handler leave posted requests to its caller */
static ngx_uint_t  ngx_http_waf_access_depth;


static ngx_int_t
ngx_http_waf_ctx_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_int_t
ngx_http_waf_ctx_var_init(ngx_conf_t *cf)
{
    ngx_int_t                  index;
    ngx_http_variable_t       *var;
    ngx_http_waf_main_conf_t  *wmcf;

    var = ngx_http_add_variable(cf, &ngx_http_waf_ctx_var_name,
                                NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_waf_ctx_variable;

    index = ngx_http_get_variable_index(cf, &ngx_http_waf_ctx_var_name);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    wmcf->ctx_var_index = (ngx_uint_t) index;

    return NGX_OK;
}


ngx_http_waf_ctx_t *
ngx_http_waf_get_ctx(ngx_http_request_t *r)
{
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_variable_value_t  *vv;
    ngx_http_waf_main_conf_t   *wmcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx != NULL) {
        return ctx;
    }

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf->ctx_var_index == NGX_CONF_UNSET_UINT) {
        return NULL;
    }

    vv = &r->variables[wmcf->ctx_var_index];

    if (!vv->valid || vv->data == NULL) {
        return NULL;
    }

    ctx = (ngx_http_waf_ctx_t *) vv->data;

    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    return ctx;
}


ngx_int_t
ngx_http_waf_set_ctx(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_variable_value_t  *vv;
    ngx_http_waf_main_conf_t   *wmcf;

    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf->ctx_var_index == NGX_CONF_UNSET_UINT) {
        return NGX_ERROR;
    }

    vv = &r->variables[wmcf->ctx_var_index];

    vv->valid        = 1;
    vv->not_found    = 0;
    vv->no_cacheable = 0;
    vv->len          = 0;
    vv->data         = (u_char *) ctx;

    return NGX_OK;
}


void
ngx_http_waf_vars_eval(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf->vars == NULL) {
        return;
    }

    n = wmcf->vars->nelts;

    ctx->vars = ngx_pcalloc(r->pool, n * sizeof(ngx_str_t));
    if (ctx->vars == NULL) {
        return;
    }

    var = wmcf->vars->elts;

    for (i = 0; i < n; i++) {
        if (ngx_http_complex_value(r, &var[i].value, &ctx->vars[i]) != NGX_OK) {
            ngx_str_null(&ctx->vars[i]);
        }
    }
}


ngx_int_t
ngx_http_waf_access_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    ngx_http_waf_access_depth++;

    rc = ngx_http_waf_access(r);

    /* a 401 or 403 left to the phase checker is overridable by "satisfy any" */

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        rc = NGX_DONE;
    }

    ngx_http_waf_access_depth--;

    return rc;
}


static ngx_int_t
ngx_http_waf_access(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (!wlcf->enable) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->request = r;
        ctx->state   = NGX_HTTP_WAF_ST_INIT;
        ctx->slot    = NGX_HTTP_WAF_SLOT_NIL;
        ctx->started = ngx_current_msec;

        ngx_http_waf_phase_enter(ctx, NGX_HTTP_WAF_PHASE_REQUEST);

        ctx->ph->body_policy = NGX_HTTP_WAF_POLICY_UNSET;

        ngx_memset(ctx->rid_hex, '-', NGX_HTTP_WAF_RID_HEX_LEN);

        ngx_http_waf_ray_next(ctx->ray_hex);

        if (ngx_http_waf_set_ctx(r, ctx) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_waf_vars_eval(ctx);

        ngx_http_waf_strip_accept_encoding(ctx);

        rc = ngx_http_waf_handshake_guard(ctx);
        if (rc != NGX_DECLINED) {
            return rc;
        }

        rc = ngx_http_waf_local_checks(ctx);
        if (rc != NGX_DECLINED) {
            return rc;
        }

        if (ngx_http_waf_wave_count(ctx) == 0
            || !ngx_http_waf_waves_pending(ctx))
        {
            ctx->ph->journal = 1;
            ctx->state       = NGX_HTTP_WAF_ST_DONE;
            return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);
        }

        return ngx_http_waf_wave_start(ctx, 0);
    }

    switch (ctx->state) {

    case NGX_HTTP_WAF_ST_WAITING:
        return NGX_DONE;

    case NGX_HTTP_WAF_ST_NEED_BODY:
        ctx->state = NGX_HTTP_WAF_ST_READING_BODY;

        rc = ngx_http_read_client_request_body(r, ngx_http_waf_body_ready);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        ngx_http_finalize_request(r, NGX_DONE);

        return NGX_DONE;

    case NGX_HTTP_WAF_ST_READING_BODY:

        /* an internal redirect to the error page of a failed body read */

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: the request body was not read, the error page "
                      "goes uninspected, ray %*s",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->state = NGX_HTTP_WAF_ST_DONE;
        return NGX_DECLINED;

    case NGX_HTTP_WAF_ST_PLACING_META:
    case NGX_HTTP_WAF_ST_FETCHING_FORM:
        return NGX_DONE;

    case NGX_HTTP_WAF_ST_FINISH:
        return ngx_http_waf_finish_done(ctx);

    case NGX_HTTP_WAF_ST_NEXT_WAVE:
        return ngx_http_waf_wave_start(ctx, ctx->ph->wave);

    case NGX_HTTP_WAF_ST_DONE:
        return NGX_DECLINED;

    default:
        return ngx_http_waf_phase_apply(ctx);
    }
}


ngx_int_t
ngx_http_waf_phase_apply(ngx_http_waf_ctx_t *ctx)
{
    switch (ctx->state) {

    case NGX_HTTP_WAF_ST_ALLOW:
        ctx->state = NGX_HTTP_WAF_ST_DONE;
        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);

    case NGX_HTTP_WAF_ST_DENY:
    case NGX_HTTP_WAF_ST_REDIRECT:
        ctx->state = NGX_HTTP_WAF_ST_DONE;
        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);

    default:
        return ngx_http_waf_fail_policy(ctx);
    }
}


ngx_int_t
ngx_http_waf_phase_resume(ngx_http_waf_ctx_t *ctx)
{
    switch (ctx->state) {

    case NGX_HTTP_WAF_ST_NEXT_WAVE:
        return ngx_http_waf_wave_start(ctx, ctx->ph->wave);

    case NGX_HTTP_WAF_ST_FINISH:
        return ngx_http_waf_finish_done(ctx);

    default:
        return ngx_http_waf_phase_apply(ctx);
    }
}


ngx_int_t
ngx_http_waf_wave_start(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    ngx_int_t                  rc;
    ngx_uint_t                 need;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_slot_t       *slot;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    ctx->ph->wave = wave;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST
        && !ctx->ph->body_ready && ngx_http_waf_wave_needs_body(ctx, wave))
    {
        ctx->state = NGX_HTTP_WAF_ST_NEED_BODY;
        return ngx_http_waf_access(r);
    }

    slot = ngx_http_waf_ensure_slot(ctx);
    if (slot == NULL) {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BUS;
        ctx->state    = NGX_HTTP_WAF_ST_FAILED;
        return ngx_http_waf_fail_policy(ctx);
    }

    need = ngx_http_waf_meta_wave_need(ctx, wave);

    if (!ctx->ph->meta_settled && need != 0) {
        rc = ngx_http_waf_meta_place(ctx, need);

        if (rc == NGX_AGAIN) {
            ctx->state = NGX_HTTP_WAF_ST_PLACING_META;
            return NGX_DONE;
        }

        if (rc != NGX_OK) {
            ngx_http_waf_slot_release(slot);
            ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
            ctx->state    = NGX_HTTP_WAF_ST_FAILED;
            return ngx_http_waf_fail_policy(ctx);
        }
    }

    if (ngx_http_waf_wave_needs_body(ctx, wave)) {

        if (!ctx->ph->body_ready) {
            ctx->state = NGX_HTTP_WAF_ST_NEED_BODY;

            if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
                return ngx_http_waf_response_body(ctx);
            }

            return ngx_http_waf_frame_body(ctx);
        }

        if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST) {
            rc = ngx_http_waf_body_place(ctx);

            if (rc == NGX_AGAIN) {
                ctx->state = NGX_HTTP_WAF_ST_PLACING_META;
                return NGX_DONE;
            }

            if (rc != NGX_OK) {
                ngx_http_waf_slot_release(slot);
                ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
                ctx->state    = NGX_HTTP_WAF_ST_FAILED;
                return ngx_http_waf_fail_policy(ctx);
            }
        }
    }

    if (ctx->ph->replies == NULL && wmcf->inspectors.nelts != 0) {
        ctx->ph->replies = ngx_pcalloc(r->pool, wmcf->inspectors.nelts
                                                * sizeof(ngx_http_waf_reply_t));
        if (ctx->ph->replies == NULL) {
            ngx_http_waf_slot_release(slot);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ctx->ph->due == 0) {
        ctx->ph->due = ngx_current_msec + wlcf->deadline[ctx->phase];
    }

    slot->published = ngx_current_msec;

    if (ngx_http_waf_bus_publish_wave(ctx, slot) != NGX_OK) {
        ngx_http_waf_slot_release(slot);
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BUS;
        ctx->state    = NGX_HTTP_WAF_ST_FAILED;
        return ngx_http_waf_fail_policy(ctx);
    }

    if (!ngx_http_waf_phase_is_frame(ctx->phase)) {
        ngx_http_waf_rate_charge_wave(ctx);
    }

    if (ngx_http_waf_wave_closed(ctx, slot)) {

        ngx_http_waf_rewrite_settle(ctx, slot);

        if (ngx_http_waf_wave_advances(ctx, slot)) {
            ngx_http_waf_slot_release(slot);
            return ngx_http_waf_wave_start(ctx, wave + 1);
        }

        ngx_http_waf_deadline_stop(ctx);
        ngx_http_waf_slot_release(slot);
        ngx_http_waf_resolve_verdict(ctx);
        ngx_http_waf_fail_pass(ctx);

        return ngx_http_waf_phase_apply(ctx);
    }

    ngx_http_waf_deadline_arm(ctx, slot);

    if (!ngx_http_waf_phase_is_frame(ctx->phase)) {
        r->read_event_handler  = ngx_http_test_reading;
        r->write_event_handler = ngx_http_request_empty_handler;
    }

    ctx->state   = NGX_HTTP_WAF_ST_WAITING;
    ctx->waiting = 1;

    return NGX_DONE;
}


static ngx_uint_t
ngx_http_waf_wave_closed(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    return (slot->got & slot->awaited) == slot->awaited;
}


static ngx_uint_t
ngx_http_waf_wave_advances(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    ngx_int_t             threshold;
    ngx_http_waf_wave_t  *wave;

    if (ctx->ph->wave + 1 >= ngx_http_waf_wave_count(ctx)) {
        return 0;
    }

    if (ctx->ph->fail != NGX_HTTP_WAF_CODE_NONE) {
        return 0;
    }

    threshold = ngx_http_waf_score_deny_at(ctx);

    if (threshold > 0 && ctx->ph->score >= threshold) {
        return 0;
    }

    wave = ngx_http_waf_current_wave(ctx);

    if (wave != NULL
        && (slot->denied & ngx_http_waf_wave_gating(ctx, wave)))
    {
        return 0;
    }

    return 1;
}


void
ngx_http_waf_on_reply(ngx_http_waf_slot_t *slot, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    uint64_t                  bit;
    ngx_http_waf_ctx_t       *ctx = slot->ctx;
    ngx_http_waf_wave_t      *wave;
    ngx_http_waf_loc_conf_t  *wlcf;

    wave = ngx_http_waf_current_wave(ctx);
    if (wave == NULL) {
        return;
    }

    bit = 1ULL << index;

    if (!(bit & wave->all)) {
        return;
    }

    if (slot->got & bit) {
        return;
    }

    slot->got |= bit;
    ctx->ph->got  |= bit;

    ngx_http_waf_breaker_account(slot, bit,
                                 reply->verdict == NGX_HTTP_WAF_V_ERROR);

    if (ctx->ph->replies != NULL) {
        ctx->ph->replies[index]          = *reply;
        ctx->ph->replies[index].received = 1;
        ctx->ph->replies[index].state    = NGX_HTTP_WAF_ENTRY_ANSWERED;
        ctx->ph->replies[index].passive  =
            (ngx_http_waf_wave_passive(ctx, wave) & bit) ? 1 : 0;
        ctx->ph->replies[index].vote     =
            (ngx_http_waf_wave_vote(ctx, wave) & bit) ? 1 : 0;
        ctx->ph->replies[index].latency  = ngx_current_msec - slot->published;
        ctx->ph->replies[index].wave     = slot->wave;

        ngx_http_waf_account(ctx, index, &ctx->ph->replies[index]);

        ngx_http_waf_actions_merge(ctx, index, &ctx->ph->replies[index],
                                   slot->wave);

        ngx_http_waf_sessions_merge(ctx, index, &ctx->ph->replies[index]);
    }

    if (reply->verdict == NGX_HTTP_WAF_V_ERROR) {

        if (bit & ngx_http_waf_wave_gating(ctx, wave)) {
            ctx->ph->fail = reply->overload
                                ? NGX_HTTP_WAF_CODE_FAIL_OVERLOAD
                                : NGX_HTTP_WAF_CODE_FAIL_INSPECTOR;
            ngx_http_waf_resume(slot);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: non-gating inspector %ui could not inspect", index);

        ngx_http_waf_settle(slot);
        return;
    }

    if (reply->verdict == NGX_HTTP_WAF_V_DENY
        || reply->verdict == NGX_HTTP_WAF_V_REDIRECT)
    {
        slot->denied |= bit;

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        if (wlcf->deny_mode[ctx->phase] == NGX_HTTP_WAF_DENY_FAST
            && (bit & ngx_http_waf_wave_gating(ctx, wave)))
        {
            ngx_http_waf_resume(slot);
            return;
        }
    }

    ngx_http_waf_settle(slot);
}


void
ngx_http_waf_omit(ngx_http_waf_slot_t *slot, ngx_http_waf_mask_t mask,
    ngx_uint_t state)
{
    uint64_t             bit;
    ngx_uint_t           index;
    ngx_http_waf_ctx_t  *ctx = slot->ctx;

    if (state == NGX_HTTP_WAF_ENTRY_SKIPPED) {
        ctx->ph->skipped |= mask;

    } else {
        ctx->ph->controlled |= mask;
    }

    slot->got |= mask;

    while (mask) {
        index = ngx_http_waf_lowest_bit(mask);
        bit   = 1ULL << index;
        mask &= ~bit;

        if (ctx->ph->replies != NULL) {
            ctx->ph->replies[index].state = state;
        }
    }
}


void
ngx_http_waf_skip(ngx_http_waf_slot_t *slot, ngx_uint_t index, ngx_uint_t code)
{
    uint64_t              bit;
    ngx_http_waf_ctx_t   *ctx = slot->ctx;
    ngx_http_waf_wave_t  *wave;

    wave = ngx_http_waf_current_wave(ctx);
    if (wave == NULL) {
        return;
    }

    bit = 1ULL << index;

    if (!(bit & wave->all) || (slot->got & bit)) {
        return;
    }

    slot->got    |= bit;
    ctx->ph->skipped |= bit;

    if (ctx->ph->replies != NULL) {
        ctx->ph->replies[index].state =
            (code == NGX_HTTP_WAF_CODE_FAIL_ABSENT)
                ? NGX_HTTP_WAF_ENTRY_ABSENT
                : NGX_HTTP_WAF_ENTRY_SKIPPED;
    }

    if (bit & ngx_http_waf_wave_mandatory(ctx, wave)) {
        ctx->ph->fail = code;

    } else {
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: non-gating inspector %ui gave no verdict (%V)",
                      index, ngx_http_waf_code_name(code));
    }

    ngx_http_waf_settle(slot);
}


static void
ngx_http_waf_rewrite_settle(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    ngx_str_t                 *stale;
    ngx_uint_t                 i, n, found;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_locator_t    *live, *from;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->replies == NULL) {
        return;
    }

    wmcf  = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp  = wmcf->inspectors.elts;
    n     = wmcf->inspectors.nelts;
    found = NGX_HTTP_WAF_MAX_INSPECTORS;

    for (i = 0; i < n; i++) {

        if (!(slot->got & (1ULL << i))) {
            continue;
        }

        reply = &ctx->ph->replies[i];

        if (!reply->received || reply->passive || reply->vote
            || !reply->rewrite_has || !reply->rewrite_body
            || reply->verdict == NGX_HTTP_WAF_V_DENY)
        {
            continue;
        }

        if (found != NGX_HTTP_WAF_MAX_INSPECTORS) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspectors \"%V\" and \"%V\" both rewrote the "
                          "%V body on wave %ui; the version cannot be "
                          "assembled, waf_exception %V body decides, ray %*s",
                          &insp[found].name, &insp[i].name,
                          ngx_http_waf_phase_name(ctx->phase), ctx->ph->wave,
                          ngx_http_waf_phase_name(ctx->phase),
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

            ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
            return;
        }

        found = i;
    }

    if (found == NGX_HTTP_WAF_MAX_INSPECTORS) {
        return;
    }

    if (ctx->ph->rewrite_depth >= NGX_HTTP_WAF_REWRITE_MAX_DEPTH) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" rewrote the %V body past the "
                      "chain limit of %ui versions; waf_exception %V body "
                      "decides, ray %*s",
                      &insp[found].name, ngx_http_waf_phase_name(ctx->phase),
                      (ngx_uint_t) NGX_HTTP_WAF_REWRITE_MAX_DEPTH,
                      ngx_http_waf_phase_name(ctx->phase),
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
        return;
    }

    reply = &ctx->ph->replies[found];

    from = ngx_http_waf_store_locator_live(ctx, ctx->phase,
                                           NGX_HTTP_WAF_OBJ_BODY);
    if (from == NULL) {
        return;
    }

    live = ngx_palloc(ctx->request->pool, sizeof(ngx_http_waf_locator_t));
    if (live == NULL) {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
        return;
    }

    *live                  = *from;
    live->key              = reply->rewrite_key;
    live->size             = reply->rewrite_size;
    live->truncated        = 0;
    live->inline_data.data = NULL;
    live->inline_data.len  = 0;

    if (reply->rewrite_sha256_set) {
        ngx_memcpy(live->sha256, reply->rewrite_sha256, 32);

    } else {
        ngx_memzero(live->sha256, 32);
    }

    if (ctx->ph->live != NULL) {

        if (ctx->ph->stale == NULL) {
            ctx->ph->stale = ngx_array_create(ctx->request->pool, 2,
                                              sizeof(ngx_str_t));
            if (ctx->ph->stale == NULL) {
                ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
                return;
            }
        }

        stale = ngx_array_push(ctx->ph->stale);
        if (stale == NULL) {
            ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
            return;
        }

        *stale = ctx->ph->live->key;
    }

    ctx->ph->live         = live;
    ctx->ph->rewrite_last = found;
    ctx->ph->rewrite_depth++;
    ctx->ph->rewrite_applied |= 1ULL << found;

    ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                  "waf: inspector \"%V\" published version %ui of the %V body, "
                  "%O bytes, ray %*s",
                  &insp[found].name, ctx->ph->rewrite_depth,
                  ngx_http_waf_phase_name(ctx->phase), live->size,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
}


static void
ngx_http_waf_settle(ngx_http_waf_slot_t *slot)
{
    ngx_http_waf_ctx_t  *ctx = slot->ctx;

    if (!ctx->waiting) {
        return;
    }

    if (!ngx_http_waf_wave_closed(ctx, slot)) {
        return;
    }

    ngx_http_waf_rewrite_settle(ctx, slot);

    if (ngx_http_waf_wave_advances(ctx, slot)) {
        ngx_http_waf_slot_release(slot);

        ctx->ph->wave++;
        ctx->state = NGX_HTTP_WAF_ST_NEXT_WAVE;

        ngx_http_waf_return_to_phases(ctx);
        return;
    }

    ngx_http_waf_conclude(slot);
}


void
ngx_http_waf_resume(ngx_http_waf_slot_t *slot)
{
    if (slot->ctx == NULL) {
        return;
    }

    ngx_http_waf_rewrite_settle(slot->ctx, slot);
    ngx_http_waf_conclude(slot);
}


static void
ngx_http_waf_conclude(ngx_http_waf_slot_t *slot)
{
    ngx_http_waf_ctx_t  *ctx = slot->ctx;

    ngx_http_waf_deadline_stop(ctx);
    ngx_http_waf_slot_release(slot);
    ngx_http_waf_resolve_verdict(ctx);
    ngx_http_waf_fail_pass(ctx);

    ngx_http_waf_return_to_phases(ctx);
}


static void
ngx_http_waf_fail(ngx_http_waf_slot_t *slot)
{
    ngx_http_waf_ctx_t   *ctx = slot->ctx;
    ngx_http_waf_wave_t  *wave;

    wave = ngx_http_waf_current_wave(ctx);

    ngx_http_waf_breaker_account(slot, slot->awaited & ~slot->got, 1);

    if (wave != NULL
        && (slot->got & ngx_http_waf_wave_mandatory(ctx, wave))
           == ngx_http_waf_wave_mandatory(ctx, wave))
    {
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: non-gating inspectors did not answer in time, "
                      "mask %uxL",
                      (uint64_t) (ngx_http_waf_wave_passive(ctx, wave)
                                  & ~slot->got));

    } else {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_TIMEOUT;
    }

    ngx_http_waf_resume(slot);
}


static void
ngx_http_waf_expire(ngx_http_waf_slot_t *slot)
{
    uint64_t                  bit;
    ngx_uint_t                index;
    ngx_http_waf_ctx_t       *ctx = slot->ctx;
    ngx_http_waf_mask_t       pending, expired;
    ngx_http_waf_wave_t      *wave;
    ngx_http_waf_binding_t   *bind;
    ngx_http_waf_loc_conf_t  *wlcf;

    wave = ngx_http_waf_current_wave(ctx);
    if (wave == NULL) {
        ngx_http_waf_fail(slot);
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    pending = slot->awaited & ~slot->got;
    expired = 0;

    while (pending) {
        index    = ngx_http_waf_lowest_bit(pending);
        bit      = 1ULL << index;
        pending &= ~bit;

        bind = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

        if (bind == NULL || bind->timeout == 0
            || (ngx_msec_int_t) (slot->published + bind->timeout
                                 - ngx_current_msec) > 0)
        {
            continue;
        }

        expired |= bit;

        if (ctx->ph->replies != NULL) {
            ctx->ph->replies[index].state = NGX_HTTP_WAF_ENTRY_TIMEOUT;
        }
    }

    if (expired == 0) {
        ngx_http_waf_deadline_arm(ctx, slot);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                  "waf: inspectors %uxL did not answer within their timeout "
                  "on wave %ui, rid %*s",
                  (uint64_t) expired, ctx->ph->wave,
                  (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);

    ngx_http_waf_breaker_account(slot, expired, 1);

    slot->got |= expired;

    if (expired & ngx_http_waf_wave_mandatory(ctx, wave)) {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_TIMEOUT;
    }

    if (ngx_http_waf_wave_closed(ctx, slot)) {
        ngx_http_waf_settle(slot);
        return;
    }

    ngx_http_waf_deadline_arm(ctx, slot);
}


static void
ngx_http_waf_return_to_phases(ngx_http_waf_ctx_t *ctx)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        ngx_http_waf_response_resume(ctx);
        return;
    }

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        ngx_http_waf_frame_resume(ctx);
        return;
    }

    ctx->waiting = 0;

    c = r->connection;

    r->read_event_handler  = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;

    ngx_http_core_run_phases(r);

    if (ngx_http_waf_access_depth == 0) {
        ngx_http_run_posted_requests(c);
    }
}


static void
ngx_http_waf_deadline_arm(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    uint64_t                  bit;
    ngx_msec_t                at, until;
    ngx_uint_t                index;
    ngx_msec_int_t            left;
    ngx_http_waf_mask_t       pending;
    ngx_http_waf_binding_t   *bind;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    at      = ctx->ph->due;
    pending = slot->awaited & ~slot->got;

    while (pending) {
        index    = ngx_http_waf_lowest_bit(pending);
        bit      = 1ULL << index;
        pending &= ~bit;

        bind = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

        if (bind == NULL || bind->timeout == 0) {
            continue;
        }

        until = slot->published + bind->timeout;

        if ((ngx_msec_int_t) (until - at) < 0) {
            at = until;
        }
    }

    if (ctx->deadline.timer_set) {
        ngx_del_timer(&ctx->deadline);
    }

    ctx->deadline.handler = ngx_http_waf_on_deadline;
    ctx->deadline.data    = ctx;
    ctx->deadline.log     = ctx->request->connection->log;

    left = (ngx_msec_int_t) (at - ngx_current_msec);

    ngx_add_timer(&ctx->deadline, left > 0 ? (ngx_msec_t) left : 0);
}


static void
ngx_http_waf_deadline_stop(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->deadline.timer_set) {
        ngx_del_timer(&ctx->deadline);
    }
}


static void
ngx_http_waf_on_deadline(ngx_event_t *ev)
{
    ngx_http_waf_ctx_t   *ctx = ev->data;
    ngx_http_waf_slot_t  *slot;

    if (!ctx->waiting) {
        return;
    }

    slot = ngx_http_waf_slot_lookup(ctx->rid);
    if (slot == NULL) {
        return;
    }

    if ((ngx_msec_int_t) (ctx->ph->due - ngx_current_msec) > 0) {
        ngx_http_waf_expire(slot);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                  "waf: deadline expired on wave %ui, awaited %uxL, got %uxL, "
                  "rid %*s",
                  ctx->ph->wave, (uint64_t) slot->awaited, (uint64_t) slot->got,
                  (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);

    ngx_http_waf_fail(slot);
}


static void
ngx_http_waf_body_ready(ngx_http_request_t *r)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);
    if (ctx == NULL) {
        return;
    }

    ctx->ph->body_ready = 1;

    r->preserve_body = 1;

    ngx_http_waf_body_resumed(ctx, NGX_OK);
}


void
ngx_http_waf_form_resumed(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->state != NGX_HTTP_WAF_ST_FETCHING_FORM) {
        return;
    }

    ctx->state = NGX_HTTP_WAF_ST_FINISH;
    ngx_http_waf_return_to_phases(ctx);
}


void
ngx_http_waf_body_resumed(ngx_http_waf_ctx_t *ctx, ngx_int_t rc)
{
    if (ctx->state != NGX_HTTP_WAF_ST_NEED_BODY
        && ctx->state != NGX_HTTP_WAF_ST_READING_BODY
        && ctx->state != NGX_HTTP_WAF_ST_PLACING_META)
    {
        return;
    }

    if (ctx->ph->agent_after_body) {
        ctx->ph->agent_after_body = 0;
        ctx->ph->agent_settled    = 1;
        ctx->state = NGX_HTTP_WAF_ST_FINISH;
        ngx_http_waf_return_to_phases(ctx);
        return;
    }

    if (rc != NGX_OK) {
        ngx_http_waf_slot_drop(ctx);
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
        ctx->state    = NGX_HTTP_WAF_ST_FAILED;

    } else {
        ctx->state = NGX_HTTP_WAF_ST_NEXT_WAVE;
    }

    ngx_http_waf_return_to_phases(ctx);
}


ngx_int_t
ngx_http_waf_local_checks(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;
    ngx_str_t  rule, response;

    if (ngx_http_waf_shm() == NULL) {
        return NGX_DECLINED;
    }

    ngx_str_null(&rule);
    ngx_str_null(&response);

    rc = ngx_http_waf_dataset_check(ctx, &rule, &response);

    if (rc == NGX_ERROR) {
        return ngx_http_waf_local_deny(ctx, &rule, &response,
                                       NGX_HTTP_WAF_CODE_LOCAL_LIST);
    }

    if (rc == NGX_DONE) {
        return NGX_DECLINED;
    }

    if (rc == NGX_OK) {
        ctx->ph->verdict = NGX_HTTP_WAF_V_ALLOW;
        ctx->state   = NGX_HTTP_WAF_ST_DONE;

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: allowed by local check \"%V\", ray %*s", &rule,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);
    }

    rc = ngx_http_waf_rate_check(ctx, &rule, &response);

    if (rc == NGX_DECLINED) {
        return ngx_http_waf_local_deny(ctx, &rule, &response,
                                       NGX_HTTP_WAF_CODE_LOCAL_RATE);
    }

    return NGX_DECLINED;
}


static ngx_str_t  ngx_http_waf_upgrade_rule = ngx_string("require_upgrade");


static ngx_int_t
ngx_http_waf_handshake_guard(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                upgrade;
    ngx_table_elt_t          *h;
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->ws_strip_ext != NULL && wlcf->ws_strip_ext->nelts != 0) {
        ngx_http_waf_ws_strip(ctx, wlcf->ws_strip_ext);
    }

    if (wlcf->require_upgrade != 1) {
        return NGX_DECLINED;
    }

    h = r->headers_in.upgrade;

    upgrade = (h != NULL && h->hash != 0
               && h->value.len == sizeof("websocket") - 1
               && ngx_strncasecmp(h->value.data, (u_char *) "websocket",
                                  sizeof("websocket") - 1) == 0);

    if (upgrade) {
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: request without websocket upgrade on a websocket "
                  "location, denied, ray %*s",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return ngx_http_waf_local_deny(ctx, &ngx_http_waf_upgrade_rule,
                                   &wlcf->require_upgrade_response,
                                   NGX_HTTP_WAF_CODE_LOCAL_UPGRADE);
}


static void
ngx_http_waf_ws_strip(ngx_http_waf_ctx_t *ctx, ngx_array_t *strip)
{
    ngx_str_t           *names;
    ngx_uint_t           i, all, kept, removed;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    names = strip->elts;
    all   = 0;

    for (i = 0; i < strip->nelts; i++) {
        if (names[i].len == 3 && ngx_strncmp(names[i].data, "all", 3) == 0) {
            all = 1;
        }
    }

    part    = &r->headers_in.headers.part;
    h       = part->elts;
    kept    = 0;
    removed = 0;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].key.len != sizeof("Sec-WebSocket-Extensions") - 1
            || ngx_strncasecmp(h[i].key.data,
                               (u_char *) "Sec-WebSocket-Extensions",
                               h[i].key.len) != 0
            || h[i].value.len == 0)
        {
            continue;
        }

        removed += ngx_http_waf_ws_strip_one(ctx, &h[i], strip, all, &kept);
    }

    if (removed == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: stripped %ui websocket extension(s) from the "
                  "handshake, %ui left, ray %*s", removed, kept,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
}


static ngx_uint_t
ngx_http_waf_ws_strip_one(ngx_http_waf_ctx_t *ctx, ngx_table_elt_t *ext,
    ngx_array_t *strip, ngx_uint_t all, ngx_uint_t *kept)
{
    u_char              *p, *start, *end, *name_end, *out, *o;
    ngx_str_t           *names, name;
    ngx_uint_t           i, n, left, removed;
    ngx_http_request_t  *r = ctx->request;

    names = strip->elts;
    n     = strip->nelts;

    out = ngx_pnalloc(r->pool, ext->value.len);
    if (out == NULL) {
        return 0;
    }

    o       = out;
    left    = 0;
    removed = 0;
    p       = ext->value.data;
    end     = ext->value.data + ext->value.len;

    while (p < end) {
        start = p;

        while (p < end && *p != ',') {
            p++;
        }

        name_end = start;

        while (name_end < p && *name_end != ';') {
            name_end++;
        }

        name.data = start;
        name.len  = name_end - start;

        while (name.len != 0 && (name.data[0] == ' ' || name.data[0] == '\t')) {
            name.data++;
            name.len--;
        }

        while (name.len != 0 && (name.data[name.len - 1] == ' '
                                 || name.data[name.len - 1] == '\t'))
        {
            name.len--;
        }

        if (all) {
            removed++;

        } else {
            for (i = 0; i < n; i++) {
                if (names[i].len == name.len
                    && ngx_strncasecmp(names[i].data, name.data, name.len)
                       == 0)
                {
                    break;
                }
            }

            if (i < n) {
                removed++;

            } else {
                if (left != 0) {
                    *o++ = ',';
                }

                o = ngx_cpymem(o, start, p - start);
                left++;
            }
        }

        if (p < end) {
            p++;
        }
    }

    *kept += left;

    if (removed == 0) {
        return 0;
    }

    if (left != 0) {
        ext->value.data = out;
        ext->value.len  = o - out;
        return removed;
    }

    ngx_str_set(&ext->key, "X-WAF-Stripped-Extensions");

    ext->lowcase_key = ngx_pnalloc(r->pool, ext->key.len);
    if (ext->lowcase_key == NULL) {
        ext->hash = 0;
        return removed;
    }

    ngx_strlow(ext->lowcase_key, ext->key.data, ext->key.len);
    ext->hash = ngx_hash_key(ext->lowcase_key, ext->key.len);

    return removed;
}


static ngx_int_t
ngx_http_waf_local_deny(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule,
    ngx_str_t *response, ngx_uint_t code)
{
    ctx->by_local        = 1;
    ctx->local_rule      = *rule;
    ctx->local_response  = *response;
    ctx->ph->code            = code;
    ctx->ph->verdict         = NGX_HTTP_WAF_V_DENY;
    ctx->state           = NGX_HTTP_WAF_ST_DONE;

    if (!ngx_http_waf_phase_is_frame(ctx->phase)) {
        ctx->ph->journal = 1;
    }

    return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);
}


static void
ngx_http_waf_breaker_account(ngx_http_waf_slot_t *slot, uint64_t mask,
    ngx_uint_t timed_out)
{
    uint64_t                   bit;
    ngx_uint_t                 index;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    if (mask == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(slot->ctx->request,
                                        ngx_http_waf_module);
    inspectors = wmcf->inspectors.elts;

    while (mask) {
        index = ngx_http_waf_lowest_bit(mask);
        bit   = 1ULL << index;
        mask &= ~bit;

        if (index >= wmcf->inspectors.nelts) {
            continue;
        }

        ngx_http_waf_breaker_result(index, &inspectors[index], timed_out);
    }
}


static ngx_int_t
ngx_http_waf_wave_needs_body(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    return (ngx_http_waf_body_wave_need(ctx, wave) != NGX_HTTP_WAF_BODY_NONE);
}


static ngx_http_waf_slot_t *
ngx_http_waf_ensure_slot(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->slot != NGX_HTTP_WAF_SLOT_NIL) {
        return ngx_http_waf_slot_lookup(ctx->rid);
    }

    return ngx_http_waf_slot_acquire(ctx);
}


static void
ngx_http_waf_slot_drop(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_slot_t  *slot;

    if (ctx->slot == NGX_HTTP_WAF_SLOT_NIL) {
        return;
    }

    slot = ngx_http_waf_slot_lookup(ctx->rid);

    if (slot != NULL) {
        ngx_http_waf_slot_release(slot);
    }

    ctx->slot = NGX_HTTP_WAF_SLOT_NIL;
}


static ngx_uint_t
ngx_http_waf_exception_policy(ngx_http_waf_ctx_t *ctx, ngx_uint_t *exc)
{
    ngx_uint_t                policy;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    *exc   = ngx_http_waf_exc_of(ctx->ph->fail);
    policy = wlcf->exception[ctx->phase][*exc];

    if (*exc == NGX_HTTP_WAF_EXC_BODY
        && ctx->ph->body_policy != NGX_HTTP_WAF_POLICY_UNSET)
    {
        policy = ctx->ph->body_policy;
    }

    return policy;
}


static void
ngx_http_waf_fail_pass(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  exc;

    if (ctx->state != NGX_HTTP_WAF_ST_FAILED
        || ngx_http_waf_exception_policy(ctx, &exc)
           != NGX_HTTP_WAF_POLICY_PASS)
    {
        return;
    }

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: no verdict (%V), policy pass",
                  ngx_http_waf_code_name(ctx->ph->fail));

    ctx->state = NGX_HTTP_WAF_ST_ALLOW;
}


static ngx_int_t
ngx_http_waf_fail_policy(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                exc, policy;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ctx->state = NGX_HTTP_WAF_ST_DONE;

    policy = ngx_http_waf_exception_policy(ctx, &exc);

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: no verdict (%V), policy %s",
                  ngx_http_waf_code_name(ctx->ph->fail),
                  policy == NGX_HTTP_WAF_POLICY_PASS ? "pass" : "block");

    if (policy == NGX_HTTP_WAF_POLICY_PASS) {
        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);
    }

    ctx->ph->code         = ctx->ph->fail;
    ctx->ph->fail_blocked = 1;

    ctx->exception_response = wlcf->exception_response[ctx->phase][exc];

    return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_FAIL);
}


ngx_int_t
ngx_http_waf_finish(ngx_http_waf_ctx_t *ctx, ngx_uint_t how)
{
    ngx_http_waf_deadline_stop(ctx);
    ngx_http_waf_slot_drop(ctx);

    ctx->finish_how = how;

    if (!ctx->ph->agent_settled) {

        if (ngx_http_waf_agent_needs_body(ctx)) {
            ctx->ph->agent_after_body = 1;
            ctx->state = NGX_HTTP_WAF_ST_NEED_BODY;
            return ngx_http_waf_access(ctx->request);
        }

        ctx->ph->agent_settled = 1;
    }

    return ngx_http_waf_finish_done(ctx);
}


static ngx_int_t
ngx_http_waf_finish_done(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    ctx->state = NGX_HTTP_WAF_ST_DONE;

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return ngx_http_waf_frame_finish(ctx, ctx->finish_how);
    }

    switch (ctx->finish_how) {

    case NGX_HTTP_WAF_FINISH_APPLY:
        ctx->state = NGX_HTTP_WAF_ST_FETCHING_FORM;

        if (ngx_http_waf_form_fetch(ctx) == NGX_AGAIN
            || ngx_http_waf_send_fetch(ctx) == NGX_AGAIN)
        {
            return NGX_DONE;
        }

        ctx->state = NGX_HTTP_WAF_ST_DONE;

        rc = ngx_http_waf_apply(ctx);

        if (rc != NGX_DECLINED && rc != NGX_DONE) {
            ngx_http_waf_discard_body(ctx);
        }

        return rc;

    case NGX_HTTP_WAF_FINISH_OVERRIDES:
        ngx_http_waf_log_verdict(ctx);
        return ngx_http_waf_apply_overrides(ctx);

    default:
        ngx_http_waf_log_verdict(ctx);
        ngx_http_waf_discard_body(ctx);
        (void) ngx_http_waf_apply_debug(ctx);
        return ngx_http_waf_fail_status(ctx);
    }
}


static void
ngx_http_waf_discard_body(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->body_ready || ctx->ph->body_discarded) {
        return;
    }

    ctx->ph->body_discarded = 1;

    (void) ngx_http_discard_request_body(ctx->request);
}


ngx_http_waf_wave_t *
ngx_http_waf_current_wave(ngx_http_waf_ctx_t *ctx)
{
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    if (waves == NULL || ctx->ph->wave >= waves->nelts) {
        return NULL;
    }

    return &((ngx_http_waf_wave_t *) waves->elts)[ctx->ph->wave];
}


ngx_uint_t
ngx_http_waf_wave_count(ngx_http_waf_ctx_t *ctx)
{
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    return (waves == NULL) ? 0 : waves->nelts;
}
