#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


static ngx_http_waf_reply_t *ngx_http_waf_pick(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t verdict, ngx_uint_t *index);


static ngx_str_t  ngx_http_waf_verdict_names[] = {
    ngx_string("allow"),
    ngx_string("score"),
    ngx_string("redirect"),
    ngx_string("deny"),
    ngx_string("error")
};


static ngx_str_t  ngx_http_waf_phase_names[] = {
    ngx_string("request"),
    ngx_string("response"),
    ngx_string("frame"),
    ngx_string("frame")
};


static ngx_str_t  ngx_http_waf_do_names[] = {
    ngx_string("challenge"),
    ngx_string("threshold"),
    ngx_string("skip"),
    ngx_string("reauth"),
    ngx_string("note"),
    ngx_string("mutate"),
    ngx_string("active"),
    ngx_string("passive"),
    ngx_string("off"),
    ngx_string("vote"),
    ngx_string("audit"),
    ngx_string("archive"),
    ngx_string("mark"),
    ngx_string("score")
};


static ngx_str_t  ngx_http_waf_apply_names[] = {
    ngx_string("request"),
    ngx_string("ip"),
    ngx_string("asn"),
    ngx_string("session"),
    ngx_string("conn"),
    ngx_string("response")
};


static ngx_str_t  ngx_http_waf_code_names[] = {
    ngx_string(""),
    ngx_string("local_list"),
    ngx_string("local_rate"),
    ngx_string("inspector"),
    ngx_string("score"),
    ngx_string("fail_timeout"),
    ngx_string("fail_absent"),
    ngx_string("fail_bus"),
    ngx_string("fail_body"),
    ngx_string("fail_inspector"),
    ngx_string("fail_overload"),
    ngx_string("local_upgrade")
};


static ngx_str_t  ngx_http_waf_exc_names[] = {
    ngx_string("timeout"),
    ngx_string("absent"),
    ngx_string("bus"),
    ngx_string("body"),
    ngx_string("inspector"),
    ngx_string("overload")
};


static ngx_str_t  ngx_http_waf_deny_scope_names[] = {
    ngx_string(""),
    ngx_string("address"),
    ngx_string("network"),
    ngx_string("country"),
    ngx_string("asn"),
    ngx_string("session"),
    ngx_string("request")
};


static ngx_str_t  ngx_http_waf_entry_state_names[] = {
    ngx_string(""),
    ngx_string("timeout"),
    ngx_string("absent"),
    ngx_string("skipped"),
    ngx_string("off")
};


ngx_str_t *
ngx_http_waf_verdict_name(ngx_uint_t verdict)
{
    if (verdict > NGX_HTTP_WAF_V_ERROR) {
        verdict = NGX_HTTP_WAF_V_ALLOW;
    }

    return &ngx_http_waf_verdict_names[verdict];
}


ngx_str_t *
ngx_http_waf_do_name(ngx_uint_t verb)
{
    if (verb > NGX_HTTP_WAF_DO_LAST) {
        verb = NGX_HTTP_WAF_DO_LAST;
    }

    return &ngx_http_waf_do_names[verb];
}


ngx_str_t *
ngx_http_waf_apply_name(ngx_uint_t axis)
{
    if (axis > NGX_HTTP_WAF_APPLY_LAST) {
        axis = NGX_HTTP_WAF_APPLY_REQUEST;
    }

    return &ngx_http_waf_apply_names[axis];
}


ngx_str_t *
ngx_http_waf_phase_name(ngx_uint_t phase)
{
    if (phase >= NGX_HTTP_WAF_NPHASE) {
        phase = NGX_HTTP_WAF_PHASE_REQUEST;
    }

    return &ngx_http_waf_phase_names[phase];
}


ngx_str_t *
ngx_http_waf_to_phase_name(ngx_uint_t phases)
{
    static ngx_str_t  frame = ngx_string("frame");

    if (phases == NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)) {
        return &ngx_http_waf_phase_names[NGX_HTTP_WAF_PHASE_REQUEST];
    }

    if (phases == NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_RESPONSE)) {
        return &ngx_http_waf_phase_names[NGX_HTTP_WAF_PHASE_RESPONSE];
    }

    return &frame;
}


ngx_str_t *
ngx_http_waf_code_name(ngx_uint_t code)
{
    if (code > NGX_HTTP_WAF_CODE_LOCAL_UPGRADE) {
        code = NGX_HTTP_WAF_CODE_NONE;
    }

    return &ngx_http_waf_code_names[code];
}


ngx_uint_t
ngx_http_waf_exc_of(ngx_uint_t code)
{
    switch (code) {

    case NGX_HTTP_WAF_CODE_FAIL_ABSENT:
        return NGX_HTTP_WAF_EXC_ABSENT;

    case NGX_HTTP_WAF_CODE_FAIL_BUS:
        return NGX_HTTP_WAF_EXC_BUS;

    case NGX_HTTP_WAF_CODE_FAIL_BODY:
        return NGX_HTTP_WAF_EXC_BODY;

    case NGX_HTTP_WAF_CODE_FAIL_INSPECTOR:
        return NGX_HTTP_WAF_EXC_INSPECTOR;

    case NGX_HTTP_WAF_CODE_FAIL_OVERLOAD:
        return NGX_HTTP_WAF_EXC_OVERLOAD;

    default:
        return NGX_HTTP_WAF_EXC_TIMEOUT;
    }
}


ngx_str_t *
ngx_http_waf_exc_name(ngx_uint_t exc)
{
    if (exc >= NGX_HTTP_WAF_EXC_COUNT) {
        exc = NGX_HTTP_WAF_EXC_TIMEOUT;
    }

    return &ngx_http_waf_exc_names[exc];
}


ngx_uint_t
ngx_http_waf_deny_scope_parse(ngx_str_t *word)
{
    ngx_uint_t  i;

    for (i = NGX_HTTP_WAF_SCOPE_ADDRESS; i <= NGX_HTTP_WAF_SCOPE_REQUEST; i++) {
        if (word->len == ngx_http_waf_deny_scope_names[i].len
            && ngx_strncmp(word->data, ngx_http_waf_deny_scope_names[i].data,
                           word->len) == 0)
        {
            return i;
        }
    }

    return NGX_HTTP_WAF_SCOPE_NONE;
}


ngx_str_t *
ngx_http_waf_deny_scope_name(ngx_uint_t scope)
{
    if (scope > NGX_HTTP_WAF_SCOPE_REQUEST) {
        scope = NGX_HTTP_WAF_SCOPE_NONE;
    }

    return &ngx_http_waf_deny_scope_names[scope];
}


ngx_str_t *
ngx_http_waf_entry_state_name(ngx_uint_t state)
{
    if (state > NGX_HTTP_WAF_ENTRY_OFF) {
        state = NGX_HTTP_WAF_ENTRY_ANSWERED;
    }

    return &ngx_http_waf_entry_state_names[state];
}


ngx_int_t
ngx_http_waf_score_deny_at(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return wlcf->score_deny[ctx->phase];
}


void
ngx_http_waf_account(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    reply->order = ++ctx->ph->order;

    if (reply->verdict == NGX_HTTP_WAF_V_REDIRECT
        && ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: redirect from inspector %ui dropped on phase %V: "
                      "there is nobody left to redirect", index,
                      ngx_http_waf_phase_name(ctx->phase));

        reply->verdict = NGX_HTTP_WAF_V_ALLOW;
        return;
    }

    if (reply->vote && reply->verdict == NGX_HTTP_WAF_V_DENY) {
        reply->score = NGX_HTTP_WAF_SCORE_MAX;

    } else if (reply->verdict != NGX_HTTP_WAF_V_SCORE) {
        return;
    }

    if (reply->score <= 0) {
        return;
    }

    if (reply->passive) {
        ctx->ph->shadow += reply->score;

    } else {
        ctx->ph->score += reply->score;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: inspector %ui scored %i, total %i",
                   index, reply->score, ctx->ph->score);
}


void
ngx_http_waf_actions_merge(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply, ngx_uint_t wave)
{
    ngx_uint_t                 i, j, found;
    ngx_http_waf_action_t     *src, *live, *slot;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (reply->actions == NULL || reply->actions->nelts == 0) {
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (wlcf->actions_max == 0) {
        return;
    }

    if (ctx->actions == NULL) {
        ctx->actions = ngx_array_create(ctx->request->pool, 4,
                                        sizeof(ngx_http_waf_action_t));
        if (ctx->actions == NULL) {
            return;
        }
    }

    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];
    src  = reply->actions->elts;

    for (i = 0; i < reply->actions->nelts; i++) {

        src[i].from    = index;
        src[i].phase   = ctx->phase;
        src[i].wave    = wave;
        src[i].passive = reply->passive;

        if (ngx_http_waf_do_control(src[i].verb)
            && ngx_http_waf_control_apply(ctx, &src[i]) != NGX_OK)
        {
            continue;
        }

        if (ngx_http_waf_do_audit(src[i].verb)
            && ngx_http_waf_audit_ovr_apply(ctx, &src[i]) != NGX_OK)
        {
            continue;
        }

        if (ngx_http_waf_do_mark(src[i].verb)) {
            (void) ngx_http_waf_markers_add(ctx, &src[i]);
        }

        if (ngx_http_waf_do_score(src[i].verb)
            && ngx_http_waf_score_apply(ctx, &src[i]) != NGX_OK)
        {
            continue;
        }

        live  = ctx->actions->elts;
        found = 0;

        for (j = 0; j < ctx->actions->nelts; j++) {

            if (live[j].from != src[i].from
                || live[j].to != src[i].to
                || live[j].to_phases != src[i].to_phases
                || live[j].verb != src[i].verb
                || live[j].apply != src[i].apply
                || live[j].code.len != src[i].code.len
                || live[j].counter.len != src[i].counter.len
                || live[j].group.len != src[i].group.len
                || live[j].marker.len != src[i].marker.len)
            {
                continue;
            }

            if (live[j].code.len != 0
                && ngx_memcmp(live[j].code.data, src[i].code.data,
                              src[i].code.len) != 0)
            {
                continue;
            }

            if (live[j].counter.len != 0
                && ngx_memcmp(live[j].counter.data, src[i].counter.data,
                              src[i].counter.len) != 0)
            {
                continue;
            }

            if (live[j].group.len != 0
                && ngx_memcmp(live[j].group.data, src[i].group.data,
                              src[i].group.len) != 0)
            {
                continue;
            }

            if (live[j].marker.len != 0
                && ngx_memcmp(live[j].marker.data, src[i].marker.data,
                              src[i].marker.len) != 0)
            {
                continue;
            }

            live[j] = src[i];
            found   = 1;
            break;
        }

        if (found) {
            continue;
        }

        if (ctx->actions->nelts >= wlcf->actions_max) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: action \"%V\" from inspector \"%V\" dropped: "
                          "waf_actions_max reached",
                          ngx_http_waf_do_name(src[i].verb), &insp->name);
            continue;
        }

        slot = ngx_array_push(ctx->actions);
        if (slot == NULL) {
            return;
        }

        *slot = src[i];
    }
}


void
ngx_http_waf_sessions_merge(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    ngx_uint_t                 i, j, found;
    ngx_http_waf_session_t    *src, *live, *slot;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (reply->sessions == NULL || reply->sessions->nelts == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ctx->sessions == NULL) {
        ctx->sessions = ngx_array_create(ctx->request->pool, 2,
                                         sizeof(ngx_http_waf_session_t));
        if (ctx->sessions == NULL) {
            return;
        }
    }

    src = reply->sessions->elts;

    for (i = 0; i < reply->sessions->nelts; i++) {

        src[i].by      = index;
        src[i].passive = reply->passive;

        live  = ctx->sessions->elts;
        found = 0;

        for (j = 0; j < ctx->sessions->nelts; j++) {

            if (live[j].by != src[i].by
                || live[j].source.len != src[i].source.len
                || live[j].id.len != src[i].id.len)
            {
                continue;
            }

            if (ngx_memcmp(live[j].source.data, src[i].source.data,
                           src[i].source.len) != 0)
            {
                continue;
            }

            if (src[i].id.len != 0
                && ngx_memcmp(live[j].id.data, src[i].id.data,
                              src[i].id.len) != 0)
            {
                continue;
            }

            live[j] = src[i];
            found   = 1;
            break;
        }

        if (found) {
            continue;
        }

        if (ctx->sessions->nelts >= NGX_HTTP_WAF_SESSIONS_MAX) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: session \"%V\" from inspector \"%V\" dropped: "
                          "too many sessions on the request",
                          &src[i].source, &insp->name);
            continue;
        }

        slot = ngx_array_push(ctx->sessions);
        if (slot == NULL) {
            return;
        }

        *slot = src[i];
    }
}


ngx_int_t
ngx_http_waf_markers_add(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    ngx_uint_t                 i;
    ngx_str_t                 *live, *slot;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (a->marker.len == 0) {
        return NGX_DECLINED;
    }

    if (ctx->markers == NULL) {
        ctx->markers = ngx_array_create(ctx->request->pool, 4,
                                        sizeof(ngx_str_t));
        if (ctx->markers == NULL) {
            return NGX_ERROR;
        }
    }

    live = ctx->markers->elts;

    for (i = 0; i < ctx->markers->nelts; i++) {

        if (live[i].len == a->marker.len
            && ngx_memcmp(live[i].data, a->marker.data, a->marker.len) == 0)
        {
            return NGX_OK;
        }
    }

    if (ctx->markers->nelts >= NGX_HTTP_WAF_MARKERS_MAX) {
        wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
        insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[a->from];

        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: marker \"%V\" from inspector \"%V\" dropped: "
                      "too many markers on the request", &a->marker,
                      &insp->name);

        return NGX_DECLINED;
    }

    slot = ngx_array_push(ctx->markers);
    if (slot == NULL) {
        return NGX_ERROR;
    }

    *slot = a->marker;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_score_apply(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    ngx_int_t                  was, now, applied;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_inspector_t  *insp;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    if (a->passive) {
        if (!wlcf->score_warned) {
            wlcf->score_warned = 1;

            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: score action from inspector \"%V\" refused: "
                          "the sender is passive on this route "
                          "(reported once)", &insp[a->from].name);
        }

        return NGX_DECLINED;
    }

    if (ctx->ph->replies == NULL || a->from >= wmcf->inspectors.nelts) {
        return NGX_DECLINED;
    }

    reply = &ctx->ph->replies[a->from];

    was = reply->score;
    now = was + a->value;

    if (now > NGX_HTTP_WAF_SCORE_MAX) {
        now = NGX_HTTP_WAF_SCORE_MAX;

    } else if (now < -NGX_HTTP_WAF_SCORE_MAX) {
        now = -NGX_HTTP_WAF_SCORE_MAX;
    }

    applied = now - was;

    if (ctx->ph->score + applied < 0) {
        applied = -ctx->ph->score;
    }

    reply->score   = was + applied;
    ctx->ph->score += applied;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: score action from %ui: %i asked, %i applied, "
                   "total %i", a->from, a->value, applied, ctx->ph->score);

    return NGX_OK;
}


void
ngx_http_waf_control_set(ngx_http_waf_control_t *ctl, ngx_uint_t verb,
    ngx_http_waf_mask_t bit)
{
    ctl->active  &= ~bit;
    ctl->passive &= ~bit;
    ctl->off     &= ~bit;
    ctl->vote    &= ~bit;

    switch (verb) {

    case NGX_HTTP_WAF_DO_ACTIVE:
        ctl->active |= bit;
        break;

    case NGX_HTTP_WAF_DO_PASSIVE:
        ctl->passive |= bit;
        break;

    case NGX_HTTP_WAF_DO_OFF:
        ctl->off |= bit;
        break;

    case NGX_HTTP_WAF_DO_VOTE:
        ctl->vote |= bit;
        break;
    }
}


ngx_int_t
ngx_http_waf_control_apply(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    static ngx_str_t           everyone = ngx_string("*");
    ngx_uint_t                 p, phases, accepted;
    const char                *why;
    ngx_http_waf_mask_t        bit;
    ngx_http_waf_control_t    *conn;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_inspector_t  *insp;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    why      = NULL;
    accepted = 0;
    phases   = (a->to_phases != 0) ? a->to_phases
                                   : (NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_NPHASE)
                                      - 1);

    if (a->to == NGX_HTTP_WAF_ACTION_ALL) {
        why = "control verbs need an addressee";

    } else if (a->passive) {
        why = "the sender is passive on this route";

    } else if (a->apply == NGX_HTTP_WAF_APPLY_CONN
               && !ngx_http_waf_phase_is_frame(ctx->phase))
    {
        why = "apply=conn exists only on frames";

    } else {
        for (p = 0; p < NGX_HTTP_WAF_NPHASE; p++) {
            if ((phases & NGX_HTTP_WAF_PH_BIT(p))
                && ngx_http_waf_binding_find(wlcf, a->to, p) != NULL)
            {
                accepted = 1;
                break;
            }
        }

        if (!accepted) {
            why = (a->to_phases != 0)
                  ? "the addressee is not called on this route in that phase"
                  : "the addressee is not called on this route";
        }
    }

    if (why != NULL) {
        if (!wlcf->control_warned) {
            wlcf->control_warned = 1;

            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: control action \"%V\" from inspector "
                          "\"%V\" to \"%V\" refused: %s (reported once)",
                          ngx_http_waf_do_name(a->verb), &insp[a->from].name,
                          (a->to == NGX_HTTP_WAF_ACTION_ALL)
                              ? &everyone : &insp[a->to].name,
                          why);
        }

        return NGX_DECLINED;
    }

    bit  = 1ULL << a->to;
    conn = (a->apply == NGX_HTTP_WAF_APPLY_CONN)
           ? ngx_http_waf_frame_control(ctx) : NULL;

    for (p = 0; p < NGX_HTTP_WAF_NPHASE; p++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(p)) == 0) {
            continue;
        }

        ngx_http_waf_control_set(&ctx->ctl[p], a->verb, bit);

        if (conn != NULL) {
            ngx_http_waf_control_set(&conn[p], a->verb, bit);
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: control %V from %ui to %ui applied, phases %ui",
                   ngx_http_waf_do_name(a->verb), a->from, a->to, phases);

    return NGX_OK;
}


static void
ngx_http_waf_audit_ovr_set(ngx_http_waf_audit_ovr_t *ovr,
    ngx_http_waf_action_t *a)
{
    ngx_http_waf_ovr_part_t  *part;

    part = (a->verb == NGX_HTTP_WAF_DO_AUDIT) ? &ovr->audit : &ovr->archive;

    *part     = a->spec;
    part->set = a->set;
}


ngx_int_t
ngx_http_waf_audit_ovr_apply(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    const char                *why;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_inspector_t  *insp;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    why = NULL;

    if (a->apply == NGX_HTTP_WAF_APPLY_RESPONSE
        && ngx_http_waf_phase_is_frame(ctx->phase))
    {
        why = "frames have no response record";
    }

    if (why != NULL) {
        if (!wlcf->audit_ovr_warned) {
            wlcf->audit_ovr_warned = 1;

            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: audit action \"%V\" from inspector \"%V\" "
                          "refused: %s (reported once)",
                          ngx_http_waf_do_name(a->verb), &insp[a->from].name,
                          why);
        }

        return NGX_DECLINED;
    }

    ngx_http_waf_audit_ovr_set(
        &ctx->audit_ovr[(a->apply == NGX_HTTP_WAF_APPLY_RESPONSE)
                        ? NGX_HTTP_WAF_OVR_RESPONSE : NGX_HTTP_WAF_OVR_REQUEST],
        a);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: audit action %V from %ui applied",
                   ngx_http_waf_do_name(a->verb), a->from);

    return NGX_OK;
}


ngx_http_waf_mask_t
ngx_http_waf_wave_off(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_control_t  *ctl = &ctx->ctl[ctx->phase];

    return (w->all & ctl->off)
           | (w->off & ~(ctl->active | ctl->passive | ctl->vote));
}


ngx_http_waf_mask_t
ngx_http_waf_wave_passive(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_mask_t      live;
    ngx_http_waf_control_t  *ctl = &ctx->ctl[ctx->phase];

    live = w->all & ~ngx_http_waf_wave_off(ctx, w);

    return (ctl->passive | (w->passive & ~(ctl->active | ctl->vote))) & live;
}


ngx_http_waf_mask_t
ngx_http_waf_wave_vote(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_mask_t      live;
    ngx_http_waf_control_t  *ctl = &ctx->ctl[ctx->phase];

    live = w->all & ~ngx_http_waf_wave_off(ctx, w);

    return (ctl->vote | (w->vote & ~(ctl->active | ctl->passive))) & live;
}


ngx_http_waf_mask_t
ngx_http_waf_wave_mandatory(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_mask_t  live;

    live = w->all & ~ngx_http_waf_wave_off(ctx, w);

    return live & ~ngx_http_waf_wave_passive(ctx, w);
}


ngx_http_waf_mask_t
ngx_http_waf_wave_gating(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    return ngx_http_waf_wave_mandatory(ctx, w) & ~ngx_http_waf_wave_vote(ctx, w);
}


void
ngx_http_waf_resolve_verdict(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t              threshold;
    ngx_uint_t             index;
    ngx_http_waf_reply_t  *reply;

    ctx->ph->decisive       = NULL;
    ctx->ph->decisive_index = 0;
    ctx->ph->by_score       = 0;
    ctx->ph->code           = NGX_HTTP_WAF_CODE_NONE;
    index               = 0;

    reply = ngx_http_waf_pick(ctx, NGX_HTTP_WAF_V_DENY, &index);

    if (reply != NULL) {
        ctx->ph->verdict        = NGX_HTTP_WAF_V_DENY;
        ctx->ph->decisive       = reply;
        ctx->ph->decisive_index = index;
        ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;
        ctx->state          = NGX_HTTP_WAF_ST_DENY;
        return;
    }

    threshold = ngx_http_waf_score_deny_at(ctx);

    if (threshold > 0 && ctx->ph->score >= threshold) {
        ctx->ph->verdict  = NGX_HTTP_WAF_V_DENY;
        ctx->ph->by_score = 1;
        ctx->ph->code     = NGX_HTTP_WAF_CODE_SCORE;
        ctx->state    = NGX_HTTP_WAF_ST_DENY;
        return;
    }

    reply = ngx_http_waf_pick(ctx, NGX_HTTP_WAF_V_REDIRECT, &index);

    if (reply != NULL) {
        ctx->ph->verdict        = NGX_HTTP_WAF_V_REDIRECT;
        ctx->ph->decisive       = reply;
        ctx->ph->decisive_index = index;
        ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;
        ctx->state          = NGX_HTTP_WAF_ST_REDIRECT;
        return;
    }

    ctx->ph->verdict = NGX_HTTP_WAF_V_ALLOW;

    ctx->state = (ctx->ph->fail != NGX_HTTP_WAF_CODE_NONE)
                     ? NGX_HTTP_WAF_ST_FAILED
                     : NGX_HTTP_WAF_ST_ALLOW;
}


static ngx_http_waf_reply_t *
ngx_http_waf_pick(ngx_http_waf_ctx_t *ctx, ngx_uint_t verdict,
    ngx_uint_t *index)
{
    ngx_uint_t                 i, n, best_order;
    ngx_http_waf_reply_t      *reply, *best;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->replies == NULL) {
        return NULL;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    n          = wmcf->inspectors.nelts;
    best       = NULL;
    best_order = 0;

    for (i = 0; i < n; i++) {
        reply = &ctx->ph->replies[i];

        if (!reply->received || reply->verdict != verdict) {
            continue;
        }

        if (reply->passive || reply->vote) {
            continue;
        }

        if (best == NULL) {
            best       = reply;
            best_order = reply->order;
            *index     = i;
            continue;
        }

        if (wlcf->deny_mode[ctx->phase] == NGX_HTTP_WAF_DENY_FAST
            && reply->order < best_order)
        {
            best       = reply;
            best_order = reply->order;
            *index     = i;
        }
    }

    return best;
}
