#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "codec/ngx_http_waf_codec.h"


static void ngx_http_waf_resume_cleanup(void *data);


ngx_http_waf_binding_t *
ngx_http_waf_binding_find(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index,
    ngx_uint_t phase)
{
    ngx_uint_t               i;
    ngx_http_waf_binding_t  *b;

    if (wlcf->inspects[phase] == NULL) {
        return NULL;
    }

    b = wlcf->inspects[phase]->elts;

    for (i = 0; i < wlcf->inspects[phase]->nelts; i++) {
        if (b[i].index == index) {
            return &b[i];
        }
    }

    return NULL;
}


ngx_uint_t
ngx_http_waf_action_deliverable(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t to,
    ngx_uint_t phase, ngx_uint_t wave)
{
    ngx_uint_t               p;
    ngx_http_waf_binding_t  *b;

    b = ngx_http_waf_binding_find(wlcf, to, phase);

    if (b != NULL && b->wave > wave) {
        return 1;
    }

    for (p = phase + 1; p < NGX_HTTP_WAF_NPHASE; p++) {
        if (ngx_http_waf_binding_find(wlcf, to, p) != NULL) {
            return 1;
        }
    }

    return 0;
}


ngx_uint_t
ngx_http_waf_resume_wanted(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index,
    ngx_uint_t phase)
{
    ngx_http_waf_binding_t  *b;

    if (phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return 0;
    }

    b = ngx_http_waf_binding_find(wlcf, index, phase);

    return b != NULL && b->keep;
}


ngx_int_t
ngx_http_waf_check_resume_pairs(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf)
{
    ngx_uint_t                 i, n, phase, later;
    ngx_array_t               *list;
    ngx_http_waf_binding_t    *b, *rb;
    ngx_http_waf_loc_conf_t  **confs, *wlcf;

    if (wmcf->loc_confs == NULL) {
        return NGX_OK;
    }

    confs = wmcf->loc_confs->elts;

    for (n = 0; n < wmcf->loc_confs->nelts; n++) {
        wlcf = confs[n];

        if (wlcf->has_children || !wlcf->enable) {
            continue;
        }

        list = wlcf->inspects[NGX_HTTP_WAF_PHASE_REQUEST];

        if (list != NULL) {
            b = list->elts;

            for (i = 0; i < list->nelts; i++) {

                if (!b[i].keep) {
                    continue;
                }

                later = ngx_http_waf_resume_phase(wlcf, b[i].index,
                                                  NGX_HTTP_WAF_PHASE_REQUEST);

                if (later == NGX_HTTP_WAF_NPHASE) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf: \"%V\" keeps its state on "
                                       "request (keep=on) but no later "
                                       "phase resumes it in location "
                                       "\"%V\"; add resume= on response "
                                       "or drop keep=",
                                       &b[i].name, &wlcf->name);
                    return NGX_ERROR;
                }
            }
        }

        for (phase = NGX_HTTP_WAF_PHASE_REQUEST + 1;
             phase < NGX_HTTP_WAF_NPHASE;
             phase++)
        {
            list = wlcf->inspects[phase];

            if (list == NULL) {
                continue;
            }

            b = list->elts;

            for (i = 0; i < list->nelts; i++) {

                if (b[i].resume == NGX_HTTP_WAF_RESUME_OFF) {
                    continue;
                }

                rb = ngx_http_waf_binding_find(wlcf, b[i].index,
                                               NGX_HTTP_WAF_PHASE_REQUEST);

                if (rb == NULL || !rb->keep) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf: \"%V\" resumes on %V but its "
                                       "request line does not keep the "
                                       "state in location \"%V\"; add "
                                       "keep=on to waf_inspect request %V",
                                       &b[i].name,
                                       ngx_http_waf_phase_name(phase),
                                       &wlcf->name, &b[i].name);
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_check_send_routes(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf)
{
    ngx_uint_t                  n, ph, obj;
    ngx_array_t                *list;
    ngx_http_waf_loc_conf_t   **confs, *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    if (wmcf->loc_confs == NULL) {
        return NGX_OK;
    }

    confs = wmcf->loc_confs->elts;

    for (n = 0; n < wmcf->loc_confs->nelts; n++) {
        wlcf = confs[n];

        if (wlcf->has_children || !wlcf->enable) {
            continue;
        }

        for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {
            list = wlcf->inspects[ph];

            if (list == NULL || list->nelts == 0) {
                continue;
            }

            sh = &wlcf->shoot[ph];

            for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {

                if (obj != NGX_HTTP_WAF_OBJ_BODY
                    || !(sh->capture & NGX_HTTP_WAF_OBJ_BIT(obj))
                    || sh->capture_limit[obj]
                       == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
                    || wlcf->send[ph][obj] != NGX_HTTP_WAF_SEND_STORE)
                {
                    continue;
                }

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "waf: location \"%V\" sends the %V %V "
                                   "from the store (waf_send %V %V=store) "
                                   "while \"waf_capture %V %V=%uz\" takes a "
                                   "prefix; an object wider than the slice "
                                   "cannot be served from the store and its "
                                   "rewrite fails per waf_exception <phase> "
                                   "body -- capture the whole object or send "
                                   "the original",
                                   &wlcf->name,
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   sh->capture_limit[obj]);
            }
        }
    }

    return NGX_OK;
}


ngx_uint_t
ngx_http_waf_resume_phase(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index,
    ngx_uint_t phase)
{
    ngx_uint_t               later;
    ngx_http_waf_binding_t  *b;

    for (later = phase + 1; later < NGX_HTTP_WAF_NPHASE; later++) {

        b = ngx_http_waf_binding_find(wlcf, index, later);

        if (b != NULL && b->resume != NGX_HTTP_WAF_RESUME_OFF) {
            return later;
        }
    }

    return NGX_HTTP_WAF_NPHASE;
}


ngx_str_t *
ngx_http_waf_resume_subject(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    ngx_http_waf_binding_t   *b;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->cont == NULL || ctx->cont[index].subject.len == 0) {
        return NULL;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    b    = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

    if (b == NULL || b->resume == NGX_HTTP_WAF_RESUME_OFF) {
        return NULL;
    }

    if ((ngx_msec_int_t) (ngx_current_msec - ctx->cont[index].expires) >= 0) {
        return NULL;
    }

    return &ctx->cont[index].subject;
}


static void
ngx_http_waf_resume_cleanup(void *data)
{
    ngx_http_waf_resume_release(data);
}


void
ngx_http_waf_resume_release(ngx_http_waf_ctx_t *ctx)
{
    u_char                     buf[512];
    u_char                     sbuf[256];
    u_char                    *p;
    ngx_str_t                  payload, subject;
    ngx_uint_t                 i, phase, denied;
    ngx_http_waf_jw_t          jw;
    ngx_http_waf_bus_t        *bus;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->resume_asked == 0) {
        return;
    }


    bus = ngx_http_waf_bus_current();

    if (bus == NULL || bus->publish_audit == NULL) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    denied = 0;

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        if (ctx->phases[i].verdict == NGX_HTTP_WAF_V_DENY) {
            denied = 1;
            break;
        }
    }

    for (i = 0; i < wmcf->inspectors.nelts; i++) {

        if (!(ctx->resume_asked & (1ULL << i))) {
            continue;
        }

        ctx->resume_asked &= ~(1ULL << i);

        phase = ngx_http_waf_resume_phase(wlcf, i, NGX_HTTP_WAF_PHASE_REQUEST);

        if (phase == NGX_HTTP_WAF_NPHASE) {
            phase = NGX_HTTP_WAF_PHASE_RESPONSE;
        }

        subject.data = sbuf;
        p = ngx_slprintf(sbuf, sbuf + sizeof(sbuf), "%V.release",
                         &insp[i].subject);
        subject.len = (size_t) (p - sbuf);

        ngx_http_waf_jw_init(&jw, buf, sizeof(buf));

        ngx_http_waf_jw_lit(&jw, "{\"v\":");
        ngx_http_waf_jw_int(&jw, NGX_HTTP_WAF_PROTOCOL_VERSION);
        ngx_http_waf_jw_lit(&jw, ",\"rid\":\"");
        ngx_http_waf_jw_raw(&jw, (const u_char *) ctx->rid_hex,
                            NGX_HTTP_WAF_RID_HEX_LEN);
        ngx_http_waf_jw_lit(&jw, "\",\"inspector\":");
        ngx_http_waf_jw_str(&jw, &insp[i].name);
        ngx_http_waf_jw_lit(&jw, ",\"phase\":");
        ngx_http_waf_jw_str(&jw, ngx_http_waf_phase_name(phase));
        ngx_http_waf_jw_lit(&jw, ",\"release\":{\"token\":\"");
        ngx_http_waf_jw_raw(&jw, (const u_char *) ctx->ray_hex,
                            NGX_HTTP_WAF_RAY_HEX_LEN);
        ngx_http_waf_jw_lit(&jw, "\",\"reason\":");

        if (denied) {
            ngx_http_waf_jw_lit(&jw, "\"deny\"");

        } else {
            ngx_http_waf_jw_lit(&jw, "\"skip\"");
        }

        ngx_http_waf_jw_lit(&jw, "}}");

        if (!ngx_http_waf_jw_ok(&jw)) {
            continue;
        }

        payload.data = buf;
        payload.len  = ngx_http_waf_jw_len(&jw);

        (void) bus->publish_audit(bus, &subject, &payload);

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: continuation released for \"%V\", ray %*s",
                      &insp[i].name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
    }
}


ngx_int_t
ngx_http_waf_resume_ask(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    ngx_pool_cleanup_t  *cln;

    if (ctx->resume_asked & (1ULL << index)) {
        return NGX_OK;
    }

    if (ctx->resume_asked == 0) {
        cln = ngx_pool_cleanup_add(ctx->request->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_resume_cleanup;
        cln->data    = ctx;
    }

    ctx->resume_asked |= (1ULL << index);

    return NGX_OK;
}


void
ngx_http_waf_resume_forget(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    ctx->resume_asked &= ~(1ULL << index);

    if (ctx->cont != NULL) {
        ngx_str_null(&ctx->cont[index].subject);
    }
}


ngx_int_t
ngx_http_waf_resume_keep(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_str_t *subject, ngx_msec_t ttl)
{
    u_char                    *p;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->cont == NULL) {
        ctx->cont = ngx_pcalloc(ctx->request->pool,
                                wmcf->inspectors.nelts
                                    * sizeof(ngx_http_waf_cont_t));
        if (ctx->cont == NULL) {
            return NGX_ERROR;
        }
    }

    p = ngx_pnalloc(ctx->request->pool, subject->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, subject->data, subject->len);

    ctx->cont[index].subject.data = p;
    ctx->cont[index].subject.len  = subject->len;
    ctx->cont[index].expires      = ngx_current_msec + ttl;

    return NGX_OK;
}


ngx_array_t *
ngx_http_waf_waves_build(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase)
{
    ngx_uint_t                  i, n, wave, first, cap_body;
    ngx_array_t                *waves;
    ngx_http_waf_wave_t        *w;
    ngx_http_waf_mask_t         bit;
    ngx_http_waf_binding_t     *b;
    ngx_http_waf_inspector_t   *insp;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[phase];

    insp = wmcf->inspectors.elts;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        wlcf->profiles[i] = insp[i].profile;
    }

    waves = ngx_array_create(cf->pool, 2, sizeof(ngx_http_waf_wave_t));
    if (waves == NULL) {
        return NULL;
    }

    if (wlcf->inspects[phase] == NULL || wlcf->inspects[phase]->nelts == 0) {
        return waves;
    }

    b = wlcf->inspects[phase]->elts;
    n = wlcf->inspects[phase]->nelts;

    first    = 1;
    cap_body = (sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
               != 0;

    for (wave = 0; wave <= NGX_HTTP_WAF_MAX_WAVE; wave++) {

        w = NULL;

        for (i = 0; i < n; i++) {

            if (b[i].phase != phase || b[i].wave != wave) {
                continue;
            }

            if (w == NULL) {
                w = ngx_array_push(waves);
                if (w == NULL) {
                    return NULL;
                }

                ngx_memzero(w, sizeof(ngx_http_waf_wave_t));
                w->obj_need = sh->capture;

                if (first && cap_body) {
                    if (sh->capture_limit[NGX_HTTP_WAF_OBJ_BODY]
                        == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE)
                    {
                        w->body_need = NGX_HTTP_WAF_BODY_FULL;

                    } else {
                        w->body_need    = NGX_HTTP_WAF_BODY_PREVIEW;
                        w->body_preview =
                            sh->capture_limit[NGX_HTTP_WAF_OBJ_BODY];
                    }
                }

                first = 0;
            }

            bit = (ngx_http_waf_mask_t) 1 << b[i].index;
            w->all |= bit;

            if (b[i].mode == NGX_HTTP_WAF_MODE_OFF) {
                w->off |= bit;

            } else if (b[i].mode == NGX_HTTP_WAF_MODE_PASSIVE) {
                w->passive |= bit;

            } else if (b[i].mode == NGX_HTTP_WAF_MODE_VOTE) {
                w->mandatory |= bit;
                w->vote      |= bit;

            } else {
                w->mandatory |= bit;
            }
        }
    }

    return waves;
}
