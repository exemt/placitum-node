#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"

#include <ngx_md5.h>


#define NGX_HTTP_WAF_PRESENCE_INTERVAL  4000


static void      ngx_http_waf_presence_tick(ngx_event_t *ev);
static void      ngx_http_waf_presence_publish(ngx_http_waf_bus_t *bus);
static ngx_int_t ngx_http_waf_presence_hash(ngx_cycle_t *cycle, ngx_str_t *out);


ngx_int_t
ngx_http_waf_bus_publish_wave(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_slot_t *slot)
{
    uint64_t                   bit, pending, off;
    ngx_str_t                 *personal;
    ngx_uint_t                 index, status, published;
    ngx_http_waf_bus_t        *bus;
    ngx_http_waf_bus_msg_t     msg;
    ngx_http_waf_wave_t       *w;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    bus  = wmcf->bus;

    if (bus == NULL) {
        return NGX_ERROR;
    }

    w = ngx_http_waf_current_wave(ctx);
    if (w == NULL) {
        return NGX_ERROR;
    }

    inspectors = wmcf->inspectors.elts;
    published  = 0;

    off = ngx_http_waf_cond_off(ctx) & w->all & ~slot->got;

    if (off != 0) {
        ngx_http_waf_omit(slot, off, NGX_HTTP_WAF_ENTRY_SKIPPED);
    }

    off = ngx_http_waf_wave_off(ctx, w) & ~slot->got;

    if (off != 0) {
        ngx_http_waf_omit(slot, off, NGX_HTTP_WAF_ENTRY_OFF);
    }

    pending = w->all & ~slot->got;

    slot->awaited = (ngx_http_waf_wave_mandatory(ctx, w)
                     | ngx_http_waf_wave_passive(ctx, w)) & ~slot->got;

    ctx->ph->wave_published = slot->published;

    while (pending) {
        index    = ngx_http_waf_lowest_bit(pending);
        bit      = 1ULL << index;
        pending &= ~bit;

        if (index >= wmcf->inspectors.nelts) {
            continue;
        }

        ctx->ph->published |= bit;

        if (ngx_http_waf_breaker_allow(index, &inspectors[index]) != NGX_OK) {
            ngx_http_waf_skip(slot, index, NGX_HTTP_WAF_CODE_FAIL_TIMEOUT);
            continue;
        }

        ngx_memzero(&msg, sizeof(ngx_http_waf_bus_msg_t));

        msg.rid       = ctx->rid;
        msg.inspector = index;
        msg.subject   = inspectors[index].subject;

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        personal = ngx_http_waf_resume_subject(ctx, index);

        if (personal != NULL) {
            msg.subject = *personal;
        }

        if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST
            && ngx_http_waf_resume_wanted(wlcf, index, ctx->phase))
        {
            if (ngx_http_waf_resume_ask(ctx, index) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (ngx_http_waf_msg_request(ctx, index, &msg.payload) != NGX_OK) {
            return NGX_ERROR;
        }

        if (personal != NULL) {
            ngx_http_waf_resume_forget(ctx, index);
        }

        if (bus->publish(bus, &msg, &status) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "waf: publish to \"%V\" failed, status %ui, rid %*s",
                          &msg.subject, status,
                          (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);

            return NGX_ERROR;
        }

        if (personal != NULL) {
            ctx->ph->personal |= bit;
        }

        published++;
    }

    if (published == 0
        && (ngx_http_waf_wave_mandatory(ctx, w) & ~slot->got) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_http_waf_bus_absent(ngx_http_waf_bus_t *bus, uint64_t rid,
    ngx_uint_t inspector)
{
    uint64_t                   bit;
    ngx_uint_t                 status;
    ngx_http_waf_ctx_t        *ctx;
    ngx_http_waf_slot_t       *slot;
    ngx_http_waf_bus_msg_t     msg;
    ngx_http_waf_binding_t    *bind;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    slot = ngx_http_waf_slot_lookup(rid);

    if (slot == NULL) {
        return;
    }

    ctx  = slot->ctx;
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (inspector >= wmcf->inspectors.nelts) {
        return;
    }

    bit = 1ULL << inspector;

    /* personal accumulates across waves of the phase; got tells whether this
     * inspector has already been resolved (in any wave), so a late or repeated
     * 503 does not re-ask the group. */
    if (!(ctx->ph->personal & bit) || (ctx->ph->got & bit)) {
        ngx_http_waf_skip(slot, inspector, NGX_HTTP_WAF_CODE_FAIL_ABSENT);
        return;
    }

    ctx->ph->personal &= ~bit;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    bind = ngx_http_waf_binding_find(wlcf, inspector, ctx->phase);

    if (bind == NULL || bind->resume != NGX_HTTP_WAF_RESUME_PREFER) {
        ngx_http_waf_skip(slot, inspector, NGX_HTTP_WAF_CODE_FAIL_ABSENT);
        return;
    }

    insp = wmcf->inspectors.elts;
    insp = &insp[inspector];

    ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                  "waf: continuation of \"%V\" has no responders, asking "
                  "\"%V\", rid %*s", &insp->name, &insp->subject,
                  (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);

    ngx_memzero(&msg, sizeof(ngx_http_waf_bus_msg_t));

    msg.rid       = ctx->rid;
    msg.inspector = inspector;
    msg.subject   = insp->subject;

    if (ngx_http_waf_msg_request(ctx, inspector, &msg.payload) != NGX_OK) {
        ngx_http_waf_skip(slot, inspector, NGX_HTTP_WAF_CODE_FAIL_BUS);
        return;
    }

    if (bus->publish(bus, &msg, &status) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: publish to \"%V\" failed, status %ui, rid %*s",
                      &msg.subject, status,
                      (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);

        ngx_http_waf_skip(slot, inspector, NGX_HTTP_WAF_CODE_FAIL_BUS);
    }
}


void
ngx_http_waf_bus_dispatch(ngx_http_waf_bus_t *bus, uint64_t rid,
    ngx_uint_t inspector, ngx_str_t *payload)
{
    ngx_str_t                  err;
    ngx_http_waf_ctx_t        *ctx;
    ngx_http_waf_slot_t       *slot;
    ngx_http_waf_reply_t       reply;
    ngx_http_waf_main_conf_t  *wmcf;

    slot = ngx_http_waf_slot_lookup(rid);

    if (slot == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, bus->log, 0,
                       "waf: late reply for rid %uxL dropped", rid);
        return;
    }

    ctx  = slot->ctx;
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (inspector >= wmcf->inspectors.nelts) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: reply for unknown inspector %ui dropped",
                      inspector);
        return;
    }

    ngx_memzero(&reply, sizeof(ngx_http_waf_reply_t));
    ngx_str_null(&err);

    if (ngx_http_waf_msg_reply(ctx, inspector, payload, &reply, &err)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: reply from inspector %ui dropped: %V",
                      inspector, &err);
        return;
    }

    ngx_http_waf_on_reply(slot, inspector, &reply);
}


ngx_http_waf_bus_t *
ngx_http_waf_bus_current(void)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return NULL;
    }

    return wmcf->bus;
}


void
ngx_http_waf_bus_ready(void)
{
    ngx_http_waf_bus_t  *bus;

    ngx_http_waf_ds_stream_ready();

    bus = ngx_http_waf_bus_current();
    if (bus != NULL && bus->presence.handler != NULL) {
        ngx_http_waf_presence_publish(bus);
        ngx_add_timer(&bus->presence, NGX_HTTP_WAF_PRESENCE_INTERVAL);
    }
}


void
ngx_http_waf_bus_lost(void)
{
    ngx_http_waf_ds_stream_lost();
}


void
ngx_http_waf_bus_dataset(ngx_uint_t index, ngx_str_t *payload)
{
    ngx_http_waf_ds_stream_message(index, payload);
}


void
ngx_http_waf_bus_js_reply(ngx_uint_t index, ngx_str_t *payload)
{
    ngx_http_waf_ds_stream_reply(index, payload);
}


ngx_int_t
ngx_http_waf_bus_inbox_build(ngx_http_waf_bus_t *bus, ngx_cycle_t *cycle,
    ngx_str_t *node_id)
{
    u_char      *p;
    uint32_t     nonce;
    size_t       len;
    static const char  prefix[] = "_INBOX.waf.";

    nonce = (uint32_t) ngx_random();

    len = sizeof(prefix) - 1 + node_id->len + 1 + NGX_INT64_LEN + 1 + 8;

    p = ngx_pnalloc(cycle->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    bus->pid   = ngx_pid;
    bus->nonce = nonce;

    bus->inbox.data = p;
    p = ngx_sprintf(p, "%s%V.%P.%08xD", prefix, node_id, ngx_pid, nonce);
    bus->inbox.len = p - bus->inbox.data;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "waf: bus inbox \"%V\"", &bus->inbox);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_presence_init(ngx_http_waf_bus_t *bus, ngx_cycle_t *cycle)
{
    u_char                    *p;
    size_t                     len;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);
    if (wmcf == NULL) {
        return NGX_ERROR;
    }

    len = sizeof("WAF_STATUS.node.") - 1
          + wmcf->node_id.len
          + sizeof(".worker.") - 1
          + NGX_INT64_LEN + 1 + 8;

    p = ngx_pnalloc(cycle->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    bus->presence_subject.data = p;
    p = ngx_sprintf(p, "WAF_STATUS.node.%V.worker.%P.%08xD",
                    &wmcf->node_id, bus->pid, bus->nonce);
    bus->presence_subject.len = p - bus->presence_subject.data;

    if (ngx_http_waf_presence_hash(cycle, &bus->config_hash) != NGX_OK) {
        return NGX_ERROR;
    }

    bus->presence.handler = ngx_http_waf_presence_tick;
    bus->presence.data    = bus;
    bus->presence.log     = cycle->log;
    bus->presence.cancelable = 1;

    return NGX_OK;
}


void
ngx_http_waf_presence_stop(ngx_http_waf_bus_t *bus)
{
    if (bus->presence.timer_set) {
        ngx_del_timer(&bus->presence);
    }

    bus->presence.handler = NULL;
}


static ngx_int_t
ngx_http_waf_presence_hash(ngx_cycle_t *cycle, ngx_str_t *out)
{
    ssize_t     n;
    ngx_fd_t    fd;
    ngx_md5_t   md5;
    u_char      digest[16];
    u_char      buf[4096];
    u_char     *p;

    out->data = ngx_pnalloc(cycle->pool, 4 + 32);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&md5);

    fd = ngx_open_file(cycle->conf_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd != NGX_INVALID_FILE) {
        for (;;) {
            n = ngx_read_fd(fd, buf, sizeof(buf));
            if (n <= 0) {
                break;
            }
            ngx_md5_update(&md5, buf, (size_t) n);
        }
        (void) ngx_close_file(fd);
    }

    ngx_md5_final(digest, &md5);

    p = ngx_cpymem(out->data, "md5:", 4);
    ngx_hex_dump(p, digest, 16);
    out->len = 4 + 32;

    return NGX_OK;
}


static void
ngx_http_waf_presence_publish(ngx_http_waf_bus_t *bus)
{
    u_char                     json[512];
    u_char                     nonce[9];
    u_char                     at[21];
    ngx_str_t                  payload;
    ngx_tm_t                   gmt;
    ngx_http_waf_jw_t          jw;
    ngx_http_waf_main_conf_t  *wmcf;

    if (bus->publish_audit == NULL) {
        return;
    }

    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);
    if (wmcf == NULL) {
        return;
    }

    ngx_sprintf(nonce, "%08xD", bus->nonce);

    ngx_gmtime(ngx_time(), &gmt);
    ngx_sprintf(at, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                gmt.ngx_tm_year, gmt.ngx_tm_mon, gmt.ngx_tm_mday,
                gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec);

    ngx_http_waf_jw_init(&jw, json, sizeof(json));
    ngx_http_waf_jw_lit(&jw, "{\"v\":1,\"kind\":\"worker\",\"node_id\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);
    ngx_http_waf_jw_lit(&jw, ",\"pid\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) bus->pid);
    ngx_http_waf_jw_lit(&jw, ",\"nonce\":\"");
    ngx_http_waf_jw_raw(&jw, nonce, 8);
    ngx_http_waf_jw_lit(&jw, "\",\"config_hash\":");
    ngx_http_waf_jw_str(&jw, &bus->config_hash);
    ngx_http_waf_jw_lit(&jw, ",\"at\":\"");
    ngx_http_waf_jw_raw(&jw, at, 20);
    ngx_http_waf_jw_lit(&jw, "\"}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        return;
    }

    payload.data = json;
    payload.len  = ngx_http_waf_jw_len(&jw);

    if (bus->publish_audit(bus, &bus->presence_subject, &payload) != NGX_OK) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, bus->log, 0,
                   "waf: worker presence \"%V\"", &bus->presence_subject);
}


static void
ngx_http_waf_presence_tick(ngx_event_t *ev)
{
    ngx_http_waf_bus_t  *bus = ev->data;

    if (ngx_exiting || ngx_terminate || ngx_quit) {
        return;
    }

    ngx_http_waf_presence_publish(bus);
    ngx_add_timer(ev, NGX_HTTP_WAF_PRESENCE_INTERVAL);
}
