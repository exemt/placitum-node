#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "runtime/ngx_http_waf_preview.h"


typedef enum {
    NGX_HTTP_WAF_PREVIEW_PAIR_OK = 0,
    NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED,
    NGX_HTTP_WAF_PREVIEW_PAIR_FULL
} ngx_http_waf_preview_pair_e;


static void ngx_http_waf_preview_headers(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static void ngx_http_waf_preview_args(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static void ngx_http_waf_preview_body(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static ngx_uint_t ngx_http_waf_preview_pair(ngx_http_waf_jw_t *jw, size_t room,
    ngx_str_t *name, ngx_str_t *value, ngx_uint_t first, size_t item_max);
static void ngx_http_waf_preview_dropped(ngx_http_waf_jw_t *jw,
    const char *field, ngx_uint_t dropped);
static size_t ngx_http_waf_preview_text(ngx_http_waf_jw_t *jw, u_char *data,
    size_t len, size_t room);
static ngx_uint_t ngx_http_waf_preview_allowed(ngx_str_t *name,
    ngx_array_t *allow, ngx_array_t *deny);
static ngx_uint_t ngx_http_waf_preview_listed(ngx_array_t *list,
    ngx_str_t *name);
static void ngx_http_waf_preview_budgets(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, size_t budget[NGX_HTTP_WAF_OBJ_COUNT]);
static size_t ngx_http_waf_preview_overhead(void);
static void ngx_http_waf_preview_lists(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj, ngx_array_t **allow,
    ngx_array_t **deny, ngx_array_t **mask, ngx_array_t **cap_deny,
    ngx_array_t **cap_mask);
static void ngx_http_waf_preview_hash(ngx_str_t *src, u_char hex[64]);
static size_t ngx_http_waf_preview_take(ngx_http_request_t *r,
    ngx_chain_t *in, u_char *dst, size_t size);


static size_t
ngx_http_waf_preview_overhead(void)
{
    return sizeof(",\"headers_preview\":[],\"args_preview\":[],"
                  "\"body_preview\":\"\""
                  ",\"body_preview_source\":\"sent\""
                  ",\"headers_preview_dropped\":4294967295"
                  ",\"args_preview_dropped\":4294967295") - 1;
}


size_t
ngx_http_waf_preview_room(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase)
{
    size_t                      room;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[phase];

    room = sh->preview[NGX_HTTP_WAF_OBJ_HEADERS]
           + sh->preview[NGX_HTTP_WAF_OBJ_ARGS]
           + sh->preview[NGX_HTTP_WAF_OBJ_BODY];

    if (room == 0) {
        return 0;
    }

    return room + ngx_http_waf_preview_overhead();
}


size_t
ngx_http_waf_preview_room_ctx(ngx_http_waf_ctx_t *ctx)
{
    size_t                    room, budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    room = budget[NGX_HTTP_WAF_OBJ_HEADERS]
           + budget[NGX_HTTP_WAF_OBJ_ARGS]
           + budget[NGX_HTTP_WAF_OBJ_BODY];

    if (room == 0) {
        return 0;
    }

    return room + ngx_http_waf_preview_overhead();
}


size_t
ngx_http_waf_preview_body_budget(ngx_http_waf_ctx_t *ctx)
{
    size_t                    budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    return budget[NGX_HTTP_WAF_OBJ_BODY];
}


static void
ngx_http_waf_preview_budgets(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, size_t budget[NGX_HTTP_WAF_OBJ_COUNT])
{
    size_t                      total, over, cut;
    ngx_int_t                   i;
    ngx_http_waf_ovr_part_t    *part;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    part  = &ngx_http_waf_audit_ovr_cur(ctx)->audit;
    total = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        budget[i] = sh->preview[i];

        if (ngx_http_waf_ovr_excluded(part, i)) {
            budget[i] = 0;

        } else if (part->set == NGX_HTTP_WAF_SET_ON
                   && (ngx_http_waf_ovr_on(part) & NGX_HTTP_WAF_OBJ_BIT(i)))
        {
            budget[i] = (part->has_limit & NGX_HTTP_WAF_OBJ_BIT(i))
                        ? part->limit[i] : NGX_HTTP_WAF_PREVIEW_MAX;
        }

        total += budget[i];
    }

    if (total <= NGX_HTTP_WAF_PREVIEW_MAX) {
        return;
    }

    over = total - NGX_HTTP_WAF_PREVIEW_MAX;

    for (i = NGX_HTTP_WAF_OBJ_COUNT - 1; i >= 0 && over > 0; i--) {
        if (budget[i] <= sh->preview[i]) {
            continue;
        }

        cut = budget[i] - sh->preview[i];

        if (cut > over) {
            cut = over;
        }

        budget[i] -= cut;
        over      -= cut;
    }
}


void
ngx_http_waf_preview_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_http_waf_preview_headers(jw, ctx, wlcf);
    ngx_http_waf_preview_args(jw, ctx, wlcf);
    ngx_http_waf_preview_body(jw, ctx, wlcf);
}


static void
ngx_http_waf_preview_headers(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                     *mark, hex[64];
    size_t                      left, item;
    ngx_str_t                   value;
    ngx_uint_t                  i, first, dropped, rc;
    ngx_keyval_t               *kv;
    ngx_array_t                *pairs;
    ngx_array_t                *allow, *deny, *mask, *cap_deny, *cap_mask;
    size_t                      budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    if (budget[NGX_HTTP_WAF_OBJ_HEADERS] == 0) {
        return;
    }

    ngx_http_waf_preview_lists(ctx, wlcf, NGX_HTTP_WAF_OBJ_HEADERS,
                               &allow, &deny, &mask, &cap_deny, &cap_mask);

    pairs = ngx_http_waf_header_pairs(ctx);

    if (pairs == NULL) {
        return;
    }

    kv = pairs->elts;

    ngx_http_waf_jw_lit(jw, ",\"headers_preview\":[");

    left    = budget[NGX_HTTP_WAF_OBJ_HEADERS];
    item    = sh->preview_item[NGX_HTTP_WAF_OBJ_HEADERS];
    first   = 1;
    dropped = 0;

    for (i = 0; i < pairs->nelts; i++) {

        if (kv[i].key.len == 0) {
            continue;
        }

        if (!ngx_http_waf_preview_allowed(&kv[i].key, allow, deny)
            || ngx_http_waf_preview_listed(cap_deny, &kv[i].key))
        {
            continue;
        }

        value = kv[i].value;

        if (ngx_http_waf_preview_listed(mask, &kv[i].key)
            || ngx_http_waf_preview_listed(cap_mask, &kv[i].key))
        {
            ngx_http_waf_preview_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
        }

        mark = jw->pos;

        rc = ngx_http_waf_preview_pair(jw, left, &kv[i].key, &value, first,
                                       item);

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_FULL) {
            break;
        }

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED) {
            dropped++;
            continue;
        }

        left -= (size_t) (jw->pos - mark);
        first = 0;
    }

    ngx_http_waf_jw_lit(jw, "]");

    ngx_http_waf_preview_dropped(jw, "headers_preview_dropped", dropped);
}


static void
ngx_http_waf_preview_args(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                     *p, *last, *amp, *eq, *mark, hex[64];
    size_t                      left, item;
    ngx_str_t                   name, value;
    ngx_uint_t                  first, dropped, rc;
    ngx_array_t                *allow, *deny, *mask, *cap_deny, *cap_mask;
    size_t                      budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    if (budget[NGX_HTTP_WAF_OBJ_ARGS] == 0) {
        return;
    }

    ngx_http_waf_preview_lists(ctx, wlcf, NGX_HTTP_WAF_OBJ_ARGS,
                               &allow, &deny, &mask, &cap_deny, &cap_mask);

    ngx_http_waf_jw_lit(jw, ",\"args_preview\":[");

    left    = budget[NGX_HTTP_WAF_OBJ_ARGS];
    item    = sh->preview_item[NGX_HTTP_WAF_OBJ_ARGS];
    first   = 1;
    dropped = 0;

    p    = r->args.data;
    last = p + r->args.len;

    while (p < last) {

        amp = ngx_strlchr(p, last, '&');
        if (amp == NULL) {
            amp = last;
        }

        eq = ngx_strlchr(p, amp, '=');

        if (eq != NULL) {
            name.data  = p;
            name.len   = (size_t) (eq - p);
            value.data = eq + 1;
            value.len  = (size_t) (amp - eq - 1);

        } else {
            name.data  = p;
            name.len   = (size_t) (amp - p);
            value.data = p;
            value.len  = 0;
        }

        p = amp + 1;

        if (name.len == 0) {
            continue;
        }

        if (!ngx_http_waf_preview_allowed(&name, allow, deny)
            || ngx_http_waf_preview_listed(cap_deny, &name))
        {
            continue;
        }

        if (ngx_http_waf_preview_listed(mask, &name)
            || ngx_http_waf_preview_listed(cap_mask, &name))
        {
            ngx_http_waf_preview_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
        }

        mark = jw->pos;

        rc = ngx_http_waf_preview_pair(jw, left, &name, &value, first, item);

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_FULL) {
            break;
        }

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED) {
            dropped++;
            continue;
        }

        left -= (size_t) (jw->pos - mark);
        first = 0;
    }

    ngx_http_waf_jw_lit(jw, "]");

    ngx_http_waf_preview_dropped(jw, "args_preview_dropped", dropped);
}


static void
ngx_http_waf_preview_body(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                     *buf;
    size_t                      len, room, budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_chain_t                *cl;
    ngx_http_request_t         *r = ctx->request;

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    room = budget[NGX_HTTP_WAF_OBJ_BODY];

    if (room == 0) {
        return;
    }

    if (ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].len != 0) {
        len = ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].len;

        if (len > room) {
            len = room;
        }

        if (len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"body_preview\":");
            (void) ngx_http_waf_preview_text(
                jw, ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].data, len,
                room);
            ngx_http_waf_jw_lit(jw, ",\"body_preview_source\":\"sent\"");
        }

        return;
    }

    /*
     * The copy of the capture serves when it is long enough: the whole body,
     * or at least as much as the budget. A record wider than the capture reads
     * the body itself, not the capture's prefix.
     */

    if (ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY].len != 0
        && (ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY].len >= room
            || (ctx->ph->locator != NULL && ctx->ph->locator->complete)
            || ngx_http_waf_body_chain(ctx) == NULL))
    {
        len = ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY].len;

        if (len > room) {
            len = room;
        }

        if (len == 0) {
            return;
        }

        ngx_http_waf_jw_lit(jw, ",\"body_preview\":");
        (void) ngx_http_waf_preview_text(jw,
                                         ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY]
                                             .data,
                                         len, room);
        return;
    }

    cl = ngx_http_waf_body_chain(ctx);

    if (cl == NULL) {
        return;
    }

    buf = ngx_pnalloc(r->pool, room);
    if (buf == NULL) {
        return;
    }

    len = ngx_http_waf_preview_take(r, cl, buf, room);
    if (len == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"body_preview\":");
    (void) ngx_http_waf_preview_text(jw, buf, len, room);
}


static ngx_uint_t
ngx_http_waf_preview_pair(ngx_http_waf_jw_t *jw, size_t room, ngx_str_t *name,
    ngx_str_t *value, ngx_uint_t first, size_t item_max)
{
    u_char             *mark;
    size_t              written, taken;
    ngx_http_waf_jw_t   sub;

    if (room > (size_t) (jw->end - jw->pos)) {
        room = (size_t) (jw->end - jw->pos);
    }

    ngx_http_waf_jw_init(&sub, jw->pos, room);

    if (!first) {
        ngx_http_waf_jw_lit(&sub, ",");
    }

    ngx_http_waf_jw_lit(&sub, "[");

    mark = sub.pos;
    ngx_http_waf_jw_str(&sub, name);

    if (item_max == NGX_HTTP_WAF_PREVIEW_ITEM_NONE) {
        ngx_http_waf_jw_lit(&sub, ",");
        ngx_http_waf_jw_str(&sub, value);

    } else {
        if (!ngx_http_waf_jw_ok(&sub)) {
            return NGX_HTTP_WAF_PREVIEW_PAIR_FULL;
        }

        written = (size_t) (sub.pos - mark);

        if (written * 2 > item_max) {
            return NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED;
        }

        ngx_http_waf_jw_lit(&sub, ",");

        taken = ngx_http_waf_preview_text(&sub, value->data, value->len,
                                          item_max - written);

        if (taken < value->len) {
            ngx_http_waf_jw_lit(&sub, ",1");
        }
    }

    ngx_http_waf_jw_lit(&sub, "]");

    if (!ngx_http_waf_jw_ok(&sub)) {
        return NGX_HTTP_WAF_PREVIEW_PAIR_FULL;
    }

    jw->pos += ngx_http_waf_jw_len(&sub);

    return NGX_HTTP_WAF_PREVIEW_PAIR_OK;
}


static void
ngx_http_waf_preview_dropped(ngx_http_waf_jw_t *jw, const char *field,
    ngx_uint_t dropped)
{
    if (dropped == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) field, ngx_strlen(field));
    ngx_http_waf_jw_lit(jw, "\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) dropped);
}


static size_t
ngx_http_waf_preview_text(ngx_http_waf_jw_t *jw, u_char *data, size_t len,
    size_t room)
{
    u_char    *p, *last, *start;
    size_t     need;
    uint32_t   u;
    static const u_char  hex[] = "0123456789abcdef";

    if (room > (size_t) (jw->end - jw->pos)) {
        room = (size_t) (jw->end - jw->pos);
    }

    if (room < 2) {
        jw->overflow = 1;
        return 0;
    }

    *jw->pos++ = '"';
    room -= 2;

    p    = data;
    last = data + len;

    while (p < last) {

        start = p;

        if (*p < 0x80) {
            u = *p++;

            if (u == '"' || u == '\\') {
                if (room < 2) {
                    p = start;
                    break;
                }

                *jw->pos++ = '\\';
                *jw->pos++ = (u_char) u;
                room -= 2;
                continue;
            }

            if (u >= 0x20) {
                if (room < 1) {
                    p = start;
                    break;
                }

                *jw->pos++ = (u_char) u;
                room--;
                continue;
            }

            if (u == '\n' || u == '\r' || u == '\t' || u == '\b' || u == '\f') {
                if (room < 2) {
                    p = start;
                    break;
                }

                *jw->pos++ = '\\';
                *jw->pos++ = (u == '\n') ? 'n'
                           : (u == '\r') ? 'r'
                           : (u == '\t') ? 't'
                           : (u == '\b') ? 'b' : 'f';
                room -= 2;
                continue;
            }

            if (room < 6) {
                p = start;
                break;
            }

            *jw->pos++ = '\\';
            *jw->pos++ = 'u';
            *jw->pos++ = '0';
            *jw->pos++ = '0';
            *jw->pos++ = hex[(u >> 4) & 0x0f];
            *jw->pos++ = hex[u & 0x0f];
            room -= 6;
            continue;
        }

        u = ngx_utf8_decode(&p, (size_t) (last - start));

        if (u == 0xfffffffe) {
            p = start;
            break;
        }

        if (u == 0xffffffff) {
            if (room < 3) {
                p = start;
                break;
            }

            *jw->pos++ = 0xef;
            *jw->pos++ = 0xbf;
            *jw->pos++ = 0xbd;
            room -= 3;
            continue;
        }

        need = (size_t) (p - start);

        if (room < need) {
            p = start;
            break;
        }

        jw->pos = ngx_cpymem(jw->pos, start, need);
        room -= need;
    }

    *jw->pos++ = '"';

    return (size_t) (p - data);
}


static void
ngx_http_waf_preview_lists(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj, ngx_array_t **allow,
    ngx_array_t **deny, ngx_array_t **mask, ngx_array_t **cap_deny,
    ngx_array_t **cap_mask)
{
    ngx_uint_t                  own;
    ngx_array_t               **pv, **cap;
    ngx_http_waf_ovr_part_t    *part = &ngx_http_waf_audit_ovr_cur(ctx)->audit;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    /*
     * The record's own lists replace the capture lists; without them the
     * record masks what the capture masked. The module cuts the record from
     * the request itself, so either way the slice comes from the original.
     * An inspector asking for the original gets the own lists only, asking
     * for the store gets the own lists over the capture lists.
     */

    own = ngx_http_waf_lists_own(sh, NGX_HTTP_WAF_LIST_PREVIEW, obj);

    pv  = sh->lists[NGX_HTTP_WAF_LIST_PREVIEW][obj];
    cap = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][obj];

    *allow = pv[NGX_HTTP_WAF_AXIS_ALLOW];
    *deny  = pv[NGX_HTTP_WAF_AXIS_DENY];
    *mask  = pv[NGX_HTTP_WAF_AXIS_MASK];

    if (ngx_http_waf_ovr_original(part, obj)
        || (own && !ngx_http_waf_ovr_store(part, obj)))
    {
        *cap_deny = NULL;
        *cap_mask = NULL;
        return;
    }

    *cap_deny = cap[NGX_HTTP_WAF_AXIS_DENY];
    *cap_mask = cap[NGX_HTTP_WAF_AXIS_MASK];
}


static void
ngx_http_waf_preview_hash(ngx_str_t *src, u_char hex[64])
{
    u_char                 digest[32];
    ngx_http_waf_sha256_t  sha;

    ngx_http_waf_sha256_init(&sha);
    ngx_http_waf_sha256_update(&sha, src->data, src->len);
    ngx_http_waf_sha256_final(&sha, digest);
    (void) ngx_hex_dump(hex, digest, 32);
}


static ngx_uint_t
ngx_http_waf_preview_allowed(ngx_str_t *name, ngx_array_t *allow,
    ngx_array_t *deny)
{
    if (ngx_http_waf_preview_listed(deny, name)) {
        return 0;
    }

    if (allow == NULL || allow->nelts == 0) {
        return 1;
    }

    return ngx_http_waf_preview_listed(allow, name);
}


static ngx_uint_t
ngx_http_waf_preview_listed(ngx_array_t *list, ngx_str_t *name)
{
    ngx_str_t   *item;
    ngx_uint_t   i;

    if (list == NULL || list->nelts == 0) {
        return 0;
    }

    item = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (item[i].len == name->len
            && ngx_strncasecmp(item[i].data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static size_t
ngx_http_waf_preview_take(ngx_http_request_t *r, ngx_chain_t *in, u_char *dst,
    size_t size)
{
    off_t         pos;
    size_t        taken, avail;
    ssize_t       n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    taken = 0;

    for (cl = in; cl != NULL && taken < size; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {

            for (pos = b->file_pos; pos < b->file_last && taken < size;
                 )
            {
                avail = (size_t) ngx_min((off_t) (size - taken),
                                         b->file_last - pos);

                n = ngx_read_file(b->file, dst + taken, avail, pos);
                if (n <= 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "waf: reading \"%V\" for the body preview "
                                  "failed", &b->file->name);
                    return taken;
                }

                taken += (size_t) n;
                pos   += n;
            }

            continue;
        }

        avail = (size_t) ngx_min((off_t) (size - taken), b->last - b->pos);

        ngx_memcpy(dst + taken, b->pos, avail);
        taken += avail;
    }

    return taken;
}
