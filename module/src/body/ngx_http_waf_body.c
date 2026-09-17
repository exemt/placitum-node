#include "body/ngx_http_waf_body.h"
#include "runtime/ngx_http_waf_preview.h"


#define NGX_HTTP_WAF_BODY_MAX_DRIVERS   8

#define NGX_HTTP_WAF_BODY_CHUNK         4096

#define NGX_HTTP_WAF_ATTACH_CHUNK       16384


static ngx_int_t ngx_http_waf_body_decide(ngx_http_waf_ctx_t *ctx);
static ngx_chain_t *ngx_http_waf_body_source(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_body_collect(ngx_http_waf_ctx_t *ctx,
    off_t total, off_t place);
static ngx_int_t ngx_http_waf_body_key(ngx_http_waf_ctx_t *ctx,
    ngx_str_t *key, ngx_str_t *suffix);
static ngx_uint_t ngx_http_waf_store_is_external(
    ngx_http_waf_body_store_t *store);
static ngx_int_t ngx_http_waf_headers_collect(ngx_http_waf_ctx_t *ctx,
    size_t limit, ngx_uint_t raw, ngx_str_t *out, ngx_uint_t *truncated);
static ngx_int_t ngx_http_waf_args_collect(ngx_http_waf_ctx_t *ctx,
    size_t limit, ngx_uint_t raw, ngx_str_t *out, ngx_uint_t *truncated);
static ngx_int_t ngx_http_waf_meta_place_one(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_int_t ngx_http_waf_meta_result(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_meta_on_put(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_store_del(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_body_op_t *op, ngx_uint_t keep);
static void ngx_http_waf_body_release_phase(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase);
static void ngx_http_waf_body_release_all(ngx_http_waf_ctx_t *ctx);
static ngx_uint_t ngx_http_waf_phase_follows(ngx_http_waf_ctx_t *ctx);
static ngx_uint_t ngx_http_waf_archive_kept(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase);
static size_t ngx_http_waf_locator_object_size(ngx_http_waf_locator_t *loc);
static off_t ngx_http_waf_body_length(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_body_encoding(ngx_http_request_t *r,
    ngx_http_waf_locator_t *loc);
static void ngx_http_waf_body_encoding_out(ngx_http_request_t *r,
    ngx_http_waf_locator_t *loc);
static void ngx_http_waf_body_attach_response(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_locator_t *loc, off_t held);
static void ngx_http_waf_body_on_put(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_body_cleanup(void *data);
static void ngx_http_waf_body_abandon(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_body_unavailable(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t reason, ngx_uint_t policy);
static char *ngx_http_waf_body_validate_phase(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase);
static ngx_uint_t ngx_http_waf_body_route_mask(ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase, ngx_http_waf_mask_t *mask);
static ngx_uint_t ngx_http_waf_name_listed(ngx_array_t *list, ngx_str_t *name);
static void ngx_http_waf_capture_hash(ngx_str_t *src, u_char hex[64]);
static ngx_int_t ngx_http_waf_args_filter(ngx_http_request_t *r, ngx_str_t *src,
    ngx_array_t *deny, ngx_array_t *mask, ngx_str_t *out);
static size_t ngx_http_waf_store_need(ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase,
    ngx_uint_t obj);
static size_t ngx_http_waf_store_need_ctx(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_uint_t ngx_http_waf_capture_masks(ngx_http_waf_shoot_conf_t *sh,
    ngx_uint_t obj);
static ngx_uint_t ngx_http_waf_attachable(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_int_t ngx_http_waf_meta_place_blob(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj, ngx_str_t *blob);
static void ngx_http_waf_jw_namelist(ngx_http_waf_jw_t *jw, const char *field,
    ngx_array_t *list);


static ngx_http_waf_body_driver_t
    *ngx_http_waf_body_drivers[NGX_HTTP_WAF_BODY_MAX_DRIVERS];
static ngx_uint_t  ngx_http_waf_body_ndrivers;

static ngx_uint_t  ngx_http_waf_body_holds;


static ngx_str_t  ngx_http_waf_body_unavail_names[] = {
    ngx_string("available"),
    ngx_string("oversize"),
    ngx_string("store_error"),
    ngx_string("store_unconfigured")
};


static ngx_str_t  ngx_http_waf_body_phase_tag[] = {
    ngx_string("req"),
    ngx_string("rsp"),
    ngx_string("frm"),
    ngx_string("frm")
};


static ngx_str_t  ngx_http_waf_body_content_encoding =
    ngx_string("content-encoding");


static ngx_str_t  ngx_http_waf_store_hot = ngx_string("hot");


#define ngx_http_waf_hdr_room(len)   ((len) * 6 + 8)


typedef struct {
    ngx_str_t    name;
    ngx_str_t    suffix;
    ngx_int_t  (*collect)(ngx_http_waf_ctx_t *ctx, size_t limit,
                          ngx_uint_t raw, ngx_str_t *out,
                          ngx_uint_t *truncated);
} ngx_http_waf_obj_t;


static ngx_http_waf_obj_t  ngx_http_waf_objs[NGX_HTTP_WAF_OBJ_COUNT] = {
    { ngx_string("headers"), ngx_string("hdr"), ngx_http_waf_headers_collect },
    { ngx_string("args"),    ngx_string("arg"), ngx_http_waf_args_collect    },
    { ngx_string("body"),    ngx_null_string,   NULL                         }
};


static size_t
ngx_http_waf_store_need(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase,
    ngx_uint_t obj)
{
    size_t                      need, one;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[phase];

    need = 0;

    if (sh->capture & NGX_HTTP_WAF_OBJ_BIT(obj)) {
        one = sh->capture_limit[obj];

        if (one == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE) {
            return (size_t) -1;
        }

        if (one > need) {
            need = one;
        }
    }

    if (ngx_http_waf_phase_is_frame(phase)) {

        if (sh->archive & NGX_HTTP_WAF_OBJ_BIT(obj)) {
            one = sh->archive_limit[obj];

            if (one == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE) {
                return (size_t) -1;
            }

            if (one > need) {
                need = one;
            }
        }

        if (sh->preview[obj] > need) {
            need = sh->preview[obj];
        }
    }

    return need;
}


static size_t
ngx_http_waf_store_need_ctx(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return ngx_http_waf_store_need(wlcf, ctx->phase, obj);
}


/*
 * How much of the object the agent takes on this outcome: 0 when it does not,
 * NGX_HTTP_WAF_AGENT_WHOLE for the whole object, a byte count otherwise. The
 * route line and the archive verb of the inspectors are both read here.
 */

size_t
ngx_http_waf_archive_wants(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    ngx_uint_t verdict)
{
    size_t                      limit;
    ngx_uint_t                  bit, mask, forced;
    ngx_http_waf_ovr_part_t    *ovr;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];
    ovr  = &ngx_http_waf_audit_ovr_cur(ctx)->archive;
    bit  = NGX_HTTP_WAF_OBJ_BIT(obj);

    if (ovr->set == NGX_HTTP_WAF_SET_OFF) {
        return 0;
    }

    forced = (ovr->set == NGX_HTTP_WAF_SET_ON && ngx_http_waf_audit_enabled());

    if (forced) {
        mask = ngx_http_waf_ovr_on(ovr);

        if (mask == 0) {
            mask = (sh->archive != 0 ? sh->archive : NGX_HTTP_WAF_OBJ_ALL)
                   & ~ovr->off;
        }

        if (!(mask & bit)) {
            return 0;
        }

        if (ovr->has_when && !(ovr->when & (1u << verdict))) {
            return 0;
        }

        limit = (ovr->has_limit & bit) ? ovr->limit[obj]
                                       : sh->archive_limit[obj];

    } else {

        if (!(sh->archive & bit)
            || !(sh->archive_when[obj] & (1u << verdict)))
        {
            return 0;
        }

        limit = sh->archive_limit[obj];
    }

    return (limit == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE)
               ? NGX_HTTP_WAF_AGENT_WHOLE : limit;
}


ngx_uint_t
ngx_http_waf_archive_names(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    return ngx_http_waf_archive_wants(ctx, obj, NGX_HTTP_WAF_V_ALLOW) != 0
           || ngx_http_waf_archive_wants(ctx, obj, NGX_HTTP_WAF_V_DENY) != 0
           || ngx_http_waf_archive_wants(ctx, obj, NGX_HTTP_WAF_V_REDIRECT)
              != 0;
}


/*
 * Name lists of a consumer (archive or record) are its own once any of the
 * three is named for the object, on this level or above: then they replace
 * the capture lists instead of adding to them. Without them the consumer
 * takes the capture lists, exactly what the inspectors saw.
 */

ngx_uint_t
ngx_http_waf_lists_own(ngx_http_waf_shoot_conf_t *sh, ngx_uint_t kind,
    ngx_uint_t obj)
{
    ngx_array_t  **list;

    if (obj >= NGX_HTTP_WAF_META_COUNT) {
        return 0;
    }

    list = sh->lists[kind][obj];

    return list[NGX_HTTP_WAF_AXIS_ALLOW] != NULL
           || list[NGX_HTTP_WAF_AXIS_MASK] != NULL
           || list[NGX_HTTP_WAF_AXIS_DENY] != NULL;
}


static ngx_uint_t
ngx_http_waf_lists_drop(ngx_array_t **own, ngx_str_t *name)
{
    ngx_array_t  *allow = own[NGX_HTTP_WAF_AXIS_ALLOW];

    if (ngx_http_waf_name_listed(own[NGX_HTTP_WAF_AXIS_DENY], name)) {
        return 1;
    }

    return allow != NULL && allow->nelts != 0
           && !ngx_http_waf_name_listed(allow, name);
}


/*
 * Whether the own lists can be laid over the capture view: every name the
 * capture dropped the own lists drop too, every name the capture hashed they
 * hash or drop. Then the copy in the exchange serves, and the agent applies
 * the own lists without hashing twice. Otherwise the view needs something the
 * capture took away, and only the original has it.
 */

ngx_uint_t
ngx_http_waf_lists_cover(ngx_http_waf_shoot_conf_t *sh, ngx_uint_t kind,
    ngx_uint_t obj)
{
    ngx_str_t     *name;
    ngx_uint_t     i;
    ngx_array_t  **cap, **own;

    if (obj >= NGX_HTTP_WAF_META_COUNT) {
        return 1;
    }

    cap = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][obj];
    own = sh->lists[kind][obj];

    if (cap[NGX_HTTP_WAF_AXIS_DENY] != NULL) {
        name = cap[NGX_HTTP_WAF_AXIS_DENY]->elts;

        for (i = 0; i < cap[NGX_HTTP_WAF_AXIS_DENY]->nelts; i++) {
            if (!ngx_http_waf_lists_drop(own, &name[i])) {
                return 0;
            }
        }
    }

    if (cap[NGX_HTTP_WAF_AXIS_MASK] != NULL) {
        name = cap[NGX_HTTP_WAF_AXIS_MASK]->elts;

        for (i = 0; i < cap[NGX_HTTP_WAF_AXIS_MASK]->nelts; i++) {
            if (!ngx_http_waf_lists_drop(own, &name[i])
                && !ngx_http_waf_name_listed(own[NGX_HTTP_WAF_AXIS_MASK],
                                             &name[i]))
            {
                return 0;
            }
        }
    }

    return 1;
}


/*
 * The agent needs the object before the capture masks: the archive has own
 * lists the capture view cannot give, or an inspector asked for the original.
 */

ngx_uint_t
ngx_http_waf_archive_original(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    ngx_http_waf_ovr_part_t  *ovr = &ngx_http_waf_audit_ovr_cur(ctx)->archive;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ngx_http_waf_ovr_original(ovr, obj)) {
        return 1;
    }

    if (ngx_http_waf_ovr_store(ovr, obj)) {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return (wlcf->shoot[ctx->phase].archive_original
            & NGX_HTTP_WAF_OBJ_BIT(obj)) != 0;
}


static ngx_uint_t
ngx_http_waf_capture_masks(ngx_http_waf_shoot_conf_t *sh, ngx_uint_t obj)
{
    ngx_array_t  *mask, *deny;

    if (obj >= NGX_HTTP_WAF_META_COUNT) {
        return 0;
    }

    mask = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][obj][NGX_HTTP_WAF_AXIS_MASK];
    deny = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][obj][NGX_HTTP_WAF_AXIS_DENY];

    return (mask != NULL && mask->nelts != 0)
           || (deny != NULL && deny->nelts != 0);
}


/*
 * The copy in the exchange is what the inspectors saw: the capture slice under
 * the capture masks. It serves the agent when the agent asks for no more than
 * that; otherwise the original travels with the record.
 */

ngx_uint_t
ngx_http_waf_store_serves(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    size_t                    need;
    ngx_uint_t                bit;
    ngx_http_waf_locator_t   *loc;
    ngx_http_waf_loc_conf_t  *wlcf;

    bit = NGX_HTTP_WAF_OBJ_BIT(obj);
    loc = ngx_http_waf_store_locator(ctx, obj);

    if (loc == NULL
        || loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE
        || loc->key.len == 0)
    {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (ngx_http_waf_archive_original(ctx, obj)
        && ngx_http_waf_capture_masks(&wlcf->shoot[ctx->phase], obj))
    {
        return 0;
    }

    need = ngx_http_waf_archive_wants(ctx, obj,
                                      ngx_http_waf_route_verdict(ctx));

    if (obj == NGX_HTTP_WAF_OBJ_BODY) {

        if (loc->complete) {
            return 1;
        }

        return need != NGX_HTTP_WAF_AGENT_WHOLE
               && (off_t) need <= ctx->ph->body_placed_len;
    }

    if (!(ctx->ph->meta_truncated & bit)) {
        return 1;
    }

    return need != NGX_HTTP_WAF_AGENT_WHOLE
           && need <= ctx->ph->store_blob[obj].len;
}


static ngx_uint_t
ngx_http_waf_attachable(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    off_t  total;

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return 0;
    }

    switch (obj) {

    case NGX_HTTP_WAF_OBJ_HEADERS:
        return 1;

    case NGX_HTTP_WAF_OBJ_ARGS:
        return ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST
               && ctx->request->args.len != 0;

    default:
        return ngx_http_waf_body_attach_len(ctx, NGX_HTTP_WAF_AGENT_WHOLE,
                                            &total) != 0;
    }
}


char *
ngx_http_waf_obj_names(ngx_uint_t mask)
{
    static u_char  buf[64];

    ngx_uint_t   i;
    u_char      *p;

    p = buf;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (p != buf) {
            *p++ = ',';
            *p++ = ' ';
        }

        p = ngx_copy(p, ngx_http_waf_objs[i].name.data,
                     ngx_http_waf_objs[i].name.len);
    }

    *p = '\0';

    return (char *) buf;
}


ngx_int_t
ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_t *drv)
{
    if (ngx_http_waf_body_driver_find(&drv->name) != NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_body_ndrivers >= NGX_HTTP_WAF_BODY_MAX_DRIVERS) {
        return NGX_ERROR;
    }

    ngx_http_waf_body_drivers[ngx_http_waf_body_ndrivers++] = drv;

    return NGX_OK;
}


ngx_http_waf_body_driver_t *
ngx_http_waf_body_driver_find(ngx_str_t *name)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_http_waf_body_ndrivers; i++) {
        if (ngx_http_waf_body_drivers[i]->name.len == name->len
            && ngx_memcmp(ngx_http_waf_body_drivers[i]->name.data, name->data,
                          name->len) == 0)
        {
            return ngx_http_waf_body_drivers[i];
        }
    }

    return NULL;
}


ngx_int_t
ngx_http_waf_body_drivers_init(ngx_conf_t *cf)
{
    if (ngx_http_waf_body_ndrivers != 0) {
        return NGX_OK;
    }

    if (ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_none())
            != NGX_OK
        || ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_inline())
            != NGX_OK
        || ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_redis())
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_http_waf_store_parse(ngx_conf_t *cf, ngx_http_waf_body_store_t **target,
    const char *directive)
{
    char                        *rv;
    ngx_str_t                   *args, name, value;
    ngx_uint_t                   i;
    ngx_http_waf_body_store_t   *store;
    ngx_http_waf_body_driver_t  *drv;

    args = cf->args->elts;

    if (*target != NULL) {
        return "is duplicate";
    }

    drv = NULL;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in %s, "
                               "expected key=value", &args[i], directive);
            return NGX_CONF_ERROR;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "driver", 6) == 0) {

            drv = ngx_http_waf_body_driver_find(&value);
            if (drv == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: unknown store driver \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            break;
        }
    }

    if (drv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: %s has no driver=", directive);
        return NGX_CONF_ERROR;
    }

    store = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_body_store_t));
    if (store == NULL) {
        return NGX_CONF_ERROR;
    }

    store->driver = drv;

    if (drv->create_conf != NULL) {
        store->conf = drv->create_conf(cf);
        if (store->conf == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        (void) ngx_http_waf_split(&args[i], &name, &value);

        if (name.len == 6 && ngx_strncmp(name.data, "driver", 6) == 0) {
            continue;
        }

        if (drv->set_option == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: store driver \"%V\" takes no options",
                               &drv->name);
            return NGX_CONF_ERROR;
        }

        rv = drv->set_option(cf, store->conf, &name, &value);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    *target = store;

    if (drv->validate_conf != NULL) {
        return drv->validate_conf(cf, store->conf);
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_store_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    return ngx_http_waf_store_parse(cf, &wmcf->body_store, "waf_store");
}


char *
ngx_http_waf_sets_store_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    char  *rv;

    rv = ngx_http_waf_store_parse(cf, &wmcf->sets_store, "waf_sets_store");
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!(wmcf->sets_store->driver->caps & NGX_HTTP_WAF_BODY_CAP_GET)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_sets_store driver \"%V\" cannot read "
                           "objects", &wmcf->sets_store->driver->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_waf_sets_get(ngx_str_t *key, off_t max, ngx_pool_t *pool,
    ngx_log_t *log, void (*handler)(ngx_http_waf_body_op_t *op), void *data,
    ngx_http_waf_body_op_t **out)
{
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_body_store_t  *store;
    ngx_http_waf_main_conf_t   *wmcf;

    *out = NULL;

    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->sets_store == NULL) {
        return NGX_ERROR;
    }

    store = wmcf->sets_store;

    if (store->driver->get == NULL) {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf  = store->conf;
    op->pool        = pool;
    op->log         = log;
    op->locator.key = *key;
    op->len         = max;
    op->handler     = handler;
    op->data_ctx    = data;
    op->status      = NGX_ERROR;

    *out = op;

    return store->driver->get(op);
}


char *
ngx_http_waf_body_validate(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf)
{
    char        *rv;
    ngx_uint_t   phase;

    if (!wlcf->enable) {
        return NGX_CONF_OK;
    }

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        rv = ngx_http_waf_body_validate_phase(cf, wmcf, wlcf, phase);

        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_body_validate_phase(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase)
{
    ngx_uint_t                   i, need, want_meta;
    ngx_str_t                   *pname;
    ngx_http_waf_wave_t         *waves;
    ngx_http_waf_body_store_t   *store;
    ngx_http_waf_body_driver_t  *drv;
    ngx_http_waf_shoot_conf_t   *sh;

    sh    = &wlcf->shoot[phase];
    pname = ngx_http_waf_phase_name(phase);

    store = wmcf->body_store;

    if (sh->archive != 0) {
        if (wmcf->agent_socket.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive needs waf_agent_socket: the "
                               "agent is what moves objects to the archive and "
                               "cleans the store");
            return NGX_CONF_ERROR;
        }

        if (!ngx_http_waf_store_is_external(store)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive requires waf_store with an "
                               "external driver (not none/inline)");
            return NGX_CONF_ERROR;
        }

        if (!(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: store driver \"%V\" has no remote readers "
                               "capability, so the agent cannot pick up what "
                               "waf_archive keeps",
                               &store->driver->name);
            return NGX_CONF_ERROR;
        }
    }

    need  = NGX_HTTP_WAF_BODY_NONE;
    waves = (wlcf->waves[phase] != NULL) ? wlcf->waves[phase]->elts : NULL;
    want_meta = 0;

    for (i = 0; waves != NULL && i < wlcf->waves[phase]->nelts; i++) {
        if (waves[i].body_need > need) {
            need = waves[i].body_need;
        }

        want_meta |= waves[i].obj_need
                     & (NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
                        | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS));
    }

    want_meta |= sh->archive
                 & (NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
                    | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS));

    if ((sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
        && waves != NULL && wlcf->waves[phase]->nelts != 0
        && need < NGX_HTTP_WAF_BODY_FULL)
    {
        need = NGX_HTTP_WAF_BODY_FULL;
    }

    if ((sh->archive & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
        && need < NGX_HTTP_WAF_BODY_FULL)
    {
        need = NGX_HTTP_WAF_BODY_FULL;
    }

    if (sh->preview[NGX_HTTP_WAF_OBJ_BODY] != 0
        && need == NGX_HTTP_WAF_BODY_NONE)
    {
        need = NGX_HTTP_WAF_BODY_PREVIEW;
    }

    if (need == NGX_HTTP_WAF_BODY_NONE && want_meta == 0) {
        return NGX_CONF_OK;
    }

    if (!ngx_http_waf_store_is_external(store)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: this route places %s, which needs waf_store "
                           "with an external driver (not none/inline)",
                           ngx_http_waf_obj_names(
                               want_meta
                               | ((need != NGX_HTTP_WAF_BODY_NONE)
                                  ? NGX_HTTP_WAF_OBJ_BIT(
                                        NGX_HTTP_WAF_OBJ_BODY)
                                  : 0)));
        return NGX_CONF_ERROR;
    }

    drv = store->driver;

    if (need != NGX_HTTP_WAF_BODY_NONE
        && drv->max_object != 0
        && (off_t) wlcf->body_limit[phase] > drv->max_object)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_body_limit %V %uz exceeds the %O byte "
                           "object limit of store driver \"%V\"",
                           pname, wlcf->body_limit[phase],
                           drv->max_object, &drv->name);
        return NGX_CONF_ERROR;
    }

    {
        ngx_http_waf_mask_t  used;

        if (!(drv->caps & NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS)
            && ngx_http_waf_body_route_mask(wlcf, phase, &used))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: this route places objects for inspectors, "
                               "but store driver \"%V\" has no remote readers "
                               "capability", &drv->name);
            return NGX_CONF_ERROR;
        }
    }

    if (!(drv->caps & NGX_HTTP_WAF_BODY_CAP_TTL)
        && !(drv->caps & NGX_HTTP_WAF_BODY_CAP_DELETE))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "waf: store driver \"%V\" supports neither ttl nor "
                           "delete; placed objects will accumulate",
                           &drv->name);
    }

    return NGX_CONF_OK;
}


static ngx_uint_t
ngx_http_waf_body_route_mask(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase,
    ngx_http_waf_mask_t *mask)
{
    ngx_uint_t            i;
    ngx_http_waf_wave_t  *waves;

    *mask = 0;

    if (wlcf->waves[phase] == NULL) {
        return 0;
    }

    waves = wlcf->waves[phase]->elts;

    for (i = 0; i < wlcf->waves[phase]->nelts; i++) {
        *mask |= waves[i].all;
    }

    return (*mask != 0);
}


static ngx_uint_t
ngx_http_waf_store_is_external(ngx_http_waf_body_store_t *store)
{
    ngx_str_t  *name;

    if (store == NULL || store->driver == NULL) {
        return 0;
    }

    name = &store->driver->name;

    if (name->len == 4 && ngx_strncmp(name->data, "none", 4) == 0) {
        return 0;
    }

    if (name->len == 6 && ngx_strncmp(name->data, "inline", 6) == 0) {
        return 0;
    }

    return 1;
}


static ngx_int_t
ngx_http_waf_store_init_worker(ngx_cycle_t *cycle,
    ngx_http_waf_body_store_t *store)
{
    if (store == NULL || store->driver->init_worker == NULL) {
        return NGX_OK;
    }

    return store->driver->init_worker(cycle, store->conf);
}


ngx_int_t
ngx_http_waf_body_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t   *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return NGX_OK;
    }

    ngx_http_waf_body_holds = 0;

    if (ngx_http_waf_store_init_worker(cycle, wmcf->body_store) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_waf_store_init_worker(cycle, wmcf->sets_store);
}


static void
ngx_http_waf_store_exit_worker(ngx_cycle_t *cycle,
    ngx_http_waf_body_store_t *store)
{
    if (store != NULL && store->driver->exit_worker != NULL) {
        store->driver->exit_worker(cycle, store->conf);
    }
}


void
ngx_http_waf_body_exit_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t   *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return;
    }

    ngx_http_waf_store_exit_worker(cycle, wmcf->body_store);
    ngx_http_waf_store_exit_worker(cycle, wmcf->sets_store);
}


ngx_uint_t
ngx_http_waf_body_wave_need(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    if (waves == NULL || wave >= waves->nelts) {
        return NGX_HTTP_WAF_BODY_NONE;
    }

    return ((ngx_http_waf_wave_t *) waves->elts)[wave].body_need;
}


ngx_uint_t
ngx_http_waf_meta_wave_need(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    ngx_uint_t                need, meta;
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    meta = NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
           | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS);

    waves = wlcf->waves[ctx->phase];

    need = 0;

    if (waves != NULL && wave < waves->nelts) {
        need = ((ngx_http_waf_wave_t *) waves->elts)[wave].obj_need & meta;
    }

    return need;
}


ngx_int_t
ngx_http_waf_meta_place(ngx_http_waf_ctx_t *ctx, ngx_uint_t need)
{
    ngx_uint_t  i;

    ctx->ph->meta_settled = 1;

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (!(need & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (ngx_http_waf_meta_place_one(ctx, i) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx->ph->meta_pending != 0) {
        return NGX_AGAIN;
    }

    return ngx_http_waf_meta_result(ctx);
}


static ngx_int_t
ngx_http_waf_meta_result(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i;

    if (ctx->ph->body_policy != NGX_HTTP_WAF_POLICY_BLOCK) {
        return NGX_OK;
    }

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (ctx->ph->meta[i] != NULL
            && ctx->ph->meta[i]->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_meta_place_one(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    ngx_str_t   blob;
    ngx_uint_t  truncated;

    if (ctx->ph->meta[obj] != NULL) {
        return NGX_OK;
    }

    if (ngx_http_waf_objs[obj].collect(ctx, ngx_http_waf_store_need_ctx(ctx, obj),
                                       0, &blob, &truncated)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (truncated) {
        ctx->ph->meta_truncated |= NGX_HTTP_WAF_OBJ_BIT(obj);
    }

    return ngx_http_waf_meta_place_blob(ctx, obj, &blob);
}


ngx_int_t
ngx_http_waf_meta_collect(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    size_t limit, ngx_uint_t raw, ngx_str_t *out, ngx_uint_t *truncated)
{
    return ngx_http_waf_objs[obj].collect(ctx, limit, raw, out, truncated);
}


static ngx_int_t
ngx_http_waf_meta_place_blob(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    ngx_str_t *blobp)
{
    ngx_int_t                   rc;
    ngx_str_t                   key, blob;
    ngx_uint_t                  pending;
    ngx_pool_cleanup_t         *cln;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_locator_t     *loc;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    blob = *blobp;

    if (blob.len == 0) {
        return NGX_OK;
    }

    ctx->ph->store_blob[obj] = blob;

    loc = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_locator_t));
    if (loc == NULL) {
        return NGX_ERROR;
    }

    ctx->ph->meta[obj] = loc;

    loc->size     = (off_t) blob.len;
    loc->complete = 1;

    wlcf  = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh    = &wlcf->shoot[ctx->phase];
    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    if (!ngx_http_waf_store_is_external(store)) {
        loc->unavailable = NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED;
        ctx->ph->body_policy = wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY];
        return NGX_OK;
    }

    if (ngx_http_waf_body_holds >= wmcf->body_max_holds) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: waf_body_max_holds %ui reached, %V not placed",
                      wmcf->body_max_holds, &ngx_http_waf_objs[obj].name);
        loc->unavailable = NGX_HTTP_WAF_BODY_STORE_ERROR;
        ctx->ph->body_policy = wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY];
        return NGX_OK;
    }

    if (ngx_http_waf_body_key(ctx, &key, &ngx_http_waf_objs[obj].suffix)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf   = store->conf;
    op->pool         = r->pool;
    op->log          = r->connection->log;
    op->rid.data     = ctx->rid_hex;
    op->rid.len      = NGX_HTTP_WAF_RID_HEX_LEN;
    op->phase        = ctx->phase;
    op->obj          = obj;
    op->len          = (off_t) blob.len;
    op->data         = blob;
    op->handler      = ngx_http_waf_meta_on_put;
    op->data_ctx     = ctx;
    op->retain       = (sh->archive & NGX_HTTP_WAF_OBJ_BIT(obj)) ? 1 : 0;

    op->locator        = *loc;
    op->locator.store  = ngx_http_waf_store_hot;
    op->locator.driver = store->driver->name;
    op->locator.key    = key;
    op->locator.size   = (off_t) blob.len;

    if (!ctx->ph->store_cleanup) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_body_cleanup;
        cln->data    = ctx;
        ctx->ph->store_cleanup = 1;
    }

    op->hold = (ctx->ph->meta_op[obj] == NULL);
    ctx->ph->meta_op[obj] = op;

    if (op->hold) {
        ngx_http_waf_body_holds++;
    }

    pending = ++ctx->ph->meta_pending;

    ctx->ph->meta_in_put = 1;
    rc = store->driver->put(op);
    ctx->ph->meta_in_put = 0;

    if (rc != NGX_AGAIN && ctx->ph->meta_pending == pending) {
        ngx_http_waf_meta_on_put(op);
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_name_listed(ngx_array_t *list, ngx_str_t *name)
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


static void
ngx_http_waf_capture_hash(ngx_str_t *src, u_char hex[64])
{
    u_char                 digest[32];
    ngx_http_waf_sha256_t  sha;

    ngx_http_waf_sha256_init(&sha);
    ngx_http_waf_sha256_update(&sha, src->data, src->len);
    ngx_http_waf_sha256_final(&sha, digest);
    (void) ngx_hex_dump(hex, digest, 32);
}


ngx_array_t *
ngx_http_waf_header_pairs(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t           i;
    ngx_keyval_t        *kv;
    ngx_array_t         *pairs;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        return ngx_http_waf_response_headers(ctx);
    }

    pairs = ngx_array_create(r->pool, 16, sizeof(ngx_keyval_t));
    if (pairs == NULL) {
        return NULL;
    }

    part = &r->headers_in.headers.part;
    h    = part->elts;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        kv = ngx_array_push(pairs);
        if (kv == NULL) {
            return NULL;
        }

        kv->key   = h[i].key;
        kv->value = h[i].value;
    }

    return pairs;
}


static ngx_int_t
ngx_http_waf_headers_collect(ngx_http_waf_ctx_t *ctx, size_t limit,
    ngx_uint_t raw, ngx_str_t *out, ngx_uint_t *truncated)
{
    size_t                    size, vroom;
    u_char                   *buf, *mark, hex[64];
    ngx_str_t                 value;
    ngx_uint_t                i, first;
    ngx_keyval_t             *kv;
    ngx_array_t              *pairs, *mask, *deny;
    ngx_http_waf_jw_t         jw;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    *truncated = 0;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];

    mask = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_HEADERS]
                    [NGX_HTTP_WAF_AXIS_MASK];
    deny = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_HEADERS]
                    [NGX_HTTP_WAF_AXIS_DENY];

    if (limit == (size_t) -1) {
        limit = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
    }

    pairs = ngx_http_waf_header_pairs(ctx);
    if (pairs == NULL) {
        return NGX_ERROR;
    }

    kv   = pairs->elts;
    size = 2;

    for (i = 0; i < pairs->nelts; i++) {

        vroom = ngx_http_waf_hdr_room(kv[i].value.len);

        if (mask != NULL && mask->nelts != 0
            && vroom < ngx_http_waf_hdr_room(64))
        {
            vroom = ngx_http_waf_hdr_room(64);
        }

        size += ngx_http_waf_hdr_room(kv[i].key.len) + vroom + 8;
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_http_waf_jw_init(&jw, buf, size);
    ngx_http_waf_jw_lit(&jw, "[");

    first = 1;

    for (i = 0; i < pairs->nelts; i++) {

        if (!raw && ngx_http_waf_name_listed(deny, &kv[i].key)) {
            continue;
        }

        value = kv[i].value;

        if (!raw && ngx_http_waf_name_listed(mask, &kv[i].key)) {
            ngx_http_waf_capture_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
        }

        mark = jw.pos;

        if (!first) {
            ngx_http_waf_jw_lit(&jw, ",");
        }

        ngx_http_waf_jw_lit(&jw, "[");
        ngx_http_waf_jw_str(&jw, &kv[i].key);
        ngx_http_waf_jw_lit(&jw, ",");
        ngx_http_waf_jw_str(&jw, &value);
        ngx_http_waf_jw_lit(&jw, "]");

        if (limit != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
            && ngx_http_waf_jw_len(&jw) + 1 > limit)
        {
            jw.pos = mark;
            *truncated = 1;
            break;
        }

        first = 0;
    }

    ngx_http_waf_jw_lit(&jw, "]");

    if (!ngx_http_waf_jw_ok(&jw)) {
        return NGX_ERROR;
    }

    out->data = buf;
    out->len  = ngx_http_waf_jw_len(&jw);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_args_collect(ngx_http_waf_ctx_t *ctx, size_t limit,
    ngx_uint_t raw, ngx_str_t *out, ngx_uint_t *truncated)
{
    ngx_array_t                *deny, *mask;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    *truncated = 0;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        ngx_str_null(out);
        return NGX_OK;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];

    if (limit == (size_t) -1) {
        limit = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
    }

    deny = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_ARGS]
                    [NGX_HTTP_WAF_AXIS_DENY];
    mask = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_ARGS]
                    [NGX_HTTP_WAF_AXIS_MASK];

    if (!raw
        && ((deny != NULL && deny->nelts != 0)
            || (mask != NULL && mask->nelts != 0)))
    {
        if (ngx_http_waf_args_filter(ctx->request, &ctx->request->args,
                                     deny, mask, out)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        *out = ctx->request->args;
    }

    if (limit != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE && out->len > limit) {
        out->len   = limit;
        *truncated = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_args_filter(ngx_http_request_t *r, ngx_str_t *src,
    ngx_array_t *deny, ngx_array_t *mask, ngx_str_t *out)
{
    u_char     *p, *last, *dst, *buf, hex[64];
    size_t      n, pairs;
    ngx_str_t   name, value;
    ngx_uint_t  first, had_eq;

    if (src->len == 0) {
        *out = *src;
        return NGX_OK;
    }

    pairs = 1;
    last  = src->data + src->len;

    for (p = src->data; p < last; p++) {
        if (*p == '&') {
            pairs++;
        }
    }

    n = src->len + pairs * 66 + 1;
    buf = ngx_pnalloc(r->pool, n);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    dst   = buf;
    first = 1;
    p     = src->data;

    while (p < last) {

        name.data = p;
        had_eq    = 0;

        while (p < last && *p != '=' && *p != '&') {
            p++;
        }

        name.len = (size_t) (p - name.data);

        if (p < last && *p == '=') {
            had_eq = 1;
            p++;
            value.data = p;

            while (p < last && *p != '&') {
                p++;
            }

            value.len = (size_t) (p - value.data);

        } else {
            value.data = (u_char *) "";
            value.len  = 0;
        }

        if (p < last && *p == '&') {
            p++;
        }

        if (ngx_http_waf_name_listed(deny, &name)) {
            continue;
        }

        if (ngx_http_waf_name_listed(mask, &name)) {
            ngx_http_waf_capture_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
            had_eq     = 1;
        }

        if (!first) {
            *dst++ = '&';
        }

        first = 0;

        if (name.len > 0) {
            dst = ngx_cpymem(dst, name.data, name.len);
        }

        if (had_eq) {
            *dst++ = '=';

            if (value.len > 0) {
                dst = ngx_cpymem(dst, value.data, value.len);
            }
        }
    }

    out->data = buf;
    out->len  = (size_t) (dst - buf);

    return NGX_OK;
}


static void
ngx_http_waf_meta_on_put(ngx_http_waf_body_op_t *op)
{
    ngx_uint_t                reason;
    ngx_http_waf_ctx_t       *ctx = op->data_ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx->ph->meta_pending--;

    if (op->status == NGX_OK) {
        *ctx->ph->meta[op->obj] = op->locator;
        ctx->ph->meta_placed   |= NGX_HTTP_WAF_OBJ_BIT(op->obj);

    } else {
        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: body store \"%V\" failed to place %O bytes of %V",
                      &op->locator.store, op->len,
                      &ngx_http_waf_objs[op->obj].name);

        reason = (op->locator.unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
                     ? op->locator.unavailable
                     : (ngx_uint_t) NGX_HTTP_WAF_BODY_STORE_ERROR;

        ctx->ph->meta[op->obj]->unavailable = reason;
        ctx->ph->meta[op->obj]->complete    = 0;

        ctx->ph->body_policy =
            (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_TRIM)
                ? NGX_HTTP_WAF_POLICY_BLOCK
                : wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY];

        if (op->hold) {
            ngx_http_waf_body_holds--;
            op->hold = 0;
        }

        ctx->ph->meta_op[op->obj] = NULL;
    }

    if (ctx->ph->meta_pending == 0 && !ctx->ph->meta_in_put) {
        ngx_http_waf_body_resumed(ctx, ngx_http_waf_meta_result(ctx));
    }
}


ngx_int_t
ngx_http_waf_body_place(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t      *r = ctx->request;
    ngx_http_waf_locator_t  *loc;

    if (ctx->ph->locator != NULL || ctx->ph->body_placed) {
        return NGX_OK;
    }

    loc = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_locator_t));
    if (loc == NULL) {
        return NGX_ERROR;
    }

    ctx->ph->locator = loc;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        ngx_http_waf_body_encoding_out(r, loc);

        loc->declared_size = (r->headers_out.content_length_n > 0)
                                 ? r->headers_out.content_length_n
                                 : 0;

    } else if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        ngx_str_set(&loc->encoding, "identity");
        loc->declared_size = ngx_http_waf_body_length(ctx);

    } else {
        ngx_http_waf_body_encoding(r, loc);

        loc->declared_size = (r->headers_in.content_length_n > 0)
                                 ? r->headers_in.content_length_n
                                 : 0;
    }

    loc->size = ngx_http_waf_body_length(ctx);

    if (loc->size == 0) {
        ctx->ph->locator = NULL;
        return NGX_OK;
    }

    return ngx_http_waf_body_decide(ctx);
}


static ngx_int_t
ngx_http_waf_body_decide(ngx_http_waf_ctx_t *ctx)
{
    off_t                       place;
    size_t                      need, limit;
    ngx_int_t                   rc;
    ngx_str_t                   key;
    ngx_uint_t                  keep, policy;
    ngx_pool_cleanup_t         *cln;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_wave_t        *wave;
    ngx_http_waf_locator_t     *loc = ctx->ph->locator;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    wlcf  = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh    = &wlcf->shoot[ctx->phase];
    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    wave = ngx_http_waf_current_wave(ctx);

    keep = (sh->archive & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY)) != 0;
    need = ngx_http_waf_store_need_ctx(ctx, NGX_HTTP_WAF_OBJ_BODY);

    if (need == 0) {

        if (wave != NULL && wave->body_need == NGX_HTTP_WAF_BODY_META) {
            place = 0;

            if (ngx_http_waf_body_collect(ctx, loc->size, place) != NGX_OK) {
                ngx_http_waf_body_unavailable(ctx,
                                              NGX_HTTP_WAF_BODY_STORE_ERROR,
                                              wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);
                return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                           ? NGX_ERROR : NGX_OK;
            }

            loc->has_sha256 = 1;
            loc->complete   = 0;
            return NGX_OK;
        }

        ctx->ph->locator = NULL;
        return NGX_OK;
    }

    place = loc->size;

    limit  = wlcf->body_limit[ctx->phase];
    policy = wlcf->body_limit_policy[ctx->phase];

    if (loc->size > (off_t) limit) {
        if (policy != NGX_HTTP_WAF_POLICY_TRIM
            && !keep
            && !(sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
            && (wave == NULL || wave->body_need == NGX_HTTP_WAF_BODY_NONE
                || wave->body_need == NGX_HTTP_WAF_BODY_META))
        {
            ctx->ph->locator = NULL;
            return NGX_OK;
        }

        if (policy != NGX_HTTP_WAF_POLICY_TRIM) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "waf: body of %O bytes exceeds waf_body_limit %uz",
                          loc->size, limit);

            ngx_http_waf_body_unavailable(ctx, NGX_HTTP_WAF_BODY_OVERSIZE,
                                          policy);

            return (policy == NGX_HTTP_WAF_POLICY_BLOCK)
                       ? NGX_ERROR : NGX_OK;
        }

        place = (off_t) limit;
    }

    if (need != (size_t) -1 && place > (off_t) need) {
        place = (off_t) need;
    }

    loc->truncated = (place < loc->size) ? 1 : 0;

    if (ngx_http_waf_body_collect(ctx, loc->size, place) != NGX_OK) {
        ngx_http_waf_body_unavailable(ctx, NGX_HTTP_WAF_BODY_STORE_ERROR,
                                      wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

        return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                   ? NGX_ERROR : NGX_OK;
    }

    loc->has_sha256 = 1;
    loc->complete   = loc->truncated ? 0 : 1;
    ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY] = loc->inline_data;

    if (place == 0) {
        return NGX_OK;
    }

    if (store == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: body of %O bytes needs a store, none configured",
                      place);

        ngx_http_waf_body_unavailable(ctx,
                                      NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED,
                                      wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

        return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                   ? NGX_ERROR : NGX_OK;
    }

    if (ngx_http_waf_body_holds >= wmcf->body_max_holds) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: waf_body_max_holds %ui reached, body not placed",
                      wmcf->body_max_holds);

        ngx_http_waf_body_unavailable(ctx, NGX_HTTP_WAF_BODY_STORE_ERROR,
                                      wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

        return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                   ? NGX_ERROR : NGX_OK;
    }

    if (ngx_http_waf_body_key(ctx, &key, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf   = store->conf;
    op->pool         = r->pool;
    op->log          = r->connection->log;
    op->rid.data     = ctx->rid_hex;
    op->rid.len      = NGX_HTTP_WAF_RID_HEX_LEN;
    op->phase        = ctx->phase;
    op->obj          = NGX_HTTP_WAF_OBJ_BODY;
    op->len          = place;
    op->data         = loc->inline_data;
    op->handler      = ngx_http_waf_body_on_put;
    op->data_ctx     = ctx;
    op->retain       = keep;

    op->locator        = *loc;
    op->locator.store  = ngx_http_waf_store_hot;
    op->locator.driver = store->driver->name;
    op->locator.key    = key;
    op->locator.size   = place;

    ngx_str_null(&op->locator.inline_data);
    ngx_str_null(&loc->inline_data);

    if (!ctx->ph->store_cleanup) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_body_cleanup;
        cln->data    = ctx;
        ctx->ph->store_cleanup = 1;
    }

    op->hold = (ctx->ph->body_op == NULL);
    ctx->ph->body_op = op;

    if (op->hold) {
        ngx_http_waf_body_holds++;
    }

    ctx->ph->body_in_put = 1;
    rc = store->driver->put(op);
    ctx->ph->body_in_put = 0;

    if (rc == NGX_AGAIN && !ctx->ph->body_settled) {
        return NGX_AGAIN;
    }

    if (!ctx->ph->body_settled) {
        ngx_http_waf_body_on_put(op);
    }

    return (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE
            && ctx->ph->body_policy == NGX_HTTP_WAF_POLICY_BLOCK)
               ? NGX_ERROR : NGX_OK;
}


static void
ngx_http_waf_body_on_put(ngx_http_waf_body_op_t *op)
{
    ngx_uint_t                reason;
    ngx_http_waf_ctx_t       *ctx = op->data_ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx->ph->body_settled = 1;

    if (op->status == NGX_OK) {
        *ctx->ph->locator        = op->locator;
        ctx->ph->body_placed     = 1;
        ctx->ph->body_placed_len = op->len;

        if (!ctx->ph->body_in_put) {
            ngx_http_waf_body_resumed(ctx, NGX_OK);
        }

        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                  "waf: body store \"%V\" failed to place %O bytes",
                  &op->locator.store, op->len);

    reason = (op->locator.unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
                 ? op->locator.unavailable
                 : (ngx_uint_t) NGX_HTTP_WAF_BODY_STORE_ERROR;

    ngx_http_waf_body_unavailable(ctx, reason, wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

    if (op->hold) {
        ngx_http_waf_body_holds--;
        op->hold = 0;
    }

    ctx->ph->body_op = NULL;

    if (!ctx->ph->body_in_put) {
        ngx_http_waf_body_resumed(ctx,
            (ctx->ph->body_policy == NGX_HTTP_WAF_POLICY_BLOCK)
                ? NGX_ERROR : NGX_OK);
    }
}


void
ngx_http_waf_body_release(ngx_http_waf_ctx_t *ctx)
{
    if (ngx_http_waf_phase_follows(ctx)) {
        return;
    }

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return;
    }

    ngx_http_waf_body_release_all(ctx);
}


void
ngx_http_waf_body_frame_end(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_phase_ctx_t  *ph;

    if (!ngx_http_waf_phase_is_frame(ctx->phase)) {
        return;
    }

    ph = &ctx->phases[ctx->phase];

    if (ph->body_op != NULL && ph->body_placed) {
        ngx_http_waf_body_release_phase(ctx, ctx->phase);
    }

    if (ph->body_op != NULL) {
        ngx_http_waf_body_holds--;
        ph->body_op = NULL;
    }
}


static void
ngx_http_waf_body_release_all(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  phase;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        ngx_http_waf_body_release_phase(ctx, phase);
    }
}


static void
ngx_http_waf_body_release_phase(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase)
{
    ngx_uint_t                 i, keep;
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    keep = ngx_http_waf_archive_kept(ctx, phase);

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (ph->meta_op[i] == NULL
            || !(ph->meta_placed & NGX_HTTP_WAF_OBJ_BIT(i)))
        {
            continue;
        }

        ngx_http_waf_store_del(ctx, ph->meta_op[i],
                               keep & NGX_HTTP_WAF_OBJ_BIT(i));

        ph->meta_op[i]   = NULL;
        ph->meta_placed &= ~NGX_HTTP_WAF_OBJ_BIT(i);
    }

    if (ph->body_op != NULL && ph->body_placed) {
        ngx_http_waf_store_del(ctx, ph->body_op,
                               keep & NGX_HTTP_WAF_OBJ_BIT(
                                          NGX_HTTP_WAF_OBJ_BODY));

        ph->body_op     = NULL;
        ph->body_placed = 0;
    }

    if (ph->stale != NULL) {
        ngx_str_t   *key = ph->stale->elts;
        ngx_uint_t   n;

        for (n = 0; n < ph->stale->nelts; n++) {
            ngx_http_waf_store_del_key(ctx, &key[n]);
        }

        ph->stale->nelts = 0;
    }
}


static ngx_uint_t
ngx_http_waf_phase_follows(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return 0;
    }

    if (ctx->ph->verdict == NGX_HTTP_WAF_V_DENY || ctx->ph->fail_blocked) {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return (wlcf->waves[NGX_HTTP_WAF_PHASE_RESPONSE] != NULL
            && wlcf->waves[NGX_HTTP_WAF_PHASE_RESPONSE]->nelts != 0)
           || (wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_C2S] != NULL
               && wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_C2S]->nelts != 0)
           || (wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_S2C] != NULL
               && wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_S2C]->nelts != 0);
}


ngx_uint_t
ngx_http_waf_archive_pending(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_phase_follows(ctx) ? 1 : 0;
}


/* Keys the agent will read: the archive set minus what rode with the record. */

static ngx_uint_t
ngx_http_waf_archive_kept(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase)
{
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    if (phase == ctx->phase) {
        return ngx_http_waf_archive_mask(ctx) & ~ph->attached;
    }

    return ph->archive_settled ? (ph->archive & ~ph->attached) : 0;
}


static void
ngx_http_waf_store_del(ngx_http_waf_ctx_t *ctx, ngx_http_waf_body_op_t *op,
    ngx_uint_t keep)
{
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    ngx_http_waf_body_holds--;

    if (keep) {
        return;
    }

    wmcf  = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    store = wmcf->body_store;

    if (store == NULL
        || !(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_DELETE)
        || store->driver->del == NULL)
    {
        return;
    }

    (void) store->driver->del(op);
}


ngx_str_t *
ngx_http_waf_body_phase_tag_name(ngx_uint_t phase)
{
    return &ngx_http_waf_body_phase_tag[
               phase >= NGX_HTTP_WAF_NPHASE ? 0 : phase];
}


ngx_int_t
ngx_http_waf_store_get(ngx_http_waf_ctx_t *ctx, ngx_str_t *key, off_t max,
    void (*handler)(ngx_http_waf_body_op_t *op), ngx_http_waf_body_op_t **out)
{
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    *out = NULL;

    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    if (store == NULL
        || !(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_GET)
        || store->driver->get == NULL)
    {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf = store->conf;
    op->pool       = r->pool;
    op->log        = r->connection->log;
    op->rid.data   = ctx->rid_hex;
    op->rid.len    = NGX_HTTP_WAF_RID_HEX_LEN;
    op->phase      = ctx->phase;
    op->obj        = NGX_HTTP_WAF_OBJ_BODY;
    op->len        = max;
    op->handler    = handler;
    op->data_ctx   = ctx;

    op->locator.store  = ngx_http_waf_store_hot;
    op->locator.driver = store->driver->name;
    op->locator.key    = *key;

    op->status = NGX_ERROR;

    *out = op;

    return store->driver->get(op);
}


void
ngx_http_waf_store_del_key(ngx_http_waf_ctx_t *ctx, ngx_str_t *key)
{
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    if (r->pool == NULL
        || store == NULL
        || !(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_DELETE)
        || store->driver->del == NULL)
    {
        return;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return;
    }

    op->store_conf  = store->conf;
    op->pool        = r->pool;
    op->log         = r->connection->log;
    op->locator.key = *key;

    (void) store->driver->del(op);
}


ngx_uint_t
ngx_http_waf_archive_mask(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i, mask, verdict;

    if (ctx->ph->archive_settled) {
        return ctx->ph->archive;
    }

    ctx->ph->archive_settled = 1;
    ctx->ph->archive         = 0;

    if (!ctx->ph->logged) {
        return 0;
    }

    if (ngx_http_waf_phase_is_frame(ctx->phase)
        && !ngx_http_waf_frame_audit_wanted(ctx))
    {
        return 0;
    }

    verdict = ngx_http_waf_route_verdict(ctx);
    mask    = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (ngx_http_waf_archive_wants(ctx, i, verdict) == 0) {
            continue;
        }

        if (ngx_http_waf_store_serves(ctx, i)
            || ngx_http_waf_attachable(ctx, i))
        {
            mask |= NGX_HTTP_WAF_OBJ_BIT(i);
        }
    }

    ctx->ph->archive = mask;

    return mask;
}


static void
ngx_http_waf_jw_namelist(ngx_http_waf_jw_t *jw, const char *field,
    ngx_array_t *list)
{
    ngx_str_t   *item;
    ngx_uint_t   i;

    if (list == NULL || list->nelts == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) field, ngx_strlen(field));
    ngx_http_waf_jw_lit(jw, "\":[");

    item = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &item[i]);
    }

    ngx_http_waf_jw_lit(jw, "]");
}


ngx_int_t
ngx_http_waf_obj_find(ngx_str_t *name, ngx_uint_t *index)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        if (name->len == ngx_http_waf_objs[i].name.len
            && ngx_strncmp(name->data, ngx_http_waf_objs[i].name.data,
                           name->len) == 0)
        {
            *index = i;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void
ngx_http_waf_action_archive_write(ngx_http_waf_jw_t *jw,
    ngx_http_waf_action_t *a)
{
    ngx_uint_t                i, bit, first;
    ngx_http_waf_ovr_part_t  *spec = &a->spec;

    if (spec->has_ttl) {
        ngx_http_waf_jw_lit(jw, ",\"ttl\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) spec->ttl);
    }

    if (spec->has_when) {
        ngx_http_waf_jw_lit(jw, ",\"when\":[");
        first = 1;

        if (spec->when & (1u << NGX_HTTP_WAF_V_ALLOW)) {
            ngx_http_waf_jw_lit(jw, "\"allow\"");
            first = 0;
        }

        if (spec->when & (1u << NGX_HTTP_WAF_V_DENY)) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            ngx_http_waf_jw_lit(jw, "\"deny\"");
        }

        ngx_http_waf_jw_lit(jw, "]");
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit = NGX_HTTP_WAF_OBJ_BIT(i);

        if (!(spec->named & bit)) {
            continue;
        }

        ngx_http_waf_jw_lit(jw, ",");
        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
        ngx_http_waf_jw_lit(jw, ":{");

        first = 1;

        if (spec->off & bit) {
            ngx_http_waf_jw_lit(jw, "\"set\":\"off\"");
            first = 0;
        }

        if (spec->has_limit & bit) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            ngx_http_waf_jw_lit(jw, "\"limit\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) spec->limit[i]);
            first = 0;
        }

        if (spec->source[i] != NGX_HTTP_WAF_SOURCE_NONE) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            if (spec->source[i] == NGX_HTTP_WAF_SOURCE_STORE) {
                ngx_http_waf_jw_lit(jw, "\"source\":\"store\"");

            } else {
                ngx_http_waf_jw_lit(jw, "\"source\":\"original\"");
            }
        }

        ngx_http_waf_jw_lit(jw, "}");
    }
}


void
ngx_http_waf_archive_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t mask)
{
    time_t                      ttl;
    size_t                      limit;
    ngx_uint_t                  i, first;
    ngx_array_t               **lists;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_audit_ovr_t   *ovr;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];
    ovr  = ngx_http_waf_audit_ovr_cur(ctx);

    ngx_http_waf_jw_lit(jw, ",\"archive\":{");

    for (i = 0, first = 1; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (!first) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        first = 0;

        ttl   = sh->archive_ttl[i];
        limit = sh->archive_limit[i];

        if (ovr->archive.set == NGX_HTTP_WAF_SET_ON) {
            if (ovr->archive.has_ttl) {
                ttl = ovr->archive.ttl;
            }

            if (ovr->archive.has_limit & NGX_HTTP_WAF_OBJ_BIT(i)) {
                limit = ovr->archive.limit[i];
            }
        }

        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
        ngx_http_waf_jw_lit(jw, ":{\"ttl\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) ttl);

        if (limit != NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE) {
            ngx_http_waf_jw_lit(jw, ",\"limit\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) limit);
        }

        if (i < NGX_HTTP_WAF_META_COUNT) {

            /*
             * The lists the agent applies: the archive's own, or the capture
             * lists when it has none. An inspector asking for the original
             * gets the own lists only, whatever they are.
             */

            lists = (ngx_http_waf_lists_own(sh, NGX_HTTP_WAF_LIST_ARCHIVE, i)
                     || ngx_http_waf_ovr_original(&ovr->archive, i))
                        ? sh->lists[NGX_HTTP_WAF_LIST_ARCHIVE][i]
                        : sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][i];

            ngx_http_waf_jw_namelist(jw, "allow",
                                     lists[NGX_HTTP_WAF_AXIS_ALLOW]);
            ngx_http_waf_jw_namelist(jw, "mask",
                                     lists[NGX_HTTP_WAF_AXIS_MASK]);
            ngx_http_waf_jw_namelist(jw, "deny",
                                     lists[NGX_HTTP_WAF_AXIS_DENY]);

            if (!(ctx->ph->attach_raw & NGX_HTTP_WAF_OBJ_BIT(i))) {
                ngx_http_waf_jw_namelist(jw, "hashed",
                    sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][i]
                             [NGX_HTTP_WAF_AXIS_MASK]);
            }
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_body_cleanup(void *data)
{
    ngx_http_waf_audit_flush_deferred(data);
    ngx_http_waf_body_release_all(data);
    ngx_http_waf_body_abandon(data);
}


static void
ngx_http_waf_body_abandon(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, phase;
    ngx_http_waf_phase_ctx_t  *ph;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        ph = &ctx->phases[phase];

        for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

            if (ph->meta_op[i] == NULL) {
                continue;
            }

            ngx_http_waf_body_holds--;
            ph->meta_op[i] = NULL;
        }

        if (ph->body_op != NULL) {
            ngx_http_waf_body_holds--;
            ph->body_op = NULL;
        }
    }
}


static ngx_chain_t *
ngx_http_waf_body_source(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        return ctx->hold;
    }

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return ngx_http_waf_frame_source(ctx);
    }

    if (r->request_body == NULL) {
        return NULL;
    }

    return r->request_body->bufs;
}


static off_t
ngx_http_waf_body_length(ngx_http_waf_ctx_t *ctx)
{
    off_t         len;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_http_waf_body_source(ctx);

    if (cl == NULL) {
        return 0;
    }

    len = 0;

    for ( ; cl != NULL; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {
            len += b->file_last - b->file_pos;

        } else {
            len += b->last - b->pos;
        }
    }

    return len;
}


static void
ngx_http_waf_body_encoding_out(ngx_http_request_t *r,
    ngx_http_waf_locator_t *loc)
{
    ngx_str_set(&loc->encoding, "identity");

    if (r->headers_out.content_encoding != NULL
        && r->headers_out.content_encoding->value.len != 0)
    {
        loc->encoding = r->headers_out.content_encoding->value;
    }
}


static void
ngx_http_waf_body_encoding(ngx_http_request_t *r, ngx_http_waf_locator_t *loc)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    ngx_str_set(&loc->encoding, "identity");

    part = &r->headers_in.headers.part;
    h    = part->elts;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                return;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].key.len == ngx_http_waf_body_content_encoding.len
            && ngx_strncasecmp(h[i].key.data,
                               ngx_http_waf_body_content_encoding.data,
                               h[i].key.len) == 0)
        {
            if (h[i].value.len != 0) {
                loc->encoding = h[i].value;
            }

            return;
        }
    }
}


static ngx_int_t
ngx_http_waf_body_collect(ngx_http_waf_ctx_t *ctx, off_t total, off_t place)
{
    ngx_chain_t  *source = ngx_http_waf_body_source(ctx);

    off_t                   left, taken, pos;
    size_t                  avail, copy;
    u_char                 *p;
    u_char                  chunk[NGX_HTTP_WAF_BODY_CHUNK];
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_http_request_t     *r = ctx->request;
    ngx_http_waf_sha256_t   sha;

    p = ngx_pnalloc(r->pool, (size_t) place);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ctx->ph->locator->inline_data.data = p;
    ctx->ph->locator->inline_data.len  = (size_t) place;

    ngx_http_waf_sha256_init(&sha);

    left  = total;
    taken = 0;

    for (cl = source; cl != NULL && left > 0; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {

            for (pos = b->file_pos; pos < b->file_last && left > 0; ) {

                avail = (size_t) ngx_min((off_t) sizeof(chunk),
                                         b->file_last - pos);

                n = ngx_read_file(b->file, chunk, avail, pos);
                if (n <= 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "waf: reading the body file \"%V\" failed",
                                  &b->file->name);
                    return NGX_ERROR;
                }

                ngx_http_waf_sha256_update(&sha, chunk, (size_t) n);

                if (taken < place) {
                    copy = (size_t) ngx_min((off_t) n, place - taken);
                    ngx_memcpy(p + taken, chunk, copy);
                    taken += (off_t) copy;
                }

                pos  += n;
                left -= n;
            }

            continue;
        }

        avail = (size_t) ngx_min((off_t) (b->last - b->pos), left);

        ngx_http_waf_sha256_update(&sha, b->pos, avail);

        if (taken < place) {
            copy = (size_t) ngx_min((off_t) avail, place - taken);
            ngx_memcpy(p + taken, b->pos, copy);
            taken += (off_t) copy;
        }

        left -= (off_t) avail;
    }

    ngx_http_waf_sha256_final(&sha, ctx->ph->locator->sha256);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_body_key(ngx_http_waf_ctx_t *ctx, ngx_str_t *key,
    ngx_str_t *suffix)
{
    u_char                    *p;
    size_t                     len;
    ngx_str_t                 *tag;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    tag = &ngx_http_waf_body_phase_tag[
              ctx->phase >= NGX_HTTP_WAF_NPHASE ? 0 : ctx->phase];

    len = wmcf->node_id.len + 1 + NGX_HTTP_WAF_RID_HEX_LEN + 1 + tag->len;

    if (suffix != NULL && suffix->len != 0) {
        len += 1 + suffix->len;
    }

    p = ngx_pnalloc(ctx->request->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    key->data = p;

    p = ngx_copy(p, wmcf->node_id.data, wmcf->node_id.len);
    *p++ = ':';
    p = ngx_copy(p, ctx->rid_hex, NGX_HTTP_WAF_RID_HEX_LEN);
    *p++ = ':';
    p = ngx_copy(p, tag->data, tag->len);

    if (suffix != NULL && suffix->len != 0) {
        *p++ = ':';
        p = ngx_copy(p, suffix->data, suffix->len);
    }

    key->len = (size_t) (p - key->data);

    return NGX_OK;
}


static void
ngx_http_waf_body_unavailable(ngx_http_waf_ctx_t *ctx, ngx_uint_t reason,
    ngx_uint_t policy)
{
    ngx_http_waf_locator_t  *loc = ctx->ph->locator;

    loc->unavailable = reason;
    loc->complete    = 0;

    ngx_str_null(&loc->inline_data);
    ngx_str_null(&loc->key);
    ngx_str_null(&loc->hint);

    ctx->ph->body_policy = (policy == NGX_HTTP_WAF_POLICY_TRIM)
                           ? NGX_HTTP_WAF_POLICY_BLOCK
                           : policy;
}


u_char *
ngx_http_waf_body_debug(ngx_http_waf_ctx_t *ctx, u_char *p, u_char *last)
{
    ngx_uint_t               i;
    ngx_http_waf_locator_t  *loc;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        loc = ngx_http_waf_store_locator(ctx, i);

        if (loc == NULL) {
            continue;
        }

        if (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE) {
            p = ngx_slprintf(p, last, " %V=unavailable:%V/%O",
                             &ngx_http_waf_objs[i].name,
                             &ngx_http_waf_body_unavail_names[loc->unavailable],
                             loc->size);
            continue;
        }

        if (loc->store.len != 0) {
            p = ngx_slprintf(p, last, " %V=%V:%V/%O",
                             &ngx_http_waf_objs[i].name, &loc->store,
                             &loc->driver, loc->size);
        }
    }

    return p;
}


static size_t
ngx_http_waf_locator_object_size(ngx_http_waf_locator_t *loc)
{
    if (loc == NULL) {
        return sizeof("null") - 1;
    }

    return sizeof("{\"store\":\"\",\"driver\":\"\",\"key\":\"\","
                  "\"size\":,\"declared_size\":,\"sha256\":\"\","
                  "\"complete\":false,\"truncated\":false,\"encoding\":\"\","
                  "\"expires_at\":,\"hint\":\"\",\"unavailable\":\"\","
                  "\"offset\":}")
           + 6 * (loc->store.len + loc->driver.len + loc->key.len
                  + loc->encoding.len + loc->hint.len)
           + 64 + 5 * NGX_INT_T_LEN + 32;
}


ngx_http_waf_locator_t *
ngx_http_waf_store_locator(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    return ngx_http_waf_store_locator_phase(ctx, ctx->phase, obj);
}


ngx_http_waf_locator_t *
ngx_http_waf_store_locator_phase(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    return (obj == NGX_HTTP_WAF_OBJ_BODY) ? ph->locator : ph->meta[obj];
}


ngx_http_waf_locator_t *
ngx_http_waf_store_locator_live(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    if (obj == NGX_HTTP_WAF_OBJ_BODY && ph->live != NULL) {
        return ph->live;
    }

    return ngx_http_waf_store_locator_phase(ctx, phase, obj);
}


ngx_uint_t
ngx_http_waf_obj_visible_phase(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return (wlcf->shoot[phase].capture & NGX_HTTP_WAF_OBJ_BIT(obj)) != 0;
}


size_t
ngx_http_waf_store_size(ngx_http_waf_ctx_t *ctx)
{
    size_t      size;
    ngx_uint_t  i, phase;

    size = 2 * sizeof(",\"request_store\":{}");

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (phase != NGX_HTTP_WAF_PHASE_REQUEST && phase != ctx->phase) {
            continue;
        }

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            size += ngx_http_waf_objs[i].name.len + sizeof("\"\":,")
                    + ngx_http_waf_locator_object_size(
                          ngx_http_waf_store_locator_phase(ctx, phase, i));
        }
    }

    return size;
}


size_t
ngx_http_waf_store_max_size(ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf, size_t client_max)
{
    size_t                      size;
    ngx_uint_t                  i;
    ngx_http_waf_locator_t      loc;
    ngx_http_waf_body_store_t  *store = wmcf->body_store;

    (void) wlcf;

    ngx_memzero(&loc, sizeof(ngx_http_waf_locator_t));

    if (store != NULL) {
        loc.store  = ngx_http_waf_store_hot;
        loc.driver = store->driver->name;
    }

    loc.key.len = wmcf->node_id.len + NGX_HTTP_WAF_RID_HEX_LEN + 3 + 3 + 3;

    loc.hint.len     = NGX_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
    loc.encoding.len = client_max;

    size = sizeof(",\"store\":{}");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        size += ngx_http_waf_objs[i].name.len + sizeof("\"\":,")
                + ngx_http_waf_locator_object_size(&loc);
    }

    return size;
}


void
ngx_http_waf_locator_write(ngx_http_waf_jw_t *jw, ngx_http_waf_locator_t *loc,
    ngx_uint_t flags)
{
    u_char      hex[64];
    ngx_uint_t  body_meta;

    if (loc == NULL) {
        ngx_http_waf_jw_lit(jw, "null");
        return;
    }

    body_meta = flags & NGX_HTTP_WAF_LOC_BODY;

    ngx_http_waf_jw_lit(jw, "{");

    if (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE) {
        ngx_http_waf_jw_lit(jw, "\"unavailable\":");
        ngx_http_waf_jw_str(jw,
                        &ngx_http_waf_body_unavail_names[loc->unavailable]);

        ngx_http_waf_jw_lit(jw, ",\"size\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) loc->size);

        if (body_meta) {
            ngx_http_waf_jw_lit(jw, ",\"declared_size\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) loc->declared_size);
        }

        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    ngx_http_waf_jw_lit(jw, "\"size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) loc->size);

    if (body_meta && loc->has_sha256) {
        (void) ngx_hex_dump(hex, loc->sha256, 32);

        ngx_http_waf_jw_lit(jw, ",\"sha256\":");
        ngx_http_waf_jw_string(jw, hex, 64);
    }

    if (body_meta) {
        if (loc->complete) {
            ngx_http_waf_jw_lit(jw, ",\"complete\":true");
        } else {
            ngx_http_waf_jw_lit(jw, ",\"complete\":false");
        }

        if (loc->truncated) {
            ngx_http_waf_jw_lit(jw, ",\"truncated\":true");
        } else {
            ngx_http_waf_jw_lit(jw, ",\"truncated\":false");
        }

        ngx_http_waf_jw_lit(jw, ",\"encoding\":");
        ngx_http_waf_jw_str(jw, &loc->encoding);
    }

    if (flags & NGX_HTTP_WAF_LOC_ATTACH) {
        ngx_http_waf_jw_lit(jw, ",\"store\":\"attach\",\"offset\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) loc->offset);
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    if (!(flags & NGX_HTTP_WAF_LOC_ADDRESS)) {
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    if (loc->store.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"store\":");
        ngx_http_waf_jw_str(jw, &loc->store);

        ngx_http_waf_jw_lit(jw, ",\"driver\":");
        ngx_http_waf_jw_str(jw, &loc->driver);

        ngx_http_waf_jw_lit(jw, ",\"key\":");
        ngx_http_waf_jw_str(jw, &loc->key);
    }

    if (loc->expires_at != 0) {
        ngx_http_waf_jw_lit(jw, ",\"expires_at\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) loc->expires_at);
    }

    if (loc->hint.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"hint\":");
        ngx_http_waf_jw_str(jw, &loc->hint);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


void
ngx_http_waf_needs_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_inspector_t *insp)
{
    ngx_uint_t                i, need, first;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    need = wlcf->shoot[ctx->phase].capture;

    (void) insp;

    ngx_http_waf_jw_lit(jw, ",\"needs\":[");

    for (i = 0, first = 1; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(need & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (!first) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        first = 0;
        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
    }

    ngx_http_waf_jw_lit(jw, "]");
}


size_t
ngx_http_waf_needs_size(void)
{
    size_t      size;
    ngx_uint_t  i;

    size = sizeof(",\"needs\":[]");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        size += ngx_http_waf_objs[i].name.len + sizeof("\",");
    }

    return size;
}


void
ngx_http_waf_store_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_inspector_t *insp)
{
    ngx_http_waf_store_write_phase(jw, ctx, ctx->phase, "store");
}


void
ngx_http_waf_store_write_phase(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase, const char *section)
{
    ngx_uint_t               i;
    ngx_http_waf_locator_t  *loc;

    ngx_http_waf_jw_lit(jw, ",\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) section, ngx_strlen(section));
    ngx_http_waf_jw_lit(jw, "\":{");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
        ngx_http_waf_jw_lit(jw, ":");

        loc = (phase == ctx->phase)
                  ? ngx_http_waf_store_locator_live(ctx, phase, i)
                  : ngx_http_waf_store_locator_phase(ctx, phase, i);

        if (loc == NULL || !ngx_http_waf_obj_visible_phase(ctx, phase, i)) {
            ngx_http_waf_jw_lit(jw, "null");
            continue;
        }

        {
            ngx_http_waf_locator_t    shown;
            ngx_http_waf_loc_conf_t  *wlcf;
            size_t                    cap;

            shown = *loc;
            wlcf  = ngx_http_get_module_loc_conf(ctx->request,
                                                 ngx_http_waf_module);
            cap   = wlcf->shoot[phase].capture_limit[i];

            if (phase == ctx->phase && loc == ctx->phases[phase].live) {
                cap = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
            }

            if (cap != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
                && shown.size > (off_t) cap)
            {
                shown.size = (off_t) cap;
            }

            ngx_http_waf_locator_write(jw, &shown,
                NGX_HTTP_WAF_LOC_ADDRESS
                | ((i == NGX_HTTP_WAF_OBJ_BODY) ? NGX_HTTP_WAF_LOC_BODY : 0));
        }
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * The body still has to be read from the client when the agent or the preview
 * of this record wants it and no wave asked for it. With a response phase
 * ahead the outcome is not final yet, so a body the archive names on any
 * outcome is read now: later there is no client to read it from.
 */

ngx_uint_t
ngx_http_waf_agent_needs_body(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return 0;
    }

    if (ctx->ph->body_ready || ctx->ph->body_discarded) {
        return 0;
    }

    if (ngx_http_waf_archive_wants(ctx, NGX_HTTP_WAF_OBJ_BODY,
                                   ngx_http_waf_route_verdict(ctx)) == 0
        && !(ngx_http_waf_phase_follows(ctx)
             && ngx_http_waf_archive_names(ctx, NGX_HTTP_WAF_OBJ_BODY))
        && ngx_http_waf_preview_body_budget(ctx) == 0)
    {
        return 0;
    }

    return (r->headers_in.content_length_n > 0 || r->headers_in.chunked);
}


ngx_chain_t *
ngx_http_waf_body_chain(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_body_source(ctx);
}


/*
 * The body as the module saw it, not as much of it as the store got: the
 * record reports the whole length even when the capture is a slice.
 */

off_t
ngx_http_waf_body_seen(ngx_http_waf_ctx_t *ctx)
{
    off_t  total;

    /* a journaled response keeps only a prefix copy, but counts every byte */

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE && ctx->rsp_journal) {
        return ctx->rsp_journal_total;
    }

    total = ngx_http_waf_body_length(ctx);

    if (total > 0) {
        return total;
    }

    return (ctx->ph->locator != NULL) ? ctx->ph->locator->size : 0;
}


/*
 * How many bytes of the body can ride with the record: the body as read, no
 * wider than waf_body_limit (a trimmed body gives its prefix, a body over the
 * limit under another policy gives nothing) and no wider than asked.
 */

off_t
ngx_http_waf_body_attach_len(ngx_http_waf_ctx_t *ctx, size_t limit,
    off_t *total)
{
    off_t                     len, cap;
    ngx_http_waf_loc_conf_t  *wlcf;

    *total = 0;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST
        && (!ctx->ph->body_ready || ctx->ph->body_discarded))
    {
        return 0;
    }

    len = ngx_http_waf_body_length(ctx);

    if (len <= 0) {
        return 0;
    }

    *total = len;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    cap  = (off_t) wlcf->body_limit[ctx->phase];

    if (len > cap) {

        if (wlcf->body_limit_policy[ctx->phase] != NGX_HTTP_WAF_POLICY_TRIM) {
            return 0;
        }

        len = cap;
    }

    if (limit != NGX_HTTP_WAF_AGENT_WHOLE && len > (off_t) limit) {
        len = (off_t) limit;
    }

    return len;
}


/*
 * Writes the body prefix the agent asked for into the attachment file and
 * describes it in loc. The checksum covers the whole body as the client sent
 * it: the placed copy already has it, otherwise it is computed on the way.
 */

ngx_int_t
ngx_http_waf_body_attach(ngx_http_waf_ctx_t *ctx, int fd, size_t limit,
    ngx_http_waf_locator_t *loc)
{
    off_t                    total, place, left, taken, pos;
    size_t                   avail, n;
    ssize_t                  rd;
    u_char                   chunk[NGX_HTTP_WAF_ATTACH_CHUNK];
    ngx_buf_t               *b;
    ngx_uint_t               hashing;
    ngx_chain_t             *cl;
    ngx_http_request_t      *r = ctx->request;
    ngx_http_waf_sha256_t    sha;
    ngx_http_waf_locator_t  *placed;

    place = ngx_http_waf_body_attach_len(ctx, limit, &total);

    if (place == 0) {
        return NGX_DECLINED;
    }

    placed = ctx->ph->locator;

    if (placed != NULL && placed->has_sha256) {
        ngx_memcpy(loc->sha256, placed->sha256, 32);
        loc->has_sha256 = 1;
        hashing = 0;

    } else {
        ngx_http_waf_sha256_init(&sha);
        hashing = 1;
    }

    left  = hashing ? total : place;
    taken = 0;

    for (cl = ngx_http_waf_body_source(ctx); cl != NULL && left > 0;
         cl = cl->next)
    {
        b = cl->buf;

        if (b->in_file) {

            for (pos = b->file_pos; pos < b->file_last && left > 0; ) {

                avail = (size_t) ngx_min((off_t) sizeof(chunk),
                                         ngx_min(b->file_last - pos, left));

                rd = ngx_read_file(b->file, chunk, avail, pos);
                if (rd <= 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "waf: reading the body file \"%V\" for the "
                                  "agent failed", &b->file->name);
                    return NGX_ERROR;
                }

                if (hashing) {
                    ngx_http_waf_sha256_update(&sha, chunk, (size_t) rd);
                }

                if (taken < place) {
                    n = (size_t) ngx_min((off_t) rd, place - taken);

                    if (ngx_http_waf_attach_write(fd, chunk, n) != NGX_OK) {
                        return NGX_ERROR;
                    }

                    taken += (off_t) n;
                }

                pos  += rd;
                left -= rd;
            }

            continue;
        }

        avail = (size_t) ngx_min((off_t) (b->last - b->pos), left);

        if (hashing) {
            ngx_http_waf_sha256_update(&sha, b->pos, avail);
        }

        if (taken < place) {
            n = (size_t) ngx_min((off_t) avail, place - taken);

            if (ngx_http_waf_attach_write(fd, b->pos, n) != NGX_OK) {
                return NGX_ERROR;
            }

            taken += (off_t) n;
        }

        left -= (off_t) avail;
    }

    if (hashing) {
        ngx_http_waf_sha256_final(&sha, loc->sha256);
        loc->has_sha256 = 1;
    }

    loc->size          = taken;
    loc->declared_size = total;
    loc->complete      = (taken == total) ? 1 : 0;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        ngx_http_waf_body_attach_response(ctx, loc, total);
        ngx_http_waf_body_encoding_out(r, loc);

    } else {
        ngx_http_waf_body_encoding(r, loc);
    }

    loc->truncated = loc->complete ? 0 : 1;

    return NGX_OK;
}


/*
 * A response is held, or copied by the journal, only up to what the phase
 * needs, so the bytes in hand are a prefix unless the last buffer came. The
 * whole length is then the journal's count or the held chain; until then it
 * is unknown, the object is not complete, and a checksum of the prefix would
 * pass for the checksum of the response -- it is left out.
 */

static void
ngx_http_waf_body_attach_response(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_locator_t *loc, off_t held)
{
    off_t                whole;
    ngx_http_request_t  *r = ctx->request;

    whole = -1;

    if (ctx->rsp_last) {
        whole = ctx->rsp_journal ? ctx->rsp_journal_total : held;
    }

    if (whole >= 0) {
        loc->declared_size = whole;

    } else if (r->headers_out.content_length_n > 0) {
        loc->declared_size = r->headers_out.content_length_n;
    }

    loc->complete = (whole >= 0 && loc->size == whole) ? 1 : 0;

    if (!loc->complete) {
        loc->has_sha256 = 0;
    }
}


ngx_uint_t
ngx_http_waf_obj_suffix_reserved(ngx_str_t *suffix)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {
        if (suffix->len == ngx_http_waf_objs[i].suffix.len
            && ngx_memcmp(suffix->data, ngx_http_waf_objs[i].suffix.data,
                          suffix->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}
