#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_SHM_MIN_SIZE   (256 * 1024)

#define NGX_HTTP_WAF_DS_BYTES_PER_ENTRY  128
#define NGX_HTTP_WAF_SHM_RESERVE         (256 * 1024)


static ngx_int_t ngx_http_waf_shm_init_zone(ngx_shm_zone_t *zone, void *data);


static ngx_http_waf_shm_t  *ngx_http_waf_shm_ctx;


ngx_http_waf_shm_t *
ngx_http_waf_shm(void)
{
    return ngx_http_waf_shm_ctx;
}


char *
ngx_http_waf_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ssize_t     size;
    ngx_str_t  *args;

    args = cf->args->elts;

    if (wmcf->shm_zone != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_shm_zone is already declared as \"%V\"",
                           &wmcf->shm_name);
        return NGX_CONF_ERROR;
    }

    size = ngx_parse_size(&args[2]);

    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid zone size \"%V\"", &args[2]);
        return NGX_CONF_ERROR;
    }

    if (size < NGX_HTTP_WAF_SHM_MIN_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: zone \"%V\" is too small, minimum is %d bytes",
                           &args[1], NGX_HTTP_WAF_SHM_MIN_SIZE);
        return NGX_CONF_ERROR;
    }

    wmcf->shm_zone = ngx_shared_memory_add(cf, &args[1], (size_t) size,
                                           &ngx_http_waf_module);
    if (wmcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    wmcf->shm_zone->init = ngx_http_waf_shm_init_zone;

    wmcf->shm_name = args[1];

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_waf_shm_required(ngx_conf_t *cf, const char *directive)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (wmcf != NULL && wmcf->shm_zone != NULL) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: %s requires waf_shm_zone to be declared",
                       directive);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_waf_shm_fit(ngx_conf_t *cf)
{
    off_t                      need;
    ngx_uint_t                 i, entries;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->shm_zone == NULL || wmcf->datasets == NULL) {
        return NGX_OK;
    }

    ds   = wmcf->datasets->elts;
    need = NGX_HTTP_WAF_SHM_RESERVE;

    for (i = 0; i < wmcf->datasets->nelts; i++) {
        entries = ds[i].mode == NGX_HTTP_WAF_DS_MODE_INTERNAL
                      ? (ds[i].entries != NULL ? ds[i].entries->nelts : 0)
                      : ds[i].max;

        need += (off_t) entries * NGX_HTTP_WAF_DS_BYTES_PER_ENTRY;
    }

    if (need <= (off_t) wmcf->shm_zone->shm.size) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: zone \"%V\" of %uz bytes does not fit the "
                       "declared datasets: they need about %O bytes "
                       "(%d per entry plus %d of overhead). Raise "
                       "waf_shm_zone or lower limit= on the datasets",
                       &wmcf->shm_name, wmcf->shm_zone->shm.size, need,
                       NGX_HTTP_WAF_DS_BYTES_PER_ENTRY,
                       NGX_HTTP_WAF_SHM_RESERVE);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_waf_shm_init_zone(ngx_shm_zone_t *zone, void *data)
{
    ngx_http_waf_shm_t  *shm = data;

    size_t            len;
    ngx_slab_pool_t  *shpool;

    if (shm != NULL) {
        ngx_http_waf_shm_ctx = shm;
        return ngx_http_waf_fcache_init(shm, zone);
    }

    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (zone->shm.exists) {
        ngx_http_waf_shm_ctx = shpool->data;
        zone->data           = shpool->data;

        return ngx_http_waf_fcache_init(shpool->data, zone);
    }

    shm = ngx_slab_calloc(shpool, sizeof(ngx_http_waf_shm_t));
    if (shm == NULL) {
        return NGX_ERROR;
    }

    shm->shpool = shpool;

    ngx_rbtree_init(&shm->rate, &shm->rate_sentinel,
                    ngx_http_waf_rate_insert_value);
    ngx_queue_init(&shm->rate_lru);

    shpool->data = shm;

    len = sizeof(" in waf zone \"\"") - 1 + zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in waf zone \"%V\"%Z", &zone->shm.name);

    ngx_http_waf_shm_ctx = shm;
    zone->data           = shm;

    return ngx_http_waf_fcache_init(shm, zone);
}
