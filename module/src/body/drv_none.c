/*
 * Драйвер none: тело не размещается никогда.
 *
 * Это правильный выбор по умолчанию для маршрутов, где инспектируются только
 * заголовки. Всё, что не влезло в инлайн, инспектор получает с
 * unavailable=store_unconfigured и обязан обработать этот случай явно.
 */

#include "body/ngx_http_waf_body.h"


static ngx_int_t ngx_http_waf_drv_none_put(ngx_http_waf_body_op_t *op);


static ngx_http_waf_body_driver_t  ngx_http_waf_drv_none = {
    ngx_string("none"),
    0,                                 /* caps                              */
    0,                                 /* max_object                        */
    NULL,                              /* create_conf                       */
    NULL,                              /* set_option                        */
    NULL,                              /* validate_conf                     */
    NULL,                              /* init_worker                       */
    NULL,                              /* exit_worker                       */
    ngx_http_waf_drv_none_put,
    NULL,                              /* del                               */
    NULL                               /* get                               */
};


ngx_http_waf_body_driver_t *
ngx_http_waf_body_driver_none(void)
{
    return &ngx_http_waf_drv_none;
}


static ngx_int_t
ngx_http_waf_drv_none_put(ngx_http_waf_body_op_t *op)
{
    op->locator.unavailable = NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED;
    op->status              = NGX_ERROR;

    return NGX_OK;
}
