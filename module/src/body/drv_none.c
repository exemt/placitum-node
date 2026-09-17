#include "body/ngx_http_waf_body.h"


static ngx_int_t ngx_http_waf_drv_none_put(ngx_http_waf_body_op_t *op);


static ngx_http_waf_body_driver_t  ngx_http_waf_drv_none = {
    ngx_string("none"),
    0,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_waf_drv_none_put,
    NULL,
    NULL
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
