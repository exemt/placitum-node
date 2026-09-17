#include "body/ngx_http_waf_body.h"


static ngx_int_t ngx_http_waf_drv_inline_put(ngx_http_waf_body_op_t *op);


static ngx_http_waf_body_driver_t  ngx_http_waf_drv_inline = {
    ngx_string("inline"),
    0,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_waf_drv_inline_put,
    NULL,
    NULL
};


ngx_http_waf_body_driver_t *
ngx_http_waf_body_driver_inline(void)
{
    return &ngx_http_waf_drv_inline;
}


static ngx_int_t
ngx_http_waf_drv_inline_put(ngx_http_waf_body_op_t *op)
{
    ngx_log_error(NGX_LOG_INFO, op->log, 0,
                  "waf: store driver \"inline\" keeps no objects, %O bytes "
                  "not placed", op->len);

    op->locator.unavailable = NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED;
    op->status              = NGX_ERROR;

    return NGX_OK;
}
