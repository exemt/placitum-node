/*
 * Драйвер inline: формально не хранилище -- тело едет в самом сообщении.
 *
 * Отдельный store с этим драйвером нужен ровно затем, чтобы запретить любое
 * внешнее размещение: тело тогда честно становится недоступным вместо того,
 * чтобы уйти в сеть.
 */

#include "body/ngx_http_waf_body.h"


static ngx_int_t ngx_http_waf_drv_inline_put(ngx_http_waf_body_op_t *op);


static ngx_http_waf_body_driver_t  ngx_http_waf_drv_inline = {
    ngx_string("inline"),
    0,                                 /* caps: размещать негде и удалять нечего */
    0,                                 /* max_object: ограничивает inline_max */
    NULL,                              /* create_conf                       */
    NULL,                              /* set_option                        */
    NULL,                              /* validate_conf                     */
    NULL,                              /* init_worker                       */
    NULL,                              /* exit_worker                       */
    ngx_http_waf_drv_inline_put,
    NULL,                              /* del                               */
    NULL                               /* get                               */
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
                  "waf: body of %O bytes exceeds the inline limit and driver "
                  "\"inline\" places nothing outside the message", op->len);

    op->locator.unavailable = NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED;
    op->status              = NGX_ERROR;

    return NGX_OK;
}
