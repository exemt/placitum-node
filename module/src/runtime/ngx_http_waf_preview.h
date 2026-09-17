#ifndef _NGX_HTTP_WAF_PREVIEW_H_INCLUDED_
#define _NGX_HTTP_WAF_PREVIEW_H_INCLUDED_


#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"


size_t     ngx_http_waf_preview_room(ngx_http_waf_loc_conf_t *wlcf,
               ngx_uint_t phase);

size_t     ngx_http_waf_preview_room_ctx(ngx_http_waf_ctx_t *ctx);

size_t     ngx_http_waf_preview_body_budget(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_preview_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx);

size_t     ngx_http_waf_preview_text(ngx_http_waf_jw_t *jw, u_char *data,
               size_t len, size_t room);


#endif
