#ifndef _NGX_HTTP_WAF_CODEC_H_INCLUDED_
#define _NGX_HTTP_WAF_CODEC_H_INCLUDED_


#include "ngx_http_waf.h"


#define NGX_HTTP_WAF_PROTOCOL_VERSION   2

#define NGX_HTTP_WAF_DATASET_VERSION    3

#define NGX_HTTP_WAF_JSON_MAX_DEPTH     16


typedef struct {
    u_char     *start;
    u_char     *pos;
    u_char     *end;
    unsigned    overflow:1;
} ngx_http_waf_jw_t;


void  ngx_http_waf_jw_init(ngx_http_waf_jw_t *jw, u_char *buf, size_t size);
void  ngx_http_waf_jw_raw(ngx_http_waf_jw_t *jw, const u_char *data,
          size_t len);
void  ngx_http_waf_jw_string(ngx_http_waf_jw_t *jw, const u_char *data,
          size_t len);
void  ngx_http_waf_jw_int(ngx_http_waf_jw_t *jw, ngx_int_t v);

#define ngx_http_waf_jw_lit(jw, s)                                            \
    ngx_http_waf_jw_raw(jw, (const u_char *) s, sizeof(s) - 1)

#define ngx_http_waf_jw_str(jw, s)                                            \
    ngx_http_waf_jw_string(jw, (s)->data, (s)->len)

#define ngx_http_waf_jw_len(jw)   ((size_t) ((jw)->pos - (jw)->start))
#define ngx_http_waf_jw_ok(jw)    ((jw)->overflow == 0)


typedef struct {
    u_char      *pos;
    u_char      *end;
    ngx_pool_t  *pool;
    const char  *error;
    unsigned     first:1;
} ngx_http_waf_jp_t;


void       ngx_http_waf_jp_init(ngx_http_waf_jp_t *jp, ngx_str_t *payload,
               ngx_pool_t *pool);

ngx_int_t  ngx_http_waf_jp_object(ngx_http_waf_jp_t *jp);
ngx_int_t  ngx_http_waf_jp_array(ngx_http_waf_jp_t *jp);

ngx_int_t  ngx_http_waf_jp_member(ngx_http_waf_jp_t *jp, ngx_str_t *key);

ngx_int_t  ngx_http_waf_jp_element(ngx_http_waf_jp_t *jp);

ngx_int_t  ngx_http_waf_jp_end(ngx_http_waf_jp_t *jp);

ngx_int_t  ngx_http_waf_jp_string(ngx_http_waf_jp_t *jp, ngx_str_t *out);

ngx_int_t  ngx_http_waf_jp_string_buf(ngx_http_waf_jp_t *jp, u_char *buf,
               size_t size, ngx_str_t *out);

ngx_int_t  ngx_http_waf_jp_int(ngx_http_waf_jp_t *jp, ngx_int_t *out);

ngx_int_t  ngx_http_waf_jp_bool(ngx_http_waf_jp_t *jp, ngx_uint_t *out);

ngx_int_t  ngx_http_waf_jp_skip(ngx_http_waf_jp_t *jp);

ngx_uint_t ngx_http_waf_jp_null(ngx_http_waf_jp_t *jp);


ngx_int_t  ngx_http_waf_msg_request(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
               ngx_str_t *out);

void       ngx_http_waf_msg_frame(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx);

char      *ngx_http_waf_msg_req_validate(ngx_conf_t *cf,
               ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf);

size_t     ngx_http_waf_vars_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t mask);
void       ngx_http_waf_vars_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, size_t value_max, ngx_uint_t mask);


ngx_int_t  ngx_http_waf_msg_reply(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
               ngx_str_t *payload, ngx_http_waf_reply_t *reply, ngx_str_t *err);


#endif
