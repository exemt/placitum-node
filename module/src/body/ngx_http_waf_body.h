#ifndef _NGX_HTTP_WAF_BODY_H_INCLUDED_
#define _NGX_HTTP_WAF_BODY_H_INCLUDED_


#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"


#define NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS  0x0001
#define NGX_HTTP_WAF_BODY_CAP_DELETE          0x0004
#define NGX_HTTP_WAF_BODY_CAP_TTL             0x0008
#define NGX_HTTP_WAF_BODY_CAP_GET             0x0020


typedef enum {
    NGX_HTTP_WAF_BODY_AVAILABLE          = 0,
    NGX_HTTP_WAF_BODY_OVERSIZE           = 1,
    NGX_HTTP_WAF_BODY_STORE_ERROR        = 2,
    NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED = 3
} ngx_http_waf_body_unavail_e;


struct ngx_http_waf_locator_s {
    ngx_str_t                  store;
    ngx_str_t                  driver;
    ngx_str_t                  key;

    ngx_str_t                  inline_data;

    off_t                      size;
    off_t                      declared_size;
    u_char                     sha256[32];

    time_t                     expires_at;
    ngx_str_t                  encoding;

    ngx_str_t                  hint;

    off_t                      offset;

    ngx_uint_t                 unavailable;

    unsigned                   has_sha256:1;
    unsigned                   complete:1;
    unsigned                   truncated:1;
};


typedef struct ngx_http_waf_body_op_s  ngx_http_waf_body_op_t;

struct ngx_http_waf_body_op_s {
    void                      *store_conf;
    ngx_pool_t                *pool;
    ngx_log_t                 *log;

    ngx_uint_t                 phase;
    ngx_uint_t                 obj;

    off_t                      len;

    ngx_str_t                  data;

    ngx_http_waf_locator_t     locator;
    ngx_int_t                  status;

    unsigned                   retain:1;
    unsigned                   hold:1;
    unsigned                   in_call:1;
    unsigned                   done:1;

    void                     (*handler)(ngx_http_waf_body_op_t *op);
    void                     (*complete)(ngx_http_waf_body_op_t *op);
    void                      *data_ctx;
};


typedef struct {
    ngx_str_t                  name;
    ngx_uint_t                 caps;
    off_t                      max_object;

    off_t                    (*object_max)(void *conf);

    void                    *(*create_conf)(ngx_conf_t *cf);
    char                    *(*set_option)(ngx_conf_t *cf, void *conf,
                                   ngx_str_t *key, ngx_str_t *value);
    char                    *(*validate_conf)(ngx_conf_t *cf, void *conf);
    ngx_int_t                (*init_worker)(ngx_cycle_t *cycle, void *conf);
    void                     (*exit_worker)(ngx_cycle_t *cycle, void *conf);

    ngx_int_t                (*put)(ngx_http_waf_body_op_t *op);
    ngx_int_t                (*del)(ngx_http_waf_body_op_t *op);
    ngx_int_t                (*get)(ngx_http_waf_body_op_t *op);
} ngx_http_waf_body_driver_t;


struct ngx_http_waf_body_store_s {
    ngx_http_waf_body_driver_t  *driver;
    void                        *conf;
};


ngx_int_t  ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_t *drv);
ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_find(ngx_str_t *name);

ngx_int_t  ngx_http_waf_body_drivers_init(ngx_conf_t *cf);

ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_none(void);
ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_inline(void);
ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_redis(void);


char *ngx_http_waf_store_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

char *ngx_http_waf_sets_store_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_int_t  ngx_http_waf_sets_get(ngx_str_t *key, off_t max, ngx_pool_t *pool,
               ngx_log_t *log, void (*handler)(ngx_http_waf_body_op_t *op),
               void *data, ngx_http_waf_body_op_t **out);

char *ngx_http_waf_body_validate(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf);


ngx_int_t  ngx_http_waf_body_init_worker(ngx_cycle_t *cycle);
void       ngx_http_waf_body_exit_worker(ngx_cycle_t *cycle);


ngx_int_t  ngx_http_waf_body_place(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_body_release(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_body_frame_end(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_store_get(ngx_http_waf_ctx_t *ctx, ngx_str_t *key,
               off_t max, void (*handler)(ngx_http_waf_body_op_t *op),
               ngx_http_waf_body_op_t **out);

void       ngx_http_waf_store_del_key(ngx_http_waf_ctx_t *ctx, ngx_str_t *key);

ngx_str_t *ngx_http_waf_body_phase_tag_name(ngx_uint_t phase);

ngx_uint_t ngx_http_waf_body_wave_need(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t wave);

ngx_uint_t ngx_http_waf_meta_wave_need(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t wave);

ngx_int_t  ngx_http_waf_meta_place(ngx_http_waf_ctx_t *ctx, ngx_uint_t need);


ngx_http_waf_locator_t *ngx_http_waf_store_locator(ngx_http_waf_ctx_t *ctx,
                            ngx_uint_t obj);

ngx_array_t *ngx_http_waf_header_pairs(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_obj_visible_phase(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t phase, ngx_uint_t obj);
ngx_http_waf_locator_t *ngx_http_waf_store_locator_phase(
               ngx_http_waf_ctx_t *ctx, ngx_uint_t phase, ngx_uint_t obj);

ngx_http_waf_locator_t *ngx_http_waf_store_locator_live(
               ngx_http_waf_ctx_t *ctx, ngx_uint_t phase, ngx_uint_t obj);
void       ngx_http_waf_store_write_phase(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, ngx_uint_t phase, const char *section);

size_t     ngx_http_waf_needs_size(void);
void       ngx_http_waf_needs_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_agent_needs_body(ngx_http_waf_ctx_t *ctx);

size_t     ngx_http_waf_archive_wants(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
               ngx_uint_t verdict);
ngx_uint_t ngx_http_waf_archive_names(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj);
ngx_uint_t ngx_http_waf_archive_original(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t obj);

ngx_uint_t ngx_http_waf_lists_own(ngx_http_waf_shoot_conf_t *sh,
               ngx_uint_t kind, ngx_uint_t obj);
ngx_uint_t ngx_http_waf_lists_cover(ngx_http_waf_shoot_conf_t *sh,
               ngx_uint_t kind, ngx_uint_t obj);
ngx_uint_t ngx_http_waf_store_serves(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj);

ngx_int_t  ngx_http_waf_meta_collect(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
               size_t limit, ngx_uint_t raw, ngx_str_t *out,
               ngx_uint_t *truncated);

off_t      ngx_http_waf_body_attach_len(ngx_http_waf_ctx_t *ctx, size_t limit,
               off_t *total);
ngx_int_t  ngx_http_waf_body_attach(ngx_http_waf_ctx_t *ctx, int fd,
               size_t limit, ngx_http_waf_locator_t *loc);

ngx_chain_t *ngx_http_waf_body_chain(ngx_http_waf_ctx_t *ctx);
off_t        ngx_http_waf_body_seen(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_obj_suffix_reserved(ngx_str_t *suffix);

char      *ngx_http_waf_obj_names(ngx_uint_t mask);

size_t     ngx_http_waf_store_size(ngx_http_waf_ctx_t *ctx);

size_t     ngx_http_waf_store_max_size(ngx_http_waf_main_conf_t *wmcf,
               size_t client_max);

void       ngx_http_waf_store_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx);

#define NGX_HTTP_WAF_LOC_BODY     0x01
#define NGX_HTTP_WAF_LOC_ADDRESS  0x02
#define NGX_HTTP_WAF_LOC_ATTACH   0x04

void       ngx_http_waf_locator_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_locator_t *loc, ngx_uint_t flags);


ngx_uint_t ngx_http_waf_archive_mask(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_archive_pending(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_archive_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, ngx_uint_t mask);

ngx_int_t  ngx_http_waf_obj_find(ngx_str_t *name, ngx_uint_t *index);

void       ngx_http_waf_action_archive_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_action_t *a);


#define NGX_HTTP_WAF_BODY_DEBUG_LEN                                            \
    (NGX_HTTP_WAF_OBJ_COUNT                                                    \
     * (sizeof(" headers=unavailable:store_unconfigured/")                \
        + NGX_OFF_T_LEN + 256))

u_char    *ngx_http_waf_body_debug(ngx_http_waf_ctx_t *ctx, u_char *p,
               u_char *last);


typedef struct {
    uint64_t    bytes;
    uint32_t    h[8];
    u_char      block[64];
    size_t      used;
} ngx_http_waf_sha256_t;

void  ngx_http_waf_sha256_init(ngx_http_waf_sha256_t *sha);
void  ngx_http_waf_sha256_update(ngx_http_waf_sha256_t *sha, const u_char *data,
          size_t len);
void  ngx_http_waf_sha256_final(ngx_http_waf_sha256_t *sha, u_char result[32]);


#endif
