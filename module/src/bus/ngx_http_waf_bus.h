#ifndef _NGX_HTTP_WAF_BUS_H_INCLUDED_
#define _NGX_HTTP_WAF_BUS_H_INCLUDED_


#include "ngx_http_waf.h"


typedef struct ngx_http_waf_bus_s  ngx_http_waf_bus_t;


typedef enum {
    NGX_HTTP_WAF_BUS_OK           = 0,
    NGX_HTTP_WAF_BUS_UNAVAILABLE  = 2,
    NGX_HTTP_WAF_BUS_OVERFLOW     = 3,
    NGX_HTTP_WAF_BUS_TOO_LARGE    = 4
} ngx_http_waf_bus_status_e;


typedef struct {
    ngx_str_t                   subject;
    ngx_str_t                   payload;

    uint64_t                    rid;
    ngx_uint_t                  inspector;
} ngx_http_waf_bus_msg_t;


struct ngx_http_waf_bus_s {
    ngx_str_t                   name;
    void                       *data;
    ngx_log_t                  *log;

    ngx_str_t                   inbox;
    ngx_pid_t                   pid;
    uint32_t                    nonce;

    ngx_str_t                   presence_subject;
    ngx_str_t                   config_hash;
    ngx_event_t                 presence;

    ngx_int_t                 (*init_worker)(ngx_http_waf_bus_t *bus,
                                    ngx_cycle_t *cycle);
    void                      (*exit_worker)(ngx_http_waf_bus_t *bus,
                                    ngx_cycle_t *cycle);

    ngx_int_t                 (*publish)(ngx_http_waf_bus_t *bus,
                                    ngx_http_waf_bus_msg_t *msg,
                                    ngx_uint_t *status);

    ngx_int_t                 (*publish_audit)(ngx_http_waf_bus_t *bus,
                                    ngx_str_t *subject, ngx_str_t *payload);

    ngx_int_t                 (*request)(ngx_http_waf_bus_t *bus,
                                    ngx_str_t *subject, ngx_str_t *reply_suffix,
                                    ngx_str_t *payload);

    ngx_int_t                 (*connected)(ngx_http_waf_bus_t *bus);
};


#define NGX_HTTP_WAF_BUS_TOKEN_V   "v"
#define NGX_HTTP_WAF_BUS_TOKEN_JS  "js"


ngx_int_t  ngx_http_waf_bus_publish_wave(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_slot_t *slot);

void       ngx_http_waf_bus_dispatch(ngx_http_waf_bus_t *bus, uint64_t rid,
               ngx_uint_t inspector, ngx_str_t *payload);

void       ngx_http_waf_bus_absent(ngx_http_waf_bus_t *bus, uint64_t rid,
               ngx_uint_t inspector);

ngx_int_t  ngx_http_waf_bus_inbox_build(ngx_http_waf_bus_t *bus,
               ngx_cycle_t *cycle, ngx_str_t *node_id);

ngx_int_t  ngx_http_waf_presence_init(ngx_http_waf_bus_t *bus,
               ngx_cycle_t *cycle);
void       ngx_http_waf_presence_stop(ngx_http_waf_bus_t *bus);

ngx_http_waf_bus_t  *ngx_http_waf_bus_current(void);

void       ngx_http_waf_bus_ready(void);
void       ngx_http_waf_bus_lost(void);

void       ngx_http_waf_bus_dataset(ngx_uint_t index, ngx_str_t *payload);
void       ngx_http_waf_bus_js_reply(ngx_uint_t index, ngx_str_t *payload);


ngx_http_waf_bus_t  *ngx_http_waf_bus_nats_create(ngx_conf_t *cf);


#endif
