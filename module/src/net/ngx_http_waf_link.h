#ifndef _NGX_HTTP_WAF_LINK_H_INCLUDED_
#define _NGX_HTTP_WAF_LINK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct ngx_http_waf_link_s  ngx_http_waf_link_t;


typedef struct {
    const char                *name;

    ngx_array_t               *servers;
    ngx_msec_t                 connect_timeout;
    ngx_msec_t                 reconnect_wait;

    size_t                     in_size;
    size_t                     out_initial;
    size_t                     out_max;

    ngx_int_t                (*on_connected)(ngx_http_waf_link_t *link);

    ngx_int_t                (*on_read)(ngx_http_waf_link_t *link);

    void                     (*on_close)(ngx_http_waf_link_t *link,
                                 ngx_uint_t was_ready);
} ngx_http_waf_link_conf_t;


struct ngx_http_waf_link_s {
    ngx_http_waf_link_conf_t  *conf;
    void                      *data;
    ngx_log_t                 *log;

    ngx_peer_connection_t      peer;
    ngx_uint_t                 next_server;

    u_char                    *in;
    size_t                     in_size;
    size_t                     in_pos;
    size_t                     in_last;

    u_char                    *out;
    size_t                     out_size;
    size_t                     out_pos;
    size_t                     out_last;

    ngx_event_t                reconnect;

    ngx_log_t                  quiet;
    ngx_uint_t                 failures;

    unsigned                   ready:1;
    unsigned                   connecting:1;
    unsigned                   up:1;
};


#define ngx_http_waf_link_level(link, level)                                  \
    ((link)->failures != 0 ? NGX_LOG_INFO : (level))


ngx_int_t  ngx_http_waf_link_init(ngx_http_waf_link_t *link,
               ngx_http_waf_link_conf_t *conf, ngx_cycle_t *cycle, void *data);

void       ngx_http_waf_link_connect(ngx_http_waf_link_t *link);

void       ngx_http_waf_link_drop(ngx_http_waf_link_t *link);

void       ngx_http_waf_link_up(ngx_http_waf_link_t *link);

void       ngx_http_waf_link_stop(ngx_http_waf_link_t *link);

ngx_int_t  ngx_http_waf_link_reserve(ngx_http_waf_link_t *link, size_t len);
ngx_int_t  ngx_http_waf_link_out(ngx_http_waf_link_t *link, const u_char *data,
               size_t len);
void       ngx_http_waf_link_flush(ngx_http_waf_link_t *link);


#endif
