#include "net/ngx_http_waf_link.h"


static void  ngx_http_waf_link_close(ngx_http_waf_link_t *link);
static void  ngx_http_waf_link_reschedule(ngx_http_waf_link_t *link);
static void  ngx_http_waf_link_on_reconnect(ngx_event_t *ev);
static void  ngx_http_waf_link_read_handler(ngx_event_t *rev);
static void  ngx_http_waf_link_write_handler(ngx_event_t *wev);


ngx_int_t
ngx_http_waf_link_init(ngx_http_waf_link_t *link,
    ngx_http_waf_link_conf_t *conf, ngx_cycle_t *cycle, void *data)
{
    link->conf = conf;
    link->data = data;
    link->log  = cycle->log;

    link->in_size = conf->in_size;

    link->in = ngx_palloc(cycle->pool, link->in_size);
    if (link->in == NULL) {
        return NGX_ERROR;
    }

    link->out_size = conf->out_initial;

    if (link->out_size > conf->out_max) {
        link->out_size = conf->out_max;
    }

    link->out = ngx_palloc(cycle->pool, link->out_size);
    if (link->out == NULL) {
        return NGX_ERROR;
    }

    link->reconnect.handler = ngx_http_waf_link_on_reconnect;
    link->reconnect.data    = link;
    link->reconnect.log     = cycle->log;

    link->reconnect.cancelable = 1;

    return NGX_OK;
}


void
ngx_http_waf_link_connect(ngx_http_waf_link_t *link)
{
    ngx_int_t                  rc;
    ngx_addr_t                *addrs;
    ngx_connection_t          *c;
    ngx_http_waf_link_conf_t  *conf = link->conf;

    if (conf->servers == NULL || conf->servers->nelts == 0) {
        return;
    }

    if (link->peer.connection != NULL) {
        return;
    }

    addrs = conf->servers->elts;

    if (link->next_server >= conf->servers->nelts) {
        link->next_server = 0;
    }

    ngx_memzero(&link->peer, sizeof(ngx_peer_connection_t));

    link->peer.sockaddr  = addrs[link->next_server].sockaddr;
    link->peer.socklen   = addrs[link->next_server].socklen;
    link->peer.name      = &addrs[link->next_server].name;
    link->peer.get       = ngx_event_get_peer;
    link->peer.log       = link->log;
    link->peer.log_error = NGX_ERROR_ERR;

    link->next_server++;

    rc = ngx_event_connect_peer(&link->peer);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, link->log, 0,
                      "waf: %s connect to \"%V\" failed",
                      conf->name, link->peer.name);

        link->peer.connection = NULL;
        ngx_http_waf_link_reschedule(link);
        return;
    }

    c = link->peer.connection;

    c->data           = link;
    c->read->handler  = ngx_http_waf_link_read_handler;
    c->write->handler = ngx_http_waf_link_write_handler;

    link->in_pos     = 0;
    link->in_last    = 0;
    link->out_pos    = 0;
    link->out_last   = 0;
    link->ready      = 0;
    link->connecting = 1;

    ngx_add_timer(c->write, conf->connect_timeout);

    if (rc == NGX_OK) {
        ngx_http_waf_link_write_handler(c->write);
    }
}


static void
ngx_http_waf_link_close(ngx_http_waf_link_t *link)
{
    ngx_uint_t         was_ready;
    ngx_connection_t  *c = link->peer.connection;

    was_ready   = link->ready;
    link->ready = 0;

    if (link->conf->on_close) {
        link->conf->on_close(link, was_ready);
    }

    if (c != NULL) {
        ngx_close_connection(c);
        link->peer.connection = NULL;
    }

    link->connecting = 0;
}


static void
ngx_http_waf_link_reschedule(ngx_http_waf_link_t *link)
{
    if (link->reconnect.timer_set) {
        return;
    }

    ngx_add_timer(&link->reconnect, link->conf->reconnect_wait);
}


void
ngx_http_waf_link_drop(ngx_http_waf_link_t *link)
{
    ngx_http_waf_link_close(link);
    ngx_http_waf_link_reschedule(link);
}


void
ngx_http_waf_link_stop(ngx_http_waf_link_t *link)
{
    if (link->reconnect.timer_set) {
        ngx_del_timer(&link->reconnect);
    }

    ngx_http_waf_link_close(link);
}


static void
ngx_http_waf_link_on_reconnect(ngx_event_t *ev)
{
    ngx_http_waf_link_connect(ev->data);
}


static void
ngx_http_waf_link_write_handler(ngx_event_t *wev)
{
    ngx_connection_t          *c = wev->data;
    ngx_http_waf_link_t       *link = c->data;
    ngx_http_waf_link_conf_t  *conf = link->conf;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, link->log, 0,
                      "waf: %s connect to \"%V\" timed out",
                      conf->name, link->peer.name);

        wev->timedout = 0;

        ngx_http_waf_link_drop(link);
        return;
    }

    if (link->connecting) {

        if (ngx_tcp_nodelay(c) != NGX_OK) {
            ngx_http_waf_link_drop(link);
            return;
        }

        link->connecting = 0;

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        ngx_log_error(NGX_LOG_NOTICE, link->log, 0,
                      "waf: %s connected to \"%V\"", conf->name,
                      link->peer.name);

        if (conf->on_connected && conf->on_connected(link) != NGX_OK) {
            ngx_http_waf_link_drop(link);
            return;
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_waf_link_drop(link);
            return;
        }
    }

    ngx_http_waf_link_flush(link);
}


static void
ngx_http_waf_link_read_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_connection_t          *c = rev->data;
    ngx_http_waf_link_t       *link = c->data;
    ngx_http_waf_link_conf_t  *conf = link->conf;

    for ( ;; ) {

        if (link->in_last == link->in_size) {

            if (link->in_pos == 0) {
                ngx_log_error(NGX_LOG_ERR, link->log, 0,
                              "waf: %s message exceeds the %uz byte input "
                              "buffer", conf->name, link->in_size);

                ngx_http_waf_link_drop(link);
                return;
            }

            ngx_memmove(link->in, link->in + link->in_pos,
                        link->in_last - link->in_pos);

            link->in_last -= link->in_pos;
            link->in_pos   = 0;
        }

        n = c->recv(c, link->in + link->in_last, link->in_size - link->in_last);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, link->log, 0,
                          "waf: %s closed the connection", conf->name);

            ngx_http_waf_link_drop(link);
            return;
        }

        if (n == NGX_ERROR) {
            ngx_http_waf_link_drop(link);
            return;
        }

        link->in_last += (size_t) n;

        if (conf->on_read(link) != NGX_OK) {
            ngx_http_waf_link_drop(link);
            return;
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_waf_link_drop(link);
    }
}


ngx_int_t
ngx_http_waf_link_reserve(ngx_http_waf_link_t *link, size_t len)
{
    u_char  *buf;
    size_t   size, limit;

    if (link->out_pos == link->out_last) {
        link->out_pos  = 0;
        link->out_last = 0;
    }

    if (link->out_size - link->out_last >= len) {
        return NGX_OK;
    }

    if (link->out_pos != 0) {
        ngx_memmove(link->out, link->out + link->out_pos,
                    link->out_last - link->out_pos);

        link->out_last -= link->out_pos;
        link->out_pos   = 0;

        if (link->out_size - link->out_last >= len) {
            return NGX_OK;
        }
    }

    limit = link->conf->out_max;
    size  = link->out_size;

    while (size - link->out_last < len) {

        if (size >= limit) {
            ngx_log_error(NGX_LOG_ERR, link->log, 0,
                          "waf: %s output buffer exhausted at %uz bytes",
                          link->conf->name, size);
            return NGX_ERROR;
        }

        size *= 2;

        if (size > limit) {
            size = limit;
        }
    }

    buf = ngx_palloc(ngx_cycle->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(buf, link->out, link->out_last);

    link->out      = buf;
    link->out_size = size;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_link_out(ngx_http_waf_link_t *link, const u_char *data,
    size_t len)
{
    if (ngx_http_waf_link_reserve(link, len) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memcpy(link->out + link->out_last, data, len);
    link->out_last += len;

    return NGX_OK;
}


void
ngx_http_waf_link_flush(ngx_http_waf_link_t *link)
{
    ssize_t            n;
    ngx_connection_t  *c = link->peer.connection;

    if (c == NULL || link->connecting) {
        return;
    }

    while (link->out_pos < link->out_last) {

        n = c->send(c, link->out + link->out_pos,
                    (ssize_t) (link->out_last - link->out_pos));

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            ngx_http_waf_link_drop(link);
            return;
        }

        link->out_pos += (size_t) n;
    }

    if (link->out_pos == link->out_last) {
        link->out_pos  = 0;
        link->out_last = 0;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_http_waf_link_drop(link);
    }
}
