#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "net/ngx_http_waf_link.h"

#include <ngx_event_connect.h>


#define NGX_HTTP_WAF_NATS_SID_V        "1"
#define NGX_HTTP_WAF_NATS_SID_JS       "2"
#define NGX_HTTP_WAF_NATS_SID_DS       "d"

#define NGX_HTTP_WAF_NATS_MAX_PING     2
#define NGX_HTTP_WAF_NATS_IN_SLACK     4096
#define NGX_HTTP_WAF_NATS_OUT_INITIAL  (32 * 1024)
#define NGX_HTTP_WAF_NATS_LINE_MAX     4096


typedef enum {
    NGX_HTTP_WAF_NATS_ST_LINE = 0,
    NGX_HTTP_WAF_NATS_ST_PAYLOAD
} ngx_http_waf_nats_state_e;


typedef enum {
    NGX_HTTP_WAF_NATS_KIND_VERDICT = 0,
    NGX_HTTP_WAF_NATS_KIND_DATASET,
    NGX_HTTP_WAF_NATS_KIND_JS_REPLY
} ngx_http_waf_nats_kind_e;


typedef struct {
    ngx_http_waf_link_t        link;

    ngx_http_waf_bus_t        *bus;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_log_t                 *log;

    ngx_str_t                  hello;

    ngx_event_t                ping;

    ngx_uint_t                 state;
    ngx_uint_t                 pings;

    u_char                    *big;
    size_t                     big_size;
    size_t                     big_len;
    size_t                     skip;

    uint64_t                   msg_rid;
    ngx_uint_t                 msg_index;
    ngx_uint_t                 msg_kind;
    size_t                     msg_hdr;
    size_t                     msg_total;
    unsigned                   msg_valid:1;
    unsigned                   msg_collect:1;
} ngx_http_waf_nats_t;


static ngx_int_t ngx_http_waf_nats_init_worker(ngx_http_waf_bus_t *bus,
    ngx_cycle_t *cycle);
static void      ngx_http_waf_nats_exit_worker(ngx_http_waf_bus_t *bus,
    ngx_cycle_t *cycle);
static ngx_int_t ngx_http_waf_nats_publish(ngx_http_waf_bus_t *bus,
    ngx_http_waf_bus_msg_t *msg, ngx_uint_t *status);
static ngx_int_t ngx_http_waf_nats_publish_audit(ngx_http_waf_bus_t *bus,
    ngx_str_t *subject, ngx_str_t *payload);
static ngx_int_t ngx_http_waf_nats_request(ngx_http_waf_bus_t *bus,
    ngx_str_t *subject, ngx_str_t *reply_suffix, ngx_str_t *payload);
static ngx_int_t ngx_http_waf_nats_connected(ngx_http_waf_bus_t *bus);

static ngx_int_t ngx_http_waf_nats_on_connected(ngx_http_waf_link_t *link);
static ngx_int_t ngx_http_waf_nats_on_read(ngx_http_waf_link_t *link);
static void      ngx_http_waf_nats_on_close(ngx_http_waf_link_t *link,
    ngx_uint_t was_ready);
static void      ngx_http_waf_nats_on_ping(ngx_event_t *ev);

static ngx_int_t ngx_http_waf_nats_parse(ngx_http_waf_nats_t *nats);
static ngx_int_t ngx_http_waf_nats_line(ngx_http_waf_nats_t *nats, u_char *line,
    size_t len);
static ngx_int_t ngx_http_waf_nats_msg_line(ngx_http_waf_nats_t *nats,
    u_char *line, size_t len, ngx_uint_t with_headers);
static ngx_int_t ngx_http_waf_nats_route(ngx_http_waf_nats_t *nats, u_char *sid,
    size_t sidlen, u_char *subject, size_t slen);
static ngx_int_t ngx_http_waf_nats_collect(ngx_http_waf_nats_t *nats,
    size_t need);
static void      ngx_http_waf_nats_deliver(ngx_http_waf_nats_t *nats,
    u_char *msg, size_t len);
static ngx_int_t ngx_http_waf_nats_handshake(ngx_http_waf_nats_t *nats);
static ngx_int_t ngx_http_waf_nats_hello_build(ngx_http_waf_nats_t *nats,
    ngx_cycle_t *cycle);
static ngx_int_t ngx_http_waf_nats_pub(ngx_http_waf_nats_t *nats,
    ngx_str_t *subject, ngx_str_t *reply, ngx_str_t *payload);

static u_char   *ngx_http_waf_nats_token(u_char **pos, u_char *last,
    size_t *len);


ngx_http_waf_bus_t *
ngx_http_waf_bus_nats_create(ngx_conf_t *cf)
{
    ngx_http_waf_bus_t  *bus;

    bus = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_bus_t));
    if (bus == NULL) {
        return NULL;
    }

    ngx_str_set(&bus->name, "nats");

    bus->init_worker   = ngx_http_waf_nats_init_worker;
    bus->exit_worker   = ngx_http_waf_nats_exit_worker;
    bus->publish       = ngx_http_waf_nats_publish;
    bus->publish_audit = ngx_http_waf_nats_publish_audit;
    bus->request       = ngx_http_waf_nats_request;
    bus->connected     = ngx_http_waf_nats_connected;

    return bus;
}


static ngx_int_t
ngx_http_waf_nats_init_worker(ngx_http_waf_bus_t *bus, ngx_cycle_t *cycle)
{
    ngx_http_waf_nats_t       *nats;
    ngx_http_waf_link_conf_t  *lc;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    nats = ngx_pcalloc(cycle->pool, sizeof(ngx_http_waf_nats_t));
    if (nats == NULL) {
        return NGX_ERROR;
    }

    nats->bus  = bus;
    nats->wmcf = wmcf;
    nats->log  = cycle->log;

    lc = ngx_pcalloc(cycle->pool, sizeof(ngx_http_waf_link_conf_t));
    if (lc == NULL) {
        return NGX_ERROR;
    }

    lc->name            = "bus";
    lc->servers         = wmcf->bus_servers;
    lc->connect_timeout = wmcf->bus_connect_timeout;
    lc->reconnect_wait  = wmcf->bus_reconnect_wait;

    lc->in_size      = wmcf->reply_max + NGX_HTTP_WAF_NATS_IN_SLACK;
    lc->out_initial  = NGX_HTTP_WAF_NATS_OUT_INITIAL;
    lc->out_max      = wmcf->bus_pending_max;
    lc->on_connected = ngx_http_waf_nats_on_connected;
    lc->on_read      = ngx_http_waf_nats_on_read;
    lc->on_close     = ngx_http_waf_nats_on_close;

    if (ngx_http_waf_link_init(&nats->link, lc, cycle, nats) != NGX_OK) {
        return NGX_ERROR;
    }

    nats->ping.handler = ngx_http_waf_nats_on_ping;
    nats->ping.data    = nats;
    nats->ping.log     = cycle->log;

    nats->ping.cancelable = 1;

    bus->data = nats;
    bus->log  = cycle->log;

    if (ngx_http_waf_nats_hello_build(nats, cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_waf_link_connect(&nats->link);

    return NGX_OK;
}


static void
ngx_http_waf_nats_exit_worker(ngx_http_waf_bus_t *bus, ngx_cycle_t *cycle)
{
    ngx_http_waf_nats_t  *nats = bus->data;

    if (nats == NULL) {
        return;
    }

    ngx_http_waf_link_stop(&nats->link);
}


static ngx_int_t
ngx_http_waf_nats_on_connected(ngx_http_waf_link_t *link)
{
    ngx_http_waf_nats_t  *nats = link->data;

    nats->state = NGX_HTTP_WAF_NATS_ST_LINE;
    nats->pings = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_on_read(ngx_http_waf_link_t *link)
{
    return ngx_http_waf_nats_parse(link->data);
}


static void
ngx_http_waf_nats_on_close(ngx_http_waf_link_t *link, ngx_uint_t was_ready)
{
    ngx_http_waf_nats_t  *nats = link->data;

    if (nats->ping.timer_set) {
        ngx_del_timer(&nats->ping);
    }

    if (was_ready) {
        ngx_http_waf_bus_lost();
    }

    nats->msg_collect = 0;
    nats->big_len     = 0;
    nats->skip        = 0;
}


static void
ngx_http_waf_nats_on_ping(ngx_event_t *ev)
{
    ngx_http_waf_nats_t  *nats = ev->data;

    if (!nats->link.ready) {
        return;
    }

    if (nats->pings >= NGX_HTTP_WAF_NATS_MAX_PING) {
        ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                      "waf: bus is not answering pings, reconnecting");

        ngx_http_waf_link_drop(&nats->link);
        return;
    }

    nats->pings++;

    (void) ngx_http_waf_link_out(&nats->link, (u_char *) "PING\r\n", 6);
    ngx_http_waf_link_flush(&nats->link);

    ngx_add_timer(&nats->ping, nats->wmcf->bus_ping_interval);
}


static ngx_int_t
ngx_http_waf_nats_parse(ngx_http_waf_nats_t *nats)
{
    u_char  *start, *crlf;
    size_t   avail, take;

    for ( ;; ) {
        start = nats->link.in + nats->link.in_pos;
        avail = nats->link.in_last - nats->link.in_pos;

        if (avail == 0) {
            nats->link.in_pos  = 0;
            nats->link.in_last = 0;
            return NGX_OK;
        }

        if (nats->state == NGX_HTTP_WAF_NATS_ST_PAYLOAD) {

            if (nats->skip != 0) {
                take = ngx_min(avail, nats->skip);

                nats->link.in_pos += take;
                nats->skip   -= take;

                if (nats->skip != 0) {
                    return NGX_OK;
                }

                nats->state = NGX_HTTP_WAF_NATS_ST_LINE;
                continue;
            }

            if (nats->msg_collect) {
                take = ngx_min(avail, nats->msg_total + 2 - nats->big_len);

                ngx_memcpy(nats->big + nats->big_len, start, take);

                nats->big_len += take;
                nats->link.in_pos  += take;

                if (nats->big_len < nats->msg_total + 2) {
                    return NGX_OK;
                }

                ngx_http_waf_nats_deliver(nats, nats->big, nats->msg_total);

                nats->msg_collect = 0;
                nats->big_len     = 0;
                nats->state       = NGX_HTTP_WAF_NATS_ST_LINE;
                continue;
            }

            if (avail < nats->msg_total + 2) {
                return NGX_OK;
            }

            if (nats->msg_valid) {
                ngx_http_waf_nats_deliver(nats, start, nats->msg_total);
            }

            nats->link.in_pos += nats->msg_total + 2;
            nats->state   = NGX_HTTP_WAF_NATS_ST_LINE;
            continue;
        }

        crlf = ngx_strlchr(start, start + avail, LF);

        if (crlf == NULL) {
            return NGX_OK;
        }

        if (ngx_http_waf_nats_line(nats, start,
                                   (size_t) (crlf - start
                                             - (crlf > start
                                                && crlf[-1] == CR ? 1 : 0)))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        nats->link.in_pos = (size_t) (crlf - nats->link.in) + 1;
    }
}


static ngx_int_t
ngx_http_waf_nats_line(ngx_http_waf_nats_t *nats, u_char *line, size_t len)
{
    if (len >= 4 && ngx_strncmp(line, "MSG ", 4) == 0) {
        return ngx_http_waf_nats_msg_line(nats, line + 4, len - 4, 0);
    }

    if (len >= 5 && ngx_strncmp(line, "HMSG ", 5) == 0) {
        return ngx_http_waf_nats_msg_line(nats, line + 5, len - 5, 1);
    }

    if (len >= 4 && ngx_strncmp(line, "PING", 4) == 0) {
        (void) ngx_http_waf_link_out(&nats->link, (u_char *) "PONG\r\n", 6);
        ngx_http_waf_link_flush(&nats->link);
        return NGX_OK;
    }

    if (len >= 4 && ngx_strncmp(line, "PONG", 4) == 0) {
        nats->pings = 0;
        ngx_http_waf_link_up(&nats->link);
        return NGX_OK;
    }

    if (len >= 4 && ngx_strncmp(line, "INFO", 4) == 0) {

        if (nats->link.ready) {
            return NGX_OK;
        }

        return ngx_http_waf_nats_handshake(nats);
    }

    if (len >= 4 && ngx_strncmp(line, "-ERR", 4) == 0) {
        ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                      "waf: bus error: %*s", len, line);

        return NGX_ERROR;
    }

    if (len >= 3 && ngx_strncmp(line, "+OK", 3) == 0) {
        return NGX_OK;
    }

    if (len == 0) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                  "waf: unexpected bus protocol line \"%*s\"", len, line);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_waf_nats_msg_line(ngx_http_waf_nats_t *nats, u_char *line, size_t len,
    ngx_uint_t with_headers)
{
    u_char      *pos, *last, *tok, *subject;
    size_t       tlen, slen, ntokens;
    ngx_int_t    n, hdr;
    u_char      *tokens[5];
    size_t       lens[5];

    pos     = line;
    last    = line + len;
    ntokens = 0;

    while (ntokens < 5) {
        tok = ngx_http_waf_nats_token(&pos, last, &tlen);

        if (tok == NULL) {
            break;
        }

        tokens[ntokens] = tok;
        lens[ntokens]   = tlen;
        ntokens++;
    }

    if (ntokens < (size_t) (with_headers ? 4 : 3)) {
        ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                      "waf: malformed bus message header");
        return NGX_ERROR;
    }

    subject = tokens[0];
    slen    = lens[0];

    hdr = 0;

    if (with_headers) {
        n   = ngx_atoi(tokens[ntokens - 1], lens[ntokens - 1]);
        hdr = ngx_atoi(tokens[ntokens - 2], lens[ntokens - 2]);

        if (n == NGX_ERROR || hdr == NGX_ERROR || hdr > n) {
            ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                          "waf: malformed bus message length");
            return NGX_ERROR;
        }

    } else {
        n = ngx_atoi(tokens[ntokens - 1], lens[ntokens - 1]);

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                          "waf: malformed bus message length");
            return NGX_ERROR;
        }
    }

    nats->msg_total   = (size_t) n;
    nats->msg_hdr     = (size_t) hdr;
    nats->msg_valid   = 0;
    nats->msg_collect = 0;
    nats->skip        = 0;
    nats->state       = NGX_HTTP_WAF_NATS_ST_PAYLOAD;

    if (ngx_http_waf_nats_route(nats, tokens[1], lens[1], subject, slen)
        == NGX_OK)
    {
        nats->msg_valid = 1;
    }

    if (nats->msg_total + 2 <= nats->link.in_size) {
        return NGX_OK;
    }

    if (nats->msg_valid
        && nats->msg_kind == NGX_HTTP_WAF_NATS_KIND_DATASET
        && nats->msg_total <= nats->wmcf->bus_payload_max
        && ngx_http_waf_nats_collect(nats, nats->msg_total + 2) == NGX_OK)
    {
        nats->msg_collect = 1;
        nats->big_len     = 0;

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                  "waf: dropping a %uz byte bus message on \"%*s\"",
                  nats->msg_total, slen, subject);

    nats->msg_valid = 0;
    nats->skip      = nats->msg_total + 2;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_route(ngx_http_waf_nats_t *nats, u_char *sid, size_t sidlen,
    u_char *subject, size_t slen)
{
    u_char     *tail, *end;
    ngx_int_t   n;
    ngx_str_t   rid_hex;

    if (sidlen == 0) {
        return NGX_ERROR;
    }

    if (sid[0] == NGX_HTTP_WAF_NATS_SID_DS[0]) {

        n = ngx_atoi(sid + 1, sidlen - 1);

        if (n == NGX_ERROR || n >= NGX_HTTP_WAF_MAX_DATASETS) {
            return NGX_ERROR;
        }

        nats->msg_kind  = NGX_HTTP_WAF_NATS_KIND_DATASET;
        nats->msg_index = (ngx_uint_t) n;

        return NGX_OK;
    }

    end  = subject + slen;
    tail = end;

    while (tail > subject && *(tail - 1) != '.') {
        tail--;
    }

    if (tail == subject) {
        return NGX_ERROR;
    }

    if (sidlen == 1 && sid[0] == NGX_HTTP_WAF_NATS_SID_JS[0]) {

        n = ngx_atoi(tail, (size_t) (end - tail));

        if (n == NGX_ERROR || n >= NGX_HTTP_WAF_MAX_DATASETS) {
            return NGX_ERROR;
        }

        nats->msg_kind  = NGX_HTTP_WAF_NATS_KIND_JS_REPLY;
        nats->msg_index = (ngx_uint_t) n;

        return NGX_OK;
    }

    nats->msg_kind = NGX_HTTP_WAF_NATS_KIND_VERDICT;

    n = ngx_hextoi(tail, (size_t) (end - tail));

    if (n == NGX_ERROR || n >= NGX_HTTP_WAF_MAX_INSPECTORS) {
        return NGX_ERROR;
    }

    if ((size_t) (tail - 1 - subject) < NGX_HTTP_WAF_RID_HEX_LEN) {
        return NGX_ERROR;
    }

    rid_hex.data = tail - 1 - NGX_HTTP_WAF_RID_HEX_LEN;
    rid_hex.len  = NGX_HTTP_WAF_RID_HEX_LEN;

    if (ngx_http_waf_rid_parse(&rid_hex, &nats->msg_rid) != NGX_OK) {
        return NGX_ERROR;
    }

    nats->msg_index = (ngx_uint_t) n;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_collect(ngx_http_waf_nats_t *nats, size_t need)
{
    u_char  *buf;

    if (nats->big_size >= need) {
        return NGX_OK;
    }

    buf = ngx_palloc(ngx_cycle->pool, need);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    nats->big      = buf;
    nats->big_size = need;

    return NGX_OK;
}


static void
ngx_http_waf_nats_deliver(ngx_http_waf_nats_t *nats, u_char *msg, size_t len)
{
    ngx_str_t  payload;

    if (nats->msg_hdr != 0) {

        if (nats->msg_hdr > len) {
            return;
        }

        if (nats->msg_kind == NGX_HTTP_WAF_NATS_KIND_VERDICT
            && nats->msg_hdr >= 12
            && ngx_strncmp(msg, "NATS/1.0 503", 12) == 0)
        {
            ngx_http_waf_bus_absent(nats->bus, nats->msg_rid,
                                    nats->msg_index);
            return;
        }

        msg += nats->msg_hdr;
        len -= nats->msg_hdr;
    }

    payload.data = msg;
    payload.len  = len;

    switch (nats->msg_kind) {

    case NGX_HTTP_WAF_NATS_KIND_DATASET:
        ngx_http_waf_bus_dataset(nats->msg_index, &payload);
        return;

    case NGX_HTTP_WAF_NATS_KIND_JS_REPLY:
        ngx_http_waf_bus_js_reply(nats->msg_index, &payload);
        return;

    default:
        ngx_http_waf_bus_dispatch(nats->bus, nats->msg_rid, nats->msg_index,
                                  &payload);
    }
}


static ngx_int_t
ngx_http_waf_nats_hello_build(ngx_http_waf_nats_t *nats, ngx_cycle_t *cycle)
{
    u_char                    *p, *buf, *last;
    size_t                     size;
    ngx_uint_t                 i;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_main_conf_t  *wmcf = nats->wmcf;

    size = 256 + wmcf->bus_name.len + wmcf->bus_user.len + wmcf->bus_pass.len
           + wmcf->bus_token.len + 2 * nats->bus->inbox.len;

    if (wmcf->datasets != NULL) {
        ds = wmcf->datasets->elts;

        for (i = 0; i < wmcf->datasets->nelts; i++) {
            size += ds[i].subject.len + NGX_INT_T_LEN + 16;
        }
    }

    buf = ngx_pnalloc(cycle->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    last = buf + size;

    p = ngx_slprintf(buf, last,
                     "CONNECT {\"verbose\":false,\"pedantic\":false,"
                     "\"tls_required\":false,\"lang\":\"c\","
                     "\"version\":\"" NGINX_VERSION "\",\"protocol\":1,"
                     "\"headers\":true,\"no_responders\":true,\"name\":\"%V\"",
                     &wmcf->bus_name);

    if (wmcf->bus_user.len != 0) {
        p = ngx_slprintf(p, last, ",\"user\":\"%V\",\"pass\":\"%V\"",
                         &wmcf->bus_user, &wmcf->bus_pass);
    }

    if (wmcf->bus_token.len != 0) {
        p = ngx_slprintf(p, last, ",\"auth_token\":\"%V\"", &wmcf->bus_token);
    }

    p = ngx_slprintf(p, last,
                     "}\r\nSUB %V." NGX_HTTP_WAF_BUS_TOKEN_V ".> "
                     NGX_HTTP_WAF_NATS_SID_V
                     "\r\nSUB %V." NGX_HTTP_WAF_BUS_TOKEN_JS ".> "
                     NGX_HTTP_WAF_NATS_SID_JS "\r\n",
                     &nats->bus->inbox, &nats->bus->inbox);

    if (wmcf->datasets != NULL) {
        ds = wmcf->datasets->elts;

        for (i = 0; i < wmcf->datasets->nelts; i++) {

            if (ds[i].mode != NGX_HTTP_WAF_DS_MODE_ACTIVE) {
                continue;
            }

            p = ngx_slprintf(p, last,
                             "SUB %V " NGX_HTTP_WAF_NATS_SID_DS "%ui\r\n",
                             &ds[i].subject, i);
        }
    }

    p = ngx_slprintf(p, last, "PING\r\n");

    if (p == last) {
        return NGX_ERROR;
    }

    nats->hello.data = buf;
    nats->hello.len  = (size_t) (p - buf);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_handshake(ngx_http_waf_nats_t *nats)
{
    if (ngx_http_waf_link_out(&nats->link, nats->hello.data, nats->hello.len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    nats->link.ready = 1;
    nats->pings = 1;

    ngx_http_waf_link_flush(&nats->link);

    ngx_add_timer(&nats->ping, nats->wmcf->bus_ping_interval);

    ngx_http_waf_bus_ready();

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_publish(ngx_http_waf_bus_t *bus, ngx_http_waf_bus_msg_t *msg,
    ngx_uint_t *status)
{
    u_char                hex[NGX_HTTP_WAF_RID_HEX_LEN];
    u_char                buf[sizeof(NGX_HTTP_WAF_BUS_TOKEN_V ".") - 1
                              + NGX_HTTP_WAF_RID_HEX_LEN + 1 + NGX_INT_T_LEN];
    ngx_int_t             rc;
    ngx_str_t             reply;
    ngx_http_waf_nats_t  *nats = bus->data;

    *status = NGX_HTTP_WAF_BUS_OK;

    if (nats == NULL || !nats->link.ready) {
        *status = NGX_HTTP_WAF_BUS_UNAVAILABLE;
        return NGX_ERROR;
    }

    if (msg->payload.len > nats->wmcf->bus_payload_max) {
        *status = NGX_HTTP_WAF_BUS_TOO_LARGE;
        return NGX_ERROR;
    }

    ngx_http_waf_rid_hex(msg->rid, hex);

    reply.data = buf;
    reply.len  = (size_t) (ngx_sprintf(buf, NGX_HTTP_WAF_BUS_TOKEN_V ".%*s.%02xi",
                                       (size_t) NGX_HTTP_WAF_RID_HEX_LEN, hex,
                                       msg->inspector)
                           - buf);

    rc = ngx_http_waf_nats_pub(nats, &msg->subject, &reply, &msg->payload);

    if (rc != NGX_OK) {
        *status = (rc == NGX_DECLINED) ? NGX_HTTP_WAF_BUS_TOO_LARGE
                                       : NGX_HTTP_WAF_BUS_OVERFLOW;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_publish_audit(ngx_http_waf_bus_t *bus, ngx_str_t *subject,
    ngx_str_t *payload)
{
    ngx_http_waf_nats_t  *nats = bus->data;

    if (nats == NULL || !nats->link.ready) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_nats_pub(nats, subject, NULL, payload) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_request(ngx_http_waf_bus_t *bus, ngx_str_t *subject,
    ngx_str_t *reply_suffix, ngx_str_t *payload)
{
    ngx_http_waf_nats_t  *nats = bus->data;

    if (nats == NULL || !nats->link.ready) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_nats_pub(nats, subject, reply_suffix, payload)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_pub(ngx_http_waf_nats_t *nats, ngx_str_t *subject,
    ngx_str_t *reply, ngx_str_t *payload)
{
    u_char               *p, *last;
    size_t                len;
    ngx_http_waf_link_t  *link = &nats->link;

    len = sizeof("PUB  \r\n") - 1 + subject->len + NGX_SIZE_T_LEN;

    if (reply != NULL) {
        len += sizeof(" .") - 1 + nats->bus->inbox.len + reply->len;
    }

    if (len > NGX_HTTP_WAF_NATS_LINE_MAX) {
        ngx_log_error(NGX_LOG_ERR, nats->log, 0,
                      "waf: bus subject \"%*s\" is too long to publish",
                      ngx_min(subject->len, 128), subject->data);
        return NGX_DECLINED;
    }

    if (ngx_http_waf_link_reserve(link, len + payload->len + 2) != NGX_OK) {
        return NGX_ERROR;
    }

    p    = link->out + link->out_last;
    last = p + len;

    if (reply != NULL) {
        p = ngx_slprintf(p, last, "PUB %V %V.%V %uz\r\n", subject,
                         &nats->bus->inbox, reply, payload->len);

    } else {
        p = ngx_slprintf(p, last, "PUB %V %uz\r\n", subject, payload->len);
    }

    if (payload->len != 0) {
        p = ngx_cpymem(p, payload->data, payload->len);
    }

    *p++ = CR;
    *p++ = LF;

    link->out_last = (size_t) (p - link->out);

    ngx_http_waf_link_flush(link);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_nats_connected(ngx_http_waf_bus_t *bus)
{
    ngx_http_waf_nats_t  *nats = bus->data;

    return nats != NULL && nats->link.ready;
}


static u_char *
ngx_http_waf_nats_token(u_char **pos, u_char *last, size_t *len)
{
    u_char  *start;

    while (*pos < last && (**pos == ' ' || **pos == '\t')) {
        (*pos)++;
    }

    if (*pos == last) {
        return NULL;
    }

    start = *pos;

    while (*pos < last && **pos != ' ' && **pos != '\t') {
        (*pos)++;
    }

    *len = (size_t) (*pos - start);

    return start;
}
