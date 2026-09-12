/*
 * Разбор проводного протокола NATS (bus/ngx_http_waf_bus_nats.c). Файл
 * включён целиком, чтобы достать статический ngx_http_waf_nats_parse();
 * доставка вердиктов и наборов заменена заглушками через --wrap: харнесс
 * проверяет разбор, а не машину состояний за ним.
 *
 * Вход подаётся двумя кусками, как его отдаёт сокет: разбор обязан одинаково
 * жить с границей сообщения в любом месте.
 */

#include "common.h"

#include "bus/ngx_http_waf_bus_nats.c"


void
__wrap_ngx_http_waf_bus_dispatch(ngx_http_waf_bus_t *bus, uint64_t rid,
    ngx_uint_t inspector, ngx_str_t *payload)
{
    volatile u_char  sink = 0;
    size_t           i;

    for (i = 0; i < payload->len; i++) {
        sink ^= payload->data[i];
    }

    (void) sink;
}


void
__wrap_ngx_http_waf_bus_absent(uint64_t rid, ngx_uint_t inspector,
    ngx_uint_t status)
{
}


void
__wrap_ngx_http_waf_bus_dataset(ngx_uint_t index, ngx_str_t *payload)
{
    volatile u_char  sink = 0;
    size_t           i;

    for (i = 0; i < payload->len; i++) {
        sink ^= payload->data[i];
    }

    (void) sink;
}


void
__wrap_ngx_http_waf_bus_js_reply(ngx_uint_t index, ngx_str_t *payload)
{
    __wrap_ngx_http_waf_bus_dataset(index, payload);
}


void
__wrap_ngx_http_waf_bus_ready(void)
{
}


void
__wrap_ngx_http_waf_bus_lost(void)
{
}


static ngx_http_waf_main_conf_t  wmcf;
static ngx_http_waf_bus_t        bus;
static ngx_http_waf_link_conf_t  lc;
static ngx_http_waf_nats_t       nats;
static u_char                    hello[] = "CONNECT {\"verbose\":false}\r\n";


static void
nats_reset(void)
{
    nats.state        = NGX_HTTP_WAF_NATS_ST_LINE;
    nats.pings        = 0;
    nats.skip         = 0;
    nats.big_len      = 0;
    nats.msg_collect  = 0;
    nats.msg_valid    = 0;
    nats.msg_hdr      = 0;
    nats.msg_total    = 0;
    nats.link.in_pos  = 0;
    nats.link.in_last = 0;
    nats.link.out_pos  = 0;
    nats.link.out_last = 0;
    nats.link.ready   = 0;

    if (nats.ping.timer_set) {
        ngx_del_timer(&nats.ping);
    }
}


static void
mock_init(void)
{
    static int  ready;

    if (ready) {
        return;
    }

    ready = 1;

    wmcf.reply_max         = 8192;
    wmcf.bus_pending_max   = 1024 * 1024;
    wmcf.bus_ping_interval = 10000;
    ngx_str_set(&wmcf.node_id, "fuzz");

    ngx_str_set(&bus.name, "nats");

    lc.name    = "bus";
    lc.out_max = wmcf.bus_pending_max;

    nats.bus  = &bus;
    nats.wmcf = &wmcf;
    nats.log  = &waf_fuzz_log;

    nats.hello.data = hello;
    nats.hello.len  = sizeof(hello) - 1;

    nats.ping.handler = ngx_http_waf_nats_on_ping;
    nats.ping.data    = &nats;
    nats.ping.log     = &waf_fuzz_log;

    nats.link.conf     = &lc;
    nats.link.data     = &nats;
    nats.link.log      = &waf_fuzz_log;
    nats.link.in_size  = wmcf.reply_max + NGX_HTTP_WAF_NATS_IN_SLACK;
    nats.link.in       = ngx_alloc(nats.link.in_size, &waf_fuzz_log);
    nats.link.out_size = 64 * 1024;
    nats.link.out      = ngx_alloc(nats.link.out_size, &waf_fuzz_log);
}


/* Как read_handler: дописать кусок, разобрать; NGX_ERROR -- соединение упало. */
static ngx_int_t
feed(const uint8_t *data, size_t len)
{
    size_t  chunk;

    while (len != 0) {

        if (nats.link.in_last == nats.link.in_size) {

            if (nats.link.in_pos == 0) {
                return NGX_ERROR;      /* сообщение больше буфера */
            }

            ngx_memmove(nats.link.in, nats.link.in + nats.link.in_pos,
                        nats.link.in_last - nats.link.in_pos);

            nats.link.in_last -= nats.link.in_pos;
            nats.link.in_pos   = 0;
        }

        chunk = ngx_min(len, nats.link.in_size - nats.link.in_last);

        ngx_memcpy(nats.link.in + nats.link.in_last, data, chunk);
        nats.link.in_last += chunk;

        data += chunk;
        len  -= chunk;

        if (ngx_http_waf_nats_parse(&nats) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t  half;

    waf_fuzz_init();
    mock_init();

    nats_reset();

    if (size == 0) {
        return 0;
    }

    half = size / 2;

    if (feed(data, half) == NGX_OK) {
        (void) feed(data + half, size - half);
    }

    nats_reset();

    return 0;
}
