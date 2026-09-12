/*
 * Разбор ответов Redis (body/drv_redis.c, RESP2). Файл включён целиком ради
 * статического ngx_http_waf_redis_parse(). Перед каждым входом в конвейер
 * ставятся четыре записи: две выбрасываемые (hello/DEL), одна с операцией
 * (SET) и одна bulk (GET) -- так ответы с провода попадают во все ветки
 * завершения, включая сборку bulk и переполнение.
 */

#include "common.h"

#include "body/drv_redis.c"


static ngx_http_waf_redis_conf_t  rcf;
static ngx_http_waf_redis_conn_t  conn;
static ngx_http_waf_link_conf_t   lc;
static ngx_uint_t                 handled;


static void
op_handler(ngx_http_waf_body_op_t *op)
{
    handled++;
}


static void
mock_init(void)
{
    static int  ready;

    if (ready) {
        return;
    }

    ready = 1;

    rcf.log             = &waf_fuzz_log;
    rcf.max             = 1024 * 1024;
    rcf.op_timeout      = 1000;
    rcf.get_timeout     = 1000;
    rcf.connect_timeout = 1000;
    rcf.reconnect_wait  = 100;

    lc.name    = "redis";
    lc.out_max = (size_t) rcf.max + NGX_HTTP_WAF_REDIS_OUT_SLACK;

    conn.conf          = &rcf;
    conn.link.conf     = &lc;
    conn.link.data     = &conn;
    conn.link.log      = &waf_fuzz_log;
    conn.link.in_size  = NGX_HTTP_WAF_REDIS_IN_SIZE;
    conn.link.in       = ngx_alloc(conn.link.in_size, &waf_fuzz_log);
    conn.link.out_size = 16 * 1024;
    conn.link.out      = ngx_alloc(conn.link.out_size, &waf_fuzz_log);
}


static void
pipeline(ngx_pool_t *pool, ngx_http_waf_body_op_t *ops)
{
    ngx_uint_t                   i;
    ngx_http_waf_redis_entry_t  *entry;

    for (i = 0; i < 4; i++) {
        entry = ngx_http_waf_redis_entry_get(&conn);
        if (entry == NULL) {
            return;
        }

        if (i >= 2) {
            ngx_memzero(&ops[i], sizeof(ngx_http_waf_body_op_t));
            ops[i].pool    = pool;
            ops[i].log     = &waf_fuzz_log;
            ops[i].handler = op_handler;
            ops[i].len     = 4096;

            entry->op   = &ops[i];
            entry->bulk = (i == 3);
        }

        ngx_http_waf_redis_entry_push(&conn, entry);
    }
}


static ngx_int_t
feed(const uint8_t *data, size_t len)
{
    size_t  chunk;

    while (len != 0) {

        if (conn.link.in_last == conn.link.in_size) {

            if (conn.link.in_pos == 0) {
                return NGX_ERROR;
            }

            ngx_memmove(conn.link.in, conn.link.in + conn.link.in_pos,
                        conn.link.in_last - conn.link.in_pos);

            conn.link.in_last -= conn.link.in_pos;
            conn.link.in_pos   = 0;
        }

        chunk = ngx_min(len, conn.link.in_size - conn.link.in_last);

        ngx_memcpy(conn.link.in + conn.link.in_last, data, chunk);
        conn.link.in_last += chunk;

        data += chunk;
        len  -= chunk;

        if (ngx_http_waf_redis_parse(&conn) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t                   half;
    ngx_pool_t              *pool;
    ngx_http_waf_body_op_t   ops[4];

    waf_fuzz_init();
    mock_init();

    pool = waf_fuzz_pool();
    if (pool == NULL) {
        return 0;
    }

    conn.link.in_pos  = 0;
    conn.link.in_last = 0;

    pipeline(pool, ops);

    half = size / 2;

    if (feed(data, half) == NGX_OK) {
        (void) feed(data + half, size - half);
    }

    /* как при потере соединения: конвейер и сборка bulk обнуляются */
    ngx_http_waf_redis_drain(&conn);

    ngx_destroy_pool(pool);

    return 0;
}
