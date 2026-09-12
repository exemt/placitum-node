/*
 * Разборщик JSON (codec/ngx_http_waf_json.c): обход произвольного документа
 * всеми примитивами API плюс пропуск целиком.
 */

#include "common.h"


static void
walk(ngx_http_waf_jp_t *jp, ngx_uint_t depth)
{
    u_char      c, buf[64];
    ngx_int_t   rc, n;
    ngx_str_t   key, s;
    ngx_uint_t  b;

    if (depth > 24) {
        (void) ngx_http_waf_jp_skip(jp);
        return;
    }

    /* пробелы парсер пропускает сам; смотрим первый значащий байт */
    while (jp->pos < jp->end
           && (*jp->pos == ' ' || *jp->pos == '\t' || *jp->pos == '\r'
               || *jp->pos == '\n'))
    {
        jp->pos++;
    }

    if (jp->pos >= jp->end) {
        return;
    }

    c = *jp->pos;

    switch (c) {

    case '{':
        if (ngx_http_waf_jp_object(jp) != NGX_OK) {
            return;
        }

        for ( ;; ) {
            rc = ngx_http_waf_jp_member(jp, &key);

            if (rc != NGX_OK) {
                return;
            }

            walk(jp, depth + 1);
        }

    case '[':
        if (ngx_http_waf_jp_array(jp) != NGX_OK) {
            return;
        }

        for ( ;; ) {
            rc = ngx_http_waf_jp_element(jp);

            if (rc != NGX_OK) {
                return;
            }

            walk(jp, depth + 1);
        }

    case '"':
        if (depth & 1) {
            (void) ngx_http_waf_jp_string_buf(jp, buf, sizeof(buf), &s);

        } else {
            (void) ngx_http_waf_jp_string(jp, &s);
        }
        return;

    case 't':
    case 'f':
        (void) ngx_http_waf_jp_bool(jp, &b);
        return;

    case 'n':
        if (!ngx_http_waf_jp_null(jp)) {
            (void) ngx_http_waf_jp_skip(jp);
        }
        return;

    default:
        if (c == '-' || (c >= '0' && c <= '9')) {
            (void) ngx_http_waf_jp_int(jp, &n);
            return;
        }

        (void) ngx_http_waf_jp_skip(jp);
        return;
    }
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_str_t           payload;
    ngx_pool_t         *pool;
    ngx_http_waf_jp_t   jp;

    waf_fuzz_init();

    pool = waf_fuzz_pool();
    if (pool == NULL) {
        return 0;
    }

    if (waf_fuzz_payload(pool, data, size, &payload) != NGX_OK) {
        ngx_destroy_pool(pool);
        return 0;
    }

    ngx_http_waf_jp_init(&jp, &payload, pool);
    walk(&jp, 0);

    ngx_http_waf_jp_init(&jp, &payload, pool);
    (void) ngx_http_waf_jp_skip(&jp);

    ngx_destroy_pool(pool);

    return 0;
}
