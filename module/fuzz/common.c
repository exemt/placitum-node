#include "common.h"


ngx_log_t  waf_fuzz_log;

static ngx_open_file_t  waf_fuzz_file;
static ngx_cycle_t      waf_fuzz_cycle;
static volatile ngx_cycle_t  *waf_fuzz_saved_cycle;

/*
 * nginx.o в харнесс не линкуется (там main), а ngx_core_module из него
 * упоминают ngx_cycle.c и таблица модулей. Заглушка того же типа закрывает
 * ссылку; конфигурацию через неё никто не читает.
 */
static ngx_core_module_t  waf_fuzz_core_ctx = {
    ngx_string("core"),
    NULL,
    NULL
};

ngx_module_t  ngx_core_module = {
    NGX_MODULE_V1,
    &waf_fuzz_core_ctx,
    NULL,
    NGX_CORE_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


void
waf_fuzz_init(void)
{
    static int  done;

    if (done) {
        return;
    }

    done = 1;

    ngx_pagesize       = 4096;
    ngx_pagesize_shift = 12;
    ngx_cacheline_size = 64;

    ngx_time_init();

    waf_fuzz_file.fd       = ngx_stderr;
    waf_fuzz_log.file      = &waf_fuzz_file;
    waf_fuzz_log.log_level = getenv("WAF_FUZZ_LOG") ? NGX_LOG_INFO : 0;

    waf_fuzz_cycle.pool = ngx_create_pool(64 * 1024, &waf_fuzz_log);
    waf_fuzz_cycle.log  = &waf_fuzz_log;

    ngx_cycle = &waf_fuzz_cycle;
    (void) waf_fuzz_saved_cycle;

    ngx_event_timer_init(&waf_fuzz_log);

    /*
     * ngx_http_get_module_*_conf() индексирует r->main_conf/loc_conf по
     * ctx_index модуля; в живом nginx его выдаёт ngx_cycle_modules(). Здесь
     * модуль один, индекс ноль.
     */
    ngx_http_waf_module.ctx_index = 0;
}


ngx_pool_t *
waf_fuzz_pool(void)
{
    return ngx_create_pool(16 * 1024, &waf_fuzz_log);
}


ngx_int_t
waf_fuzz_payload(ngx_pool_t *pool, const uint8_t *data, size_t size,
    ngx_str_t *out)
{
    u_char  *p;

    /* один лишний байт: парсеры не обязаны терпеть буфер без запаса, но
       читать за ним они не вправе -- ASan это и ловит */
    p = ngx_pnalloc(pool, size == 0 ? 1 : size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (size != 0) {
        ngx_memcpy(p, data, size);
    }

    out->data = p;
    out->len  = size;

    return NGX_OK;
}
