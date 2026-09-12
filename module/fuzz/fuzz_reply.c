/*
 * Разбор ответа инспектора (codec/ngx_http_waf_msg_reply.c): единственное
 * место, куда попадают непроверенные байты с шины. Контекст запроса и
 * конфигурация -- макеты ровно того, что разбор читает: реестр из двух
 * инспекторов, каталог отказов с одной записью, один
 * разрешённый шаблон редиректа, пределы канала действий.
 */

#include "common.h"


static ngx_http_waf_main_conf_t  wmcf;
static ngx_http_waf_loc_conf_t   wlcf;
static void                     *main_conf[1];
static void                     *loc_conf[1];
static ngx_array_t              *inspectors;
static int                       ready;


static void
mock_init(void)
{
    ngx_http_waf_inspector_t       *insp;
    ngx_http_waf_deny_response_t   *dr;
    ngx_http_waf_redirect_allow_t  *ra;
    ngx_pool_t                     *pool = ngx_cycle->pool;

    if (ready) {
        return;
    }

    ready = 1;

    inspectors = ngx_array_create(pool, 2, sizeof(ngx_http_waf_inspector_t));

    insp = ngx_array_push(inspectors);
    ngx_memzero(insp, sizeof(ngx_http_waf_inspector_t));
    ngx_str_set(&insp->name, "modsec");
    ngx_str_set(&insp->subject, "waf.req.modsec");
    ngx_str_set(&insp->profile, "default");
    insp->index  = 0;

    insp = ngx_array_push(inspectors);
    ngx_memzero(insp, sizeof(ngx_http_waf_inspector_t));
    ngx_str_set(&insp->name, "ip");
    ngx_str_set(&insp->subject, "waf.req.ip");
    ngx_str_set(&insp->profile, "default");
    insp->index = 1;

    wmcf.inspectors       = *inspectors;
    wmcf.reply_max        = 64 * 1024;
    wmcf.header_value_max = 4096;
    ngx_str_set(&wmcf.node_id, "fuzz");

    wmcf.deny_responses = ngx_array_create(pool, 1,
                                           sizeof(ngx_http_waf_deny_response_t));
    dr = ngx_array_push(wmcf.deny_responses);
    ngx_memzero(dr, sizeof(ngx_http_waf_deny_response_t));
    ngx_str_set(&dr->name, "blocked");
    dr->status = 403;

    wlcf.redirect_allow = ngx_array_create(pool, 1,
                                           sizeof(ngx_http_waf_redirect_allow_t));
    ra = ngx_array_push(wlcf.redirect_allow);
    ngx_memzero(ra, sizeof(ngx_http_waf_redirect_allow_t));
    ngx_str_set(&ra->scheme, "https");
    ngx_str_set(&ra->host, "example.com");
    ngx_str_set(&ra->path, "/");
    ra->port     = 443;
    ra->wildcard = 1;

    wlcf.action_max  = 4096;
    wlcf.actions_max = 8;

    main_conf[0] = &wmcf;
    loc_conf[0]  = &wlcf;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_str_t             payload, err;
    ngx_pool_t           *pool;
    ngx_uint_t            index;
    ngx_connection_t      c;
    ngx_http_request_t   *r;
    ngx_http_waf_ctx_t    ctx;
    ngx_http_waf_reply_t  reply;

    waf_fuzz_init();
    mock_init();

    if (size == 0) {
        return 0;
    }

    pool = waf_fuzz_pool();
    if (pool == NULL) {
        return 0;
    }

    /* первый байт -- фаза и адресат, остальное -- ответ с провода */
    index = data[0] & 1;

    if (waf_fuzz_payload(pool, data + 1, size - 1, &payload) != NGX_OK) {
        ngx_destroy_pool(pool);
        return 0;
    }

    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }

    ngx_memzero(&c, sizeof(ngx_connection_t));
    c.log = &waf_fuzz_log;

    r->pool       = pool;
    r->connection = &c;
    r->main_conf  = main_conf;
    r->loc_conf   = loc_conf;

    ngx_memzero(&ctx, sizeof(ngx_http_waf_ctx_t));
    ctx.request = r;
    ctx.phase   = (data[0] >> 1) & 1;
    ctx.ph      = &ctx.phases[ctx.phase];
    ngx_memcpy(ctx.rid_hex, "00000000deadbeef", NGX_HTTP_WAF_RID_HEX_LEN);
    ngx_memcpy(ctx.ray_hex, "00000000-0000-4000-8000-000000000000",
               NGX_HTTP_WAF_RAY_HEX_LEN);

    ngx_str_null(&err);

    (void) ngx_http_waf_msg_reply(&ctx, index, &payload, &reply, &err);

    ngx_destroy_pool(pool);

    return 0;
}
