/*
 * Фаза ответа: фильтр заголовков и фильтр тела.
 *
 * Устройство держится на трёх решениях.
 *
 * Первое: ответ удерживается прямо в фильтре, без подмены обработчиков запроса.
 * Фильтр не умеет вернуть "подожди" -- он либо отдал байты дальше, либо не
 * отдал, -- поэтому заголовки не уходят в next_header_filter, тело копится в
 * ctx->hold, а запрос помечается r->buffered. Без этого бита
 * ngx_http_finalize_request() освободит запрос сразу после того, как апстрим
 * отдал последний буфер: вместе с пулом, контекстом, слотом и удержанной
 * цепочкой, которую мы собирались отдать.
 *
 * Второе: решение принимается только в своём стеке. Колбэк шины меняет
 * состояние и зовёт ngx_http_waf_response_resume(), а применяет исход
 * возобновление -- ровно так же, как на фазе запроса применяет его обработчик
 * фазы, а не колбэк.
 *
 * Третье: отказ собирается заново через ngx_http_filter_finalize_request().
 * Заголовки апстрима к этому моменту не отправлены -- ради этого фаза их и
 * держит, -- поэтому отказ выглядит как любой другой отказ nginx: error_page,
 * $waf_deny_name, тот же путь, что у фазы запроса.
 */

#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"


static ngx_int_t ngx_http_waf_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_body_filter(ngx_http_request_t *r,
                     ngx_chain_t *in);
static ngx_uint_t ngx_http_waf_response_bypass(ngx_http_request_t *r,
                      ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_outcome(ngx_http_waf_ctx_t *ctx,
                     ngx_int_t rc);
static ngx_int_t ngx_http_waf_response_hold(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_release(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_deny(ngx_http_waf_ctx_t *ctx,
                     ngx_int_t status);
static ngx_int_t ngx_http_waf_hold_chain(ngx_http_waf_ctx_t *ctx,
                     ngx_chain_t *in);
static ngx_uint_t ngx_http_waf_response_body_ready(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_body_place(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_restore_accept_encoding(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_response_rewrite(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_rewrite_fetched(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_rewrite_fail(ngx_http_waf_ctx_t *ctx,
                     ngx_uint_t index, const char *why);
static ngx_int_t ngx_http_waf_rewrite_swap(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_body_op_t *op);


/*
 * Код причины отказа, когда подмена тела не состоялась и политика велит block.
 * Свой, а не присланный: причина случилась в модуле, и подписывать её кодом
 * инспектора значило бы приписать ему решение, которого он не выносил.
 */
static ngx_str_t  ngx_http_waf_rewrite_fail_code =
    ngx_string("REWRITE_UNAVAILABLE");


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


ngx_int_t
ngx_http_waf_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = ngx_http_waf_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter  = ngx_http_waf_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx != NULL) {
        ngx_http_waf_restore_accept_encoding(ctx);
    }

    /*
     * Контекста нет -- фазы запроса на этом маршруте не было, и восстанавливать
     * фазе ответа нечего: ни rid, ни ray, ни объектов запроса. Повторный вход
     * бывает на странице отказа: её ответ идёт теми же фильтрами.
     */
    if (ctx == NULL || ctx->rsp_entered) {

        /*
         * Второй вход -- это наша же страница отказа: заголовки ответа
         * приложения вычищены ngx_http_filter_finalize_request(), и вместе с
         * ними ушла диагностика. Возвращаем её здесь: "почему 418" -- первый
         * вопрос к фазе ответа, и отвечать на него нечем, если заголовка нет
         * ровно на том ответе, который клиент увидел.
         */
        if (ctx != NULL && ctx->rsp_denied) {
            (void) ngx_http_waf_apply_debug(ctx);
        }

        return ngx_http_next_header_filter(r);
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (!wlcf->enable
        || wlcf->waves[NGX_HTTP_WAF_PHASE_RESPONSE] == NULL
        || wlcf->waves[NGX_HTTP_WAF_PHASE_RESPONSE]->nelts == 0)
    {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_waf_response_bypass(r, ctx)) {
        /* Фазы ответа не будет -- исход маршрута известен. */
        ngx_http_waf_audit_flush_deferred(ctx);
        return ngx_http_next_header_filter(r);
    }

    ctx->rsp_entered = 1;
    ctx->hold_last   = &ctx->hold;
    ctx->rsp_status  = r->headers_out.status;

    if (ngx_http_waf_response_headers(ctx) == NULL) {
        ctx->rsp_entered = 0;
        return NGX_ERROR;
    }

    /*
     * Время апстрима -- то, что уже посчитал сам nginx: своего измерения у
     * модуля нет, а два разных числа в записи аудита и в сообщении инспектору
     * означали бы два разных ответа на один вопрос.
     *
     * Без ограждения: макроса NGX_HTTP_UPSTREAM у nginx нет, апстрим --
     * часть http-ядра, а прежнее #if молча выкидывало этот блок целиком.
     */
    if (r->upstream != NULL && r->upstream->state != NULL) {
        ctx->upstream_ms = r->upstream->state->response_time;
    }

    /*
     * Бюджет фазы считается со своего начала: waf_deadline response -- это
     * время на инспекцию ответа, а не остаток от времени запроса.
     */
    ngx_http_waf_phase_enter(ctx, NGX_HTTP_WAF_PHASE_RESPONSE);

    ctx->started = ngx_current_msec;
    ctx->state   = NGX_HTTP_WAF_ST_INIT;

    rc = ngx_http_waf_wave_start(ctx, 0);

    return ngx_http_waf_response_outcome(ctx, rc);
}


/*
 * Что фаза ответа не инспектирует. Список закрытый и проверяется до входа в
 * фазу: удержать ответ, который нельзя удержать, дороже, чем не смотреть.
 */
static ngx_uint_t
ngx_http_waf_response_bypass(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
    /*
     * Подзапросы порождает не клиент: инспектировать их незачем, а r->ctx у
     * них общий с основным запросом.
     */
    if (r != r->main) {
        return 1;
    }

    /* Тела не будет, а заголовки уже нечем задержать осмысленно. */
    if (r->header_only) {
        return 1;
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_NO_CONTENT:
    case NGX_HTTP_NOT_MODIFIED:
        return 1;

    case NGX_HTTP_SWITCHING_PROTOCOLS:
        /*
         * Апгрейд: после 101 байты копирует
         * ngx_http_upstream_process_upgraded(), мимо фильтров. Это фаза кадров,
         * и до неё у модуля нет ни одной точки подключения.
         */
        return 1;

    default:
        break;
    }

    /*
     * Наш собственный отказ. Страница отказа фазы запроса -- это ответ,
     * который сгенерировал сам модуль, и инспектировать его значило бы
     * спрашивать инспекторов про свою же страницу.
     */
    if (ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST].verdict == NGX_HTTP_WAF_V_DENY
        || ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST].fail_blocked)
    {
        return 1;
    }

    return 0;
}


/*
 * Заголовки ответа парами. Список nginx неполон: content-type и длина живут
 * отдельными полями структуры, а в список не попадают вовсе -- их дописывает
 * ngx_http_header_filter при отправке. Инспектору они нужны раньше: по типу
 * содержимого движок правил решает, разбирать ли тело.
 */
ngx_array_t *
ngx_http_waf_response_headers(ngx_http_waf_ctx_t *ctx)
{
    u_char              *p;
    ngx_uint_t           i;
    ngx_keyval_t        *kv;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_headers != NULL) {
        return ctx->rsp_headers;
    }

    ctx->rsp_headers = ngx_array_create(r->pool, 16, sizeof(ngx_keyval_t));
    if (ctx->rsp_headers == NULL) {
        return NULL;
    }

    part = &r->headers_out.headers.part;
    h    = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        kv = ngx_array_push(ctx->rsp_headers);
        if (kv == NULL) {
            return NULL;
        }

        kv->key   = h[i].key;
        kv->value = h[i].value;
    }

    if (r->headers_out.content_type.len != 0) {
        kv = ngx_array_push(ctx->rsp_headers);
        if (kv == NULL) {
            return NULL;
        }

        ngx_str_set(&kv->key, "Content-Type");
        kv->value = r->headers_out.content_type;
    }

    if (r->headers_out.content_length_n >= 0
        && r->headers_out.content_length == NULL)
    {
        p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
        if (p == NULL) {
            return NULL;
        }

        kv = ngx_array_push(ctx->rsp_headers);
        if (kv == NULL) {
            return NULL;
        }

        ngx_str_set(&kv->key, "Content-Length");
        kv->value.data = p;
        kv->value.len  = ngx_sprintf(p, "%O",
                                     r->headers_out.content_length_n) - p;
    }

    return ctx->rsp_headers;
}


/*
 * Accept-Encoding в апстрим: снимаем там, где маршрут снимает тело ответа.
 *
 * Не согласовать сжатие дешевле, чем распаковывать: распаковка в воркере -- это
 * лимиты, счётчики и поверхность декомпрессионной бомбы, а сжатое тело
 * инспектору бесполезно. Та же мысль, что снятие permessage-deflate на
 * рукопожатии вебсокета.
 *
 * Цена -- апстрим отдаёт несжатое; клиенту nginx сожмёт сам, если настроен
 * gzip. Кому цена не нравится, пишет waf_strip_accept_encoding off и получает
 * тело с encoding в локаторе -- инспектор вправе его не смотреть.
 */
void
ngx_http_waf_strip_accept_encoding(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                  strip;
    ngx_table_elt_t            *ae;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    ae = r->headers_in.accept_encoding;

    if (ae == NULL || ae->hash == 0) {
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh   = &wlcf->shoot[NGX_HTTP_WAF_PHASE_RESPONSE];

    strip = (sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY)) != 0;

    if (wlcf->strip_accept_encoding != NGX_CONF_UNSET) {
        strip = (ngx_uint_t) wlcf->strip_accept_encoding;
    }

    if (!strip) {
        return;
    }

    /*
     * Значение подменяется, а не убирается: обнуление хеша заголовок из
     * запроса не выкидывает -- прокси копирует список как есть, и апстрим
     * получил бы его нетронутым. "identity" при этом честнее пустой строки:
     * это валидное значение, и апстрим читает его однозначно.
     */
    ctx->accept_encoding = ae->value;

    ngx_str_set(&ae->value, "identity");
}


/*
 * Вернуть клиентское значение на место. Вызывается из фильтра заголовков, то
 * есть до фильтра сжатия: тот читает тот же самый заголовок, решая, сжимать ли
 * ответ клиенту. Не вернуть -- значит выключить сжатие ещё и клиенту, который
 * его просил и к апстриму отношения не имеет.
 */
static void
ngx_http_waf_restore_accept_encoding(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->accept_encoding.data == NULL
        || r->headers_in.accept_encoding == NULL)
    {
        return;
    }

    r->headers_in.accept_encoding->value = ctx->accept_encoding;
    ctx->accept_encoding.data = NULL;
}


/*
 * Тело ответа для волны, которая его требует.
 *
 * Разница с фазой запроса вся здесь: тело запроса модуль читает сам и знает,
 * когда оно кончилось, а тело ответа ему отдают кусками. Волна поэтому ждёт
 * одного из двух событий -- набрался снимок или апстрим отдал последний буфер, --
 * и будит её фильтр, а не драйвер обменника.
 */
ngx_int_t
ngx_http_waf_response_body(ngx_http_waf_ctx_t *ctx)
{
    if (!ngx_http_waf_response_body_ready(ctx)) {
        ctx->rsp_wait_body = 1;
        return NGX_DONE;
    }

    return ngx_http_waf_response_body_place(ctx);
}


/*
 * Снимка набралось столько, сколько маршрут просил, либо тела больше не будет.
 * Ждать полное тело при заданном размере снимка незачем: инспектор всё равно
 * увидит префикс, а ответ на гигабайт задержал бы вердикт на своё скачивание.
 */
static ngx_uint_t
ngx_http_waf_response_body_ready(ngx_http_waf_ctx_t *ctx)
{
    size_t                      need;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    if (ctx->rsp_last) {
        return 1;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[NGX_HTTP_WAF_PHASE_RESPONSE];

    need = sh->capture_limit[NGX_HTTP_WAF_OBJ_BODY];

    if (need == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE) {
        return 0;                      /* просили целиком -- ждём last_buf */
    }

    return ctx->hold_size >= need;
}


static ngx_int_t
ngx_http_waf_response_body_place(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    ctx->rsp_wait_body  = 0;
    ctx->ph->body_ready = 1;

    rc = ngx_http_waf_body_place(ctx);

    if (rc == NGX_AGAIN) {
        return NGX_DONE;               /* драйвер разбудит сам */
    }

    /*
     * Размещение закончилось на месте. Волну продолжает то же возобновление,
     * что и после драйвера: другого пути к публикации у фазы нет, и заводить
     * второй значило бы однажды разойтись в состояниях.
     */
    ngx_http_waf_body_resumed(ctx, rc);

    return NGX_DONE;
}


/* Код возврата волны -- в решение фазы ответа. */
static ngx_int_t
ngx_http_waf_response_outcome(ngx_http_waf_ctx_t *ctx, ngx_int_t rc)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    if (rc == NGX_DONE) {

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        /*
         * monitor: ответ уходит немедленно, инспекция идёт вслед. Вердикт при
         * этом не пропадает -- он попадёт в лог и в аудит, -- но отменить
         * отданное он уже не может, и отказ на этом маршруте означает "оборвать
         * поток", а не "не пропустить".
         */
        if (wlcf->hold[NGX_HTTP_WAF_PHASE_RESPONSE]
            == NGX_HTTP_WAF_HOLD_MONITOR)
        {
            ctx->rsp_monitor = 1;
            return ngx_http_waf_response_release(ctx);
        }

        return ngx_http_waf_response_hold(ctx);
    }

    if (rc == NGX_OK || rc == NGX_DECLINED) {
        return ngx_http_waf_response_release(ctx);
    }

    if (rc == NGX_ERROR) {
        return ngx_http_waf_response_deny(ctx,
                                          NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    return ngx_http_waf_response_deny(ctx, rc);
}


static ngx_int_t
ngx_http_waf_response_hold(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    /*
     * Исход мог примениться прямо внутри волны: тело собралось на месте,
     * возобновление отпустило ответ, и держать уже нечего.
     */
    if (ctx->rsp_settled) {
        return NGX_OK;
    }

    ctx->rsp_holding = 1;

    /*
     * Бит держит запрос живым: ngx_http_finalize_request() при выставленном
     * r->buffered не освобождает запрос, а ставит писателя и ждёт. Снимаем его
     * при возобновлении -- и только там.
     */
    r->buffered |= NGX_HTTP_WAF_BUFFERED;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_response_release(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t            rc;
    ngx_chain_t         *out;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_settled) {
        return NGX_OK;
    }

    ctx->rsp_settled = 1;
    ctx->rsp_holding = 0;
    r->buffered &= ~NGX_HTTP_WAF_BUFFERED;

    out            = ctx->hold;
    ctx->hold      = NULL;
    ctx->hold_last = &ctx->hold;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    if (out == NULL) {
        return rc;
    }

    return ngx_http_next_body_filter(r, out);
}


static ngx_int_t
ngx_http_waf_response_deny(ngx_http_waf_ctx_t *ctx, ngx_int_t status)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->rsp_settled) {
        return NGX_OK;
    }

    ctx->rsp_settled = 1;
    ctx->rsp_holding = 0;
    ctx->rsp_denied  = 1;

    /*
     * Удержанное тело выбрасывается целиком: клиент не должен увидеть ни байта
     * ответа приложения. Ради этого фаза его и держала.
     */
    ctx->hold      = NULL;
    ctx->hold_last = &ctx->hold;
    ctx->hold_size = 0;

    r->buffered &= ~NGX_HTTP_WAF_BUFFERED;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: response denied with %i, ray %*s", status,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    /*
     * Контекст модуля эта функция сохраняет (она чистит r->ctx всех остальных),
     * а якорь в r->variables переживает и внутренний редирект на страницу
     * отказа. Повторного входа в фазу не будет: rsp_entered уже выставлен.
     */
    return ngx_http_filter_finalize_request(r, &ngx_http_waf_module, status);
}


void
ngx_http_waf_response_resume(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t            rc;
    ngx_http_request_t  *r = ctx->request;

    ctx->waiting = 0;

    /*
     * Подмена тела -- до применения исхода: лог, аудит и освобождение объектов
     * обменника обязаны видеть ответ таким, каким его получит клиент. Fetch
     * асинхронный, и его колбэк возвращается ровно сюда с уже закрытым
     * вопросом (rsp_fetch_done).
     */
    if (ctx->state != NGX_HTTP_WAF_ST_NEXT_WAVE
        && !ctx->rsp_fetch_done
        && ngx_http_waf_response_rewrite(ctx) == NGX_AGAIN)
    {
        return;                        /* колбэк обменника вернёт нас сюда */
    }

    if (ctx->state == NGX_HTTP_WAF_ST_NEXT_WAVE) {
        rc = ngx_http_waf_wave_start(ctx, ctx->ph->wave);

    } else {
        rc = ngx_http_waf_phase_apply(ctx);
    }

    if (rc == NGX_DONE) {
        /* Следующая волна опубликована либо обменник ещё пишет: ждём дальше. */
        return;
    }

    /*
     * monitor: ответ давно у клиента. Отказ теперь -- это обрыв соединения, и
     * ничего другого сделать уже нельзя; allow не делает ничего вовсе.
     */
    if (ctx->rsp_monitor) {

        if (rc != NGX_OK && rc != NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "waf: response phase denied a monitored response "
                          "with %i; the bytes are already out, cutting the "
                          "connection, ray %*s", rc,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

            ngx_http_finalize_request(r, NGX_ERROR);
        }

        return;
    }

    rc = ngx_http_waf_response_outcome(ctx, rc);

    /*
     * Апстрим уже отдал всё, что у него было, и ушёл: доигрывать запрос
     * теперь некому, кроме нас. Пока не отдал -- остаток тела дойдёт через
     * фильтр обычным ходом, и финализация не наша.
     */
    if (ctx->rsp_last || rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_run_posted_requests(r->connection);
}


/*
 * Подмена тела ответа по секции rewrite настоявшегося вердикта.
 *
 * NGX_AGAIN -- GET к обменнику в полёте, возобновление продолжит его колбэк.
 * NGX_DECLINED -- вопрос закрыт: подменять нечего, подмена выполнена на месте
 * либо отказ уже разрешён политикой фазы (state мог стать ST_DENY).
 *
 * Подменяет тело последнее звено цепочки версий: волна за волной их сводил
 * ngx_http_waf_rewrite_settle(), здесь остаётся поднять актуальный объект.
 */
static ngx_int_t
ngx_http_waf_response_rewrite(ngx_http_waf_ctx_t *ctx)
{
    off_t                      cap;
    ngx_int_t                  rc;
    ngx_uint_t                 found;
    ngx_table_elt_t           *ce;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_body_op_t    *op;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->state != NGX_HTTP_WAF_ST_ALLOW || ctx->ph->replies == NULL) {
        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    insp  = wmcf->inspectors.elts;

    found = (ctx->ph->live != NULL)
                ? ctx->ph->rewrite_last : NGX_HTTP_WAF_MAX_INSPECTORS;

    if (found == NGX_HTTP_WAF_MAX_INSPECTORS) {
        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    reply = &ctx->ph->replies[found];
    ctx->rsp_rewrite_index = found;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    /*
     * waf_send response body=original: маршрут подмену тела не принимает.
     * Строка INFO, не WARN -- инспектор ничего не нарушил, это решение
     * маршрута; в записи секция rewrite с applied:false.
     */
    if (ngx_http_waf_send_of(wlcf, NGX_HTTP_WAF_PHASE_RESPONSE,
                             NGX_HTTP_WAF_OBJ_BODY)
        != NGX_HTTP_WAF_SEND_STORE)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: response body rewrite by \"%V\" skipped: "
                      "waf_send response body=original, ray %*s",
                      &insp[found].name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    /*
     * Ответ уже отпущен: переполнение удержания превратило gate в monitor, и
     * байты у клиента. Подменять нечего, а отказывать поздно -- это тот же
     * документированный fail-open, что и сам WARN о переполнении.
     */
    if (ctx->rsp_settled) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: inspector \"%V\" asked to rewrite a response "
                      "that was already released; skipped, ray %*s",
                      &insp[found].name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->rsp_fetch_done = 1;
        return NGX_DECLINED;
    }

    /*
     * Снимок взял префикс (ответ шире среза waf_capture), а маршрут просит
     * отдать тело из обменника. Инспектор видел часть, и заменить целое
     * куском значит сломать ответ -- это сбой подъёма наравне с пропавшим
     * ключом: исход решает политика фазы, в записи partial:true рядом с
     * applied:false. Ответ, уложившийся в срез, сюда не попадает.
     */
    if (!ctx->rsp_last) {
        reply->rewrite_partial = 1;

        ngx_http_waf_rewrite_fail(ctx, found, "the capture is a prefix of "
                                  "the body and a slice cannot replace the "
                                  "whole; waf_send response body=store needs "
                                  "a whole capture");
        return NGX_DECLINED;
    }

    ce = r->headers_out.content_encoding;

    if (ce != NULL && ce->hash != 0 && ce->value.len != 0
        && !(ce->value.len == 8
             && ngx_strncasecmp(ce->value.data, (u_char *) "identity", 8)
                == 0))
    {
        ngx_http_waf_rewrite_fail(ctx, found,
                                  "the upstream response is encoded");
        return NGX_DECLINED;
    }

    cap = (off_t) wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE];

    if (reply->rewrite_size > cap) {
        ngx_http_waf_rewrite_fail(ctx, found,
                                  "the object exceeds waf_body_limit");
        return NGX_DECLINED;
    }

    rc = ngx_http_waf_store_get(ctx, &reply->rewrite_key, cap,
                                ngx_http_waf_rewrite_fetched, &op);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK || op == NULL || op->status != NGX_OK) {
        ngx_http_waf_rewrite_fail(ctx, found, "the store cannot serve the "
                                  "object");
        return NGX_DECLINED;
    }

    /* драйвер ответил на месте: применяем без второго захода в resume */
    if (ngx_http_waf_rewrite_swap(ctx, op) != NGX_OK) {
        ngx_http_waf_rewrite_fail(ctx, found, "the object does not match its "
                                  "declaration");
    }

    return NGX_DECLINED;
}


static void
ngx_http_waf_rewrite_fetched(ngx_http_waf_body_op_t *op)
{
    ngx_http_waf_ctx_t  *ctx = op->data_ctx;

    if (op->status == NGX_OK) {

        if (ngx_http_waf_rewrite_swap(ctx, op) != NGX_OK) {
            ngx_http_waf_rewrite_fail(ctx, ctx->rsp_rewrite_index,
                                      "the object does not match its "
                                      "declaration");
        }

    } else if (op->status == NGX_DECLINED) {
        ngx_http_waf_rewrite_fail(ctx, ctx->rsp_rewrite_index,
                                  "no such key in the store");

    } else {
        ngx_http_waf_rewrite_fail(ctx, ctx->rsp_rewrite_index,
                                  "store error or timeout");
    }

    ngx_http_waf_response_resume(ctx);
}


/*
 * Подмена не состоялась. Это сбой обработки, и распоряжается им политика фазы
 * -- waf_exception … body: deny -- отказ, pass -- оригинал с WARN.
 * Умолчание политики (block) выбрано той же меркой, что и здесь: намерение
 * спрятать содержимое известно, и отдать оригинал молча значит слить ровно то,
 * что маскировали.
 */
static void
ngx_http_waf_rewrite_fail(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    const char *why)
{
    ngx_uint_t                 deny;
    ngx_http_waf_reply_t      *reply = &ctx->ph->replies[index];
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    ctx->rsp_fetch_done = 1;

    deny = wlcf->exception[NGX_HTTP_WAF_PHASE_RESPONSE][NGX_HTTP_WAF_EXC_BODY]
           == NGX_HTTP_WAF_POLICY_BLOCK;

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: response rewrite by \"%V\" failed (%s); %s, ray %*s",
                  &insp->name, why,
                  deny ? "denying per waf_exception body"
                       : "passing the original",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    if (!deny) {
        return;
    }

    /*
     * Поздний отказ поверх решённого allow. Лестница вердиктов уже отработала,
     * поэтому итог правится руками -- ровно так же честно, как обрыв
     * соединения у monitor: требование инспектора выполнить нельзя, и исходом
     * распоряжается политика фазы.
     */
    reply->verdict     = NGX_HTTP_WAF_V_DENY;
    reply->reason_code = ngx_http_waf_rewrite_fail_code;

    /* своей записи у сбоя нет: страницу назовёт waf_deny_response_default */
    ngx_str_null(&reply->response_name);

    ctx->ph->verdict        = NGX_HTTP_WAF_V_DENY;
    ctx->ph->decisive       = reply;
    ctx->ph->decisive_index = index;
    ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;

    ctx->state = NGX_HTTP_WAF_ST_DENY;
}


/*
 * Сама подмена: удержанная цепочка выбрасывается, её место занимает один буфер
 * с объектом обменника. Заголовки ещё не отправлены, поэтому Content-Length
 * честно переписывается под новую длину.
 */
static ngx_int_t
ngx_http_waf_rewrite_swap(ngx_http_waf_ctx_t *ctx, ngx_http_waf_body_op_t *op)
{
    u_char                 digest[32];
    size_t                 was;
    ngx_buf_t             *b;
    ngx_chain_t           *cl;
    ngx_http_request_t    *r = ctx->request;
    ngx_http_waf_reply_t  *reply;
    ngx_http_waf_sha256_t  sha;

    reply = &ctx->ph->replies[ctx->rsp_rewrite_index];

    if (op->data.len != (size_t) reply->rewrite_size) {
        return NGX_ERROR;
    }

    /*
     * Контрольная сумма считается всегда: реплай с ней -- сверка, без неё --
     * запись обязана назвать, что именно ушло клиенту, сама: объект из
     * обменника после подъёма удаляется, в архиве остаётся оригинал.
     */
    ngx_http_waf_sha256_init(&sha);
    ngx_http_waf_sha256_update(&sha, op->data.data, op->data.len);
    ngx_http_waf_sha256_final(&sha, digest);

    if (reply->rewrite_sha256_set
        && ngx_memcmp(digest, reply->rewrite_sha256, 32) != 0)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(reply->rewrite_sha256, digest, 32);
    reply->rewrite_digest = 1;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b->start    = op->data.data;
    b->pos      = op->data.data;
    b->last     = op->data.data + op->data.len;
    b->end      = b->last;
    b->memory   = 1;
    b->last_buf = 1;

    cl->buf  = b;
    cl->next = NULL;

    was = ctx->hold_size;

    ctx->hold      = cl;
    ctx->hold_last = &cl->next;
    ctx->hold_size = op->data.len;

    r->headers_out.content_length_n = (off_t) op->data.len;

    if (r->headers_out.content_length != NULL) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length       = NULL;
    }

    ctx->rsp_fetch_done = 1;
    ctx->rsp_rewritten  = 1;

    /*
     * source=sent: показать в записи доставленную версию. Байты подмены живут
     * в пуле запроса (op->data) до конца ответа -- записи хватит указателя,
     * копировать незачем. Оригинал остаётся в обменнике для архива.
     */
    {
        ngx_http_waf_loc_conf_t  *wlcf;

        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

        if (wlcf->shoot[ctx->phase].preview_source_sent
            & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
        {
            ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY] = op->data;
        }
    }

    /* объект прочитан и скопирован; в обменнике он больше никому не нужен */
    ngx_http_waf_store_del_key(ctx, &reply->rewrite_key);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: response body rewritten, %uz -> %uz bytes, ray %*s",
                  was, ctx->hold_size,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);

    /*
     * Апгрейд: 101 прошёл фильтр заголовков обходом, а этот вызов -- flush,
     * которым ngx_http_upstream_upgrade() заканчивает переключение. Его
     * обработчики уже расставлены, и обработчик кадров забирает соединение
     * себе -- до того, как буфер уйдёт дальше, чтобы клиент увидел 101 уже
     * под нашим присмотром.
     */
    if (ctx != NULL && r->header_sent && r->upstream != NULL
        && r->upstream->upgrade && ngx_http_waf_frame_wanted(r, ctx))
    {
        if (ngx_http_waf_frame_attach(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx == NULL || r != r->main || !ctx->rsp_entered || ctx->rsp_settled) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in != NULL && ngx_http_waf_hold_chain(ctx, in) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Волна ждала тело: разбудить её -- дело фильтра, потому что только он
     * знает, что байты дошли.
     */
    if (ctx->rsp_wait_body
        && !ctx->rsp_settled
        && ngx_http_waf_response_body_ready(ctx))
    {
        (void) ngx_http_waf_response_body_place(ctx);
    }

    /*
     * Для апстрима это "записано": иначе он остановит чтение и будет ждать
     * места, которого мы не освободим до вердикта. Настоящая запись случится
     * при возобновлении, и до тех пор запрос держит r->buffered.
     */
    return NGX_OK;
}


/*
 * Копия цепочки в контекст. Именно копия: буферы апстрима переиспользуются
 * сразу после возврата из фильтра, и отданная клиенту ссылка показала бы ему
 * не тот ответ, который мы инспектировали.
 *
 * Файловые буферы копируются структурой: файл живёт до конца запроса, а
 * переписывать его во второй временный файл ради удержания незачем.
 */
static ngx_int_t
ngx_http_waf_hold_chain(ngx_http_waf_ctx_t *ctx, ngx_chain_t *in)
{
    off_t                     size;
    u_char                   *p;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    for ( /* void */ ; in != NULL; in = in->next) {

        if (in->buf->last_buf) {
            ctx->rsp_last = 1;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        *b = *in->buf;

        size = ngx_buf_size(in->buf);

        if (ngx_buf_in_memory(in->buf) && size > 0) {
            p = ngx_pnalloc(r->pool, (size_t) size);
            if (p == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(p, in->buf->pos, (size_t) size);

            b->start = b->pos = p;
            b->end   = b->last = p + size;
            b->memory = 1;
            b->temporary = 0;

            ctx->hold_size += (size_t) size;
        }

        /* Апстрим считает буфер отработанным, иначе он не двинется дальше. */
        in->buf->pos = in->buf->last;
        in->buf->file_pos = in->buf->file_last;

        cl->buf  = b;
        cl->next = NULL;

        *ctx->hold_last = cl;
        ctx->hold_last  = &cl->next;
    }

    /*
     * Удержание не бесконечно. Предел -- waf_body_limit этой фазы: он и есть
     * ответ на вопрос "сколько байт ответа модуль вообще берётся держать".
     * Упёрлись -- отпускаем ответ, не дожидаясь вердикта, и говорим об этом
     * в лог: молча превратить gate в monitor нельзя, это разница между
     * "не пропустил" и "не успел".
     */
    if (ctx->hold_size > wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE]) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: response of %uz bytes passed the %uz byte hold "
                      "limit before the verdict; releasing it, ray %*s",
                      ctx->hold_size,
                      wlcf->body_limit[NGX_HTTP_WAF_PHASE_RESPONSE],
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        return ngx_http_waf_response_release(ctx) == NGX_ERROR
                   ? NGX_ERROR : NGX_OK;
    }

    return NGX_OK;
}
