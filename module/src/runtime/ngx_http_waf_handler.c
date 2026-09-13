/*
 * Обработчик access-фазы: приостановка запроса до вердикта и возобновление по
 * внешнему событию.
 *
 * Главная ловушка этой фазы -- r->main->count. Инкрементировать его здесь
 * нельзя: для access-фазы nginx не вызывает ngx_http_finalize_request(),
 * декрементировать счётчик будет некому, и запрос не освободится никогда.
 * Инкремент -- приём content-фазы и подзапросов. Корректный паттерн взят из
 * ngx_http_limit_req_module: обработчик возвращает NGX_DONE, а внешнее событие
 * возвращает запрос в фазы через ngx_http_core_run_phases().
 *
 * Второе правило этого файла: решение принимается только внутри обработчика
 * фазы. Колбэки шины и таймеров меняют состояние контекста и возвращают запрос
 * в фазы, но сами ничего не применяют. Иначе применение вердикта оказывалось бы
 * то внутри стека обработчика фаз, то внутри стека обработчика события чтения
 * сокета шины, и разница между этими двумя случаями рано или поздно выстрелила
 * бы двойной финализацией.
 */

#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "bus/ngx_http_waf_bus.h"
#include "local/ngx_http_waf_local.h"


static ngx_int_t ngx_http_waf_ctx_variable(ngx_http_request_t *r,
                     ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_waf_handshake_guard(ngx_http_waf_ctx_t *ctx);
static void      ngx_http_waf_ws_strip(ngx_http_waf_ctx_t *ctx,
                     ngx_array_t *strip);
static ngx_int_t ngx_http_waf_local_deny(ngx_http_waf_ctx_t *ctx,
                     ngx_str_t *rule, ngx_str_t *response, ngx_uint_t code);
static void      ngx_http_waf_breaker_account(ngx_http_waf_slot_t *slot,
                     uint64_t mask, ngx_uint_t timed_out);
static void      ngx_http_waf_on_deadline(ngx_event_t *ev);
static void      ngx_http_waf_body_ready(ngx_http_request_t *r);

static ngx_int_t ngx_http_waf_fail_policy(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_wave_needs_body(ngx_http_waf_ctx_t *ctx,
                     ngx_uint_t wave);
static ngx_http_waf_slot_t *ngx_http_waf_ensure_slot(ngx_http_waf_ctx_t *ctx);
static void      ngx_http_waf_discard_body(ngx_http_waf_ctx_t *ctx);
static ngx_uint_t ngx_http_waf_wave_closed(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static ngx_uint_t ngx_http_waf_wave_advances(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_settle(ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_rewrite_settle(ngx_http_waf_ctx_t *ctx,
                     ngx_http_waf_slot_t *slot);
static void      ngx_http_waf_return_to_phases(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_finish_done(ngx_http_waf_ctx_t *ctx);


/*
 * Служебная переменная-якорь для контекста. Значением никогда не пользуются:
 * важен только сам слот в r->variables, который переживает внутренний
 * редирект.
 */
static ngx_str_t  ngx_http_waf_ctx_var_name = ngx_string("waf_internal_ctx");


static ngx_int_t
ngx_http_waf_ctx_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_int_t
ngx_http_waf_ctx_var_init(ngx_conf_t *cf)
{
    ngx_int_t                  index;
    ngx_http_variable_t       *var;
    ngx_http_waf_main_conf_t  *wmcf;

    /*
     * NOHASH: переменная не должна быть доступна из конфигурации, она чисто
     * служебная.
     */
    var = ngx_http_add_variable(cf, &ngx_http_waf_ctx_var_name,
                                NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_waf_ctx_variable;

    index = ngx_http_get_variable_index(cf, &ngx_http_waf_ctx_var_name);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    wmcf->ctx_var_index = (ngx_uint_t) index;

    return NGX_OK;
}


ngx_http_waf_ctx_t *
ngx_http_waf_get_ctx(ngx_http_request_t *r)
{
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_variable_value_t  *vv;
    ngx_http_waf_main_conf_t   *wmcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx != NULL) {
        return ctx;
    }

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf->ctx_var_index == NGX_CONF_UNSET_UINT) {
        return NULL;
    }

    vv = &r->variables[wmcf->ctx_var_index];

    if (!vv->valid || vv->data == NULL) {
        return NULL;
    }

    ctx = (ngx_http_waf_ctx_t *) vv->data;

    /* восстанавливаем обнулённую редиректом связь */
    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    return ctx;
}


ngx_int_t
ngx_http_waf_set_ctx(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_variable_value_t  *vv;
    ngx_http_waf_main_conf_t   *wmcf;

    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf->ctx_var_index == NGX_CONF_UNSET_UINT) {
        return NGX_ERROR;
    }

    vv = &r->variables[wmcf->ctx_var_index];

    vv->valid        = 1;
    vv->not_found    = 0;
    vv->no_cacheable = 0;
    vv->len          = 0;
    vv->data         = (u_char *) ctx;

    return NGX_OK;
}


void
ngx_http_waf_vars_eval(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    if (wmcf->vars == NULL) {
        return;
    }

    n = wmcf->vars->nelts;

    ctx->vars = ngx_pcalloc(r->pool, n * sizeof(ngx_str_t));
    if (ctx->vars == NULL) {
        return;                        /* поля пропадут, запрос -- нет */
    }

    var = wmcf->vars->elts;

    for (i = 0; i < n; i++) {
        if (ngx_http_complex_value(r, &var[i].value, &ctx->vars[i]) != NGX_OK) {
            ngx_str_null(&ctx->vars[i]);
        }
    }
}


ngx_int_t
ngx_http_waf_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    /*
     * Подзапросы порождает не клиент, а сам nginx, и инспектировать их незачем.
     * Кроме того, подзапрос разделяет r->variables с основным запросом, то есть
     * увидел бы чужой контекст.
     */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (!wlcf->enable) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->request = r;
        ctx->state   = NGX_HTTP_WAF_ST_INIT;
        ctx->slot    = NGX_HTTP_WAF_SLOT_NIL;
        ctx->started = ngx_current_msec;

        ngx_http_waf_phase_enter(ctx, NGX_HTTP_WAF_PHASE_REQUEST);

        ctx->ph->body_policy = NGX_HTTP_WAF_POLICY_UNSET;

        /*
         * rid появляется только вместе со слотом, а слот берётся под
         * публикацию. Путей, доходящих до лога без него, два: маршрут, где все
         * инспекторы игнорируются, и отказ ещё до публикации. Прочерк вместо
         * нулей нужен потому, что rid печатается как строка фиксированной
         * длины.
         */
        ngx_memset(ctx->rid_hex, '-', NGX_HTTP_WAF_RID_HEX_LEN);

        /*
         * ray, в отличие от rid, есть у запроса всегда: он не связан со слотом
         * и потому переживает и локальный отказ, и пустую волну. UUID, не
         * счётчик -- иначе соседние значения палят RPS.
         */
        ngx_http_waf_ray_next(ctx->ray_hex);

        if (ngx_http_waf_set_ctx(r, ctx) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * Поля оператора вычисляются раньше локального слоя: его отказ едет и
         * в лог, и агенту, и там они нужны так же, как в сообщении инспектору.
         */
        ngx_http_waf_vars_eval(ctx);

        /*
         * Снятие Accept-Encoding -- до проксирования и только здесь: позже
         * заголовок уже уехал апстриму, а инспектору фазы ответа достанется
         * gzip, в котором не найти ничего.
         */
        ngx_http_waf_strip_accept_encoding(ctx);

        /*
         * Локальный слой: счётчики частоты и наборы адресов, всё решается на
         * месте и ни одного сообщения на шину. Без него шина сама становится
         * целью атаки, потому что усиливает один клиентский запрос в четыре и
         * более внутренних.
         *
         * Исход: отказать, пропустить мимо волн, либо wave -- остальные
         * local не смотрим, идём в inspect. Челлендж локальный слой не
         * назначает: кому и когда его проходить, решает сервис.
         */
        /*
         * Рукопожатие websocket-пути: снять расширения до проксирования и
         * отказать запросу без апгрейда -- до локального слоя и до шины.
         */
        rc = ngx_http_waf_handshake_guard(ctx);
        if (rc != NGX_DECLINED) {
            return rc;
        }

        rc = ngx_http_waf_local_checks(ctx);
        if (rc != NGX_DECLINED) {
            return rc;
        }

        /*
         * Спрашивать некого и тогда, когда все инспекторы фазы сняты условиями:
         * тогда не нужно ни брать слот, ни класть снимок в обменник -- ровно ради
         * этого if и пишут на дорогом маршруте.
         */
        if (ngx_http_waf_wave_count(ctx) == 0
            || !ngx_http_waf_waves_pending(ctx))
        {
            /*
             * Спрашивать некого, и фаза пишет журнал: запись агенту уходит
             * и без инспекторов, а waf_archive кладёт объекты перекладкой
             * до неё (ngx_http_waf_store_reload) -- снимка, за которым
             * архив стоял бы, здесь нет.
             */
            ctx->ph->journal = 1;
            ctx->state       = NGX_HTTP_WAF_ST_DONE;
            return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);
        }

        return ngx_http_waf_wave_start(ctx, 0);
    }

    switch (ctx->state) {

    case NGX_HTTP_WAF_ST_WAITING:
        /*
         * Повторный вход из ngx_http_core_run_phases() до прихода вердикта.
         * Случается, например, при записи в соединение: обработчик фаз
         * вызывается заново, а решения ещё нет.
         */
        return NGX_DONE;

    case NGX_HTTP_WAF_ST_NEED_BODY:
        /*
         * Состояние меняется до вызова: тело может быть уже прочитано целиком,
         * и тогда колбэк вызывается изнутри, а фазы проходятся заново из его
         * стека. Повторный вход обязан увидеть "уже читаю", а не начать чтение
         * второй раз.
         */
        ctx->state = NGX_HTTP_WAF_ST_READING_BODY;

        rc = ngx_http_read_client_request_body(r, ngx_http_waf_body_ready);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;                 /* nginx уже финализировал запрос */
        }

        /*
         * Чтение тела инкрементирует r->main->count, и компенсировать это
         * обязан вызывающий. Для access-фазы nginx не вызывает
         * ngx_http_finalize_request(), то есть декрементировать счётчик будет
         * некому и запрос не освободится никогда. Тот же порядок -- в
         * ngx_http_mirror_module.
         */
        ngx_http_finalize_request(r, NGX_DONE);

        return NGX_DONE;

    case NGX_HTTP_WAF_ST_READING_BODY:
    case NGX_HTTP_WAF_ST_PLACING_META:
    case NGX_HTTP_WAF_ST_RELOADING:
    case NGX_HTTP_WAF_ST_FETCHING_FORM:
        return NGX_DONE;

    case NGX_HTTP_WAF_ST_FINISH:
        return ngx_http_waf_finish_done(ctx);

    case NGX_HTTP_WAF_ST_NEXT_WAVE:
        return ngx_http_waf_wave_start(ctx, ctx->ph->wave);

    case NGX_HTTP_WAF_ST_DONE:
        /*
         * Решение уже применено. Такое бывает при внутреннем редиректе: фазы
         * проходятся заново с тем же ctx, и повторно опрашивать инспекторов
         * не нужно.
         */
        return NGX_DECLINED;

    default:
        return ngx_http_waf_phase_apply(ctx);
    }
}


/*
 * Единственное место, где исход фазы превращается в код возврата. На фазе
 * запроса это код фазы nginx, на фазе ответа его перечитывает фильтр: там
 * NGX_DECLINED значит "отпустить ответ", а статус -- "собрать отказ".
 *
 * Вызывается только из своего стека: из access_handler и wave_start на фазе
 * запроса, из возобновления -- на фазе ответа.
 */
ngx_int_t
ngx_http_waf_phase_apply(ngx_http_waf_ctx_t *ctx)
{
    /*
     * Объекты обменника освобождает ngx_http_waf_log_verdict(): они нужны ровно
     * до того момента, как о них написали. Раньше -- нельзя, потому что часть
     * из них модуль обязан оставить агенту, а решается это по итогу, который
     * на этом пути ещё не окончателен: политика отказа выносит его ниже.
     */
    switch (ctx->state) {

    case NGX_HTTP_WAF_ST_ALLOW:
        ctx->state = NGX_HTTP_WAF_ST_DONE;
        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);

    case NGX_HTTP_WAF_ST_DENY:
    case NGX_HTTP_WAF_ST_REDIRECT:
        ctx->state = NGX_HTTP_WAF_ST_DONE;
        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);

    default:
        /* ST_FAILED: причина в ctx->ph->fail */
        return ngx_http_waf_fail_policy(ctx);
    }
}


/*
 * Возобновление там, где обработчика фаз nginx нет: у фильтра ответа и у
 * обработчика кадров. Запрос разбирает состояние в access-обработчике, здесь
 * тот же разбор. ST_FINISH -- перекладка перед агентом либо чтение формы
 * закрылись, исход уже решён: его применяют, а не зовут политику сбоя,
 * которой phase_apply отвечает на всё, чего не знает.
 */
ngx_int_t
ngx_http_waf_phase_resume(ngx_http_waf_ctx_t *ctx)
{
    switch (ctx->state) {

    case NGX_HTTP_WAF_ST_NEXT_WAVE:
        return ngx_http_waf_wave_start(ctx, ctx->ph->wave);

    case NGX_HTTP_WAF_ST_FINISH:
        return ngx_http_waf_finish_done(ctx);

    default:
        return ngx_http_waf_phase_apply(ctx);
    }
}


ngx_int_t
ngx_http_waf_wave_start(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    ngx_int_t                  rc;
    ngx_msec_t                 budget;
    ngx_uint_t                 need;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_waf_slot_t       *slot;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    ctx->ph->wave = wave;

    /*
     * Ключ store содержит rid, а rid появляется вместе со слотом. Слот берём
     * до размещения: иначе заголовки и тело уехали бы под прочерками.
     */
    slot = ngx_http_waf_ensure_slot(ctx);
    if (slot == NULL) {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BUS;
        ctx->state    = NGX_HTTP_WAF_ST_FAILED;
        return ngx_http_waf_fail_policy(ctx);
    }

    need = ngx_http_waf_meta_wave_need(ctx, wave);

    if (!ctx->ph->meta_settled && need != 0) {
        rc = ngx_http_waf_meta_place(ctx, need);

        if (rc == NGX_AGAIN) {
            ctx->state = NGX_HTTP_WAF_ST_PLACING_META;
            return NGX_DONE;
        }

        if (rc != NGX_OK) {
            ngx_http_waf_slot_release(slot);
            ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
            ctx->state    = NGX_HTTP_WAF_ST_FAILED;
            return ngx_http_waf_fail_policy(ctx);
        }
    }

    /*
     * Тело читается настолько поздно, насколько возможно -- только когда его
     * требует очередная волна. Запрос, заблокированный на волне 0, не приводит
     * ни к чтению тела, ни к обращению к хранилищу.
     */
    if (!ctx->ph->body_ready && ngx_http_waf_wave_needs_body(ctx, wave)) {

        ctx->state = NGX_HTTP_WAF_ST_NEED_BODY;

        /*
         * Тело ответа не читают -- его отдают: оно приходит в фильтр кусками, и
         * волна ждёт, пока не наберётся снимок или пока апстрим не скажет, что
         * это было всё.
         */
        if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
            return ngx_http_waf_response_body(ctx);
        }

        /* Полезная нагрузка кадра уже на руках: размещаем, не читая. */
        if (ngx_http_waf_phase_is_frame(ctx->phase)) {
            return ngx_http_waf_frame_body(ctx);
        }

        return ngx_http_waf_access_handler(r);
    }

    /*
     * Ответы живут в контексте, а не в слоте: слот освобождается между волнами,
     * а счёт и переопределения накапливаются по всей фазе.
     */
    if (ctx->ph->replies == NULL && wmcf->inspectors.nelts != 0) {
        ctx->ph->replies = ngx_pcalloc(r->pool, wmcf->inspectors.nelts
                                                * sizeof(ngx_http_waf_reply_t));
        if (ctx->ph->replies == NULL) {
            ngx_http_waf_slot_release(slot);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_http_waf_bus_publish_wave(ctx, slot) != NGX_OK) {
        ngx_http_waf_slot_release(slot);
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BUS;
        ctx->state    = NGX_HTTP_WAF_ST_FAILED;
        return ngx_http_waf_fail_policy(ctx);
    }

    /*
     * count=waves считает опубликованные волны, а не запросы: усиление на шине
     * даёт именно волна, и запрос с четырьмя волнами стоит контуру вчетверо
     * дороже одноволнового. Решения здесь уже не принимается -- волна
     * опубликована, и отменять её поздно; учтётся она на следующем запросе.
     */
    ngx_http_waf_rate_charge_wave(ctx);

    /*
     * Волна могла закрыться прямо здесь: все её инспекторы совещательные, или
     * шина сразу сообщила об отсутствии подписчиков. Публикация намеренно не
     * возвращает запрос в фазы сама -- мы всё ещё внутри обработчика фазы, и
     * возврат делается кодом, а не повторным входом.
     */
    if (ngx_http_waf_wave_closed(ctx, slot)) {

        ngx_http_waf_rewrite_settle(ctx, slot);

        if (ngx_http_waf_wave_advances(ctx, slot)) {
            ngx_http_waf_slot_release(slot);
            return ngx_http_waf_wave_start(ctx, wave + 1);
        }

        if (ctx->deadline.timer_set) {
            ngx_del_timer(&ctx->deadline);
        }

        ngx_http_waf_slot_release(slot);
        ngx_http_waf_resolve_verdict(ctx);

        return ngx_http_waf_phase_apply(ctx);
    }

    /*
     * Дедлайн вооружается один раз на фазу, а не на волну: он гарантирует
     * клиенту верхнюю границу независимо от числа волн и от того, как
     * инспекторы распорядились своими таймаутами.
     */
    if (!ctx->deadline.timer_set) {
        budget = wlcf->deadline[ctx->phase];

        ctx->deadline.handler = ngx_http_waf_on_deadline;
        ctx->deadline.data    = ctx;
        ctx->deadline.log     = r->connection->log;

        ngx_add_timer(&ctx->deadline, budget);
    }

    /*
     * Пока мы ждём вердикт, клиент может уйти. Без ngx_http_test_reading
     * оборванные соединения продолжают занимать слоты, а при сотнях запросов в
     * полёте это исчерпание таблицы.
     *
     * На кадрах обработчики -- наши и остаются на месте: соединение живёт,
     * и обрыв клиента увидит сам обработчик кадров.
     */
    if (!ngx_http_waf_phase_is_frame(ctx->phase)) {
        r->read_event_handler  = ngx_http_test_reading;
        r->write_event_handler = ngx_http_request_empty_handler;
    }

    ctx->state   = NGX_HTTP_WAF_ST_WAITING;
    ctx->waiting = 1;

    return NGX_DONE;
}


/* Все, кого волна обязана дождаться, разрешены: ответом либо отсутствием. */
static ngx_uint_t
ngx_http_waf_wave_closed(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    return (slot->got & slot->awaited) == slot->awaited;
}


static ngx_uint_t
ngx_http_waf_wave_advances(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    ngx_http_waf_wave_t  *wave;

    if (ctx->ph->wave + 1 >= ngx_http_waf_wave_count(ctx)) {
        return 0;
    }

    /*
     * Отказ обязательного инспектора и отказ шины заканчивают фазу здесь:
     * следующая волна всё равно не может отменить уже полученный deny, а её
     * публикация -- это лишняя нагрузка ровно на атакующем трафике.
     */
    if (ctx->ph->fail != NGX_HTTP_WAF_CODE_NONE) {
        return 0;
    }

    wave = ngx_http_waf_current_wave(ctx);

    /*
     * Совещательный в маску не входит: его deny -- сто очков, а не отказ,
     * и дальние волны должны увидеть их в prior.
     */
    if (wave != NULL
        && (slot->denied & ngx_http_waf_wave_gating(ctx, wave)))
    {
        return 0;
    }

    return 1;
}


void
ngx_http_waf_on_reply(ngx_http_waf_slot_t *slot, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    uint64_t                  bit;
    ngx_http_waf_ctx_t       *ctx = slot->ctx;
    ngx_http_waf_wave_t      *wave;
    ngx_http_waf_loc_conf_t  *wlcf;

    wave = ngx_http_waf_current_wave(ctx);
    if (wave == NULL) {
        return;
    }

    bit = 1ULL << index;

    /*
     * Изоляция: ответ от инспектора, которого в этой волне не спрашивали, не
     * выставляет ни одного бита. Скомпрометированный инспектор не может
     * ответить за другого.
     */
    if (!(bit & wave->all)) {
        return;
    }

    /* Дедупликация: повторная доставка не засчитывается вторым подтверждением */
    if (slot->got & bit) {
        return;
    }

    slot->got |= bit;
    ctx->ph->got  |= bit;

    /*
     * Отказом предохранителю считается отсутствие годного вердикта, и error --
     * ровно оно: инспектор ответил, но работу не выполнил. Не считать его
     * отказом значило бы дать способ быть сломанным и здоровым одновременно --
     * отвечай error, и предохранитель никогда не откроется.
     */
    ngx_http_waf_breaker_account(slot, bit,
                                 reply->verdict == NGX_HTTP_WAF_V_ERROR);

    if (ctx->ph->replies != NULL) {
        ctx->ph->replies[index]          = *reply;
        ctx->ph->replies[index].received = 1;
        ctx->ph->replies[index].state    = NGX_HTTP_WAF_ENTRY_ANSWERED;
        ctx->ph->replies[index].passive  =
            (ngx_http_waf_wave_passive(ctx, wave) & bit) ? 1 : 0;
        ctx->ph->replies[index].vote     =
            (ngx_http_waf_wave_vote(ctx, wave) & bit) ? 1 : 0;
        ctx->ph->replies[index].latency  = ngx_current_msec - slot->published;
        ctx->ph->replies[index].wave     = slot->wave;

        ngx_http_waf_account(ctx, index, &ctx->ph->replies[index]);

        /*
         * Действия -- после того, как известна пассивность отправителя на
         * маршруте: метку ставит модуль, и без неё просьба теневого инспектора
         * доехала бы до соседа неотличимой от боевой.
         *
         * На кадрах живой набор -- копия набора рукопожатия в пуле кадра
         * (stream/ngx_http_waf_frame.c): просьба первой волны видна второй,
         * а с концом кадра умирает вместе с его пулом. Между кадрами
         * переписка не переносится.
         */
        ngx_http_waf_actions_merge(ctx, index, &ctx->ph->replies[index],
                                   slot->wave);

        /* Сессии -- туда же: метку пассивности тоже ставит модуль. */
        ngx_http_waf_sessions_merge(ctx, index, &ctx->ph->replies[index]);
    }

    /*
     * "Проверить не смог". Для волны это не вердикт, а признанное его
     * отсутствие -- то же, что молчание, но названное вслух и сразу: ждать
     * дедлайна незачем, инспектор уже ответил.
     *
     * Обязательный срывает волну (исход выбирает waf_exception класса
     * inspector); совещательный здесь обязательный -- его ждут ради очков, и
     * сломанный он так же лишает сумму вклада. Пассивный -- нет: он не
     * гейтит, и его поломка не должна ни блокировать запрос, ни занижать
     * счёт. Причина (reason.code) остаётся в записи участника -- по ней и
     * разбирают, что именно у инспектора сломалось.
     */
    if (reply->verdict == NGX_HTTP_WAF_V_ERROR) {

        if (bit & ngx_http_waf_wave_mandatory(ctx, wave)) {
            /* Сброс на входе судится своим классом waf_exception. */
            ctx->ph->fail = reply->overload
                                ? NGX_HTTP_WAF_CODE_FAIL_OVERLOAD
                                : NGX_HTTP_WAF_CODE_FAIL_INSPECTOR;
            ngx_http_waf_resume(slot);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: non-gating inspector %ui could not inspect", index);

        ngx_http_waf_settle(slot);
        return;
    }

    /*
     * denied -- это только безоговорочный отказ, а не любой неразрешающий
     * вердикт. score в маску не попадает намеренно: он ничего не решает сам, и
     * если считать его отказом, следующая волна не публикуется -- а именно её
     * инспекторы и должны увидеть накопленный счёт в prior.
     */
    if (reply->verdict == NGX_HTTP_WAF_V_DENY
        || reply->verdict == NGX_HTTP_WAF_V_REDIRECT)
    {
        slot->denied |= bit;

        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        /*
         * Короткое замыкание. Первый deny экономит весь остаток бюджета, и
         * именно это защищает дорогие инспекторы от нагрузки на атакующем
         * трафике. Плата -- при двух почти одновременных deny победитель
         * определяется гонкой; кому это неприемлемо, ставит deterministic.
         *
         * Замыкает только гейтящий инспектор: пассивный не гейтит по
         * определению, совещательный -- тоже (его deny -- очки), и их
         * вердикт не должен обрывать волну.
         */
        if (wlcf->deny_mode[ctx->phase] == NGX_HTTP_WAF_DENY_FAST
            && (bit & ngx_http_waf_wave_gating(ctx, wave)))
        {
            ngx_http_waf_resume(slot);
            return;
        }
    }

    ngx_http_waf_settle(slot);
}


/*
 * Инспекторы, которых на этом запросе не спрашивают: if не сошёлся. Отмечаются
 * до публикации волны, одним движением и без ngx_http_waf_settle() -- волна ещё
 * не начата, и закрывать здесь нечего.
 *
 * Не skip: там ответа ждали и не дождались, и это включает класс absent. Здесь
 * вопроса не было, и обязательным такой инспектор для волны не является.
 */
void
ngx_http_waf_omit(ngx_http_waf_slot_t *slot, ngx_http_waf_mask_t mask,
    ngx_uint_t state)
{
    uint64_t             bit;
    ngx_uint_t           index;
    ngx_http_waf_ctx_t  *ctx = slot->ctx;

    /*
     * Снятые условием -- пропуск маршрута; выключенные (mode=off свой или
     * поставленный соседом) -- решение контура, и в аудите они видны со своим
     * состоянием, а кеш кадров их не считает сбоем.
     */
    if (state == NGX_HTTP_WAF_ENTRY_SKIPPED) {
        ctx->ph->skipped |= mask;

    } else {
        ctx->ph->controlled |= mask;
    }

    slot->got |= mask;

    while (mask) {
        index = ngx_http_waf_lowest_bit(mask);
        bit   = 1ULL << index;
        mask &= ~bit;

        if (ctx->ph->replies != NULL) {
            ctx->ph->replies[index].state = state;
        }
    }
}


void
ngx_http_waf_skip(ngx_http_waf_slot_t *slot, ngx_uint_t index, ngx_uint_t code)
{
    uint64_t              bit;
    ngx_http_waf_ctx_t   *ctx = slot->ctx;
    ngx_http_waf_wave_t  *wave;

    wave = ngx_http_waf_current_wave(ctx);
    if (wave == NULL) {
        return;
    }

    bit = 1ULL << index;

    if (!(bit & wave->all) || (slot->got & bit)) {
        return;
    }

    slot->got    |= bit;
    ctx->ph->skipped |= bit;

    /*
     * Отсутствие подписчиков -- это "инспектора некому спросить", а отказ
     * публикации и разомкнутый предохранитель -- "мы его не спрашивали".
     * Дедлайн сюда не приходит вовсе: там ответа ждали, и это timeout,
     * который выводится из published & ~got при записи аудита.
     */
    if (ctx->ph->replies != NULL) {
        ctx->ph->replies[index].state =
            (code == NGX_HTTP_WAF_CODE_FAIL_ABSENT)
                ? NGX_HTTP_WAF_ENTRY_ABSENT
                : NGX_HTTP_WAF_ENTRY_SKIPPED;
    }

    /*
     * Ответа не будет. Для обязательного (и совещательного: его ждут ради
     * очков) это причина применить политику отказа, для пассивного -- только
     * запись в лог: он не гейтит, и его отсутствие не должно ни блокировать
     * запрос, ни занижать счёт.
     */
    if (bit & ngx_http_waf_wave_mandatory(ctx, wave)) {
        ctx->ph->fail = code;

    } else {
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: non-gating inspector %ui gave no verdict (%V)",
                      index, ngx_http_waf_code_name(code));
    }

    ngx_http_waf_settle(slot);
}


/*
 * Версии объекта по итогам волны. Инспектор не правит объект на месте: он
 * кладёт свою версию рядом и называет её ключ секцией rewrite. Здесь волна
 * закрыта, и модуль решает, что считать актуальным дальше: принятая версия
 * становится локатором следующей волны (та читает её и наращивает на её ключе
 * свой), а получателю уходит последнее звено цепочки.
 *
 * Оригинал не трогается: он остаётся в ph->locator, и по нему живут аудит,
 * архив и превью. Прежняя версия не удаляется на месте -- волна, принявшая
 * подмену, ещё не знает, доживёт ли запрос до отдачи; ключи копятся в
 * ph->stale и уходят вместе со своими объектами при разрешении вердикта.
 *
 * Две секции на одной волне -- не конкурс. Инспекторы волны видели один и тот
 * же объект и правили его параллельно: взять "последнюю" значит молча потерять
 * чужую правку, взять "первую по объявлению" -- то же самое с другим порядком.
 * Собрать версию модуль не может, и это исключение класса body, как и всякая
 * несобранная подмена (docs/verdict-protocol.md). Тем же классом кончается
 * упёршаяся глубина цепочки: растёт не число объектов, а длина ключа,
 * производного от предыдущего.
 *
 * Отказ сюда не попадает: rewrite при deny -- это тело собственного отказа
 * (форма входа, виджет капчи), его поднимает ngx_http_waf_form_fetch(), и
 * версией объекта фазы оно не становится.
 */
static void
ngx_http_waf_rewrite_settle(ngx_http_waf_ctx_t *ctx, ngx_http_waf_slot_t *slot)
{
    ngx_str_t                 *stale;
    ngx_uint_t                 i, n, found;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_locator_t    *live, *from;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->replies == NULL) {
        return;
    }

    wmcf  = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp  = wmcf->inspectors.elts;
    n     = wmcf->inspectors.nelts;
    found = NGX_HTTP_WAF_MAX_INSPECTORS;

    for (i = 0; i < n; i++) {

        if (!(slot->got & (1ULL << i))) {
            continue;                       /* ответ не этой волны */
        }

        reply = &ctx->ph->replies[i];

        if (!reply->received || reply->passive || reply->vote
            || !reply->rewrite_has || !reply->rewrite_body
            || reply->verdict == NGX_HTTP_WAF_V_DENY)
        {
            continue;
        }

        if (found != NGX_HTTP_WAF_MAX_INSPECTORS) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: inspectors \"%V\" and \"%V\" both rewrote the "
                          "%V body on wave %ui; the version cannot be "
                          "assembled, waf_exception %V body decides, ray %*s",
                          &insp[found].name, &insp[i].name,
                          ngx_http_waf_phase_name(ctx->phase), ctx->ph->wave,
                          ngx_http_waf_phase_name(ctx->phase),
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

            ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
            return;
        }

        found = i;
    }

    if (found == NGX_HTTP_WAF_MAX_INSPECTORS) {
        return;
    }

    if (ctx->ph->rewrite_depth >= NGX_HTTP_WAF_REWRITE_MAX_DEPTH) {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: inspector \"%V\" rewrote the %V body past the "
                      "chain limit of %ui versions; waf_exception %V body "
                      "decides, ray %*s",
                      &insp[found].name, ngx_http_waf_phase_name(ctx->phase),
                      (ngx_uint_t) NGX_HTTP_WAF_REWRITE_MAX_DEPTH,
                      ngx_http_waf_phase_name(ctx->phase),
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
        return;
    }

    reply = &ctx->ph->replies[found];

    /*
     * Версия наследует адресацию объекта -- драйвер и store те же, менялось
     * только содержимое. Размер и хеш называет реплай: модуль объект не читал
     * и прочтёт его один раз, на отдаче.
     */
    from = ngx_http_waf_store_locator_live(ctx, ctx->phase,
                                           NGX_HTTP_WAF_OBJ_BODY);
    if (from == NULL) {
        return;                            /* объекта не было -- нечего вести */
    }

    live = ngx_palloc(ctx->request->pool, sizeof(ngx_http_waf_locator_t));
    if (live == NULL) {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
        return;
    }

    *live                  = *from;
    live->key              = reply->rewrite_key;
    live->size             = reply->rewrite_size;
    live->truncated        = 0;
    live->inline_data.data = NULL;
    live->inline_data.len  = 0;

    if (reply->rewrite_sha256_set) {
        ngx_memcpy(live->sha256, reply->rewrite_sha256, 32);

    } else {
        ngx_memzero(live->sha256, 32);
    }

    /*
     * Прежняя версия больше никому не нужна -- но удалять её сейчас нельзя:
     * запрос может не дойти до отдачи, а объект уже был бы стёрт. Оригинал в
     * этот список не попадает никогда: им распоряжается архив.
     */
    if (ctx->ph->live != NULL) {

        if (ctx->ph->stale == NULL) {
            ctx->ph->stale = ngx_array_create(ctx->request->pool, 2,
                                              sizeof(ngx_str_t));
            if (ctx->ph->stale == NULL) {
                ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
                return;
            }
        }

        stale = ngx_array_push(ctx->ph->stale);
        if (stale == NULL) {
            ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
            return;
        }

        *stale = ctx->ph->live->key;
    }

    ctx->ph->live         = live;
    ctx->ph->rewrite_last = found;
    ctx->ph->rewrite_depth++;
    ctx->ph->rewrite_applied |= 1ULL << found;

    ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                  "waf: inspector \"%V\" published version %ui of the %V body, "
                  "%O bytes, ray %*s",
                  &insp[found].name, ctx->ph->rewrite_depth,
                  ngx_http_waf_phase_name(ctx->phase), live->size,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
}


/*
 * Закрытие волны в асинхронном контексте: колбэк шины или таймера. Решение
 * здесь не применяется -- запрос возвращается в фазы, где его примет
 * access_handler.
 */
static void
ngx_http_waf_settle(ngx_http_waf_slot_t *slot)
{
    ngx_http_waf_ctx_t  *ctx = slot->ctx;

    /*
     * Пока запрос не начал ждать, мы находимся внутри обработчика фазы: волну
     * закрывает ngx_http_waf_wave_start() кодом возврата. Возврат в фазы отсюда
     * означал бы повторный вход в них из их же стека.
     */
    if (!ctx->waiting) {
        return;
    }

    if (!ngx_http_waf_wave_closed(ctx, slot)) {
        return;
    }

    ngx_http_waf_rewrite_settle(ctx, slot);

    if (ngx_http_waf_wave_advances(ctx, slot)) {
        /*
         * Слот освобождается перед публикацией следующей волны: каждая волна
         * получает свой rid, поэтому опоздавший ответ предыдущей волны не
         * попадает в набор текущей.
         */
        ngx_http_waf_slot_release(slot);

        ctx->ph->wave++;
        ctx->state = NGX_HTTP_WAF_ST_NEXT_WAVE;

        ngx_http_waf_return_to_phases(ctx);
        return;
    }

    ngx_http_waf_resume(slot);
}


void
ngx_http_waf_resume(ngx_http_waf_slot_t *slot)
{
    ngx_http_waf_ctx_t  *ctx = slot->ctx;

    if (ctx == NULL) {
        return;
    }

    if (ctx->deadline.timer_set) {
        ngx_del_timer(&ctx->deadline);
    }

    ngx_http_waf_slot_release(slot);
    ngx_http_waf_resolve_verdict(ctx);

    ngx_http_waf_return_to_phases(ctx);
}


void
ngx_http_waf_fail(ngx_http_waf_slot_t *slot, ngx_uint_t code)
{
    ngx_http_waf_ctx_t   *ctx = slot->ctx;
    ngx_http_waf_wave_t  *wave;

    if (ctx == NULL) {
        return;
    }

    wave = ngx_http_waf_current_wave(ctx);

    /*
     * Молчавшие к дедлайну -- это и есть та самая доля таймаутов, по которой
     * открывается breaker. Считаются все, кого волна ждала, а не только
     * обязательные: отключать инспектор надо и тогда, когда он совещательный, --
     * иначе он продолжает съедать бюджет фазы, ничего не добавляя.
     */
    if (code == NGX_HTTP_WAF_CODE_FAIL_TIMEOUT) {
        ngx_http_waf_breaker_account(slot, slot->awaited & ~slot->got, 1);
    }

    /*
     * Не хватает только пассивных ответов -- это не отказ. Пассивный инспектор
     * заведён ровно для того, чтобы наблюдать за ним, не отдавая ему решение, и
     * его молчание не должно превращаться в 503 по политике дедлайна.
     */
    if (wave != NULL
        && (slot->got & ngx_http_waf_wave_mandatory(ctx, wave))
           == ngx_http_waf_wave_mandatory(ctx, wave))
    {
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: non-gating inspectors did not answer in time, "
                      "mask %uxL",
                      (uint64_t) (ngx_http_waf_wave_passive(ctx, wave)
                                  & ~slot->got));

    } else {
        ctx->ph->fail = code;
    }

    ngx_http_waf_resume(slot);
}


/*
 * Возврат запроса в обработчик фаз. Обработчики событий соединения обязаны быть
 * восстановлены до вызова: пока запрос ждал вердикт, чтение обслуживал
 * ngx_http_test_reading.
 */
static void
ngx_http_waf_return_to_phases(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    /*
     * У ответа фаз нет: его доигрывают фильтры, и возврат туда -- своя
     * функция. Одно ветвление здесь дешевле, чем второй колбэк шины.
     */
    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        ngx_http_waf_response_resume(ctx);
        return;
    }

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        ngx_http_waf_frame_resume(ctx);
        return;
    }

    ctx->waiting = 0;

    r->read_event_handler  = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;

    ngx_http_core_run_phases(r);
}


static void
ngx_http_waf_on_deadline(ngx_event_t *ev)
{
    ngx_http_waf_ctx_t   *ctx = ev->data;
    ngx_http_waf_slot_t  *slot;

    slot = ngx_http_waf_slot_lookup(ctx->rid);
    if (slot == NULL) {
        return;                        /* гонка с приходом последнего ответа */
    }

    ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                  "waf: deadline expired on wave %ui, awaited %uxL, got %uxL, "
                  "rid %*s",
                  ctx->ph->wave, (uint64_t) slot->awaited, (uint64_t) slot->got,
                  (size_t) NGX_HTTP_WAF_RID_HEX_LEN, ctx->rid_hex);

    ngx_http_waf_fail(slot, NGX_HTTP_WAF_CODE_FAIL_TIMEOUT);
}


static void
ngx_http_waf_body_ready(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_waf_get_ctx(r);
    if (ctx == NULL) {
        return;
    }

    ctx->ph->body_ready = 1;

    /*
     * Без preserve_body внутренний редирект обнуляет r->request_body, а вместе
     * с ним и тело, которое уже размещено и обещано инспектору локатором.
     */
    r->preserve_body = 1;

    if (ctx->ph->reload_after_body) {
        ngx_http_waf_body_resumed(ctx, NGX_OK);
        return;
    }

    rc = ngx_http_waf_body_place(ctx);

    if (rc == NGX_AGAIN) {
        return;                        /* драйвер вернёт запрос в фазы сам */
    }

    ngx_http_waf_body_resumed(ctx, rc);
}


void
ngx_http_waf_form_resumed(ngx_http_waf_ctx_t *ctx)
{
    ctx->state = NGX_HTTP_WAF_ST_FINISH;
    ngx_http_waf_return_to_phases(ctx);
}


void
ngx_http_waf_body_resumed(ngx_http_waf_ctx_t *ctx, ngx_int_t rc)
{
    if (ctx->ph->reload_after_body) {
        ctx->ph->reload_after_body = 0;

        rc = ngx_http_waf_store_reload(ctx);

        if (rc == NGX_AGAIN) {
            ctx->state = NGX_HTTP_WAF_ST_RELOADING;
            ngx_http_waf_return_to_phases(ctx);
            return;
        }

        ctx->state = NGX_HTTP_WAF_ST_FINISH;
        ngx_http_waf_return_to_phases(ctx);
        return;
    }

    if (ctx->ph->reloading) {
        if (ctx->ph->reload_issuing
            || ctx->ph->meta_pending != 0
            || (ctx->ph->body_op != NULL && !ctx->ph->body_settled))
        {
            return;
        }

        ctx->ph->store_raw      = 0;
        ctx->ph->store_reloaded = 1;
        ctx->ph->reloading      = 0;
        ctx->state          = NGX_HTTP_WAF_ST_FINISH;
        ngx_http_waf_return_to_phases(ctx);
        return;
    }

    if (rc != NGX_OK) {
        ctx->ph->fail = NGX_HTTP_WAF_CODE_FAIL_BODY;
        ctx->state    = NGX_HTTP_WAF_ST_FAILED;

    } else if (ctx->state == NGX_HTTP_WAF_ST_NEED_BODY
               || ctx->state == NGX_HTTP_WAF_ST_READING_BODY
               || ctx->state == NGX_HTTP_WAF_ST_PLACING_META)
    {
        /*
         * Волна, потребовавшая тела, ещё не публиковалась: ctx->ph->wave не
         * менялся, и NEXT_WAVE означает "опубликовать её теперь".
         */
        ctx->state = NGX_HTTP_WAF_ST_NEXT_WAVE;

    } else {
        ctx->state = NGX_HTTP_WAF_ST_NEXT_WAVE;
    }

    ngx_http_waf_return_to_phases(ctx);
}


/*
 * Локальный слой целиком: наборы данных, затем счётчики частоты. NGX_DECLINED --
 * продолжать инспекцию.
 *
 * Порядок именно такой. Разрешающий набор -- это список того, что проверять не
 * надо вовсе: собственные пробы, партнёрские интеграции, служебные адреса. Если
 * бы лимит частоты применялся раньше, разрешающий список перестал бы что-либо
 * значить ровно там, где он нужен -- на нагрузочном тесте со своего же адреса.
 */
ngx_int_t
ngx_http_waf_local_checks(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;
    ngx_str_t  rule, response;

    if (ngx_http_waf_shm() == NULL) {
        return NGX_DECLINED;           /* зоны нет -- локального слоя нет */
    }

    ngx_str_null(&rule);
    ngx_str_null(&response);

    rc = ngx_http_waf_dataset_check(ctx, &rule, &response);

    if (rc == NGX_ERROR) {
        return ngx_http_waf_local_deny(ctx, &rule, &response,
                                       NGX_HTTP_WAF_CODE_LOCAL_LIST);
    }

    if (rc == NGX_DONE) {
        /* wave: rate и остальные check ниже не смотрим */
        return NGX_DECLINED;
    }

    if (rc == NGX_OK) {
        ctx->ph->verdict = NGX_HTTP_WAF_V_ALLOW;
        ctx->state   = NGX_HTTP_WAF_ST_DONE;

        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: allowed by local check \"%V\", ray %*s", &rule,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);
    }

    rc = ngx_http_waf_rate_check(ctx, &rule, &response);

    if (rc == NGX_DECLINED) {
        return ngx_http_waf_local_deny(ctx, &rule, &response,
                                       NGX_HTTP_WAF_CODE_LOCAL_RATE);
    }

    return NGX_DECLINED;
}


static ngx_str_t  ngx_http_waf_upgrade_rule = ngx_string("require_upgrade");


/*
 * Рукопожатие websocket-пути. Расширения снимаются из запроса всегда, когда
 * названы: это правка заголовка, а не решение. Запрос без `Upgrade: websocket`
 * на пути с waf_require_upgrade отказывается как локальный: у такого пути
 * фазы ответа нет, и проксировать обычный GET значило бы отдать клиенту
 * ответ, которого никто не проверил.
 */
static ngx_int_t
ngx_http_waf_handshake_guard(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                upgrade;
    ngx_table_elt_t          *h;
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->ws_strip_ext != NULL && wlcf->ws_strip_ext->nelts != 0) {
        ngx_http_waf_ws_strip(ctx, wlcf->ws_strip_ext);
    }

    if (wlcf->require_upgrade != 1) {
        return NGX_DECLINED;
    }

    h = r->headers_in.upgrade;

    upgrade = (h != NULL && h->hash != 0
               && h->value.len == sizeof("websocket") - 1
               && ngx_strncasecmp(h->value.data, (u_char *) "websocket",
                                  sizeof("websocket") - 1) == 0);

    if (upgrade) {
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: request without websocket upgrade on a websocket "
                  "location, denied, ray %*s",
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    return ngx_http_waf_local_deny(ctx, &ngx_http_waf_upgrade_rule,
                                   &wlcf->require_upgrade_response,
                                   NGX_HTTP_WAF_CODE_LOCAL_UPGRADE);
}


/*
 * Sec-WebSocket-Extensions: список предложений через запятую, у каждого имя
 * до первой точки с запятой. Названные снимаются, остальные остаются.
 * Пустой остаток заголовок не убирает -- прокси копирует список как есть, а
 * уплотнение списка ломает кэшированные указатели (см. apply.c); заголовок
 * переименовывается, и апстрим получает предложение под именем, которого не
 * читает.
 */
static void
ngx_http_waf_ws_strip(ngx_http_waf_ctx_t *ctx, ngx_array_t *strip)
{
    u_char              *p, *start, *end, *name_end, *out, *o;
    size_t               i, n;
    ngx_str_t           *names, name;
    ngx_uint_t           all, kept, removed;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h, *ext;
    ngx_http_request_t  *r = ctx->request;

    part = &r->headers_in.headers.part;
    h    = part->elts;
    ext  = NULL;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].hash != 0
            && h[i].key.len == sizeof("Sec-WebSocket-Extensions") - 1
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "Sec-WebSocket-Extensions",
                               h[i].key.len) == 0)
        {
            ext = &h[i];
            break;
        }
    }

    if (ext == NULL || ext->value.len == 0) {
        return;
    }

    names = strip->elts;
    n     = strip->nelts;
    all   = 0;

    for (i = 0; i < n; i++) {
        if (names[i].len == 3 && ngx_strncmp(names[i].data, "all", 3) == 0) {
            all = 1;
        }
    }

    out = ngx_pnalloc(r->pool, ext->value.len);
    if (out == NULL) {
        return;
    }

    o       = out;
    kept    = 0;
    removed = 0;
    p       = ext->value.data;
    end     = ext->value.data + ext->value.len;

    while (p < end) {

        /* одно предложение: до запятой, имя -- до точки с запятой */
        start = p;

        while (p < end && *p != ',') {
            p++;
        }

        name_end = start;

        while (name_end < p && *name_end != ';') {
            name_end++;
        }

        name.data = start;
        name.len  = name_end - start;

        while (name.len != 0 && (name.data[0] == ' ' || name.data[0] == '\t')) {
            name.data++;
            name.len--;
        }

        while (name.len != 0 && (name.data[name.len - 1] == ' '
                                 || name.data[name.len - 1] == '\t'))
        {
            name.len--;
        }

        if (all) {
            removed++;

        } else {
            for (i = 0; i < n; i++) {
                if (names[i].len == name.len
                    && ngx_strncasecmp(names[i].data, name.data, name.len)
                       == 0)
                {
                    break;
                }
            }

            if (i < n) {
                removed++;

            } else {
                if (kept != 0) {
                    *o++ = ',';
                }

                o = ngx_cpymem(o, start, p - start);
                kept++;
            }
        }

        if (p < end) {
            p++;                       /* запятая */
        }
    }

    if (removed == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "waf: stripped %ui websocket extension(s) from the "
                  "handshake, %ui left, ray %*s", removed, kept,
                  (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

    if (kept != 0) {
        ext->value.data = out;
        ext->value.len  = o - out;
        return;
    }

    ngx_str_set(&ext->key, "X-WAF-Stripped-Extensions");

    ext->lowcase_key = ngx_pnalloc(r->pool, ext->key.len);
    if (ext->lowcase_key == NULL) {
        ext->hash = 0;
        return;
    }

    ngx_strlow(ext->lowcase_key, ext->key.data, ext->key.len);
    ext->hash = ngx_hash_key(ext->lowcase_key, ext->key.len);
}


/*
 * code различает список и лимит частоты. Отличать их по имени сработавшего
 * правила нельзя: имя набора задаёт оператор, и совпадение с любой строкой,
 * которую выбрал бы модуль, -- вопрос времени.
 */
static ngx_int_t
ngx_http_waf_local_deny(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule,
    ngx_str_t *response, ngx_uint_t code)
{
    ctx->by_local        = 1;
    ctx->local_rule      = *rule;
    ctx->local_response  = *response;
    ctx->ph->code            = code;
    ctx->ph->verdict         = NGX_HTTP_WAF_V_DENY;
    ctx->state           = NGX_HTTP_WAF_ST_DONE;

    /*
     * Тело не сбрасываем до reload: archive-only body ещё не читали, а агенту
     * оно нужно. discard -- после записи.
     */
    return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_APPLY);
}


/*
 * Учёт исхода в circuit breaker. Единственное место, где ответы и молчание
 * превращаются в статистику инспектора: считать это в разборе ответа нельзя --
 * там ещё не известно, дождалась ли его волна.
 */
static void
ngx_http_waf_breaker_account(ngx_http_waf_slot_t *slot, uint64_t mask,
    ngx_uint_t timed_out)
{
    uint64_t                   bit;
    ngx_uint_t                 index;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    if (mask == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(slot->ctx->request,
                                        ngx_http_waf_module);
    inspectors = wmcf->inspectors.elts;

    while (mask) {
        index = ngx_http_waf_lowest_bit(mask);
        bit   = 1ULL << index;
        mask &= ~bit;

        if (index >= wmcf->inspectors.nelts) {
            continue;
        }

        ngx_http_waf_breaker_result(index, &inspectors[index], timed_out);
    }
}


static ngx_int_t
ngx_http_waf_wave_needs_body(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    /*
     * Волна ждёт put только если тело в capture. Archive и preview кладут
     * оригинал после вердикта, до агента -- волну это не держит.
     */
    return (ngx_http_waf_body_wave_need(ctx, wave) != NGX_HTTP_WAF_BODY_NONE);
}


static ngx_http_waf_slot_t *
ngx_http_waf_ensure_slot(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->slot != NGX_HTTP_WAF_SLOT_NIL) {
        return ngx_http_waf_slot_lookup(ctx->rid);
    }

    return ngx_http_waf_slot_acquire(ctx);
}


static ngx_int_t
ngx_http_waf_fail_policy(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                exc, policy, reason;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    /*
     * Причина берётся из ctx->ph->fail, а не из ctx->state: к моменту выбора
     * политики состояние уже могло стать ALLOW -- резолюция вердикта выполняется
     * и при частичном наборе ответов. Ровно на этом и ломалась политика
     * дедлайна в первой версии: она выбиралась по состоянию, состояние было
     * ALLOW, и блокировки не происходило.
     */
    reason     = ctx->ph->fail;
    ctx->state = NGX_HTTP_WAF_ST_DONE;

    exc = NGX_HTTP_WAF_EXC_TIMEOUT;

    /*
     * Одна директива, но класс события сохранён: отсутствие подписчиков -- это
     * ошибка развёртывания, а не перегрузка, и политика для неё другая.
     */
    exc    = ngx_http_waf_exc_of(reason);
    policy = wlcf->exception[ctx->phase][exc];

    /*
     * У недоступного тела политику мог выбрать тот, кто её обнаружил:
     * превышение размера решается вторым словом waf_body_limit, а отказ
     * хранилища -- классом body, и по состоянию их не отличить.
     */
    if (exc == NGX_HTTP_WAF_EXC_BODY
        && ctx->ph->body_policy != NGX_HTTP_WAF_POLICY_UNSET)
    {
        policy = ctx->ph->body_policy;
    }

    ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                  "waf: no verdict (%V), policy %s",
                  ngx_http_waf_code_name(reason),
                  policy == NGX_HTTP_WAF_POLICY_PASS ? "pass" : "block");

    /*
     * Код срыва волны ставится только на блокировке. Пропуск по политике -- это
     * итог allow, а у allow причины нет: запрос прошёл, и объяснять нечего.
     */
    if (policy != NGX_HTTP_WAF_POLICY_PASS) {
        ctx->ph->code         = reason;
        ctx->ph->fail_blocked = 1;

        /*
         * Чем отвечать, знает только конфигурация: у сбоя нет ни инспектора,
         * ни правила, которые назвали бы запись. Не названа -- 503 без
         * каталога, как отвечал модуль до появления директивы.
         */
        ctx->exception_response = wlcf->exception_response[ctx->phase][exc];
    }

    if (policy == NGX_HTTP_WAF_POLICY_PASS) {
        /*
         * Переопределения от успевших инспекторов применяются и здесь: они
         * валидны сами по себе, и это зафиксированное поведение, а не деталь
         * реализации.
         */
        return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_OVERRIDES);
    }

    return ngx_http_waf_finish(ctx, NGX_HTTP_WAF_FINISH_FAIL);
}


ngx_int_t
ngx_http_waf_finish(ngx_http_waf_ctx_t *ctx, ngx_uint_t how)
{
    ngx_int_t  rc;

    ctx->finish_how = how;

    if (!ctx->ph->store_reloaded) {

        if (ngx_http_waf_store_reload_needs_body(ctx)) {
            ctx->ph->reload_after_body = 1;
            ctx->state             = NGX_HTTP_WAF_ST_NEED_BODY;
            return ngx_http_waf_access_handler(ctx->request);
        }

        rc = ngx_http_waf_store_reload(ctx);

        if (rc == NGX_AGAIN) {
            ctx->state = NGX_HTTP_WAF_ST_RELOADING;
            return NGX_DONE;
        }
    }

    return ngx_http_waf_finish_done(ctx);
}


static ngx_int_t
ngx_http_waf_finish_done(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t  rc;

    /*
     * У кадра нет ни страницы отказа, ни переопределений заголовков, ни тела
     * на выброс: исход -- пропустить кадр либо закрыть соединение.
     */
    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return ngx_http_waf_frame_finish(ctx, ctx->finish_how);
    }

    switch (ctx->finish_how) {

    case NGX_HTTP_WAF_FINISH_APPLY:
        /*
         * Тело отказа из обменника читается до применения: apply пишет лог
         * вердикта, и второй заход в него после чтения удвоил бы запись.
         */
        rc = ngx_http_waf_form_fetch(ctx);

        if (rc == NGX_AGAIN) {
            ctx->state = NGX_HTTP_WAF_ST_FETCHING_FORM;
            return NGX_DONE;
        }

        /*
         * Объекты подмены запроса (waf_send request body=store / args=store)
         * -- следом и по той же причине. Тело отказа читается первым: если
         * подъём сорвётся и политика фазы велит block, отказ идёт страницей
         * каталога, и форму ему искать не надо.
         */
        rc = ngx_http_waf_send_fetch(ctx);

        if (rc == NGX_AGAIN) {
            ctx->state = NGX_HTTP_WAF_ST_FETCHING_FORM;
            return NGX_DONE;
        }

        rc = ngx_http_waf_apply(ctx);

        /*
         * Тело выбрасывается только там, где отвечаем мы. NGX_DECLINED --
         * это пропуск: запрос идёт дальше по фазам, и его тело нужно тому,
         * кто стоит за нами. NGX_DONE -- ответ уже отдан и запрос
         * финализирован телом отказа: выбросить его тело успели до отправки.
         */
        if (rc != NGX_DECLINED && rc != NGX_DONE) {
            ngx_http_waf_discard_body(ctx);
        }

        return rc;

    case NGX_HTTP_WAF_FINISH_OVERRIDES:
        /*
         * Спрашивать было некого, запрос пропущен. Выбрасывать тело здесь
         * нельзя: маршрут без инспекторов -- обычный проксируемый маршрут,
         * и апстрим получил бы POST с пустым телом. Так и было, пока
         * страницу проверки держали на "waf off": стоило включить модуль
         * ради локального слоя, как форма переставала отправляться.
         */
        ngx_http_waf_log_verdict(ctx);
        return ngx_http_waf_apply_overrides(ctx);

    default:
        ngx_http_waf_log_verdict(ctx);
        ngx_http_waf_discard_body(ctx);
        (void) ngx_http_waf_apply_debug(ctx);
        return ngx_http_waf_fail_status(ctx);
    }
}


/*
 * Тело, которого мы не читали, -- на выброс. Обязательно на путях раннего
 * ответа: клиент шлёт тело, мы отвечаем не дочитав, и следующий запрос того же
 * keepalive-соединения начинает разбираться с середины чужого тела.
 *
 * Только там, где отвечаем мы. На пропуске тело принадлежит апстриму, и
 * выброшенное здесь до него уже не доедет.
 */
static void
ngx_http_waf_discard_body(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->body_ready || ctx->ph->body_discarded) {
        return;
    }

    ctx->ph->body_discarded = 1;

    (void) ngx_http_discard_request_body(ctx->request);
}


ngx_http_waf_wave_t *
ngx_http_waf_current_wave(ngx_http_waf_ctx_t *ctx)
{
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    if (waves == NULL || ctx->ph->wave >= waves->nelts) {
        return NULL;
    }

    return &((ngx_http_waf_wave_t *) waves->elts)[ctx->ph->wave];
}


ngx_uint_t
ngx_http_waf_wave_count(ngx_http_waf_ctx_t *ctx)
{
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    return (waves == NULL) ? 0 : waves->nelts;
}
