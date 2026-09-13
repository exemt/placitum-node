/*
 * Сериализация описания запроса для инспектора.
 *
 * Размер сообщения считается до записи, буфер выделяется один раз. Проверка
 * переполнения в конце остаётся: она ловит ошибку в расчёте, а не во входных
 * данных, и лучше отказ публикации, чем обрезанный JSON у инспектора.
 */

#include "codec/ngx_http_waf_codec.h"
#include "body/ngx_http_waf_body.h"


/*
 * Скелет сообщения: имена полей, rid, ray, адреса и порты обеих сторон, версия
 * TLS и SNI. SNI отдельным слагаемым не считается -- он ограничен 255 байтами,
 * и запас проще держать здесь, чем тянуть строку из соединения дважды.
 */
#define NGX_HTTP_WAF_MSG_OVERHEAD   1024


static size_t ngx_http_waf_msg_prior_size(ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf);
static void ngx_http_waf_msg_conn(ngx_http_waf_jw_t *jw,
    ngx_http_request_t *r);
static void ngx_http_waf_msg_http(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_msg_prior(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static void ngx_http_waf_msg_resume(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static void ngx_http_waf_msg_response(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx);
static size_t ngx_http_waf_msg_response_size(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_msg_sessions(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_uint_t index);
static size_t ngx_http_waf_msg_sessions_size(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index);
static void ngx_http_waf_msg_groups(ngx_http_waf_jw_t *jw, ngx_str_t *groups);


/* Верхняя граница длины строки в JSON: экранирование даёт не больше шести. */
#define ngx_http_waf_msg_room(len)   ((len) * 6 + 8)

/*
 * Предел кода причины в prior. Код с провода длиной не ограничен, а место
 * под prior считается по реестру до запроса; длиннее предела -- в prior не
 * печатается (в аудите и диагностическом заголовке он всё равно есть).
 */
#define NGX_HTTP_WAF_PRIOR_REASON_MAX  64


ngx_int_t
ngx_http_waf_msg_request(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_str_t *out)
{
    size_t                     size;
    u_char                    *buf;
    ngx_msec_int_t             left;
    ngx_http_waf_jw_t          jw;
    ngx_http_request_t        *r = ctx->request;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    size = NGX_HTTP_WAF_MSG_OVERHEAD
           + ngx_http_waf_msg_room(insp->name.len)
           + ngx_http_waf_msg_room(wmcf->node_id.len)
           + ngx_http_waf_msg_room(r->method_name.len)
           + ngx_http_waf_msg_room(r->headers_in.server.len)
           + ngx_http_waf_msg_room(r->uri.len)
           + ngx_http_waf_msg_room(r->http_protocol.len)
           + ngx_http_waf_msg_room(cscf->server_name.len)
           + ngx_http_waf_msg_room(clcf->name.len)
           + ngx_http_waf_msg_room(wlcf->profiles[index].len)
           + ngx_http_waf_msg_room(insp->audit_subject.len)
           + ngx_http_waf_msg_prior_size(wmcf, wlcf)
           + ngx_http_waf_msg_sessions_size(ctx, index)
           + ngx_http_waf_vars_size(ctx, insp->vars_mask)
           + ngx_http_waf_needs_size()
           + ngx_http_waf_store_size(ctx)
           + ngx_http_waf_msg_response_size(ctx)
           + ngx_http_waf_msg_frame_size(ctx)
           + sizeof(",\"resume\":{\"want\":true,\"require\":false,"
                    "\"token\":\"\"}")
           + NGX_HTTP_WAF_RAY_HEX_LEN;

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_http_waf_jw_init(&jw, buf, size);

    /*
     * Остаток бюджета, а не таймаут инспектора: инспектор обязан уважать
     * deadline_ms, и знать он должен именно то время, после которого его ответ
     * будет выброшен. Свой таймаут ограничивает это время сверху.
     */
    left = (ngx_msec_int_t) (wlcf->deadline[ctx->phase]
                             - (ngx_current_msec - ctx->started));
    if (left < 0) {
        left = 0;
    }

    {
        ngx_http_waf_binding_t  *bind;

        bind = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

        if (bind != NULL && bind->timeout != 0
            && (ngx_msec_t) left > bind->timeout)
        {
            left = (ngx_msec_int_t) bind->timeout;
        }
    }

    ngx_http_waf_jw_lit(&jw, "{\"v\":");
    ngx_http_waf_jw_int(&jw, NGX_HTTP_WAF_PROTOCOL_VERSION);

    ngx_http_waf_jw_lit(&jw, ",\"rid\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->rid_hex, NGX_HTTP_WAF_RID_HEX_LEN);

    /*
     * rid у инспектора остаётся адресом ответа: по нему модуль находит слот.
     * ray -- то, чем инцидент склеивается во всём остальном контуре, поэтому
     * инспектор обязан вернуть его в своём событии аудита, а не выдумывать
     * склейку по node+rid.
     */
    ngx_http_waf_jw_lit(&jw, "\",\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->ray_hex, NGX_HTTP_WAF_RAY_HEX_LEN);

    ngx_http_waf_jw_lit(&jw, "\",\"phase\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_phase_name(ctx->phase));

    ngx_http_waf_jw_lit(&jw, ",\"wave\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) ctx->ph->wave);

    ngx_http_waf_jw_lit(&jw, ",\"inspector\":");
    ngx_http_waf_jw_str(&jw, &insp->name);

    ngx_http_waf_jw_lit(&jw, ",\"deadline_ms\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) left);

    /*
     * Куда публиковать подробности находок. Приезжает с сообщением, а не зашито
     * в инспекторе: subject -- часть топологии контура, и выключить болтливый
     * инспектор оператор должен уметь директивой, не пересобирая сервис.
     * null -- деталей с этого инспектора не ждут.
     */
    ngx_http_waf_jw_lit(&jw, ",\"audit_subject\":");

    if (insp->audit_subject.len != 0) {
        ngx_http_waf_jw_str(&jw, &insp->audit_subject);

    } else {
        ngx_http_waf_jw_lit(&jw, "null");
    }

    ngx_http_waf_jw_lit(&jw, ",\"node\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);

    ngx_http_waf_msg_conn(&jw, r);
    ngx_http_waf_msg_http(&jw, ctx);

    /*
     * Кадр: идентичность соединения, номер и кадрирование. На остальных
     * фазах секции нет (docs/streaming.md#идентификация).
     */
    ngx_http_waf_msg_frame(&jw, ctx);

    /*
     * Поля запроса: стандартный набор и waf_var, но только те, что названы в
     * vars= этого объявления. Значения одни на волну (ngx_http_waf_vars_eval),
     * состав -- у каждого имени свой: инспектору едет то, что он заявил.
     */
    ngx_http_waf_vars_write(&jw, ctx, NGX_HTTP_WAF_VAR_MAX, insp->vars_mask);

    /*
     * Заголовки, строка запроса и тело -- тремя локаторами одной формы. Ни
     * массива пар, ни inline, ни самой строки запроса в сообщении нет: длину
     * всех трёх задаёт клиент, а сообщение публикуется по одному на каждого
     * инспектора волны.
     */
    ngx_http_waf_needs_write(&jw, ctx, insp);
    ngx_http_waf_store_write(&jw, ctx, insp);

    /*
     * Фаза ответа несёт обе стороны: store -- объекты этой фазы, request_store
     * -- объекты фазы запроса, из которых инспектор восстанавливает контекст.
     * На фазе запроса второй секции нет: дублировать в ней ту же тройку значило
     * бы отдать одно и то же дважды.
     */
    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        ngx_http_waf_store_write_phase(&jw, ctx, NGX_HTTP_WAF_PHASE_REQUEST,
                                       "request_store");
    }

    ngx_http_waf_msg_response(&jw, ctx);
    ngx_http_waf_msg_resume(&jw, ctx, index);

    ngx_http_waf_jw_lit(&jw, ",\"route\":{\"server_name\":");
    ngx_http_waf_jw_str(&jw, &cscf->server_name);
    ngx_http_waf_jw_lit(&jw, ",\"location\":");
    ngx_http_waf_jw_str(&jw, &clcf->name);
    ngx_http_waf_jw_lit(&jw, ",\"profile\":");

    /*
     * Профиль непрозрачен для модуля: значение просто передаётся как есть.
     * Отсутствие директивы на всех уровнях -- не ошибка, а литерал "default",
     * см. docs/verdict-protocol.md#профиль-инспектора-по-маршруту.
     */
    if (wlcf->profiles[index].len != 0) {
        ngx_http_waf_jw_str(&jw, &wlcf->profiles[index]);

    } else {
        ngx_http_waf_jw_lit(&jw, "\"default\"");
    }

    ngx_http_waf_jw_lit(&jw, "}");

    /*
     * Накопленный счёт и порог отказа. Инспектору это нужно для двух разных
     * дел. Во-первых, соразмерить собственный ответ: при total 95 и deny_at 100
     * тратить остаток дедлайна на уточнение уже незачем. Во-вторых, решить за
     * модуль то, чего модуль не решает, -- сервис челленджа именно по этой паре
     * и определяет, пора ли требовать доказательство, что клиент человек.
     */
    ngx_http_waf_jw_lit(&jw, ",\"score\":{\"total\":");
    ngx_http_waf_jw_int(&jw, ctx->ph->score);
    ngx_http_waf_jw_lit(&jw, ",\"deny_at\":");
    ngx_http_waf_jw_int(&jw, ngx_http_waf_score_deny_at(ctx));
    ngx_http_waf_jw_lit(&jw, "}");

    ngx_http_waf_msg_prior(&jw, ctx, index);
    ngx_http_waf_msg_sessions(&jw, ctx, index);

    ngx_http_waf_jw_lit(&jw, "}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "waf: inspect message for \"%V\" does not fit %uz bytes",
                      &insp->name, size);
        return NGX_ERROR;
    }

    out->data = buf;
    out->len  = ngx_http_waf_jw_len(&jw);

    return NGX_OK;
}


/*
 * Секция ответа: статус и время апстрима инлайном, заголовки -- списком пар.
 *
 * Заголовки здесь временно: их место -- объект обменника, как у запроса, где к ним
 * применяются mask= и deny= маршрута. Пока снимка фазы ответа нет, списков тоже
 * нет, и применять к заголовкам нечего -- поэтому set-cookie не отправляется
 * вовсе, а не отправляется "как есть": сессия в чужом процессе дороже, чем
 * находка, которую без неё не сделают.
 */
/*
 * Липкость, обе её стороны.
 *
 * На фазе запроса едет want: на строке инспектора стоит keep=on, то есть
 * поздняя фаза за состоянием вернётся. Инспектору это нужно заранее -- иначе
 * он либо держит состояние на каждом запросе (память), либо не держит никогда
 * (переигровка). Без want инспектор обязан выбросить транзакцию, ответив.
 *
 * Вместе с вопросом едет ключ, под которым состояние держать. Ключ называет
 * модуль, а не инспектор, и называет в вопросе, а не получает в ответе: ответ
 * может не дойти -- волна замыкается на чужом отказе, и наш ответ приходит в
 * закрытый слот. Ключ, существующий только в таком ответе, нельзя ни
 * использовать, ни отозвать.
 *
 * Ключ -- ray: он один на запрос и переживает фазы, в отличие от rid, который
 * кодирует слот ожидания и берётся заново на каждую волну.
 *
 * На потребляющей фазе секция едет всегда, когда на строке стоит resume=, --
 * и в личный subject, и в групповой. Тот же ключ и require: инспектор, у
 * которого состояния под ключом нет, по нему решает, переиграть фазы или
 * отказать. В личный subject сообщение уходит только пока продолжение живо
 * (ngx_http_waf_resume_subject); в групповой -- когда его не было, оно
 * истекло или экземпляр исчез. Данных в секции нет и быть не должно: сообщение
 * в оба адреса одинаково.
 */
static void
ngx_http_waf_msg_resume(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_http_waf_binding_t   *b;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST) {

        if (!ngx_http_waf_resume_wanted(wlcf, index, ctx->phase)) {
            return;
        }

        ngx_http_waf_jw_lit(jw, ",\"resume\":{\"want\":true,\"token\":\"");
        ngx_http_waf_jw_raw(jw, (const u_char *) ctx->ray_hex,
                            NGX_HTTP_WAF_RAY_HEX_LEN);
        ngx_http_waf_jw_lit(jw, "\"}");

        return;
    }

    b = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

    if (b == NULL || b->resume == NGX_HTTP_WAF_RESUME_OFF) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"resume\":{\"token\":\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) ctx->ray_hex,
                        NGX_HTTP_WAF_RAY_HEX_LEN);

    if (b->resume == NGX_HTTP_WAF_RESUME_REQUIRE) {
        ngx_http_waf_jw_lit(jw, "\",\"require\":true}");

    } else {
        ngx_http_waf_jw_lit(jw, "\",\"require\":false}");
    }
}


static void
ngx_http_waf_msg_response(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t           i, first;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_RESPONSE) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"response\":{\"status\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ctx->rsp_status);

    ngx_http_waf_jw_lit(jw, ",\"upstream_ms\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ctx->upstream_ms);

    /*
     * Заголовки в обменнике -- инлайн не нужен: инспектор читает объект, к
     * которому применены mask= и deny= маршрута. Инлайновый список остаётся
     * только там, где снимка заголовков нет вовсе, и тогда set-cookie из него
     * выброшен: маскировать его нечем.
     */
    if (ngx_http_waf_store_locator_phase(ctx, NGX_HTTP_WAF_PHASE_RESPONSE,
                                         NGX_HTTP_WAF_OBJ_HEADERS) != NULL
        && ngx_http_waf_obj_visible_phase(ctx, NGX_HTTP_WAF_PHASE_RESPONSE,
                                          NGX_HTTP_WAF_OBJ_HEADERS))
    {
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"headers\":[");

    part  = &r->headers_out.headers.part;
    h     = part->elts;
    first = 1;

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

        if (h[i].key.len == 10
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Set-Cookie", 10) == 0)
        {
            continue;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, "[");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",[");
        }

        ngx_http_waf_jw_str(jw, &h[i].key);
        ngx_http_waf_jw_lit(jw, ",");
        ngx_http_waf_jw_str(jw, &h[i].value);
        ngx_http_waf_jw_lit(jw, "]");
    }

    ngx_http_waf_jw_lit(jw, "]}");
}


static size_t
ngx_http_waf_msg_response_size(ngx_http_waf_ctx_t *ctx)
{
    size_t               size;
    ngx_uint_t           i;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_RESPONSE) {
        return 0;
    }

    size = sizeof(",\"response\":{\"status\":,\"upstream_ms\":,\"headers\":[]}")
           + 2 * NGX_INT_T_LEN;

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

        size += ngx_http_waf_msg_room(h[i].key.len)
                + ngx_http_waf_msg_room(h[i].value.len)
                + sizeof(",[,]");
    }

    return size;
}


/*
 * Худший размер сообщения против max_payload шины.
 *
 * Проверка здесь, а не обрезка в рантайме: обрезать URI нельзя -- атака уедет
 * в отсечённый хвост, и модуль своими руками спрячет от инспектора именно то,
 * ради чего его спрашивают. А отказ публикации на пределе max_payload -- это не
 * деградация покрытия, а потеря всей волны, то есть запрос, ушедший в
 * waf_exception … bus. Такую конфигурацию лучше не загрузить.
 *
 * Считаем по границе, которую задаёт сам nginx: строка запроса и любой
 * заголовок обязаны уместиться в large_client_header_buffers, иначе запрос
 * отвергается до всякой инспекции.
 */
char *
ngx_http_waf_msg_req_validate(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf)
{
    size_t                     size, client, name, profile;
    ngx_uint_t                 i;
    ngx_http_waf_var_t        *var;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_waf_inspector_t  *insp;

    if (!wlcf->enable || wlcf->waves[NGX_HTTP_WAF_PHASE_REQUEST] == NULL
        || wlcf->waves[NGX_HTTP_WAF_PHASE_REQUEST]->nelts == 0)
    {
        return NGX_CONF_OK;
    }

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    client = cscf->large_client_header_buffers.size;

    /* Длиннейшее имя инспектора и длиннейший профиль этого маршрута. */
    name    = 0;
    profile = 0;
    insp    = wmcf->inspectors.elts;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        if (insp[i].name.len > name) {
            name = insp[i].name.len;
        }

        if (wlcf->profiles[i].len > profile) {
            profile = wlcf->profiles[i].len;
        }
    }

    size = NGX_HTTP_WAF_MSG_OVERHEAD
           + ngx_http_waf_msg_room(name)
           + ngx_http_waf_msg_room(wmcf->node_id.len)
           + ngx_http_waf_msg_room(cscf->server_name.len)
           + ngx_http_waf_msg_room(clcf->name.len)
           + ngx_http_waf_msg_room(profile)
           + ngx_http_waf_msg_prior_size(wmcf, wlcf)
           + ngx_http_waf_store_max_size(wmcf, wlcf, client)
           /*
            * Секция sessions: контекст держит их не больше SESSIONS_MAX, а
            * длину каждой строки ограничил разбор реплая -- худший случай
            * считается по этим двум пределам, как и всё остальное здесь.
            */
           + sizeof(",\"sessions\":[]")
           + NGX_HTTP_WAF_SESSIONS_MAX * NGX_HTTP_WAF_SESSION_JSON;

    /*
     * Строка запроса целиком -- это method, uri и version, а Host -- отдельный
     * заголовок; и то и другое ограничено одним и тем же буфером.
     */
    size += 2 * ngx_http_waf_msg_room(client);

    /*
     * Секция кадра: conn_id, seq, stream. Подпротокол -- заголовок ответа
     * апстрима, его длина ограничена тем же буфером, что и заголовки.
     */
    if (wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_C2S] != NULL
        && wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_C2S]->nelts != 0)
    {
        size += 256 + NGX_HTTP_WAF_RAY_HEX_LEN + ngx_http_waf_msg_room(client);
    }

    if (wmcf->vars != NULL) {
        var = wmcf->vars->elts;

        for (i = 0; i < wmcf->vars->nelts; i++) {
            size += ngx_http_waf_msg_room(var[i].name.len)
                    + ngx_http_waf_msg_room(NGX_HTTP_WAF_VAR_MAX) + 2;
        }
    }

    if (size <= wmcf->bus_payload_max) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: an inspect message on this route may reach %uz "
                       "bytes, which does not fit the %uz byte bus payload "
                       "limit; lower large_client_header_buffers (%uz) or "
                       "raise payload_max= in waf_bus",
                       size, wmcf->bus_payload_max, client);

    return NGX_CONF_ERROR;
}


size_t
ngx_http_waf_vars_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t mask)
{
    size_t                     size;
    ngx_uint_t                 i, n;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->vars == NULL || wmcf->vars == NULL || mask == 0) {
        return 0;
    }

    var  = wmcf->vars->elts;
    n    = wmcf->vars->nelts;
    size = sizeof(",\"vars\":{}") - 1;

    for (i = 0; i < n; i++) {
        if (!(mask & ((ngx_uint_t) 1 << i))) {
            continue;
        }

        size += ngx_http_waf_msg_room(var[i].name.len)
                + ngx_http_waf_msg_room(ctx->vars[i].len)
                + 2;                            /* двоеточие и запятая */
    }

    return size;
}


/*
 * Граница UTF-8 не дальше len. Обрезка внутри последовательности даёт байты,
 * которые получатель всё равно заменит на U+FFFD, -- лучше отдать на символ
 * меньше.
 */
static size_t
ngx_http_waf_utf8_trim(u_char *data, size_t len)
{
    while (len > 0 && (data[len] & 0xc0) == 0x80) {
        len--;
    }

    return len;
}


void
ngx_http_waf_vars_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    size_t value_max, ngx_uint_t mask)
{
    ngx_str_t                  value;
    ngx_uint_t                 i, n, first;
    ngx_http_waf_var_t        *var;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->vars == NULL || wmcf->vars == NULL || mask == 0) {
        return;
    }

    var   = wmcf->vars->elts;
    n     = wmcf->vars->nelts;
    first = 1;

    for (i = 0; i < n; i++) {

        if (!(mask & ((ngx_uint_t) 1 << i))) {
            continue;
        }

        /*
         * Пустое значение опускается целиком. Незаданная переменная nginx --
         * это пустая строка, и отличить её от заданной пустой всё равно
         * нельзя, а поле с "" в каждом сообщении -- чистый шум.
         */
        value = ctx->vars[i];

        if (value.len == 0) {
            continue;
        }

        if (value_max != 0 && value.len > value_max) {
            value.len = ngx_http_waf_utf8_trim(value.data, value_max);

            if (value.len == 0) {
                continue;
            }
        }

        /*
         * Место под запись плюс запас на остаток документа. В сообщении
         * инспектору размер посчитан заранее и проверка не срабатывает; в
         * итоге агенту буфер фиксированный, и значение из управляющих байтов
         * раздувается экранированием в шесть раз. Потерять на этом хвост
         * секции лучше, чем потерять запись аудита целиком.
         */
        if ((size_t) (jw->end - jw->pos)
            < value.len * 6 + var[i].name.len + 128)
        {
            break;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, ",\"vars\":{");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &var[i].name);
        ngx_http_waf_jw_lit(jw, ":");
        ngx_http_waf_jw_str(jw, &value);
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "}");
    }
}


/* Место под секцию prior: по записи на каждого объявленного инспектора. */
static size_t
ngx_http_waf_msg_prior_size(ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf)
{
    size_t                     size;
    ngx_uint_t                 i;
    ngx_http_waf_inspector_t  *insp;

    insp = wmcf->inspectors.elts;
    size = 16;

    /*
     * Записей у инспектора столько, на скольких фазах он стоял, а фаз у
     * запроса не больше NGX_HTTP_WAF_NPHASE. Считается по потолку, а не по
     * текущей фазе: буфер выделяется до публикации, и занижение здесь --
     * обрезанный JSON у инспектора.
     */
    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        size += NGX_HTTP_WAF_NPHASE
                * (ngx_http_waf_msg_room(insp[i].name.len)
                   + sizeof(",{\"phase\":\"response\",\"wave\":,"
                            "\"inspector\":,\"verdict\":\"redirect\","
                            "\"score\":,"
                            "\"reason\":{\"code\":}}") - 1
                   + 2 * NGX_INT_T_LEN
                   + ngx_http_waf_msg_room(NGX_HTTP_WAF_PRIOR_REASON_MAX));
    }

    /*
     * Действия входят в бюджет отдельным слагаемым: их число ограничено на
     * запрос, а не на инспектора, и печатаются они не длиннее того, чем
     * приехали. Ноль в waf_actions_max выключает канал -- и слагаемое.
     */
    size += wlcf->actions_max
            * (wlcf->action_max
               + sizeof(",{\"do\":\"threshold\",\"apply\":\"session\","
                        "\"phase\":\"response\","
                        "\"code\":,\"delta\":,\"value\":,\"counter\":,"
                        "\"group\":,\"set\":\"off\"}") - 1
               + 2 * NGX_INT_T_LEN);

    return size;
}


static void
ngx_http_waf_msg_conn(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    u_char             buf[NGX_SOCKADDR_STRLEN];
    ngx_str_t          s;
    ngx_connection_t  *c = r->connection;

    ngx_http_waf_jw_lit(jw, ",\"conn\":{\"client_ip\":");
    ngx_http_waf_jw_str(jw, &c->addr_text);

    ngx_http_waf_jw_lit(jw, ",\"client_port\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_inet_get_port(c->sockaddr));

    /*
     * Локальный адрес приходится запрашивать явно: при listen на wildcard
     * nginx не заполняет local_sockaddr до первого обращения.
     */
    if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) {
        s.data = buf;
        s.len  = ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf,
                               NGX_SOCKADDR_STRLEN, 0);

        ngx_http_waf_jw_lit(jw, ",\"server_ip\":");
        ngx_http_waf_jw_string(jw, s.data, s.len);

        ngx_http_waf_jw_lit(jw, ",\"server_port\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_inet_get_port(c->local_sockaddr));
    }

#if (NGX_SSL)
    if (c->ssl != NULL) {
        ngx_str_t  version, sni;

        ngx_http_waf_jw_lit(jw, ",\"tls\":{");

        if (ngx_ssl_get_protocol(c, r->pool, &version) == NGX_OK
            && version.len != 0)
        {
            ngx_http_waf_jw_lit(jw, "\"version\":");
            ngx_http_waf_jw_str(jw, &version);
        } else {
            ngx_http_waf_jw_lit(jw, "\"version\":null");
        }

        if (ngx_ssl_get_server_name(c, r->pool, &sni) == NGX_OK
            && sni.len != 0)
        {
            ngx_http_waf_jw_lit(jw, ",\"sni\":");
            ngx_http_waf_jw_str(jw, &sni);
        }

        ngx_http_waf_jw_lit(jw, "}");
    }
#endif

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_msg_http(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    ngx_http_waf_jw_lit(jw, ",\"http\":{\"method\":");
    ngx_http_waf_jw_str(jw, &r->method_name);

    ngx_http_waf_jw_lit(jw, ",\"scheme\":");

#if (NGX_SSL)
    if (r->connection->ssl != NULL) {
        ngx_http_waf_jw_lit(jw, "\"https\"");
    } else
#endif
    {
        ngx_http_waf_jw_lit(jw, "\"http\"");
    }

    if (r->headers_in.server.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"host\":");
        ngx_http_waf_jw_str(jw, &r->headers_in.server);
    }

    ngx_http_waf_jw_lit(jw, ",\"uri\":");
    ngx_http_waf_jw_str(jw, &r->uri);

    /*
     * Длина строки запроса, а не она сама: содержимое лежит в обменнике, а факт и
     * объём query нужны каждому инспектору и без похода туда. Ноль означает,
     * что query не было, -- это видно, даже когда запись выключена.
     */
    ngx_http_waf_jw_lit(jw, ",\"args_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) r->args.len);

    if (r->http_protocol.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"version\":");
        ngx_http_waf_jw_str(jw, &r->http_protocol);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Действия одной записи prior: что инспектор i сказал на фазе p и что из этого
 * адресовано читателю. Поля to в доставленном действии нет -- адресат тот, кто
 * читает, и широковещательное от адресного он не отличает намеренно: иначе
 * правило в профиле пришлось бы писать дважды.
 */
static void
ngx_http_waf_msg_prior_actions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index, ngx_uint_t from, ngx_uint_t phase)
{
    ngx_uint_t              i, first;
    ngx_http_waf_action_t  *action;

    if (ctx->actions == NULL) {
        return;
    }

    action = ctx->actions->elts;
    first  = 1;

    for (i = 0; i < ctx->actions->nelts; i++) {

        if (action[i].from != from || action[i].phase != phase) {
            continue;
        }

        if (action[i].to != NGX_HTTP_WAF_ACTION_ALL && action[i].to != index) {
            continue;
        }

        /*
         * Маркер соседям не доставляют. Поля to у него нет, то есть по форме
         * он широковещательный, -- но исполняет его модуль в адрес записи, и
         * получателю остаётся только отчитаться "нет правила" на просьбу,
         * которая ему и не адресована. В аудите модуля метка видна целиком.
         */
        if (ngx_http_waf_do_mark(action[i].verb)) {
            continue;
        }

        /*
         * Очки соседям не доставляют по той же причине: исполнил модуль, и
         * след уже в поле score отправителя этой же записи prior.
         */
        if (ngx_http_waf_do_score(action[i].verb)) {
            continue;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, ",\"actions\":[{\"do\":");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",{\"do\":");
        }

        ngx_http_waf_jw_str(jw, ngx_http_waf_do_name(action[i].verb));

        ngx_http_waf_jw_lit(jw, ",\"apply\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_apply_name(action[i].apply));

        /*
         * Фаза вызова адресата -- та же форма, что прислал отправитель:
         * получатель видит просьбу такой, какой она уехала. Фаза самой
         * записи стоит уровнем выше и означает другое -- где высказано.
         */
        if (action[i].to_phases != 0) {
            ngx_http_waf_jw_lit(jw, ",\"phase\":");
            ngx_http_waf_jw_str(jw,
                                ngx_http_waf_to_phase_name(action[i].to_phases));
        }

        if (action[i].code.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"code\":");
            ngx_http_waf_jw_str(jw, &action[i].code);
        }

        if (action[i].has_delta) {
            ngx_http_waf_jw_lit(jw, ",\"delta\":");
            ngx_http_waf_jw_int(jw, action[i].delta);
        }

        if (action[i].has_value) {
            ngx_http_waf_jw_lit(jw, ",\"value\":");
            ngx_http_waf_jw_int(jw, action[i].value);
        }

        if (action[i].counter.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"counter\":");
            ngx_http_waf_jw_str(jw, &action[i].counter);
        }

        if (action[i].group.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"group\":");
            ngx_http_waf_jw_str(jw, &action[i].group);
        }

        if (action[i].set == NGX_HTTP_WAF_SET_ON) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"on\"");

        } else if (action[i].set == NGX_HTTP_WAF_SET_OFF) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"off\"");
        }

        ngx_http_waf_action_archive_write(jw, &action[i]);

        ngx_http_waf_jw_lit(jw, "}");
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "]");
    }
}


/*
 * Секция prior: полная запись о тех, кто на этом запросе высказался раньше.
 *
 * Сквозная по фазам: просьба, высказанная на фазе запроса, обязана дожить до
 * фазы ответа и до кадров, иначе ранняя волна не может обратиться к
 * инспектору, которого на её фазе нет. Ключ записи -- пара инспектор + фаза:
 * инспектор отвечает один раз за фазу, поэтому записей у него столько, на
 * скольких фазах он стоял.
 *
 * Свои собственные записи не приезжают: своё состояние между фазами инспектор
 * держит через continue / resume, и дублировать его здесь значило бы иметь два
 * источника одного факта.
 */
static void
ngx_http_waf_msg_prior(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_uint_t                 i, p, first;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    inspectors = wmcf->inspectors.elts;
    first      = 1;

    for (p = 0; p < NGX_HTTP_WAF_NPHASE; p++) {

        if (ctx->phases[p].replies == NULL) {
            continue;
        }

        for (i = 0; i < wmcf->inspectors.nelts; i++) {

            if (i == index) {
                continue;
            }

            reply = &ctx->phases[p].replies[i];

            if (!reply->received) {
                continue;
            }

            /*
             * Пассивный не попадает в prior вовсе -- ни вердиктом, ни вкладом,
             * ни действиями. Не метка, которую получатель волен применить, а
             * отсутствие записи: режим, который держится на умолчании в чужом
             * профиле, -- не режим. Что он сказал, целиком видно в аудите.
             *
             * Совещательный -- участник решения: его очки лежат в сумме, и
             * соседям он виден как боевой. Вердикт печатается как сказан
             * (deny), а score -- что легло в сумму (сотня).
             */
            if (reply->passive) {
                continue;
            }

            if (first) {
                ngx_http_waf_jw_lit(jw, ",\"prior\":[{\"phase\":");
                first = 0;

            } else {
                ngx_http_waf_jw_lit(jw, ",{\"phase\":");
            }

            /*
             * Где высказался. Без фазы инспектор не отличил бы "сосед по
             * волне" от "то, что уже применено к запросу", а решения по ним
             * разные.
             */
            ngx_http_waf_jw_str(jw, ngx_http_waf_phase_name(p));

            ngx_http_waf_jw_lit(jw, ",\"wave\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) reply->wave);

            ngx_http_waf_jw_lit(jw, ",\"inspector\":");
            ngx_http_waf_jw_str(jw, &inspectors[i].name);

            ngx_http_waf_jw_lit(jw, ",\"verdict\":");
            ngx_http_waf_jw_str(jw, ngx_http_waf_verdict_name(reply->verdict));

            if (reply->score != 0) {
                ngx_http_waf_jw_lit(jw, ",\"score\":");
                ngx_http_waf_jw_int(jw, reply->score);
            }

            /*
             * Код причины: чем инспектор объяснил свой вердикт. Просьбы едут
             * рядом, в actions, -- код объясняет решение, действие адресуется
             * соседу, и путать их значит держать один словарь на две задачи.
             */
            if (reply->reason_code.len != 0
                && reply->reason_code.len <= NGX_HTTP_WAF_PRIOR_REASON_MAX)
            {
                ngx_http_waf_jw_lit(jw, ",\"reason\":{\"code\":");
                ngx_http_waf_jw_str(jw, &reply->reason_code);
                ngx_http_waf_jw_lit(jw, "}");
            }

            ngx_http_waf_msg_prior_actions(jw, ctx, index, i, p);

            ngx_http_waf_jw_lit(jw, "}");
        }
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "]");
    }
}


/*
 * Секция sessions: кого соседи узнали на этом запросе.
 *
 * Модуль сам их не толкует -- он только держит сказанное калиткой (секция
 * sessions реплая, ngx_http_waf_sessions_merge) и возвращает соседям. Нужно
 * это тем, кто ключует свой счёт личностью, а не тем, что прислал клиент:
 * заголовок X-WAF-User ложится в r->headers_in только на apply, то есть
 * после всех волн, а снимок заголовков к тому моменту давно в обменнике.
 *
 * Сквозная по фазам, как prior: сессия, узнанная на фазе запроса, обязана
 * дожить до фазы ответа и до кадров -- фаза ответа считает по ней уже
 * унесённое, а куки в этот момент никто заново не читает.
 *
 * Пассивного отправителя здесь нет по той же причине, что и в prior: режим
 * наблюдения не должен менять то, что видят соседи. Своих записей инспектор
 * тоже не получает -- их он знает и без нас.
 */
static void
ngx_http_waf_msg_sessions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t index)
{
    ngx_uint_t                 i, first;
    ngx_http_waf_session_t    *sess;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->sessions == NULL || ctx->sessions->nelts == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    inspectors = wmcf->inspectors.elts;
    sess       = ctx->sessions->elts;
    first      = 1;

    for (i = 0; i < ctx->sessions->nelts; i++) {

        if (sess[i].passive || sess[i].by == index) {
            continue;
        }

        if (first) {
            ngx_http_waf_jw_lit(jw, ",\"sessions\":[{\"inspector\":");
            first = 0;

        } else {
            ngx_http_waf_jw_lit(jw, ",{\"inspector\":");
        }

        ngx_http_waf_jw_str(jw, &inspectors[sess[i].by].name);

        ngx_http_waf_jw_lit(jw, ",\"source\":");
        ngx_http_waf_jw_str(jw, &sess[i].source);

        ngx_http_waf_jw_lit(jw, ",\"kind\":");
        ngx_http_waf_jw_str(jw, &sess[i].kind);

        ngx_http_waf_jw_lit(jw, ",\"user\":");
        ngx_http_waf_jw_str(jw, &sess[i].user);

        ngx_http_waf_jw_lit(jw, ",\"id\":");
        ngx_http_waf_jw_str(jw, &sess[i].id);

        /* Литерал целиком: jw_lit считает длину из sizeof, тернарник ему не
         * литерал, а char *. */
        if (sess[i].verified) {
            ngx_http_waf_jw_lit(jw, ",\"verified\":true");

        } else {
            ngx_http_waf_jw_lit(jw, ",\"verified\":false");
        }

        if (sess[i].groups.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"groups\":");
            ngx_http_waf_msg_groups(jw, &sess[i].groups);
        }

        if (sess[i].issued != 0) {
            ngx_http_waf_jw_lit(jw, ",\"issued\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].issued);
        }

        if (sess[i].expires != 0) {
            ngx_http_waf_jw_lit(jw, ",\"expires\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].expires);
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    if (!first) {
        ngx_http_waf_jw_lit(jw, "]");
    }
}


/*
 * Группы: в контексте они лежат одной строкой через запятую (так их прислал
 * отправитель), а на проводе это массив -- ровно та же форма, в которой
 * инспектор их и написал в своём реплае. Пустых имён не бывает: разбор
 * реплая склеил список сам.
 */
static void
ngx_http_waf_msg_groups(ngx_http_waf_jw_t *jw, ngx_str_t *groups)
{
    u_char  *p, *end, *mark;

    p   = groups->data;
    end = groups->data + groups->len;

    ngx_http_waf_jw_lit(jw, "[");

    for (mark = p; p <= end; p++) {

        if (p != end && *p != ',') {
            continue;
        }

        if (p != mark) {
            if (mark != groups->data) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            ngx_http_waf_jw_string(jw, mark, (size_t) (p - mark));
        }

        mark = p + 1;
    }

    ngx_http_waf_jw_lit(jw, "]");
}


/*
 * Место под секцию sessions: по факту, а не по пределам формы. Записи уже
 * лежат в контексте -- считать по SESSIONS_MAX значило бы возить лишние
 * тринадцать килобайт запаса в каждом сообщении каждой волны.
 */
static size_t
ngx_http_waf_msg_sessions_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    size_t                     size;
    ngx_uint_t                 i;
    ngx_http_waf_session_t    *sess;
    ngx_http_waf_inspector_t  *inspectors;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->sessions == NULL || ctx->sessions->nelts == 0) {
        return 0;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    inspectors = wmcf->inspectors.elts;
    sess       = ctx->sessions->elts;
    size       = sizeof(",\"sessions\":[]");

    for (i = 0; i < ctx->sessions->nelts; i++) {

        if (sess[i].passive || sess[i].by == index) {
            continue;
        }

        size += ngx_http_waf_msg_room(inspectors[sess[i].by].name.len)
                + ngx_http_waf_msg_room(sess[i].source.len)
                + ngx_http_waf_msg_room(sess[i].kind.len)
                + ngx_http_waf_msg_room(sess[i].user.len)
                + ngx_http_waf_msg_room(sess[i].id.len)
                /* Группы: те же байты плюс кавычки и запятые массива. */
                + ngx_http_waf_msg_room(sess[i].groups.len)
                + sizeof("{\"inspector\":,\"source\":,\"kind\":,\"user\":,"
                         "\"id\":,\"verified\":false,\"groups\":[],"
                         "\"issued\":,\"expires\":},")
                + 2 * NGX_INT_T_LEN;
    }

    return size;
}
