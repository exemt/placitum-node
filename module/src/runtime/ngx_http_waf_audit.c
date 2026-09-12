/*
 * Итог фазы -- агенту, не в WAF_AUDIT.
 *
 * Модуль не логирует: один datagram на unix-сокет, MSG_DONTWAIT. Промах
 * (агент не поднят, очередь полна) не двигает запрос. Конверт kind=request
 * дописывает агент, склейка -- по ray. rid слота в сокет не кладём.
 *
 * Форма сообщения -- docs/messages/agent.schema.ts. Это единственный источник
 * данных о самом запросе: kind=inspector рассказывает только про инспектора,
 * ни адреса, ни маршрута, ни размеров, ни того, кто промолчал, там нет и
 * взяться неоткуда. Поэтому контекст собирается здесь и целиком.
 *
 * Три вопроса -- три поля: что сделали (verdict), почему (code), кто (by --
 * ключ в inspectors). Остальное -- контекст.
 */

#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "codec/ngx_http_waf_codec.h"
#include "runtime/ngx_http_waf_preview.h"

#include <sys/socket.h>
#include <sys/un.h>


/*
 * Буфер отправки сокета. Ставится явным значением, а не оставляется системным:
 * датаграмма с превью на порядки длиннее прежней, и молчаливый EMSGSIZE от
 * умолчания ядра выглядел бы как потерянная запись без единой причины в логе.
 */
#define NGX_HTTP_WAF_AUDIT_SNDBUF  NGX_HTTP_WAF_AUDIT_DGRAM_MAX

/*
 * Ключ модуля в карте участников. Итог модуля лежит там же, где ответы
 * инспекторов, и в той же форме: иначе локальный список, срыв волны и deny по
 * порогу выглядели бы тремя разными сообщениями. Имя "agent" здесь не годится
 * -- так называется процесс, который это сообщение читает.
 */
static ngx_str_t  ngx_http_waf_audit_module = ngx_string("module");
static ngx_str_t  ngx_http_waf_audit_session_phase = ngx_string("session");

/* Сколько байт полезной нагрузки кадра едет в запись как срез. */
#define NGX_HTTP_WAF_AUDIT_FRAME_PREVIEW  256

static ngx_socket_t        ngx_http_waf_agent_fd = (ngx_socket_t) -1;
static struct sockaddr_un  ngx_http_waf_agent_addr;
static socklen_t           ngx_http_waf_agent_addrlen;


/*
 * Итог для аудита. Политика отказа вердикта не выносит -- ctx->ph->verdict
 * остаётся allow, потому что его действительно никто не выносил, -- но клиент
 * получил 503, и для записи это отказ.
 *
 * score сюда попасть не может: разрешение вердикта сворачивает порог в deny.
 * Проверка остаётся на случай, если это когда-нибудь перестанет быть так.
 */
ngx_uint_t
ngx_http_waf_audit_verdict(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->fail_blocked) {
        return NGX_HTTP_WAF_V_DENY;
    }

    return (ctx->ph->verdict == NGX_HTTP_WAF_V_SCORE)
               ? NGX_HTTP_WAF_V_ALLOW
               : ctx->ph->verdict;
}


/*
 * Кого-то из спрошенных не дождались. Смотрим все прошедшие фазы, а не только
 * текущую: решение сэмпла одно на запрос, и таймаут в фазе запроса обязан
 * сохранить и запись фазы ответа -- иначе в журнале останется половина
 * истории именно того запроса, ради которого журнал и ведут.
 */
static ngx_uint_t
ngx_http_waf_audit_silent(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n, phase;
    ngx_http_waf_phase_ctx_t  *ph;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    n    = wmcf->inspectors.nelts;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        ph = &ctx->phases[phase];

        if (ph->replies == NULL) {
            continue;
        }

        for (i = 0; i < n; i++) {

            if (!(ph->published & (1ULL << i))) {
                continue;
            }

            if (!ph->replies[i].received) {
                return 1;
            }
        }
    }

    return 0;
}


/*
 * Писать ли эту запись.
 *
 * Прорежается только то, что нечем объяснить. Всё остальное -- отказ, редирект,
 * молчание спрошенного инспектора, передача объектов в архив -- пишется при
 * любом сэмпле, и вот почему:
 *
 *   - отказ и редирект: расследование начинается с них, и сэмпл, умеющий их
 *     потерять, -- не сэмпл, а дыра;
 *   - молчание: это отказ инфраструктуры, и по одному проценту таких записей
 *     его не увидеть;
 *   - архив: непустая секция означает, что объекты переданы агенту, и он их
 *     перекладывает и чистит обменник. Выброшенная запись оставила бы их лежать
 *     до истечения TTL, то есть сэмпл менял бы не объём журнала, а занятость
 *     обменника.
 *
 * Решение маршрута принимается один раз на запрос и запоминается: у одного
 * ray записей бывает две, и запись фазы ответа без своего якоря не объясняет
 * ничего. Поверх него -- просьба соседа глаголом записи, у каждой
 * записи своя (ось apply): on -- писать вопреки жребию; off -- считать, что
 * жребий не выпал. off не сильнее сэмпла: отказ, молчание и архив пишутся при
 * любом его значении, и просьба соседа этого не отменяет -- иначе она прятала
 * бы улики.
 */
static ngx_uint_t
ngx_http_waf_audit_evidence(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_route_verdict(ctx) != NGX_HTTP_WAF_V_ALLOW
           || ngx_http_waf_archive_mask(ctx) != 0
           || ngx_http_waf_audit_silent(ctx);
}


static ngx_uint_t
ngx_http_waf_audit_keep(ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_uint_t  set;

    set = ngx_http_waf_audit_ovr_cur(ctx)->audit.set;

    if (set == NGX_HTTP_WAF_SET_ON) {
        return 1;
    }

    if (set == NGX_HTTP_WAF_SET_OFF) {
        return ngx_http_waf_audit_evidence(ctx);
    }

    if (ctx->audit_sampled) {
        return ctx->audit_keep;
    }

    ctx->audit_sampled = 1;
    ctx->audit_keep    = 1;

    if (wlcf->audit_sample >= 100 || ngx_http_waf_audit_evidence(ctx)) {
        return 1;
    }

    /*
     * ngx_random(), а не хеш ray: сэмпл обязан быть равномерным по запросам, а
     * не по значениям ray -- иначе один клиент с "неудачным" ray не попадал бы
     * в журнал никогда.
     */
    if (wlcf->audit_sample <= 0
        || (ngx_int_t) (ngx_random() % 100) >= wlcf->audit_sample)
    {
        ctx->audit_keep = 0;
    }

    return ctx->audit_keep;
}


/*
 * Отказ считается тем же способом, что у записи: сорванная политикой волна --
 * отказ, счёт без порога -- нет. Фаза, которая не бежала, исхода не имеет.
 */
static ngx_uint_t
ngx_http_waf_phase_denied(ngx_http_waf_phase_ctx_t *ph)
{
    return ph->fail_blocked || ph->verdict == NGX_HTTP_WAF_V_DENY;
}


ngx_uint_t
ngx_http_waf_route_verdict(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  phase;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (!ctx->phases[phase].logged) {
            continue;
        }

        if (ngx_http_waf_phase_denied(&ctx->phases[phase])) {
            return NGX_HTTP_WAF_V_DENY;
        }
    }

    return ngx_http_waf_audit_verdict(ctx);
}


void
ngx_http_waf_audit_flush_deferred(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 saved_phase;
    ngx_http_waf_phase_ctx_t  *saved_ph, *ph;

    ph = &ctx->phases[NGX_HTTP_WAF_PHASE_REQUEST];

    if (!ph->audit_deferred) {
        return;
    }

    ph->audit_deferred = 0;

    /*
     * Запись строится от текущей фазы контекста: превью, тип содержимого,
     * участники -- всё по ctx->ph. Подменяем на время записи и возвращаем:
     * вызывающий стоит в своей фазе и продолжит в ней.
     */
    saved_phase = ctx->phase;
    saved_ph    = ctx->ph;

    ctx->phase = NGX_HTTP_WAF_PHASE_REQUEST;
    ctx->ph    = ph;

    ngx_http_waf_audit_request(ctx);

    ctx->phase = saved_phase;
    ctx->ph    = saved_ph;
}


static ngx_uint_t
ngx_http_waf_audit_status(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->fail_blocked) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    return ngx_http_waf_result_status(ctx);
}


/*
 * Чей вердикт стал итогом. Чужое решение -- только code=inspector; локальный
 * бан, порог и срыв волны решает модуль, и указывать там на инспектора не на
 * что. Инвариант схемы verdict === inspectors[by].verdict держится этим.
 */
static ngx_str_t *
ngx_http_waf_audit_by(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->code != NGX_HTTP_WAF_CODE_INSPECTOR || ctx->ph->decisive == NULL) {
        return &ngx_http_waf_audit_module;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->ph->decisive_index >= wmcf->inspectors.nelts) {
        return &ngx_http_waf_audit_module;
    }

    insp = wmcf->inspectors.elts;

    return &insp[ctx->ph->decisive_index].name;
}


/*
 * Момент поступления запроса, UTC с миллисекундами. Ставит модуль, а не агент:
 * агентское время -- это момент публикации, то есть после сокета, очереди и
 * планировщика. Для порядка событий и для склейки с access-логом нужно начало
 * обработки.
 */
static void
ngx_http_waf_audit_ts(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    u_char   buf[sizeof("2026-08-15T21:42:31.660Z") - 1];
    u_char  *p;
    ngx_tm_t tm;

    ngx_gmtime(r->start_sec, &tm);

    p = ngx_sprintf(buf, "%4d-%02d-%02dT%02d:%02d:%02d.%03MZ",
                    tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                    tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec,
                    r->start_msec);

    ngx_http_waf_jw_lit(jw, ",\"ts\":");
    ngx_http_waf_jw_string(jw, buf, (size_t) (p - buf));
}


/*
 * Время записи -- сейчас, а не начало запроса: у кадра и у закрытия сессии
 * момент поступления рукопожатия давно позади, и порядок событий одного
 * соединения строится по их собственному времени.
 */
static void
ngx_http_waf_audit_ts_now(ngx_http_waf_jw_t *jw)
{
    u_char      buf[sizeof("2026-08-15T21:42:31.660Z") - 1];
    u_char     *p;
    ngx_tm_t    tm;
    ngx_time_t *tp;

    tp = ngx_timeofday();

    ngx_gmtime(tp->sec, &tm);

    p = ngx_sprintf(buf, "%4d-%02d-%02dT%02d:%02d:%02d.%03MZ",
                    tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                    tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec,
                    (ngx_msec_t) tp->msec);

    ngx_http_waf_jw_lit(jw, ",\"ts\":");
    ngx_http_waf_jw_string(jw, buf, (size_t) (p - buf));
}


/* Секция frame записи kind=request на фазе кадров. */
static void
ngx_http_waf_audit_frame(ngx_http_waf_jw_t *jw, ngx_http_waf_frame_audit_t *fa)
{
    size_t  n;

    ngx_http_waf_jw_lit(jw, ",\"frame\":{\"conn_id\":\"");
    ngx_http_waf_jw_raw(jw, fa->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(jw, "\",\"seq\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) fa->seq);
    ngx_http_waf_jw_lit(jw, ",\"direction\":");
    ngx_http_waf_jw_str(jw, fa->direction);
    ngx_http_waf_jw_lit(jw, ",\"opcode\":");
    ngx_http_waf_jw_str(jw, fa->opcode);
    ngx_http_waf_jw_lit(jw, ",\"fin\":");

    if (fa->fin) {
        ngx_http_waf_jw_lit(jw, "true");

    } else {
        ngx_http_waf_jw_lit(jw, "false");
    }

    ngx_http_waf_jw_lit(jw, ",\"size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) fa->size);
    ngx_http_waf_jw_lit(jw, ",\"rewritten\":");

    if (fa->rewritten) {
        ngx_http_waf_jw_lit(jw, "true");

    } else {
        ngx_http_waf_jw_lit(jw, "false");
    }

    /* собранное сообщение: из скольких кадров; одиночный кадр поля не несёт */
    if (fa->fragments > 1) {
        ngx_http_waf_jw_lit(jw, ",\"fragments\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) fa->fragments);
    }

    /* вердикт взят из кеша по хешу: инспекторов у записи нет намеренно */
    if (fa->cached) {
        ngx_http_waf_jw_lit(jw, ",\"cached\":true");
    }

    /*
     * Срез полезной нагрузки -- первые байты как есть, экранированные: у
     * текстового кадра это начало сообщения, у двоичного -- то, что есть.
     */
    if (fa->payload != NULL && fa->size != 0) {
        n = ngx_min(fa->size, NGX_HTTP_WAF_AUDIT_FRAME_PREVIEW);

        ngx_http_waf_jw_lit(jw, ",\"payload_preview\":");
        ngx_http_waf_jw_string(jw, fa->payload, n);

        if (n < fa->size) {
            ngx_http_waf_jw_lit(jw, ",\"payload_truncated\":true");
        }
    }

    ngx_http_waf_jw_lit(jw, "}");
}


static void
ngx_http_waf_audit_conn(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    u_char             buf[NGX_SOCKADDR_STRLEN];
    size_t             len;
    ngx_connection_t  *c = r->connection;

    /*
     * Адрес клиента: то же значение, что уезжает инспекторам в conn.client_ip.
     * Это r->connection->addr_text, то есть $remote_addr после realip, а не
     * то, что видно в сокете до подстановки, -- иначе за балансировщиком в
     * поиске инцидента стоял бы его адрес, один на весь трафик.
     */
    ngx_http_waf_jw_lit(jw, ",\"client_ip\":");
    ngx_http_waf_jw_str(jw, &c->addr_text);
    ngx_http_waf_jw_lit(jw, ",\"client_port\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_inet_get_port(c->sockaddr));

    /*
     * Локальный адрес приходится запрашивать явно: при listen на wildcard
     * nginx не заполняет local_sockaddr до первого обращения. Без него на
     * нескольких адресах не понять, какой именно фронт поймал трафик.
     */
    if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) {
        len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf,
                            NGX_SOCKADDR_STRLEN, 0);

        ngx_http_waf_jw_lit(jw, ",\"server_ip\":");
        ngx_http_waf_jw_string(jw, buf, len);
        ngx_http_waf_jw_lit(jw, ",\"server_port\":");
        ngx_http_waf_jw_int(jw,
                            (ngx_int_t) ngx_inet_get_port(c->local_sockaddr));
    }

#if (NGX_SSL)
    if (c->ssl != NULL) {
        ngx_str_t  version, sni;

        /*
         * Секции нет вовсе, если версию рукопожатия узнать не удалось: пустое
         * значение в ней ничем не лучше отсутствия, а разбирать приходится оба
         * случая.
         */
        if (ngx_ssl_get_protocol(c, r->pool, &version) == NGX_OK
            && version.len != 0)
        {
            ngx_http_waf_jw_lit(jw, ",\"tls\":{\"version\":");
            ngx_http_waf_jw_str(jw, &version);

            /* Может расходиться с http.host -- это само по себе сигнал. */
            if (ngx_ssl_get_server_name(c, r->pool, &sni) == NGX_OK
                && sni.len != 0)
            {
                ngx_http_waf_jw_lit(jw, ",\"sni\":");
                ngx_http_waf_jw_str(jw, &sni);
            }

            ngx_http_waf_jw_lit(jw, "}");
        }
    }
#endif
}


/*
 * Размер сырых заголовков и их число. Считается здесь, а не берётся из
 * локатора заголовков: там лежит длина JSON-блоба для обменника, а не то, что
 * пришло по проводу. Формат восстанавливается по составу -- "key: value\r\n",
 * -- потому что после разбора исходного буфера у HTTP/2 не существует вовсе.
 *
 * Считаются заголовки той фазы, о которой запись: на ответе описывать размер
 * запроса значило бы отвечать на вопрос, которого запись не задаёт, -- тем
 * более что рядом с ним стоят длина тела и код ответа этой же фазы.
 */
static void
ngx_http_waf_audit_headers_size(ngx_http_waf_ctx_t *ctx, off_t *size,
    ngx_uint_t *count)
{
    ngx_uint_t     i;
    ngx_keyval_t  *kv;
    ngx_array_t   *pairs;

    *size  = 0;
    *count = 0;

    pairs = ngx_http_waf_header_pairs(ctx);
    if (pairs == NULL) {
        return;
    }

    kv = pairs->elts;

    for (i = 0; i < pairs->nelts; i++) {

        if (kv[i].key.len == 0) {
            continue;
        }

        *size += (off_t) (kv[i].key.len + kv[i].value.len
                          + sizeof(": \r\n") - 1);
        (*count)++;
    }
}


/*
 * Content-Type без параметров: "text/html; charset=utf-8" -> "text/html".
 * Опять же той фазы, о которой запись: тип тела ответа -- это headers_out, и
 * nginx держит его отдельным полем, а не в списке.
 */
static void
ngx_http_waf_audit_content_type(ngx_http_waf_ctx_t *ctx, ngx_str_t *out)
{
    u_char              *p;
    ngx_http_request_t  *r = ctx->request;

    ngx_str_null(out);

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {

        if (r->headers_out.content_type.len == 0) {
            return;
        }

        *out = r->headers_out.content_type;

    } else {

        if (r->headers_in.content_type == NULL) {
            return;
        }

        *out = r->headers_in.content_type->value;
    }

    p = ngx_strlchr(out->data, out->data + out->len, ';');

    if (p != NULL) {
        out->len = (size_t) (p - out->data);
    }

    while (out->len != 0 && out->data[out->len - 1] == ' ') {
        out->len--;
    }
}


static void
ngx_http_waf_audit_http(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    off_t                headers_size;
    ngx_str_t            content_type;
    ngx_uint_t           headers_count;
    ngx_http_request_t  *r = ctx->request;

    ngx_http_waf_audit_headers_size(ctx, &headers_size, &headers_count);
    ngx_http_waf_audit_content_type(ctx, &content_type);

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

    ngx_http_waf_jw_lit(jw, ",\"host\":");
    ngx_http_waf_jw_str(jw, &r->headers_in.server);

    ngx_http_waf_jw_lit(jw, ",\"uri\":");
    ngx_http_waf_jw_str(jw, &r->uri);

    /*
     * Поверхность атаки у версий протокола разная. Пустым http_protocol
     * остаётся ровно на HTTP/0.9: строки версии в таком запросе нет, и назвать
     * её всё равно нужно -- пустое поле схема не принимает.
     */
    ngx_http_waf_jw_lit(jw, ",\"version\":");

    if (r->http_protocol.len != 0) {
        ngx_http_waf_jw_str(jw, &r->http_protocol);

    } else {
        ngx_http_waf_jw_lit(jw, "\"HTTP/0.9\"");
    }

    /*
     * Длины, а не содержимое: аномалия видна и без него, а содержимое едет в
     * обменник. Ноль в args_size означает, что query не было, -- это видно даже
     * когда запись строки запроса выключена.
     */
    ngx_http_waf_jw_lit(jw, ",\"args_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) r->args.len);
    ngx_http_waf_jw_lit(jw, ",\"headers_size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) headers_size);
    ngx_http_waf_jw_lit(jw, ",\"headers_count\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) headers_count);

    /*
     * Сколько байт тела модуль прочитал. С Content-Length расходится при
     * chunked и при усечении -- усечение отмечено в локаторе store.body.
     */
    ngx_http_waf_jw_lit(jw, ",\"body_size\":");
    ngx_http_waf_jw_int(jw,
                        (ctx->ph->locator != NULL)
                            ? (ngx_int_t) ctx->ph->locator->size
                            : 0);

    if (content_type.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"content_type\":");
        ngx_http_waf_jw_str(jw, &content_type);
    }

    /*
     * Код, который модуль отдал клиенту, не апстрим. На allow фазы запроса
     * апстрим ещё не отвечал, поле 0.
     */
    ngx_http_waf_jw_lit(jw, ",\"status\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) ngx_http_waf_audit_status(ctx));

    /*
     * И отдельно -- код самого приложения, до любого вмешательства. Без него
     * запись не отвечает на первый вопрос разбора инцидента: приложение
     * ответило успехом и мы его закрыли, или приложение само упало? В поле
     * status оба случая выглядят одинаково -- там стоит наш код отказа.
     *
     * Поля нет, пока апстрим не отвечал: ноль означал бы "ответил нулём", а
     * такого кода не бывает. На фазе запроса его нет по построению.
     */
    if (ctx->rsp_status != 0) {
        ngx_http_waf_jw_lit(jw, ",\"upstream_status\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) ctx->rsp_status);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Какая конфигурация сработала. Без этого вопрос "почему на этот URL правило
 * не применилось" не разбирается: набор инспекторов, пороги и веса заданы на
 * location.
 */
static void
ngx_http_waf_audit_route(ngx_http_waf_jw_t *jw, ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_waf_loc_conf_t   *wlcf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    /*
     * Оба имени бывают пустыми: server без server_name -- это перехватчик по
     * умолчанию, а пустое имя location означает, что блока нет вовсе и
     * настройки взяты с уровня server. Пустое поле схема не принимает, и
     * подставлять сюда нечего, кроме обозначения самого случая: "_" -- та же
     * запись перехватчика, которой её пишут в конфигурации явно, "/" -- весь
     * охват уровня server.
     */
    ngx_http_waf_jw_lit(jw, ",\"route\":{\"server_name\":");

    if (cscf->server_name.len != 0) {
        ngx_http_waf_jw_str(jw, &cscf->server_name);

    } else {
        ngx_http_waf_jw_lit(jw, "\"_\"");
    }

    ngx_http_waf_jw_lit(jw, ",\"location\":");

    if (clcf->name.len != 0) {
        ngx_http_waf_jw_str(jw, &clcf->name);

    } else {
        ngx_http_waf_jw_lit(jw, "\"/\"");
    }

    /*
     * Uuid пути (waf_route_id) -- ключ, по которому журнал схлопывает трафик
     * маршрута; имя блока рядом остаётся для чтения. Поля нет, если
     * директивы нет: конфигурация не от контроллера, либо запрос остался на
     * уровне server -- с обязательным корнем в панели такого не бывает.
     */
    if (wlcf->route_id.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"id\":");
        ngx_http_waf_jw_str(jw, &wlcf->route_id);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Роль инспектора на этом маршруте. Берётся из конфигурации, а не из ответа:
 * у молчуна ответа нет, а роль у него та же, и именно она объясняет, почему
 * его отсутствие ничего не сорвало.
 */
static ngx_str_t *
ngx_http_waf_audit_role(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_inspector_t *insp,
    ngx_http_waf_reply_t *reply)
{
    static ngx_str_t         passive = ngx_string("passive");
    static ngx_str_t         active  = ngx_string("active");
    static ngx_str_t         vote    = ngx_string("vote");
    ngx_uint_t               was, is;
    ngx_http_waf_mask_t      bit;
    ngx_http_waf_binding_t  *bind;

    bind = ngx_http_waf_binding_find(wlcf, insp->index, ctx->phase);
    was  = (bind != NULL) ? bind->mode : NGX_HTTP_WAF_MODE_ACTIVE;
    bit  = (ngx_http_waf_mask_t) 1 << insp->index;

    /*
     * Действующая роль, а не записанная: сосед мог перевести инспектора
     * глаголом passive/active/vote. У ответившего она зафиксирована в момент
     * ответа; у промолчавшего считается по маскам управления.
     */
    if (reply != NULL && reply->received) {
        is = reply->passive ? NGX_HTTP_WAF_MODE_PASSIVE
             : reply->vote  ? NGX_HTTP_WAF_MODE_VOTE
                            : NGX_HTTP_WAF_MODE_ACTIVE;

    } else if (ctx->ctl[ctx->phase].active & bit) {
        is = NGX_HTTP_WAF_MODE_ACTIVE;

    } else if (ctx->ctl[ctx->phase].passive & bit) {
        is = NGX_HTTP_WAF_MODE_PASSIVE;

    } else if (ctx->ctl[ctx->phase].vote & bit) {
        is = NGX_HTTP_WAF_MODE_VOTE;

    } else {
        is = was;
    }

    if (is == NGX_HTTP_WAF_MODE_PASSIVE) {
        return &passive;
    }

    if (is == NGX_HTTP_WAF_MODE_VOTE) {
        return &vote;
    }

    /*
     * Записан пассивным или совещательным, а гейтил: active печатается,
     * только если она не своя. У записанного off роль в записи -- state.
     */
    return (was == NGX_HTTP_WAF_MODE_PASSIVE || was == NGX_HTTP_WAF_MODE_VOTE)
               ? &active : NULL;
}


/*
 * Одна форма записи на всех участников: и на модуль, и на инспектора.
 * Ровно одно из verdict / state -- участник либо ответил, либо нет.
 *
 * reply == NULL -- запись модуля: у него нет ни round-trip, ни веса, ни
 * профиля, и приписывать их ему нечем.
 */
static void
ngx_http_waf_audit_entry(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t verdict, ngx_http_waf_reply_t *reply,
    ngx_http_waf_inspector_t *insp)
{
    ngx_str_t                *role;
    ngx_uint_t                state;
    ngx_http_waf_loc_conf_t  *wlcf;

    ngx_http_waf_jw_lit(jw, "{");

    if (reply == NULL) {
        ngx_http_waf_jw_lit(jw, "\"verdict\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_verdict_name(verdict));
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (reply->received) {
        /*
         * Заявка в ноль -- это отсутствие заявки: модуль её и не учитывает
         * (ngx_http_waf_account), поэтому в записи она выглядит пропуском, а
         * не счётом без числа.
         */
        if (reply->verdict == NGX_HTTP_WAF_V_SCORE && reply->score > 0) {
            ngx_http_waf_jw_lit(jw, "\"verdict\":\"score\"");

        } else {
            ngx_http_waf_jw_lit(jw, "\"verdict\":");
            ngx_http_waf_jw_str(jw,
                ngx_http_waf_verdict_name(
                    (reply->verdict == NGX_HTTP_WAF_V_SCORE)
                        ? NGX_HTTP_WAF_V_ALLOW
                        : reply->verdict));
        }

        /*
         * Что легло в score.total: при score -- заявка как прислана, у
         * совещательного с deny -- сотня при вердикте deny, плюс очки
         * просьбами score самого отправителя (могут увести и в минус).
         * Множителя на маршруте нет, и второго числа рядом не нужно:
         * арифметика итога сходится по этому полю.
         */
        if (reply->score != 0) {
            ngx_http_waf_jw_lit(jw, ",\"score\":");
            ngx_http_waf_jw_int(jw, reply->score);
        }

        /*
         * Round-trip: публикация волны -> разбор ответа. В kind=inspector есть
         * только engine_ms -- время внутри движка, без шины и очереди, --
         * поэтому "инспектор тормозит" видно исключительно отсюда.
         */
        ngx_http_waf_jw_lit(jw, ",\"latency_ms\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) reply->latency);

    } else {
        /*
         * Ответа не было. Пропуск и отсутствие подписчиков отмечены там, где
         * стали известны; всё остальное, что спрашивали, -- не уложилось в
         * дедлайн фазы.
         */
        state = (reply->state != NGX_HTTP_WAF_ENTRY_ANSWERED)
                    ? reply->state
                    : NGX_HTTP_WAF_ENTRY_TIMEOUT;

        ngx_http_waf_jw_lit(jw, "\"state\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_entry_state_name(state));

        /*
         * У не уложившегося round-trip есть -- это весь бюджет, который он
         * потратил. У пропущенного его нет: волна его не касалась.
         */
        if (state == NGX_HTTP_WAF_ENTRY_TIMEOUT && ctx->ph->wave_published != 0) {
            ngx_http_waf_jw_lit(jw, ",\"latency_ms\":");
            ngx_http_waf_jw_int(jw,
                (ngx_int_t) (ngx_current_msec - ctx->ph->wave_published));
        }
    }

    role = ngx_http_waf_audit_role(ctx, wlcf, insp, reply);

    if (role != NULL) {
        ngx_http_waf_jw_lit(jw, ",\"role\":");
        ngx_http_waf_jw_str(jw, role);
    }

    /*
     * Тот же профиль, что уехал инспектору в route.profile. Пустой слот --
     * литерал "default", как в сообщении волны: иначе чистый allow без находок
     * в карточке выглядит так, будто инспектора звали без набора правил.
     */
    ngx_http_waf_jw_lit(jw, ",\"profile\":");

    if (wlcf->profiles[insp->index].len != 0) {
        ngx_http_waf_jw_str(jw, &wlcf->profiles[insp->index]);

    } else {
        ngx_http_waf_jw_lit(jw, "\"default\"");
    }

    /*
     * Секция rewrite: то, что ушло получателю, разошлось с тем, что снято и
     * заархивировано -- архив хранит оригинал, а получатель получил объект
     * инспектора или его правки строки запроса. Без этой пометки расхождение
     * выглядело бы порчей данных, а не работой контура. Печатается у автора
     * секции.
     */
    if (reply != NULL && reply->received
        && (reply->rewrite_has || reply->args_set != NULL
            || reply->args_unset != NULL))
    {
        ngx_http_waf_jw_lit(jw, ",\"rewrite\":{\"applied\":");

        if (reply->rewrite_body) {

            if (ngx_http_waf_rewrite_applied(ctx, insp->index)) {
                ngx_http_waf_jw_lit(jw, "true");

            } else {
                ngx_http_waf_jw_lit(jw, "false");
            }

            ngx_http_waf_jw_lit(jw, ",\"size\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) reply->rewrite_size);

            /*
             * Контрольная сумма поднятого объекта: единственный след того, что
             * получатель получил вместо оригинала, -- сам объект из обменника
             * после подъёма удалён, а в архиве лежит оригинал. Есть только у
             * состоявшейся подмены: у сорвавшейся сравнивать не с чем.
             */
            if (reply->rewrite_digest) {
                u_char  hex[64];

                (void) ngx_hex_dump(hex, reply->rewrite_sha256, 32);

                ngx_http_waf_jw_lit(jw, ",\"sha256\":\"");
                ngx_http_waf_jw_raw(jw, hex, 64);
                ngx_http_waf_jw_lit(jw, "\"");
            }

            /*
             * Подмена легла на неполный снимок: объект не поднят
             * (applied:false), это сбой подъёма, исход решила политика.
             * Опции отдать кусок нет ни на одной фазе.
             */
            if (reply->rewrite_partial) {
                ngx_http_waf_jw_lit(jw, ",\"partial\":true");
            }

        } else if (reply->passive || reply->vote) {
            ngx_http_waf_jw_lit(jw, "false");

        } else if (reply->rewrite_has) {
            /* только заголовки: их применяют переопределения */
            ngx_http_waf_jw_lit(jw, "true");

        } else if (reply->args_applied) {
            /* только строка запроса */
            ngx_http_waf_jw_lit(jw, "true");

        } else {
            ngx_http_waf_jw_lit(jw, "false");
        }

        /*
         * Правки строки запроса по именам -- своя пара: легли ли и сколько
         * операций. applied:false -- маршрут их не принял (waf_send request
         * args=original), исход не allow или строка не собралась.
         */
        if (reply->args_set != NULL || reply->args_unset != NULL) {
            ngx_http_waf_jw_lit(jw, ",\"args\":{\"applied\":");

            if (reply->args_applied) {
                ngx_http_waf_jw_lit(jw, "true");

            } else {
                ngx_http_waf_jw_lit(jw, "false");
            }

            ngx_http_waf_jw_lit(jw, ",\"set\":");
            ngx_http_waf_jw_int(jw, reply->args_set != NULL
                                        ? (ngx_int_t) reply->args_set->nelts
                                        : 0);
            ngx_http_waf_jw_lit(jw, ",\"unset\":");
            ngx_http_waf_jw_int(jw, reply->args_unset != NULL
                                        ? (ngx_int_t) reply->args_unset->nelts
                                        : 0);
            ngx_http_waf_jw_lit(jw, "}");
        }

        if (reply->rewrite_groups != NULL
            && reply->rewrite_groups->nelts != 0)
        {
            ngx_str_t   *group = reply->rewrite_groups->elts;
            ngx_uint_t   g;

            ngx_http_waf_jw_lit(jw, ",\"groups\":[");

            for (g = 0; g < reply->rewrite_groups->nelts; g++) {
                if (g != 0) {
                    ngx_http_waf_jw_lit(jw, ",");
                }

                ngx_http_waf_jw_str(jw, &group[g]);
            }

            ngx_http_waf_jw_lit(jw, "]");
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Все участники фазы одной картой: module есть всегда, инспектор -- если его
 * звали. Промолчавший тоже здесь, со state вместо вердикта: без него
 * code=fail_timeout не объясняет, из-за кого.
 */
static void
ngx_http_waf_audit_inspectors(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t verdict)
{
    ngx_uint_t                 i, n;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    n    = wmcf->inspectors.nelts;

    ngx_http_waf_jw_lit(jw, ",\"inspectors\":{");
    ngx_http_waf_jw_str(jw, &ngx_http_waf_audit_module);
    ngx_http_waf_jw_lit(jw, ":");
    ngx_http_waf_audit_entry(jw, ctx, verdict, NULL, NULL);

    if (ctx->ph->replies == NULL) {
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    /*
     * Выключенные (state off) печатаются наравне со спрошенными:
     * "инспектора не звали" -- такое же объяснение решения, как его вердикт.
     */
    for (i = 0; i < n; i++) {

        if (!((ctx->ph->published | ctx->ph->controlled) & (1ULL << i))) {
            continue;
        }

        ngx_http_waf_jw_lit(jw, ",");
        ngx_http_waf_jw_str(jw, &insp[i].name);
        ngx_http_waf_jw_lit(jw, ":");
        ngx_http_waf_audit_entry(jw, ctx, verdict, &ctx->ph->replies[i], &insp[i]);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Живые действия запроса: кто, кому, о чём просил и был ли при этом пассивен.
 *
 * Действие, не попавшее в аудит, -- невидимая причина видимого решения: по
 * записи должно быть видно, почему клиент увидел капчу, без доступа к самим
 * инспекторам. Поэтому здесь перечислены все живые, а не только применённые:
 * применённые называет получатель, в своём kind=inspector.
 */
static void
ngx_http_waf_audit_actions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t frame)
{
    ngx_uint_t                 i, n, printed;
    ngx_http_waf_action_t     *action;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->actions == NULL || ctx->actions->nelts == 0) {
        return;
    }

    wmcf   = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp   = wmcf->inspectors.elts;
    n      = wmcf->inspectors.nelts;
    action = ctx->actions->elts;

    /*
     * У записи кадра ctx->actions -- набор рукопожатия плюс просьбы этого
     * кадра. Первые печатались бы на каждом кадре сотни раз; пишутся только
     * высказанные на кадре -- по ним видно, кто позвал вторую волну и о чём
     * просил.
     */
    printed = 0;

    for (i = 0; i < ctx->actions->nelts; i++) {
        if (!frame || ngx_http_waf_phase_is_frame(action[i].phase)) {
            printed++;
        }
    }

    if (printed == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"actions\":[");
    printed = 0;

    for (i = 0; i < ctx->actions->nelts; i++) {

        if (frame && !ngx_http_waf_phase_is_frame(action[i].phase)) {
            continue;
        }

        if (printed++ != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_lit(jw, "{\"from\":");

        if (action[i].from < n) {
            ngx_http_waf_jw_str(jw, &insp[action[i].from].name);

        } else {
            ngx_http_waf_jw_lit(jw, "null");
        }

        /*
         * Широковещательное действие поля to не имеет вовсе: "всем" -- это не
         * имя адресата, и печатать его звёздочкой значило бы завести в схеме
         * имя, которого нет в реестре.
         */
        if (action[i].to != NGX_HTTP_WAF_ACTION_ALL && action[i].to < n) {
            ngx_http_waf_jw_lit(jw, ",\"to\":");
            ngx_http_waf_jw_str(jw, &insp[action[i].to].name);
        }

        /*
         * Фаза вызова адресата у управляющего глагола. На проводе инспектора
         * это поле phase, но здесь phase уже занято -- где высказано, -- и
         * адрес печатается как to_phase, рядом с to.
         */
        if (action[i].to_phases != 0) {
            ngx_http_waf_jw_lit(jw, ",\"to_phase\":");
            ngx_http_waf_jw_str(jw,
                                ngx_http_waf_to_phase_name(action[i].to_phases));
        }

        ngx_http_waf_jw_lit(jw, ",\"do\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_do_name(action[i].verb));

        ngx_http_waf_jw_lit(jw, ",\"apply\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_apply_name(action[i].apply));

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

        if (action[i].marker.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"marker\":");
            ngx_http_waf_jw_str(jw, &action[i].marker);
        }

        if (action[i].set == NGX_HTTP_WAF_SET_ON) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"on\"");

        } else if (action[i].set == NGX_HTTP_WAF_SET_OFF) {
            ngx_http_waf_jw_lit(jw, ",\"set\":\"off\"");
        }

        ngx_http_waf_action_archive_write(jw, &action[i]);

        ngx_http_waf_jw_lit(jw, ",\"phase\":");
        ngx_http_waf_jw_str(jw, ngx_http_waf_phase_name(action[i].phase));

        /*
         * Отправитель пассивен -- значит, действие никому не доставлено: его
         * записи в prior нет вовсе. Здесь оно всё равно перечислено, и здесь же
         * единственное место, где "что было бы, если инспектора включить"
         * вообще можно прочитать.
         */
        if (action[i].passive) {
            ngx_http_waf_jw_lit(jw, ",\"passive\":true");

        } else {
            ngx_http_waf_jw_lit(jw, ",\"passive\":false");
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "]");
}


/*
 * Маркеры записи: метки, которые попросили поставить глаголом mark.
 *
 * У всех записей, включая кадры: метка называет событие, а событие у кадра
 * своё. Набор рукопожатия кадр наследует (stream/ngx_http_waf_frame.c), и
 * помеченное на рукопожатии стоит на каждом кадре соединения -- в отличие от
 * действий, которые печатаются там, где высказаны: строка в множестве стоит
 * дёшево, а искать кадры по метке иначе пришлось бы через склейку по ray.
 */
static void
ngx_http_waf_audit_markers(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i;
    ngx_str_t  *m;

    if (ctx->markers == NULL || ctx->markers->nelts == 0) {
        return;
    }

    m = ctx->markers->elts;

    ngx_http_waf_jw_lit(jw, ",\"markers\":[");

    for (i = 0; i < ctx->markers->nelts; i++) {

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &m[i]);
    }

    ngx_http_waf_jw_lit(jw, "]");
}


/*
 * Сессии запроса, как их назвали инспекторы: секция sessions записи.
 *
 * Только у записей запроса и ответа: кадры WebSocket лежат под ray
 * рукопожатия, и печатать одни и те же сессии на каждом кадре значило бы
 * повторять их сотни раз ради склейки, которая и так есть.
 */
static void
ngx_http_waf_audit_sessions(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, n;
    ngx_http_waf_session_t    *sess;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->sessions == NULL || ctx->sessions->nelts == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;
    n    = wmcf->inspectors.nelts;
    sess = ctx->sessions->elts;

    ngx_http_waf_jw_lit(jw, ",\"sessions\":[");

    for (i = 0; i < ctx->sessions->nelts; i++) {

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_lit(jw, "{\"by\":");

        if (sess[i].by < n) {
            ngx_http_waf_jw_str(jw, &insp[sess[i].by].name);

        } else {
            ngx_http_waf_jw_lit(jw, "null");
        }

        ngx_http_waf_jw_lit(jw, ",\"source\":");
        ngx_http_waf_jw_str(jw, &sess[i].source);

        ngx_http_waf_jw_lit(jw, ",\"kind\":");
        ngx_http_waf_jw_str(jw, &sess[i].kind);

        ngx_http_waf_jw_lit(jw, ",\"user\":");
        ngx_http_waf_jw_str(jw, &sess[i].user);

        ngx_http_waf_jw_lit(jw, ",\"id\":");
        ngx_http_waf_jw_str(jw, &sess[i].id);

        if (sess[i].verified) {
            ngx_http_waf_jw_lit(jw, ",\"verified\":true");

        } else {
            ngx_http_waf_jw_lit(jw, ",\"verified\":false");
        }

        if (sess[i].issued != 0) {
            ngx_http_waf_jw_lit(jw, ",\"issued\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].issued);
        }

        if (sess[i].expires != 0) {
            ngx_http_waf_jw_lit(jw, ",\"expires\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) sess[i].expires);
        }

        if (sess[i].groups.len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"groups\":");
            ngx_http_waf_jw_str(jw, &sess[i].groups);
        }

        /*
         * Отправитель пассивен: заголовки личности приложению не легли, а
         * запись всё равно здесь -- единственное место, где видно, кого
         * назвала бы калитка, будь она боевой.
         */
        if (sess[i].passive) {
            ngx_http_waf_jw_lit(jw, ",\"passive\":true");
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "]");
}


/*
 * Пишется ли этот кадр по политике маршрута: deny -- только кадр, у которого
 * есть что сказать (отказ, подмена, счёт), all -- каждый sample-й
 * спрошенный, off -- никакой. Зовётся из записи, когда подмена уже известна.
 */
static ngx_uint_t
ngx_http_waf_frame_audit_policy(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_frame_audit_t *fa)
{
    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_OFF
        || !ngx_http_waf_frame_audit(ctx, fa))
    {
        return 0;
    }

    /*
     * Сосед сказал своё глаголом записи: on -- писать этот кадр
     * вопреки deny и sample=; off -- писать только то, что нечем объяснить,
     * как при deny. Выключенный журнал кадров просьба не включает: off у
     * маршрута -- это "кадров в журнале нет", а не "мало".
     */
    if (ngx_http_waf_audit_ovr_cur(ctx)->audit.set == NGX_HTTP_WAF_SET_ON) {
        return 1;
    }

    if ((wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_DENY
         || ngx_http_waf_audit_ovr_cur(ctx)->audit.set == NGX_HTTP_WAF_SET_OFF)
        && ngx_http_waf_audit_verdict(ctx) == NGX_HTTP_WAF_V_ALLOW
        && !fa->rewritten && ctx->ph->score == 0)
    {
        return 0;
    }

    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_ALL
        && wlcf->audit_frames_sample > 1
        && (fa->seq % wlcf->audit_frames_sample) != 0)
    {
        return 0;
    }

    return 1;
}


ngx_uint_t
ngx_http_waf_audit_enabled(void)
{
    return ngx_http_waf_agent_fd != (ngx_socket_t) -1;
}


ngx_uint_t
ngx_http_waf_frame_audit_wanted(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t     *wlcf;
    ngx_http_waf_frame_audit_t   fa;

    if (ngx_http_waf_agent_fd == (ngx_socket_t) -1) {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return ngx_http_waf_frame_audit_policy(ctx, wlcf, &fa);
}


/*
 * Локаторы обменника: где лежит то, что в датаграмму не влезает. Секции нет,
 * если обменник не задействован, -- локального бана волна не открывала.
 * Разобранных cookie нет: сырой Cookie лежит внутри headers.
 */
static void
ngx_http_waf_audit_store(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i, used, keep;

    used = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        if (ngx_http_waf_store_locator(ctx, i) != NULL) {
            used = 1;
            break;
        }
    }

    if (!used) {
        return;
    }

    /*
     * Что осталось лежать в обменнике. Всё остальное модуль удалил ещё до сборки
     * этой записи -- при разрешении вердикта, -- поэтому адресация пишется
     * только у названных здесь: ключ, по которому уже ничего не достать, в
     * записи не появляется.
     */
    keep = ngx_http_waf_archive_mask(ctx);

    /*
     * Та же секция и та же форма локатора, что в сообщении инспектору: логер
     * достаёт содержимое по записи аудита тем же кодом, которым инспектор
     * доставал его во время инспекции. Отличие одно -- здесь видны все три
     * объекта, а не только те, что просил конкретный инспектор.
     */
    ngx_http_waf_jw_lit(jw, ",\"store\":{\"headers\":");
    ngx_http_waf_locator_write(jw,
        ngx_http_waf_store_locator(ctx, NGX_HTTP_WAF_OBJ_HEADERS),
        (keep & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS))
            ? NGX_HTTP_WAF_LOC_ADDRESS : 0);

    ngx_http_waf_jw_lit(jw, ",\"args\":");
    ngx_http_waf_locator_write(jw,
        ngx_http_waf_store_locator(ctx, NGX_HTTP_WAF_OBJ_ARGS),
        (keep & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS))
            ? NGX_HTTP_WAF_LOC_ADDRESS : 0);

    ngx_http_waf_jw_lit(jw, ",\"body\":");
    ngx_http_waf_locator_write(jw,
        ngx_http_waf_store_locator(ctx, NGX_HTTP_WAF_OBJ_BODY),
        NGX_HTTP_WAF_LOC_BODY
        | ((keep & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
               ? NGX_HTTP_WAF_LOC_ADDRESS : 0));

    /*
     * Кого агент забирает себе. Без этого поля он не отличит объект, который
     * ему передали, от того, чей ключ просто ещё не истёк.
     */
    if (keep != 0) {
        ngx_http_waf_archive_write(jw, ctx, keep);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


ngx_int_t
ngx_http_waf_audit_init_worker(ngx_cycle_t *cycle)
{
    int                        sndbuf;
    socklen_t                  len;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_socket_t               s;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    ngx_http_waf_agent_fd = (ngx_socket_t) -1;

    if (wmcf == NULL || wmcf->agent_socket.len == 0) {
        return NGX_OK;
    }

    if (wmcf->agent_socket.len >= sizeof(ngx_http_waf_agent_addr.sun_path)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "waf: waf_agent_socket is too long");
        return NGX_ERROR;
    }

    s = ngx_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "waf: socket(AF_UNIX, SOCK_DGRAM) failed");
        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "waf: nonblocking agent socket failed");
        ngx_close_socket(s);
        return NGX_ERROR;
    }

    /*
     * Датаграмму длиннее буфера отправки ядро не примет вовсе. Неудача здесь
     * не повод не стартовать -- умолчания хватает записи без превью, -- но
     * знать о ней надо до первой потерянной записи.
     */
    sndbuf = NGX_HTTP_WAF_AUDIT_SNDBUF;

    if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const void *) &sndbuf,
                   sizeof(int)) == -1)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_socket_errno,
                      "waf: SO_SNDBUF %d on the agent socket failed; large "
                      "previews may not fit a datagram", sndbuf);

    } else {
        /*
         * Просьбу ядро молча урезает до net.core.wmem_max, и об этом узнать
         * можно только спросив обратно. Пропустить проверку значило бы
         * получить EMSGSIZE на каждой записи с большим превью -- не при
         * старте, а под нагрузкой, и без единого слова о причине.
         *
         * Linux сообщает удвоенное значение: половина буфера уходит на
         * служебные структуры сокета. Отсюда деление, а не сравнение как есть.
         */
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *) &sndbuf, &len) == 0
            && sndbuf / 2 < NGX_HTTP_WAF_AUDIT_SNDBUF)
        {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "waf: the kernel capped the agent socket send "
                          "buffer at %d bytes, below the %d a record with "
                          "previews may need; raise net.core.wmem_max",
                          sndbuf / 2, NGX_HTTP_WAF_AUDIT_SNDBUF);
        }
    }

    ngx_memzero(&ngx_http_waf_agent_addr, sizeof(ngx_http_waf_agent_addr));
    ngx_http_waf_agent_addr.sun_family = AF_UNIX;
    ngx_cpystrn((u_char *) ngx_http_waf_agent_addr.sun_path,
                wmcf->agent_socket.data,
                sizeof(ngx_http_waf_agent_addr.sun_path));
    ngx_http_waf_agent_addrlen = (socklen_t)
        (offsetof(struct sockaddr_un, sun_path) + wmcf->agent_socket.len + 1);

    ngx_http_waf_agent_fd = s;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "waf: agent socket \"%V\"", &wmcf->agent_socket);

    return NGX_OK;
}


void
ngx_http_waf_audit_exit_worker(ngx_cycle_t *cycle)
{
    if (ngx_http_waf_agent_fd != (ngx_socket_t) -1) {
        ngx_close_socket(ngx_http_waf_agent_fd);
        ngx_http_waf_agent_fd = (ngx_socket_t) -1;
    }

    (void) cycle;
}


void
ngx_http_waf_audit_request(ngx_http_waf_ctx_t *ctx)
{
    u_char                    *json;
    size_t                     size;
    ngx_int_t                  deny_at;
    ngx_http_waf_jw_t          jw;
    ngx_http_request_t        *r;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_uint_t                 verdict, frame;
    ssize_t                    n;
    ngx_http_waf_frame_audit_t fa;

    if (ngx_http_waf_agent_fd == (ngx_socket_t) -1) {
        return;
    }

    r = ctx->request;
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    /*
     * Кадры пишутся по своей политике (waf_audit_frames), а не по сэмплу
     * запросов. Тот же предикат решает и судьбу объекта кадра в обменнике
     * (ngx_http_waf_archive_mask): без записи передавать его агенту некому.
     */
    frame = 0;

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {

        if (!ngx_http_waf_frame_audit_policy(ctx, wlcf, &fa)) {
            return;
        }

        frame = 1;

    } else if (!ngx_http_waf_audit_keep(ctx, wlcf)) {
        /* Прорежено сэмплом: запись не собирается и датаграмма не уходит. */
        return;
    }

    /*
     * Размер буфера -- это размер датаграммы, и он известен из конфигурации
     * маршрута до первого записанного байта. Бюджеты превью проверены на
     * nginx -t, поэтому переполнение здесь означало бы ошибку расчёта, а не
     * слишком длинный запрос.
     */
    size = NGX_HTTP_WAF_AUDIT_JSON
           /* с учётом бюджетов, назначенных просьбой audit на этом запросе */
           + ngx_http_waf_preview_room_ctx(ctx)
           /*
            * Действия -- переменная часть записи, ограниченная маршрутом. В
            * NGX_HTTP_WAF_AUDIT_JSON они не входят: там считаемая верхняя
            * граница полей самого запроса, а канал переписки настраивается
            * отдельно и на каждом location по-своему.
            */
           + wlcf->actions_max * (wlcf->action_max + 128)
           /* сессии: потолок на запрос, строки после экранирования */
           + (frame ? 0 : NGX_HTTP_WAF_SESSIONS_MAX * NGX_HTTP_WAF_SESSION_JSON)
           /* маркеры: потолок на запись, строки после экранирования */
           + NGX_HTTP_WAF_MARKERS_JSON
           /* route.id -- uuid пути, длина известна из конфигурации */
           + wlcf->route_id.len
           /* секция frame: кадрирование и срез полезной нагрузки */
           + (frame ? 256 + NGX_HTTP_WAF_AUDIT_FRAME_PREVIEW * 6 : 0);

    json = ngx_pnalloc(r->pool, size);
    if (json == NULL) {
        return;
    }

    verdict = ngx_http_waf_audit_verdict(ctx);
    deny_at = ngx_http_waf_score_deny_at(ctx);

    ngx_http_waf_jw_init(&jw, json, size);

    /* --- идентификация --- */

    /*
     * Кадр пишется под ray рукопожатия: соединение -- один запрос, и все его
     * записи (рукопожатие, кадры, сессия) лежат под одним ray. Кадр внутри
     * него адресуется стороной и номером (секция frame); таблица аудита
     * держит их в ключе, чтобы кадры не схлопывались друг с другом.
     */
    ngx_http_waf_jw_lit(&jw, "{\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->ray_hex, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\",\"node\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);
    ngx_http_waf_jw_lit(&jw, ",\"phase\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_phase_name(ctx->phase));

    if (frame) {
        ngx_http_waf_audit_ts_now(&jw);

    } else {
        ngx_http_waf_audit_ts(&jw, r);
    }

    /* --- соединение и запрос --- */

    ngx_http_waf_audit_conn(&jw, r);
    ngx_http_waf_audit_http(&jw, ctx);
    ngx_http_waf_audit_route(&jw, r);

    if (frame) {
        ngx_http_waf_audit_frame(&jw, &fa);
    }

    /* --- решение --- */

    ngx_http_waf_jw_lit(&jw, ",\"verdict\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_verdict_name(verdict));

    /* Кода нет ровно на allow: запрос прошёл, объяснять нечего. */
    if (verdict != NGX_HTTP_WAF_V_ALLOW
        && ctx->ph->code != NGX_HTTP_WAF_CODE_NONE)
    {
        ngx_http_waf_jw_lit(&jw, ",\"code\":");
        ngx_http_waf_jw_str(&jw, ngx_http_waf_code_name(ctx->ph->code));
    }

    ngx_http_waf_jw_lit(&jw, ",\"by\":");
    ngx_http_waf_jw_str(&jw, ngx_http_waf_audit_by(ctx));

    /*
     * Счёт есть, если маршрут его считает, -- набрался он или нет. Ноль при
     * известном пороге и отсутствие секции читаются по-разному: первое значит
     * "считали, никто не начислил", второе -- "на этом маршруте не считают".
     * Без порога же несопоставимы события разных location: 30 из 50 и 30 из
     * 500 -- это разные инциденты, а в записи они выглядели бы одинаково.
     */
    if (deny_at > 0) {
        ngx_http_waf_jw_lit(&jw, ",\"score\":{\"total\":");
        ngx_http_waf_jw_int(&jw, ctx->ph->score);
        ngx_http_waf_jw_lit(&jw, ",\"deny_at\":");
        ngx_http_waf_jw_int(&jw, deny_at);

        /*
         * Взвешенный вклад пассивных и совещательных. В total не входит и
         * порог не двигает: это ответ на "сколько было бы, переведи их в
         * боевые".
         */
        if (ctx->ph->shadow > 0) {
            ngx_http_waf_jw_lit(&jw, ",\"shadow\":");
            ngx_http_waf_jw_int(&jw, ctx->ph->shadow);
        }

        ngx_http_waf_jw_lit(&jw, "}");
    }

    ngx_http_waf_audit_inspectors(&jw, ctx, verdict);

    /*
     * Просьбы соседей живут на запросе и в пуле кадра (docs/streaming.md):
     * у записи кадра печатаются только высказанные на этом кадре, набор
     * рукопожатия -- в записи рукопожатия.
     */
    ngx_http_waf_audit_actions(&jw, ctx, frame);

    /*
     * Сессии -- свойство запроса, не кадра: у записи рукопожатия целиком,
     * у кадров -- по склейке под тем же ray.
     */
    if (!frame) {
        ngx_http_waf_audit_sessions(&jw, ctx);
    }

    /* Маркеры -- свойство записи, и у кадра она своя. */
    ngx_http_waf_audit_markers(&jw, ctx);

    /* --- контекст --- */

    /* Запись аудита везёт набор целиком: выбора по инспектору здесь нет. */
    ngx_http_waf_vars_write(&jw, ctx, NGX_HTTP_WAF_VAR_MAX,
                            NGX_HTTP_WAF_VARS_ALL);
    ngx_http_waf_audit_store(&jw, ctx);

    /*
     * Срез запроса. Не описание объекта в обменнике, а само содержимое -- в том
     * объёме, который назвала конфигурация. Пишется последним из полей запроса:
     * это единственная секция, чья длина не выводится из остальных, и держать
     * её рядом с ними значило бы мешать читать документ глазами.
     */
    ngx_http_waf_preview_write(&jw, ctx);

    ngx_http_waf_jw_lit(&jw, ",\"waf_latency_us\":");
    ngx_http_waf_jw_int(&jw,
                        (ngx_int_t) (ngx_current_msec - ctx->started) * 1000);
    ngx_http_waf_jw_lit(&jw, "}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: agent event overflow, ray %*s",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        return;
    }

    n = sendto(ngx_http_waf_agent_fd, json, ngx_http_waf_jw_len(&jw),
               MSG_DONTWAIT,
               (struct sockaddr *) &ngx_http_waf_agent_addr,
               ngx_http_waf_agent_addrlen);

    if (n == -1) {

        /*
         * Полная очередь и неподнятый агент -- рабочие состояния: запись
         * теряется, запрос идёт дальше, и на каждый такой промах в лог писать
         * нечего. Слишком длинная датаграмма -- другое дело: она не пролезет
         * никогда и ни при какой нагрузке, а причина у неё одна -- бюджеты
         * превью против буферов сокета.
         */
        if (ngx_socket_errno == EMSGSIZE) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_socket_errno,
                          "waf: agent event of %uz bytes does not fit a "
                          "datagram; lower the preview budgets",
                          ngx_http_waf_jw_len(&jw));
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_socket_errno,
                       "waf: agent socket send dropped");
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "waf: agent verdict %uz bytes", (size_t) n);
}


/*
 * Запись phase=session: итог соединения при закрытии. Ray -- ray
 * рукопожатия, чтобы карточка сессии стояла рядом с ним; контекст
 * соединения, запроса и маршрута -- те же, что у рукопожатия. Пишется при
 * любой политике, кроме off: одна запись на соединение стоит дёшево, а без
 * неё поток кадров невидим целиком.
 */
void
ngx_http_waf_audit_session(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_session_audit_t *sess)
{
    u_char                    *json;
    size_t                     size;
    ssize_t                    n;
    ngx_str_t                  why;
    ngx_http_waf_jw_t          jw;
    ngx_http_request_t        *r;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ngx_http_waf_agent_fd == (ngx_socket_t) -1) {
        return;
    }

    r    = ctx->request;
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->audit_frames == NGX_HTTP_WAF_AUDIT_FRAMES_OFF) {
        return;
    }

    size = NGX_HTTP_WAF_AUDIT_JSON + wlcf->route_id.len + 512;

    json = ngx_pnalloc(r->pool, size);
    if (json == NULL) {
        return;
    }

    ngx_http_waf_jw_init(&jw, json, size);

    ngx_http_waf_jw_lit(&jw, "{\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, sess->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\",\"node\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);
    ngx_http_waf_jw_lit(&jw, ",\"phase\":");
    ngx_http_waf_jw_str(&jw, &ngx_http_waf_audit_session_phase);

    ngx_http_waf_audit_ts_now(&jw);

    ngx_http_waf_audit_conn(&jw, r);
    ngx_http_waf_audit_http(&jw, ctx);
    ngx_http_waf_audit_route(&jw, r);

    /*
     * Вердикт сессии -- deny, если её закрыл WAF: по нему сессии с отказом
     * находятся тем же фильтром, что запросы. Иначе allow.
     */
    ngx_http_waf_jw_lit(&jw, ",\"verdict\":");

    /*
     * Код -- свой, ws_close: закрыл соединение модуль по политике кадра, а
     * какой инспектор и чем -- у записи того кадра. "inspector" врал бы:
     * участников у сессии нет.
     */
    if (ngx_strcmp(sess->close_reason, "waf_deny") == 0) {
        ngx_http_waf_jw_lit(&jw, "\"deny\",\"code\":\"ws_close\"");

    } else {
        ngx_http_waf_jw_lit(&jw, "\"allow\"");
    }

    ngx_http_waf_jw_lit(&jw, ",\"by\":");
    ngx_http_waf_jw_str(&jw, &ngx_http_waf_audit_module);

    ngx_http_waf_jw_lit(&jw, ",\"inspectors\":{}");

    ngx_http_waf_jw_lit(&jw, ",\"session\":{\"conn_id\":\"");
    ngx_http_waf_jw_raw(&jw, sess->conn_id, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\",\"protocol\":\"websocket\",\"frames_c2s\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->frames_c2s);
    ngx_http_waf_jw_lit(&jw, ",\"frames_s2c\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->frames_s2c);
    ngx_http_waf_jw_lit(&jw, ",\"bytes_c2s\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->bytes_c2s);
    ngx_http_waf_jw_lit(&jw, ",\"bytes_s2c\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->bytes_s2c);
    ngx_http_waf_jw_lit(&jw, ",\"frames_denied\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->denied);
    ngx_http_waf_jw_lit(&jw, ",\"frames_rewritten\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->rewritten);
    ngx_http_waf_jw_lit(&jw, ",\"frames_cached\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->cached);
    ngx_http_waf_jw_lit(&jw, ",\"messages_reassembled\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->reassembled);
    ngx_http_waf_jw_lit(&jw, ",\"control_dropped\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->control_dropped);
    ngx_http_waf_jw_lit(&jw, ",\"close_code\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->close_code);
    ngx_http_waf_jw_lit(&jw, ",\"close_reason\":");

    why.data = (u_char *) sess->close_reason;
    why.len  = ngx_strlen(sess->close_reason);
    ngx_http_waf_jw_str(&jw, &why);

    if (sess->close_why != NULL) {
        ngx_http_waf_jw_lit(&jw, ",\"close_why\":");
        why.data = (u_char *) sess->close_why;
        why.len  = ngx_strlen(sess->close_why);
        ngx_http_waf_jw_str(&jw, &why);
    }

    ngx_http_waf_jw_lit(&jw, ",\"duration_ms\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) sess->duration_ms);
    ngx_http_waf_jw_lit(&jw, "}");

    ngx_http_waf_jw_lit(&jw, ",\"waf_latency_us\":0}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: agent session event overflow, conn %*s",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, sess->conn_id);
        return;
    }

    n = sendto(ngx_http_waf_agent_fd, json, ngx_http_waf_jw_len(&jw),
               MSG_DONTWAIT,
               (struct sockaddr *) &ngx_http_waf_agent_addr,
               ngx_http_waf_agent_addrlen);

    if (n == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, ngx_socket_errno,
                       "waf: agent session send dropped");
    }
}
