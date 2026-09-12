/*
 * Срез запроса для записи аудита: заголовки, параметры, тело.
 *
 * Единственное место, где содержимое запроса попадает в саму запись, а не в
 * обменник. Отсюда все правила этого файла:
 *
 * -- Предел считается по байтам, записанным в JSON, а не по исходным. Длину
 *    заголовка задаёт клиент, экранирование раздувает её непредсказуемо, и
 *    только счёт по выходу даёт размер датаграммы, известный до отправки.
 *
 * -- Секция обрывается на последней паре, целиком уместившейся в бюджет.
 *    Оборванная посередине пара -- это сломанный JSON у получателя, а
 *    получатель у датаграммы один и разбирает её целиком.
 *
 * -- Потолок на пару делит бюджет между парами, чтобы один разросшийся
 *    заголовок не вытеснил остальные. Правило намеренно несимметрично к имени и
 *    значению: имя пишется первым, и если оно заняло больше половины потолка,
 *    пара выбрасывается целиком. Имя такой длины само по себе улика, обрезок
 *    значения при нём ничего не добавит, а обрезанное имя дало бы ключ, по
 *    которому не ищется ни один запрос. Уложившееся имя оставляет остаток
 *    значению: оно режется по границе символа UTF-8 и помечается третьим
 *    элементом пары.
 *
 * -- Ни одна ошибка здесь не имеет права изменить вердикт. Превью описывает
 *    запрос, а не решает его судьбу: не поместилось -- значит, в записи будет
 *    меньше, чем хотелось, и ничего больше.
 */

#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "runtime/ngx_http_waf_preview.h"


/* Судьба пары: записана, выброшена по имени, не влезла в остаток бюджета. */
typedef enum {
    NGX_HTTP_WAF_PREVIEW_PAIR_OK = 0,
    NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED,
    NGX_HTTP_WAF_PREVIEW_PAIR_FULL
} ngx_http_waf_preview_pair_e;


static void ngx_http_waf_preview_headers(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static void ngx_http_waf_preview_args(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static void ngx_http_waf_preview_body(ngx_http_waf_jw_t *jw,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_loc_conf_t *wlcf);
static ngx_uint_t ngx_http_waf_preview_pair(ngx_http_waf_jw_t *jw, size_t room,
    ngx_str_t *name, ngx_str_t *value, ngx_uint_t first, size_t item_max);
static void ngx_http_waf_preview_dropped(ngx_http_waf_jw_t *jw,
    const char *field, ngx_uint_t dropped);
static size_t ngx_http_waf_preview_text(ngx_http_waf_jw_t *jw, u_char *data,
    size_t len, size_t room);
static ngx_uint_t ngx_http_waf_preview_allowed(ngx_str_t *name,
    ngx_array_t *allow, ngx_array_t *deny);
static ngx_uint_t ngx_http_waf_preview_listed(ngx_array_t *list,
    ngx_str_t *name);
static void ngx_http_waf_preview_budgets(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, size_t budget[NGX_HTTP_WAF_OBJ_COUNT]);
static size_t ngx_http_waf_preview_overhead(void);
static void ngx_http_waf_preview_lists(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj, ngx_array_t **allow,
    ngx_array_t **deny, ngx_array_t **mask, ngx_array_t **cap_deny,
    ngx_array_t **cap_mask);
static void ngx_http_waf_preview_hash(ngx_str_t *src, u_char hex[64]);
static size_t ngx_http_waf_preview_take(ngx_http_request_t *r, u_char *dst,
    size_t size);


/*
 * Имена секций, скобки массивов и счётчики выброшенных пар сверх бюджетов.
 * Мелочь, но буфер рассчитывается по этой сумме, а бюджет обязан достаться
 * данным целиком: иначе последняя пара не влезала бы из-за закрывающей
 * скобки.
 *
 * Признак урезанной пары места сверх бюджета не просит: он пишется третьим
 * элементом внутри самой пары и потому уже в него входит.
 */
static size_t
ngx_http_waf_preview_overhead(void)
{
    return sizeof(",\"headers_preview\":[],\"args_preview\":[],"
                  "\"body_preview\":\"\""
                  ",\"body_preview_source\":\"sent\""
                  ",\"headers_preview_dropped\":4294967295"
                  ",\"args_preview_dropped\":4294967295") - 1;
}


size_t
ngx_http_waf_preview_room(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase)
{
    size_t                      room;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[phase];

    room = sh->preview[NGX_HTTP_WAF_OBJ_HEADERS]
           + sh->preview[NGX_HTTP_WAF_OBJ_ARGS]
           + sh->preview[NGX_HTTP_WAF_OBJ_BODY];

    if (room == 0) {
        return 0;
    }

    return room + ngx_http_waf_preview_overhead();
}


size_t
ngx_http_waf_preview_room_ctx(ngx_http_waf_ctx_t *ctx)
{
    size_t                    room, budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    room = budget[NGX_HTTP_WAF_OBJ_HEADERS]
           + budget[NGX_HTTP_WAF_OBJ_ARGS]
           + budget[NGX_HTTP_WAF_OBJ_BODY];

    if (room == 0) {
        return 0;
    }

    return room + ngx_http_waf_preview_overhead();
}


/*
 * Бюджеты превью этого запроса: маршрута, а у объектов, названных просьбой
 * audit, -- предел просьбы либо, без предела, "весь": потолок датаграммы.
 * Сумма не выше того же потолка, что nginx -t держит для маршрута: лишнее
 * срезается у назначенных просьбой, начиная с тела, и никогда ниже бюджета
 * маршрута -- поэтому "весь" у трёх объектов сразу достаётся заголовкам
 * первыми.
 */
static void
ngx_http_waf_preview_budgets(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, size_t budget[NGX_HTTP_WAF_OBJ_COUNT])
{
    size_t                      total, over, cut;
    ngx_int_t                   i;
    ngx_http_waf_ovr_part_t    *part;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    part  = &ngx_http_waf_audit_ovr_cur(ctx)->audit;
    total = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        budget[i] = sh->preview[i];

        if (ngx_http_waf_ovr_excluded(part, i)) {
            budget[i] = 0;

        } else if (part->set == NGX_HTTP_WAF_SET_ON
                   && (ngx_http_waf_ovr_on(part) & NGX_HTTP_WAF_OBJ_BIT(i)))
        {
            budget[i] = (part->has_limit & NGX_HTTP_WAF_OBJ_BIT(i))
                        ? part->limit[i] : NGX_HTTP_WAF_PREVIEW_MAX;
        }

        total += budget[i];
    }

    if (total <= NGX_HTTP_WAF_PREVIEW_MAX) {
        return;
    }

    over = total - NGX_HTTP_WAF_PREVIEW_MAX;

    for (i = NGX_HTTP_WAF_OBJ_COUNT - 1; i >= 0 && over > 0; i--) {
        if (budget[i] <= sh->preview[i]) {
            continue;
        }

        cut = budget[i] - sh->preview[i];

        if (cut > over) {
            cut = over;
        }

        budget[i] -= cut;
        over      -= cut;
    }
}


void
ngx_http_waf_preview_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_http_waf_preview_headers(jw, ctx, wlcf);
    ngx_http_waf_preview_args(jw, ctx, wlcf);
    ngx_http_waf_preview_body(jw, ctx, wlcf);
}


/*
 * Заголовки парами [имя, значение] в порядке получения. Повторяющиеся имена
 * едут как есть: свернуть их в карту -- решение получателя, и принимать его
 * здесь значило бы выбирать за него правило склейки.
 */
static void
ngx_http_waf_preview_headers(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                     *mark, hex[64];
    size_t                      left, item;
    ngx_str_t                   value;
    ngx_uint_t                  i, first, dropped, rc;
    ngx_keyval_t               *kv;
    ngx_array_t                *pairs;
    ngx_array_t                *allow, *deny, *mask, *cap_deny, *cap_mask;
    size_t                      budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    if (budget[NGX_HTTP_WAF_OBJ_HEADERS] == 0) {
        return;
    }

    ngx_http_waf_preview_lists(ctx, wlcf, NGX_HTTP_WAF_OBJ_HEADERS,
                               &allow, &deny, &mask, &cap_deny, &cap_mask);

    /*
     * Источник -- тот же, что у снимка: пары фазы. На ответе это список
     * headers_out плюс content-type и длина, которые nginx держит отдельными
     * полями, -- без них запись аудита не объясняет, что за байты в теле.
     */
    pairs = ngx_http_waf_header_pairs(ctx);

    if (pairs == NULL) {
        return;
    }

    kv = pairs->elts;

    ngx_http_waf_jw_lit(jw, ",\"headers_preview\":[");

    left    = budget[NGX_HTTP_WAF_OBJ_HEADERS];
    item    = sh->preview_item[NGX_HTTP_WAF_OBJ_HEADERS];
    first   = 1;
    dropped = 0;

    for (i = 0; i < pairs->nelts; i++) {

        if (kv[i].key.len == 0) {
            continue;
        }

        if (!ngx_http_waf_preview_allowed(&kv[i].key, allow, deny)
            || ngx_http_waf_preview_listed(cap_deny, &kv[i].key))
        {
            continue;
        }

        value = kv[i].value;

        if (ngx_http_waf_preview_listed(mask, &kv[i].key)
            || ngx_http_waf_preview_listed(cap_mask, &kv[i].key))
        {
            ngx_http_waf_preview_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
        }

        mark = jw->pos;

        rc = ngx_http_waf_preview_pair(jw, left, &kv[i].key, &value, first,
                                       item);

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_FULL) {
            break;
        }

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED) {
            dropped++;
            continue;
        }

        left -= (size_t) (jw->pos - mark);
        first = 0;
    }

    ngx_http_waf_jw_lit(jw, "]");

    ngx_http_waf_preview_dropped(jw, "headers_preview_dropped", dropped);
}


/*
 * Строка запроса парами. Разбор здесь -- сознательное отступление от правила
 * "модуль не интерпретирует args": инспектору строка едет сырой через обменник, а
 * превью существует ради поиска и показа, и карта пар -- единственная форма, в
 * которой по параметру можно отфильтровать, не перебирая все записи подряд.
 *
 * Значения не декодируются: способ кодирования в атаке -- сама улика, и
 * раскрывать его в записи значило бы стереть разницу между "?q=<script>" и
 * "?q=%3Cscript%3E". Раскодирует показ.
 */
static void
ngx_http_waf_preview_args(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                     *p, *last, *amp, *eq, *mark, hex[64];
    size_t                      left, item;
    ngx_str_t                   name, value;
    ngx_uint_t                  first, dropped, rc;
    ngx_array_t                *allow, *deny, *mask, *cap_deny, *cap_mask;
    size_t                      budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    if (budget[NGX_HTTP_WAF_OBJ_ARGS] == 0) {
        return;
    }

    ngx_http_waf_preview_lists(ctx, wlcf, NGX_HTTP_WAF_OBJ_ARGS,
                               &allow, &deny, &mask, &cap_deny, &cap_mask);

    ngx_http_waf_jw_lit(jw, ",\"args_preview\":[");

    left    = budget[NGX_HTTP_WAF_OBJ_ARGS];
    item    = sh->preview_item[NGX_HTTP_WAF_OBJ_ARGS];
    first   = 1;
    dropped = 0;

    p    = r->args.data;
    last = p + r->args.len;

    while (p < last) {

        amp = ngx_strlchr(p, last, '&');
        if (amp == NULL) {
            amp = last;
        }

        eq = ngx_strlchr(p, amp, '=');

        if (eq != NULL) {
            name.data  = p;
            name.len   = (size_t) (eq - p);
            value.data = eq + 1;
            value.len  = (size_t) (amp - eq - 1);

        } else {
            /* Параметр без значения -- это имя, а не пустая строка. */
            name.data  = p;
            name.len   = (size_t) (amp - p);
            value.data = p;
            value.len  = 0;
        }

        p = amp + 1;

        if (name.len == 0) {
            continue;
        }

        if (!ngx_http_waf_preview_allowed(&name, allow, deny)
            || ngx_http_waf_preview_listed(cap_deny, &name))
        {
            continue;
        }

        if (ngx_http_waf_preview_listed(mask, &name)
            || ngx_http_waf_preview_listed(cap_mask, &name))
        {
            ngx_http_waf_preview_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
        }

        mark = jw->pos;

        rc = ngx_http_waf_preview_pair(jw, left, &name, &value, first, item);

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_FULL) {
            break;
        }

        if (rc == NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED) {
            dropped++;
            continue;
        }

        left -= (size_t) (jw->pos - mark);
        first = 0;
    }

    ngx_http_waf_jw_lit(jw, "]");

    ngx_http_waf_preview_dropped(jw, "args_preview_dropped", dropped);
}


/*
 * Префикс тела одной строкой. Здесь, в отличие от заголовков, байты приходят
 * произвольные: тело бывает и protobuf, и архивом, и просто мусором, -- поэтому
 * писатель проверяет UTF-8 и подменяет негодное, а не отдаёт как есть. Иначе
 * колонка в базе оказалась бы непригодной для поиска, ради которого и заведена.
 */
static void
ngx_http_waf_preview_body(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf)
{
    u_char                     *buf;
    size_t                      len, room, budget[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_http_request_t         *r = ctx->request;

    ngx_http_waf_preview_budgets(ctx, wlcf, budget);

    room = budget[NGX_HTTP_WAF_OBJ_BODY];

    if (room == 0) {
        return;
    }

    /*
     * source=sent: инспектор подменил тело, и маршрут просит показать в записи
     * доставленную версию, а не оригинал. Байты подмены уже отложены фазой
     * (preview_sent); оригинал при этом остаётся в обменнике/архиве. Помечаем
     * секцию, чтобы оператор не принял доставленное за исходное.
     */
    if (ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].len != 0) {
        len = ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].len;

        if (len > room) {
            len = room;
        }

        if (len != 0) {
            ngx_http_waf_jw_lit(jw, ",\"body_preview\":");
            (void) ngx_http_waf_preview_text(
                jw, ctx->ph->preview_sent[NGX_HTTP_WAF_OBJ_BODY].data, len,
                room);
            ngx_http_waf_jw_lit(jw, ",\"body_preview_source\":\"sent\"");
        }

        return;
    }

    /*
     * Сначала то, что уже уложили в обменник: один префикс на три оси, второго
     * прохода по запросу незачем. Нет блоба -- обменника не было, берём из
     * запроса, как раньше.
     */
    if (ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY].len != 0) {
        len = ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY].len;

        if (len > room) {
            len = room;
        }

        if (len == 0) {
            return;
        }

        ngx_http_waf_jw_lit(jw, ",\"body_preview\":");
        (void) ngx_http_waf_preview_text(jw,
                                         ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY]
                                             .data,
                                         len, room);
        return;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return;                        /* тело не читалось -- секции нет */
    }

    /*
     * Сырых байт берётся не больше бюджета: экранирование только удлиняет
     * запись, поэтому всё, что не влезет в бюджет сырым, не влезет и готовым.
     */
    buf = ngx_pnalloc(r->pool, room);
    if (buf == NULL) {
        return;
    }

    len = ngx_http_waf_preview_take(r, buf, room);
    if (len == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"body_preview\":");
    (void) ngx_http_waf_preview_text(jw, buf, len, room);
}


/*
 * Пара в пределах остатка бюджета. Пишется через отдельный писатель по тому же
 * буферу: переполнение здесь -- это конец секции, а не срыв документа, и
 * выносить его флагом наружу нельзя. Не поместилась -- позиция основного
 * писателя не двигается, и от пары не остаётся следа.
 *
 * Потолок на пару делит бюджет между парами. Имя пишется первым и меряется по
 * готовому JSON: занявшее больше половины потолка, оно означает выброс всей
 * пары -- обрезать имя нельзя, по обрезку никто ничего не найдёт, а обрезок
 * значения при таком имени не расскажет ничего сверх самого имени. Иначе
 * остаток потолка достаётся значению, и урезанное значение помечается третьим
 * элементом пары: читатель не должен принимать префикс за оригинал.
 */
static ngx_uint_t
ngx_http_waf_preview_pair(ngx_http_waf_jw_t *jw, size_t room, ngx_str_t *name,
    ngx_str_t *value, ngx_uint_t first, size_t item_max)
{
    u_char             *mark;
    size_t              written, taken;
    ngx_http_waf_jw_t   sub;

    if (room > (size_t) (jw->end - jw->pos)) {
        room = (size_t) (jw->end - jw->pos);
    }

    ngx_http_waf_jw_init(&sub, jw->pos, room);

    if (!first) {
        ngx_http_waf_jw_lit(&sub, ",");
    }

    ngx_http_waf_jw_lit(&sub, "[");

    mark = sub.pos;
    ngx_http_waf_jw_str(&sub, name);

    if (item_max == NGX_HTTP_WAF_PREVIEW_ITEM_NONE) {
        ngx_http_waf_jw_lit(&sub, ",");
        ngx_http_waf_jw_str(&sub, value);

    } else {
        if (!ngx_http_waf_jw_ok(&sub)) {
            return NGX_HTTP_WAF_PREVIEW_PAIR_FULL;
        }

        written = (size_t) (sub.pos - mark);

        if (written * 2 > item_max) {
            return NGX_HTTP_WAF_PREVIEW_PAIR_DROPPED;
        }

        ngx_http_waf_jw_lit(&sub, ",");

        taken = ngx_http_waf_preview_text(&sub, value->data, value->len,
                                          item_max - written);

        if (taken < value->len) {
            ngx_http_waf_jw_lit(&sub, ",1");
        }
    }

    ngx_http_waf_jw_lit(&sub, "]");

    if (!ngx_http_waf_jw_ok(&sub)) {
        return NGX_HTTP_WAF_PREVIEW_PAIR_FULL;
    }

    jw->pos += ngx_http_waf_jw_len(&sub);

    return NGX_HTTP_WAF_PREVIEW_PAIR_OK;
}


/*
 * Сколько пар секции выброшено по слишком длинному имени. Ноль не пишется:
 * поле, стоящее в каждой записи нулём, только раздувает датаграмму, а его
 * отсутствие читается так же однозначно.
 */
static void
ngx_http_waf_preview_dropped(ngx_http_waf_jw_t *jw, const char *field,
    ngx_uint_t dropped)
{
    if (dropped == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) field, ngx_strlen(field));
    ngx_http_waf_jw_lit(jw, "\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) dropped);
}


/*
 * Строка в кавычках, не длиннее room байт вывода, с проверкой UTF-8. Возвращает
 * число байт источника, которые уместились: меньше len означает, что строка
 * урезана, и вызывающий обязан это пометить.
 *
 * Штатный писатель отдаёт байты старше 0x7f как есть -- для заголовков это
 * верно, их читает инспектор, а не аналитик. Тело же едет в базу и в поиск,
 * поэтому негодная последовательность заменяется на U+FFFD, а обрыв приходится
 * на границу символа: половина последовательности в записи -- это не данные, а
 * повод не доверять всей колонке. Значение с потолком на пару режется тем же
 * писателем и по той же причине.
 */
static size_t
ngx_http_waf_preview_text(ngx_http_waf_jw_t *jw, u_char *data, size_t len,
    size_t room)
{
    u_char    *p, *last, *start;
    size_t     need;
    uint32_t   u;
    static const u_char  hex[] = "0123456789abcdef";

    if (room > (size_t) (jw->end - jw->pos)) {
        room = (size_t) (jw->end - jw->pos);
    }

    if (room < 2) {
        /*
         * Даже на пустую строку не хватило: ключ уже записан, и оборвать
         * документ здесь нельзя. Это промах расчёта буфера, а не свойство
         * данных, -- пусть его увидит проверка в конце сборки.
         */
        jw->overflow = 1;
        return 0;
    }

    *jw->pos++ = '"';
    room -= 2;                         /* закрывающая кавычка забронирована */

    p    = data;
    last = data + len;

    /*
     * Перед каждым выходом позиция откатывается на начало символа: тогда
     * "сколько уместилось" -- это ровно p - data, и считать его в семи местах
     * по отдельности не приходится.
     */
    while (p < last) {

        start = p;

        if (*p < 0x80) {
            u = *p++;

            if (u == '"' || u == '\\') {
                if (room < 2) {
                    p = start;
                    break;
                }

                *jw->pos++ = '\\';
                *jw->pos++ = (u_char) u;
                room -= 2;
                continue;
            }

            if (u >= 0x20) {
                if (room < 1) {
                    p = start;
                    break;
                }

                *jw->pos++ = (u_char) u;
                room--;
                continue;
            }

            /* Управляющий символ: короткая форма там, где она есть. */
            if (u == '\n' || u == '\r' || u == '\t' || u == '\b' || u == '\f') {
                if (room < 2) {
                    p = start;
                    break;
                }

                *jw->pos++ = '\\';
                *jw->pos++ = (u == '\n') ? 'n'
                           : (u == '\r') ? 'r'
                           : (u == '\t') ? 't'
                           : (u == '\b') ? 'b' : 'f';
                room -= 2;
                continue;
            }

            if (room < 6) {
                p = start;
                break;
            }

            *jw->pos++ = '\\';
            *jw->pos++ = 'u';
            *jw->pos++ = '0';
            *jw->pos++ = '0';
            *jw->pos++ = hex[(u >> 4) & 0x0f];
            *jw->pos++ = hex[u & 0x0f];
            room -= 6;
            continue;
        }

        u = ngx_utf8_decode(&p, (size_t) (last - start));

        if (u == 0xfffffffe) {
            /*
             * Последовательность оборвана концом префикса, а не испорчена:
             * это край превью, и дописывать за него нечего.
             */
            p = start;
            break;
        }

        if (u == 0xffffffff) {
            if (room < 3) {
                p = start;
                break;
            }

            /* U+FFFD в UTF-8: три байта, и в JSON они не экранируются. */
            *jw->pos++ = 0xef;
            *jw->pos++ = 0xbf;
            *jw->pos++ = 0xbd;
            room -= 3;
            continue;
        }

        need = (size_t) (p - start);

        if (room < need) {
            p = start;
            break;
        }

        jw->pos = ngx_cpymem(jw->pos, start, need);
        room -= need;
    }

    *jw->pos++ = '"';

    return (size_t) (p - data);
}


/*
 * Списки превью. Своя строка -- замена, не дополнение к capture.
 * Нет строки и нет reload -- mask/deny capture (cookie тогда sha256).
 * reload -- оригинал, списки capture не применяем. Источник может назначить
 * и сосед с грантом просьбой audit: original -- оригинал, store -- как
 * снято, даже если маршрут велел reload.
 */
static void
ngx_http_waf_preview_lists(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj, ngx_array_t **allow,
    ngx_array_t **deny, ngx_array_t **mask, ngx_array_t **cap_deny,
    ngx_array_t **cap_mask)
{
    ngx_uint_t                  reload;
    ngx_array_t               **pv, **cap;
    ngx_http_waf_ovr_part_t    *part = &ngx_http_waf_audit_ovr_cur(ctx)->audit;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    reload = (sh->preview_reload & NGX_HTTP_WAF_OBJ_BIT(obj)) != 0;

    if (ngx_http_waf_ovr_original(part, obj)) {
        reload = 1;

    } else if (ngx_http_waf_ovr_store(part, obj)) {
        reload = 0;
    }

    pv  = sh->lists[NGX_HTTP_WAF_LIST_PREVIEW][obj];
    cap = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][obj];

    *allow = pv[NGX_HTTP_WAF_AXIS_ALLOW];
    *deny  = pv[NGX_HTTP_WAF_AXIS_DENY];
    *mask  = pv[NGX_HTTP_WAF_AXIS_MASK];

    if (reload) {
        *cap_deny = NULL;
        *cap_mask = NULL;
        return;
    }

    *cap_deny = cap[NGX_HTTP_WAF_AXIS_DENY];
    *cap_mask = cap[NGX_HTTP_WAF_AXIS_MASK];
}


static void
ngx_http_waf_preview_hash(ngx_str_t *src, u_char hex[64])
{
    u_char                 digest[32];
    ngx_http_waf_sha256_t  sha;

    ngx_http_waf_sha256_init(&sha);
    ngx_http_waf_sha256_update(&sha, src->data, src->len);
    ngx_http_waf_sha256_final(&sha, digest);
    (void) ngx_hex_dump(hex, digest, 32);
}


/*
 * Пускать ли имя в превью. Запрет сильнее разрешения.
 */
static ngx_uint_t
ngx_http_waf_preview_allowed(ngx_str_t *name, ngx_array_t *allow,
    ngx_array_t *deny)
{
    if (ngx_http_waf_preview_listed(deny, name)) {
        return 0;
    }

    if (allow == NULL || allow->nelts == 0) {
        return 1;
    }

    return ngx_http_waf_preview_listed(allow, name);
}


static ngx_uint_t
ngx_http_waf_preview_listed(ngx_array_t *list, ngx_str_t *name)
{
    ngx_str_t   *item;
    ngx_uint_t   i;

    if (list == NULL || list->nelts == 0) {
        return 0;
    }

    item = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (item[i].len == name->len
            && ngx_strncasecmp(item[i].data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Префикс тела в один буфер. Тело в файле читается здесь же -- по тем же
 * причинам, что и в body_collect: неблокирующее чтение файла в цикле событий
 * потребовало бы пула потоков, а превью не стоит такой цены. Читается только
 * префикс, не всё тело.
 */
static size_t
ngx_http_waf_preview_take(ngx_http_request_t *r, u_char *dst, size_t size)
{
    off_t         pos;
    size_t        taken, avail;
    ssize_t       n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    taken = 0;

    for (cl = r->request_body->bufs; cl != NULL && taken < size; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {

            for (pos = b->file_pos; pos < b->file_last && taken < size;
                 /* void */)
            {
                avail = (size_t) ngx_min((off_t) (size - taken),
                                         b->file_last - pos);

                n = ngx_read_file(b->file, dst + taken, avail, pos);
                if (n <= 0) {
                    /*
                     * Превью не имеет права ни задержать запрос, ни изменить
                     * вердикт: что успели прочитать, то и поедет.
                     */
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "waf: reading \"%V\" for the body preview "
                                  "failed", &b->file->name);
                    return taken;
                }

                taken += (size_t) n;
                pos   += n;
            }

            continue;
        }

        avail = (size_t) ngx_min((off_t) (size - taken), b->last - b->pos);

        ngx_memcpy(dst + taken, b->pos, avail);
        taken += avail;
    }

    return taken;
}
