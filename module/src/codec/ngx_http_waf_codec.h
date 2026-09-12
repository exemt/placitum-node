/*
 * Сериализация и разбор сообщений протокола вердикта.
 *
 * Здесь единственное место, куда попадают непроверенные байты с провода, и
 * обращаться с ним надо соответственно: парсер работает по буферу с явной
 * верхней границей (waf_reply_max), не аллоцирует ничего, кроме копий
 * извлечённых строк, и не имеет ни одной зависимости от сторонних библиотек.
 *
 * Спецификация формата: docs/verdict-protocol.md.
 */

#ifndef _NGX_HTTP_WAF_CODEC_H_INCLUDED_
#define _NGX_HTTP_WAF_CODEC_H_INCLUDED_


#include "ngx_http_waf.h"


/*
 * Версия 2: заголовки, строка запроса и тело сведены в одну секцию store с
 * общей формой локатора, добавлены needs и audit_subject, из ответа убрано
 * всё, что не решение. Форма изменилась несовместимо, поэтому не 1.
 */
#define NGX_HTTP_WAF_PROTOCOL_VERSION   2

/* Кадр активного набора (keeper, docs/keeper.md). Отдельно от вердиктов. */
#define NGX_HTTP_WAF_DATASET_VERSION    3

/* Предел вложенности при пропуске незнакомых полей. */
#define NGX_HTTP_WAF_JSON_MAX_DEPTH     16


/* --- писатель -------------------------------------------------------------
 *
 * Пишет в заранее выделенный буфер и отмечает переполнение флагом вместо
 * прерывания: вызывающему проще проверить один раз в конце, чем каждое поле.
 * Переполнение означает ошибку расчёта размера, то есть ошибку в коде, а не во
 * входных данных, поэтому обрабатывается как отказ публикации.
 */
typedef struct {
    u_char     *start;
    u_char     *pos;
    u_char     *end;
    unsigned    overflow:1;
} ngx_http_waf_jw_t;


void  ngx_http_waf_jw_init(ngx_http_waf_jw_t *jw, u_char *buf, size_t size);
void  ngx_http_waf_jw_raw(ngx_http_waf_jw_t *jw, const u_char *data,
          size_t len);
void  ngx_http_waf_jw_string(ngx_http_waf_jw_t *jw, const u_char *data,
          size_t len);
void  ngx_http_waf_jw_int(ngx_http_waf_jw_t *jw, ngx_int_t v);

#define ngx_http_waf_jw_lit(jw, s)                                            \
    ngx_http_waf_jw_raw(jw, (const u_char *) s, sizeof(s) - 1)

#define ngx_http_waf_jw_str(jw, s)                                            \
    ngx_http_waf_jw_string(jw, (s)->data, (s)->len)

#define ngx_http_waf_jw_len(jw)   ((size_t) ((jw)->pos - (jw)->start))
#define ngx_http_waf_jw_ok(jw)    ((jw)->overflow == 0)


/* --- парсер --------------------------------------------------------------- */

typedef struct {
    u_char      *pos;
    u_char      *end;
    ngx_pool_t  *pool;
    const char  *error;
} ngx_http_waf_jp_t;


void       ngx_http_waf_jp_init(ngx_http_waf_jp_t *jp, ngx_str_t *payload,
               ngx_pool_t *pool);

/* Начало объекта или массива: NGX_OK либо NGX_ERROR с *error. */
ngx_int_t  ngx_http_waf_jp_object(ngx_http_waf_jp_t *jp);
ngx_int_t  ngx_http_waf_jp_array(ngx_http_waf_jp_t *jp);

/*
 * Следующий член объекта: NGX_OK и имя в *key, NGX_DONE на закрывающей скобке,
 * NGX_ERROR при нарушении формата. После NGX_OK позиция стоит на значении.
 */
ngx_int_t  ngx_http_waf_jp_member(ngx_http_waf_jp_t *jp, ngx_str_t *key);

/* То же для элементов массива. */
ngx_int_t  ngx_http_waf_jp_element(ngx_http_waf_jp_t *jp);

/*
 * Строка с раскрытием escape-последовательностей в копию из пула. Копия
 * короче исходного текста, поэтому размер известен заранее и не считается.
 */
ngx_int_t  ngx_http_waf_jp_string(ngx_http_waf_jp_t *jp, ngx_str_t *out);

/*
 * То же в буфер вызывающего, без обращения к пулу. Для массивов, где строк
 * много: копия в пул на каждый элемент -- это аллокация на запись, а записей в
 * снапшоте набора данных бывает миллион.
 */
ngx_int_t  ngx_http_waf_jp_string_buf(ngx_http_waf_jp_t *jp, u_char *buf,
               size_t size, ngx_str_t *out);

/*
 * Целое. Дробное, экспоненциальная запись и выход за границу int64 --
 * NGX_ERROR: подрезка недоверенного числа превращает ошибку инспектора в тихо
 * неверное решение.
 */
ngx_int_t  ngx_http_waf_jp_int(ngx_http_waf_jp_t *jp, ngx_int_t *out);

ngx_int_t  ngx_http_waf_jp_bool(ngx_http_waf_jp_t *jp, ngx_uint_t *out);

/* Пропуск значения любого типа с ограничением вложенности. */
ngx_int_t  ngx_http_waf_jp_skip(ngx_http_waf_jp_t *jp);

/* Значение -- null? Проверка без потребления, если это не так. */
ngx_uint_t ngx_http_waf_jp_null(ngx_http_waf_jp_t *jp);


/* --- codec/ngx_http_waf_msg_req.c ----------------------------------------- */

/*
 * Описание запроса для одного инспектора волны. Результат аллоцируется из
 * r->pool и принадлежит вызывающему до конца запроса.
 */
ngx_int_t  ngx_http_waf_msg_request(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
               ngx_str_t *out);

/*
 * Секция кадра (stream/ngx_http_waf_frame.c): conn_id, seq и stream. На
 * фазах запроса и ответа не пишет ничего, поэтому зовётся безусловно.
 */
void       ngx_http_waf_msg_frame(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx);

/*
 * Проверка при загрузке конфигурации: помещается ли худшее сообщение маршрута
 * в max_payload шины. Живёт рядом с сериализацией намеренно -- считать верхнюю
 * границу должен тот же код, который потом пишет сообщение.
 */
char      *ngx_http_waf_msg_req_validate(ngx_conf_t *cf,
               ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf);

/*
 * Секция vars: стандартный набор модуля плюс поля, выбранные оператором через
 * waf_var. Общая для сообщения инспектору и для итога агенту -- иначе одно и
 * то же поле выглядело бы в двух местах по-разному, и склейка инцидента
 * разъехалась бы на именах.
 *
 * mask -- какие поля печатать, по индексу в wmcf->vars: у сообщения инспектору
 * это vars= его объявления, у записи аудита -- NGX_HTTP_WAF_VARS_ALL.
 *
 * value_max ограничивает длину одного значения; 0 -- без ограничения. Обрезка
 * идёт по границе UTF-8: половина последовательности в JSON бесполезна всем.
 */
size_t     ngx_http_waf_vars_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t mask);
void       ngx_http_waf_vars_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, size_t value_max, ngx_uint_t mask);


/* --- codec/ngx_http_waf_msg_reply.c --------------------------------------- */

/*
 * Разбор ответа инспектора со всеми проверками ограничений канала. Возврат
 * NGX_ERROR означает, что ответ отбракован целиком; причина -- в *err для
 * записи в лог.
 *
 * Переопределения, не прошедшие белый список, отбрасываются по одному, не
 * задевая остальной вердикт: они валидны или невалидны сами по себе.
 */
ngx_int_t  ngx_http_waf_msg_reply(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
               ngx_str_t *payload, ngx_http_waf_reply_t *reply, ngx_str_t *err);


#endif /* _NGX_HTTP_WAF_CODEC_H_INCLUDED_ */
