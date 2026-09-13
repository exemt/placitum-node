/*
 * Срез заголовков, параметров и тела для записи аудита.
 *
 * Только для сообщения агенту. Инспектор видит содержимое через локатор
 * обменника, и подменять один канал другим нельзя: у них разные пределы, разный
 * срок жизни и разный круг читателей. Превью живёт в аналитической базе
 * месяцами и открыто всем, у кого есть доступ к поиску, -- поэтому оно всегда
 * ограничено конфигурацией и никогда не следует за размером запроса.
 *
 * Считается из запроса. Нет своей строки mask/deny -- списки capture.
 * reload -- оригинал, списки capture не применяются.
 */

#ifndef _NGX_HTTP_WAF_PREVIEW_H_INCLUDED_
#define _NGX_HTTP_WAF_PREVIEW_H_INCLUDED_


#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"


/*
 * Сколько байт секции превью могут занять в датаграмме на этом маршруте.
 * Верхняя граница, а не оценка: буфер аудита выделяется по ней, и превышать
 * её сборщик не имеет права.
 */
size_t     ngx_http_waf_preview_room(ngx_http_waf_loc_conf_t *wlcf,
               ngx_uint_t phase);

/*
 * То же для записи этого запроса: бюджеты маршрута, поверх них -- бюджеты,
 * назначенные просьбой audit соседа с грантом, сумма прижата к потолку
 * датаграммы. Буфер записи выделяется по этой функции.
 */
size_t     ngx_http_waf_preview_room_ctx(ngx_http_waf_ctx_t *ctx);

/* Бюджет превью тела на этом запросе, с просьбами audit. */
size_t     ngx_http_waf_preview_body_budget(ngx_http_waf_ctx_t *ctx);

/* Секции headers_preview, args_preview и body_preview в документ агента. */
void       ngx_http_waf_preview_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx);


#endif /* _NGX_HTTP_WAF_PREVIEW_H_INCLUDED_ */
