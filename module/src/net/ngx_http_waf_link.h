/*
 * Соединение с внешним сервисом контура: шина NATS, обменник Redis.
 *
 * Общее у обоих клиентов -- не протокол, а форма: неблокирующий сокет в цикле
 * событий nginx, вечное переподключение по таймеру, входной буфер со сдвигом
 * разобранного и исходящий буфер, растущий до предела. Протокол остаётся у
 * владельца: он получает байты колбэком on_read и складывает команды через
 * ngx_http_waf_link_out(). Здесь нет ни строки NATS, ни строки RESP.
 *
 * Требование одно и то же, что у транспорта и у драйвера обменника: все колбэки
 * исполняются в потоке цикла событий воркера, чужих потоков нет.
 */

#ifndef _NGX_HTTP_WAF_LINK_H_INCLUDED_
#define _NGX_HTTP_WAF_LINK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct ngx_http_waf_link_s  ngx_http_waf_link_t;


typedef struct {
    const char                *name;         /* "bus", "redis": для лога     */

    ngx_array_t               *servers;      /* ngx_addr_t, по кругу          */
    ngx_msec_t                 connect_timeout;
    ngx_msec_t                 reconnect_wait;

    size_t                     in_size;      /* входной буфер, фиксирован     */
    size_t                     out_initial;  /* исходящий: начальный размер   */
    size_t                     out_max;      /* ... и предел роста            */

    /*
     * TCP установлен: владелец шлёт рукопожатие через ngx_http_waf_link_out()
     * и, если готовность не ждёт ответа сервера, ставит link->ready сам.
     * NGX_ERROR -- соединение бросается и переподключается.
     */
    ngx_int_t                (*on_connected)(ngx_http_waf_link_t *link);

    /*
     * Во входном буфере есть новые байты: разбирать link->in[in_pos..in_last),
     * двигая in_pos. NGX_ERROR -- протокол сломан, соединение бросается.
     */
    ngx_int_t                (*on_read)(ngx_http_waf_link_t *link);

    /*
     * Соединение закрывается (ошибка, таймаут, выход воркера). Всё, что жило
     * в нём -- конвейер команд, потребители, -- умирает здесь. was_ready --
     * значение link->ready до закрытия: сам флаг к этому моменту уже снят,
     * чтобы никто не успел положить в закрывающееся соединение новую команду.
     */
    void                     (*on_close)(ngx_http_waf_link_t *link,
                                 ngx_uint_t was_ready);
} ngx_http_waf_link_conf_t;


struct ngx_http_waf_link_s {
    ngx_http_waf_link_conf_t  *conf;
    void                      *data;         /* владелец                      */
    ngx_log_t                 *log;

    ngx_peer_connection_t      peer;
    ngx_uint_t                 next_server;

    u_char                    *in;
    size_t                     in_size;
    size_t                     in_pos;       /* разобрано до                 */
    size_t                     in_last;      /* прочитано до                 */

    u_char                    *out;
    size_t                     out_size;
    size_t                     out_pos;
    size_t                     out_last;

    ngx_event_t                reconnect;

    unsigned                   ready:1;      /* владелец готов принимать     */
    unsigned                   connecting:1;
};


/* Буферы и таймер; соединения не открывает. */
ngx_int_t  ngx_http_waf_link_init(ngx_http_waf_link_t *link,
               ngx_http_waf_link_conf_t *conf, ngx_cycle_t *cycle, void *data);

/* Открыть соединение к очередному адресу; при отказе -- перевзвести таймер. */
void       ngx_http_waf_link_connect(ngx_http_waf_link_t *link);

/* Закрыть и переподключиться по таймеру: любая ошибка соединения. */
void       ngx_http_waf_link_drop(ngx_http_waf_link_t *link);

/* Выход воркера: снять таймер и закрыть без переподключения. */
void       ngx_http_waf_link_stop(ngx_http_waf_link_t *link);

/*
 * Исходящий буфер. reserve гарантирует место под len байт (или NGX_ERROR на
 * пределе), out дописывает, flush отправляет сколько получится и оставляет
 * остаток на событие записи. Ошибка отправки бросает соединение.
 */
ngx_int_t  ngx_http_waf_link_reserve(ngx_http_waf_link_t *link, size_t len);
ngx_int_t  ngx_http_waf_link_out(ngx_http_waf_link_t *link, const u_char *data,
               size_t len);
void       ngx_http_waf_link_flush(ngx_http_waf_link_t *link);


#endif /* _NGX_HTTP_WAF_LINK_H_INCLUDED_ */
