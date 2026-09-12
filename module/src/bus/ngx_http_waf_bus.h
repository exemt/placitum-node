/*
 * Интерфейс транспорта вердиктов.
 *
 * Модуль не знает, какая шина под ним. Он публикует волну и получает вердикты
 * через колбэк, исполняемый СТРОГО в потоке цикла событий nginx.
 *
 * Это требование, а не пожелание. Колбэк добирается до ngx_http_waf_slot_t и
 * далее до ngx_http_request_t; вызов из чужого потока -- это гонка и
 * use-after-free одновременно.
 *
 * Отсюда следует ограничение на реализацию поверх nats.c. Опция
 * natsOptions_SetEventLoop() убирает только поток чтения сокета; асинхронная
 * подписка по-прежнему получает собственный поток доставки, который и вызовет
 * пользовательский колбэк. Использовать nats.c можно двумя способами:
 * синхронной подпиской, которую мы вычерпываем natsSubscription_NextMsg() с
 * нулевым таймаутом из обработчика read-события nginx, либо переносом
 * сообщений в цикл через ngx_notify(). Оба варианта прячутся за этим vtable и
 * не видны остальному модулю.
 *
 * Первичная реализация -- ngx_http_waf_bus_nats.c: протокол NATS поверх
 * ngx_event напрямую. Текстовый протокол core NATS невелик (CONNECT, PUB, SUB,
 * MSG, HMSG, PING, PONG, INFO, -ERR), а публикация в JetStream для аудита в
 * режиме fire-and-forget -- это обычный PUB на subject потока, без JS API.
 * Взамен получаем: ни одного чужого потока, аллокации из ngx_pool, TLS через
 * тот же OpenSSL-контекст, что и у nginx, и отсутствие внешней зависимости в
 * модуле, собираемом с --with-compat.
 */

#ifndef _NGX_HTTP_WAF_BUS_H_INCLUDED_
#define _NGX_HTTP_WAF_BUS_H_INCLUDED_


#include "ngx_http_waf.h"


typedef struct ngx_http_waf_bus_s  ngx_http_waf_bus_t;


/* Причина, по которой волна не получит ответ от конкретного инспектора. */
typedef enum {
    NGX_HTTP_WAF_BUS_OK           = 0,
    NGX_HTTP_WAF_BUS_NO_RESPONDER = 1,  /* на subject нет подписчиков        */
    NGX_HTTP_WAF_BUS_UNAVAILABLE  = 2,  /* нет соединения с шиной            */
    NGX_HTTP_WAF_BUS_OVERFLOW     = 3,  /* исчерпан pending_max              */
    NGX_HTTP_WAF_BUS_TOO_LARGE    = 4   /* сообщение больше max_payload      */
} ngx_http_waf_bus_status_e;


/*
 * Одна публикация. Модуль формирует по такой структуре на каждого инспектора
 * волны; payload уже сериализован и принадлежит вызывающему до возврата
 * publish().
 */
typedef struct {
    ngx_str_t                   subject;
    ngx_str_t                   payload;

    uint64_t                    rid;
    ngx_uint_t                  inspector;   /* индекс бита                  */
    ngx_msec_t                  timeout;
} ngx_http_waf_bus_msg_t;


struct ngx_http_waf_bus_s {
    ngx_str_t                   name;        /* "nats", "stub", ...          */
    void                       *data;        /* приватное состояние воркера  */
    ngx_log_t                  *log;

    /*
     * Инбокс воркера. Уникален между воркерами и между поколениями конфига,
     * иначе при reload старые и новые воркеры получат чужие вердикты:
     *   _INBOX.waf.<node_id>.<pid>.<nonce>
     * Подписка идёт с суффиксом ".>", rid берётся из последнего токена.
     */
    ngx_str_t                   inbox;
    ngx_pid_t                   pid;
    uint32_t                    nonce;

    /*
     * Пульс присутствия воркера: WAF_STATUS.node.<id>.worker.<pid>.<nonce>.
     * Таймер воркера, не мастера; cancelable, иначе reload не завершается.
     */
    ngx_str_t                   presence_subject;
    ngx_str_t                   config_hash;
    ngx_event_t                 presence;

    /* конфигурация и жизненный цикл */
    ngx_int_t                 (*init_worker)(ngx_http_waf_bus_t *bus,
                                    ngx_cycle_t *cycle);
    void                      (*exit_worker)(ngx_http_waf_bus_t *bus,
                                    ngx_cycle_t *cycle);

    /*
     * Публикация. Неблокирующая. NGX_OK означает, что сообщение принято в
     * исходящий буфер, а не что оно доставлено: ответственность за таймаут
     * лежит на дедлайне фазы.
     *
     * Возврат NGX_ERROR сопровождается заполнением *status и обрабатывается
     * по waf_exception: класс bus либо absent.
     */
    ngx_int_t                 (*publish)(ngx_http_waf_bus_t *bus,
                                    ngx_http_waf_bus_msg_t *msg,
                                    ngx_uint_t *status);

    /*
     * Отмена ожидания. Вызывается при разрешении вердикта до прихода всех
     * ответов, чтобы транспорт мог отбросить поздние сообщения дёшево.
     * Необязательна: корректность обеспечивается поколением в rid.
     */
    void                      (*cancel)(ngx_http_waf_bus_t *bus, uint64_t rid);

    /* fire-and-forget публикация аудита; никогда не входит в набор ожидания */
    ngx_int_t                 (*publish_audit)(ngx_http_waf_bus_t *bus,
                                    ngx_str_t *subject, ngx_str_t *payload);

    /*
     * Публикация с ответом в подтему инбокса. reply_suffix определяет, кому
     * транспорт отдаст ответ: "js.<n>" -- потребителю наборов, NULL -- никому,
     * то есть обычный PUB без reply-to.
     *
     * Отдельно от publish() потому, что здесь нет ни rid, ни инспектора, ни
     * набора ожидания: это служебный запрос воркера, а не часть волны.
     */
    ngx_int_t                 (*request)(ngx_http_waf_bus_t *bus,
                                    ngx_str_t *subject, ngx_str_t *reply_suffix,
                                    ngx_str_t *payload);

    ngx_int_t                 (*connected)(ngx_http_waf_bus_t *bus);
};


/*
 * Токены подтем инбокса:
 *
 *     <inbox>.v.<rid>.<ii>   вердикт инспектора
 *     <inbox>.js.<n>         ответ JetStream API
 *
 * Ветки разделены токеном, а не только числом, потому что подписки на них
 * разные и пересекаться им нельзя. Кадры наборов идут не через инбокс, а
 * подпиской на subject набора (local/ngx_http_waf_ds_stream.c).
 */
#define NGX_HTTP_WAF_BUS_TOKEN_V   "v"
#define NGX_HTTP_WAF_BUS_TOKEN_JS  "js"


/* --- bus/ngx_http_waf_bus.c ----------------------------------------------- */

/*
 * Публикует все сообщения волны и заполняет маску ожидания слота. Здесь же
 * применяются sample= и режим ignore: инспектор, пропущенный по любой из этих
 * причин, не публикуется и в маску ожидания не попадает.
 *
 * Ни один отказ здесь не возвращает запрос в фазы: публикация выполняется из
 * стека обработчика фазы, и повторный вход в него означал бы двойную
 * финализацию. Отсутствие подписчиков отмечается в слоте, а решение принимает
 * вызывающий.
 */
ngx_int_t  ngx_http_waf_bus_publish_wave(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_slot_t *slot);

/*
 * Единая точка входа для транспорта. Находит слот по rid, разбирает payload,
 * валидирует все ограничения канала и передаёт результат в машину состояний.
 * Транспорт не должен знать ни про JSON, ни про вердикты.
 *
 * Номер инспектора приходит из адреса ответа, а не из его содержимого: ответ на
 * publish без подписчиков не содержит payload вовсе, и определить, о каком
 * инспекторе речь, можно только по subject.
 */
void       ngx_http_waf_bus_dispatch(ngx_http_waf_bus_t *bus, uint64_t rid,
               ngx_uint_t inspector, ngx_str_t *payload);

/* Инспектор не ответит: нет подписчиков, breaker открыт, sample= не выпал. */
void       ngx_http_waf_bus_absent(uint64_t rid, ngx_uint_t inspector,
               ngx_uint_t status);

ngx_int_t  ngx_http_waf_bus_inbox_build(ngx_http_waf_bus_t *bus,
               ngx_cycle_t *cycle, ngx_str_t *node_id);

ngx_int_t  ngx_http_waf_presence_init(ngx_http_waf_bus_t *bus,
               ngx_cycle_t *cycle);
void       ngx_http_waf_presence_stop(ngx_http_waf_bus_t *bus);

/* Шина этого воркера; NULL, если транспорт не сконфигурирован. */
ngx_http_waf_bus_t  *ngx_http_waf_bus_current(void);

/*
 * Соединение с шиной установлено либо потеряно. Вызывается транспортом; здесь
 * это разворачивается в то, что должно случиться при переподключении, --
 * пересоздание потребителей наборов.
 */
void       ngx_http_waf_bus_ready(void);
void       ngx_http_waf_bus_lost(void);

/*
 * Сообщение в служебной подтеме инбокса. Транспорт различает их по адресу и не
 * знает, что внутри.
 */
void       ngx_http_waf_bus_dataset(ngx_uint_t index, ngx_str_t *payload);
void       ngx_http_waf_bus_js_reply(ngx_uint_t index, ngx_str_t *payload);


/* --- реализации ----------------------------------------------------------- */

ngx_http_waf_bus_t  *ngx_http_waf_bus_nats_create(ngx_conf_t *cf);


#endif /* _NGX_HTTP_WAF_BUS_H_INCLUDED_ */
