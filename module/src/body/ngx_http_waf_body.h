/*
 * Интерфейс драйвера хранилища тела и жизненный цикл размещения.
 *
 * Тело и сырые заголовки не помещаются в сообщение: оба объекта кладутся в
 * store двумя ключами, а в волне едут только локаторы. Нужно ли тело вообще,
 * решается конфигурацией на уровне location; заголовки -- headers= инспектора.
 *
 * Чтение в интерфейсе одно и узкое: get объекта, который инспектор с mutate=on
 * переписал для подмены тела ответа (секция rewrite реплая). Свои объекты
 * модуль по-прежнему не перечитывает -- store_blob держит тот же буфер, что
 * ушёл драйверу, -- а инспекторы читают обменник своими клиентами.
 *
 * Единственное жёсткое требование -- асинхронность. Драйвер работает в цикле
 * событий nginx, и любая блокирующая операция останавливает воркер вместе со
 * всеми его соединениями. Это отсекает наивное использование готовых SDK:
 * подойдут только реализации на неблокирующих сокетах, зарегистрированных в
 * ngx_event, либо использующие пул upstream-соединений nginx.
 *
 * Спецификация: docs/body-storage.md.
 */

#ifndef _NGX_HTTP_WAF_BODY_H_INCLUDED_
#define _NGX_HTTP_WAF_BODY_H_INCLUDED_


#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"


/*
 * Возможности драйвера. Обменник горячего пути один и сетевой (redis): тёплого
 * архива здесь нет -- объекты в S3 перекладывает агент по записям аудита.
 */
#define NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS  0x0001  /* видно с других хостов */
#define NGX_HTTP_WAF_BODY_CAP_DELETE          0x0004
#define NGX_HTTP_WAF_BODY_CAP_TTL             0x0008
#define NGX_HTTP_WAF_BODY_CAP_GET             0x0020  /* чтение по ключу       */


/*
 * Причина недоступности тела; едет инспектору в поле body.unavailable.
 *
 * Ещё два значения -- expired и archive_error -- существуют только на проводе
 * к логеру: их ставит агент, разбираясь с архивацией уже после того, как
 * модуль отпустил запрос. Модуль их не выставляет никогда, поэтому и в этом
 * перечислении их нет; см. docs/messages/agent.schema.ts.
 */
typedef enum {
    NGX_HTTP_WAF_BODY_AVAILABLE          = 0,
    NGX_HTTP_WAF_BODY_OVERSIZE           = 1,
    NGX_HTTP_WAF_BODY_STORE_ERROR        = 2,
    NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED = 3
} ngx_http_waf_body_unavail_e;


/*
 * Локатор. Единый формат для всех драйверов: инспектор не должен знать, каким
 * драйвером тело размещено, чтобы прочитать его.
 */
struct ngx_http_waf_locator_s {
    ngx_str_t                  store;
    ngx_str_t                  driver;
    ngx_str_t                  key;

    ngx_str_t                  inline_data;   /* собранный буфер до put      */

    off_t                      size;
    off_t                      declared_size; /* сколько заявил клиент       */
    u_char                     sha256[32];

    time_t                     expires_at;
    ngx_str_t                  encoding;

    /*
     * Подсказка драйвера. У redis это адрес узла, на который лёг ключ: пока
     * шардирования нет, узел один и подсказка совпадает с конфигурацией, но
     * формат сообщения обязан быть готов к обратному заранее -- менять его на
     * живом контуре дороже, чем завести поле сейчас.
     */
    ngx_str_t                  hint;

    ngx_uint_t                 unavailable;   /* ngx_http_waf_body_unavail_e */

    unsigned                   has_sha256:1;
    unsigned                   complete:1;
    unsigned                   truncated:1;
};


typedef struct ngx_http_waf_body_op_s  ngx_http_waf_body_op_t;

struct ngx_http_waf_body_op_s {
    void                      *store_conf;
    ngx_pool_t                *pool;
    ngx_log_t                 *log;

    ngx_str_t                  rid;
    ngx_uint_t                 phase;         /* ngx_http_waf_phase_e        */
    ngx_uint_t                 obj;           /* ngx_http_waf_obj_e          */

    off_t                      len;

    /*
     * Тело, собранное в один буфер. Заполняется жизненным циклом до вызова
     * драйвера: размещение -- одна операция после чтения целиком, потому что
     * SHA-256 локатора считается одним полным проходом. Потокового put нет
     * ни у одного драйвера (docs/nginx/module/known-issues.md).
     */
    ngx_str_t                  data;

    ngx_http_waf_locator_t     locator;       /* заполняется драйвером       */
    ngx_int_t                  status;

    /*
     * Маршрут может отдать этот объект агенту, и тогда удалит его агент, а не
     * модуль. Драйверу это нужно на put: срок жизни выбирается в момент
     * размещения, а к моменту вердикта менять его поздно -- это ещё один
     * round-trip в горячем пути. Признак маршрутный, не итоговый: when=
     * решается позже, TTL здесь только страховка.
     */
    unsigned                   retain:1;
    unsigned                   hold:1;        /* этот put учтён в body_holds  */

    void                     (*handler)(ngx_http_waf_body_op_t *op);
    void                      *data_ctx;      /* ngx_http_waf_ctx_t *        */
};


typedef struct {
    ngx_str_t                  name;          /* "redis"                     */
    ngx_uint_t                 caps;
    off_t                      max_object;

    void                    *(*create_conf)(ngx_conf_t *cf);
    char                    *(*set_option)(ngx_conf_t *cf, void *conf,
                                   ngx_str_t *key, ngx_str_t *value);
    char                    *(*validate_conf)(ngx_conf_t *cf, void *conf);
    ngx_int_t                (*init_worker)(ngx_cycle_t *cycle, void *conf);
    void                     (*exit_worker)(ngx_cycle_t *cycle, void *conf);

    /*
     * Горячий путь. Обе функции обязаны быть неблокирующими; возврат NGX_AGAIN
     * означает, что op->handler будет вызван позже.
     *
     * put вызывается не более одного раза на тело и фазу: ретрай тела в горячем
     * пути удваивает латентность в худший момент. Ретраи, если нужны, --
     * внутри драйвера, в пределах его op_timeout.
     *
     * Ключ генерирует модуль, не драйвер: формат <node>:<rid>:<phase> даёт
     * уникальность без координации и читаемость при разборе инцидентов.
     *
     * put обязан считать SHA-256 по ходу записи, а не отдельным проходом.
     *
     * get -- единственное чтение: объект, которым инспектор просит подменить
     * тело ответа. Ключ и потолок размера (op->len) ставит вызывающий; итог --
     * в op->status (NGX_OK и op->data; NGX_DECLINED -- ключа нет; NGX_ERROR),
     * буфер данных -- из op->pool. NULL у драйвера без CAP_GET.
     */
    ngx_int_t                (*put)(ngx_http_waf_body_op_t *op);
    ngx_int_t                (*del)(ngx_http_waf_body_op_t *op);
    ngx_int_t                (*get)(ngx_http_waf_body_op_t *op);
} ngx_http_waf_body_driver_t;


/*
 * Объявленный waf_store. Живёт в main conf в единственном экземпляре:
 * конфигурация обменника принадлежит драйверу, а признак объявления -- модулю.
 * Имени у обменника нет -- называть можно то, из чего выбирают.
 */
struct ngx_http_waf_body_store_s {
    ngx_http_waf_body_driver_t  *driver;
    void                        *conf;
};


/*
 * Регистрация выполняется в preconfiguration модуля драйвера, поэтому сторонний
 * драйвер -- это отдельный динамический модуль nginx, не требующий пересборки
 * основного.
 */
ngx_int_t  ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_t *drv);
ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_find(ngx_str_t *name);

/* Встроенные драйверы: none, inline, redis. */
ngx_int_t  ngx_http_waf_body_drivers_init(ngx_conf_t *cf);

ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_none(void);
ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_inline(void);
ngx_http_waf_body_driver_t  *ngx_http_waf_body_driver_redis(void);


/* --- конфигурация --------------------------------------------------------- */

char *ngx_http_waf_store_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * waf_sets_store: внутренний Redis контура, где keeper держит пакеты и
 * снапшоты активных наборов. Тот же драйвер, другой экземпляр: боевой
 * обменник объектов запроса и состояние наборов -- разные хранилища, и
 * состав наборов в обменник не ходит.
 */
char *ngx_http_waf_sets_store_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * Чтение объекта набора из waf_sets_store вне запроса: пул и журнал даёт
 * вызывающий, итог -- как у ngx_http_waf_store_get. NGX_ERROR -- хранилище
 * не объявлено или не умеет читать.
 */
ngx_int_t  ngx_http_waf_sets_get(ngx_str_t *key, off_t max, ngx_pool_t *pool,
               ngx_log_t *log, void (*handler)(ngx_http_waf_body_op_t *op),
               void *data, ngx_http_waf_body_op_t **out);

/*
 * Проверки маршрута: требование тела против доступа к нему, класс латентности
 * против дедлайна, размер против пределов обменника. Вызывается из
 * merge_loc_conf, когда волны уже посчитаны.
 */
char *ngx_http_waf_body_validate(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf);

/* Проверки уровня конфигурации целиком: объявленный, но ненужный обменник. */
char *ngx_http_waf_body_validate_main(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf);


/* --- воркер --------------------------------------------------------------- */

ngx_int_t  ngx_http_waf_body_init_worker(ngx_cycle_t *cycle);
void       ngx_http_waf_body_exit_worker(ngx_cycle_t *cycle);


/* --- горячий путь --------------------------------------------------------- */

/*
 * Размещение прочитанного тела. NGX_OK -- локатор готов, NGX_AGAIN -- драйвер
 * ответит позже вызовом ngx_http_waf_body_resumed(), NGX_ERROR -- размещение не
 * состоялось и locator->unavailable заполнен.
 */
ngx_int_t  ngx_http_waf_body_place(ngx_http_waf_ctx_t *ctx);

/* Удаление размещённого тела при разрешении вердикта. */
void       ngx_http_waf_body_release(ngx_http_waf_ctx_t *ctx);

/*
 * Конец кадра: объект фазы кадра снимается с обменника, незавершённая операция
 * бросается. Зовётся до уничтожения пула кадра, потому что cleanup этого пула
 * общий на весь контекст и снял бы заодно объекты рукопожатия.
 */
void       ngx_http_waf_body_frame_end(ngx_http_waf_ctx_t *ctx);

/*
 * Чтение объекта обменника по ключу: подмена тела ответа по секции rewrite.
 * NGX_AGAIN -- ждать op->handler; NGX_OK -- итог уже в op->status/op->data;
 * NGX_ERROR -- операция не начата (обменник не объявлен или без CAP_GET).
 * max -- потолок размера; больший объект приходит как op->status = NGX_ERROR.
 */
ngx_int_t  ngx_http_waf_store_get(ngx_http_waf_ctx_t *ctx, ngx_str_t *key,
               off_t max, void (*handler)(ngx_http_waf_body_op_t *op),
               ngx_http_waf_body_op_t **out);

/* Удаление объекта по явному ключу, в один конец: прочитанный rewrite-объект. */
void       ngx_http_waf_store_del_key(ngx_http_waf_ctx_t *ctx, ngx_str_t *key);

/* Тег фазы в ключе обменника: req, rsp, frm. Общий для put, get и разбора реплая. */
ngx_str_t *ngx_http_waf_body_phase_tag_name(ngx_uint_t phase);

/* Требует ли волна тела: максимум по body= её инспекторов. */
ngx_uint_t ngx_http_waf_body_wave_need(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t wave);

/*
 * Какие метаобъекты нужны волне: маска по ngx_http_waf_obj_e, уже
 * пересечённая с waf_capture маршрута. Ноль -- в хранилище идти незачем.
 */
ngx_uint_t ngx_http_waf_meta_wave_need(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t wave);

/*
 * Размещение заголовков и строки запроса в том же store, что и тело. Оба
 * объекта уходят в драйвер одним заходом, поэтому round-trip один на оба.
 */
ngx_int_t  ngx_http_waf_meta_place(ngx_http_waf_ctx_t *ctx, ngx_uint_t need);


/* --- локатор в сообщении -------------------------------------------------- */

/* Локатор объекта обменника либо NULL, если его не клали. */
ngx_http_waf_locator_t *ngx_http_waf_store_locator(ngx_http_waf_ctx_t *ctx,
                            ngx_uint_t obj);

/* Объект в capture маршрута: его видят все инспекторы. */
/*
 * Заголовки фазы парами: у запроса из r->headers_in, у ответа -- список
 * headers_out плюс поля, которые nginx держит отдельно. Один источник на снимок
 * и на превью: иначе запись аудита и объект обменника разошлись бы в том, что
 * такое "заголовки".
 */
ngx_array_t *ngx_http_waf_header_pairs(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_obj_visible_phase(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t phase, ngx_uint_t obj);
ngx_http_waf_locator_t *ngx_http_waf_store_locator_phase(
               ngx_http_waf_ctx_t *ctx, ngx_uint_t phase, ngx_uint_t obj);

/*
 * Актуальная версия объекта: последняя принятая подмена, иначе оригинал. Её
 * видит следующая волна и её отдаёт waf_send … =store; запись и архив живут по
 * ngx_http_waf_store_locator_phase().
 */
ngx_http_waf_locator_t *ngx_http_waf_store_locator_live(
               ngx_http_waf_ctx_t *ctx, ngx_uint_t phase, ngx_uint_t obj);
void       ngx_http_waf_store_write_phase(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, ngx_uint_t phase, const char *section);

/* Объекты capture маршрута, списком имён. Одинаковы у всех инспекторов. */
size_t     ngx_http_waf_needs_size(void);
void       ngx_http_waf_needs_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, ngx_http_waf_inspector_t *insp);

/*
 * Повторный put оригинала в те же ключи, до audit_request. Инспекторы
 * уже закрыты: mask/deny и трансформ в Redis им больше не видны.
 */
ngx_int_t  ngx_http_waf_store_reload(ngx_http_waf_ctx_t *ctx);
ngx_uint_t ngx_http_waf_store_reload_needs_body(ngx_http_waf_ctx_t *ctx);

/* Суффикс ключа, которым модуль называет свой объект (hdr, arg): инспектору под rewrite не отдаётся. */
ngx_uint_t ngx_http_waf_obj_suffix_reserved(ngx_str_t *suffix);

/* Место под секцию store сообщения инспектору: три локатора с именами. */
size_t     ngx_http_waf_store_size(ngx_http_waf_ctx_t *ctx);

/* Та же граница по конфигурации, для проверки размера сообщения при nginx -t. */
size_t     ngx_http_waf_store_max_size(ngx_http_waf_main_conf_t *wmcf,
               ngx_http_waf_loc_conf_t *wlcf, size_t client_max);

/*
 * Секция store сообщения инспектору. Объект, которого инспектор не просил,
 * получает null, даже если он лежит для других: инспектор объявляет, что ему
 * нужно, а не получает всё подряд.
 */
void       ngx_http_waf_store_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, ngx_http_waf_inspector_t *insp);

/*
 * Что писать в локаторе.
 *
 * BODY -- поля, которые есть только у тела: контрольная сумма, полнота,
 * усечение, кодировка. У заголовков и строки запроса нет ни того, ни другого.
 *
 * ADDRESS -- адресация: store, driver, key, expires_at, hint. Она пишется
 * только тогда, когда по ней действительно можно что-то достать. Инспектору
 * -- всегда: он читает объект, пока тот жив. В записи аудита -- лишь у тех
 * объектов, которые модуль оставил жить для агента: остальные он удалил
 * раньше, чем запись ушла в сокет, и ключ в ней указывал бы в пустоту.
 */
#define NGX_HTTP_WAF_LOC_BODY     0x01
#define NGX_HTTP_WAF_LOC_ADDRESS  0x02

/* Локатор без имени поля: аудит пишет свою секцию store сам. */
void       ngx_http_waf_locator_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_locator_t *loc, ngx_uint_t flags);


/* --- архивация ------------------------------------------------------------ */

/*
 * Объекты, которые модуль не удаляет: владение ими переходит агенту. Маска по
 * ngx_http_waf_obj_e, считается один раз за запрос и запоминается в контексте.
 */
ngx_uint_t ngx_http_waf_archive_mask(ngx_http_waf_ctx_t *ctx);

/* Набор архива фазы зависит от исхода, которого ещё нет: впереди фаза ответа. */
ngx_uint_t ngx_http_waf_archive_pending(ngx_http_waf_ctx_t *ctx);

/* Секция archive записи аудита: "вид объекта" -> срок хранения в секундах. */
void       ngx_http_waf_archive_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_ctx_t *ctx, ngx_uint_t mask);

/* Объект обменника по имени с провода: headers, args, body. */
ngx_int_t  ngx_http_waf_obj_find(ngx_str_t *name, ngx_uint_t *index);

/*
 * Хвост действия archive в записи и в prior: objects, ttl, limit. Печатается
 * там же, где остальные поля действия, но объекты знает только этот файл.
 */
void       ngx_http_waf_action_archive_write(ngx_http_waf_jw_t *jw,
               ngx_http_waf_action_t *a);


/* --- диагностика ---------------------------------------------------------- */

/*
 * Поле body= диагностического заголовка: инлайн, хранилище с драйвером либо
 * причина недоступности. Без него инлайн и размещение неотличимы снаружи, а
 * разбираться, почему инспектор не увидел тела, приходится именно снаружи.
 */
#define NGX_HTTP_WAF_BODY_DEBUG_LEN                                            \
    (NGX_HTTP_WAF_OBJ_COUNT                                                    \
     * (sizeof(" headers=unavailable:store_unconfigured/")                \
        + NGX_OFF_T_LEN + 256))

u_char    *ngx_http_waf_body_debug(ngx_http_waf_ctx_t *ctx, u_char *p,
               u_char *last);


/* --- SHA-256 -------------------------------------------------------------- */

/*
 * Своя реализация, а не OpenSSL: модуль собирается с --with-compat и не должен
 * требовать ssl-сборки nginx только ради контрольной суммы тела.
 */
typedef struct {
    uint64_t    bytes;
    uint32_t    h[8];
    u_char      block[64];
    size_t      used;
} ngx_http_waf_sha256_t;

void  ngx_http_waf_sha256_init(ngx_http_waf_sha256_t *sha);
void  ngx_http_waf_sha256_update(ngx_http_waf_sha256_t *sha, const u_char *data,
          size_t len);
void  ngx_http_waf_sha256_final(ngx_http_waf_sha256_t *sha, u_char result[32]);


#endif /* _NGX_HTTP_WAF_BODY_H_INCLUDED_ */
