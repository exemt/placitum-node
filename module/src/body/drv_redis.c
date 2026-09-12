/*
 * Драйвер redis: основной вариант, когда инспекторы живут на отдельных машинах.
 *
 * Клиент свой, поверх ngx_event, по тем же причинам, что и клиент шины
 * (bus/ngx_http_waf_bus_nats.c): готовые библиотеки Redis либо блокируют, либо
 * заводят собственные потоки, а колбэк здесь добирается до ngx_http_request_t.
 * Проводной протокол RESP при этом крошечный -- нужны SET, DEL, AUTH и SELECT,
 * то есть массив bulk-строк на запись и однострочные ответы на чтение.
 *
 * Свойства реализации, которые стоит знать:
 *
 * Соединения открываются в init_worker и переподключаются в фоне, как у шины.
 * В горячем пути неготовое соединение означает немедленный store_error, а не
 * ожидание: тело, размещения которого запрос ждёт дольше своего дедлайна, всё
 * равно бесполезно, а очередь ожидания на неподнятом соединении -- это способ
 * превратить недоступность хранилища в исчерпание памяти воркера.
 *
 * Команды конвейеризуются, ответы разбираются строго по порядку отправки.
 * Истёкший op_timeout не рвёт соединение: запись очереди остаётся на месте и
 * становится "ответ выбросить", поэтому конвейер не рассинхронизируется, а
 * запрос получает свой отказ вовремя.
 *
 * Кластер не поддержан намеренно. Ключ здесь один на команду, то есть
 * CROSSSLOT невозможен по построению, но карта слотов, MOVED и ASK -- это
 * отдельная машина состояний топологии, и до неё редирект обрабатывается
 * честным store_error с записью в лог, а не вторым round-trip в обход правила
 * "put не более одного раза".
 */

#include "body/ngx_http_waf_body.h"

#include "net/ngx_http_waf_link.h"


#define NGX_HTTP_WAF_REDIS_IN_SIZE       1024
#define NGX_HTTP_WAF_REDIS_OUT_INITIAL   (16 * 1024)
#define NGX_HTTP_WAF_REDIS_OUT_SLACK     512


typedef struct ngx_http_waf_redis_conn_s   ngx_http_waf_redis_conn_t;
typedef struct ngx_http_waf_redis_entry_s  ngx_http_waf_redis_entry_t;


/*
 * Запись конвейера. Живёт в пуле цикла, а не запроса: ответ может прийти после
 * того, как запрос закрыт и его пул уничтожен. Cleanup пула запроса обнуляет
 * поле op, и запись превращается в "ответ выбросить" -- этим конвейер и
 * остаётся синхронным, что бы ни случилось с запросом.
 *
 * Обратная ссылка на этот cleanup обязательна: запись переиспользуется, а пул
 * запроса живёт дольше ответа хранилища -- у проксируемого запроса это весь
 * round-trip до апстрима. Не сняв cleanup в момент, когда операция покидает
 * запись, отработавший запрос отцепил бы чужую операцию, уже занявшую ту же
 * запись, и её колбэк не пришёл бы никогда.
 */
struct ngx_http_waf_redis_entry_s {
    ngx_http_waf_body_op_t      *op;
    ngx_pool_cleanup_t          *cln;
    ngx_http_waf_redis_conn_t   *conn;
    ngx_event_t                  timer;
    ngx_http_waf_redis_entry_t  *next;

    /*
     * GET: bulk-ответ не выбрасывается, а собирается для op->data. Флаг на
     * записи, а не на op: op к приходу ответа может быть уже отцеплен, а
     * решение "копить или пропустить" разбор принимает по голове конвейера.
     */
    unsigned                     bulk:1;
};


struct ngx_http_waf_redis_conn_s {
    ngx_http_waf_link_t          link;       /* соединение и буферы: net/   */
    void                        *conf;       /* ngx_http_waf_redis_conf_t * */

    ngx_http_waf_redis_entry_t  *head;       /* ждут ответа, в порядке отправки */
    ngx_http_waf_redis_entry_t  *tail;
    ngx_http_waf_redis_entry_t  *free;

    ngx_uint_t                   inflight;
    size_t                       skip;       /* байт bulk-ответа на выброс   */

    /*
     * Сборка bulk-ответа на GET. Буфер malloc, а не пул запроса: запрос может
     * умереть посреди ответа, а конвейер обязан дочитать его до конца. Копия в
     * op->pool делается при завершении, когда известно, что запрос жив.
     */
    u_char                      *bulk;
    size_t                       bulk_size;  /* длина полезной части         */
    size_t                       bulk_need;  /* осталось прочитать, с CRLF   */
    size_t                       bulk_got;

    unsigned                     skip_err:1; /* пропуск завершить ошибкой    */
};


typedef struct {
    ngx_array_t                 *servers;    /* ngx_addr_t                   */
    ngx_msec_t                   ttl;

    /*
     * Срок жизни объекта, за которым придёт агент. Тридцати секунд хватает на
     * волну, но не на то, чтобы агент под нагрузкой успел прочитать объект и
     * переложить его в архив. Выбирается в момент put -- маршрутная политика
     * известна заранее, а второй заход к хранилищу ради EXPIRE стоил бы ещё
     * одного round-trip в горячем пути.
     */
    ngx_msec_t                   retain_ttl;
    off_t                        max;
    ngx_uint_t                   pool;
    ngx_msec_t                   connect_timeout;
    ngx_msec_t                   op_timeout;

    /*
     * Свой срок у GET: он тянет из хранилища целое тело, а op_timeout выбран
     * под ответ в одну строку. Общий срок задушил бы подмену больших ответов
     * молча, по таймеру.
     */
    ngx_msec_t                   get_timeout;
    ngx_msec_t                   reconnect_wait;
    ngx_str_t                    user;
    ngx_str_t                    password;
    ngx_uint_t                   db;

    ngx_http_waf_redis_conn_t   *conns;
    ngx_uint_t                   nconns;
    ngx_uint_t                   next;       /* выбор соединения по кругу    */
    ngx_log_t                   *log;
} ngx_http_waf_redis_conf_t;


static void      *ngx_http_waf_drv_redis_create_conf(ngx_conf_t *cf);
static char      *ngx_http_waf_drv_redis_set_option(ngx_conf_t *cf, void *conf,
                      ngx_str_t *key, ngx_str_t *value);
static char      *ngx_http_waf_drv_redis_validate(ngx_conf_t *cf, void *conf);
static ngx_int_t  ngx_http_waf_drv_redis_init_worker(ngx_cycle_t *cycle,
                      void *conf);
static void       ngx_http_waf_drv_redis_exit_worker(ngx_cycle_t *cycle,
                      void *conf);
static ngx_int_t  ngx_http_waf_drv_redis_put(ngx_http_waf_body_op_t *op);
static ngx_int_t  ngx_http_waf_drv_redis_del(ngx_http_waf_body_op_t *op);
static ngx_int_t  ngx_http_waf_drv_redis_get(ngx_http_waf_body_op_t *op);

static char      *ngx_http_waf_redis_urls(ngx_conf_t *cf,
                      ngx_http_waf_redis_conf_t *rcf, ngx_str_t *value);
static char      *ngx_http_waf_redis_password_file(ngx_conf_t *cf,
                      ngx_http_waf_redis_conf_t *rcf, ngx_str_t *path);

static ngx_int_t  ngx_http_waf_redis_on_connected(ngx_http_waf_link_t *link);
static ngx_int_t  ngx_http_waf_redis_on_read(ngx_http_waf_link_t *link);
static void       ngx_http_waf_redis_on_close(ngx_http_waf_link_t *link,
                      ngx_uint_t was_ready);
static ngx_int_t  ngx_http_waf_redis_hello(ngx_http_waf_redis_conn_t *conn);
static ngx_int_t  ngx_http_waf_redis_parse(ngx_http_waf_redis_conn_t *conn);

static ngx_http_waf_redis_conn_t *ngx_http_waf_redis_pick(
                      ngx_http_waf_redis_conf_t *rcf);
static ngx_http_waf_redis_entry_t *ngx_http_waf_redis_entry_get(
                      ngx_http_waf_redis_conn_t *conn);
static void       ngx_http_waf_redis_entry_push(
                      ngx_http_waf_redis_conn_t *conn,
                      ngx_http_waf_redis_entry_t *entry);
static void       ngx_http_waf_redis_entry_done(
                      ngx_http_waf_redis_conn_t *conn, ngx_int_t status,
                      const char *err);
static void       ngx_http_waf_redis_bulk_ready(
                      ngx_http_waf_redis_conn_t *conn);
static void       ngx_http_waf_redis_entry_free(
                      ngx_http_waf_redis_conn_t *conn,
                      ngx_http_waf_redis_entry_t *entry);
static void       ngx_http_waf_redis_on_timeout(ngx_event_t *ev);
static void       ngx_http_waf_redis_detach(void *data);
static void       ngx_http_waf_redis_drain(ngx_http_waf_redis_conn_t *conn);

static ngx_int_t  ngx_http_waf_redis_bulk(ngx_http_waf_redis_conn_t *conn,
                      const u_char *data, size_t len);


static ngx_http_waf_body_driver_t  ngx_http_waf_drv_redis = {
    ngx_string("redis"),
    NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS
        |NGX_HTTP_WAF_BODY_CAP_DELETE
        |NGX_HTTP_WAF_BODY_CAP_TTL
        |NGX_HTTP_WAF_BODY_CAP_GET,
    512 * 1024 * 1024,                 /* предел значения Redis             */
    ngx_http_waf_drv_redis_create_conf,
    ngx_http_waf_drv_redis_set_option,
    ngx_http_waf_drv_redis_validate,
    ngx_http_waf_drv_redis_init_worker,
    ngx_http_waf_drv_redis_exit_worker,
    ngx_http_waf_drv_redis_put,
    ngx_http_waf_drv_redis_del,
    ngx_http_waf_drv_redis_get
};


ngx_http_waf_body_driver_t *
ngx_http_waf_body_driver_redis(void)
{
    return &ngx_http_waf_drv_redis;
}


/* --- конфигурация --------------------------------------------------------- */

static void *
ngx_http_waf_drv_redis_create_conf(ngx_conf_t *cf)
{
    ngx_http_waf_redis_conf_t  *rcf;

    rcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_redis_conf_t));
    if (rcf == NULL) {
        return NULL;
    }

    rcf->ttl             = 30000;
    rcf->retain_ttl      = 300000;
    rcf->max             = 8 * 1024 * 1024;
    rcf->pool            = 4;
    rcf->connect_timeout = 200;
    rcf->op_timeout      = 100;
    rcf->get_timeout     = 500;
    rcf->reconnect_wait  = 500;

    return rcf;
}


static char *
ngx_http_waf_drv_redis_set_option(ngx_conf_t *cf, void *conf, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_http_waf_redis_conf_t  *rcf = conf;

    ngx_int_t  n;

    if (key->len == 3 && ngx_strncmp(key->data, "url", 3) == 0) {
        return ngx_http_waf_redis_urls(cf, rcf, value);
    }

    if (key->len == 3 && ngx_strncmp(key->data, "ttl", 3) == 0) {

        n = ngx_parse_time(value, 0);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: invalid ttl \"%V\"",
                               value);
            return NGX_CONF_ERROR;
        }

        rcf->ttl = (ngx_msec_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 10 && ngx_strncmp(key->data, "retain_ttl", 10) == 0) {

        n = ngx_parse_time(value, 0);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid retain_ttl \"%V\"", value);
            return NGX_CONF_ERROR;
        }

        rcf->retain_ttl = (ngx_msec_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 3 && ngx_strncmp(key->data, "max", 3) == 0) {

        n = (ngx_int_t) ngx_parse_size(value);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: invalid max \"%V\"",
                               value);
            return NGX_CONF_ERROR;
        }

        rcf->max = (off_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 4 && ngx_strncmp(key->data, "pool", 4) == 0) {

        n = ngx_atoi(value->data, value->len);
        if (n == NGX_ERROR || n < 1 || n > 64) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid pool \"%V\", expected 1..64",
                               value);
            return NGX_CONF_ERROR;
        }

        rcf->pool = (ngx_uint_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 15 && ngx_strncmp(key->data, "connect_timeout", 15) == 0) {

        n = ngx_parse_time(value, 0);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid connect_timeout \"%V\"", value);
            return NGX_CONF_ERROR;
        }

        rcf->connect_timeout = (ngx_msec_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 10 && ngx_strncmp(key->data, "op_timeout", 10) == 0) {

        n = ngx_parse_time(value, 0);
        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid op_timeout \"%V\"", value);
            return NGX_CONF_ERROR;
        }

        rcf->op_timeout = (ngx_msec_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 11 && ngx_strncmp(key->data, "get_timeout", 11) == 0) {

        n = ngx_parse_time(value, 0);
        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid get_timeout \"%V\"", value);
            return NGX_CONF_ERROR;
        }

        rcf->get_timeout = (ngx_msec_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 14 && ngx_strncmp(key->data, "reconnect_wait", 14) == 0) {

        n = ngx_parse_time(value, 0);
        if (n == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid reconnect_wait \"%V\"", value);
            return NGX_CONF_ERROR;
        }

        rcf->reconnect_wait = (ngx_msec_t) n;
        return NGX_CONF_OK;
    }

    if (key->len == 4 && ngx_strncmp(key->data, "user", 4) == 0) {
        rcf->user = *value;
        return NGX_CONF_OK;
    }

    if (key->len == 13 && ngx_strncmp(key->data, "password_file", 13) == 0) {
        return ngx_http_waf_redis_password_file(cf, rcf, value);
    }

    if (key->len == 2 && ngx_strncmp(key->data, "db", 2) == 0) {

        n = ngx_atoi(value->data, value->len);
        if (n == NGX_ERROR || n < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: invalid db \"%V\"",
                               value);
            return NGX_CONF_ERROR;
        }

        rcf->db = (ngx_uint_t) n;
        return NGX_CONF_OK;
    }

    /*
     * Пароль в тексте конфигурации не принимается: файл конфигурации читают
     * все, кому нужен маршрут, а секрет хранилища тел -- это доступ ко всем
     * телам контура.
     */
    if (key->len == 8 && ngx_strncmp(key->data, "password", 8) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: use password_file= instead of password=");
        return NGX_CONF_ERROR;
    }

    if ((key->len == 3 && ngx_strncmp(key->data, "tls", 3) == 0)
        || (key->len > 4 && ngx_strncmp(key->data, "tls_", 4) == 0)
        || (key->len == 7 && ngx_strncmp(key->data, "cluster", 7) == 0)
        || (key->len == 8 && ngx_strncmp(key->data, "sentinel", 8) == 0))
    {
        /*
         * Молча проигнорировать значило бы выдать конфигурацию, которая
         * выглядит рабочей: кластер требует карты слотов и обработки MOVED,
         * которых здесь ещё нет.
         */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: body driver redis option \"%V\" is not "
                           "implemented yet", key);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: unknown option \"%V\" for body driver redis", key);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_waf_redis_urls(ngx_conf_t *cf, ngx_http_waf_redis_conf_t *rcf,
    ngx_str_t *value)
{
    u_char      *p, *last;
    ngx_str_t    host;
    ngx_url_t    u;
    ngx_addr_t  *addr;
    ngx_uint_t   j;

    if (rcf->servers == NULL) {
        rcf->servers = ngx_array_create(cf->pool, 2, sizeof(ngx_addr_t));
        if (rcf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Адреса разрешаются при загрузке конфигурации, как и у шины: воркеру
     * резолвер недоступен, а getaddrinfo в цикле событий блокирует воркер
     * целиком.
     */
    p    = value->data;
    last = value->data + value->len;

    while (p < last) {
        host.data = p;

        while (p < last && *p != ',') {
            p++;
        }

        host.len = (size_t) (p - host.data);

        if (p < last) {
            p++;
        }

        if (host.len > 8 && ngx_strncmp(host.data, "redis://", 8) == 0) {
            host.data += 8;
            host.len  -= 8;
        }

        if (host.len == 0) {
            continue;
        }

        ngx_memzero(&u, sizeof(ngx_url_t));

        u.url          = host;
        u.default_port = 6379;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: %s in redis address \"%V\"",
                               u.err ? u.err : "error", &host);
            return NGX_CONF_ERROR;
        }

        for (j = 0; j < u.naddrs; j++) {
            addr = ngx_array_push(rcf->servers);
            if (addr == NULL) {
                return NGX_CONF_ERROR;
            }

            *addr = u.addrs[j];
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_redis_password_file(ngx_conf_t *cf, ngx_http_waf_redis_conf_t *rcf,
    ngx_str_t *path)
{
    u_char      *p;
    size_t       len;
    ssize_t      n;
    ngx_fd_t     fd;
    ngx_file_t   file;
    u_char       buf[256];

    ngx_memzero(&file, sizeof(ngx_file_t));

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", path);
        return NGX_CONF_ERROR;
    }

    file.fd   = fd;
    file.name = *path;
    file.log  = cf->log;

    n = ngx_read_file(&file, buf, sizeof(buf), 0);

    (void) ngx_close_file(fd);

    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: password file \"%V\" is empty", path);
        return NGX_CONF_ERROR;
    }

    len = (size_t) n;

    /* хвостовой перевод строки -- часть файла, а не пароля */
    while (len > 0
           && (buf[len - 1] == LF || buf[len - 1] == CR
               || buf[len - 1] == ' '))
    {
        len--;
    }

    if (len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: password file \"%V\" holds no password", path);
        return NGX_CONF_ERROR;
    }

    p = ngx_pnalloc(cf->pool, len);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(p, buf, len);

    rcf->password.data = p;
    rcf->password.len  = len;

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_drv_redis_validate(ngx_conf_t *cf, void *conf)
{
    ngx_http_waf_redis_conf_t  *rcf = conf;

    if (rcf->servers == NULL || rcf->servers->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: body driver redis requires url=");
        return NGX_CONF_ERROR;
    }

    if (rcf->servers->nelts > 1) {
        /*
         * Несколько адресов -- это отказоустойчивость, а не шардирование:
         * воркер работает с одним из них, а инспектор находит ключ, потому что
         * адрес узла едет в локаторе подсказкой. Шардирование по хешу ключа
         * потребовало бы, чтобы инспектор считал тот же хеш по тому же списку,
         * и любое расхождение конфигураций давало бы ненаходимые тела.
         */
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                           "waf: body driver redis got %ui addresses; they are "
                           "used as failover, not as shards",
                           rcf->servers->nelts);
    }

    /*
     * Объект, за которым придёт агент, обязан жить не меньше остальных. Иначе
     * маршрут с архивацией теряет ключи раньше, чем маршрут без неё, -- то
     * есть настройка, включённая ради сохранности, её и ломает.
     */
    if (rcf->ttl != 0 && rcf->retain_ttl != 0 && rcf->retain_ttl < rcf->ttl) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: retain_ttl %M ms is below ttl %M ms",
                           rcf->retain_ttl, rcf->ttl);
        return NGX_CONF_ERROR;
    }

    if (rcf->max > ngx_http_waf_drv_redis.max_object) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: max %O exceeds the %O byte Redis value limit",
                           rcf->max, ngx_http_waf_drv_redis.max_object);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* --- воркер --------------------------------------------------------------- */

static ngx_int_t
ngx_http_waf_drv_redis_init_worker(ngx_cycle_t *cycle, void *conf)
{
    ngx_uint_t                  i;
    ngx_http_waf_link_conf_t   *lc;
    ngx_http_waf_redis_conf_t  *rcf = conf;
    ngx_http_waf_redis_conn_t  *conn;

    rcf->log    = cycle->log;
    rcf->nconns = rcf->pool;

    lc = ngx_pcalloc(cycle->pool, sizeof(ngx_http_waf_link_conf_t));
    if (lc == NULL) {
        return NGX_ERROR;
    }

    lc->name            = "redis";
    lc->servers         = rcf->servers;
    lc->connect_timeout = rcf->connect_timeout;
    lc->reconnect_wait  = rcf->reconnect_wait;
    lc->in_size         = NGX_HTTP_WAF_REDIS_IN_SIZE;
    lc->out_initial     = NGX_HTTP_WAF_REDIS_OUT_INITIAL;

    /*
     * Предел исходящего буфера -- одно тело максимального размера плюс запас
     * на команду. Больше означало бы, что воркер копит тела в памяти вместо
     * того, чтобы честно отказать: у Redis есть предел скорости, и очередь
     * перед ним не ускоряет ни одного запроса.
     */
    lc->out_max      = (size_t) rcf->max + NGX_HTTP_WAF_REDIS_OUT_SLACK;
    lc->on_connected = ngx_http_waf_redis_on_connected;
    lc->on_read      = ngx_http_waf_redis_on_read;
    lc->on_close     = ngx_http_waf_redis_on_close;

    rcf->conns = ngx_pcalloc(cycle->pool,
                             rcf->nconns * sizeof(ngx_http_waf_redis_conn_t));
    if (rcf->conns == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < rcf->nconns; i++) {
        conn = &rcf->conns[i];

        conn->conf = rcf;

        if (ngx_http_waf_link_init(&conn->link, lc, cycle, conn) != NGX_OK) {
            return NGX_ERROR;
        }

        /* распределение начальных соединений по адресам, а не все на первый */
        conn->link.next_server = i % rcf->servers->nelts;

        ngx_http_waf_link_connect(&conn->link);
    }

    return NGX_OK;
}


static void
ngx_http_waf_drv_redis_exit_worker(ngx_cycle_t *cycle, void *conf)
{
    ngx_uint_t                  i;
    ngx_http_waf_redis_conf_t  *rcf = conf;

    if (rcf->conns == NULL) {
        return;
    }

    for (i = 0; i < rcf->nconns; i++) {

        ngx_http_waf_link_stop(&rcf->conns[i].link);
    }
}


/* --- горячий путь --------------------------------------------------------- */

static ngx_int_t
ngx_http_waf_drv_redis_put(ngx_http_waf_body_op_t *op)
{
    u_char                       ms[NGX_INT64_LEN];
    u_char                      *p;
    ngx_msec_t                   ttl;
    ngx_pool_cleanup_t          *cln;
    ngx_http_waf_redis_conf_t   *rcf = op->store_conf;
    ngx_http_waf_redis_conn_t   *conn;
    ngx_http_waf_redis_entry_t  *entry;

    op->status = NGX_ERROR;

    /*
     * Длинный срок применяется на всём маршруте, где архивация возможна, даже
     * при when=deny: TTL здесь -- страховка на случай, если агент до объекта
     * не доберётся, а штатно ключ убивает он сам, сразу после публикации.
     */
    ttl = op->retain ? rcf->retain_ttl : rcf->ttl;

    if (op->len > rcf->max) {
        ngx_log_error(NGX_LOG_ERR, op->log, 0,
                      "waf: body of %O bytes exceeds the store max %O",
                      op->len, rcf->max);
        return NGX_OK;
    }

    conn = ngx_http_waf_redis_pick(rcf);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, op->log, 0,
                      "waf: no ready redis connection to place the body");
        return NGX_OK;
    }

    entry = ngx_http_waf_redis_entry_get(conn);
    if (entry == NULL) {
        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(op->pool, 0);
    if (cln == NULL) {
        ngx_http_waf_redis_entry_free(conn, entry);
        return NGX_OK;
    }

    /*
     * Пул запроса умирает раньше ответа при любом обрыве соединения клиентом.
     * Cleanup обнуляет op в записи конвейера, и ответ становится просто
     * выброшенным -- без этого колбэк пришёл бы в освобождённую память.
     */
    cln->handler = ngx_http_waf_redis_detach;
    cln->data    = entry;

    entry->op  = op;
    entry->cln = cln;

    if (ttl != 0) {
        p = ngx_sprintf(ms, "%M", ttl);

        if (ngx_http_waf_link_out(&conn->link, (u_char *) "*5\r\n", 4) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, (u_char *) "SET", 3) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, op->locator.key.data,
                                       op->locator.key.len) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, op->data.data, op->data.len)
               != NGX_OK
            || ngx_http_waf_redis_bulk(conn, (u_char *) "PX", 2) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, ms, (size_t) (p - ms)) != NGX_OK)
        {
            ngx_http_waf_redis_entry_free(conn, entry);
            cln->handler = NULL;
            return NGX_OK;
        }

    } else {
        if (ngx_http_waf_link_out(&conn->link, (u_char *) "*3\r\n", 4) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, (u_char *) "SET", 3) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, op->locator.key.data,
                                       op->locator.key.len) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, op->data.data, op->data.len)
               != NGX_OK)
        {
            ngx_http_waf_redis_entry_free(conn, entry);
            cln->handler = NULL;
            return NGX_OK;
        }
    }

    entry->timer.handler = ngx_http_waf_redis_on_timeout;
    entry->timer.data    = entry;
    entry->timer.log     = rcf->log;

    ngx_add_timer(&entry->timer, rcf->op_timeout);

    ngx_http_waf_redis_entry_push(conn, entry);
    ngx_http_waf_link_flush(&conn->link);

    /*
     * Адрес узла в подсказке: инспектору не нужно повторять логику выбора
     * соединения, чтобы найти тело, а при появлении шардирования формат
     * сообщения останется тем же.
     */
    op->locator.hint       = *conn->link.peer.name;
    op->locator.expires_at = (ttl != 0)
                                 ? ngx_time() + (time_t) (ttl / 1000)
                                 : 0;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_waf_drv_redis_del(ngx_http_waf_body_op_t *op)
{
    ngx_http_waf_redis_conf_t   *rcf = op->store_conf;
    ngx_http_waf_redis_conn_t   *conn;
    ngx_http_waf_redis_entry_t  *entry;

    conn = ngx_http_waf_redis_pick(rcf);
    if (conn == NULL) {
        return NGX_OK;                 /* останется на TTL */
    }

    /*
     * Ответ на DEL никого не ждёт, но прочитать его обязаны: запись конвейера
     * без op -- это и есть "ответ выбросить".
     */
    entry = ngx_http_waf_redis_entry_get(conn);
    if (entry == NULL) {
        return NGX_OK;
    }

    if (ngx_http_waf_link_out(&conn->link, (u_char *) "*2\r\n", 4) != NGX_OK
        || ngx_http_waf_redis_bulk(conn, (u_char *) "DEL", 3) != NGX_OK
        || ngx_http_waf_redis_bulk(conn, op->locator.key.data,
                                   op->locator.key.len) != NGX_OK)
    {
        ngx_http_waf_redis_entry_free(conn, entry);
        return NGX_OK;
    }

    ngx_http_waf_redis_entry_push(conn, entry);
    ngx_http_waf_link_flush(&conn->link);

    return NGX_OK;
}


/*
 * GET rewrite-объекта. Единственная команда драйвера, чей ответ не
 * выбрасывается: bulk собирается в scratch-буфер соединения и копируется в
 * op->pool при завершении. Итог различает три случая: NGX_OK с данными,
 * NGX_DECLINED -- ключа нет (TTL истёк или инспектор назвал несуществующий),
 * NGX_ERROR -- сбой, таймаут либо объект больше op->len.
 */
static ngx_int_t
ngx_http_waf_drv_redis_get(ngx_http_waf_body_op_t *op)
{
    ngx_pool_cleanup_t          *cln;
    ngx_http_waf_redis_conf_t   *rcf = op->store_conf;
    ngx_http_waf_redis_conn_t   *conn;
    ngx_http_waf_redis_entry_t  *entry;

    op->status = NGX_ERROR;

    conn = ngx_http_waf_redis_pick(rcf);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, op->log, 0,
                      "waf: no ready redis connection to fetch the rewrite "
                      "object");
        return NGX_OK;
    }

    entry = ngx_http_waf_redis_entry_get(conn);
    if (entry == NULL) {
        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(op->pool, 0);
    if (cln == NULL) {
        ngx_http_waf_redis_entry_free(conn, entry);
        return NGX_OK;
    }

    cln->handler = ngx_http_waf_redis_detach;
    cln->data    = entry;

    entry->op   = op;
    entry->cln  = cln;
    entry->bulk = 1;

    if (ngx_http_waf_link_out(&conn->link, (u_char *) "*2\r\n", 4) != NGX_OK
        || ngx_http_waf_redis_bulk(conn, (u_char *) "GET", 3) != NGX_OK
        || ngx_http_waf_redis_bulk(conn, op->locator.key.data,
                                   op->locator.key.len) != NGX_OK)
    {
        ngx_http_waf_redis_entry_free(conn, entry);
        cln->handler = NULL;
        return NGX_OK;
    }

    entry->timer.handler = ngx_http_waf_redis_on_timeout;
    entry->timer.data    = entry;
    entry->timer.log     = rcf->log;

    ngx_add_timer(&entry->timer, rcf->get_timeout);

    ngx_http_waf_redis_entry_push(conn, entry);
    ngx_http_waf_link_flush(&conn->link);

    return NGX_AGAIN;
}


/*
 * Соединение с самым коротким конвейером. Round-robin здесь хуже: конвейеры
 * разной длины означают разную латентность, а тело ждёт именно свой ответ.
 */
static ngx_http_waf_redis_conn_t *
ngx_http_waf_redis_pick(ngx_http_waf_redis_conf_t *rcf)
{
    ngx_uint_t                  i;
    ngx_http_waf_redis_conn_t  *best;

    if (rcf->conns == NULL) {
        return NULL;
    }

    best = NULL;

    for (i = 0; i < rcf->nconns; i++) {

        if (!rcf->conns[i].link.ready) {
            continue;
        }

        if (best == NULL || rcf->conns[i].inflight < best->inflight) {
            best = &rcf->conns[i];
        }
    }

    return best;
}


/* --- соединение: net/ngx_http_waf_link.c ---------------------------------- */

static ngx_int_t
ngx_http_waf_redis_on_connected(ngx_http_waf_link_t *link)
{
    ngx_http_waf_redis_conn_t  *conn = link->data;

    if (ngx_http_waf_redis_hello(conn) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Соединение считается готовым сразу: AUTH и SELECT конвейеризованы
     * перед первой командой тела, и их ответы разбираются как обычные
     * выбрасываемые. Ждать их подтверждения незачем -- порядок в конвейере
     * гарантирует, что до SET сервер уже применил их.
     */
    link->ready = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_redis_on_read(ngx_http_waf_link_t *link)
{
    return ngx_http_waf_redis_parse(link->data);
}


/* Всё, что ждало ответа в этом соединении, ответа уже не получит. */
static void
ngx_http_waf_redis_on_close(ngx_http_waf_link_t *link, ngx_uint_t was_ready)
{
    ngx_http_waf_redis_drain(link->data);
}


static ngx_int_t
ngx_http_waf_redis_hello(ngx_http_waf_redis_conn_t *conn)
{
    u_char                      *p;
    u_char                       num[NGX_INT_T_LEN];
    ngx_http_waf_redis_conf_t   *rcf = conn->conf;
    ngx_http_waf_redis_entry_t  *entry;

    if (rcf->password.len != 0) {

        entry = ngx_http_waf_redis_entry_get(conn);
        if (entry == NULL) {
            return NGX_ERROR;
        }

        if (rcf->user.len != 0) {
            if (ngx_http_waf_link_out(&conn->link, (u_char *) "*3\r\n", 4) != NGX_OK
                || ngx_http_waf_redis_bulk(conn, (u_char *) "AUTH", 4) != NGX_OK
                || ngx_http_waf_redis_bulk(conn, rcf->user.data, rcf->user.len)
                   != NGX_OK
                || ngx_http_waf_redis_bulk(conn, rcf->password.data,
                                           rcf->password.len) != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else {
            if (ngx_http_waf_link_out(&conn->link, (u_char *) "*2\r\n", 4) != NGX_OK
                || ngx_http_waf_redis_bulk(conn, (u_char *) "AUTH", 4) != NGX_OK
                || ngx_http_waf_redis_bulk(conn, rcf->password.data,
                                           rcf->password.len) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        ngx_http_waf_redis_entry_push(conn, entry);
    }

    if (rcf->db != 0) {

        entry = ngx_http_waf_redis_entry_get(conn);
        if (entry == NULL) {
            return NGX_ERROR;
        }

        p = ngx_sprintf(num, "%ui", rcf->db);

        if (ngx_http_waf_link_out(&conn->link, (u_char *) "*2\r\n", 4) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, (u_char *) "SELECT", 6) != NGX_OK
            || ngx_http_waf_redis_bulk(conn, num, (size_t) (p - num)) != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_http_waf_redis_entry_push(conn, entry);
    }

    return NGX_OK;
}


/* --- разбор RESP ---------------------------------------------------------- */

/*
 * Ответы, которые здесь бывают: +OK на SET и AUTH, :<n> на DEL, -ERR на любую
 * из них. Bulk и массивы не запрашиваются, но пропускаются корректно, чтобы
 * неожидаемый ответ не рассинхронизировал конвейер и не превратился в отказ
 * всех тел в полёте.
 */
static ngx_int_t
ngx_http_waf_redis_parse(ngx_http_waf_redis_conn_t *conn)
{
    u_char                     *start, *crlf;
    size_t                      avail, len, take;
    ngx_int_t                   n;
    ngx_http_waf_redis_conf_t  *rcf = conn->conf;

    for ( ;; ) {
        start = conn->link.in + conn->link.in_pos;
        avail = conn->link.in_last - conn->link.in_pos;

        if (avail == 0) {
            conn->link.in_pos  = 0;
            conn->link.in_last = 0;
            return NGX_OK;
        }

        /* сборка bulk-ответа на GET: полезная часть в scratch, CRLF мимо */
        if (conn->bulk_need != 0) {
            take = ngx_min(avail, conn->bulk_need);

            if (conn->bulk_got < conn->bulk_size) {
                len = ngx_min(take, conn->bulk_size - conn->bulk_got);

                ngx_memcpy(conn->bulk + conn->bulk_got, start, len);
                conn->bulk_got += len;
            }

            conn->link.in_pos    += take;
            conn->bulk_need -= take;

            if (conn->bulk_need != 0) {
                return NGX_OK;
            }

            ngx_http_waf_redis_bulk_ready(conn);
            continue;
        }

        if (conn->skip != 0) {
            take = ngx_min(avail, conn->skip);

            conn->link.in_pos += take;
            conn->skip   -= take;

            if (conn->skip != 0) {
                return NGX_OK;
            }

            if (conn->skip_err) {
                conn->skip_err = 0;
                ngx_http_waf_redis_entry_done(conn, NGX_ERROR, "oversize");

            } else {
                ngx_http_waf_redis_entry_done(conn, NGX_OK, NULL);
            }

            continue;
        }

        crlf = ngx_strlchr(start, start + avail, LF);

        if (crlf == NULL) {
            return NGX_OK;                 /* строка ответа ещё не целиком */
        }

        len = (size_t) (crlf - start);

        if (len != 0 && start[len - 1] == CR) {
            len--;
        }

        conn->link.in_pos += (size_t) (crlf - start) + 1;

        switch (start[0]) {

        case '+':
            ngx_http_waf_redis_entry_done(conn, NGX_OK, NULL);
            break;

        case ':':
            ngx_http_waf_redis_entry_done(conn, NGX_OK, NULL);
            break;

        case '-':
            /*
             * MOVED и ASK различаются в логе от прочих ошибок: это не сбой
             * хранилища, а незакрытая функциональность, и администратор должен
             * видеть разницу.
             */
            if (len > 6 && ngx_strncmp(start + 1, "MOVED ", 6) == 0) {
                ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                              "waf: redis answered %*s; cluster redirects are "
                              "not supported by this driver",
                              len - 1, start + 1);

            } else if (len > 4 && ngx_strncmp(start + 1, "ASK ", 4) == 0) {
                ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                              "waf: redis answered %*s; cluster resharding is "
                              "not supported by this driver",
                              len - 1, start + 1);

            } else {
                ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                              "waf: redis error: %*s", len - 1, start + 1);
            }

            ngx_http_waf_redis_entry_done(conn, NGX_ERROR, "store error");
            break;

        case '$':
            n = ngx_atoi(start + 1, len - 1);

            /*
             * Голова конвейера ждёт данные (GET): bulk не пропускается, а
             * собирается. Отцепленный запрос (op == NULL) и объект больше
             * заявленного потолка дочитываются как пропуск -- конвейер обязан
             * остаться синхронным при любом исходе запроса.
             */
            if (conn->head != NULL && conn->head->bulk) {

                if (n < 0) {
                    ngx_http_waf_redis_entry_done(conn, NGX_DECLINED,
                                                  "no such key");
                    break;
                }

                if (conn->head->op == NULL
                    || (off_t) n > conn->head->op->len)
                {
                    if (conn->head->op != NULL) {
                        ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                                      "waf: rewrite object of %i bytes exceeds "
                                      "the %O byte cap", n, conn->head->op->len);
                    }

                    conn->skip     = (size_t) n + 2;
                    conn->skip_err = 1;
                    break;
                }

                conn->bulk = ngx_alloc(n == 0 ? 1 : (size_t) n, rcf->log);

                if (conn->bulk == NULL) {
                    conn->skip     = (size_t) n + 2;
                    conn->skip_err = 1;
                    break;
                }

                conn->bulk_size = (size_t) n;
                conn->bulk_need = (size_t) n + 2;   /* тело и его CRLF */
                conn->bulk_got  = 0;
                break;
            }

            if (n < 0) {
                ngx_http_waf_redis_entry_done(conn, NGX_OK, NULL);
                break;
            }

            conn->skip = (size_t) n + 2;   /* тело и его CRLF */
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                          "waf: unexpected redis reply type \"%c\"", start[0]);
            return NGX_ERROR;
        }
    }
}


/* --- конвейер ------------------------------------------------------------- */

static ngx_http_waf_redis_entry_t *
ngx_http_waf_redis_entry_get(ngx_http_waf_redis_conn_t *conn)
{
    ngx_http_waf_redis_entry_t  *entry;

    entry = conn->free;

    if (entry != NULL) {
        conn->free = entry->next;

    } else {
        entry = ngx_pcalloc(ngx_cycle->pool,
                            sizeof(ngx_http_waf_redis_entry_t));
        if (entry == NULL) {
            return NULL;
        }
    }

    entry->op   = NULL;
    entry->cln  = NULL;
    entry->next = NULL;
    entry->conn = conn;
    entry->bulk = 0;

    ngx_memzero(&entry->timer, sizeof(ngx_event_t));

    return entry;
}


static void
ngx_http_waf_redis_entry_push(ngx_http_waf_redis_conn_t *conn,
    ngx_http_waf_redis_entry_t *entry)
{
    if (conn->tail == NULL) {
        conn->head = entry;

    } else {
        conn->tail->next = entry;
    }

    conn->tail = entry;
    conn->inflight++;
}


/* Ответ на голову конвейера. Порядок ответов Redis совпадает с порядком команд. */
static void
ngx_http_waf_redis_entry_done(ngx_http_waf_redis_conn_t *conn, ngx_int_t status,
    const char *err)
{
    ngx_http_waf_body_op_t      *op;
    ngx_http_waf_redis_conf_t   *rcf = conn->conf;
    ngx_http_waf_redis_entry_t  *entry;

    entry = conn->head;

    if (entry == NULL) {
        ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                      "waf: redis sent a reply nobody asked for");
        return;
    }

    conn->head = entry->next;

    if (conn->head == NULL) {
        conn->tail = NULL;
    }

    conn->inflight--;

    if (entry->timer.timer_set) {
        ngx_del_timer(&entry->timer);
    }

    op        = entry->op;
    entry->op = NULL;

    ngx_http_waf_redis_entry_free(conn, entry);

    if (op == NULL) {
        return;                        /* DEL, hello либо оборванный запрос */
    }

    op->status = status;

    op->handler(op);
}


/*
 * Собранный bulk-ответ на GET -- в op запроса. Копия в op->pool делается
 * здесь, а не по месту чтения: scratch общий для соединения, а пул запроса к
 * завершению может быть уже мёртв -- тогда op == NULL и данные выбрасываются.
 */
static void
ngx_http_waf_redis_bulk_ready(ngx_http_waf_redis_conn_t *conn)
{
    u_char                      *p;
    ngx_http_waf_body_op_t      *op;
    ngx_http_waf_redis_conf_t   *rcf = conn->conf;
    ngx_http_waf_redis_entry_t  *entry;

    entry = conn->head;

    if (entry == NULL) {
        ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                      "waf: redis sent a bulk reply nobody asked for");

        ngx_free(conn->bulk);
        conn->bulk      = NULL;
        conn->bulk_size = 0;
        conn->bulk_got  = 0;
        return;
    }

    conn->head = entry->next;

    if (conn->head == NULL) {
        conn->tail = NULL;
    }

    conn->inflight--;

    if (entry->timer.timer_set) {
        ngx_del_timer(&entry->timer);
    }

    op        = entry->op;
    entry->op = NULL;

    ngx_http_waf_redis_entry_free(conn, entry);

    if (op != NULL) {

        p = ngx_pnalloc(op->pool, conn->bulk_size == 0 ? 1 : conn->bulk_size);

        if (p == NULL) {
            op->status = NGX_ERROR;

        } else {
            ngx_memcpy(p, conn->bulk, conn->bulk_size);

            op->data.data = p;
            op->data.len  = conn->bulk_size;
            op->status    = NGX_OK;
        }
    }

    ngx_free(conn->bulk);
    conn->bulk      = NULL;
    conn->bulk_size = 0;
    conn->bulk_got  = 0;

    if (op != NULL) {
        op->handler(op);
    }
}


static void
ngx_http_waf_redis_entry_free(ngx_http_waf_redis_conn_t *conn,
    ngx_http_waf_redis_entry_t *entry)
{
    /*
     * Запись уходит в свободный список и может достаться другому запросу уже
     * следующей командой, поэтому cleanup, который её отцепляет, снимается
     * здесь же. Ненулевой cln означает, что пул запроса ещё жив: уничтожив
     * его, detach обнулил бы эту ссылку сам.
     */
    if (entry->cln != NULL) {
        entry->cln->handler = NULL;
        entry->cln          = NULL;
    }

    entry->op   = NULL;
    entry->next = conn->free;

    conn->free = entry;
}


/*
 * Истёкший op_timeout. Соединение не рвётся: запись остаётся в конвейере как
 * "ответ выбросить", поэтому порядок не теряется, а запрос получает отказ, не
 * дожидаясь ответа, который ему уже не нужен.
 */
static void
ngx_http_waf_redis_on_timeout(ngx_event_t *ev)
{
    ngx_http_waf_body_op_t      *op;
    ngx_http_waf_redis_entry_t  *entry = ev->data;

    op = entry->op;

    if (op == NULL) {
        return;
    }

    entry->op = NULL;

    ngx_log_error(NGX_LOG_ERR, op->log, 0,
                  "waf: redis did not answer within the op timeout");

    op->status = NGX_ERROR;

    op->handler(op);
}


static void
ngx_http_waf_redis_detach(void *data)
{
    ngx_http_waf_redis_entry_t  *entry = data;

    if (entry->timer.timer_set) {
        ngx_del_timer(&entry->timer);
    }

    /*
     * Запись остаётся в конвейере: её ответ ещё придёт, и выбросить его должен
     * тот же разбор, что и все остальные. Освободится она там же.
     *
     * Cleanup уходит вместе с пулом, поэтому ссылка на него обнуляется: по ней
     * освобождение записи отличает живой запрос от уже закрытого.
     */
    entry->op  = NULL;
    entry->cln = NULL;
}


static void
ngx_http_waf_redis_drain(ngx_http_waf_redis_conn_t *conn)
{
    while (conn->head != NULL) {
        ngx_http_waf_redis_entry_done(conn, NGX_ERROR, "connection lost");
    }

    conn->skip     = 0;
    conn->skip_err = 0;

    if (conn->bulk != NULL) {
        ngx_free(conn->bulk);
        conn->bulk = NULL;
    }

    conn->bulk_size = 0;
    conn->bulk_need = 0;
    conn->bulk_got  = 0;
}


/* --- исходящий буфер ------------------------------------------------------ */

static ngx_int_t
ngx_http_waf_redis_bulk(ngx_http_waf_redis_conn_t *conn, const u_char *data,
    size_t len)
{
    u_char   head[NGX_INT64_LEN + 4];
    u_char  *p;

    p = ngx_sprintf(head, "$%uz\r\n", len);

    if (ngx_http_waf_link_out(&conn->link, head, (size_t) (p - head)) != NGX_OK
        || ngx_http_waf_link_out(&conn->link, data, len) != NGX_OK
        || ngx_http_waf_link_out(&conn->link, (u_char *) "\r\n", 2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
