#include "body/ngx_http_waf_body.h"

#include "net/ngx_http_waf_link.h"


#define NGX_HTTP_WAF_REDIS_IN_SIZE       1024
#define NGX_HTTP_WAF_REDIS_OUT_INITIAL   (16 * 1024)
#define NGX_HTTP_WAF_REDIS_OUT_SLACK     512
#define NGX_HTTP_WAF_REDIS_PASSWORD_MAX  1024


typedef struct ngx_http_waf_redis_conn_s   ngx_http_waf_redis_conn_t;
typedef struct ngx_http_waf_redis_entry_s  ngx_http_waf_redis_entry_t;


struct ngx_http_waf_redis_entry_s {
    ngx_http_waf_body_op_t      *op;
    ngx_pool_cleanup_t          *cln;
    ngx_event_t                  timer;
    ngx_http_waf_redis_entry_t  *next;

    unsigned                     bulk:1;
};


struct ngx_http_waf_redis_conn_s {
    ngx_http_waf_link_t          link;
    void                        *conf;

    ngx_http_waf_redis_entry_t  *head;
    ngx_http_waf_redis_entry_t  *tail;
    ngx_http_waf_redis_entry_t  *free;

    ngx_uint_t                   inflight;
    size_t                       skip;

    u_char                      *bulk;
    size_t                       bulk_size;
    size_t                       bulk_need;
    size_t                       bulk_got;

    unsigned                     skip_err:1;
};


typedef struct {
    ngx_array_t                 *servers;
    ngx_msec_t                   ttl;

    ngx_msec_t                   retain_ttl;
    off_t                        max;
    ngx_uint_t                   pool;
    ngx_msec_t                   connect_timeout;
    ngx_msec_t                   op_timeout;

    ngx_msec_t                   get_timeout;
    ngx_msec_t                   reconnect_wait;
    ngx_str_t                    user;
    ngx_str_t                    password;
    ngx_uint_t                   db;

    ngx_http_waf_redis_conn_t   *conns;
    ngx_uint_t                   nconns;
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
static off_t      ngx_http_waf_drv_redis_object_max(void *conf);
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
                      ngx_http_waf_redis_conf_t *rcf, ngx_str_t *hint);
static ngx_int_t  ngx_http_waf_redis_command(ngx_http_waf_redis_conn_t *conn,
                      ngx_str_t *argv, ngx_uint_t argc);
static ngx_int_t  ngx_http_waf_redis_queue(ngx_http_waf_redis_conn_t *conn,
                      ngx_str_t *argv, ngx_uint_t argc);
static void       ngx_http_waf_redis_send(ngx_http_waf_redis_conn_t *conn);
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


static ngx_http_waf_body_driver_t  ngx_http_waf_drv_redis = {
    ngx_string("redis"),
    NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS
        |NGX_HTTP_WAF_BODY_CAP_DELETE
        |NGX_HTTP_WAF_BODY_CAP_TTL
        |NGX_HTTP_WAF_BODY_CAP_GET,
    512 * 1024 * 1024,
    ngx_http_waf_drv_redis_object_max,
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
        if (n == NGX_ERROR || n == 0) {
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
        if (n == NGX_ERROR || n == 0) {
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
        if (n == NGX_ERROR || n == 0) {
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
    u_char       buf[NGX_HTTP_WAF_REDIS_PASSWORD_MAX + 3];

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

    if (len == sizeof(buf)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: password in \"%V\" is longer than %d bytes",
                           path, NGX_HTTP_WAF_REDIS_PASSWORD_MAX);
        return NGX_CONF_ERROR;
    }

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

    if (len > NGX_HTTP_WAF_REDIS_PASSWORD_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: password in \"%V\" is longer than %d bytes",
                           path, NGX_HTTP_WAF_REDIS_PASSWORD_MAX);
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
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                           "waf: body driver redis got %ui addresses; the "
                           "connections are spread over all of them at once, "
                           "so they must serve the same data",
                           rcf->servers->nelts);
    }

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


static off_t
ngx_http_waf_drv_redis_object_max(void *conf)
{
    ngx_http_waf_redis_conf_t  *rcf = conf;

    return rcf->max;
}


static ngx_int_t
ngx_http_waf_drv_redis_put(ngx_http_waf_body_op_t *op)
{
    u_char                       ms[NGX_INT64_LEN];
    ngx_str_t                    argv[5];
    ngx_uint_t                   argc;
    ngx_msec_t                   ttl;
    ngx_pool_cleanup_t          *cln;
    ngx_http_waf_redis_conf_t   *rcf = op->store_conf;
    ngx_http_waf_redis_conn_t   *conn;
    ngx_http_waf_redis_entry_t  *entry;

    op->status = NGX_ERROR;

    ttl = (op->retain && rcf->ttl != 0) ? rcf->retain_ttl : rcf->ttl;

    if (op->len > rcf->max) {
        ngx_log_error(NGX_LOG_ERR, op->log, 0,
                      "waf: object of %O bytes exceeds the store max %O",
                      op->len, rcf->max);
        return NGX_OK;
    }

    conn = ngx_http_waf_redis_pick(rcf, NULL);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, op->log, 0,
                      "waf: no ready redis connection to place %O bytes",
                      op->len);
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

    entry->op  = op;
    entry->cln = cln;

    ngx_str_set(&argv[0], "SET");
    argv[1] = op->locator.key;
    argv[2] = op->data;
    argc    = 3;

    if (ttl != 0) {
        ngx_str_set(&argv[3], "PX");
        argv[4].data = ms;
        argv[4].len  = (size_t) (ngx_sprintf(ms, "%M", ttl) - ms);
        argc = 5;
    }

    if (ngx_http_waf_redis_command(conn, argv, argc) != NGX_OK) {
        ngx_http_waf_redis_entry_free(conn, entry);
        return NGX_OK;
    }

    entry->timer.handler = ngx_http_waf_redis_on_timeout;
    entry->timer.data    = entry;
    entry->timer.log     = rcf->log;

    ngx_add_timer(&entry->timer, rcf->op_timeout);

    ngx_http_waf_redis_entry_push(conn, entry);
    ngx_http_waf_redis_send(conn);

    op->locator.hint       = *conn->link.peer.name;
    op->locator.expires_at = (ttl != 0)
                                 ? ngx_time() + (time_t) (ttl / 1000)
                                 : 0;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_waf_drv_redis_del(ngx_http_waf_body_op_t *op)
{
    ngx_str_t                   argv[2];
    ngx_http_waf_redis_conf_t  *rcf = op->store_conf;
    ngx_http_waf_redis_conn_t  *conn;

    conn = ngx_http_waf_redis_pick(rcf, &op->locator.hint);
    if (conn == NULL) {
        return NGX_OK;
    }

    ngx_str_set(&argv[0], "DEL");
    argv[1] = op->locator.key;

    if (ngx_http_waf_redis_queue(conn, argv, 2) == NGX_OK) {
        ngx_http_waf_redis_send(conn);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_drv_redis_get(ngx_http_waf_body_op_t *op)
{
    ngx_str_t                    argv[2];
    ngx_pool_cleanup_t          *cln;
    ngx_http_waf_redis_conf_t   *rcf = op->store_conf;
    ngx_http_waf_redis_conn_t   *conn;
    ngx_http_waf_redis_entry_t  *entry;

    op->status = NGX_ERROR;

    conn = ngx_http_waf_redis_pick(rcf, NULL);
    if (conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, op->log, 0,
                      "waf: no ready redis connection to read \"%V\"",
                      &op->locator.key);
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

    ngx_str_set(&argv[0], "GET");
    argv[1] = op->locator.key;

    if (ngx_http_waf_redis_command(conn, argv, 2) != NGX_OK) {
        ngx_http_waf_redis_entry_free(conn, entry);
        return NGX_OK;
    }

    entry->timer.handler = ngx_http_waf_redis_on_timeout;
    entry->timer.data    = entry;
    entry->timer.log     = rcf->log;

    ngx_add_timer(&entry->timer, rcf->get_timeout);

    ngx_http_waf_redis_entry_push(conn, entry);
    ngx_http_waf_redis_send(conn);

    return NGX_AGAIN;
}


static ngx_http_waf_redis_conn_t *
ngx_http_waf_redis_pick(ngx_http_waf_redis_conf_t *rcf, ngx_str_t *hint)
{
    ngx_str_t                  *name;
    ngx_uint_t                  i;
    ngx_http_waf_redis_conn_t  *conn, *best;

    if (rcf->conns == NULL) {
        return NULL;
    }

    best = NULL;

    for (i = 0; i < rcf->nconns; i++) {
        conn = &rcf->conns[i];

        if (!conn->link.ready) {
            continue;
        }

        if (hint != NULL && hint->len != 0) {
            name = conn->link.peer.name;

            if (name == NULL
                || name->len != hint->len
                || ngx_strncmp(name->data, hint->data, hint->len) != 0)
            {
                continue;
            }
        }

        if (best == NULL || conn->inflight < best->inflight) {
            best = conn;
        }
    }

    if (best == NULL && hint != NULL && hint->len != 0) {
        return ngx_http_waf_redis_pick(rcf, NULL);
    }

    return best;
}


/* A command cut short in the output buffer would shift every later reply. */

static ngx_int_t
ngx_http_waf_redis_command(ngx_http_waf_redis_conn_t *conn, ngx_str_t *argv,
    ngx_uint_t argc)
{
    u_char      head[NGX_INT64_LEN + 4];
    u_char     *p;
    size_t      size;
    ngx_uint_t  i;

    size = (size_t) (ngx_sprintf(head, "*%ui\r\n", argc) - head);

    for (i = 0; i < argc; i++) {
        size += (size_t) (ngx_sprintf(head, "$%uz\r\n", argv[i].len) - head)
                + argv[i].len + 2;
    }

    if (ngx_http_waf_link_reserve(&conn->link, size) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(head, "*%ui\r\n", argc);
    (void) ngx_http_waf_link_out(&conn->link, head, (size_t) (p - head));

    for (i = 0; i < argc; i++) {
        p = ngx_sprintf(head, "$%uz\r\n", argv[i].len);
        (void) ngx_http_waf_link_out(&conn->link, head, (size_t) (p - head));

        if (argv[i].len != 0) {
            (void) ngx_http_waf_link_out(&conn->link, argv[i].data,
                                         argv[i].len);
        }

        (void) ngx_http_waf_link_out(&conn->link, (u_char *) "\r\n", 2);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_redis_queue(ngx_http_waf_redis_conn_t *conn, ngx_str_t *argv,
    ngx_uint_t argc)
{
    ngx_http_waf_redis_entry_t  *entry;

    entry = ngx_http_waf_redis_entry_get(conn);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_redis_command(conn, argv, argc) != NGX_OK) {
        ngx_http_waf_redis_entry_free(conn, entry);
        return NGX_ERROR;
    }

    ngx_http_waf_redis_entry_push(conn, entry);

    return NGX_OK;
}


/*
 * A send error drops the link and fails the queued operations; that must not
 * happen inside put, get or del, so the write goes out from a posted event.
 */

static void
ngx_http_waf_redis_send(ngx_http_waf_redis_conn_t *conn)
{
    ngx_connection_t  *c;

    c = conn->link.peer.connection;

    if (c != NULL) {
        ngx_post_event(c->write, &ngx_posted_events);
    }
}


static ngx_int_t
ngx_http_waf_redis_on_connected(ngx_http_waf_link_t *link)
{
    ngx_http_waf_redis_conn_t  *conn = link->data;

    if (ngx_http_waf_redis_hello(conn) != NGX_OK) {
        return NGX_ERROR;
    }

    link->ready = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_redis_on_read(ngx_http_waf_link_t *link)
{
    return ngx_http_waf_redis_parse(link->data);
}


static void
ngx_http_waf_redis_on_close(ngx_http_waf_link_t *link, ngx_uint_t was_ready)
{
    ngx_http_waf_redis_drain(link->data);
}


static ngx_int_t
ngx_http_waf_redis_hello(ngx_http_waf_redis_conn_t *conn)
{
    u_char                      num[NGX_INT_T_LEN];
    ngx_str_t                   argv[3];
    ngx_uint_t                  argc;
    ngx_http_waf_redis_conf_t  *rcf = conn->conf;

    if (rcf->password.len != 0) {
        ngx_str_set(&argv[0], "AUTH");
        argc = 1;

        if (rcf->user.len != 0) {
            argv[argc] = rcf->user;
            argc++;
        }

        argv[argc] = rcf->password;
        argc++;

        if (ngx_http_waf_redis_queue(conn, argv, argc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (rcf->db != 0) {
        ngx_str_set(&argv[0], "SELECT");
        argv[1].data = num;
        argv[1].len  = (size_t) (ngx_sprintf(num, "%ui", rcf->db) - num);

        if (ngx_http_waf_redis_queue(conn, argv, 2) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


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
            return NGX_OK;
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
                                      "waf: redis object \"%V\" of %i bytes "
                                      "exceeds the %O byte cap",
                                      &conn->head->op->locator.key, n,
                                      conn->head->op->len);
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
                conn->bulk_need = (size_t) n + 2;
                conn->bulk_got  = 0;
                break;
            }

            if (n < 0) {
                ngx_http_waf_redis_entry_done(conn, NGX_OK, NULL);
                break;
            }

            conn->skip = (size_t) n + 2;
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, rcf->log, 0,
                          "waf: unexpected redis reply type \"%c\"", start[0]);
            return NGX_ERROR;
        }
    }
}


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
        return;
    }

    op->status = status;

    op->handler(op);
}


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
    if (entry->cln != NULL) {
        entry->cln->handler = NULL;
        entry->cln          = NULL;
    }

    entry->op   = NULL;
    entry->next = conn->free;

    conn->free = entry;
}


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
                  "waf: redis did not answer \"%V\" within %s",
                  &op->locator.key, entry->bulk ? "get_timeout" : "op_timeout");

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
