/*
 * Наборы данных локального слоя: представления, поиск и применение обновлений.
 *
 * Набор неизменяем после публикации. Обновление строится целиком рядом и
 * подменяется одним указателем, поэтому читатель не берёт мьютекс и не может
 * увидеть полуприменённое состояние -- ни при снапшоте на миллион сетей, ни при
 * дельте на одну. Освобождается прежний набор только тогда, когда его отпустил
 * последний читатель: воркеров несколько, и "уже подменили" не значит "уже
 * никто не читает".
 *
 * Так устроена база internal-набора: она приходит конфигом и меняется только
 * на reload. Активный набор живёт иначе -- целиком в overlay
 * (ngx_http_waf_ds_live.c), куда пакеты keeper ложатся точечно; здесь у него
 * разбор двоичных объектов keeper, применение пакета и снапшота и сверка
 * хеша. Провод -- docs/keeper.md.
 */

#include <ngx_md5.h>

#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"


/* Сколько раз читатель повторит попытку взять набор при одновременной подмене. */
#define NGX_HTTP_WAF_DS_ACQUIRE_TRIES 4


/* Операция слияния базы internal-набора; активные наборы живут в overlay. */
#define NGX_HTTP_WAF_DS_MERGE_ADD     1
#define NGX_HTTP_WAF_DS_MERGE_REMOVE  2


/* Диапазон адресов одного префикса; пара (начало, конец) задаёт префикс однозначно. */
typedef struct {
    uint32_t                  start;
    uint32_t                  end;
    uint64_t                  h;          /* SipHash текста под ключом эпохи */
} ngx_http_waf_ds_r4_t;


typedef struct {
    u_char                    start[16];
    u_char                    end[16];
    uint64_t                  h;
} ngx_http_waf_ds_r6_t;


/* Записи базы internal-набора перед построением представления в зоне. */
typedef struct {
    ngx_uint_t                op;
    u_char                    key[16];    /* ключ SipHash: у internal нули  */

    ngx_array_t              *r4;         /* ngx_http_waf_ds_r4_t           */
    ngx_array_t              *r6;         /* ngx_http_waf_ds_r6_t           */
    ngx_array_t              *str;        /* ngx_str_t                      */
} ngx_http_waf_ds_update_t;


static ngx_uint_t ngx_http_waf_ds_arg_option(ngx_str_t *arg);
static ngx_int_t ngx_http_waf_ds_add_entry(ngx_conf_t *cf,
    ngx_http_waf_dataset_t *ds, ngx_str_t *text);
static ngx_int_t ngx_http_waf_ds_load_internal(ngx_cycle_t *cycle,
    ngx_http_waf_dataset_t *ds);

static ngx_int_t ngx_http_waf_ds_entry_cidr(ngx_str_t *text,
    ngx_http_waf_ds_update_t *up, uint64_t h);
static uint64_t ngx_http_waf_ds_siphash(const u_char *key, const u_char *data,
    size_t len);
static ngx_int_t ngx_http_waf_ds_hex(ngx_str_t *text, u_char *out, size_t n);
static ngx_int_t ngx_http_waf_ds_hex64(ngx_str_t *text, uint64_t *out);

static void ngx_http_waf_ds_sort_uniq(ngx_array_t *a,
    int (ngx_libc_cdecl *cmp)(const void *, const void *));

static void *ngx_http_waf_ds_build_cidr(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_update_t *up);
static void *ngx_http_waf_ds_build_str(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_update_t *up);

static void *ngx_http_waf_ds_acquire(ngx_http_waf_ds_slot_t *slot);
static void  ngx_http_waf_ds_release(void *set);
static void  ngx_http_waf_ds_retire(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, void *set);
static void  ngx_http_waf_ds_reclaim(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot);

static ngx_int_t ngx_http_waf_ds_lookup_cidr(ngx_http_waf_cidr_set_t *set,
    ngx_str_t *value);
static ngx_int_t ngx_http_waf_ds_lookup_str(ngx_http_waf_str_set_t *set,
    ngx_str_t *value);
static ngx_uint_t ngx_http_waf_ds_str_probe(ngx_http_waf_str_set_t *set,
    u_char *data, size_t len, ngx_uint_t *slot);

static int ngx_libc_cdecl ngx_http_waf_ds_cmp_r4(const void *a, const void *b);
static int ngx_libc_cdecl ngx_http_waf_ds_cmp_r6(const void *a, const void *b);
static int ngx_libc_cdecl ngx_http_waf_ds_cmp_str(const void *a,
    const void *b);


/* --- директивы ------------------------------------------------------------ */

ngx_http_waf_dataset_t *
ngx_http_waf_dataset_find(ngx_http_waf_main_conf_t *wmcf, ngx_str_t *name)
{
    ngx_uint_t               i;
    ngx_http_waf_dataset_t  *ds;

    if (wmcf->datasets == NULL) {
        return NULL;
    }

    ds = wmcf->datasets->elts;

    for (i = 0; i < wmcf->datasets->nelts; i++) {
        if (ds[i].name.len == name->len
            && ngx_memcmp(ds[i].name.data, name->data, name->len) == 0)
        {
            return &ds[i];
        }
    }

    return NULL;
}


static ngx_uint_t
ngx_http_waf_ds_arg_option(ngx_str_t *arg)
{
    ngx_str_t  name, value;

    if (arg->len == 6 && ngx_strncmp(arg->data, "active", 6) == 0) {
        return 1;
    }

    if (arg->len == 8 && ngx_strncmp(arg->data, "internal", 8) == 0) {
        return 1;
    }

    if (ngx_http_waf_split(arg, &name, &value) != NGX_OK) {
        return 0;
    }

    if ((name.len == 4 && ngx_strncmp(name.data, "type", 4) == 0)
        || (name.len == 4 && ngx_strncmp(name.data, "hash", 4) == 0)
        || (name.len == 5 && ngx_strncmp(name.data, "limit", 5) == 0)
        || (name.len == 3 && ngx_strncmp(name.data, "ttl", 3) == 0)
        || (name.len == 7 && ngx_strncmp(name.data, "subject", 7) == 0)
        || (name.len == 4 && ngx_strncmp(name.data, "uuid", 4) == 0)
        || (name.len == 3 && ngx_strncmp(name.data, "max", 3) == 0)
        || (name.len == 8 && ngx_strncmp(name.data, "live_max", 8) == 0))
    {
        return 1;
    }

    return 0;
}


static ngx_int_t
ngx_http_waf_ds_add_entry(ngx_conf_t *cf, ngx_http_waf_dataset_t *ds,
    ngx_str_t *text)
{
    ngx_int_t   rc;
    ngx_cidr_t  cidr;
    ngx_str_t  *item;

    if (text->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: empty entry in dataset \"%V\"", &ds->name);
        return NGX_ERROR;
    }

    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        rc = ngx_ptocidr(text, &cidr);

        if (rc != NGX_OK && rc != NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: dataset \"%V\" has an invalid network "
                               "\"%V\"", &ds->name, text);
            return NGX_ERROR;
        }

    } else if (text->len > NGX_HTTP_WAF_DS_ENTRY_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: dataset \"%V\" entry is longer than %d bytes",
                           &ds->name, NGX_HTTP_WAF_DS_ENTRY_MAX);
        return NGX_ERROR;
    }

    if (ds->entries == NULL) {
        ds->entries = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
        if (ds->entries == NULL) {
            return NGX_ERROR;
        }
    }

    if (ds->entries->nelts >= ds->max) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: dataset \"%V\" has more than limit=%ui "
                           "entries", &ds->name, ds->max);
        return NGX_ERROR;
    }

    item = ngx_array_push(ds->entries);
    if (item == NULL) {
        return NGX_ERROR;
    }

    *item = *text;

    return NGX_OK;
}


char *
ngx_http_waf_local_dataset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ngx_str_t               *args, name, value;
    ngx_uint_t               i, saw_ttl;
    ngx_http_waf_dataset_t  *ds;

    if (ngx_http_waf_shm_required(cf, "waf_local_dataset") != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    args = cf->args->elts;

    if (args[1].len > NGX_HTTP_WAF_DS_NAME_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: dataset name \"%V\" is longer than %d bytes",
                           &args[1], NGX_HTTP_WAF_DS_NAME_MAX);
        return NGX_CONF_ERROR;
    }

    ds = ngx_http_waf_dataset_find(wmcf, &args[1]);

    if (ds != NULL) {

        for (i = 2; i < cf->args->nelts; i++) {
            if (ngx_http_waf_ds_arg_option(&args[i])) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: dataset \"%V\" is already declared",
                                   &args[1]);
                return NGX_CONF_ERROR;
            }
        }

        if (ds->mode != NGX_HTTP_WAF_DS_MODE_INTERNAL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: entries are not allowed on active "
                               "dataset \"%V\"", &ds->name);
            return NGX_CONF_ERROR;
        }

        for (i = 2; i < cf->args->nelts; i++) {
            if (ngx_http_waf_ds_add_entry(cf, ds, &args[i]) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        return NGX_CONF_OK;
    }

    if (!ngx_http_waf_ds_arg_option(&args[2])) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: dataset \"%V\" is not declared; "
                           "waf_local_dataset <name> … internal must come "
                           "first", &args[1]);
        return NGX_CONF_ERROR;
    }

    if (wmcf->datasets == NULL) {
        wmcf->datasets = ngx_array_create(cf->pool, 4,
                                          sizeof(ngx_http_waf_dataset_t));
        if (wmcf->datasets == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (wmcf->datasets->nelts >= NGX_HTTP_WAF_MAX_DATASETS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: at most %d datasets may be declared",
                           NGX_HTTP_WAF_MAX_DATASETS);
        return NGX_CONF_ERROR;
    }

    ds = ngx_array_push(wmcf->datasets);
    if (ds == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ds, sizeof(ngx_http_waf_dataset_t));

    ds->name     = args[1];
    ds->index    = wmcf->datasets->nelts - 1;
    ds->type     = NGX_HTTP_WAF_DS_CIDR;
    ds->max      = 1000000;
    /* Ноль -- «не сказано»: разбор аргументов ниже возьмёт потолок из limit=. */
    ds->live_max = 0;

    saw_ttl = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (args[i].len == 6 && ngx_strncmp(args[i].data, "active", 6) == 0) {

            if (ds->mode == NGX_HTTP_WAF_DS_MODE_INTERNAL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: dataset \"%V\" cannot be both "
                                   "active and internal", &ds->name);
                return NGX_CONF_ERROR;
            }

            ds->mode = NGX_HTTP_WAF_DS_MODE_ACTIVE;
            continue;
        }

        if (args[i].len == 8
            && ngx_strncmp(args[i].data, "internal", 8) == 0)
        {

            if (ds->mode == NGX_HTTP_WAF_DS_MODE_ACTIVE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: dataset \"%V\" cannot be both "
                                   "active and internal", &ds->name);
                return NGX_CONF_ERROR;
            }

            ds->mode = NGX_HTTP_WAF_DS_MODE_INTERNAL;
            continue;
        }

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in "
                               "waf_local_dataset; entries go on a separate "
                               "line after internal", &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 7 && ngx_strncmp(name.data, "subject", 7) == 0) {
            /*
             * Тему набора ведёт keeper и выводит её из имени: waf.sets.<имя>.
             * Своя тема подписала бы воркер туда, где никто не публикует, и
             * набор молчал бы, выглядя объявленным.
             */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: subject= is not supported; keeper "
                               "addresses dataset \"%V\" by name", &ds->name);
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "uuid", 4) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: uuid= is not allowed; the dataset slot "
                               "is its name");
            return NGX_CONF_ERROR;
        }

        /*
         * live_max= -- потолок overlay, то есть записей со сроком. Отдельно
         * от limit= он нужен редко: у набора один состав, и делить его на два
         * потолка -- значит завести число, о котором оператор не знает.
         * Поэтому умолчание берётся из limit=, а эта строка нужна тем, кто
         * хочет держать точечные баны короче общего потолка.
         */
        if (name.len == 8 && ngx_strncmp(name.data, "live_max", 8) == 0) {
            ngx_int_t  n = ngx_atoi(value.data, value.len);

            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid live_max \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            ds->live_max = (ngx_uint_t) n;
            continue;
        }

        if (name.len == 3 && ngx_strncmp(name.data, "max", 3) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: max= is not allowed; use limit=");
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "type", 4) == 0) {

            if (value.len == 4 && ngx_strncmp(value.data, "cidr", 4) == 0) {
                ds->type = NGX_HTTP_WAF_DS_CIDR;

            } else if (value.len == 6
                       && ngx_strncmp(value.data, "string", 6) == 0)
            {
                ds->type = NGX_HTTP_WAF_DS_STRING;

            } else if (value.len == 5
                       && ngx_strncmp(value.data, "regex", 5) == 0)
            {
                /*
                 * Регулярные выражения в зоне не живут: скомпилированная
                 * программа PCRE содержит указатели и аллоцируется своим
                 * аллокатором, то есть общей для воркеров быть не может, а
                 * компиляция присланного с провода выражения в каждом воркере --
                 * это исполнение недоверенного кода в терминаторе TLS.
                 */
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: dataset type \"regex\" is not "
                                   "implemented");
                return NGX_CONF_ERROR;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: dataset type must be cidr or string");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "hash", 4) == 0) {

            if (value.len == 3 && ngx_strncmp(value.data, "md5", 3) == 0) {
                ds->hash = NGX_HTTP_WAF_DS_HASH_MD5;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: dataset hash must be md5");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 5 && ngx_strncmp(name.data, "limit", 5) == 0) {
            ngx_int_t  n = ngx_atoi(value.data, value.len);

            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid limit \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            ds->max = (ngx_uint_t) n;
            continue;
        }

        if (name.len == 3 && ngx_strncmp(name.data, "ttl", 3) == 0) {
            ngx_int_t  n = ngx_parse_time(&value, 1);

            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid dataset ttl \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            ds->ttl = (ngx_uint_t) n;
            saw_ttl = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_local_dataset",
                           &name);
        return NGX_CONF_ERROR;
    }

    if (ds->mode == NGX_HTTP_WAF_DS_MODE_UNSET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_local_dataset \"%V\" requires active "
                           "or internal", &ds->name);
        return NGX_CONF_ERROR;
    }

    /*
     * Хешировать есть смысл только строку: адрес и так 4 или 16 байт, а
     * префикс после md5 перестал бы быть префиксом. Проверка после цикла,
     * потому что type= может стоять и после hash=.
     */
    /*
     * Потолок overlay по умолчанию -- общий потолок набора: у набора один
     * состав, и то, что часть записей со сроком и лежит на другом уровне, --
     * устройство зеркала, а не дело оператора. Прежде здесь стояла
     * константа в десять тысяч, и активный список крупнее неё молча
     * обрезался: край держал последние десять тысяч, расходился с keeper
     * хешем навсегда и уходил в круг снапшотов.
     */
    if (ds->live_max == 0) {
        ds->live_max = ds->max;
    }

    if (ds->hash != NGX_HTTP_WAF_DS_HASH_NONE
        && ds->type != NGX_HTTP_WAF_DS_STRING)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: hash= on dataset \"%V\" requires "
                           "type=string", &ds->name);
        return NGX_CONF_ERROR;
    }

    if (ds->mode == NGX_HTTP_WAF_DS_MODE_INTERNAL) {

        if (saw_ttl) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: ttl= is not allowed on internal "
                               "dataset \"%V\"", &ds->name);
            return NGX_CONF_ERROR;
        }

        ngx_str_null(&ds->subject);

        return NGX_CONF_OK;
    }

    if (ds->subject.len == 0) {
        ds->subject.data = ngx_pnalloc(cf->pool, sizeof("waf.sets.") - 1
                                       + ds->name.len);
        if (ds->subject.data == NULL) {
            return NGX_CONF_ERROR;
        }

        {
            u_char  *p;

            p = ngx_sprintf(ds->subject.data, "waf.sets.%V", &ds->name);
            ds->subject.len = (size_t) (p - ds->subject.data);
        }
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_local_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    ngx_str_t                         *args, name, value;
    ngx_uint_t                         i;
    ngx_http_waf_check_rule_t         *rule;
    ngx_http_waf_main_conf_t          *wmcf;

    args = cf->args->elts;

    /*
     * "none" -- снять доставшееся от родителя. Наследование здесь замена, а
     * пустого списка отсутствием строк не выразить: маршрут без своих проверок
     * получает родительские. Пустой (но созданный) массив останавливает
     * наследование в merge -- это единственный способ сказать "здесь не
     * проверяем", и он виден в конфиге.
     *
     * Зона для "none" не нужна: правил нет, в разделяемую память никто не
     * ходит. Требовать её значило бы требовать зону ради выключения.
     */
    if (cf->args->nelts == 2
        && args[1].len == 4 && ngx_strncmp(args[1].data, "none", 4) == 0)
    {
        if (wlcf->local_checks != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_local_check none cannot mix with "
                               "checks on the same level");
            return NGX_CONF_ERROR;
        }

        wlcf->local_checks = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_http_waf_check_rule_t));
        if (wlcf->local_checks == NULL) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_local_check expects <dataset> <value> "
                           "or \"none\"");
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_shm_required(cf, "waf_local_check") != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (wlcf->local_checks == NULL) {
        wlcf->local_checks = ngx_array_create(cf->pool, 2,
                                         sizeof(ngx_http_waf_check_rule_t));
        if (wlcf->local_checks == NULL) {
            return NGX_CONF_ERROR;
        }

    } else if (wlcf->local_checks->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_local_check none cannot mix with "
                           "checks on the same level");
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(wlcf->local_checks);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_http_waf_check_rule_t));

    /*
     * Набор обязан быть объявлен раньше проверки. Иначе опечатка в имени
     * набора становится проверкой, которая никогда не срабатывает, -- то есть
     * выглядящей работающей защитой.
     */
    rule->dataset = ngx_http_waf_dataset_find(wmcf, &args[1]);

    if (rule->dataset == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: dataset \"%V\" is not declared; "
                           "waf_local_dataset must come first", &args[1]);
        return NGX_CONF_ERROR;
    }

    rule->action = NGX_HTTP_WAF_CHECK_BLOCK;

    if (ngx_http_waf_operand_compile(cf, &args[2], &rule->operand, 1,
                                     "waf_local_check") != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (i = 3; i < cf->args->nelts; i++) {

        if (args[i].len == 2 && ngx_strncmp(args[i].data, "if", 2) == 0) {

            if (ngx_http_waf_cond_parse(cf, &i, &rule->conds,
                                        "waf_local_check") != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "waf: invalid option \"%V\" in waf_local_check",
                                &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "action", 6) == 0) {

            if (value.len == 5 && ngx_strncmp(value.data, "block", 5) == 0) {
                rule->action = NGX_HTTP_WAF_CHECK_BLOCK;

            } else if (value.len == 5
                       && ngx_strncmp(value.data, "allow", 5) == 0)
            {
                rule->action = NGX_HTTP_WAF_CHECK_ALLOW;

            } else if (value.len == 4
                       && ngx_strncmp(value.data, "wave", 4) == 0)
            {
                rule->action = NGX_HTTP_WAF_CHECK_WAVE;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: action must be block, allow or wave");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 8 && ngx_strncmp(name.data, "response", 8) == 0) {

            if (ngx_http_waf_deny_response_find(wmcf, &value) == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_deny_response \"%V\" is not "
                                   "declared", &value);
                return NGX_CONF_ERROR;
            }

            rule->response = value;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_local_check",
                           &name);
        return NGX_CONF_ERROR;
    }

    if (rule->action != NGX_HTTP_WAF_CHECK_BLOCK && rule->response.len != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: response= is only valid with action=block");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* --- привязка к слотам зоны ----------------------------------------------- */

/*
 * Слоты сохраняются между поколениями конфигурации, поэтому набор находит свой
 * слот по имени, а не по порядку объявления: иначе добавление одной директивы
 * сдвигало бы все наборы и каждый начинал бы работать с чужими данными.
 */
ngx_int_t
ngx_http_waf_dataset_bind(ngx_cycle_t *cycle)
{
    ngx_uint_t                 i, j, free_slot;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->datasets == NULL) {
        return NGX_OK;
    }

    shm = ngx_http_waf_shm();

    if (shm == NULL) {
        return NGX_ERROR;
    }

    ds = wmcf->datasets->elts;

    ngx_shmtx_lock(&shm->shpool->mutex);

    for (i = 0; i < wmcf->datasets->nelts; i++) {

        free_slot = NGX_HTTP_WAF_MAX_DATASETS;
        slot      = NULL;

        for (j = 0; j < NGX_HTTP_WAF_MAX_DATASETS; j++) {

            if (!shm->datasets[j].bound) {
                if (free_slot == NGX_HTTP_WAF_MAX_DATASETS) {
                    free_slot = j;
                }
                continue;
            }

            if (shm->datasets[j].name_len == ds[i].name.len
                && ngx_memcmp(shm->datasets[j].name, ds[i].name.data,
                              ds[i].name.len) == 0)
            {
                slot = &shm->datasets[j];
                break;
            }
        }

        if (slot == NULL) {

            if (free_slot == NGX_HTTP_WAF_MAX_DATASETS) {
                ngx_shmtx_unlock(&shm->shpool->mutex);

                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "waf: no free dataset slot in the zone for "
                              "\"%V\"; a full restart is required after "
                              "renaming datasets", &ds[i].name);
                return NGX_ERROR;
            }

            slot = &shm->datasets[free_slot];

            ngx_memcpy(slot->name, ds[i].name.data, ds[i].name.len);
            slot->name_len = ds[i].name.len;

            slot->type     = ds[i].type;
            slot->live_max = ds[i].live_max;
            slot->bound    = 1;

        } else if (slot->type != ds[i].type) {
            /*
             * Тип изменился: данные прежнего представления читать нельзя, и
             * притворяться, что они подходят, тоже. Набор начинает жизнь пустым
             * и наполнится первым же снапшотом.
             */
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "waf: dataset \"%V\" changed type, its data is "
                          "dropped", &ds[i].name);

            if (slot->set != NULL) {
                ngx_http_waf_ds_retire(shm, slot, slot->set);
                slot->set = NULL;
            }

            slot->type  = ds[i].type;
            slot->seq   = 0;
            slot->epoch = 0;
            slot->snap_bad = 0;
            slot->syncing  = 0;

            ngx_shmtx_unlock(&shm->shpool->mutex);
            ngx_http_waf_ds_live_reset(slot);
            ngx_shmtx_lock(&shm->shpool->mutex);
        }

        /*
         * У активного набора базы нет: всё, что осталось в слоте от прежнего
         * представления, снимается, иначе оно отвечало бы вне хеша keeper.
         */
        if (ds[i].mode == NGX_HTTP_WAF_DS_MODE_ACTIVE && slot->set != NULL) {
            ngx_http_waf_ds_retire(shm, slot, slot->set);
            slot->set = NULL;
        }

        if (ds[i].name.len != slot->name_len
            || ngx_memcmp(slot->name, ds[i].name.data, ds[i].name.len) != 0)
        {
            ngx_memcpy(slot->name, ds[i].name.data, ds[i].name.len);
            slot->name_len = ds[i].name.len;
        }

        slot->live_max = ds[i].live_max;
        ds[i].index = (ngx_uint_t) (slot - shm->datasets);
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    for (i = 0; i < wmcf->datasets->nelts; i++) {
        if (ds[i].mode != NGX_HTTP_WAF_DS_MODE_INTERNAL) {
            continue;
        }

        if (ngx_http_waf_ds_load_internal(cycle, &ds[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_ds_load_internal(ngx_cycle_t *cycle, ngx_http_waf_dataset_t *ds)
{
    void                      *set;
    ngx_uint_t                 i, entries;
    ngx_pool_t                *pool;
    ngx_str_t                 *items;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_ds_update_t   up;

    shm = ngx_http_waf_shm();

    if (shm == NULL) {
        return NGX_ERROR;
    }

    slot = &shm->datasets[ds->index];

    if (ds->entries == NULL || ds->entries->nelts == 0) {

        ngx_shmtx_lock(&shm->shpool->mutex);

        if (slot->set != NULL) {
            ngx_http_waf_ds_retire(shm, slot, slot->set);
            slot->set = NULL;
        }

        slot->seq = 0;

        ngx_shmtx_unlock(&shm->shpool->mutex);

        return NGX_OK;
    }

    pool = ngx_create_pool(4096, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&up, sizeof(ngx_http_waf_ds_update_t));
    up.op = NGX_HTTP_WAF_DS_MERGE_ADD;

    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        up.r4 = ngx_array_create(pool, ds->entries->nelts,
                                 sizeof(ngx_http_waf_ds_r4_t));
        up.r6 = ngx_array_create(pool, 4, sizeof(ngx_http_waf_ds_r6_t));

        if (up.r4 == NULL || up.r6 == NULL) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }

    } else {
        up.str = ngx_array_create(pool, ds->entries->nelts, sizeof(ngx_str_t));
        if (up.str == NULL) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }
    }

    items = ds->entries->elts;

    for (i = 0; i < ds->entries->nelts; i++) {

        if (ds->type == NGX_HTTP_WAF_DS_CIDR) {

            if (ngx_http_waf_ds_entry_cidr(&items[i], &up, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "waf: dataset \"%V\" has an invalid network "
                              "\"%V\"", &ds->name, &items[i]);
                ngx_destroy_pool(pool);
                return NGX_ERROR;
            }

        } else {
            ngx_str_t  *item;

            item = ngx_array_push(up.str);
            if (item == NULL) {
                ngx_destroy_pool(pool);
                return NGX_ERROR;
            }

            *item = items[i];
        }
    }

    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        ngx_http_waf_ds_sort_uniq(up.r4, ngx_http_waf_ds_cmp_r4);
        ngx_http_waf_ds_sort_uniq(up.r6, ngx_http_waf_ds_cmp_r6);
        entries = up.r4->nelts + up.r6->nelts;

    } else {
        ngx_http_waf_ds_sort_uniq(up.str, ngx_http_waf_ds_cmp_str);
        entries = up.str->nelts;
    }

    ngx_shmtx_lock(&shm->shpool->mutex);

    set = (ds->type == NGX_HTTP_WAF_DS_CIDR)
              ? ngx_http_waf_ds_build_cidr(shm, &up)
              : ngx_http_waf_ds_build_str(shm, &up);

    if (set == NULL) {
        ngx_shmtx_unlock(&shm->shpool->mutex);

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "waf: no room in the zone for dataset \"%V\"",
                      &ds->name);
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    if (slot->set != NULL) {
        ngx_http_waf_ds_retire(shm, slot, slot->set);
    }

    slot->set     = set;
    slot->seq     = 1;
    slot->updated = ngx_time();

    ngx_shmtx_unlock(&shm->shpool->mutex);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "waf: dataset \"%V\" loaded %ui internal entries",
                  &ds->name, entries);

    ngx_destroy_pool(pool);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_dataset_snapshot_claim(ngx_uint_t index, ngx_msec_t wait)
{
    ngx_msec_t               now;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_ds_slot_t  *slot;

    shm = ngx_http_waf_shm();

    if (shm == NULL || index >= NGX_HTTP_WAF_MAX_DATASETS) {
        return NGX_DECLINED;
    }

    slot = &shm->datasets[index];
    now  = ngx_current_msec;

    ngx_shmtx_lock(&shm->shpool->mutex);

    if (slot->snapshot_at != 0
        && (ngx_msec_int_t) (now - slot->snapshot_at) < (ngx_msec_int_t) wait)
    {
        ngx_shmtx_unlock(&shm->shpool->mutex);
        return NGX_DECLINED;
    }

    slot->snapshot_at = now;

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_OK;
}


/* --- проверки маршрута ---------------------------------------------------- */

/*
 * У активного набора состав целиком в overlay; база (неизменяемый набор в
 * зоне) есть только у internal. Автобан этой ноды ложится в overlay и у
 * internal, поэтому overlay смотрится первым у обоих.
 */
ngx_uint_t
ngx_http_waf_dataset_hit(ngx_http_waf_dataset_t *ds, ngx_str_t *value)
{
    void                    *set;
    ngx_int_t                hit;
    u_char                   hex[NGX_HTTP_WAF_MD5_HEX_LEN];
    ngx_str_t                hashed;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_ds_slot_t  *slot;

    if (value->len == 0) {
        return 0;
    }

    /*
     * Набор с hash=md5 хранит хеши: сравнивается хеш значения. Здесь, а не у
     * вызывающих, чтобы check, if и селекторы со звёздочкой не расходились.
     */
    if (ds->hash == NGX_HTTP_WAF_DS_HASH_MD5) {
        ngx_http_waf_md5_hex(value, hex);
        hashed.data = hex;
        hashed.len = NGX_HTTP_WAF_MD5_HEX_LEN;
        value = &hashed;
    }

    shm = ngx_http_waf_shm();

    if (shm == NULL) {
        return 0;
    }

    slot = &shm->datasets[ds->index];

    if (ngx_http_waf_ds_live_hit(ds, slot, value)) {
        return 1;
    }

    if (ds->mode != NGX_HTTP_WAF_DS_MODE_INTERNAL) {
        return 0;                      /* активный набор: только overlay */
    }

    set = ngx_http_waf_ds_acquire(slot);

    if (set == NULL) {
        return 0;
    }

    hit = (slot->type == NGX_HTTP_WAF_DS_CIDR)
              ? ngx_http_waf_ds_lookup_cidr(set, value)
              : ngx_http_waf_ds_lookup_str(set, value);

    ngx_http_waf_ds_release(set);

    return hit ? 1 : 0;
}




void
ngx_http_waf_md5_hex(ngx_str_t *in, u_char *out)
{
    u_char     digest[16];
    ngx_md5_t  md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, in->data, in->len);
    ngx_md5_final(digest, &md5);

    /* Строчный hex: keeper и контроллер печатают так же. */
    (void) ngx_hex_dump(out, digest, sizeof(digest));
}


ngx_int_t
ngx_http_waf_dataset_check(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule_name,
    ngx_str_t *response)
{
    ngx_str_t                   value;
    ngx_uint_t                  i;
    ngx_http_waf_shm_t         *shm;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_check_rule_t  *rules;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (wlcf->local_checks == NULL) {
        return NGX_DECLINED;
    }

    shm = ngx_http_waf_shm();

    if (shm == NULL) {
        return NGX_DECLINED;
    }

    rules = wlcf->local_checks->elts;

    /*
     * Порядок -- по объявлению, первое совпадение решает. Поэтому белый список
     * объявляется выше чёрного, и это зафиксированное поведение: любой другой
     * порядок пришлось бы выводить из приоритетов действий, а он не выражен ни в
     * одной директиве.
     */
    for (i = 0; i < wlcf->local_checks->nelts; i++) {

        /*
         * if считается раньше самой проверки: строка, у которой условие не
         * сошлось, на этом запросе не существует -- ни как отказ, ни как
         * пропуск, ни как wave.
         */
        if (ngx_http_waf_cond_test(ctx, rules[i].conds) != NGX_OK) {
            continue;
        }

        ngx_str_null(&value);

        if (ngx_http_waf_operand_hit(ctx, &rules[i].operand,
                                     rules[i].dataset, &value) != NGX_OK)
        {
            continue;
        }

        *rule_name = rules[i].dataset->name;

        if (rules[i].action == NGX_HTTP_WAF_CHECK_ALLOW) {
            ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                          "waf: local allow by dataset \"%V\", value \"%V\", "
                          "ray %*s", rule_name, &value,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

            return NGX_OK;
        }

        if (rules[i].action == NGX_HTTP_WAF_CHECK_WAVE) {

            ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                          "waf: local wave by dataset \"%V\", value \"%V\", "
                          "ray %*s", rule_name, &value,
                          (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

            return NGX_DONE;
        }

        ngx_log_error(NGX_LOG_NOTICE, ctx->request->connection->log, 0,
                      "waf: local block by dataset \"%V\", value \"%V\", "
                      "ray %*s", rule_name, &value,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        *response = rules[i].response;

        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


/* --- поиск в наборах ------------------------------------------------------ */


static ngx_int_t
ngx_http_waf_ds_lookup_cidr(ngx_http_waf_cidr_set_t *set, ngx_str_t *value)
{
    u_char      addr6[16];
    uint32_t    addr;
    ngx_uint_t  lo, hi, mid;

    /*
     * Значение приходит из переменной, то есть от конфигурации, а не с провода:
     * двоичный вид ($binary_remote_addr) -- основной путь, текстовый принимается
     * потому, что $remote_addr в конфигурации встречается чаще, и молча не
     * срабатывающая проверка была бы худшим ответом на такую запись.
     */
    if (value->len == 4) {
        addr = ((uint32_t) value->data[0] << 24)
               + ((uint32_t) value->data[1] << 16)
               + ((uint32_t) value->data[2] << 8)
               + (uint32_t) value->data[3];

    } else if (value->len == 16) {
        ngx_memcpy(addr6, value->data, 16);
        goto v6;

    } else {
        in_addr_t  in = ngx_inet_addr(value->data, value->len);

        if (in != INADDR_NONE) {
            addr = ntohl(in);

        } else if (ngx_inet6_addr(value->data, value->len, addr6) == NGX_OK) {
            goto v6;

        } else {
            return 0;
        }
    }

    if (set->n4 == 0) {
        return 0;
    }

    lo = 0;
    hi = set->n4;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;

        if (set->v4_start[mid] <= addr) {
            lo = mid + 1;

        } else {
            hi = mid;
        }
    }

    if (lo == 0) {
        return 0;
    }

    /*
     * cover[i] -- максимум конца по всем записям до i включительно. Он не меньше
     * адреса тогда и только тогда, когда какая-то из этих записей адрес
     * покрывает: все они начинаются не позже него.
     */
    return set->v4_cover[lo - 1] >= addr;

v6:

    if (set->n6 == 0) {
        return 0;
    }

    lo = 0;
    hi = set->n6;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;

        if (ngx_memcmp(set->v6_start + mid * 16, addr6, 16) <= 0) {
            lo = mid + 1;

        } else {
            hi = mid;
        }
    }

    if (lo == 0) {
        return 0;
    }

    return ngx_memcmp(set->v6_cover + (lo - 1) * 16, addr6, 16) >= 0;
}


static ngx_int_t
ngx_http_waf_ds_lookup_str(ngx_http_waf_str_set_t *set, ngx_str_t *value)
{
    ngx_uint_t  slot;

    if (set->h.entries == 0) {
        return 0;
    }

    return ngx_http_waf_ds_str_probe(set, value->data, value->len, &slot);
}


/*
 * Открытая адресация с линейным пробированием. Возвращает 1 при попадании; при
 * промахе в *slot остаётся индекс первой свободной ячейки, то есть место для
 * вставки, -- на этом же коде построено наполнение таблицы.
 */
static ngx_uint_t
ngx_http_waf_ds_str_probe(ngx_http_waf_str_set_t *set, u_char *data,
    size_t len, ngx_uint_t *slot)
{
    u_char      *entry;
    uint32_t     off;
    size_t       elen;
    ngx_uint_t   i;

    i = ngx_crc32_short(data, len) & set->mask;

    for ( ;; ) {
        off = set->table[i];

        if (off == 0) {
            *slot = i;
            return 0;
        }

        entry = set->blob + (off - 1);
        elen  = ((size_t) entry[0] << 8) + (size_t) entry[1];

        if (elen == len && ngx_memcmp(entry + 2, data, len) == 0) {
            *slot = i;
            return 1;
        }

        i = (i + 1) & set->mask;
    }
}


/* --- владение набором ----------------------------------------------------- */

static void *
ngx_http_waf_ds_acquire(ngx_http_waf_ds_slot_t *slot)
{
    ngx_uint_t           n;
    ngx_http_waf_set_t  *set;

    for (n = 0; n < NGX_HTTP_WAF_DS_ACQUIRE_TRIES; n++) {

        set = slot->set;

        if (set == NULL) {
            return NULL;
        }

        (void) ngx_atomic_fetch_add(&set->readers, 1);

        /*
         * Барьер и повторная проверка -- то, чем читатель отделён от
         * освобождения: набор освобождается только при нулевом счётчике
         * читателей, а увидеть тот же указатель после инкремента можно лишь
         * если подмены между чтением и инкрементом не было.
         */
        ngx_memory_barrier();

        if (slot->set == set) {
            return set;
        }

        (void) ngx_atomic_fetch_add(&set->readers, -1);
    }

    return NULL;
}


static void
ngx_http_waf_ds_release(void *set)
{
    (void) ngx_atomic_fetch_add(&((ngx_http_waf_set_t *) set)->readers, -1);
}


/* Вызывается под мьютексом зоны. */
static void
ngx_http_waf_ds_retire(ngx_http_waf_shm_t *shm, ngx_http_waf_ds_slot_t *slot,
    void *set)
{
    ngx_uint_t  i;

    ngx_http_waf_ds_reclaim(shm, slot);

    for (i = 0; i < NGX_HTTP_WAF_DS_RETIRED; i++) {
        if (slot->retired[i] == NULL) {
            slot->retired[i] = set;
            return;
        }
    }

    /*
     * Мест не осталось: столько обновлений подряд при читателях, не отпустивших
     * ни одного прежнего набора, означает либо зависший воркер, либо ошибку в
     * учёте. Память теряется до перезапуска -- это лучше, чем освободить набор
     * из-под читателя.
     */
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                  "waf: dataset \"%*s\" leaked a retired set: all %d retire "
                  "slots are busy", (size_t) slot->name_len, slot->name,
                  NGX_HTTP_WAF_DS_RETIRED);
}


/* Вызывается под мьютексом зоны. */
static void
ngx_http_waf_ds_reclaim(ngx_http_waf_shm_t *shm, ngx_http_waf_ds_slot_t *slot)
{
    ngx_uint_t           i;
    ngx_http_waf_set_t  *set;

    for (i = 0; i < NGX_HTTP_WAF_DS_RETIRED; i++) {

        set = slot->retired[i];

        if (set == NULL || set->readers != 0) {
            continue;
        }

        ngx_slab_free_locked(shm->shpool, set);
        slot->retired[i] = NULL;
    }
}


/* --- двоичные объекты keeper ----------------------------------------------
 *
 * Пакет изменений и снапшот -- один формат (keeper/internal/wire/pack.go):
 *
 *   заголовок 52 байта: "WAFS", версия u8, вид u8 (1 снапшот, 2 пакет),
 *   тип u8 (1 cidr, 2 string), флаги u8 (бит 0 -- у строк есть повод),
 *   epoch u64, seq u64, hash u64, ключ эпохи 16 байт, count u32; всё LE.
 *
 *   запись cidr:   op u8 | семейство u8 | биты u8 | адрес 4|16 | срок u64
 *   запись string: op u8 | длина u16 | байты | срок u64 | [длина u16 | повод]
 *
 * Материал записи -- байты между op и сроком у адреса, сама строка у строки:
 * это и ключ overlay, и вход SipHash. Разбора текста здесь нет вовсе.
 */

#define NGX_HTTP_WAF_PACK_HEADER    52
#define NGX_HTTP_WAF_PACK_SNAPSHOT  1
#define NGX_HTTP_WAF_PACK_PACKAGE   2
#define NGX_HTTP_WAF_PACK_CIDR      1
#define NGX_HTTP_WAF_PACK_STRING    2
#define NGX_HTTP_WAF_PACK_REASONS   1
#define NGX_HTTP_WAF_PACK_ADD       1
#define NGX_HTTP_WAF_PACK_REMOVE    2

/* Записей под одним исключительным замком при снапшоте. */
#define NGX_HTTP_WAF_DS_BATCH       1024


typedef struct {
    ngx_uint_t                kind;
    ngx_uint_t                type;
    ngx_uint_t                flags;
    uint64_t                  epoch;
    uint64_t                  seq;
    uint64_t                  hash;
    u_char                    key[16];
    ngx_uint_t                count;
} ngx_http_waf_ds_pack_t;


typedef struct {
    u_char                   *p;
    u_char                   *last;
    ngx_uint_t                type;
    ngx_uint_t                flags;
} ngx_http_waf_ds_cursor_t;


static uint64_t
ngx_http_waf_ds_le64(const u_char *p);


static ngx_int_t
ngx_http_waf_ds_pack_head(ngx_str_t *data, ngx_http_waf_ds_pack_t *h,
    ngx_http_waf_ds_cursor_t *cur)
{
    u_char  *p = data->data;

    if (data->len < NGX_HTTP_WAF_PACK_HEADER
        || ngx_memcmp(p, "WAFS", 4) != 0 || p[4] != 1)
    {
        return NGX_ERROR;
    }

    h->kind  = p[5];
    h->type  = p[6];
    h->flags = p[7];
    h->epoch = ngx_http_waf_ds_le64(p + 8);
    h->seq   = ngx_http_waf_ds_le64(p + 16);
    h->hash  = ngx_http_waf_ds_le64(p + 24);
    ngx_memcpy(h->key, p + 32, 16);
    h->count = (ngx_uint_t) p[48] | ((ngx_uint_t) p[49] << 8)
               | ((ngx_uint_t) p[50] << 16) | ((ngx_uint_t) p[51] << 24);

    cur->p     = p + NGX_HTTP_WAF_PACK_HEADER;
    cur->last  = p + data->len;
    cur->type  = h->type;
    cur->flags = h->flags;

    return NGX_OK;
}


/*
 * Следующая запись: NGX_OK -- op, материал и срок (мс UTC, 0 -- вечная);
 * NGX_DONE -- записи кончились; NGX_ERROR -- порванный хвост.
 */
static ngx_int_t
ngx_http_waf_ds_pack_next(ngx_http_waf_ds_cursor_t *cur, ngx_uint_t *op,
    ngx_str_t *key, int64_t *exp)
{
    size_t   n;
    u_char  *p = cur->p;

    if (p == cur->last) {
        return NGX_DONE;
    }

    if (p + 1 > cur->last) {
        return NGX_ERROR;
    }

    *op = *p++;

    if (cur->type == NGX_HTTP_WAF_PACK_CIDR) {

        if (p + 2 > cur->last) {
            return NGX_ERROR;
        }

        if (p[0] == 4) {
            n = 4;

        } else if (p[0] == 6) {
            n = 16;

        } else {
            return NGX_ERROR;
        }

        if (p + 2 + n + 8 > cur->last) {
            return NGX_ERROR;
        }

        key->data = p;
        key->len  = 2 + n;
        p += 2 + n;

    } else {

        if (p + 2 > cur->last) {
            return NGX_ERROR;
        }

        n = (size_t) p[0] | ((size_t) p[1] << 8);
        p += 2;

        if (p + n + 8 > cur->last) {
            return NGX_ERROR;
        }

        key->data = p;
        key->len  = n;
        p += n;
    }

    *exp = (int64_t) ngx_http_waf_ds_le64(p);
    p += 8;

    if (cur->type == NGX_HTTP_WAF_PACK_STRING
        && (cur->flags & NGX_HTTP_WAF_PACK_REASONS))
    {
        /* Повод записи модулю не нужен: пропускается. */
        if (p + 2 > cur->last) {
            return NGX_ERROR;
        }

        n = (size_t) p[0] | ((size_t) p[1] << 8);
        p += 2;

        if (p + n > cur->last) {
            return NGX_ERROR;
        }

        p += n;
    }

    cur->p = p;

    return NGX_OK;
}


/*
 * Срок keeper абсолютный (мс UTC), overlay живёт по ngx_current_msec.
 * Истёкшее к приходу кладётся уже просроченным: пакет remove от keeper
 * снимет его, а до него оно и так промах.
 */
static ngx_msec_t
ngx_http_waf_ds_expires(int64_t exp, int64_t now_ms)
{
    int64_t  left;

    if (exp == 0) {
        return 0;
    }

    left = exp - now_ms;

    if (left <= 0) {
        return ngx_current_msec - 1;
    }

    return ngx_current_msec + (ngx_msec_t) left;
}


static int64_t
ngx_http_waf_ds_now_ms(void)
{
    ngx_time_t  *tp = ngx_timeofday();

    return (int64_t) tp->sec * 1000 + (int64_t) tp->msec;
}


static ngx_int_t
ngx_http_waf_ds_locate(ngx_uint_t index, ngx_http_waf_dataset_t **ds,
    ngx_http_waf_ds_slot_t **slot)
{
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_main_conf_t  *wmcf;

    shm  = ngx_http_waf_shm();
    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (shm == NULL || wmcf == NULL || wmcf->datasets == NULL
        || index >= wmcf->datasets->nelts)
    {
        return NGX_ERROR;
    }

    *ds   = &((ngx_http_waf_dataset_t *) wmcf->datasets->elts)[index];
    *slot = &shm->datasets[(*ds)->index];

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_ds_type_matches(ngx_http_waf_dataset_t *ds,
    ngx_http_waf_ds_pack_t *h)
{
    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        return h->type == NGX_HTTP_WAF_PACK_CIDR;
    }

    return h->type == NGX_HTTP_WAF_PACK_STRING;
}


/*
 * Пакет изменений: seq обязан быть ровно свой+1, эпоха -- своей. Записи
 * ложатся под одним исключительным замком -- их в пакете десятки, и
 * читатели ждут микросекунды. Хеш после сверяется с заголовком.
 */
ngx_int_t
ngx_http_waf_dataset_apply_package(ngx_uint_t index, ngx_str_t *data)
{
    int64_t                    exp, now_ms;
    uint64_t                   have, h;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    uint32_t                   gen;
    ngx_uint_t                 op, n, lost;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_ds_pack_t     head;
    ngx_http_waf_ds_cursor_t   cur;

    if (ngx_http_waf_ds_locate(index, &ds, &slot) != NGX_OK) {
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    if (ngx_http_waf_ds_pack_head(data, &head, &cur) != NGX_OK
        || head.kind != NGX_HTTP_WAF_PACK_PACKAGE)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": package is not a WAFS package "
                      "(%uz bytes)", &ds->name, data->len);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    if (!ngx_http_waf_ds_type_matches(ds, &head)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": package type %ui does not match "
                      "the declared type", &ds->name, head.type);
        return NGX_HTTP_WAF_DS_FOREIGN;
    }

    now_ms = ngx_http_waf_ds_now_ms();

    ngx_rwlock_wlock(&slot->lock);

    if (slot->epoch == 0 || head.epoch != slot->epoch) {
        ngx_rwlock_unlock(&slot->lock);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" got package of epoch %016xL, have "
                      "%016xL, snapshot required", &ds->name, head.epoch,
                      slot->epoch);
        return NGX_HTTP_WAF_DS_FOREIGN;
    }

    if (slot->syncing) {
        ngx_rwlock_unlock(&slot->lock);
        return NGX_HTTP_WAF_DS_BUSY;
    }

    if (head.seq <= slot->seq) {
        ngx_rwlock_unlock(&slot->lock);
        return NGX_HTTP_WAF_DS_STALE;
    }

    if (head.seq != slot->seq + 1) {
        ngx_rwlock_unlock(&slot->lock);
        return NGX_HTTP_WAF_DS_GAP;
    }

    gen  = ngx_http_waf_ds_live_gen(slot);
    n    = 0;
    lost = 0;

    for ( ;; ) {
        rc = ngx_http_waf_ds_pack_next(&cur, &op, &key, &exp);

        if (rc == NGX_DONE) {
            break;
        }

        if (rc != NGX_OK) {
            ngx_rwlock_unlock(&slot->lock);

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "waf: dataset \"%V\": package seq %uL is truncated "
                          "after %ui records", &ds->name, head.seq, n);
            return NGX_HTTP_WAF_DS_MALFORMED;
        }

        n++;

        if (op == NGX_HTTP_WAF_PACK_REMOVE) {
            (void) ngx_http_waf_ds_live_drop(slot, &key);
            continue;
        }

        h = ngx_http_waf_ds_siphash(slot->key, key.data, key.len);

        if (ngx_http_waf_ds_live_put(slot, &key,
                                     ngx_http_waf_ds_expires(exp, now_ms),
                                     h, gen) == NGX_ERROR)
        {
            lost++;
        }
    }

    slot->seq     = head.seq;
    slot->updated = ngx_time();
    have          = slot->live_hash;

    ngx_rwlock_unlock(&slot->lock);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "waf: dataset \"%V\" applied package seq %uL, %ui records",
                   &ds->name, head.seq, n);

    if (lost != 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": %ui of %ui records of package seq "
                      "%uL did not fit", &ds->name, lost, n, head.seq);
    }

    if (have != head.hash) {
        /*
         * Единственный WARN в штатной работе зеркала, и он всегда означает
         * ошибку -- провода, хеширования, места. Снапшот приведёт состав в
         * порядок, но причину надо искать.
         */
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" diverged at package seq %uL: want "
                      "%016xL, got %016xL", &ds->name, head.seq, head.hash,
                      have);
        return NGX_HTTP_WAF_DS_DIVERGED;
    }

    return NGX_HTTP_WAF_DS_APPLIED;
}


/*
 * Снапшот: пометка и выметание. Записи объекта кладутся порциями под
 * исключительным замком с новым поколением -- между порциями читатели
 * получают состав, и он всё время не хуже прежнего; затем всё с прежним
 * поколением выметается, тоже порциями. Пакеты на это время не применяются
 * (syncing): догон пойдёт с seq объекта, пакеты после него keeper держит
 * дольше самого объекта.
 */
ngx_int_t
ngx_http_waf_dataset_apply_snapshot(ngx_uint_t index, ngx_str_t *data)
{
    int64_t                    exp, now_ms;
    uint64_t                   have, h;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    uint32_t                   gen;
    ngx_uint_t                 op, n, k, lost, swept, entries;
    ngx_rbtree_node_t         *cursor;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_ds_pack_t     head;
    ngx_http_waf_ds_cursor_t   cur;

    if (ngx_http_waf_ds_locate(index, &ds, &slot) != NGX_OK) {
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    if (ngx_http_waf_ds_pack_head(data, &head, &cur) != NGX_OK
        || head.kind != NGX_HTTP_WAF_PACK_SNAPSHOT)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": object is not a WAFS snapshot "
                      "(%uz bytes)", &ds->name, data->len);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    if (!ngx_http_waf_ds_type_matches(ds, &head)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": snapshot type %ui does not match "
                      "the declared type", &ds->name, head.type);
        return NGX_HTTP_WAF_DS_FOREIGN;
    }

    if (head.count > ds->max) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" snapshot rejected: %ui entries "
                      "exceed limit=%ui", &ds->name, head.count, ds->max);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    now_ms = ngx_http_waf_ds_now_ms();

    ngx_rwlock_wlock(&slot->lock);

    if (slot->syncing) {
        ngx_rwlock_unlock(&slot->lock);
        return NGX_HTTP_WAF_DS_BUSY;
    }

    gen = ngx_http_waf_ds_live_begin(slot);

    if (gen == 0) {
        ngx_rwlock_unlock(&slot->lock);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    slot->syncing = 1;
    ngx_rwlock_unlock(&slot->lock);

    n    = 0;
    lost = 0;
    rc   = NGX_OK;

    while (rc == NGX_OK) {

        ngx_rwlock_wlock(&slot->lock);

        for (k = 0; k < NGX_HTTP_WAF_DS_BATCH; k++) {
            rc = ngx_http_waf_ds_pack_next(&cur, &op, &key, &exp);

            if (rc != NGX_OK) {
                break;
            }

            n++;

            if (op != NGX_HTTP_WAF_PACK_ADD) {
                continue;              /* в снапшоте только add */
            }

            h = ngx_http_waf_ds_siphash(head.key, key.data, key.len);

            if (ngx_http_waf_ds_live_put(slot, &key,
                                         ngx_http_waf_ds_expires(exp, now_ms),
                                         h, gen) == NGX_ERROR)
            {
                lost++;
            }
        }

        ngx_rwlock_unlock(&slot->lock);
    }

    if (rc == NGX_ERROR) {
        /*
         * Порванный объект: помеченное остаётся -- это записи keeper, лишними
         * они не бывают, -- а выметать по неполному составу нельзя. Следующий
         * снапшот доведёт дело до конца.
         */
        ngx_rwlock_wlock(&slot->lock);
        slot->syncing = 0;
        ngx_rwlock_unlock(&slot->lock);

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": snapshot object is truncated after "
                      "%ui of %ui records", &ds->name, n, head.count);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    cursor = NULL;
    swept  = 0;

    do {
        ngx_rwlock_wlock(&slot->lock);
        rc = ngx_http_waf_ds_live_sweep(slot, gen, NGX_HTTP_WAF_DS_BATCH,
                                        &cursor, &swept);
        ngx_rwlock_unlock(&slot->lock);
    } while (rc == NGX_AGAIN);

    ngx_rwlock_wlock(&slot->lock);

    slot->epoch   = head.epoch;
    slot->seq     = head.seq;
    slot->updated = ngx_time();
    ngx_memcpy(slot->key, head.key, 16);
    slot->syncing = 0;

    have    = slot->live_hash;
    entries = (slot->live != NULL) ? slot->live->n : 0;

    slot->snap_bad = (have != head.hash);

    ngx_rwlock_unlock(&slot->lock);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "waf: dataset \"%V\" applied snapshot epoch %016xL seq %uL: "
                  "%ui records, %ui swept, %ui in overlay", &ds->name,
                  head.epoch, head.seq, n, swept, entries);

    if (lost != 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": %ui snapshot records did not fit "
                      "into the zone", &ds->name, lost);
    }

    if (have != head.hash) {
        /*
         * Состав собран из того же объекта, что и хеш keeper, и не сошёлся:
         * это дефект, а не гонка. Ещё один снапшот дал бы то же самое, поэтому
         * до новой эпохи расхождения только логируются.
         */
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" snapshot hash mismatch: keeper "
                      "%016xL, built %016xL; further divergence is logged, "
                      "not resynced", &ds->name, head.hash, have);
        return NGX_HTTP_WAF_DS_DIVERGED;
    }

    return NGX_HTTP_WAF_DS_APPLIED;
}


ngx_int_t
ngx_http_waf_dataset_verify(ngx_uint_t index, uint64_t epoch, uint64_t seq,
    uint64_t hash)
{
    uint64_t                 have, my_seq, my_epoch;
    ngx_uint_t               syncing;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (ngx_http_waf_ds_locate(index, &ds, &slot) != NGX_OK) {
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    ngx_rwlock_rlock(&slot->lock);
    my_epoch = slot->epoch;
    my_seq   = slot->seq;
    have     = slot->live_hash;
    syncing  = slot->syncing;
    ngx_rwlock_unlock(&slot->lock);

    if (my_epoch == 0 || epoch != my_epoch) {
        return NGX_HTTP_WAF_DS_FOREIGN;
    }

    if (syncing) {
        return NGX_HTTP_WAF_DS_BUSY;
    }

    if (seq > my_seq) {
        return NGX_HTTP_WAF_DS_GAP;
    }

    if (seq < my_seq) {
        return NGX_HTTP_WAF_DS_STALE;
    }

    if (have != hash) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" diverged at tick seq %uL: want "
                      "%016xL, got %016xL", &ds->name, seq, hash, have);
        return NGX_HTTP_WAF_DS_DIVERGED;
    }

    return NGX_HTTP_WAF_DS_APPLIED;
}


ngx_uint_t
ngx_http_waf_dataset_snap_bad(ngx_uint_t index)
{
    ngx_uint_t               bad;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (ngx_http_waf_ds_locate(index, &ds, &slot) != NGX_OK) {
        return 0;
    }

    ngx_rwlock_rlock(&slot->lock);
    bad = slot->snap_bad;
    ngx_rwlock_unlock(&slot->lock);

    return bad;
}


void
ngx_http_waf_dataset_state(ngx_uint_t index, uint64_t *epoch, uint64_t *seq)
{
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_main_conf_t  *wmcf;

    *epoch = 0;
    *seq   = 0;

    shm  = ngx_http_waf_shm();
    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (shm == NULL || wmcf == NULL || wmcf->datasets == NULL
        || index >= wmcf->datasets->nelts)
    {
        return;
    }

    ds   = &((ngx_http_waf_dataset_t *) wmcf->datasets->elts)[index];
    slot = &shm->datasets[ds->index];

    ngx_shmtx_lock(&shm->shpool->mutex);
    *epoch = slot->epoch;
    *seq   = slot->seq;
    ngx_shmtx_unlock(&shm->shpool->mutex);
}


ngx_msec_int_t
ngx_http_waf_dataset_seen(ngx_uint_t index, ngx_uint_t touch,
    ngx_uint_t *first_silence)
{
    ngx_msec_int_t             age;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_main_conf_t  *wmcf;

    if (first_silence != NULL) {
        *first_silence = 0;
    }

    shm  = ngx_http_waf_shm();
    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (shm == NULL || wmcf == NULL || wmcf->datasets == NULL
        || index >= wmcf->datasets->nelts)
    {
        return 0;
    }

    ds   = &((ngx_http_waf_dataset_t *) wmcf->datasets->elts)[index];
    slot = &shm->datasets[ds->index];

    ngx_shmtx_lock(&shm->shpool->mutex);

    if (touch) {
        slot->seen   = ngx_current_msec;
        slot->silent = 0;
        age = 0;

    } else {
        age = (slot->seen == 0) ? 0
                                : (ngx_msec_int_t) (ngx_current_msec - slot->seen);

        if (first_silence != NULL && !slot->silent && age > 0) {
            slot->silent   = 1;
            *first_silence = 1;
        }
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return age;
}


/* --- SipHash-2-4 и hex ---------------------------------------------------- */

/*
 * Хеш записи -- SipHash-2-4 текста под ключом эпохи; хеш набора -- XOR по
 * записям. Функция задана до байта, потому что сверяется с keeper на Go
 * (keeper/internal/set/siphash.go); справочная реализация без ускорений.
 */
#define ngx_http_waf_ds_rotl(x, b)  (uint64_t) (((x) << (b)) | ((x) >> (64 - (b))))

#define ngx_http_waf_ds_sipround(v0, v1, v2, v3)                              \
    do {                                                                      \
        v0 += v1; v1 = ngx_http_waf_ds_rotl(v1, 13); v1 ^= v0;                \
        v0 = ngx_http_waf_ds_rotl(v0, 32);                                    \
        v2 += v3; v3 = ngx_http_waf_ds_rotl(v3, 16); v3 ^= v2;                \
        v0 += v3; v3 = ngx_http_waf_ds_rotl(v3, 21); v3 ^= v0;                \
        v2 += v1; v1 = ngx_http_waf_ds_rotl(v1, 17); v1 ^= v2;                \
        v2 = ngx_http_waf_ds_rotl(v2, 32);                                    \
    } while (0)

static uint64_t
ngx_http_waf_ds_le64(const u_char *p)
{
    return (uint64_t) p[0] | ((uint64_t) p[1] << 8) | ((uint64_t) p[2] << 16)
           | ((uint64_t) p[3] << 24) | ((uint64_t) p[4] << 32)
           | ((uint64_t) p[5] << 40) | ((uint64_t) p[6] << 48)
           | ((uint64_t) p[7] << 56);
}

static uint64_t
ngx_http_waf_ds_siphash(const u_char *key, const u_char *data, size_t len)
{
    size_t    i, full;
    uint64_t  k0, k1, v0, v1, v2, v3, m, last;

    k0 = ngx_http_waf_ds_le64(key);
    k1 = ngx_http_waf_ds_le64(key + 8);

    v0 = k0 ^ 0x736f6d6570736575ULL;
    v1 = k1 ^ 0x646f72616e646f6dULL;
    v2 = k0 ^ 0x6c7967656e657261ULL;
    v3 = k1 ^ 0x7465646279746573ULL;

    full = len - len % 8;

    for (i = 0; i < full; i += 8) {
        m = ngx_http_waf_ds_le64(data + i);
        v3 ^= m;
        ngx_http_waf_ds_sipround(v0, v1, v2, v3);
        ngx_http_waf_ds_sipround(v0, v1, v2, v3);
        v0 ^= m;
    }

    last = (uint64_t) len << 56;

    for (i = full; i < len; i++) {
        last |= (uint64_t) data[i] << (8 * (i - full));
    }

    v3 ^= last;
    ngx_http_waf_ds_sipround(v0, v1, v2, v3);
    ngx_http_waf_ds_sipround(v0, v1, v2, v3);
    v0 ^= last;

    v2 ^= 0xff;
    ngx_http_waf_ds_sipround(v0, v1, v2, v3);
    ngx_http_waf_ds_sipround(v0, v1, v2, v3);
    ngx_http_waf_ds_sipround(v0, v1, v2, v3);
    ngx_http_waf_ds_sipround(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}


static ngx_int_t
ngx_http_waf_ds_hex(ngx_str_t *text, u_char *out, size_t n)
{
    size_t      i;
    ngx_int_t   hi, lo;

    if (text->len == 0) {
        ngx_memzero(out, n);
        return NGX_OK;
    }

    if (text->len != n * 2) {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        hi = ngx_hextoi(text->data + i * 2, 1);
        lo = ngx_hextoi(text->data + i * 2 + 1, 1);

        if (hi == NGX_ERROR || lo == NGX_ERROR) {
            return NGX_ERROR;
        }

        out[i] = (u_char) ((hi << 4) | lo);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_ds_hex64(ngx_str_t *text, uint64_t *out)
{
    u_char  b[8];

    if (text->len == 0) {
        *out = 0;
        return NGX_OK;
    }

    if (ngx_http_waf_ds_hex(text, b, 8) != NGX_OK) {
        return NGX_ERROR;
    }

    *out = ((uint64_t) b[0] << 56) | ((uint64_t) b[1] << 48)
           | ((uint64_t) b[2] << 40) | ((uint64_t) b[3] << 32)
           | ((uint64_t) b[4] << 24) | ((uint64_t) b[5] << 16)
           | ((uint64_t) b[6] << 8) | (uint64_t) b[7];

    return NGX_OK;
}


/* --- кадр провода --------------------------------------------------------- */

static ngx_int_t
ngx_http_waf_ds_copy(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    if (src->len == 0) {
        ngx_str_null(dst);
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->len = src->len;

    return NGX_OK;
}


/*
 * Уведомление, тик или ответ на .snapshot: заголовок без состава. Имя набора
 * в кадре обязано совпадать с тем, на чей subject подписка: расхождение --
 * чужой поток или ошибка поставщика, и применять такое к нашему набору нельзя.
 */
ngx_int_t
ngx_http_waf_dataset_notice(ngx_uint_t index, ngx_str_t *payload,
    ngx_pool_t *pool, ngx_http_waf_ds_notice_t *n)
{
    u_char                   head[96 * 6 + 1], *last;
    size_t                   len;
    ngx_int_t                rc, v, num;
    ngx_str_t                key, value;
    ngx_http_waf_jp_t        jp;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (ngx_http_waf_ds_locate(index, &ds, &slot) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(n, sizeof(ngx_http_waf_ds_notice_t));
    n->op = NGX_HTTP_WAF_DS_OP_OTHER;

    ngx_http_waf_jp_init(&jp, payload, pool);

    if (ngx_http_waf_jp_object(&jp) != NGX_OK) {
        goto invalid;
    }

    v = 0;

    for ( ;; ) {
        rc = ngx_http_waf_jp_member(&jp, &key);

        if (rc == NGX_DONE) {
            break;
        }

        if (rc != NGX_OK) {
            goto invalid;
        }

        if (key.len == 1 && key.data[0] == 'v') {
            if (ngx_http_waf_jp_int(&jp, &v) != NGX_OK) {
                goto invalid;
            }

            continue;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "set", 3) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK) {
                goto invalid;
            }

            if (value.len != ds->name.len
                || ngx_memcmp(value.data, ds->name.data, value.len) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "waf: dataset message names \"%V\", expected "
                              "\"%V\"", &value, &ds->name);
                return NGX_ERROR;
            }

            continue;
        }

        if (key.len == 2 && ngx_strncmp(key.data, "op", 2) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK) {
                goto invalid;
            }

            if (value.len == 4 && ngx_strncmp(value.data, "diff", 4) == 0) {
                n->op = NGX_HTTP_WAF_DS_OP_DIFF;

            } else if (value.len == 4
                       && ngx_strncmp(value.data, "tick", 4) == 0)
            {
                n->op = NGX_HTTP_WAF_DS_OP_TICK;

            } else if (value.len == 8
                       && ngx_strncmp(value.data, "snapshot", 8) == 0)
            {
                n->op = NGX_HTTP_WAF_DS_OP_SNAPSHOT;

            } else {
                n->op = NGX_HTTP_WAF_DS_OP_OTHER;
            }

            if (ngx_http_waf_ds_copy(pool, &value, &n->reply) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "seq", 3) == 0) {
            if (ngx_http_waf_jp_int(&jp, &num) != NGX_OK || num < 0) {
                goto invalid;
            }

            n->seq = (uint64_t) num;
            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "count", 5) == 0) {
            if (ngx_http_waf_jp_int(&jp, &num) != NGX_OK || num < 0) {
                goto invalid;
            }

            n->count = (ngx_uint_t) num;
            continue;
        }

        if (key.len == 3 && ngx_strncmp(key.data, "ttl", 3) == 0) {
            if (ngx_http_waf_jp_int(&jp, &num) != NGX_OK || num < 0) {
                goto invalid;
            }

            n->ttl = (ngx_uint_t) num;
            continue;
        }

        if (key.len == 5 && ngx_strncmp(key.data, "epoch", 5) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK
                || ngx_http_waf_ds_hex64(&value, &n->epoch) != NGX_OK)
            {
                goto invalid;
            }

            continue;
        }

        if (key.len == 4 && ngx_strncmp(key.data, "hash", 4) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK
                || ngx_http_waf_ds_hex64(&value, &n->hash) != NGX_OK)
            {
                goto invalid;
            }

            n->has_hash = (value.len != 0);
            continue;
        }

        if (key.len == 7 && ngx_strncmp(key.data, "package", 7) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK
                || ngx_http_waf_ds_copy(pool, &value, &n->package) != NGX_OK)
            {
                goto invalid;
            }

            continue;
        }

        if (key.len == 6 && ngx_strncmp(key.data, "object", 6) == 0) {
            if (ngx_http_waf_jp_string(&jp, &value) != NGX_OK
                || ngx_http_waf_ds_copy(pool, &value, &n->object) != NGX_OK)
            {
                goto invalid;
            }

            continue;
        }

        if (ngx_http_waf_jp_skip(&jp) != NGX_OK) {
            goto invalid;
        }
    }

    if (v != NGX_HTTP_WAF_DATASET_VERSION) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: unsupported dataset message version %i", v);
        return NGX_ERROR;
    }

    return NGX_OK;

invalid:

    /*
     * Начало сообщения в логе -- единственный способ отличить ошибку поставщика
     * от чужого сообщения в потоке, не включая trace на шине. Экранирование
     * обязательно: это недоверенные байты, а лог читают глазами и грепом.
     */
    len  = ngx_min(payload->len, 96);
    last = head + ngx_escape_json(head, payload->data, len);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "waf: malformed dataset message at %uz of %uz: %s: \"%*s\"",
                  (size_t) (jp.pos - payload->data), payload->len,
                  jp.error ? jp.error : "unexpected end",
                  (size_t) (last - head), head);

    return NGX_ERROR;
}



static ngx_int_t
ngx_http_waf_ds_entry_cidr(ngx_str_t *text, ngx_http_waf_ds_update_t *up,
    uint64_t h)
{
    ngx_int_t              rc;
    ngx_cidr_t             cidr;
    ngx_http_waf_ds_r4_t  *r4;

    rc = ngx_ptocidr(text, &cidr);

    /*
     * NGX_DONE означает, что за префиксом были значащие биты; ngx_ptocidr их уже
     * обнулил. Это ошибка поставщика, но не повод отвергать весь снапшот:
     * "10.0.0.1/24" однозначно значит сеть 10.0.0.0/24.
     */
    if (rc != NGX_OK && rc != NGX_DONE) {
        return NGX_ERROR;
    }

    if (cidr.family == AF_INET) {
        r4 = ngx_array_push(up->r4);
        if (r4 == NULL) {
            return NGX_ERROR;
        }

        r4->start = ntohl(cidr.u.in.addr);
        r4->end   = r4->start | ~ntohl(cidr.u.in.mask);
        r4->h     = h;

        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (cidr.family == AF_INET6) {
        ngx_uint_t             i;
        ngx_http_waf_ds_r6_t  *r6;

        r6 = ngx_array_push(up->r6);
        if (r6 == NULL) {
            return NGX_ERROR;
        }

        for (i = 0; i < 16; i++) {
            r6->start[i] = cidr.u.in6.addr.s6_addr[i];
            r6->end[i]   = (u_char) (r6->start[i]
                                     | ~cidr.u.in6.mask.s6_addr[i]);
        }

        r6->h = h;

        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


static void
ngx_http_waf_ds_sort_uniq(ngx_array_t *a,
    int (ngx_libc_cdecl *cmp)(const void *, const void *))
{
    u_char      *elts;
    size_t       size;
    ngx_uint_t   i, n;

    if (a->nelts < 2) {
        return;
    }

    elts = a->elts;
    size = a->size;

    ngx_qsort(elts, a->nelts, size, cmp);

    /*
     * Дубликаты убираются здесь, а не при построении представления: набор с
     * повторами дал бы неверное число записей, а по нему проверяется max=.
     */
    n = 1;

    for (i = 1; i < a->nelts; i++) {

        if (cmp(elts + (n - 1) * size, elts + i * size) == 0) {
            continue;
        }

        if (n != i) {
            ngx_memcpy(elts + n * size, elts + i * size, size);
        }

        n++;
    }

    a->nelts = n;
}


/* --- построение представлений в зоне -------------------------------------- */

/*
 * Набор выделяется одним куском: заголовок и все массивы внутри. Освобождение
 * отставленного набора после этого -- один ngx_slab_free, то есть операция, в
 * которой нечему пойти не так наполовину.
 */
static void *
ngx_http_waf_ds_build_cidr(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_update_t *up)
{
    u_char                   *p;
    size_t                    size;
    uint32_t                  cover;
    ngx_uint_t                i, n4, n6;
    ngx_http_waf_ds_r4_t     *r4;
    ngx_http_waf_ds_r6_t     *r6;
    ngx_http_waf_cidr_set_t  *set;

    n4 = up->r4->nelts;
    n6 = up->r6->nelts;
    r4 = up->r4->elts;
    r6 = up->r6->elts;

    size = ngx_align(sizeof(ngx_http_waf_cidr_set_t), sizeof(uint64_t))
           + ngx_align(n4 * 3 * sizeof(uint32_t), sizeof(uint64_t))
           + n6 * 3 * 16
           + (n4 + n6) * sizeof(uint64_t);

    set = ngx_slab_calloc_locked(shm->shpool, size);
    if (set == NULL) {
        return NULL;
    }

    set->h.entries = n4 + n6;
    set->h.size    = size;

    p = (u_char *) set
        + ngx_align(sizeof(ngx_http_waf_cidr_set_t), sizeof(uint64_t));

    set->v4_start = (uint32_t *) p;  p += n4 * sizeof(uint32_t);
    set->v4_end   = (uint32_t *) p;  p += n4 * sizeof(uint32_t);
    set->v4_cover = (uint32_t *) p;  p += n4 * sizeof(uint32_t);

    p = (u_char *) set
        + ngx_align(sizeof(ngx_http_waf_cidr_set_t), sizeof(uint64_t))
        + ngx_align(n4 * 3 * sizeof(uint32_t), sizeof(uint64_t));

    set->v4_h     = (uint64_t *) p;  p += n4 * sizeof(uint64_t);
    set->v6_h     = (uint64_t *) p;  p += n6 * sizeof(uint64_t);

    set->v6_start = p;               p += n6 * 16;
    set->v6_end   = p;               p += n6 * 16;
    set->v6_cover = p;

    set->n4 = n4;
    set->n6 = n6;

    cover = 0;

    for (i = 0; i < n4; i++) {
        set->v4_start[i] = r4[i].start;
        set->v4_end[i]   = r4[i].end;
        set->v4_h[i]     = r4[i].h;
        set->h.hash     ^= r4[i].h;

        if (i == 0 || r4[i].end > cover) {
            cover = r4[i].end;
        }

        set->v4_cover[i] = cover;
    }

    for (i = 0; i < n6; i++) {
        ngx_memcpy(set->v6_start + i * 16, r6[i].start, 16);
        ngx_memcpy(set->v6_end + i * 16, r6[i].end, 16);
        set->v6_h[i]  = r6[i].h;
        set->h.hash  ^= r6[i].h;

        if (i == 0 || ngx_memcmp(r6[i].end, set->v6_cover + (i - 1) * 16, 16)
                          > 0)
        {
            ngx_memcpy(set->v6_cover + i * 16, r6[i].end, 16);

        } else {
            ngx_memcpy(set->v6_cover + i * 16, set->v6_cover + (i - 1) * 16,
                       16);
        }
    }

    return set;
}


static void *
ngx_http_waf_ds_build_str(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_update_t *up)
{
    u_char                  *p;
    size_t                   size, blob_len;
    ngx_str_t               *items;
    ngx_uint_t               i, n, slot, table;
    ngx_http_waf_str_set_t  *set;

    items = up->str->elts;
    n     = up->str->nelts;

    /*
     * Заполнение таблицы наполовину -- обычный компромисс открытой адресации:
     * при большей плотности длина пробы растёт нелинейно, при меньшей растёт
     * расход зоны, а таблица здесь неизменяема и рехеширования не будет.
     */
    table = 8;

    while (table < n * 2) {
        table *= 2;
    }

    blob_len = 0;

    for (i = 0; i < n; i++) {

        if (items[i].len > NGX_HTTP_WAF_DS_ENTRY_MAX) {
            return NULL;
        }

        blob_len += 2 + items[i].len;
    }

    size = ngx_align(sizeof(ngx_http_waf_str_set_t), sizeof(uint32_t))
           + table * sizeof(uint32_t)
           + blob_len;

    set = ngx_slab_calloc_locked(shm->shpool, size);
    if (set == NULL) {
        return NULL;
    }

    set->h.size  = size;
    set->mask    = table - 1;

    p = (u_char *) set
        + ngx_align(sizeof(ngx_http_waf_str_set_t), sizeof(uint32_t));

    set->table = (uint32_t *) p;  p += table * sizeof(uint32_t);
    set->blob  = p;

    for (i = 0; i < n; i++) {
        *p++ = (u_char) (items[i].len >> 8);
        *p++ = (u_char) (items[i].len & 0xff);

        ngx_memcpy(p, items[i].data, items[i].len);

        set->h.hash ^= ngx_http_waf_ds_siphash(up->key, items[i].data,
                                               items[i].len);

        /*
         * Смещение хранится увеличенным на единицу: ноль занят под "ячейка
         * пуста", а нулевое смещение -- это первая запись blob.
         */
        (void) ngx_http_waf_ds_str_probe(set, p, items[i].len, &slot);

        set->table[slot] = (uint32_t) (p - 2 - set->blob) + 1;

        p += items[i].len;
    }

    set->blob_len  = blob_len;
    set->h.entries = n;

    return set;
}


/* --- сравнение записей ---------------------------------------------------- */

/*
 * Порядок для CIDR: начало по возрастанию, конец по убыванию. Вложенные
 * префиксы при таком порядке идут строго после объемлющего, и префиксный
 * максимум конца становится ответом на вопрос "покрыт ли адрес".
 */
static int ngx_libc_cdecl
ngx_http_waf_ds_cmp_r4(const void *a, const void *b)
{
    const ngx_http_waf_ds_r4_t  *x = a, *y = b;

    if (x->start != y->start) {
        return (x->start < y->start) ? -1 : 1;
    }

    if (x->end != y->end) {
        return (x->end > y->end) ? -1 : 1;
    }

    return 0;
}


static int ngx_libc_cdecl
ngx_http_waf_ds_cmp_r6(const void *a, const void *b)
{
    int                          rc;
    const ngx_http_waf_ds_r6_t  *x = a, *y = b;

    rc = ngx_memcmp(x->start, y->start, 16);

    if (rc != 0) {
        return rc;
    }

    return -ngx_memcmp(x->end, y->end, 16);
}


static int ngx_libc_cdecl
ngx_http_waf_ds_cmp_str(const void *a, const void *b)
{
    const ngx_str_t  *x = a, *y = b;

    return ngx_memn2cmp(x->data, y->data, x->len, y->len);
}
