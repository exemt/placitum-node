#include <ngx_md5.h>

#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_DS_SYNC_WAIT     5000
#define NGX_HTTP_WAF_DS_READERS_SPIN  4096


typedef struct {
    uint32_t                  start;
    uint32_t                  end;
} ngx_http_waf_ds_r4_t;


typedef struct {
    u_char                    start[16];
    u_char                    end[16];
} ngx_http_waf_ds_r6_t;


static ngx_uint_t ngx_http_waf_ds_arg_option(ngx_str_t *arg);
static ngx_int_t ngx_http_waf_ds_add_entry(ngx_conf_t *cf,
    ngx_http_waf_dataset_t *ds, ngx_str_t *text);

static void ngx_http_waf_ds_slot_reset(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot);
static ngx_int_t ngx_http_waf_ds_build(ngx_http_waf_shm_t *shm,
    ngx_http_waf_dataset_t *ds, ngx_log_t *log, void **out);
static ngx_int_t ngx_http_waf_ds_entry_cidr(ngx_str_t *text, ngx_array_t *r4,
    ngx_array_t *r6);
static void ngx_http_waf_ds_sort_uniq(ngx_array_t *a,
    int (ngx_libc_cdecl *cmp)(const void *, const void *));
static void *ngx_http_waf_ds_build_cidr(ngx_http_waf_shm_t *shm,
    ngx_array_t *r4, ngx_array_t *r6);
static void *ngx_http_waf_ds_build_str(ngx_http_waf_shm_t *shm,
    ngx_array_t *str);

static void ngx_http_waf_ds_publish(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, void *set);
static void *ngx_http_waf_ds_acquire(ngx_http_waf_ds_slot_t *slot);
static void ngx_http_waf_ds_release(ngx_http_waf_ds_slot_t *slot);

static ngx_uint_t ngx_http_waf_ds_lookup_cidr(ngx_http_waf_cidr_set_t *set,
    ngx_uint_t fam, u_char *addr);
static ngx_uint_t ngx_http_waf_ds_str_probe(ngx_http_waf_str_set_t *set,
    u_char *data, size_t len, ngx_uint_t *slot);

static uint64_t ngx_http_waf_ds_siphash(const u_char *key, const u_char *data,
    size_t len);
static uint64_t ngx_http_waf_ds_le64(const u_char *p);
static ngx_int_t ngx_http_waf_ds_hex(ngx_str_t *text, u_char *out, size_t n);
static ngx_int_t ngx_http_waf_ds_hex64(ngx_str_t *text, uint64_t *out);

static int ngx_libc_cdecl ngx_http_waf_ds_cmp_r4(const void *a, const void *b);
static int ngx_libc_cdecl ngx_http_waf_ds_cmp_r6(const void *a, const void *b);
static int ngx_libc_cdecl ngx_http_waf_ds_cmp_str(const void *a,
    const void *b);


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



ngx_int_t
ngx_http_waf_dataset_init_zone(ngx_http_waf_shm_conf_t *scf, ngx_log_t *log)
{
    void                      *sets[NGX_HTTP_WAF_MAX_DATASETS];
    u_char                     taken[NGX_HTTP_WAF_MAX_DATASETS];
    u_char                     reset[NGX_HTTP_WAF_MAX_DATASETS];
    u_char                     freed[NGX_HTTP_WAF_MAX_DATASETS];
    ngx_int_t                  rc;
    ngx_uint_t                 i, j, n, gen, best;
    ngx_uint_t                 slots[NGX_HTTP_WAF_MAX_DATASETS];
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_main_conf_t  *wmcf;

    shm  = scf->shm;
    wmcf = scf->wmcf;

    ds = (wmcf->datasets != NULL) ? wmcf->datasets->elts : NULL;
    n  = (wmcf->datasets != NULL) ? wmcf->datasets->nelts : 0;

    ngx_memzero(sets, sizeof(sets));
    ngx_memzero(taken, sizeof(taken));
    ngx_memzero(reset, sizeof(reset));
    ngx_memzero(freed, sizeof(freed));

    rc = NGX_OK;

    ngx_shmtx_lock(&shm->shpool->mutex);

    gen = ++shm->ds_gen;
    scf->gen = gen;

    for (i = 0; i < n; i++) {
        slots[i] = NGX_HTTP_WAF_MAX_DATASETS;

        for (j = 0; j < NGX_HTTP_WAF_MAX_DATASETS; j++) {
            slot = &shm->datasets[j];

            if (!slot->bound
                || slot->name_len != ds[i].name.len
                || ngx_memcmp(slot->name, ds[i].name.data, ds[i].name.len)
                   != 0)
            {
                continue;
            }

            slots[i] = j;
            taken[j] = 1;

            if (slot->type != ds[i].type
                || (slot->mode == NGX_HTTP_WAF_DS_MODE_ACTIVE
                    && ds[i].mode == NGX_HTTP_WAF_DS_MODE_INTERNAL))
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                              "waf: dataset \"%V\" changed type or mode, its "
                              "data is dropped", &ds[i].name);
                reset[j] = 1;
            }

            break;
        }
    }

    /*
     * a slot is released only when the running workers do not name it:
     * they committed a generation newer than its last declaration
     */

    for (j = 0; j < NGX_HTTP_WAF_MAX_DATASETS; j++) {
        slot = &shm->datasets[j];

        if (slot->bound && !taken[j] && slot->gen < shm->ds_committed) {
            slot->bound    = 0;
            slot->released = gen;
            reset[j] = 1;
            freed[j] = 1;
        }
    }

    for (i = 0; i < n; i++) {

        if (slots[i] != NGX_HTTP_WAF_MAX_DATASETS) {
            continue;
        }

        best = NGX_HTTP_WAF_MAX_DATASETS;

        for (j = 0; j < NGX_HTTP_WAF_MAX_DATASETS; j++) {
            slot = &shm->datasets[j];

            if (slot->bound || taken[j]) {
                continue;
            }

            if (best == NGX_HTTP_WAF_MAX_DATASETS
                || slot->released < shm->datasets[best].released)
            {
                best = j;
            }
        }

        if (best == NGX_HTTP_WAF_MAX_DATASETS) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "waf: no free dataset slot for \"%V\": the running "
                          "configuration holds the others, restart nginx to "
                          "switch to this set of datasets", &ds[i].name);
            rc = NGX_ERROR;
            break;
        }

        slots[i] = best;
        taken[best] = 1;
        reset[best] = 1;
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    for (j = 0; j < NGX_HTTP_WAF_MAX_DATASETS; j++) {

        if (!reset[j]) {
            continue;
        }

        slot = &shm->datasets[j];

        if (freed[j]) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "waf: dataset \"%*s\" is no longer declared, its "
                          "slot and data are released",
                          (size_t) slot->name_len, slot->name);
        }

        ngx_http_waf_ds_slot_reset(shm, slot);
    }

    if (rc != NGX_OK) {
        return rc;
    }

    for (i = 0; i < n; i++) {

        if (ds[i].mode != NGX_HTTP_WAF_DS_MODE_INTERNAL) {
            continue;
        }

        if (ngx_http_waf_ds_build(shm, &ds[i], log, &sets[i]) != NGX_OK) {
            rc = NGX_ERROR;
            break;
        }
    }

    ngx_shmtx_lock(&shm->shpool->mutex);

    if (rc != NGX_OK) {

        for (i = 0; i < n; i++) {
            if (sets[i] != NULL) {
                ngx_slab_free_locked(shm->shpool, sets[i]);
            }
        }

        ngx_shmtx_unlock(&shm->shpool->mutex);

        return rc;
    }

    for (i = 0; i < n; i++) {
        slot = &shm->datasets[slots[i]];

        if (!slot->bound) {
            ngx_memcpy(slot->name, ds[i].name.data, ds[i].name.len);
            slot->name_len = ds[i].name.len;
            slot->bound    = 1;
        }

        if (slot->mode != ds[i].mode) {
            slot->seq   = 0;
            slot->epoch = 0;
        }

        slot->type     = ds[i].type;
        slot->mode     = ds[i].mode;
        slot->live_max = ds[i].live_max;
        slot->gen      = gen;

        if (ds[i].mode == NGX_HTTP_WAF_DS_MODE_INTERNAL) {
            ngx_http_waf_ds_publish(shm, slot, sets[i]);
            slot->seq = (sets[i] != NULL) ? 1 : 0;

        } else if (slot->set != NULL) {
            ngx_http_waf_ds_publish(shm, slot, NULL);
        }

        ds[i].index = slots[i];
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_dataset_bind(ngx_cycle_t *cycle)
{
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_shm_conf_t   *scf;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->shm_zone == NULL) {
        return NGX_OK;
    }

    scf = wmcf->shm_zone->data;
    shm = scf->shm;

    if (shm == NULL) {
        return NGX_OK;
    }

    ngx_shmtx_lock(&shm->shpool->mutex);

    if (scf->gen > shm->ds_committed) {
        shm->ds_committed = scf->gen;
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_OK;
}


static void
ngx_http_waf_ds_slot_reset(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot)
{
    ngx_uint_t  n;

    for (n = 0; slot->syncing && n < NGX_HTTP_WAF_DS_SYNC_WAIT; n++) {
        ngx_msleep(1);
    }

    ngx_http_waf_ds_live_reset(shm, slot);

    ngx_rwlock_wlock(&slot->lock);

    slot->seq         = 0;
    slot->epoch       = 0;
    slot->live_hash   = 0;
    slot->seen        = 0;
    slot->snapshot_at = 0;
    slot->silent      = 0;
    slot->syncing     = 0;
    slot->snap_bad    = 0;

    ngx_memzero(slot->key, sizeof(slot->key));

    ngx_rwlock_unlock(&slot->lock);

    ngx_shmtx_lock(&shm->shpool->mutex);
    ngx_http_waf_ds_publish(shm, slot, NULL);
    ngx_shmtx_unlock(&shm->shpool->mutex);
}


static ngx_int_t
ngx_http_waf_ds_build(ngx_http_waf_shm_t *shm, ngx_http_waf_dataset_t *ds,
    ngx_log_t *log, void **out)
{
    void         *set;
    ngx_uint_t    i, entries;
    ngx_pool_t   *pool;
    ngx_str_t    *items, *item;
    ngx_array_t  *r4, *r6, *str;

    *out = NULL;

    if (ds->entries == NULL || ds->entries->nelts == 0) {
        return NGX_OK;
    }

    pool = ngx_create_pool(4096, log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    items = ds->entries->elts;

    r4  = NULL;
    r6  = NULL;
    str = NULL;

    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        r4 = ngx_array_create(pool, ds->entries->nelts,
                              sizeof(ngx_http_waf_ds_r4_t));
        r6 = ngx_array_create(pool, 4, sizeof(ngx_http_waf_ds_r6_t));

        if (r4 == NULL || r6 == NULL) {
            goto failed;
        }

        for (i = 0; i < ds->entries->nelts; i++) {
            if (ngx_http_waf_ds_entry_cidr(&items[i], r4, r6) != NGX_OK) {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "waf: dataset \"%V\" has an invalid network "
                              "\"%V\"", &ds->name, &items[i]);
                goto failed;
            }
        }

        ngx_http_waf_ds_sort_uniq(r4, ngx_http_waf_ds_cmp_r4);
        ngx_http_waf_ds_sort_uniq(r6, ngx_http_waf_ds_cmp_r6);

        entries = r4->nelts + r6->nelts;
        set = ngx_http_waf_ds_build_cidr(shm, r4, r6);

    } else {
        str = ngx_array_create(pool, ds->entries->nelts, sizeof(ngx_str_t));
        if (str == NULL) {
            goto failed;
        }

        for (i = 0; i < ds->entries->nelts; i++) {
            item = ngx_array_push(str);
            if (item == NULL) {
                goto failed;
            }

            *item = items[i];
        }

        ngx_http_waf_ds_sort_uniq(str, ngx_http_waf_ds_cmp_str);

        entries = str->nelts;
        set = ngx_http_waf_ds_build_str(shm, str);
    }

    if (set == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "waf: no room in the zone for dataset \"%V\"",
                      &ds->name);
        goto failed;
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "waf: dataset \"%V\" loaded %ui internal entries",
                  &ds->name, entries);

    ngx_destroy_pool(pool);

    *out = set;

    return NGX_OK;

failed:

    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


static void
ngx_http_waf_ds_publish(ngx_http_waf_shm_t *shm, ngx_http_waf_ds_slot_t *slot,
    void *set)
{
    void        *old;
    ngx_uint_t   i, n;

    old = slot->set;

    if (old == set) {
        return;
    }

    slot->set = set;

    ngx_memory_barrier();

    if (old != NULL) {

        for (i = 0; i < NGX_HTTP_WAF_DS_RETIRED; i++) {
            if (slot->retired[i] == NULL) {
                slot->retired[i] = old;
                old = NULL;
                break;
            }
        }
    }

    /*
     * readers count themselves before they load slot->set: once the count is
     * seen at zero after the swap, nobody holds an unpublished set
     */

    for (n = 0; slot->readers != 0 && n < NGX_HTTP_WAF_DS_READERS_SPIN; n++) {
        ngx_cpu_pause();
    }

    if (slot->readers != 0) {

        if (old != NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "waf: dataset \"%*s\" leaked a retired set: all %d "
                          "retire slots are busy", (size_t) slot->name_len,
                          slot->name, NGX_HTTP_WAF_DS_RETIRED);
        }

        return;
    }

    if (old != NULL) {
        ngx_slab_free_locked(shm->shpool, old);
    }

    for (i = 0; i < NGX_HTTP_WAF_DS_RETIRED; i++) {
        if (slot->retired[i] != NULL) {
            ngx_slab_free_locked(shm->shpool, slot->retired[i]);
            slot->retired[i] = NULL;
        }
    }
}


static void *
ngx_http_waf_ds_acquire(ngx_http_waf_ds_slot_t *slot)
{
    void  *set;

    (void) ngx_atomic_fetch_add(&slot->readers, 1);

    ngx_memory_barrier();

    set = slot->set;

    if (set == NULL) {
        (void) ngx_atomic_fetch_add(&slot->readers, -1);
    }

    return set;
}


static void
ngx_http_waf_ds_release(ngx_http_waf_ds_slot_t *slot)
{
    (void) ngx_atomic_fetch_add(&slot->readers, -1);
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


ngx_uint_t
ngx_http_waf_dataset_hit(ngx_http_waf_dataset_t *ds, ngx_str_t *value,
    ngx_uint_t binary)
{
    void                    *set;
    u_char                   addr[16];
    u_char                   hex[NGX_HTTP_WAF_MD5_HEX_LEN];
    ngx_str_t                hashed;
    ngx_uint_t               hit, fam, pos;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_set_t      *h;
    ngx_http_waf_ds_slot_t  *slot;

    if (value->len == 0) {
        return 0;
    }

    fam = 0;

    shm = ngx_http_waf_shm();

    if (shm == NULL || ds->index >= NGX_HTTP_WAF_MAX_DATASETS) {
        return 0;
    }

    slot = &shm->datasets[ds->index];

    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {

        if (ngx_http_waf_ds_addr(value, binary, &fam, addr) != NGX_OK) {
            return 0;
        }

        if (ds->mode != NGX_HTTP_WAF_DS_MODE_INTERNAL) {
            return ngx_http_waf_ds_live_probe(slot, fam, addr);
        }

    } else {

        if (ds->hash == NGX_HTTP_WAF_DS_HASH_MD5) {
            ngx_http_waf_md5_hex(value, hex);
            hashed.data = hex;
            hashed.len = NGX_HTTP_WAF_MD5_HEX_LEN;
            value = &hashed;
        }

        if (ds->mode != NGX_HTTP_WAF_DS_MODE_INTERNAL) {
            return ngx_http_waf_ds_live_hit(slot, value);
        }
    }

    set = ngx_http_waf_ds_acquire(slot);

    if (set == NULL) {
        return 0;
    }

    h = set;

    if (h->type != ds->type) {
        hit = 0;

    } else if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        hit = ngx_http_waf_ds_lookup_cidr(set, fam, addr);

    } else {
        hit = (h->entries != 0
               && ngx_http_waf_ds_str_probe(set, value->data, value->len,
                                            &pos));
    }

    ngx_http_waf_ds_release(slot);

    return hit;
}


void
ngx_http_waf_md5_hex(ngx_str_t *in, u_char *out)
{
    u_char     digest[16];
    ngx_md5_t  md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, in->data, in->len);
    ngx_md5_final(digest, &md5);

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

    for (i = 0; i < wlcf->local_checks->nelts; i++) {
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


static ngx_uint_t
ngx_http_waf_ds_lookup_cidr(ngx_http_waf_cidr_set_t *set, ngx_uint_t fam,
    u_char *addr)
{
    uint32_t    a;
    ngx_uint_t  lo, hi, mid;

    if (fam == 1) {
        goto v6;
    }

    if (set->n4 == 0) {
        return 0;
    }

    a = ((uint32_t) addr[0] << 24) | ((uint32_t) addr[1] << 16)
        | ((uint32_t) addr[2] << 8) | (uint32_t) addr[3];

    lo = 0;
    hi = set->n4;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;

        if (set->v4_start[mid] <= a) {
            lo = mid + 1;

        } else {
            hi = mid;
        }
    }

    if (lo == 0) {
        return 0;
    }

    return set->v4_cover[lo - 1] >= a;

v6:

    if (set->n6 == 0) {
        return 0;
    }

    lo = 0;
    hi = set->n6;

    while (lo < hi) {
        mid = lo + (hi - lo) / 2;

        if (ngx_memcmp(set->v6_start + mid * 16, addr, 16) <= 0) {
            lo = mid + 1;

        } else {
            hi = mid;
        }
    }

    if (lo == 0) {
        return 0;
    }

    return ngx_memcmp(set->v6_cover + (lo - 1) * 16, addr, 16) >= 0;
}


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


#define NGX_HTTP_WAF_PACK_HEADER    52
#define NGX_HTTP_WAF_PACK_SNAPSHOT  1
#define NGX_HTTP_WAF_PACK_PACKAGE   2
#define NGX_HTTP_WAF_PACK_CIDR      1
#define NGX_HTTP_WAF_PACK_STRING    2
#define NGX_HTTP_WAF_PACK_REASONS   1
#define NGX_HTTP_WAF_PACK_ADD       1
#define NGX_HTTP_WAF_PACK_REMOVE    2

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

        if (p[1] > n * 8 || p + 2 + n + 8 > cur->last) {
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
ngx_http_waf_ds_locate(ngx_uint_t index, ngx_http_waf_shm_t **shm,
    ngx_http_waf_dataset_t **ds, ngx_http_waf_ds_slot_t **slot)
{
    ngx_http_waf_main_conf_t  *wmcf;

    *shm = ngx_http_waf_shm();
    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (*shm == NULL || wmcf == NULL || wmcf->datasets == NULL
        || index >= wmcf->datasets->nelts)
    {
        return NGX_ERROR;
    }

    *ds = &((ngx_http_waf_dataset_t *) wmcf->datasets->elts)[index];

    if ((*ds)->index >= NGX_HTTP_WAF_MAX_DATASETS) {
        return NGX_ERROR;
    }

    *slot = &(*shm)->datasets[(*ds)->index];

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


ngx_int_t
ngx_http_waf_dataset_apply_package(ngx_uint_t index, ngx_str_t *data)
{
    int64_t                    exp, now_ms;
    uint64_t                   have, h, epoch;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    uint32_t                   gen;
    ngx_uint_t                 op, k, n, lost;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_ds_pack_t     head;
    ngx_http_waf_ds_cursor_t   cur, scan;

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
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

    scan = cur;
    n = 0;

    while ((rc = ngx_http_waf_ds_pack_next(&scan, &op, &key, &exp)) == NGX_OK)
    {
        n++;
    }

    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": package seq %uL is truncated "
                      "after %ui records, nothing applied", &ds->name,
                      head.seq, n);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    now_ms = ngx_http_waf_ds_now_ms();

    ngx_rwlock_wlock(&slot->lock);

    epoch = slot->epoch;

    if (epoch == 0 || head.epoch != epoch) {
        ngx_rwlock_unlock(&slot->lock);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" got package of epoch %016xL, have "
                      "%016xL, snapshot required", &ds->name, head.epoch,
                      epoch);
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

    slot->syncing = 1;
    gen = ngx_http_waf_ds_live_gen(slot);

    ngx_rwlock_unlock(&slot->lock);

    have = 0;
    lost = 0;
    rc   = NGX_OK;

    while (rc == NGX_OK) {

        ngx_rwlock_wlock(&slot->lock);

        for (k = 0; k < NGX_HTTP_WAF_DS_BATCH; k++) {
            rc = ngx_http_waf_ds_pack_next(&cur, &op, &key, &exp);

            if (rc != NGX_OK) {
                break;
            }

            if (op == NGX_HTTP_WAF_PACK_REMOVE) {
                (void) ngx_http_waf_ds_live_drop(shm, slot, &key);
                continue;
            }

            if (op != NGX_HTTP_WAF_PACK_ADD) {
                continue;
            }

            h = ngx_http_waf_ds_siphash(slot->key, key.data, key.len);

            rc = ngx_http_waf_ds_live_put(shm, slot, &key,
                                          ngx_http_waf_ds_expires(exp, now_ms),
                                          h, gen);

            if (rc == NGX_ERROR || rc == NGX_BUSY) {
                lost++;
            }

            rc = NGX_OK;
        }

        if (rc != NGX_OK) {
            slot->seq     = head.seq;
            slot->syncing = 0;
            have          = slot->live_hash;
        }

        ngx_rwlock_unlock(&slot->lock);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "waf: dataset \"%V\" applied package seq %uL, %ui records",
                   &ds->name, head.seq, n);

    if (lost != 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": %ui of %ui records of package seq "
                      "%uL did not fit", &ds->name, lost, n, head.seq);
    }

    if (have != head.hash) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" diverged at package seq %uL: want "
                      "%016xL, got %016xL", &ds->name, head.seq, head.hash,
                      have);
        return NGX_HTTP_WAF_DS_DIVERGED;
    }

    return NGX_HTTP_WAF_DS_APPLIED;
}


ngx_int_t
ngx_http_waf_dataset_apply_snapshot(ngx_uint_t index, ngx_str_t *data)
{
    int64_t                    exp, now_ms;
    uint64_t                   have, h, seq;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    uint32_t                   gen;
    ngx_uint_t                 op, n, k, adds, cap, lost, swept, entries;
    ngx_rbtree_node_t         *cursor;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_ds_pack_t     head;
    ngx_http_waf_ds_cursor_t   start, cur;

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    if (ngx_http_waf_ds_pack_head(data, &head, &start) != NGX_OK
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

    cur  = start;
    n    = 0;
    adds = 0;

    while ((rc = ngx_http_waf_ds_pack_next(&cur, &op, &key, &exp)) == NGX_OK) {
        n++;

        if (op == NGX_HTTP_WAF_PACK_ADD) {
            adds++;
        }
    }

    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\": snapshot object is truncated after "
                      "%ui of %ui records, nothing applied", &ds->name, n,
                      head.count);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    cap = (slot->live_max != 0) ? slot->live_max : NGX_HTTP_WAF_DS_LIVE_MAX;
    cap = ngx_min(cap, ds->max);

    if (head.count > cap || adds > cap) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" snapshot rejected: %ui entries "
                      "exceed the limit of %ui, the current entries stay",
                      &ds->name, ngx_max(head.count, adds), cap);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    now_ms = ngx_http_waf_ds_now_ms();

    ngx_rwlock_wlock(&slot->lock);

    if (slot->syncing) {
        ngx_rwlock_unlock(&slot->lock);
        return NGX_HTTP_WAF_DS_BUSY;
    }

    seq = slot->seq;

    if (slot->epoch != 0 && head.epoch == slot->epoch && head.seq < seq) {
        ngx_rwlock_unlock(&slot->lock);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" dropped a stale snapshot seq %uL, "
                      "have seq %uL", &ds->name, head.seq, seq);
        return NGX_HTTP_WAF_DS_STALE;
    }

    gen = ngx_http_waf_ds_live_begin(shm, slot);

    if (gen == 0) {
        ngx_rwlock_unlock(&slot->lock);

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" snapshot rejected: no room in the "
                      "zone for its overlay", &ds->name);
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    slot->syncing = 1;

    ngx_rwlock_unlock(&slot->lock);

    /* entries the snapshot keeps are marked, the rest leave before it loads */

    cur = start;
    rc  = NGX_OK;

    while (rc == NGX_OK) {

        ngx_rwlock_wlock(&slot->lock);

        for (k = 0; k < NGX_HTTP_WAF_DS_BATCH; k++) {
            rc = ngx_http_waf_ds_pack_next(&cur, &op, &key, &exp);

            if (rc != NGX_OK) {
                break;
            }

            if (op == NGX_HTTP_WAF_PACK_ADD) {
                ngx_http_waf_ds_live_mark(slot, &key, gen);
            }
        }

        ngx_rwlock_unlock(&slot->lock);
    }

    cursor = NULL;
    swept  = 0;

    do {
        ngx_rwlock_wlock(&slot->lock);
        rc = ngx_http_waf_ds_live_sweep(shm, slot, gen, NGX_HTTP_WAF_DS_BATCH,
                                        &cursor, &swept);
        ngx_rwlock_unlock(&slot->lock);
    } while (rc == NGX_AGAIN);

    cur  = start;
    rc   = NGX_OK;
    lost = 0;

    while (rc == NGX_OK) {

        ngx_rwlock_wlock(&slot->lock);

        for (k = 0; k < NGX_HTTP_WAF_DS_BATCH; k++) {
            rc = ngx_http_waf_ds_pack_next(&cur, &op, &key, &exp);

            if (rc != NGX_OK) {
                break;
            }

            if (op != NGX_HTTP_WAF_PACK_ADD) {
                continue;
            }

            h = ngx_http_waf_ds_siphash(head.key, key.data, key.len);

            rc = ngx_http_waf_ds_live_put(shm, slot, &key,
                                          ngx_http_waf_ds_expires(exp, now_ms),
                                          h, gen);

            if (rc == NGX_ERROR || rc == NGX_BUSY) {
                lost++;
            }

            rc = NGX_OK;
        }

        ngx_rwlock_unlock(&slot->lock);
    }

    ngx_rwlock_wlock(&slot->lock);

    slot->epoch   = head.epoch;
    slot->seq     = head.seq;
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
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset \"%V\" snapshot hash mismatch: keeper "
                      "%016xL, built %016xL; divergence within this epoch is "
                      "logged, not resynced", &ds->name, head.hash, have);
        return NGX_HTTP_WAF_DS_DIVERGED;
    }

    return NGX_HTTP_WAF_DS_APPLIED;
}


ngx_int_t
ngx_http_waf_dataset_verify(ngx_uint_t index, uint64_t epoch, uint64_t seq,
    uint64_t hash)
{
    uint64_t                 have, my_seq, my_epoch;
    ngx_uint_t               syncing, bad;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
        return NGX_HTTP_WAF_DS_MALFORMED;
    }

    ngx_rwlock_rlock(&slot->lock);
    my_epoch = slot->epoch;
    my_seq   = slot->seq;
    have     = slot->live_hash;
    syncing  = slot->syncing;
    bad      = slot->snap_bad;
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

    if (bad) {
        ngx_rwlock_wlock(&slot->lock);

        if (slot->epoch == epoch && slot->seq == seq
            && slot->live_hash == hash)
        {
            slot->snap_bad = 0;
        }

        ngx_rwlock_unlock(&slot->lock);
    }

    return NGX_HTTP_WAF_DS_APPLIED;
}


ngx_uint_t
ngx_http_waf_dataset_snap_bad(ngx_uint_t index)
{
    ngx_uint_t               bad;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
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
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    *epoch = 0;
    *seq   = 0;

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
        return;
    }

    ngx_rwlock_rlock(&slot->lock);
    *epoch = slot->epoch;
    *seq   = slot->seq;
    ngx_rwlock_unlock(&slot->lock);
}


ngx_msec_int_t
ngx_http_waf_dataset_seen(ngx_uint_t index, ngx_uint_t touch,
    ngx_msec_t silence, ngx_uint_t *first_silence)
{
    ngx_msec_int_t           age;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (first_silence != NULL) {
        *first_silence = 0;
    }

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
        return 0;
    }

    ngx_shmtx_lock(&shm->shpool->mutex);

    if (touch) {
        slot->seen   = ngx_current_msec;
        slot->silent = 0;
        age = 0;

    } else {
        age = (slot->seen == 0) ? 0
                                : (ngx_msec_int_t) (ngx_current_msec - slot->seen);

        if (first_silence != NULL && !slot->silent
            && age > (ngx_msec_int_t) silence)
        {
            slot->silent   = 1;
            *first_silence = 1;
        }
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return age;
}


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


ngx_int_t
ngx_http_waf_dataset_notice(ngx_uint_t index, ngx_str_t *payload,
    ngx_pool_t *pool, ngx_http_waf_ds_notice_t *n)
{
    u_char                   head[96 * 6 + 1], *last;
    size_t                   len;
    ngx_int_t                rc, v, num;
    ngx_str_t                key, value;
    ngx_http_waf_jp_t        jp;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_dataset_t  *ds;
    ngx_http_waf_ds_slot_t  *slot;

    if (ngx_http_waf_ds_locate(index, &shm, &ds, &slot) != NGX_OK) {
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

    len  = ngx_min(payload->len, 96);
    last = (u_char *) ngx_escape_json(head, payload->data, len);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "waf: malformed dataset message at %uz of %uz: %s: \"%*s\"",
                  (size_t) (jp.pos - payload->data), payload->len,
                  jp.error ? jp.error : "unexpected end",
                  (size_t) (last - head), head);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_waf_ds_entry_cidr(ngx_str_t *text, ngx_array_t *r4, ngx_array_t *r6)
{
    ngx_int_t              rc;
    ngx_cidr_t             cidr;
    ngx_http_waf_ds_r4_t  *e4;

    rc = ngx_ptocidr(text, &cidr);

    if (rc != NGX_OK && rc != NGX_DONE) {
        return NGX_ERROR;
    }

#if (NGX_HAVE_INET6)
    if (cidr.family == AF_INET6) {
        u_char                *a, *m;
        ngx_uint_t             i, mapped;
        ngx_http_waf_ds_r6_t  *e6;

        a = cidr.u.in6.addr.s6_addr;
        m = cidr.u.in6.mask.s6_addr;

        mapped = (a[10] == 0xff && a[11] == 0xff
                  && m[10] == 0xff && m[11] == 0xff);

        for (i = 0; mapped && i < 10; i++) {
            mapped = (a[i] == 0 && m[i] == 0xff);
        }

        if (!mapped) {
            e6 = ngx_array_push(r6);
            if (e6 == NULL) {
                return NGX_ERROR;
            }

            for (i = 0; i < 16; i++) {
                e6->start[i] = a[i];
                e6->end[i]   = (u_char) (a[i] | ~m[i]);
            }

            return NGX_OK;
        }

        e4 = ngx_array_push(r4);
        if (e4 == NULL) {
            return NGX_ERROR;
        }

        e4->start = ((uint32_t) a[12] << 24) | ((uint32_t) a[13] << 16)
                    | ((uint32_t) a[14] << 8) | (uint32_t) a[15];
        e4->end   = e4->start
                    | ~(((uint32_t) m[12] << 24) | ((uint32_t) m[13] << 16)
                        | ((uint32_t) m[14] << 8) | (uint32_t) m[15]);

        return NGX_OK;
    }
#endif

    if (cidr.family != AF_INET) {
        return NGX_ERROR;
    }

    e4 = ngx_array_push(r4);
    if (e4 == NULL) {
        return NGX_ERROR;
    }

    e4->start = ntohl(cidr.u.in.addr);
    e4->end   = e4->start | ~ntohl(cidr.u.in.mask);

    return NGX_OK;
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


static void *
ngx_http_waf_ds_build_cidr(ngx_http_waf_shm_t *shm, ngx_array_t *r4,
    ngx_array_t *r6)
{
    u_char                   *p;
    size_t                    size;
    uint32_t                  cover;
    ngx_uint_t                i, n4, n6;
    ngx_http_waf_ds_r4_t     *e4;
    ngx_http_waf_ds_r6_t     *e6;
    ngx_http_waf_cidr_set_t  *set;

    n4 = r4->nelts;
    n6 = r6->nelts;
    e4 = r4->elts;
    e6 = r6->elts;

    size = ngx_align(sizeof(ngx_http_waf_cidr_set_t), NGX_ALIGNMENT)
           + n4 * 2 * sizeof(uint32_t)
           + n6 * 2 * 16;

    set = ngx_slab_calloc(shm->shpool, size);
    if (set == NULL) {
        return NULL;
    }

    set->h.type    = NGX_HTTP_WAF_DS_CIDR;
    set->h.entries = n4 + n6;

    p = (u_char *) set + ngx_align(sizeof(ngx_http_waf_cidr_set_t),
                                   NGX_ALIGNMENT);

    set->v4_start = (uint32_t *) p;  p += n4 * sizeof(uint32_t);
    set->v4_cover = (uint32_t *) p;  p += n4 * sizeof(uint32_t);
    set->v6_start = p;               p += n6 * 16;
    set->v6_cover = p;

    set->n4 = n4;
    set->n6 = n6;

    cover = 0;

    for (i = 0; i < n4; i++) {
        set->v4_start[i] = e4[i].start;

        if (i == 0 || e4[i].end > cover) {
            cover = e4[i].end;
        }

        set->v4_cover[i] = cover;
    }

    for (i = 0; i < n6; i++) {
        ngx_memcpy(set->v6_start + i * 16, e6[i].start, 16);

        if (i == 0
            || ngx_memcmp(e6[i].end, set->v6_cover + (i - 1) * 16, 16) > 0)
        {
            ngx_memcpy(set->v6_cover + i * 16, e6[i].end, 16);

        } else {
            ngx_memcpy(set->v6_cover + i * 16, set->v6_cover + (i - 1) * 16,
                       16);
        }
    }

    return set;
}


static void *
ngx_http_waf_ds_build_str(ngx_http_waf_shm_t *shm, ngx_array_t *str)
{
    u_char                  *p;
    size_t                   size, blob_len;
    ngx_str_t               *items;
    ngx_uint_t               i, n, slot, table;
    ngx_http_waf_str_set_t  *set;

    items = str->elts;
    n     = str->nelts;

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

    if (blob_len >= 0xffffffff) {
        return NULL;
    }

    size = ngx_align(sizeof(ngx_http_waf_str_set_t), NGX_ALIGNMENT)
           + table * sizeof(uint32_t)
           + blob_len;

    set = ngx_slab_calloc(shm->shpool, size);
    if (set == NULL) {
        return NULL;
    }

    set->h.type = NGX_HTTP_WAF_DS_STRING;
    set->mask   = table - 1;

    p = (u_char *) set + ngx_align(sizeof(ngx_http_waf_str_set_t),
                                   NGX_ALIGNMENT);

    set->table = (uint32_t *) p;  p += table * sizeof(uint32_t);
    set->blob  = p;

    for (i = 0; i < n; i++) {
        *p++ = (u_char) (items[i].len >> 8);
        *p++ = (u_char) (items[i].len & 0xff);

        ngx_memcpy(p, items[i].data, items[i].len);

        (void) ngx_http_waf_ds_str_probe(set, p, items[i].len, &slot);

        set->table[slot] = (uint32_t) (p - 2 - set->blob) + 1;

        p += items[i].len;
    }

    set->h.entries = n;

    return set;
}


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
