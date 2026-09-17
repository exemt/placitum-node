#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_RATE_KEY_MAX   255

#define NGX_HTTP_WAF_RATE_EVICT     16


typedef struct {
    u_char             color;
    u_char             len;
    ngx_queue_t        queue;
    ngx_msec_t         last;
    ngx_uint_t         excess;
    ngx_uint_t         rate;
    uint32_t           sig;
    u_char             data[1];
} ngx_http_waf_rate_node_t;


typedef enum {
    NGX_HTTP_WAF_RATE_PEEK = 0,
    NGX_HTTP_WAF_RATE_GATE,
    NGX_HTTP_WAF_RATE_DEBT
} ngx_http_waf_rate_mode_e;


static ngx_int_t ngx_http_waf_rate_account(ngx_http_waf_shm_conf_t *scf,
    ngx_http_waf_rate_rule_t *rule, ngx_str_t *key, ngx_uint_t mode,
    ngx_uint_t *excess);
static ngx_http_waf_rate_node_t *ngx_http_waf_rate_lookup(
    ngx_http_waf_shm_t *shm, ngx_http_waf_rate_rule_t *rule, ngx_str_t *key,
    uint32_t hash);
static ngx_int_t ngx_http_waf_rate_insert(ngx_http_waf_shm_conf_t *scf,
    ngx_http_waf_rate_rule_t *rule, ngx_str_t *key, uint32_t hash,
    ngx_uint_t excess);
static void ngx_http_waf_rate_expire(ngx_http_waf_shm_t *shm, ngx_uint_t force);
static void ngx_http_waf_rate_free(ngx_http_waf_shm_t *shm,
    ngx_http_waf_rate_node_t *rn);
static size_t ngx_http_waf_rate_charge(size_t len);
static ngx_msec_int_t ngx_http_waf_rate_elapsed(ngx_msec_t now,
    ngx_msec_t last);
static ngx_int_t ngx_http_waf_rate_key(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_rate_rule_t *rule, ngx_str_t *raw, ngx_str_t *key,
    u_char *hex);


static ngx_str_t  ngx_http_waf_rate_rule_name = ngx_string("LOCAL_RATE");


char *
ngx_http_waf_local_rate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    uint32_t                            sig;
    ngx_str_t                          *args, name, value, list_name;
    ngx_uint_t                          i;
    ngx_http_waf_rate_rule_t           *rule;

    args = cf->args->elts;

    if (cf->args->nelts == 2
        && args[1].len == 4 && ngx_strncmp(args[1].data, "none", 4) == 0)
    {
        if (wlcf->local_rates != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_local_rate none cannot mix with "
                               "limits on the same level");
            return NGX_CONF_ERROR;
        }

        wlcf->local_rates = ngx_array_create(cf->pool, 1,
                                          sizeof(ngx_http_waf_rate_rule_t));
        if (wlcf->local_rates == NULL) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (ngx_http_waf_shm_required(cf, "waf_local_rate") != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (wlcf->local_rates == NULL) {
        wlcf->local_rates = ngx_array_create(cf->pool, 2,
                                          sizeof(ngx_http_waf_rate_rule_t));
        if (wlcf->local_rates == NULL) {
            return NGX_CONF_ERROR;
        }

    } else if (wlcf->local_rates->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_local_rate none cannot mix with "
                           "limits on the same level");
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(wlcf->local_rates);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(ngx_http_waf_rate_rule_t));

    rule->count  = NGX_HTTP_WAF_RATE_REQUESTS;
    rule->action = NGX_HTTP_WAF_POLICY_BLOCK;
    ngx_str_null(&list_name);

    if (ngx_http_waf_operand_compile(cf, &args[1], &rule->key, 0,
                                     "waf_local_rate") != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (args[i].len == 2 && ngx_strncmp(args[i].data, "if", 2) == 0) {

            if (ngx_http_waf_cond_parse(cf, &i, &rule->conds,
                                        "waf_local_rate") != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in waf_local_rate",
                               &args[i]);
            return NGX_CONF_ERROR;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "rate", 4) == 0) {
            ngx_int_t   n;
            ngx_uint_t  scale;
            ngx_str_t   digits = value;

            if (digits.len > 3
                && ngx_strncmp(digits.data + digits.len - 3, "r/s", 3) == 0)
            {
                scale = 1;

            } else if (digits.len > 3
                       && ngx_strncmp(digits.data + digits.len - 3, "r/m", 3)
                          == 0)
            {
                scale = 60;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: rate \"%V\" must end with r/s or r/m",
                                   &value);
                return NGX_CONF_ERROR;
            }

            digits.len -= 3;

            n = ngx_atoi(digits.data, digits.len);

            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid rate \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            rule->rate = (ngx_uint_t) n * 1000 / scale;

            if (rule->rate == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: rate \"%V\" rounds down to zero",
                                   &value);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 5 && ngx_strncmp(name.data, "burst", 5) == 0) {
            ngx_int_t  n = ngx_atoi(value.data, value.len);

            if (n == NGX_ERROR || n < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid burst \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            rule->burst = (ngx_uint_t) n * 1000;
            continue;
        }

        if (name.len == 5 && ngx_strncmp(name.data, "count", 5) == 0) {

            if (value.len == 8
                && ngx_strncmp(value.data, "requests", 8) == 0)
            {
                rule->count = NGX_HTTP_WAF_RATE_REQUESTS;

            } else if (value.len == 5
                       && ngx_strncmp(value.data, "waves", 5) == 0)
            {
                rule->count = NGX_HTTP_WAF_RATE_WAVES;

            } else if (value.len == 6
                       && ngx_strncmp(value.data, "frames", 6) == 0)
            {
                rule->count = NGX_HTTP_WAF_RATE_FRAMES;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: count must be requests, waves or "
                                   "frames");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 8 && ngx_strncmp(name.data, "response", 8) == 0) {
            rule->response = value;
            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "hash", 4) == 0) {

            if (value.len == 3 && ngx_strncmp(value.data, "md5", 3) == 0) {
                rule->hash = NGX_HTTP_WAF_DS_HASH_MD5;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: waf_local_rate hash must be md5");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (name.len == 4 && ngx_strncmp(name.data, "list", 4) == 0) {
            list_name = value;
            continue;
        }

        if (name.len == 3 && ngx_strncmp(name.data, "ttl", 3) == 0) {
            ngx_int_t  n = ngx_parse_time(&value, 1);

            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: invalid list ttl \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            rule->list_ttl = (ngx_uint_t) n;
            continue;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "action", 6) == 0) {

            if (value.len == 5 && ngx_strncmp(value.data, "block", 5) == 0) {
                rule->action = NGX_HTTP_WAF_POLICY_BLOCK;

            } else if (value.len == 4
                       && ngx_strncmp(value.data, "pass", 4) == 0)
            {
                rule->action = NGX_HTTP_WAF_POLICY_PASS;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: action must be block or pass");
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: unknown option \"%V\" in waf_local_rate",
                           &name);
        return NGX_CONF_ERROR;
    }

    if (rule->rate == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_local_rate requires rate=");
        return NGX_CONF_ERROR;
    }

    if (rule->response.len != 0) {
        ngx_http_waf_main_conf_t  *wmcf;

        wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

        if (ngx_http_waf_deny_response_find(wmcf, &rule->response) == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_deny_response \"%V\" is not declared",
                               &rule->response);
            return NGX_CONF_ERROR;
        }
    }

    if (list_name.len != 0) {
        ngx_http_waf_main_conf_t  *wmcf;

        wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
        rule->list = ngx_http_waf_dataset_find(wmcf, &list_name);

        if (rule->list == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: dataset \"%V\" is not declared; "
                               "waf_local_dataset must come first",
                               &list_name);
            return NGX_CONF_ERROR;
        }

        if (rule->list->mode != NGX_HTTP_WAF_DS_MODE_ACTIVE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_local_rate list= \"%V\" must be "
                               "an active dataset", &list_name);
            return NGX_CONF_ERROR;
        }

        if (rule->list_ttl == 0) {
            rule->list_ttl = rule->list->ttl;
        }

        if (rule->list_ttl == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_local_rate list= requires ttl= "
                               "on the rule or the dataset");
            return NGX_CONF_ERROR;
        }

        if (rule->action == NGX_HTTP_WAF_POLICY_PASS) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: list= is meaningless with action=pass");
            return NGX_CONF_ERROR;
        }

    } else if (rule->list_ttl != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: ttl= requires list=");
        return NGX_CONF_ERROR;
    }

    ngx_crc32_init(sig);
    ngx_crc32_update(&sig, (u_char *) &rule->rate, sizeof(rule->rate));
    ngx_crc32_update(&sig, (u_char *) &rule->burst, sizeof(rule->burst));
    ngx_crc32_update(&sig, (u_char *) &rule->count, sizeof(rule->count));
    ngx_crc32_update(&sig, (u_char *) &rule->hash, sizeof(rule->hash));
    ngx_crc32_update(&sig, rule->key.text.data, rule->key.text.len);
    ngx_crc32_final(sig);

    rule->sig = sig;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_waf_rate_check(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule_name,
    ngx_str_t *response)
{
    u_char                    hex[NGX_HTTP_WAF_MD5_HEX_LEN];
    ngx_str_t                 raw, key;
    ngx_uint_t                i, excess, frame;
    ngx_http_waf_loc_conf_t  *wlcf;
    ngx_http_waf_shm_conf_t  *scf;
    ngx_http_waf_rate_rule_t *rules;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (wlcf->local_rates == NULL) {
        return NGX_OK;
    }

    scf = ngx_http_waf_shm_conf();

    if (scf == NULL || scf->shm == NULL) {
        return NGX_OK;
    }

    rules = wlcf->local_rates->elts;
    frame = ngx_http_waf_phase_is_frame(ctx->phase);

    for (i = 0; i < wlcf->local_rates->nelts; i++) {
        if (frame ? rules[i].count != NGX_HTTP_WAF_RATE_FRAMES
                  : rules[i].count == NGX_HTTP_WAF_RATE_FRAMES)
        {
            continue;
        }

        if (ngx_http_waf_cond_test(ctx, rules[i].conds) != NGX_OK) {
            continue;
        }

        if (ngx_http_waf_rate_key(ctx, &rules[i], &raw, &key, hex) != NGX_OK) {
            continue;
        }

        if (ngx_http_waf_rate_account(scf, &rules[i], &key,
                                      rules[i].count
                                          == NGX_HTTP_WAF_RATE_WAVES
                                              ? NGX_HTTP_WAF_RATE_PEEK
                                              : NGX_HTTP_WAF_RATE_GATE,
                                      &excess)
            == NGX_OK)
        {
            continue;
        }

        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: local rate limit exceeded for key \"%V\" "
                      "(rule \"%V\", excess %ui.%03ui), action %s, ray %*s",
                      &key, &rules[i].key.text, excess / 1000, excess % 1000,
                      rules[i].action == NGX_HTTP_WAF_POLICY_PASS
                          ? "pass" : "block",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);

        if (rules[i].action == NGX_HTTP_WAF_POLICY_BLOCK) {
            *rule_name = ngx_http_waf_rate_rule_name;
            *response  = rules[i].response;

            if (rules[i].list != NULL) {
                (void) ngx_http_waf_dataset_put(ctx, rules[i].list, &raw,
                                                rules[i].key.binary,
                                                rules[i].list_ttl,
                                                &ngx_http_waf_rate_rule_name);

                ctx->local_retry = rules[i].list_ttl;
            }

            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


void
ngx_http_waf_rate_charge_wave(ngx_http_waf_ctx_t *ctx)
{
    u_char                     hex[NGX_HTTP_WAF_MD5_HEX_LEN];
    ngx_str_t                  raw, key;
    ngx_uint_t                 i, excess;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_shm_conf_t   *scf;
    ngx_http_waf_rate_rule_t  *rules;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    if (wlcf->local_rates == NULL) {
        return;
    }

    scf = ngx_http_waf_shm_conf();

    if (scf == NULL || scf->shm == NULL) {
        return;
    }

    rules = wlcf->local_rates->elts;

    for (i = 0; i < wlcf->local_rates->nelts; i++) {

        if (rules[i].count != NGX_HTTP_WAF_RATE_WAVES) {
            continue;
        }

        if (ngx_http_waf_cond_test(ctx, rules[i].conds) != NGX_OK) {
            continue;
        }

        if (ngx_http_waf_rate_key(ctx, &rules[i], &raw, &key, hex) != NGX_OK) {
            continue;
        }

        (void) ngx_http_waf_rate_account(scf, &rules[i], &key,
                                         NGX_HTTP_WAF_RATE_DEBT, &excess);
    }
}


static ngx_int_t
ngx_http_waf_rate_key(ngx_http_waf_ctx_t *ctx, ngx_http_waf_rate_rule_t *rule,
    ngx_str_t *raw, ngx_str_t *key, u_char *hex)
{
    if (ngx_http_waf_operand_single(ctx, &rule->key, raw) != NGX_OK) {
        return NGX_ERROR;
    }

    if (raw->len == 0) {
        return NGX_ERROR;
    }

    if (rule->hash == NGX_HTTP_WAF_DS_HASH_MD5) {
        ngx_http_waf_md5_hex(raw, hex);
        key->data = hex;
        key->len = NGX_HTTP_WAF_MD5_HEX_LEN;
        return NGX_OK;
    }

    *key = *raw;

    if (key->len > NGX_HTTP_WAF_RATE_KEY_MAX) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: local rate key \"%V\" is longer than %d bytes, "
                      "rule \"%V\" skipped; hash=md5 lifts the limit", key,
                      NGX_HTTP_WAF_RATE_KEY_MAX, &rule->key.text);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_msec_int_t
ngx_http_waf_rate_elapsed(ngx_msec_t now, ngx_msec_t last)
{
    ngx_msec_int_t  ms;

    /* another worker may have stored a fresher cached time */

    ms = (ngx_msec_int_t) (now - last);

    if (ms < -60000) {
        ms = 1;

    } else if (ms < 0) {
        ms = 0;
    }

    return ms;
}


static ngx_int_t
ngx_http_waf_rate_account(ngx_http_waf_shm_conf_t *scf,
    ngx_http_waf_rate_rule_t *rule, ngx_str_t *key, ngx_uint_t mode,
    ngx_uint_t *excess)
{
    uint32_t                   hash;
    ngx_int_t                  value, limit;
    ngx_msec_t                 now;
    ngx_msec_int_t             ms;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_rate_node_t  *rn;

    shm  = scf->shm;
    hash = ngx_crc32_short(key->data, key->len) ^ rule->sig;
    now  = ngx_current_msec;

    ngx_shmtx_lock(&shm->shpool->mutex);

    rn = ngx_http_waf_rate_lookup(shm, rule, key, hash);

    if (rn == NULL) {
        *excess = 0;

        if (mode != NGX_HTTP_WAF_RATE_PEEK) {
            (void) ngx_http_waf_rate_insert(scf, rule, key, hash,
                                            mode == NGX_HTTP_WAF_RATE_DEBT
                                                ? 1000 : 0);
        }

        ngx_shmtx_unlock(&shm->shpool->mutex);

        return NGX_OK;
    }

    ngx_queue_remove(&rn->queue);
    ngx_queue_insert_head(&shm->rate_lru, &rn->queue);

    ms = ngx_http_waf_rate_elapsed(now, rn->last);

    value = (ngx_int_t) rn->excess
            - (ngx_int_t) (rule->rate * (ngx_uint_t) ms / 1000)
            + (mode == NGX_HTTP_WAF_RATE_PEEK ? 0 : 1000);

    if (value < 0) {
        value = 0;
    }

    *excess = (ngx_uint_t) value;

    if (mode == NGX_HTTP_WAF_RATE_PEEK) {
        ngx_shmtx_unlock(&shm->shpool->mutex);

        return (value <= (ngx_int_t) rule->burst) ? NGX_OK : NGX_DECLINED;
    }

    if (value <= (ngx_int_t) rule->burst) {
        rn->excess = (ngx_uint_t) value;

        if (ms) {
            rn->last = now;
        }

        ngx_shmtx_unlock(&shm->shpool->mutex);

        return NGX_OK;
    }

    if (mode == NGX_HTTP_WAF_RATE_DEBT) {
        limit = (ngx_int_t) (rule->burst + rule->rate);

        rn->excess = (ngx_uint_t) (value > limit ? limit : value);

        if (ms) {
            rn->last = now;
        }
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_DECLINED;
}


static ngx_http_waf_rate_node_t *
ngx_http_waf_rate_lookup(ngx_http_waf_shm_t *shm,
    ngx_http_waf_rate_rule_t *rule, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t                  rc;
    ngx_rbtree_node_t         *node, *sentinel;
    ngx_http_waf_rate_node_t  *rn;

    node     = shm->rate.root;
    sentinel = shm->rate.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        rn = (ngx_http_waf_rate_node_t *) &node->color;

        if (rn->sig == rule->sig) {
            rc = ngx_memn2cmp(key->data, rn->data, key->len,
                              (size_t) rn->len);
            if (rc == 0) {
                return rn;
            }

        } else {
            rc = (rule->sig < rn->sig) ? -1 : 1;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static size_t
ngx_http_waf_rate_charge(size_t len)
{
    size_t  size, charge;

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_waf_rate_node_t, data)
           + len;

    for (charge = 8; charge < size; charge <<= 1) { /* void */ }

    return charge;
}


static ngx_int_t
ngx_http_waf_rate_insert(ngx_http_waf_shm_conf_t *scf,
    ngx_http_waf_rate_rule_t *rule, ngx_str_t *key, uint32_t hash,
    ngx_uint_t excess)
{
    size_t                     charge;
    ngx_uint_t                 n;
    ngx_rbtree_node_t         *node;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_rate_node_t  *rn;

    static ngx_msec_t          warned;

    shm    = scf->shm;
    charge = ngx_http_waf_rate_charge(key->len);

    ngx_http_waf_rate_expire(shm, 0);

    for (n = 0;
         shm->rate_bytes + charge > scf->rate_max
         && n < NGX_HTTP_WAF_RATE_EVICT
         && !ngx_queue_empty(&shm->rate_lru);
         n++)
    {
        ngx_http_waf_rate_expire(shm, 1);
    }

    node = NULL;

    if (shm->rate_bytes + charge <= scf->rate_max) {
        node = ngx_slab_alloc_locked(shm->shpool, charge);

        if (node == NULL) {
            ngx_http_waf_rate_expire(shm, 1);

            node = ngx_slab_alloc_locked(shm->shpool, charge);
        }
    }

    if (node == NULL) {

        if (ngx_current_msec - warned >= 1000) {
            warned = ngx_current_msec;

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "waf: local rate counters are out of room in zone "
                          "\"%V\" (%uz of %uz bytes), rule \"%V\" does not "
                          "count a new key", &scf->wmcf->shm_name,
                          shm->rate_bytes, scf->rate_max, &rule->key.text);
        }

        return NGX_ERROR;
    }

    shm->rate_bytes += charge;

    node->key = hash;

    rn = (ngx_http_waf_rate_node_t *) &node->color;

    rn->len    = (u_char) key->len;
    rn->sig    = rule->sig;
    rn->rate   = rule->rate;
    rn->excess = excess;
    rn->last   = ngx_current_msec;

    ngx_memcpy(rn->data, key->data, key->len);

    ngx_rbtree_insert(&shm->rate, node);
    ngx_queue_insert_head(&shm->rate_lru, &rn->queue);

    return NGX_OK;
}


static void
ngx_http_waf_rate_free(ngx_http_waf_shm_t *shm, ngx_http_waf_rate_node_t *rn)
{
    size_t              charge;
    ngx_rbtree_node_t  *node;

    charge = ngx_http_waf_rate_charge(rn->len);

    node = (ngx_rbtree_node_t *)
               ((u_char *) rn - offsetof(ngx_rbtree_node_t, color));

    ngx_queue_remove(&rn->queue);
    ngx_rbtree_delete(&shm->rate, node);
    ngx_slab_free_locked(shm->shpool, node);

    shm->rate_bytes = (shm->rate_bytes > charge) ? shm->rate_bytes - charge
                                                 : 0;
}


static void
ngx_http_waf_rate_expire(ngx_http_waf_shm_t *shm, ngx_uint_t force)
{
    ngx_int_t                  excess;
    ngx_uint_t                 n;
    ngx_queue_t               *q;
    ngx_msec_t                 now;
    ngx_msec_int_t             ms;
    ngx_http_waf_rate_node_t  *rn;

    now = ngx_current_msec;

    for (n = 0; n < 2; n++) {

        if (ngx_queue_empty(&shm->rate_lru)) {
            return;
        }

        q  = ngx_queue_last(&shm->rate_lru);
        rn = ngx_queue_data(q, ngx_http_waf_rate_node_t, queue);

        if (!force) {
            ms     = ngx_http_waf_rate_elapsed(now, rn->last);
            excess = (ngx_int_t) rn->excess
                     - (ngx_int_t) (rn->rate * (ngx_uint_t) ms / 1000);

            if (excess > 0) {
                return;
            }
        }

        ngx_http_waf_rate_free(shm, rn);

        force = 0;
    }
}


void
ngx_http_waf_rate_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t        **p;
    ngx_http_waf_rate_node_t  *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            rn      = (ngx_http_waf_rate_node_t *) &node->color;
            rn_temp = (ngx_http_waf_rate_node_t *) &temp->color;

            if (rn->sig != rn_temp->sig) {
                p = (rn->sig < rn_temp->sig) ? &temp->left : &temp->right;

            } else {
                p = (ngx_memn2cmp(rn->data, rn_temp->data,
                                  (size_t) rn->len, (size_t) rn_temp->len) < 0)
                        ? &temp->left : &temp->right;
            }
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p           = node;
    node->parent = temp;
    node->left   = sentinel;
    node->right  = sentinel;
    ngx_rbt_red(node);
}
