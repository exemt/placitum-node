#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"


typedef struct {
    u_char             color;
    u_char             pad;
    uint16_t           len;
    uint32_t           gen;
    ngx_msec_t         expires;
    uint64_t           h;
    u_char             data[1];
} ngx_http_waf_ds_live_node_t;


static void ngx_http_waf_ds_live_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_http_waf_ds_live_t *ngx_http_waf_ds_live_ensure(
    ngx_http_waf_shm_t *shm, ngx_http_waf_ds_slot_t *slot);
static ngx_http_waf_ds_live_node_t *ngx_http_waf_ds_live_lookup(
    ngx_http_waf_ds_live_t *live, ngx_str_t *key, uint32_t hash);
static void ngx_http_waf_ds_live_delete(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, ngx_http_waf_ds_live_node_t *ln);
static ngx_int_t ngx_http_waf_ds_live_bits(ngx_http_waf_ds_slot_t *slot,
    ngx_str_t *key, ngx_uint_t *fam, ngx_uint_t *bits);
static ngx_int_t ngx_http_waf_ds_material(ngx_http_waf_dataset_t *ds,
    ngx_str_t *value, ngx_uint_t binary, u_char *buf, ngx_str_t *key);


ngx_int_t
ngx_http_waf_ds_addr(ngx_str_t *value, ngx_uint_t binary, ngx_uint_t *fam,
    u_char *addr)
{
    size_t     i;
    in_addr_t  in;

    if (binary) {

        if (value->len == 4) {
            ngx_memcpy(addr, value->data, 4);
            *fam = 0;
            return NGX_OK;
        }

        if (value->len != 16) {
            return NGX_DECLINED;
        }

        ngx_memcpy(addr, value->data, 16);

    } else {
        in = ngx_inet_addr(value->data, value->len);

        if (in != INADDR_NONE) {
            ngx_memcpy(addr, &in, 4);
            *fam = 0;
            return NGX_OK;
        }

#if (NGX_HAVE_INET6)
        if (ngx_inet6_addr(value->data, value->len, addr) != NGX_OK) {
            return NGX_DECLINED;
        }
#else
        return NGX_DECLINED;
#endif
    }

    *fam = 1;

    for (i = 0; i < 10; i++) {
        if (addr[i] != 0) {
            return NGX_OK;
        }
    }

    if (addr[10] != 0xff || addr[11] != 0xff) {
        return NGX_OK;
    }

    ngx_memmove(addr, addr + 12, 4);
    *fam = 0;

    return NGX_OK;
}


static ngx_http_waf_ds_live_t *
ngx_http_waf_ds_live_ensure(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot)
{
    ngx_http_waf_ds_live_t  *live;

    live = slot->live;

    if (live == NULL) {
        live = ngx_slab_calloc(shm->shpool, sizeof(ngx_http_waf_ds_live_t));
        if (live == NULL) {
            return NULL;
        }

        ngx_rbtree_init(&live->tree, &live->sentinel,
                        ngx_http_waf_ds_live_insert_value);
        live->gen = 1;

        slot->live = live;
    }

    live->max = (slot->live_max != 0) ? slot->live_max
                                      : NGX_HTTP_WAF_DS_LIVE_MAX;

    return live;
}


static ngx_int_t
ngx_http_waf_ds_live_bits(ngx_http_waf_ds_slot_t *slot, ngx_str_t *key,
    ngx_uint_t *fam, ngx_uint_t *bits)
{
    if (slot->type != NGX_HTTP_WAF_DS_CIDR) {
        return NGX_DECLINED;
    }

    if (key->len == 6 && key->data[0] == 4 && key->data[1] <= 32) {
        *fam = 0;

    } else if (key->len == 18 && key->data[0] == 6 && key->data[1] <= 128) {
        *fam = 1;

    } else {
        return NGX_ERROR;
    }

    *bits = key->data[1];

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_ds_live_put(ngx_http_waf_shm_t *shm, ngx_http_waf_ds_slot_t *slot,
    ngx_str_t *key, ngx_msec_t expires, uint64_t h, uint32_t gen)
{
    size_t                        size;
    uint32_t                      hash;
    ngx_int_t                     rc;
    ngx_uint_t                    fam, bits;
    ngx_rbtree_node_t            *node;
    ngx_http_waf_ds_live_t       *live;
    ngx_http_waf_ds_live_node_t  *ln;

    if (key->len == 0 || key->len > NGX_HTTP_WAF_DS_ENTRY_MAX) {
        return NGX_ERROR;
    }

    rc = ngx_http_waf_ds_live_bits(slot, key, &fam, &bits);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    live = ngx_http_waf_ds_live_ensure(shm, slot);
    if (live == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_long(key->data, key->len);
    ln = ngx_http_waf_ds_live_lookup(live, key, hash);

    if (ln != NULL) {
        ln->gen = gen;

        if (h != 0) {
            if (ln->h != h) {
                slot->live_hash ^= ln->h ^ h;
                ln->h = h;
            }

            if (ln->expires == expires) {
                return NGX_DECLINED;
            }

            ln->expires = expires;
            return NGX_OK;
        }

        if (expires != 0 && ln->expires != 0 && expires <= ln->expires) {
            return NGX_DECLINED;
        }

        ln->expires = expires;
        return NGX_OK;
    }

    if (live->n >= live->max) {
        return NGX_BUSY;
    }

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_waf_ds_live_node_t, data)
           + key->len;

    node = ngx_slab_alloc(shm->shpool, size);
    if (node == NULL) {
        return NGX_ERROR;
    }

    node->key = hash;
    ln = (ngx_http_waf_ds_live_node_t *) &node->color;
    ln->len = (uint16_t) key->len;
    ln->gen = gen;
    ln->expires = expires;
    ln->h = h;
    ngx_memcpy(ln->data, key->data, key->len);

    ngx_rbtree_insert(&live->tree, node);
    live->n++;
    slot->live_hash ^= h;

    if (rc == NGX_OK) {
        live->lens[fam][bits]++;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_ds_live_drop(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, ngx_str_t *key)
{
    uint32_t                      hash;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL || key->len == 0) {
        return NGX_DECLINED;
    }

    hash = ngx_crc32_long(key->data, key->len);

    ln = ngx_http_waf_ds_live_lookup(slot->live, key, hash);
    if (ln == NULL) {
        return NGX_DECLINED;
    }

    ngx_http_waf_ds_live_delete(shm, slot, ln);
    return NGX_OK;
}


void
ngx_http_waf_ds_live_mark(ngx_http_waf_ds_slot_t *slot, ngx_str_t *key,
    uint32_t gen)
{
    uint32_t                      hash;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL || key->len == 0) {
        return;
    }

    hash = ngx_crc32_long(key->data, key->len);

    ln = ngx_http_waf_ds_live_lookup(slot->live, key, hash);

    if (ln != NULL) {
        ln->gen = gen;
    }
}


ngx_uint_t
ngx_http_waf_ds_live_hit(ngx_http_waf_ds_slot_t *slot, ngx_str_t *value)
{
    uint32_t                      hash;
    ngx_uint_t                    hit;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL || value->len == 0) {
        return 0;
    }

    hash = ngx_crc32_long(value->data, value->len);

    ngx_rwlock_rlock(&slot->lock);

    ln = ngx_http_waf_ds_live_lookup(slot->live, value, hash);

    hit = (ln != NULL
           && (ln->expires == 0
               || (ngx_msec_int_t) (ln->expires - ngx_current_msec) >= 0));

    ngx_rwlock_unlock(&slot->lock);

    return hit;
}


ngx_uint_t
ngx_http_waf_ds_live_probe(ngx_http_waf_ds_slot_t *slot, ngx_uint_t fam,
    u_char *addr)
{
    u_char                        key[18];
    size_t                        i, alen;
    uint32_t                      hash;
    ngx_int_t                     bits, keep;
    ngx_str_t                     k;
    ngx_uint_t                    hit;
    ngx_http_waf_ds_live_t       *live;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL) {
        return 0;
    }

    alen   = (fam == 0) ? 4 : 16;
    key[0] = (fam == 0) ? 4 : 6;
    k.data = key;
    k.len  = 2 + alen;
    hit    = 0;

    ngx_rwlock_rlock(&slot->lock);

    live = slot->live;

    for (bits = (ngx_int_t) alen * 8; bits >= 0; bits--) {

        if (live->lens[fam][bits] == 0) {
            continue;
        }

        key[1] = (u_char) bits;

        for (i = 0; i < alen; i++) {
            keep = bits - (ngx_int_t) i * 8;

            if (keep >= 8) {
                key[2 + i] = addr[i];

            } else if (keep <= 0) {
                key[2 + i] = 0;

            } else {
                key[2 + i] = (u_char) (addr[i] & (0xff << (8 - keep)));
            }
        }

        hash = ngx_crc32_long(key, k.len);
        ln = ngx_http_waf_ds_live_lookup(live, &k, hash);

        if (ln != NULL
            && (ln->expires == 0
                || (ngx_msec_int_t) (ln->expires - ngx_current_msec) >= 0))
        {
            hit = 1;
            break;
        }
    }

    ngx_rwlock_unlock(&slot->lock);

    return hit;
}


void
ngx_http_waf_ds_live_reset(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot)
{
    ngx_rbtree_node_t            *node;
    ngx_http_waf_ds_live_t       *live;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL) {
        return;
    }

    ngx_rwlock_wlock(&slot->lock);

    live = slot->live;

    while (live->tree.root != live->tree.sentinel) {
        node = ngx_rbtree_min(live->tree.root, live->tree.sentinel);
        ln = (ngx_http_waf_ds_live_node_t *) &node->color;
        ngx_http_waf_ds_live_delete(shm, slot, ln);
    }

    live->n = 0;
    ngx_memzero(live->lens, sizeof(live->lens));
    slot->live_hash = 0;

    ngx_rwlock_unlock(&slot->lock);
}


uint32_t
ngx_http_waf_ds_live_begin(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot)
{
    ngx_http_waf_ds_live_t  *live;

    live = ngx_http_waf_ds_live_ensure(shm, slot);
    if (live == NULL) {
        return 0;
    }

    live->gen++;

    if (live->gen == 0) {
        live->gen = 1;
    }

    return live->gen;
}


uint32_t
ngx_http_waf_ds_live_gen(ngx_http_waf_ds_slot_t *slot)
{
    return (slot->live != NULL) ? slot->live->gen : 1;
}


ngx_int_t
ngx_http_waf_ds_live_sweep(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, uint32_t gen, ngx_uint_t batch,
    ngx_rbtree_node_t **cursor, ngx_uint_t *swept)
{
    ngx_uint_t                    n;
    ngx_http_waf_ds_live_t       *live;
    ngx_rbtree_node_t            *node, *next;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL) {
        return NGX_OK;
    }

    live = slot->live;

    if (live->tree.root == live->tree.sentinel) {
        return NGX_OK;
    }

    node = *cursor;

    if (node == NULL) {
        node = ngx_rbtree_min(live->tree.root, live->tree.sentinel);
    }

    for (n = 0; node != NULL && n < batch; n++) {
        next = ngx_rbtree_next(&live->tree, node);

        ln = (ngx_http_waf_ds_live_node_t *) &node->color;

        if (ln->gen != gen) {
            ngx_http_waf_ds_live_delete(shm, slot, ln);
            (*swept)++;
        }

        node = next;
    }

    *cursor = node;

    return (node == NULL) ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_waf_ds_material(ngx_http_waf_dataset_t *ds, ngx_str_t *value,
    ngx_uint_t binary, u_char *buf, ngx_str_t *key)
{
    ngx_uint_t  fam;

    if (ds->type != NGX_HTTP_WAF_DS_CIDR) {
        *key = *value;
        return NGX_OK;
    }

    if (ngx_http_waf_ds_addr(value, binary, &fam, buf + 2) != NGX_OK) {
        return NGX_DECLINED;
    }

    buf[0] = (fam == 0) ? 4 : 6;
    buf[1] = (fam == 0) ? 32 : 128;

    key->data = buf;
    key->len  = (fam == 0) ? 6 : 18;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_dataset_put(ngx_http_waf_ctx_t *ctx, ngx_http_waf_dataset_t *ds,
    ngx_str_t *value, ngx_uint_t binary, ngx_uint_t ttl, ngx_str_t *reason)
{
    u_char                     stack[1024], *buf, *p;
    u_char                     hex[NGX_HTTP_WAF_MD5_HEX_LEN];
    u_char                     mat[18];
    u_char                     text[NGX_SOCKADDR_STRLEN];
    u_char                     subj[NGX_HTTP_WAF_DS_NAME_MAX + 32];
    size_t                     len;
    ngx_int_t                  rc;
    ngx_str_t                  payload, subject, hashed, key, shown;
    ngx_log_t                 *log;
    ngx_http_waf_jw_t          jw;
    ngx_http_waf_bus_t        *bus;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ds == NULL || value == NULL || value->len == 0 || ttl == 0) {
        return NGX_ERROR;
    }

    shm = ngx_http_waf_shm();

    if (shm == NULL || ds->index >= NGX_HTTP_WAF_MAX_DATASETS) {
        return NGX_ERROR;
    }

    log = ctx->request->connection->log;

    if (ds->hash == NGX_HTTP_WAF_DS_HASH_MD5) {
        ngx_http_waf_md5_hex(value, hex);
        hashed.data = hex;
        hashed.len = NGX_HTTP_WAF_MD5_HEX_LEN;
        value = &hashed;
    }

    if (ngx_http_waf_ds_material(ds, value, binary, mat, &key) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "waf: dataset \"%V\" bans single addresses only, "
                      "the rate key is not one, ray %*s", &ds->name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        return NGX_DECLINED;
    }

    slot = &shm->datasets[ds->index];

    ngx_rwlock_wlock(&slot->lock);
    rc = ngx_http_waf_ds_live_put(shm, slot, &key,
                                  ngx_current_msec + (ngx_msec_t) ttl * 1000,
                                  0, ngx_http_waf_ds_live_gen(slot));
    ngx_rwlock_unlock(&slot->lock);

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waf: dataset \"%V\" did not take the ban: %s, ray %*s",
                      &ds->name,
                      (rc == NGX_BUSY) ? "the overlay is full"
                                       : "no room in the zone",
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        return NGX_ERROR;
    }

    bus = ngx_http_waf_bus_current();
    if (bus == NULL || bus->publish_audit == NULL) {
        return NGX_OK;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ds->type == NGX_HTTP_WAF_DS_CIDR) {
        shown.data = text;
        shown.len  = ngx_inet_ntop((key.len == 6) ? AF_INET : AF_INET6,
                                   key.data + 2, text, sizeof(text));

    } else {
        shown = *value;
    }

    len = sizeof("{\"v\":1,\"dataset\":\"\",\"op\":\"add\",\"value\":\"\","
                 "\"ttl\":,\"hashed\":true,\"origin\":\"\",\"reason\":\"\","
                 "\"ray\":\"\"}") - 1
          + 6 * (ds->name.len + shown.len + wmcf->node_id.len
                 + (reason != NULL ? reason->len : 0))
          + NGX_INT_T_LEN + NGX_HTTP_WAF_RAY_HEX_LEN;

    buf = stack;

    if (len > sizeof(stack)) {
        buf = ngx_alloc(len, log);
        if (buf == NULL) {
            return NGX_OK;
        }
    }

    ngx_http_waf_jw_init(&jw, buf, len);
    ngx_http_waf_jw_lit(&jw, "{\"v\":1,\"dataset\":");
    ngx_http_waf_jw_str(&jw, &ds->name);

    ngx_http_waf_jw_lit(&jw, ",\"op\":\"add\",\"value\":");
    ngx_http_waf_jw_str(&jw, &shown);

    ngx_http_waf_jw_lit(&jw, ",\"ttl\":");
    ngx_http_waf_jw_int(&jw, (ngx_int_t) ttl);

    if (ds->hash == NGX_HTTP_WAF_DS_HASH_MD5) {
        ngx_http_waf_jw_lit(&jw, ",\"hashed\":true");
    }

    ngx_http_waf_jw_lit(&jw, ",\"origin\":");
    ngx_http_waf_jw_str(&jw, &wmcf->node_id);

    if (reason != NULL && reason->len != 0) {
        ngx_http_waf_jw_lit(&jw, ",\"reason\":");
        ngx_http_waf_jw_str(&jw, reason);
    }

    ngx_http_waf_jw_lit(&jw, ",\"ray\":\"");
    ngx_http_waf_jw_raw(&jw, ctx->ray_hex, NGX_HTTP_WAF_RAY_HEX_LEN);
    ngx_http_waf_jw_lit(&jw, "\"}");

    if (!ngx_http_waf_jw_ok(&jw)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "waf: dataset \"%V\": the ban event does not fit "
                      "%uz bytes and is not published, ray %*s", &ds->name,
                      len, (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
        goto done;
    }

    p = ngx_slprintf(subj, subj + sizeof(subj), "%V.event", &ds->subject);

    subject.data = subj;
    subject.len  = (size_t) (p - subj);

    payload.data = buf;
    payload.len  = ngx_http_waf_jw_len(&jw);

    (void) bus->publish_audit(bus, &subject, &payload);

done:

    if (buf != stack) {
        ngx_free(buf);
    }

    return NGX_OK;
}


static ngx_http_waf_ds_live_node_t *
ngx_http_waf_ds_live_lookup(ngx_http_waf_ds_live_t *live, ngx_str_t *key,
    uint32_t hash)
{
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_waf_ds_live_node_t  *ln;

    node = live->tree.root;
    sentinel = live->tree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        ln = (ngx_http_waf_ds_live_node_t *) &node->color;
        rc = ngx_memn2cmp(key->data, ln->data, key->len, (size_t) ln->len);

        if (rc == 0) {
            return ln;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_http_waf_ds_live_delete(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, ngx_http_waf_ds_live_node_t *ln)
{
    ngx_str_t                k;
    ngx_uint_t               fam, bits;
    ngx_rbtree_node_t       *node;
    ngx_http_waf_ds_live_t  *live = slot->live;

    node = (ngx_rbtree_node_t *)
               ((u_char *) ln - offsetof(ngx_rbtree_node_t, color));

    k.data = ln->data;
    k.len  = ln->len;

    if (ngx_http_waf_ds_live_bits(slot, &k, &fam, &bits) == NGX_OK
        && live->lens[fam][bits] > 0)
    {
        live->lens[fam][bits]--;
    }

    slot->live_hash ^= ln->h;

    ngx_rbtree_delete(&live->tree, node);
    ngx_slab_free(shm->shpool, node);

    if (live->n > 0) {
        live->n--;
    }
}


static void
ngx_http_waf_ds_live_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t            **p;
    ngx_http_waf_ds_live_node_t   *ln, *ln_temp;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            ln = (ngx_http_waf_ds_live_node_t *) &node->color;
            ln_temp = (ngx_http_waf_ds_live_node_t *) &temp->color;

            p = (ngx_memn2cmp(ln->data, ln_temp->data, ln->len, ln_temp->len)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}
