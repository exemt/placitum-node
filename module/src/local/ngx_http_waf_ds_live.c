/*
 * Overlay набора: записи keeper со сроком в зоне. У активного набора это
 * весь состав -- неизменяемой базы у него больше нет: каждое изменение
 * приходит пакетом и ложится сюда точечно, а не пересобирает миллионный
 * набор целиком.
 *
 * Ключ записи -- её материал с провода (docs/keeper.md): у адреса семейство,
 * длина маски и адрес под маской, у строки -- она сама. Префикс с маской --
 * такая же запись, как одиночный адрес: поиск адреса пробует только те длины
 * масок, которые в наборе есть (счётчики по длинам), и на каждой -- одно
 * обращение к дереву.
 *
 * Замок -- rwlock слота, свой у каждого набора: читатель на пути запроса
 * берёт разделяемый, применение пакета -- исключительный, и ни тот, ни
 * другой не делят мьютекс зоны со счётчиками частоты и остальными наборами.
 * Выделение памяти под узел идёт через ngx_slab_alloc, который берёт мьютекс
 * зоны сам; порядок «замок слота, затем мьютекс зоны» -- единственный.
 *
 * Снапшот ложится пометкой и выметанием: записи объекта кладутся с новым
 * поколением, затем всё с прежним поколением снимается. Состав отвечает всё
 * это время -- дыры «сбросили, ещё не наполнили» нет, и памяти вдвое тоже.
 *
 * Истёкшее не сметается само: истечение приходит пакетом remove от keeper,
 * и снятая раньше него запись разошлась бы с ним хешем. На поиске истёкшая
 * запись -- промах.
 */

#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "codec/ngx_http_waf_codec.h"
#include "local/ngx_http_waf_local.h"


/*
 * color -- первый байт ngx_rbtree_node_t: узел и запись живут в одной
 * аллокации, как в limit_req. Узел адреса IPv4 -- 62 байта, класс slab 64;
 * IPv6 и md5-строки -- класс 128.
 */
typedef struct {
    u_char             color;
    u_char             pad;
    uint16_t           len;
    uint32_t           gen;       /* поколение снапшота, которым положена  */
    ngx_msec_t         expires;   /* 0 -- вечная                           */
    /*
     * SipHash материала под ключом эпохи -- слагаемое хеша набора. 0 у записи
     * автобана: keeper её ещё не подтвердил, хеш придёт с пакетом.
     */
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
static ngx_uint_t ngx_http_waf_ds_live_probe(ngx_http_waf_ds_live_t *live,
    ngx_uint_t fam, const u_char *addr, size_t alen);


static ngx_int_t
ngx_http_waf_ds_live_init(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot)
{
    ngx_http_waf_ds_live_t  *live;

    live = ngx_slab_calloc(shm->shpool, sizeof(ngx_http_waf_ds_live_t));
    if (live == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&live->tree, &live->sentinel,
                    ngx_http_waf_ds_live_insert_value);
    live->max = slot->live_max != 0 ? slot->live_max
                                    : NGX_HTTP_WAF_DS_LIVE_MAX;
    live->gen = 1;
    slot->live = live;
    return NGX_OK;
}


static ngx_http_waf_ds_live_t *
ngx_http_waf_ds_live_ensure(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot)
{
    if (slot->live == NULL) {
        if (ngx_http_waf_ds_live_init(shm, slot) != NGX_OK) {
            return NULL;
        }
    }

    if (slot->live_max != 0) {
        slot->live->max = slot->live_max;
    }

    return slot->live;
}


/* Семейство и длина адреса из материала: 4 -> IPv4, 6 -> IPv6. */
static ngx_uint_t
ngx_http_waf_ds_live_family(ngx_str_t *key)
{
    if (key->len == 6 && key->data[0] == 4) {
        return 0;
    }

    if (key->len == 18 && key->data[0] == 6) {
        return 1;
    }

    return 2;                          /* не адрес */
}


/*
 * Запись под исключительным замком слота. h != 0 -- запись от keeper: срок
 * авторитетен и ставится как есть, хеш входит в live_hash на переходе
 * состояния (новая запись, запись автобана без хеша, смена ключа эпохи).
 * h == 0 -- автобан этой ноды: срок только удлиняется.
 *
 * NGX_OK -- записано (новая или срок изменён), NGX_DECLINED -- уже есть с не
 * меньшим сроком, NGX_ERROR -- потолок или зона.
 */
ngx_int_t
ngx_http_waf_ds_live_put(ngx_http_waf_ds_slot_t *slot, ngx_str_t *key,
    ngx_msec_t expires, uint64_t h, uint32_t gen)
{
    size_t                         size;
    uint32_t                       hash;
    ngx_uint_t                     fam;
    ngx_http_waf_shm_t            *shm;
    ngx_http_waf_ds_live_t        *live;
    ngx_rbtree_node_t             *node;
    ngx_http_waf_ds_live_node_t   *ln;

    if (key->len == 0 || key->len > NGX_HTTP_WAF_DS_ENTRY_MAX) {
        return NGX_ERROR;
    }

    shm = ngx_http_waf_shm();
    if (shm == NULL) {
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

    /*
     * Потолок равен объявленному limit=, место под него проверено на
     * nginx -t (ngx_http_waf_shm_fit): сюда попадают только настоящие
     * расхождения -- keeper прислал больше, чем объявлено на краю. Живое не
     * вытесняется: набор молча пропускал бы то, что обязан резать.
     */
    if (live->n >= live->max) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: dataset overlay \"%*s\" is full (%ui)",
                      (size_t) slot->name_len, slot->name, live->max);
        return NGX_ERROR;
    }

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_waf_ds_live_node_t, data)
           + key->len;

    node = ngx_slab_alloc(shm->shpool, size);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "waf: no room in the zone for an overlay entry of "
                      "dataset \"%*s\" (%ui of %ui entries)",
                      (size_t) slot->name_len, slot->name, live->n,
                      live->max);
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

    fam = ngx_http_waf_ds_live_family(key);
    if (fam < 2) {
        live->lens[fam][key->data[1]]++;
    }

    return NGX_OK;
}


/* Снятие под исключительным замком слота. NGX_DECLINED -- записи не было. */
ngx_int_t
ngx_http_waf_ds_live_drop(ngx_http_waf_ds_slot_t *slot, ngx_str_t *key)
{
    uint32_t                      hash;
    ngx_http_waf_shm_t           *shm;
    ngx_http_waf_ds_live_node_t  *ln;

    shm = ngx_http_waf_shm();
    if (shm == NULL || slot->live == NULL || key->len == 0) {
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


/*
 * Поиск значения на пути запроса: разделяемый замок. У набора адресов
 * значение -- $binary_remote_addr (4 или 16 байт) либо текст адреса; по
 * каждой присутствующей длине маски одно обращение к дереву, от узкой к
 * широкой. У набора строк -- сама строка.
 */
ngx_uint_t
ngx_http_waf_ds_live_hit(ngx_http_waf_dataset_t *ds,
    ngx_http_waf_ds_slot_t *slot, ngx_str_t *value)
{
    u_char                        addr[16];
    size_t                        alen;
    uint32_t                      hash;
    ngx_uint_t                    fam, hit;
    in_addr_t                     in;
    ngx_http_waf_ds_live_t       *live;
    ngx_http_waf_ds_live_node_t  *ln;

    if (slot->live == NULL || value->len == 0) {
        return 0;
    }

    if (ds->type != NGX_HTTP_WAF_DS_CIDR) {
        hash = ngx_crc32_long(value->data, value->len);

        ngx_rwlock_rlock(&slot->lock);

        live = slot->live;
        ln = ngx_http_waf_ds_live_lookup(live, value, hash);

        hit = (ln != NULL
               && (ln->expires == 0
                   || (ngx_msec_int_t) (ln->expires - ngx_current_msec) >= 0));

        ngx_rwlock_unlock(&slot->lock);

        return hit;
    }

    /*
     * Двоичный вид -- основной путь ($binary_remote_addr); текст принимается
     * потому, что $remote_addr в конфигурации встречается чаще, и молча не
     * срабатывающая проверка была бы худшим ответом на такую запись.
     */
    if (value->len == 4) {
        ngx_memcpy(addr, value->data, 4);
        fam = 0;
        alen = 4;

    } else if (value->len == 16) {
        ngx_memcpy(addr, value->data, 16);
        fam = 1;
        alen = 16;

    } else {
        in = ngx_inet_addr(value->data, value->len);

        if (in != INADDR_NONE) {
            ngx_memcpy(addr, &in, 4);
            fam = 0;
            alen = 4;

        } else if (ngx_inet6_addr(value->data, value->len, addr) == NGX_OK) {
            fam = 1;
            alen = 16;

        } else {
            return 0;
        }
    }

    ngx_rwlock_rlock(&slot->lock);
    hit = ngx_http_waf_ds_live_probe(slot->live, fam, addr, alen);
    ngx_rwlock_unlock(&slot->lock);

    return hit;
}


/* Под замком: адрес против всех присутствующих длин масок семейства. */
static ngx_uint_t
ngx_http_waf_ds_live_probe(ngx_http_waf_ds_live_t *live, ngx_uint_t fam,
    const u_char *addr, size_t alen)
{
    u_char                        key[18];
    size_t                        i;
    uint32_t                      hash;
    ngx_int_t                     bits;
    ngx_str_t                     k;
    ngx_http_waf_ds_live_node_t  *ln;

    key[0] = (fam == 0) ? 4 : 6;
    k.data = key;
    k.len  = 2 + alen;

    for (bits = (ngx_int_t) alen * 8; bits >= 0; bits--) {

        if (live->lens[fam][bits] == 0) {
            continue;
        }

        key[1] = (u_char) bits;

        for (i = 0; i < alen; i++) {
            ngx_int_t  keep = bits - (ngx_int_t) i * 8;

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
            return 1;
        }
    }

    return 0;
}


/* Снять всё: исключительный замок берётся здесь. */
void
ngx_http_waf_ds_live_reset(ngx_http_waf_ds_slot_t *slot)
{
    ngx_http_waf_shm_t           *shm;
    ngx_http_waf_ds_live_t       *live;
    ngx_rbtree_node_t            *node;
    ngx_http_waf_ds_live_node_t  *ln;

    shm = ngx_http_waf_shm();
    if (shm == NULL || slot->live == NULL) {
        return;
    }

    ngx_rwlock_wlock(&slot->lock);

    live = slot->live;

    while (live->tree.root != live->tree.sentinel) {
        node = ngx_rbtree_min(live->tree.root, live->tree.sentinel);
        ln = (ngx_http_waf_ds_live_node_t *) &node->color;
        ngx_http_waf_ds_live_delete(shm, slot, ln);
    }

    slot->live_hash = 0;

    ngx_rwlock_unlock(&slot->lock);
}


/*
 * Новое поколение под снапшот: то, что положено дальше, помечено им, а
 * выметание снимет всё, что помечено прежним. Под исключительным замком.
 */
uint32_t
ngx_http_waf_ds_live_begin(ngx_http_waf_ds_slot_t *slot)
{
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_ds_live_t  *live;

    shm = ngx_http_waf_shm();
    if (shm == NULL) {
        return 0;
    }

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


/* Текущее поколение: им помечается автобан, чтобы пережить выметание. */
uint32_t
ngx_http_waf_ds_live_gen(ngx_http_waf_ds_slot_t *slot)
{
    return (slot->live != NULL) ? slot->live->gen : 1;
}


/*
 * Выметание записей чужого поколения, порциями под исключительным замком.
 * cursor -- откуда продолжать (NULL -- с начала); NGX_AGAIN -- порция
 * кончилась раньше дерева, звать ещё. Обход в порядке ключей, преемник
 * берётся до удаления: ngx_rbtree_delete перевязывает узлы, но не двигает
 * их в памяти.
 */
ngx_int_t
ngx_http_waf_ds_live_sweep(ngx_http_waf_ds_slot_t *slot, uint32_t gen,
    ngx_uint_t batch, ngx_rbtree_node_t **cursor, ngx_uint_t *swept)
{
    ngx_uint_t                    n;
    ngx_http_waf_shm_t           *shm;
    ngx_http_waf_ds_live_t       *live;
    ngx_rbtree_node_t            *node, *next;
    ngx_http_waf_ds_live_node_t  *ln;

    shm = ngx_http_waf_shm();
    if (shm == NULL || slot->live == NULL) {
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


/*
 * Материал значения для overlay: у набора адресов -- семейство, биты, адрес
 * под маской из текста ("203.0.113.0/24", "203.0.113.7") или двоичного адреса
 * (4/16 байт); у строк -- сама строка. buf -- 18 байт от вызывающего.
 */
ngx_int_t
ngx_http_waf_ds_material(ngx_http_waf_dataset_t *ds, ngx_str_t *value,
    u_char *buf, ngx_str_t *key)
{
    size_t      i, alen;
    u_char     *slash;
    ngx_int_t   bits, keep;
    ngx_str_t   addr;
    in_addr_t   in;

    if (ds->type != NGX_HTTP_WAF_DS_CIDR) {
        *key = *value;
        return NGX_OK;
    }

    if (value->len == 4 || value->len == 16) {
        alen = value->len;
        buf[0] = (alen == 4) ? 4 : 6;
        buf[1] = (u_char) (alen * 8);
        ngx_memcpy(buf + 2, value->data, alen);

        key->data = buf;
        key->len  = 2 + alen;
        return NGX_OK;
    }

    addr  = *value;
    bits  = -1;
    slash = ngx_strlchr(addr.data, addr.data + addr.len, '/');

    if (slash != NULL) {
        bits = ngx_atoi(slash + 1, addr.data + addr.len - slash - 1);
        addr.len = (size_t) (slash - addr.data);

        if (bits == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    in = ngx_inet_addr(addr.data, addr.len);

    if (in != INADDR_NONE) {
        ngx_memcpy(buf + 2, &in, 4);
        alen = 4;
        buf[0] = 4;

    } else if (ngx_inet6_addr(addr.data, addr.len, buf + 2) == NGX_OK) {
        alen = 16;
        buf[0] = 6;

    } else {
        return NGX_ERROR;
    }

    if (bits < 0) {
        bits = (ngx_int_t) alen * 8;
    }

    if (bits > (ngx_int_t) alen * 8) {
        return NGX_ERROR;
    }

    buf[1] = (u_char) bits;

    for (i = 0; i < alen; i++) {
        keep = bits - (ngx_int_t) i * 8;

        if (keep >= 8) {
            continue;
        }

        buf[2 + i] = (keep <= 0) ? 0
                                 : (u_char) (buf[2 + i] & (0xff << (8 - keep)));
    }

    key->data = buf;
    key->len  = 2 + alen;

    return NGX_OK;
}


/*
 * Автобан: запись в overlay этой ноды сразу и событие keeper, который
 * разнесёт её остальным пакетом. Хеш записи пока 0 -- его принесёт пакет.
 */
ngx_int_t
ngx_http_waf_dataset_put(ngx_http_waf_ctx_t *ctx, ngx_http_waf_dataset_t *ds,
    ngx_str_t *value, ngx_uint_t ttl, ngx_str_t *reason)
{
    u_char                     buf[512];
    u_char                     hex[NGX_HTTP_WAF_MD5_HEX_LEN];
    u_char                     mat[18];
    ngx_str_t                  payload, subject, hashed, key;
    ngx_http_waf_jw_t          jw;
    ngx_http_waf_bus_t        *bus;
    ngx_http_waf_shm_t        *shm;
    ngx_http_waf_ds_slot_t    *slot;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_int_t                  rc;

    if (ds == NULL || value == NULL || value->len == 0 || ttl == 0) {
        return NGX_ERROR;
    }

    shm = ngx_http_waf_shm();
    if (shm == NULL) {
        return NGX_ERROR;
    }

    /*
     * Набор с hash=md5: в overlay и на провод уезжает хеш, а не значение.
     * Событие помечено hashed -- keeper не хеширует второй раз; чужие
     * писатели шлют сырое, и хеширует уже он.
     */
    if (ds->hash == NGX_HTTP_WAF_DS_HASH_MD5) {
        ngx_http_waf_md5_hex(value, hex);
        hashed.data = hex;
        hashed.len = NGX_HTTP_WAF_MD5_HEX_LEN;
        value = &hashed;
    }

    if (ngx_http_waf_ds_material(ds, value, mat, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    slot = &shm->datasets[ds->index];

    ngx_rwlock_wlock(&slot->lock);
    rc = ngx_http_waf_ds_live_put(slot, &key,
                                  ngx_current_msec + (ngx_msec_t) ttl * 1000,
                                  0, ngx_http_waf_ds_live_gen(slot));
    ngx_rwlock_unlock(&slot->lock);

    if (rc != NGX_OK) {
        return rc;
    }

    bus = ngx_http_waf_bus_current();
    if (bus == NULL || bus->publish_audit == NULL) {
        return NGX_OK;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    ngx_http_waf_jw_init(&jw, buf, sizeof(buf));
    ngx_http_waf_jw_lit(&jw, "{\"v\":1,\"dataset\":");
    ngx_http_waf_jw_str(&jw, &ds->name);

    ngx_http_waf_jw_lit(&jw, ",\"op\":\"add\",\"value\":");

    if (ds->type == NGX_HTTP_WAF_DS_CIDR && (value->len == 4 || value->len == 16)) {
        u_char     text[NGX_SOCKADDR_STRLEN];
        ngx_str_t  t;

        /* На провод -- текст адреса: keeper двоичного вида не читает. */
        t.data = text;
        t.len  = ngx_inet_ntop((value->len == 4) ? AF_INET : AF_INET6,
                               value->data, text, sizeof(text));
        ngx_http_waf_jw_str(&jw, &t);

    } else {
        ngx_http_waf_jw_str(&jw, value);
    }

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
        return NGX_OK;
    }

    subject.data = ngx_pnalloc(ctx->request->pool, ds->subject.len + 6);
    if (subject.data == NULL) {
        return NGX_OK;
    }

    {
        u_char  *p;

        p = ngx_sprintf(subject.data, "%V.event", &ds->subject);
        subject.len = (size_t) (p - subject.data);
    }

    payload.data = buf;
    payload.len = ngx_http_waf_jw_len(&jw);

    (void) bus->publish_audit(bus, &subject, &payload);
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


/* Под исключительным замком: узел из дерева, хеш из live_hash, счётчик длины. */
static void
ngx_http_waf_ds_live_delete(ngx_http_waf_shm_t *shm,
    ngx_http_waf_ds_slot_t *slot, ngx_http_waf_ds_live_node_t *ln)
{
    ngx_str_t                k;
    ngx_uint_t               fam;
    ngx_rbtree_node_t       *node;
    ngx_http_waf_ds_live_t  *live = slot->live;

    node = (ngx_rbtree_node_t *)
               ((u_char *) ln - offsetof(ngx_rbtree_node_t, color));

    k.data = ln->data;
    k.len  = ln->len;

    fam = ngx_http_waf_ds_live_family(&k);
    if (fam < 2 && live->lens[fam][ln->data[1]] > 0) {
        live->lens[fam][ln->data[1]]--;
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
