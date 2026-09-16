#ifndef _NGX_HTTP_WAF_LOCAL_H_INCLUDED_
#define _NGX_HTTP_WAF_LOCAL_H_INCLUDED_


#include "ngx_http_waf.h"


#define NGX_HTTP_WAF_DS_NAME_MAX        64


typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  value;
} ngx_http_waf_pair_t;

#define NGX_HTTP_WAF_DS_ENTRY_MAX      4096

#define NGX_HTTP_WAF_DS_RETIRED        4


typedef struct {
    ngx_atomic_t               state;
    ngx_atomic_t               epoch;
    ngx_atomic_t               attempts;
    ngx_atomic_t               failures;
    ngx_atomic_t               probe_at;
} ngx_http_waf_breaker_t;


typedef struct {
    ngx_atomic_t               readers;
    ngx_uint_t                 entries;
    size_t                     size;
    uint64_t                   hash;
} ngx_http_waf_set_t;


typedef struct {
    ngx_http_waf_set_t         h;

    ngx_uint_t                 n4;
    uint32_t                  *v4_start;
    uint32_t                  *v4_end;
    uint32_t                  *v4_cover;

    ngx_uint_t                 n6;
    u_char                    *v6_start;
    u_char                    *v6_end;
    u_char                    *v6_cover;

    uint64_t                  *v4_h;
    uint64_t                  *v6_h;
} ngx_http_waf_cidr_set_t;


typedef struct {
    ngx_http_waf_set_t         h;

    ngx_uint_t                 mask;
    uint32_t                  *table;
    u_char                    *blob;
    size_t                     blob_len;
} ngx_http_waf_str_set_t;


typedef struct {
    ngx_rbtree_t               tree;
    ngx_rbtree_node_t          sentinel;
    ngx_uint_t                 n;
    ngx_uint_t                 max;
    uint32_t                   gen;
    uint32_t                   lens[2][129];
} ngx_http_waf_ds_live_t;


typedef struct {
    u_char                     name[NGX_HTTP_WAF_DS_NAME_MAX];
    size_t                     name_len;
    ngx_uint_t                 type;

    void                      *set;
    ngx_http_waf_ds_live_t    *live;
    ngx_uint_t                 live_max;

    ngx_atomic_t               lock;

    uint64_t                   seq;
    time_t                     updated;

    uint64_t                   epoch;
    u_char                     key[16];
    uint64_t                   live_hash;

    ngx_msec_t                 seen;
    unsigned                   silent:1;

    unsigned                   syncing:1;
    unsigned                   snap_bad:1;

    ngx_msec_t                 snapshot_at;

    void                      *retired[NGX_HTTP_WAF_DS_RETIRED];

    unsigned                   bound:1;
} ngx_http_waf_ds_slot_t;


#define NGX_HTTP_WAF_FCACHE_ENTRIES     4096
#define NGX_HTTP_WAF_FCACHE_PROBE       8

typedef struct {
    u_char                     digest[16];
    uint32_t                   route;
    uint8_t                    phase;
    uint8_t                    opcode;
    uint16_t                   pad;
    ngx_msec_t                 expires;
} ngx_http_waf_fcache_entry_t;

typedef struct {
    ngx_atomic_t               hits;
    ngx_atomic_t               misses;
    ngx_atomic_t               inserts;
    ngx_http_waf_fcache_entry_t  entries[NGX_HTTP_WAF_FCACHE_ENTRIES];
} ngx_http_waf_fcache_t;


typedef struct {
    ngx_slab_pool_t           *shpool;

    ngx_http_waf_breaker_t     breakers[NGX_HTTP_WAF_MAX_INSPECTORS];

    ngx_rbtree_t               rate;
    ngx_rbtree_node_t          rate_sentinel;
    ngx_queue_t                rate_lru;

    ngx_http_waf_ds_slot_t     datasets[NGX_HTTP_WAF_MAX_DATASETS];

    ngx_http_waf_fcache_t     *fcache;
} ngx_http_waf_shm_t;


char      *ngx_http_waf_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);

ngx_int_t  ngx_http_waf_shm_required(ngx_conf_t *cf, const char *directive);

ngx_int_t  ngx_http_waf_shm_fit(ngx_conf_t *cf);

ngx_http_waf_shm_t  *ngx_http_waf_shm(void);


ngx_int_t  ngx_http_waf_breaker_allow(ngx_uint_t index,
               ngx_http_waf_inspector_t *insp);

void       ngx_http_waf_breaker_result(ngx_uint_t index,
               ngx_http_waf_inspector_t *insp, ngx_uint_t timed_out);


char      *ngx_http_waf_local_rate(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);

void       ngx_http_waf_rate_insert_value(ngx_rbtree_node_t *temp,
               ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

ngx_int_t  ngx_http_waf_rate_check(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule,
               ngx_str_t *response);

void       ngx_http_waf_rate_charge_wave(ngx_http_waf_ctx_t *ctx);


char      *ngx_http_waf_local_dataset(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);
char      *ngx_http_waf_local_check(ngx_conf_t *cf, ngx_command_t *cmd,
               void *conf);

ngx_http_waf_dataset_t  *ngx_http_waf_dataset_find(
                             ngx_http_waf_main_conf_t *wmcf, ngx_str_t *name);

ngx_int_t  ngx_http_waf_dataset_bind(ngx_cycle_t *cycle);

typedef enum {
    NGX_HTTP_WAF_DS_OP_DIFF     = 0,
    NGX_HTTP_WAF_DS_OP_TICK     = 1,
    NGX_HTTP_WAF_DS_OP_SNAPSHOT = 2,
    NGX_HTTP_WAF_DS_OP_OTHER    = 3
} ngx_http_waf_ds_op_e;

typedef struct {
    ngx_uint_t                 op;
    uint64_t                   epoch;
    uint64_t                   seq;
    uint64_t                   hash;
    ngx_uint_t                 has_hash;
    ngx_str_t                  package;
    ngx_str_t                  object;
    ngx_str_t                  reply;
    ngx_uint_t                 count;
    ngx_uint_t                 ttl;
} ngx_http_waf_ds_notice_t;

ngx_int_t  ngx_http_waf_dataset_notice(ngx_uint_t index, ngx_str_t *payload,
               ngx_pool_t *pool, ngx_http_waf_ds_notice_t *n);

#define NGX_HTTP_WAF_DS_APPLIED    0
#define NGX_HTTP_WAF_DS_STALE      1
#define NGX_HTTP_WAF_DS_GAP        2
#define NGX_HTTP_WAF_DS_FOREIGN    3
#define NGX_HTTP_WAF_DS_DIVERGED   4
#define NGX_HTTP_WAF_DS_MALFORMED  5
#define NGX_HTTP_WAF_DS_BUSY       6

ngx_int_t  ngx_http_waf_dataset_apply_package(ngx_uint_t index,
               ngx_str_t *data);

ngx_int_t  ngx_http_waf_dataset_apply_snapshot(ngx_uint_t index,
               ngx_str_t *data);

ngx_int_t  ngx_http_waf_dataset_verify(ngx_uint_t index, uint64_t epoch,
               uint64_t seq, uint64_t hash);

void       ngx_http_waf_dataset_state(ngx_uint_t index, uint64_t *epoch,
               uint64_t *seq);

ngx_uint_t ngx_http_waf_dataset_snap_bad(ngx_uint_t index);

ngx_msec_int_t ngx_http_waf_dataset_seen(ngx_uint_t index, ngx_uint_t touch,
               ngx_uint_t *first_silence);

ngx_int_t  ngx_http_waf_dataset_check(ngx_http_waf_ctx_t *ctx, ngx_str_t *rule,
               ngx_str_t *response);

ngx_uint_t ngx_http_waf_dataset_hit(ngx_http_waf_dataset_t *ds,
               ngx_str_t *value);

void       ngx_http_waf_md5_hex(ngx_str_t *in, u_char *out);

ngx_int_t  ngx_http_waf_dataset_snapshot_claim(ngx_uint_t index,
               ngx_msec_t wait);

ngx_int_t  ngx_http_waf_ds_live_put(ngx_http_waf_ds_slot_t *slot,
               ngx_str_t *key, ngx_msec_t expires, uint64_t h, uint32_t gen);
ngx_int_t  ngx_http_waf_ds_live_drop(ngx_http_waf_ds_slot_t *slot,
               ngx_str_t *key);
ngx_uint_t ngx_http_waf_ds_live_hit(ngx_http_waf_dataset_t *ds,
               ngx_http_waf_ds_slot_t *slot, ngx_str_t *value);
void       ngx_http_waf_ds_live_reset(ngx_http_waf_ds_slot_t *slot);

uint32_t   ngx_http_waf_ds_live_begin(ngx_http_waf_ds_slot_t *slot);
uint32_t   ngx_http_waf_ds_live_gen(ngx_http_waf_ds_slot_t *slot);

ngx_int_t  ngx_http_waf_ds_live_sweep(ngx_http_waf_ds_slot_t *slot,
               uint32_t gen, ngx_uint_t batch, ngx_rbtree_node_t **cursor,
               ngx_uint_t *swept);

ngx_int_t  ngx_http_waf_ds_material(ngx_http_waf_dataset_t *ds,
               ngx_str_t *value, u_char *buf, ngx_str_t *key);

ngx_int_t  ngx_http_waf_dataset_put(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_dataset_t *ds, ngx_str_t *value, ngx_uint_t ttl,
               ngx_str_t *reason);


ngx_int_t  ngx_http_waf_fcache_init(ngx_http_waf_shm_t *shm,
               ngx_shm_zone_t *zone);

void       ngx_http_waf_fcache_want(ngx_uint_t on);

ngx_int_t  ngx_http_waf_fcache_lookup(uint32_t route, ngx_uint_t phase,
               ngx_uint_t opcode, u_char *sha256);

void       ngx_http_waf_fcache_insert(uint32_t route, ngx_uint_t phase,
               ngx_uint_t opcode, u_char *sha256, ngx_msec_t ttl);


ngx_int_t  ngx_http_waf_ds_stream_init_worker(ngx_cycle_t *cycle);

void       ngx_http_waf_ds_stream_ready(void);
void       ngx_http_waf_ds_stream_lost(void);

void       ngx_http_waf_ds_stream_message(ngx_uint_t index, ngx_str_t *payload);
void       ngx_http_waf_ds_stream_reply(ngx_uint_t index, ngx_str_t *payload);


#endif
