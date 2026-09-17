#ifndef _NGX_HTTP_WAF_H_INCLUDED_
#define _NGX_HTTP_WAF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_WAF_MAX_INSPECTORS   64
#define NGX_HTTP_WAF_MAX_WAVE         64

typedef uint64_t  ngx_http_waf_mask_t;


#define NGX_HTTP_WAF_MAX_DATASETS     128

#define NGX_HTTP_WAF_DS_LIVE_MAX      10000

#define NGX_HTTP_WAF_MAX_VARS         16

#define NGX_HTTP_WAF_STD_VARS         8

#if (NGX_HTTP_WAF_STD_VARS + NGX_HTTP_WAF_MAX_VARS > 32)
#error "waf: vars do not fit the declaration mask"
#endif

#define NGX_HTTP_WAF_VARS_ALL         ((ngx_uint_t) -1)

#define NGX_HTTP_WAF_VAR_MAX          256


#define NGX_HTTP_WAF_DEFAULT_PREVIEW          0

#define NGX_HTTP_WAF_DEFAULT_CONTROL_RATE     10000

#define NGX_HTTP_WAF_PREVIEW_ITEM_NONE        ((size_t) -3)

#define NGX_HTTP_WAF_AUDIT_JSON               8192

#define NGX_HTTP_WAF_AUDIT_DGRAM_MAX          (8 * 1024 * 1024)

#define NGX_HTTP_WAF_PREVIEW_MAX                                               \
    (NGX_HTTP_WAF_AUDIT_DGRAM_MAX - NGX_HTTP_WAF_AUDIT_JSON)


typedef enum {
    NGX_HTTP_WAF_V_ALLOW    = 0,
    NGX_HTTP_WAF_V_SCORE    = 1,
    NGX_HTTP_WAF_V_REDIRECT = 2,
    NGX_HTTP_WAF_V_DENY     = 3,
    NGX_HTTP_WAF_V_ERROR    = 4
} ngx_http_waf_verdict_e;


#define NGX_HTTP_WAF_SCORE_MAX        100

#define NGX_HTTP_WAF_ACTION_CODE_MAX  64
#define NGX_HTTP_WAF_ACTION_CNT_MAX   64

#define NGX_HTTP_WAF_ACTION_MARKER_MAX  128
#define NGX_HTTP_WAF_MARKERS_MAX        16

#define NGX_HTTP_WAF_MARKERS_JSON                                             \
    (NGX_HTTP_WAF_MARKERS_MAX * (2 * NGX_HTTP_WAF_ACTION_MARKER_MAX + 4) + 16)

#define NGX_HTTP_WAF_ACTION_TTL_MAX   315360000
#define NGX_HTTP_WAF_ACTION_LIMIT_MAX (1 << 30)
#define NGX_HTTP_WAF_DELTA_MAX        1000
#define NGX_HTTP_WAF_VALUE_MAX        1000

#define NGX_HTTP_WAF_ACTIONS_LIMIT    64

#define NGX_HTTP_WAF_MUTATE_GROUPS_MAX  16
#define NGX_HTTP_WAF_MUTATE_NAME_MAX    64

#define NGX_HTTP_WAF_SESSIONS_REPLY_MAX   4
#define NGX_HTTP_WAF_SESSIONS_MAX         8
#define NGX_HTTP_WAF_SESSION_USER_MAX     256
#define NGX_HTTP_WAF_SESSION_ID_MAX       128
#define NGX_HTTP_WAF_SESSION_SOURCE_MAX   64
#define NGX_HTTP_WAF_SESSION_KIND_MAX     16
#define NGX_HTTP_WAF_SESSION_GROUPS_MAX   256

#define NGX_HTTP_WAF_SESSION_JSON                                              \
    (2 * (NGX_HTTP_WAF_SESSION_USER_MAX + NGX_HTTP_WAF_SESSION_ID_MAX           \
          + NGX_HTTP_WAF_SESSION_SOURCE_MAX + NGX_HTTP_WAF_SESSION_KIND_MAX     \
          + NGX_HTTP_WAF_SESSION_GROUPS_MAX) + 256)


typedef enum {
    NGX_HTTP_WAF_PHASE_REQUEST   = 0,
    NGX_HTTP_WAF_PHASE_RESPONSE  = 1,
    NGX_HTTP_WAF_PHASE_FRAME_C2S = 2,
    NGX_HTTP_WAF_PHASE_FRAME_S2C = 3
} ngx_http_waf_phase_e;

#define NGX_HTTP_WAF_NPHASE  4

#define NGX_HTTP_WAF_BUFFERED       0x08


#define NGX_HTTP_WAF_PH_BIT(p)      (1u << (p))

#define NGX_HTTP_WAF_PH_FRAME     (NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_FRAME_C2S)      | NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_FRAME_S2C))

#define ngx_http_waf_phase_is_frame(p)     ((p) == NGX_HTTP_WAF_PHASE_FRAME_C2S      || (p) == NGX_HTTP_WAF_PHASE_FRAME_S2C)


typedef enum {
    NGX_HTTP_WAF_HOLD_GATE    = 0,
    NGX_HTTP_WAF_HOLD_MONITOR = 1
} ngx_http_waf_hold_e;


typedef enum {
    NGX_HTTP_WAF_RESUME_OFF     = 0,
    NGX_HTTP_WAF_RESUME_PREFER  = 1,
    NGX_HTTP_WAF_RESUME_REQUIRE = 2
} ngx_http_waf_resume_e;


typedef struct {
    ngx_str_t                  subject;
    size_t                     size;
    ngx_msec_t                 expires;
} ngx_http_waf_cont_t;


typedef enum {
    NGX_HTTP_WAF_ST_INIT = 0,
    NGX_HTTP_WAF_ST_NEED_BODY,
    NGX_HTTP_WAF_ST_READING_BODY,
    NGX_HTTP_WAF_ST_PLACING_META,
    NGX_HTTP_WAF_ST_FETCHING_FORM,
    NGX_HTTP_WAF_ST_FINISH,
    NGX_HTTP_WAF_ST_WAITING,
    NGX_HTTP_WAF_ST_NEXT_WAVE,
    NGX_HTTP_WAF_ST_ALLOW,
    NGX_HTTP_WAF_ST_REDIRECT,
    NGX_HTTP_WAF_ST_DENY,
    NGX_HTTP_WAF_ST_FAILED,
    NGX_HTTP_WAF_ST_DONE
} ngx_http_waf_state_e;


#define NGX_HTTP_WAF_FINISH_APPLY      0
#define NGX_HTTP_WAF_FINISH_OVERRIDES  1
#define NGX_HTTP_WAF_FINISH_FAIL       2

#define NGX_HTTP_WAF_FORM_MAX          (1024 * 1024)

#define NGX_HTTP_WAF_REWRITE_MAX_DEPTH 8


typedef enum {
    NGX_HTTP_WAF_CODE_NONE = 0,
    NGX_HTTP_WAF_CODE_LOCAL_LIST,
    NGX_HTTP_WAF_CODE_LOCAL_RATE,
    NGX_HTTP_WAF_CODE_INSPECTOR,
    NGX_HTTP_WAF_CODE_SCORE,
    NGX_HTTP_WAF_CODE_FAIL_TIMEOUT,
    NGX_HTTP_WAF_CODE_FAIL_ABSENT,
    NGX_HTTP_WAF_CODE_FAIL_BUS,
    NGX_HTTP_WAF_CODE_FAIL_BODY,
    NGX_HTTP_WAF_CODE_FAIL_INSPECTOR,
    NGX_HTTP_WAF_CODE_FAIL_OVERLOAD,
    NGX_HTTP_WAF_CODE_LOCAL_UPGRADE
} ngx_http_waf_code_e;


typedef enum {
    NGX_HTTP_WAF_ENTRY_ANSWERED = 0,
    NGX_HTTP_WAF_ENTRY_TIMEOUT,
    NGX_HTTP_WAF_ENTRY_ABSENT,
    NGX_HTTP_WAF_ENTRY_SKIPPED,
    NGX_HTTP_WAF_ENTRY_OFF
} ngx_http_waf_entry_state_e;


typedef enum {
    NGX_HTTP_WAF_POLICY_PASS  = 0,
    NGX_HTTP_WAF_POLICY_BLOCK = 1,
    NGX_HTTP_WAF_POLICY_TRIM  = 2
} ngx_http_waf_policy_e;

#define NGX_HTTP_WAF_POLICY_UNSET  (NGX_CONF_UNSET_UINT)


typedef enum {
    NGX_HTTP_WAF_EXC_TIMEOUT = 0,
    NGX_HTTP_WAF_EXC_ABSENT,
    NGX_HTTP_WAF_EXC_BUS,
    NGX_HTTP_WAF_EXC_BODY,
    NGX_HTTP_WAF_EXC_INSPECTOR,
    NGX_HTTP_WAF_EXC_OVERLOAD,
    NGX_HTTP_WAF_EXC_COUNT
} ngx_http_waf_exc_e;

#define NGX_HTTP_WAF_SEND_ORIGINAL     0
#define NGX_HTTP_WAF_SEND_STORE        1


typedef enum {
    NGX_HTTP_WAF_DENY_FAST          = 0,
    NGX_HTTP_WAF_DENY_DETERMINISTIC = 1
} ngx_http_waf_deny_mode_e;


typedef enum {
    NGX_HTTP_WAF_BODY_NONE    = 0,
    NGX_HTTP_WAF_BODY_META    = 1,
    NGX_HTTP_WAF_BODY_PREVIEW = 2,
    NGX_HTTP_WAF_BODY_FULL    = 3
} ngx_http_waf_body_need_e;


typedef enum {
    NGX_HTTP_WAF_OBJ_HEADERS = 0,
    NGX_HTTP_WAF_OBJ_ARGS    = 1,
    NGX_HTTP_WAF_OBJ_BODY    = 2
} ngx_http_waf_obj_e;

#define NGX_HTTP_WAF_OBJ_COUNT     3

#define NGX_HTTP_WAF_META_COUNT    2

#define NGX_HTTP_WAF_OBJ_BIT(i)    (1u << (i))


#define NGX_HTTP_WAF_ARCHIVE_WHEN_ALL                                          \
    ((1u << NGX_HTTP_WAF_V_ALLOW) | (1u << NGX_HTTP_WAF_V_REDIRECT)            \
     | (1u << NGX_HTTP_WAF_V_DENY))

#define NGX_HTTP_WAF_ARCHIVE_TTL_FOREVER  0

#define NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE  0

#define NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE  0

#define NGX_HTTP_WAF_AGENT_WHOLE  ((size_t) -1)


typedef struct ngx_http_waf_locator_s     ngx_http_waf_locator_t;
typedef struct ngx_http_waf_body_store_s  ngx_http_waf_body_store_t;


typedef enum {
    NGX_HTTP_WAF_MODE_ACTIVE  = 0,
    NGX_HTTP_WAF_MODE_PASSIVE = 1,

    NGX_HTTP_WAF_MODE_OFF     = 2,

    NGX_HTTP_WAF_MODE_VOTE    = 3
} ngx_http_waf_mode_e;


typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  subject;

    ngx_str_t                  audit_subject;

    ngx_str_t                  profile;

    ngx_uint_t                 index;

    unsigned                   breaker:1;
    unsigned                   breaker_named:1;

    ngx_uint_t                 breaker_threshold;
    ngx_msec_t                 breaker_window;
    ngx_msec_t                 breaker_probe;

    ngx_str_t                  vars_spec;
    ngx_uint_t                 vars_mask;
} ngx_http_waf_inspector_t;


typedef struct {
    ngx_str_t                  name;
    ngx_uint_t                 index;
    ngx_uint_t                 wave;
    ngx_msec_t                 timeout;
    ngx_uint_t                 mode;
    ngx_uint_t                 phase;
    ngx_uint_t                 resume;

    ngx_uint_t                 keep;

    ngx_array_t               *conds;
} ngx_http_waf_binding_t;

#define NGX_HTTP_WAF_AUDIT_PREFIX   "waf.audit.inspector."


typedef enum {
    NGX_HTTP_WAF_DENY_TYPE_HTTP      = 0,
    NGX_HTTP_WAF_DENY_TYPE_GRPC      = 1,
    NGX_HTTP_WAF_DENY_TYPE_WEBSOCKET = 2
} ngx_http_waf_deny_type_e;


typedef enum {
    NGX_HTTP_WAF_SCOPE_NONE = 0,
    NGX_HTTP_WAF_SCOPE_ADDRESS,
    NGX_HTTP_WAF_SCOPE_NETWORK,
    NGX_HTTP_WAF_SCOPE_COUNTRY,
    NGX_HTTP_WAF_SCOPE_ASN,
    NGX_HTTP_WAF_SCOPE_SESSION,
    NGX_HTTP_WAF_SCOPE_REQUEST
} ngx_http_waf_deny_scope_e;

#define NGX_HTTP_WAF_DENY_SUBJECT_MAX  64

#define NGX_HTTP_WAF_DENY_RETRY_MAX    2592000


#define NGX_HTTP_WAF_DENY_P_RAY      0x01
#define NGX_HTTP_WAF_DENY_P_ADDR    0x02
#define NGX_HTTP_WAF_DENY_P_SCOPE   0x04
#define NGX_HTTP_WAF_DENY_P_SUBJECT 0x08
#define NGX_HTTP_WAF_DENY_P_RETRY   0x10

typedef struct {
    ngx_str_t                  name;
    ngx_uint_t                 type;
    ngx_uint_t                 status;
    ngx_str_t                  page;
    ngx_str_t                  message;
    ngx_uint_t                 code;
    ngx_str_t                  reason;
    ngx_uint_t                 params;
} ngx_http_waf_deny_response_t;


typedef struct {
    ngx_str_t                  scheme;
    ngx_str_t                  host;
    ngx_str_t                  path;
    in_port_t                  port;
    unsigned                   wildcard:1;
} ngx_http_waf_redirect_allow_t;


typedef enum {
    NGX_HTTP_WAF_DS_CIDR   = 0,
    NGX_HTTP_WAF_DS_STRING = 1
} ngx_http_waf_dataset_type_e;


typedef enum {
    NGX_HTTP_WAF_DS_MODE_UNSET    = 0,
    NGX_HTTP_WAF_DS_MODE_ACTIVE   = 1,
    NGX_HTTP_WAF_DS_MODE_INTERNAL = 2
} ngx_http_waf_dataset_mode_e;


typedef enum {
    NGX_HTTP_WAF_DS_HASH_NONE = 0,
    NGX_HTTP_WAF_DS_HASH_MD5  = 1
} ngx_http_waf_dataset_hash_e;

#define NGX_HTTP_WAF_MD5_HEX_LEN  32


typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  uuid;
    ngx_str_t                  subject;

    ngx_uint_t                 type;
    ngx_uint_t                 mode;
    ngx_uint_t                 hash;
    ngx_uint_t                 max;
    ngx_uint_t                 ttl;
    ngx_uint_t                 live_max;
    ngx_uint_t                 index;
    ngx_array_t               *entries;
} ngx_http_waf_dataset_t;


typedef enum {
    NGX_HTTP_WAF_SEL_VAR     = 0,
    NGX_HTTP_WAF_SEL_ARGS    = 1,
    NGX_HTTP_WAF_SEL_COOKIES = 2,
    NGX_HTTP_WAF_SEL_HEADERS = 3,
    NGX_HTTP_WAF_SEL_COUNT   = 4
} ngx_http_waf_select_e;


typedef struct {
    ngx_uint_t                 object;
    ngx_str_t                  name;
    unsigned                   all:1;

    ngx_http_complex_value_t   value;

    ngx_str_t                  text;
} ngx_http_waf_operand_t;


typedef struct {
    ngx_http_waf_operand_t     operand;
    ngx_http_waf_dataset_t    *dataset;
    unsigned                   negate:1;
} ngx_http_waf_cond_t;


typedef enum {
    NGX_HTTP_WAF_RATE_REQUESTS = 0,
    NGX_HTTP_WAF_RATE_WAVES    = 1,
    NGX_HTTP_WAF_RATE_FRAMES   = 2
} ngx_http_waf_rate_count_e;


typedef struct {
    ngx_http_waf_operand_t     key;

    ngx_uint_t                 rate;
    ngx_uint_t                 burst;
    ngx_uint_t                 count;
    ngx_uint_t                 action;

    ngx_str_t                  response;

    ngx_http_waf_dataset_t    *list;
    ngx_uint_t                 list_ttl;

    ngx_uint_t                 hash;

    ngx_array_t               *conds;

    uint32_t                   sig;
} ngx_http_waf_rate_rule_t;


typedef enum {
    NGX_HTTP_WAF_CHECK_BLOCK = 0,
    NGX_HTTP_WAF_CHECK_ALLOW = 1,
    NGX_HTTP_WAF_CHECK_WAVE  = 2
} ngx_http_waf_check_action_e;


typedef struct {
    ngx_http_waf_dataset_t    *dataset;
    ngx_http_waf_operand_t     operand;

    ngx_uint_t                 action;
    ngx_str_t                  response;

    ngx_array_t               *conds;
} ngx_http_waf_check_rule_t;


typedef struct {
    ngx_http_waf_mask_t        passive;
    ngx_http_waf_mask_t        vote;
    ngx_http_waf_mask_t        all;

    ngx_http_waf_mask_t        off;

    ngx_uint_t                 body_need;

    ngx_uint_t                 obj_need;
} ngx_http_waf_wave_t;


typedef enum {
    NGX_HTTP_WAF_DO_CHALLENGE = 0,
    NGX_HTTP_WAF_DO_THRESHOLD = 1,
    NGX_HTTP_WAF_DO_SKIP      = 2,
    NGX_HTTP_WAF_DO_REAUTH    = 3,
    NGX_HTTP_WAF_DO_NOTE      = 4,
    NGX_HTTP_WAF_DO_MUTATE    = 5,

    NGX_HTTP_WAF_DO_ACTIVE    = 6,
    NGX_HTTP_WAF_DO_PASSIVE   = 7,
    NGX_HTTP_WAF_DO_OFF       = 8,
    NGX_HTTP_WAF_DO_VOTE      = 9,

    NGX_HTTP_WAF_DO_AUDIT     = 10,
    NGX_HTTP_WAF_DO_ARCHIVE   = 11,

    NGX_HTTP_WAF_DO_MARK      = 12,

    NGX_HTTP_WAF_DO_SCORE     = 13
} ngx_http_waf_do_e;

#define NGX_HTTP_WAF_DO_LAST      NGX_HTTP_WAF_DO_SCORE

#define NGX_HTTP_WAF_POINTS_MAX   100

#define ngx_http_waf_do_score(verb)    ((verb) == NGX_HTTP_WAF_DO_SCORE)

#define ngx_http_waf_do_control(verb)                                        \
    ((verb) >= NGX_HTTP_WAF_DO_ACTIVE && (verb) <= NGX_HTTP_WAF_DO_VOTE)

#define ngx_http_waf_do_audit(verb)                                          \
    ((verb) >= NGX_HTTP_WAF_DO_AUDIT && (verb) <= NGX_HTTP_WAF_DO_ARCHIVE)

#define ngx_http_waf_do_mark(verb)     ((verb) == NGX_HTTP_WAF_DO_MARK)

#define ngx_http_waf_do_module(verb)   ((verb) >= NGX_HTTP_WAF_DO_ACTIVE)


typedef enum {
    NGX_HTTP_WAF_APPLY_REQUEST = 0,
    NGX_HTTP_WAF_APPLY_IP      = 1,
    NGX_HTTP_WAF_APPLY_ASN     = 2,
    NGX_HTTP_WAF_APPLY_SESSION = 3,

    NGX_HTTP_WAF_APPLY_CONN    = 4,

    NGX_HTTP_WAF_APPLY_RESPONSE = 5
} ngx_http_waf_apply_e;

#define NGX_HTTP_WAF_APPLY_LAST   NGX_HTTP_WAF_APPLY_RESPONSE


typedef struct {
    ngx_http_waf_mask_t        active;
    ngx_http_waf_mask_t        passive;
    ngx_http_waf_mask_t        off;
    ngx_http_waf_mask_t        vote;
} ngx_http_waf_control_t;


typedef enum {
    NGX_HTTP_WAF_SOURCE_NONE = 0,
    NGX_HTTP_WAF_SOURCE_STORE,
    NGX_HTTP_WAF_SOURCE_ORIGINAL,
    NGX_HTTP_WAF_SOURCE_SENT
} ngx_http_waf_source_e;

typedef struct {
    ngx_uint_t                 set;
    time_t                     ttl;
    unsigned                   has_ttl:1;
    ngx_uint_t                 when;
    unsigned                   has_when:1;
    ngx_uint_t                 named;
    ngx_uint_t                 off;
    ngx_uint_t                 has_limit;
    size_t                     limit[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_uint_t                 source[NGX_HTTP_WAF_OBJ_COUNT];
} ngx_http_waf_ovr_part_t;

typedef struct {
    ngx_http_waf_ovr_part_t    audit;
    ngx_http_waf_ovr_part_t    archive;
} ngx_http_waf_audit_ovr_t;

#define NGX_HTTP_WAF_OBJ_ALL  (NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_COUNT) - 1)

#define NGX_HTTP_WAF_OVR_REQUEST   0
#define NGX_HTTP_WAF_OVR_RESPONSE  1
#define NGX_HTTP_WAF_OVR_COUNT     2

#define ngx_http_waf_ovr_slot(phase)                                         \
    ((phase) == NGX_HTTP_WAF_PHASE_RESPONSE ? NGX_HTTP_WAF_OVR_RESPONSE      \
                                            : NGX_HTTP_WAF_OVR_REQUEST)

#define ngx_http_waf_audit_ovr_cur(ctx)                                      \
    (&(ctx)->audit_ovr[ngx_http_waf_ovr_slot((ctx)->phase)])

#define ngx_http_waf_ovr_on(part)  ((part)->named & ~(part)->off)

#define ngx_http_waf_ovr_objects(part)                                       \
    (ngx_http_waf_ovr_on(part) != 0 ? ngx_http_waf_ovr_on(part)              \
                                    : (NGX_HTTP_WAF_OBJ_ALL & ~(part)->off))

#define ngx_http_waf_ovr_excluded(part, obj)                                 \
    ((part)->set == NGX_HTTP_WAF_SET_ON                                      \
     && ((part)->off & NGX_HTTP_WAF_OBJ_BIT(obj)))

#define ngx_http_waf_ovr_original(part, obj)                                 \
    ((part)->set == NGX_HTTP_WAF_SET_ON                                      \
     && (ngx_http_waf_ovr_on(part) & NGX_HTTP_WAF_OBJ_BIT(obj))              \
     && (part)->source[obj] == NGX_HTTP_WAF_SOURCE_ORIGINAL)

#define ngx_http_waf_ovr_store(part, obj)                                    \
    ((part)->set == NGX_HTTP_WAF_SET_ON                                      \
     && (ngx_http_waf_ovr_on(part) & NGX_HTTP_WAF_OBJ_BIT(obj))              \
     && (part)->source[obj] == NGX_HTTP_WAF_SOURCE_STORE)


typedef struct {
    ngx_uint_t                 verb;

    ngx_uint_t                 to;

    ngx_uint_t                 to_phases;

    ngx_str_t                  code;

    ngx_uint_t                 apply;

    ngx_int_t                  delta;
    ngx_int_t                  value;

    ngx_str_t                  counter;

    ngx_str_t                  group;
    ngx_uint_t                 set;

    ngx_str_t                  marker;

    ngx_http_waf_ovr_part_t    spec;

    ngx_uint_t                 from;
    ngx_uint_t                 phase;
    ngx_uint_t                 wave;

    unsigned                   passive:1;
    unsigned                   has_delta:1;
    unsigned                   has_value:1;
} ngx_http_waf_action_t;


#define NGX_HTTP_WAF_ACTION_ALL   ((ngx_uint_t) -1)

typedef enum {
    NGX_HTTP_WAF_SET_NONE = 0,
    NGX_HTTP_WAF_SET_ON,
    NGX_HTTP_WAF_SET_OFF
} ngx_http_waf_set_e;


typedef struct {
    ngx_uint_t                 verdict;

    ngx_int_t                  score;

    ngx_str_t                  reason_code;

    ngx_uint_t                 reason_scope;
    ngx_str_t                  reason_subject;

    ngx_uint_t                 reason_retry;

    ngx_str_t                  response_name;
    ngx_str_t                  redirect_url;
    ngx_uint_t                 status;

    ngx_array_t               *headers_set;
    ngx_array_t               *headers_unset;
    ngx_array_t               *cookies;

    ngx_array_t               *sessions;

    ngx_array_t               *args_set;
    ngx_array_t               *args_unset;
    unsigned                   args_applied:1;

    unsigned                   overload:1;

    ngx_array_t               *actions;

    ngx_str_t                  rewrite_key;
    off_t                      rewrite_size;
    u_char                     rewrite_sha256[32];
    ngx_array_t               *rewrite_groups;
    ngx_str_t                  rewrite_content_type;

    unsigned                   rewrite_has:1;
    unsigned                   rewrite_body:1;
    unsigned                   rewrite_sha256_set:1;
    unsigned                   rewrite_partial:1;
    unsigned                   rewrite_digest:1;

    ngx_msec_t                 latency;
    ngx_uint_t                 order;

    ngx_uint_t                 wave;

    ngx_uint_t                 state;

    unsigned                   received:1;
    unsigned                   passive:1;
    unsigned                   vote:1;

    unsigned                   no_cache:1;
} ngx_http_waf_reply_t;


typedef struct {
    ngx_str_t                  name;
    ngx_str_t                  value;
    ngx_str_t                  path;
    time_t                     max_age;
    unsigned                   max_age_set:1;
} ngx_http_waf_cookie_t;


typedef struct {
    ngx_str_t                  source;
    ngx_str_t                  kind;
    ngx_str_t                  user;
    ngx_str_t                  id;
    ngx_str_t                  groups;
    time_t                     issued;
    time_t                     expires;
    ngx_uint_t                 by;
    unsigned                   verified:1;
    unsigned                   passive:1;
} ngx_http_waf_session_t;


typedef enum {
    NGX_HTTP_WAF_SAMESITE_UNSET  = 0,
    NGX_HTTP_WAF_SAMESITE_LAX    = 1,
    NGX_HTTP_WAF_SAMESITE_STRICT = 2,
    NGX_HTTP_WAF_SAMESITE_NONE   = 3
} ngx_http_waf_samesite_e;


typedef struct ngx_http_waf_ctx_s  ngx_http_waf_ctx_t;

typedef struct {
    uint64_t                   gen;
    ngx_uint_t                 next_free;

    ngx_http_waf_ctx_t        *ctx;

    ngx_uint_t                 wave;
    ngx_http_waf_mask_t        got;
    ngx_http_waf_mask_t        denied;
    ngx_http_waf_mask_t        awaited;

    ngx_msec_t                 published;
} ngx_http_waf_slot_t;


#define NGX_HTTP_WAF_SLOT_NIL          ((ngx_uint_t) -1)
#define NGX_HTTP_WAF_SLOT_INDEX_BITS   24
#define NGX_HTTP_WAF_SLOT_INDEX_MASK   ((uint64_t) ((1u << NGX_HTTP_WAF_SLOT_INDEX_BITS) - 1))

#define NGX_HTTP_WAF_SLOT_GEN_BITS     (64 - NGX_HTTP_WAF_SLOT_INDEX_BITS)
#define NGX_HTTP_WAF_SLOT_GEN_MASK \
    ((uint64_t) ((1ULL << NGX_HTTP_WAF_SLOT_GEN_BITS) - 1))

#define NGX_HTTP_WAF_RID_HEX_LEN       16

#define NGX_HTTP_WAF_RAY_HEX_LEN       36


typedef struct {
    ngx_uint_t                 wave;

    ngx_msec_t                 wave_published;
    ngx_msec_t                 due;

    ngx_http_waf_reply_t      *replies;
    ngx_http_waf_mask_t        got;
    ngx_http_waf_mask_t        published;
    ngx_http_waf_mask_t        skipped;

    ngx_http_waf_mask_t        controlled;

    ngx_int_t                  score;
    ngx_int_t                  shadow;
    ngx_uint_t                 order;

    ngx_uint_t                 verdict;
    ngx_http_waf_reply_t      *decisive;
    ngx_uint_t                 decisive_index;
    ngx_uint_t                 fail;

    ngx_uint_t                 code;

    ngx_http_waf_mask_t        cond_off;
    unsigned                   cond_settled:1;

    ngx_http_waf_locator_t    *locator;
    ngx_http_waf_locator_t    *meta[NGX_HTTP_WAF_META_COUNT];

    ngx_http_waf_locator_t    *live;

    ngx_array_t               *stale;

    ngx_uint_t                 rewrite_depth;

    ngx_uint_t                 rewrite_last;

    ngx_http_waf_mask_t        rewrite_applied;

    ngx_str_t                  store_blob[NGX_HTTP_WAF_OBJ_COUNT];

    ngx_str_t                  preview_sent[NGX_HTTP_WAF_OBJ_COUNT];
    void                      *body_op;
    void                      *meta_op[NGX_HTTP_WAF_META_COUNT];

    ngx_uint_t                 meta_pending;
    ngx_uint_t                 meta_placed;

    ngx_uint_t                 meta_truncated;

    ngx_uint_t                 attached;
    ngx_uint_t                 attach_raw;
    ngx_http_waf_locator_t    *attach_loc[NGX_HTTP_WAF_OBJ_COUNT];
    int                        attach_fd;

    off_t                      body_placed_len;

    ngx_uint_t                 body_policy;

    ngx_uint_t                 archive;
    unsigned                   archive_settled:1;

    unsigned                   by_score:1;

    unsigned                   fail_blocked:1;

    unsigned                   body_ready:1;
    unsigned                   body_discarded:1;
    unsigned                   body_placed:1;
    unsigned                   meta_settled:1;
    unsigned                   store_cleanup:1;
    unsigned                   agent_settled:1;
    unsigned                   agent_after_body:1;
    unsigned                   attach_planned:1;

    unsigned                   journal:1;

    unsigned                   logged:1;

    unsigned                   audit_deferred:1;

    unsigned                   deny_warned:1;
} ngx_http_waf_phase_ctx_t;


struct ngx_http_waf_ctx_s {
    ngx_http_request_t        *request;

    ngx_uint_t                 state;

    ngx_uint_t                 phase;
    ngx_http_waf_phase_ctx_t   phases[NGX_HTTP_WAF_NPHASE];
    ngx_http_waf_phase_ctx_t  *ph;

    uint64_t                   rid;
    u_char                     rid_hex[NGX_HTTP_WAF_RID_HEX_LEN];
    ngx_uint_t                 slot;

    u_char                     ray_hex[NGX_HTTP_WAF_RAY_HEX_LEN];

    ngx_event_t                deadline;
    ngx_msec_t                 started;

    ngx_str_t                  local_response;
    ngx_str_t                  local_rule;

    ngx_str_t                  exception_response;

    ngx_uint_t                 local_retry;

    ngx_chain_t               *hold;
    ngx_chain_t              **hold_last;
    size_t                     hold_size;

    ngx_uint_t                 rsp_status;
    ngx_msec_t                 upstream_ms;

    ngx_array_t               *rsp_headers;

    ngx_array_t               *req_headers;
    ngx_str_t                  req_args;

    unsigned                   rsp_entered:1;
    unsigned                   rsp_holding:1;
    unsigned                   rsp_settled:1;
    unsigned                   rsp_last:1;
    unsigned                   rsp_denied:1;
    unsigned                   rsp_monitor:1;
    unsigned                   rsp_wait_body:1;

    unsigned                   rsp_journal:1;
    unsigned                   rsp_journal_done:1;
    size_t                     rsp_journal_need;
    off_t                      rsp_journal_total;

    unsigned                   rsp_fetch_done:1;
    unsigned                   rsp_rewritten:1;
    ngx_uint_t                 rsp_rewrite_index;

    void                      *form_op;
    unsigned                   form_fetched:1;
    unsigned                   form_failed:1;

    void                      *send_body_op;
    ngx_uint_t                 send_body_index;
    unsigned                   send_fetched:1;
    unsigned                   send_body_done:1;
    unsigned                   req_body_rewritten:1;

    ngx_http_waf_cont_t       *cont;

    ngx_http_waf_mask_t        resume_asked;

    ngx_array_t               *actions;

    ngx_array_t               *sessions;

    ngx_array_t               *markers;

    ngx_http_waf_control_t     ctl[NGX_HTTP_WAF_NPHASE];

    ngx_http_waf_audit_ovr_t   audit_ovr[NGX_HTTP_WAF_OVR_COUNT];

    ngx_str_t                  accept_encoding;

    ngx_str_t                 *vars;

    ngx_array_t               *pairs[NGX_HTTP_WAF_SEL_COUNT];
    ngx_uint_t                 pairs_parsed;

    unsigned                   by_local:1;
    unsigned                   waiting:1;

    unsigned                   audit_sampled:1;
    unsigned                   audit_keep:1;

    ngx_uint_t                 finish_how;

    void                      *frame;

    ngx_pool_t                *keep_pool;
};


static ngx_inline ngx_pool_t *
ngx_http_waf_ctx_pool(ngx_http_waf_ctx_t *ctx)
{
    return (ctx->keep_pool != NULL) ? ctx->keep_pool : ctx->request->pool;
}


typedef struct {
    ngx_str_t                  name;
    ngx_http_complex_value_t   value;

    unsigned                   builtin:1;
} ngx_http_waf_var_t;


typedef struct {
    ngx_array_t                inspectors;

    ngx_array_t               *loc_confs;

    ngx_array_t               *deny_responses;

    ngx_str_t                  node_id;
    ngx_str_t                  agent_socket;

    ngx_array_t               *vars;

    void                      *bus;

    ngx_array_t               *bus_servers;
    ngx_str_t                  bus_name;
    ngx_str_t                  bus_user;
    ngx_str_t                  bus_pass;
    ngx_str_t                  bus_token;
    ngx_msec_t                 bus_connect_timeout;
    ngx_msec_t                 bus_reconnect_wait;
    ngx_msec_t                 bus_ping_interval;
    size_t                     bus_pending_max;
    size_t                     bus_payload_max;

    ngx_shm_zone_t            *shm_zone;
    ngx_str_t                  shm_name;

    ngx_array_t               *datasets;

    ngx_http_waf_body_store_t *body_store;

    ngx_http_waf_body_store_t *sets_store;

    ngx_uint_t                 body_max_holds;

    ngx_uint_t                 max_inflight;

    size_t                     reply_max;
    size_t                     header_value_max;

    ngx_uint_t                 ctx_var_index;
} ngx_http_waf_main_conf_t;


typedef enum {
    NGX_HTTP_WAF_LIST_CAPTURE = 0,
    NGX_HTTP_WAF_LIST_ARCHIVE = 1,
    NGX_HTTP_WAF_LIST_PREVIEW = 2
} ngx_http_waf_list_kind_e;

#define NGX_HTTP_WAF_LIST_COUNT    3

typedef enum {
    NGX_HTTP_WAF_AXIS_ALLOW = 0,
    NGX_HTTP_WAF_AXIS_MASK  = 1,
    NGX_HTTP_WAF_AXIS_DENY  = 2
} ngx_http_waf_list_axis_e;

#define NGX_HTTP_WAF_AXIS_COUNT    3


typedef struct {
    ngx_uint_t                 capture;
    ngx_uint_t                 capture_set;
    ngx_uint_t                 capture_cleared;
    size_t                     capture_limit[NGX_HTTP_WAF_OBJ_COUNT];

    ngx_uint_t                 archive;
    ngx_uint_t                 archive_set;
    ngx_uint_t                 archive_cleared;
    ngx_uint_t                 archive_when[NGX_HTTP_WAF_OBJ_COUNT];
    time_t                     archive_ttl[NGX_HTTP_WAF_OBJ_COUNT];
    size_t                     archive_limit[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_uint_t                 archive_original;

    size_t                     preview[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_uint_t                 preview_source[NGX_HTTP_WAF_OBJ_COUNT];

    size_t                     preview_item[NGX_HTTP_WAF_OBJ_COUNT];
    ngx_uint_t                 preview_cleared;

    ngx_array_t               *lists[NGX_HTTP_WAF_LIST_COUNT]
                                    [NGX_HTTP_WAF_META_COUNT]
                                    [NGX_HTTP_WAF_AXIS_COUNT];
} ngx_http_waf_shoot_conf_t;


#define NGX_HTTP_WAF_NAMED_DEADLINE        0x0001
#define NGX_HTTP_WAF_NAMED_DENY_MODE       0x0002
#define NGX_HTTP_WAF_NAMED_HOLD            0x0004
#define NGX_HTTP_WAF_NAMED_SCORE_DENY      0x0008
#define NGX_HTTP_WAF_NAMED_BODY_LIMIT      0x0010
#define NGX_HTTP_WAF_NAMED_EXCEPTION(exc)  (0x0100u << (exc))

typedef struct {
    ngx_flag_t                 enable;

    ngx_str_t                  name;
    unsigned                   has_children:1;

    ngx_array_t               *inspects[NGX_HTTP_WAF_NPHASE];

    ngx_array_t               *waves[NGX_HTTP_WAF_NPHASE];

    ngx_str_t                  profiles[NGX_HTTP_WAF_MAX_INSPECTORS];

    ngx_uint_t                 named[NGX_HTTP_WAF_NPHASE];

    ngx_msec_t                 deadline[NGX_HTTP_WAF_NPHASE];

    ngx_uint_t                 exception[NGX_HTTP_WAF_NPHASE]
                                        [NGX_HTTP_WAF_EXC_COUNT];
    ngx_str_t                  exception_response[NGX_HTTP_WAF_NPHASE]
                                                 [NGX_HTTP_WAF_EXC_COUNT];

    ngx_uint_t                 send[NGX_HTTP_WAF_NPHASE]
                                   [NGX_HTTP_WAF_OBJ_COUNT];

    ngx_uint_t                 deny_mode[NGX_HTTP_WAF_NPHASE];

    ngx_uint_t                 hold[NGX_HTTP_WAF_NPHASE];

    ngx_int_t                  score_deny[NGX_HTTP_WAF_NPHASE];
    ngx_str_t                  score_deny_response[NGX_HTTP_WAF_NPHASE];

    ngx_str_t                  deny_response_default;

    ngx_str_t                  route_id;

    ngx_array_t               *redirect_allow;

    ngx_array_t               *local_rates;
    ngx_array_t               *local_checks;


    size_t                     body_limit[NGX_HTTP_WAF_NPHASE];
    ngx_uint_t                 body_limit_policy[NGX_HTTP_WAF_NPHASE];

    ngx_http_waf_shoot_conf_t  shoot[NGX_HTTP_WAF_NPHASE];

    ngx_flag_t                 debug_header;

    ngx_flag_t                 require_upgrade;
    ngx_str_t                  require_upgrade_response;
    ngx_array_t               *ws_strip_ext;

    ngx_uint_t                 audit_frames;
    ngx_uint_t                 audit_frames_sample;

    ngx_flag_t                 frame_reassemble;

    ngx_uint_t                 frame_control_rate;

    ngx_msec_t                 frame_cache_ttl[NGX_HTTP_WAF_NPHASE];

    ngx_flag_t                 strip_accept_encoding;

    size_t                     action_max;
    ngx_uint_t                 actions_max;

    ngx_int_t                  audit_sample;

    unsigned                   dead_action_warned:1;
    unsigned                   control_warned:1;
    unsigned                   audit_ovr_warned:1;
    unsigned                   score_warned:1;

    ngx_flag_t                 cookie_secure;
    ngx_flag_t                 cookie_http_only;
    ngx_uint_t                 cookie_same_site;
} ngx_http_waf_loc_conf_t;


extern ngx_module_t  ngx_http_waf_module;


void      *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
char      *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
void      *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
char      *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


char *ngx_http_waf_inspector(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_inspect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_deny_response(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_redirect_allow(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_audit_sample(ngx_conf_t *cf, ngx_command_t *cmd,
           void *conf);
char *ngx_http_waf_score_deny(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_hold(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_require_upgrade(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_audit_frames(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_ws_strip_extensions(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_frame_control_rate(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_frame_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_exception(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_send(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_phase_deny_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_bus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_cookie_defaults(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_waf_capture(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_archive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_waf_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

char *ngx_http_waf_preview(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

char *ngx_http_waf_deadline(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

char *ngx_http_waf_body_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_waf_split(ngx_str_t *arg, ngx_str_t *name, ngx_str_t *value);

ngx_uint_t ngx_http_waf_value_clean(ngx_str_t *s);

ngx_str_t *ngx_http_waf_obj_name(ngx_uint_t obj);

ngx_http_waf_inspector_t *ngx_http_waf_inspector_find(
    ngx_http_waf_main_conf_t *wmcf, ngx_str_t *name);

ngx_http_waf_deny_response_t *ngx_http_waf_deny_response_find(
    ngx_http_waf_main_conf_t *wmcf, ngx_str_t *name);

ngx_http_waf_deny_response_t *ngx_http_waf_deny_entry_pub(
    ngx_http_waf_ctx_t *ctx);

ngx_int_t ngx_http_waf_variables_init(ngx_conf_t *cf);


ngx_http_waf_binding_t *ngx_http_waf_binding_find(
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index, ngx_uint_t phase);

ngx_uint_t ngx_http_waf_action_deliverable(ngx_http_waf_loc_conf_t *wlcf,
               ngx_uint_t to, ngx_uint_t phase, ngx_uint_t wave);

ngx_uint_t ngx_http_waf_resume_wanted(ngx_http_waf_loc_conf_t *wlcf,
               ngx_uint_t index, ngx_uint_t phase);

ngx_int_t  ngx_http_waf_check_resume_pairs(ngx_conf_t *cf,
               ngx_http_waf_main_conf_t *wmcf);

ngx_int_t  ngx_http_waf_check_send_routes(ngx_conf_t *cf,
               ngx_http_waf_main_conf_t *wmcf);

ngx_str_t *ngx_http_waf_resume_subject(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t index);

void       ngx_http_waf_resume_forget(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t index);

ngx_int_t  ngx_http_waf_resume_keep(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
               ngx_str_t *subject, ngx_msec_t ttl);

ngx_int_t  ngx_http_waf_resume_ask(ngx_http_waf_ctx_t *ctx, ngx_uint_t index);

ngx_uint_t ngx_http_waf_resume_phase(ngx_http_waf_loc_conf_t *wlcf,
               ngx_uint_t index, ngx_uint_t phase);

void       ngx_http_waf_resume_release(ngx_http_waf_ctx_t *ctx);

ngx_array_t  *ngx_http_waf_waves_build(ngx_conf_t *cf,
                  ngx_http_waf_main_conf_t *wmcf,
                  ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase);


ngx_int_t  ngx_http_waf_operand_compile(ngx_conf_t *cf, ngx_str_t *token,
               ngx_http_waf_operand_t *op, ngx_uint_t all,
               const char *directive);

ngx_int_t  ngx_http_waf_cond_parse(ngx_conf_t *cf, ngx_uint_t *i,
               ngx_array_t **conds, const char *directive);

ngx_int_t  ngx_http_waf_operand_single(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_operand_t *op, ngx_str_t *out);

ngx_int_t  ngx_http_waf_operand_hit(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_operand_t *op, ngx_http_waf_dataset_t *ds,
               ngx_str_t *matched);

ngx_int_t  ngx_http_waf_cond_test(ngx_http_waf_ctx_t *ctx, ngx_array_t *conds);

ngx_http_waf_mask_t  ngx_http_waf_cond_off(ngx_http_waf_ctx_t *ctx);

ngx_uint_t  ngx_http_waf_waves_pending(ngx_http_waf_ctx_t *ctx);


ngx_int_t  ngx_http_waf_access_handler(ngx_http_request_t *r);

ngx_http_waf_ctx_t  *ngx_http_waf_get_ctx(ngx_http_request_t *r);
ngx_int_t            ngx_http_waf_set_ctx(ngx_http_request_t *r,
                         ngx_http_waf_ctx_t *ctx);
ngx_int_t            ngx_http_waf_ctx_var_init(ngx_conf_t *cf);

void                 ngx_http_waf_vars_eval(ngx_http_waf_ctx_t *ctx);

char                *ngx_http_waf_vars_init(ngx_conf_t *cf,
                         ngx_http_waf_main_conf_t *wmcf);
ngx_int_t  ngx_http_waf_wave_start(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave);

ngx_int_t  ngx_http_waf_local_checks(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_finish(ngx_http_waf_ctx_t *ctx, ngx_uint_t how);

void       ngx_http_waf_body_resumed(ngx_http_waf_ctx_t *ctx, ngx_int_t rc);

void       ngx_http_waf_form_resumed(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_form_fetch(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_send_fetch(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_send_of(ngx_http_waf_loc_conf_t *wlcf,
               ngx_uint_t phase, ngx_uint_t obj);

ngx_uint_t ngx_http_waf_rewrite_applied(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t index);
size_t     ngx_http_waf_args_cap(ngx_http_request_t *r);
void       ngx_http_waf_on_reply(ngx_http_waf_slot_t *slot, ngx_uint_t index,
               ngx_http_waf_reply_t *reply);
void       ngx_http_waf_resume(ngx_http_waf_slot_t *slot);

void       ngx_http_waf_skip(ngx_http_waf_slot_t *slot, ngx_uint_t index,
               ngx_uint_t code);

void       ngx_http_waf_omit(ngx_http_waf_slot_t *slot,
               ngx_http_waf_mask_t mask, ngx_uint_t state);

ngx_http_waf_mask_t  ngx_http_waf_wave_off(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_wave_t *w);
ngx_http_waf_mask_t  ngx_http_waf_wave_passive(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_wave_t *w);
ngx_http_waf_mask_t  ngx_http_waf_wave_vote(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_wave_t *w);
ngx_http_waf_mask_t  ngx_http_waf_wave_mandatory(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_wave_t *w);

ngx_http_waf_mask_t  ngx_http_waf_wave_gating(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_wave_t *w);

ngx_int_t  ngx_http_waf_score_apply(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_action_t *a);

ngx_int_t  ngx_http_waf_control_apply(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_action_t *a);
void       ngx_http_waf_control_set(ngx_http_waf_control_t *ctl,
               ngx_uint_t verb, ngx_http_waf_mask_t bit);

ngx_http_waf_control_t  *ngx_http_waf_frame_control(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_audit_ovr_apply(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_action_t *a);

ngx_http_waf_audit_ovr_t  *ngx_http_waf_frame_audit_ovr(
               ngx_http_waf_ctx_t *ctx);


void       ngx_http_waf_resolve_verdict(ngx_http_waf_ctx_t *ctx);
ngx_str_t *ngx_http_waf_verdict_name(ngx_uint_t verdict);
ngx_str_t *ngx_http_waf_phase_name(ngx_uint_t phase);

ngx_str_t *ngx_http_waf_code_name(ngx_uint_t code);

ngx_int_t ngx_http_waf_fail_status(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_exc_of(ngx_uint_t code);
ngx_str_t *ngx_http_waf_exc_name(ngx_uint_t exc);
ngx_str_t *ngx_http_waf_entry_state_name(ngx_uint_t state);

ngx_uint_t ngx_http_waf_deny_scope_parse(ngx_str_t *word);
ngx_str_t *ngx_http_waf_deny_scope_name(ngx_uint_t scope);

ngx_int_t  ngx_http_waf_score_deny_at(ngx_http_waf_ctx_t *ctx);
void       ngx_http_waf_account(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
               ngx_http_waf_reply_t *reply);

void       ngx_http_waf_actions_merge(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t index, ngx_http_waf_reply_t *reply,
               ngx_uint_t wave);

void       ngx_http_waf_sessions_merge(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t index, ngx_http_waf_reply_t *reply);

ngx_int_t  ngx_http_waf_markers_add(ngx_http_waf_ctx_t *ctx,
               ngx_http_waf_action_t *a);

ngx_str_t *ngx_http_waf_do_name(ngx_uint_t verb);
ngx_str_t *ngx_http_waf_apply_name(ngx_uint_t axis);
ngx_str_t *ngx_http_waf_to_phase_name(ngx_uint_t phases);


ngx_int_t  ngx_http_waf_apply(ngx_http_waf_ctx_t *ctx);


ngx_int_t  ngx_http_waf_filter_init(ngx_conf_t *cf);

ngx_array_t *ngx_http_waf_response_headers(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_response_body(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_strip_accept_encoding(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_phase_apply(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_phase_resume(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_response_resume(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_apply_overrides(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_apply_debug(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_log_verdict(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_result_status(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_audit_request(ngx_http_waf_ctx_t *ctx);

ngx_int_t  ngx_http_waf_attach_prepare(ngx_http_waf_ctx_t *ctx);
void       ngx_http_waf_attach_close(ngx_http_waf_ctx_t *ctx);
int        ngx_http_waf_attach_fd(ngx_http_waf_ctx_t *ctx);
ngx_int_t  ngx_http_waf_attach_write(int fd, u_char *data, size_t len);
ngx_http_waf_locator_t *ngx_http_waf_audit_locator(ngx_http_waf_ctx_t *ctx,
               ngx_uint_t obj);

void       ngx_http_waf_audit_flush_deferred(ngx_http_waf_ctx_t *ctx);

void       ngx_http_waf_audit_defer(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_route_verdict(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_audit_verdict(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_frame_audit_wanted(ngx_http_waf_ctx_t *ctx);

ngx_uint_t ngx_http_waf_audit_enabled(void);

ngx_int_t  ngx_http_waf_audit_init_worker(ngx_cycle_t *cycle);
void       ngx_http_waf_audit_exit_worker(ngx_cycle_t *cycle);


#define NGX_HTTP_WAF_AUDIT_FRAMES_OFF   0
#define NGX_HTTP_WAF_AUDIT_FRAMES_DENY  1
#define NGX_HTTP_WAF_AUDIT_FRAMES_ALL   2

typedef struct {
    u_char                    *conn_id;
    ngx_str_t                 *direction;
    ngx_str_t                 *opcode;
    uint64_t                   seq;
    size_t                     size;
    u_char                    *payload;
    ngx_uint_t                 fragments;
    unsigned                   fin:1;
    unsigned                   rewritten:1;
    unsigned                   cached:1;
} ngx_http_waf_frame_audit_t;

typedef struct {
    u_char                    *conn_id;
    uint64_t                   frames_c2s;
    uint64_t                   frames_s2c;
    off_t                      bytes_c2s;
    off_t                      bytes_s2c;
    uint64_t                   denied;
    uint64_t                   rewritten;
    uint64_t                   cached;
    uint64_t                   reassembled;
    uint64_t                   control_dropped;
    ngx_uint_t                 close_code;
    const char                *close_reason;
    const char                *close_why;
    ngx_msec_t                 duration_ms;
} ngx_http_waf_session_audit_t;

ngx_uint_t   ngx_http_waf_frame_audit(ngx_http_waf_ctx_t *ctx,
                 ngx_http_waf_frame_audit_t *out);
void         ngx_http_waf_audit_session(ngx_http_waf_ctx_t *ctx,
                 ngx_http_waf_session_audit_t *sess);

ngx_uint_t   ngx_http_waf_frame_wanted(ngx_http_request_t *r,
                 ngx_http_waf_ctx_t *ctx);

ngx_int_t    ngx_http_waf_frame_attach(ngx_http_request_t *r,
                 ngx_http_waf_ctx_t *ctx);

void         ngx_http_waf_frame_resume(ngx_http_waf_ctx_t *ctx);

ngx_int_t    ngx_http_waf_frame_body(ngx_http_waf_ctx_t *ctx);

ngx_chain_t *ngx_http_waf_frame_source(ngx_http_waf_ctx_t *ctx);

#define NGX_HTTP_WAF_FRAME_VAR_OPCODE     0
#define NGX_HTTP_WAF_FRAME_VAR_DIRECTION  1
#define NGX_HTTP_WAF_FRAME_VAR_SIZE       2
#define NGX_HTTP_WAF_FRAME_VAR_CONN_ID    3

ngx_int_t    ngx_http_waf_frame_var(ngx_http_waf_ctx_t *ctx, ngx_uint_t which,
                 ngx_str_t *out);

ngx_int_t    ngx_http_waf_frame_finish(ngx_http_waf_ctx_t *ctx,
                 ngx_uint_t how);

size_t       ngx_http_waf_msg_frame_size(ngx_http_waf_ctx_t *ctx);


ngx_int_t            ngx_http_waf_slot_table_init(ngx_cycle_t *cycle,
                         ngx_uint_t nslots);
ngx_http_waf_slot_t *ngx_http_waf_slot_acquire(ngx_http_waf_ctx_t *ctx);
ngx_http_waf_slot_t *ngx_http_waf_slot_lookup(uint64_t rid);
void                 ngx_http_waf_slot_release(ngx_http_waf_slot_t *slot);

void                 ngx_http_waf_slot_detach(void *data);

void       ngx_http_waf_rid_hex(uint64_t rid, u_char *dst);
ngx_int_t  ngx_http_waf_rid_parse(ngx_str_t *hex, uint64_t *rid);

void       ngx_http_waf_ray_next(u_char *dst);


static ngx_inline void
ngx_http_waf_phase_enter(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase)
{
    ctx->phase = phase;
    ctx->ph    = &ctx->phases[phase];
}


static ngx_inline ngx_uint_t
ngx_http_waf_phase_inspected(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase)
{
    return wlcf->waves[phase] != NULL && wlcf->waves[phase]->nelts != 0;
}


ngx_http_waf_wave_t  *ngx_http_waf_current_wave(ngx_http_waf_ctx_t *ctx);
ngx_uint_t            ngx_http_waf_wave_count(ngx_http_waf_ctx_t *ctx);

static ngx_inline ngx_uint_t
ngx_http_waf_lowest_bit(uint64_t mask)
{
#if defined(__GNUC__) || defined(__clang__)
    return (ngx_uint_t) __builtin_ctzll(mask);
#else
    ngx_uint_t  n = 0;

    while ((mask & 1) == 0) {
        mask >>= 1;
        n++;
    }

    return n;
#endif
}


#endif
