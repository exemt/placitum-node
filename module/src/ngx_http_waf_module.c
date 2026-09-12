/*
 * Определение модуля: таблица директив, точки подключения к фазам и фильтрам,
 * инициализация воркера.
 *
 * Логики здесь нет намеренно. Разбор конфигурации живёт в core/, горячий путь
 * в runtime/, транспорт в bus/. Этот файл только связывает их с nginx.
 */

#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"
#include "bus/ngx_http_waf_bus.h"
#include "local/ngx_http_waf_local.h"


static ngx_int_t ngx_http_waf_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_init_worker(ngx_cycle_t *cycle);
static void      ngx_http_waf_exit_worker(ngx_cycle_t *cycle);


/*
 * Реализованное подмножество директив из docs/directives/list/. Всё, что ещё не
 * реализовано, здесь отсутствует намеренно: неизвестная директива -- это ошибка
 * при nginx -t, тогда как принятая и проигнорированная -- это конфигурация,
 * которая выглядит рабочей и таковой не является.
 */
/*
 * Снятая директива: любой контекст из прежнего, любая арность -- обработчик
 * всё равно отвечает ошибкой с подсказкой. Смещение конфигурации не важно.
 */
#define NGX_HTTP_WAF_RETIRED(name, ctx, hint)                                  \
    { ngx_string(name), (ctx)|NGX_CONF_ANY, ngx_http_waf_retired, 0, 0, hint }

#define NGX_HTTP_WAF_CTX_ANY                                                   \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)


static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, enable),
      NULL },

    { ngx_string("waf_node_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, node_id),
      NULL },

    { ngx_string("waf_agent_socket"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, agent_socket),
      NULL },

    { ngx_string("waf_bus"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_bus,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_reply_max"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, reply_max),
      NULL },

    { ngx_string("waf_header_value_max"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, header_value_max),
      NULL },

    /*
     * Поле запроса, выбранное оператором. Модуль сам решает, что положить в
     * conn и http, и этот набор общий для всех контуров; всё остальное, от
     * $ssl_ja3 до заголовка балансировщика, знает только конфигурация.
     */
    { ngx_string("waf_var"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_var,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* --- инспекторы ------------------------------------------------------- */

    { ngx_string("waf_inspector"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_waf_inspector,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_inspect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_inspect,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_max_inflight"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, max_inflight),
      NULL },

    { ngx_string("waf_hold"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_hold,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* Только бюджет фазы: исход называет waf_exception. */
    { ngx_string("waf_deadline"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_waf_deadline,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Одна директива на все причины «вердикта нет»: класс необязательным
     * вторым словом, исход -- pass либо deny с записью каталога.
     */
    { ngx_string("waf_exception"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_exception,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_send"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_send,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_deny_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_phase_deny_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- скоринг ---------------------------------------------------------- */

    { ngx_string("waf_score_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
          |NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_waf_score_deny,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- ответы и цели ---------------------------------------------------- */

    { ngx_string("waf_deny_response"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_waf_deny_response,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_deny_response_default"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, deny_response_default),
      NULL },

    /*
     * Uuid пути из панели. Только location: на сервере он ничего не значил
     * бы, а унаследованный всеми путями -- врал бы. Вложенный уровень (if)
     * наследует значение блока, в котором стоит.
     */
    { ngx_string("waf_route_id"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, route_id),
      NULL },

    { ngx_string("waf_redirect_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_redirect_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_cookie_defaults"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_cookie_defaults,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- переписка инспекторов -------------------------------------------- */

    { ngx_string("waf_action_max"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, action_max),
      NULL },

    { ngx_string("waf_actions_max"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, actions_max),
      NULL },

    /* --- диагностика ------------------------------------------------------ */

    { ngx_string("waf_strip_accept_encoding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, strip_accept_encoding),
      NULL },

    { ngx_string("waf_debug_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, debug_header),
      NULL },

    /*
     * Что снимаем с запроса ради инспекции. Единственная ось разрешения:
     * прежний waf_request_body_access называл то же самое вторым словом и
     * снят -- headers, args и body обязаны перечисляться одинаково.
     */
    { ngx_string("waf_capture"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_capture,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Отдельного разрешения читать тело ответа нет: об этом говорит снимок.
     * Два выключателя на один вопрос означали бы маршрут, где waf_capture
     * response body= настроен, а тело всё равно не приезжает.
     */
    /* --- локальный слой --------------------------------------------------- */

    /*
     * Общая на воркеры зона: в ней живут circuit breaker, счётчики частоты и
     * наборы данных. Без неё локальный слой не существует -- директивы ниже
     * требуют её явного объявления, а не подразумевают размер по умолчанию.
     */
    { ngx_string("waf_shm_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_shm_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_local_rate"),
      /* 1MORE, а не 2MORE: "none" -- одно слово. Арность разбирает сам обработчик. */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_local_rate,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_local_dataset"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_waf_local_dataset,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_local_check"),
      /* 1MORE, а не 2MORE: "none" -- одно слово. Арность разбирает сам обработчик. */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_local_check,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- рукопожатие websocket-пути --------------------------------------- */

    { ngx_string("waf_require_upgrade"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_require_upgrade,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_ws_strip_extensions"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_ws_strip_extensions,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_audit_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_audit_frames,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- кадры: сборка, контрольные кадры, кеш вердикта -------------------- */

    { ngx_string("waf_frame_reassemble"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, frame_reassemble),
      NULL },

    { ngx_string("waf_frame_control_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_frame_control_rate,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_frame_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_frame_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- тело запроса ----------------------------------------------------- */

    /*
     * Единственный обменник контура. Конфигурация экземпляра принадлежит
     * драйверу: опции разбирает он сам, поэтому добавление драйвера не требует
     * правок ни здесь, ни в core/. Имени нет и выбора на маршруте нет --
     * горячее хранилище общее для всех нод, всех инспекторов и агента.
     */
    { ngx_string("waf_store"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_store_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /*
     * Внутренний Redis контура: пакеты и снапшоты активных наборов от keeper.
     * Тот же драйвер и те же опции, что у waf_store, но другой экземпляр:
     * боевой обменник и состояние наборов -- разные хранилища.
     */
    { ngx_string("waf_sets_store"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_waf_sets_store_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /*
     * Предел размещаемого тела и политика на превышение. Одной строкой по той
     * же причине, что и у дедлайна: размер без политики не описывает поведение,
     * а политика без размера не имеет к чему примениться.
     */
    { ngx_string("waf_body_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_waf_body_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_body_max_holds"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, body_max_holds),
      NULL },

    /*
     * Что из обменника не удалять, а передать агенту. Адреса архива здесь нет:
     * куда уедет объект, знает агент, на проводе едут срок хранения и предел
     * записи. Область называется первым словом -- пока только request.
     */
    { ngx_string("waf_archive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_waf_archive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Доля разрешённых запросов в аудите. Отказы, редиректы и запросы,
     * отдавшие объекты в архив, пишутся при любом значении -- см.
     * runtime/ngx_http_waf_audit.c.
     */
    { ngx_string("waf_audit_sample"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_audit_sample,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* --- превью для записи аудита ----------------------------------------- */

    /*
     * Срез запроса, который уезжает в саму запись, а не в обменник. Размер
     * пишется на объекте (headers=64k/2k): бюджеты у заголовков, параметров
     * и тела разные, потому что живут в разных единицах и режутся по-разному,
     * но вопрос один, и трёх директив он не стоит.
     *
     * Списки имён -- отдельными строками: allow= на строке с headers= и args=
     * не к чему отнести, а у args списков раньше не было вовсе.
     */
    { ngx_string("waf_preview"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_preview,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },


    /* --- снятые директивы ------------------------------------------------
     *
     * Имена, которых больше нет. Каждое -- ошибка nginx -t с подсказкой,
     * чем его заменили (ngx_http_waf_retired): молча игнорировать нельзя,
     * а "unknown directive" отправляет читать changelog.
     */

    NGX_HTTP_WAF_RETIRED("waf_inspector_allow_headers", NGX_HTTP_MAIN_CONF,
        "forbidden header list + sanitize; there is no allow-list"),

    NGX_HTTP_WAF_RETIRED("waf_inspector_allow_cookies", NGX_HTTP_MAIN_CONF,
        "waf_cookie_defaults; there is no allow-list"),

    NGX_HTTP_WAF_RETIRED("waf_request_inspectors", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect request <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_response_inspectors", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect response <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_request_inspect", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect request <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_response_inspect", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect response <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_frame_inspect", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect frame <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_frame_inspectors_c2s", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect frame:c2s <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_frame_inspectors_s2c", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect frame:s2c <name> wave=<n>"),

    NGX_HTTP_WAF_RETIRED("waf_inspector_mode", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspect request <name> wave=<n> mode=active|passive|off|vote"),

    NGX_HTTP_WAF_RETIRED("waf_inspector_profile", NGX_HTTP_WAF_CTX_ANY,
        "waf_inspector <name> subject=... profile=<profile>"),

    NGX_HTTP_WAF_RETIRED("waf_frame_mode", NGX_HTTP_WAF_CTX_ANY,
        "waf_hold frame gate|monitor"),

    NGX_HTTP_WAF_RETIRED("waf_frame_mode_c2s", NGX_HTTP_WAF_CTX_ANY,
        "waf_hold frame:c2s gate|monitor"),

    NGX_HTTP_WAF_RETIRED("waf_frame_mode_s2c", NGX_HTTP_WAF_CTX_ANY,
        "waf_hold frame:s2c gate|monitor"),

    NGX_HTTP_WAF_RETIRED("waf_response_buffer_max", NGX_HTTP_WAF_CTX_ANY,
        "waf_capture response body=<size>"),

    NGX_HTTP_WAF_RETIRED("waf_frame_deadline", NGX_HTTP_WAF_CTX_ANY,
        "waf_deadline frame 5ms block"),

    NGX_HTTP_WAF_RETIRED("waf_on_absent", NGX_HTTP_WAF_CTX_ANY,
        "waf_exception <phase> absent pass|deny [response=<name>]"),

    NGX_HTTP_WAF_RETIRED("waf_on_bus_error", NGX_HTTP_WAF_CTX_ANY,
        "waf_exception <phase> bus pass|deny [response=<name>]"),

    NGX_HTTP_WAF_RETIRED("waf_on_body_unavailable", NGX_HTTP_WAF_CTX_ANY,
        "waf_exception <phase> body pass|deny [response=<name>]"),

    NGX_HTTP_WAF_RETIRED("waf_on_frame_timeout", NGX_HTTP_WAF_CTX_ANY,
        "waf_deadline frame 5ms and waf_exception frame timeout deny"),

    NGX_HTTP_WAF_RETIRED("waf_response_deadline", NGX_HTTP_WAF_CTX_ANY,
        "waf_deadline response 50ms"),

    NGX_HTTP_WAF_RETIRED("waf_on_partial_rewrite", NGX_HTTP_WAF_CTX_ANY,
        "waf_send <phase> body=original|store -- a partial capture cannot be "
        "served from the store and fails per waf_exception <phase> body, "
        "there is no option to send a slice"),

    NGX_HTTP_WAF_RETIRED("waf_request_deadline", NGX_HTTP_WAF_CTX_ANY,
        "waf_deadline request 50ms"),

    NGX_HTTP_WAF_RETIRED("waf_on_timeout", NGX_HTTP_WAF_CTX_ANY,
        "waf_deadline request 50ms and waf_exception request timeout deny"),

    NGX_HTTP_WAF_RETIRED("waf_on_body_oversize", NGX_HTTP_WAF_CTX_ANY,
        "waf_body_limit 1m block|trim|pass -- the policy is the second word of "
        "the limit; \"truncate\" is now \"trim\""),

    NGX_HTTP_WAF_RETIRED("waf_request_deny_mode", NGX_HTTP_WAF_CTX_ANY,
        "waf_deny_mode request fast|deterministic"),

    NGX_HTTP_WAF_RETIRED("waf_response_deny_mode", NGX_HTTP_WAF_CTX_ANY,
        "waf_deny_mode response fast|deterministic"),

    NGX_HTTP_WAF_RETIRED("waf_response_score_deny", NGX_HTTP_WAF_CTX_ANY,
        "waf_score_deny response <n> [response=<name>]"),

    NGX_HTTP_WAF_RETIRED("waf_request_score_deny", NGX_HTTP_WAF_CTX_ANY,
        "waf_score_deny request <n> [response=<name>]"),

    NGX_HTTP_WAF_RETIRED("waf_request_body_access", NGX_HTTP_WAF_CTX_ANY,
        "waf_capture request headers args body"),

    NGX_HTTP_WAF_RETIRED("waf_response_body_access", NGX_HTTP_WAF_CTX_ANY,
        "waf_capture response body=<size>"),

    NGX_HTTP_WAF_RETIRED("waf_body_store", NGX_HTTP_MAIN_CONF,
        "waf_store driver=redis url=..."),

    NGX_HTTP_WAF_RETIRED("waf_body", NGX_HTTP_WAF_CTX_ANY,
        "waf_store in the http block; the store is no longer chosen per route"),

    NGX_HTTP_WAF_RETIRED("waf_frame_max_size", NGX_HTTP_WAF_CTX_ANY,
        "waf_body_limit frame 64k block"),

    NGX_HTTP_WAF_RETIRED("waf_message_max", NGX_HTTP_WAF_CTX_ANY,
        "waf_body_limit frame 256k block"),

    NGX_HTTP_WAF_RETIRED("waf_body_max", NGX_HTTP_WAF_CTX_ANY,
        "waf_body_limit 1m block"),

    NGX_HTTP_WAF_RETIRED("waf_body_inline_max", NGX_HTTP_WAF_CTX_ANY,
        "nothing: the hot path never read it, every object goes to waf_store"),

    NGX_HTTP_WAF_RETIRED("waf_request_archive", NGX_HTTP_WAF_CTX_ANY,
        "waf_archive request headers args body ttl=180d"),

    NGX_HTTP_WAF_RETIRED("waf_body_archive", NGX_HTTP_WAF_CTX_ANY,
        "waf_archive request headers args body ttl=180d"),

    NGX_HTTP_WAF_RETIRED("waf_headers_preview", NGX_HTTP_WAF_CTX_ANY,
        "waf_preview headers=30k/1k allow=content-type,user-agent"),

    NGX_HTTP_WAF_RETIRED("waf_args_preview", NGX_HTTP_WAF_CTX_ANY,
        "waf_preview args=8k/1k"),

    NGX_HTTP_WAF_RETIRED("waf_body_preview", NGX_HTTP_WAF_CTX_ANY,
        "waf_preview body=10k -- \"force\" is gone, a named preview is itself "
        "the requirement to extract"),

    NGX_HTTP_WAF_RETIRED("waf_headers_preview_allow", NGX_HTTP_WAF_CTX_ANY,
        "waf_preview headers=<size> allow=content-type,user-agent"),

    NGX_HTTP_WAF_RETIRED("waf_headers_preview_deny", NGX_HTTP_WAF_CTX_ANY,
        "waf_preview headers=<size> deny=x-api-key"),

      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_module_ctx = {
    ngx_http_waf_preconfiguration,     /* preconfiguration  */
    ngx_http_waf_postconfiguration,    /* postconfiguration */

    ngx_http_waf_create_main_conf,     /* create main configuration */
    ngx_http_waf_init_main_conf,       /* init main configuration   */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration  */

    ngx_http_waf_create_loc_conf,      /* create location configuration */
    ngx_http_waf_merge_loc_conf        /* merge location configuration  */
};


ngx_module_t  ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,          /* module context    */
    ngx_http_waf_commands,             /* module directives */
    NGX_HTTP_MODULE,                   /* module type       */
    NULL,                              /* init master       */
    NULL,                              /* init module       */
    ngx_http_waf_init_worker,          /* init process      */
    NULL,                              /* init thread       */
    NULL,                              /* exit thread       */
    ngx_http_waf_exit_worker,          /* exit process      */
    NULL,                              /* exit master       */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_waf_preconfiguration(ngx_conf_t *cf)
{
    /*
     * Драйверы регистрируются до разбора конфигурации: waf_store обязан найти
     * драйвер по имени уже при первом появлении директивы. Сторонний драйвер
     * регистрируется так же -- из preconfiguration своего модуля.
     */
    if (ngx_http_waf_body_drivers_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_waf_ctx_var_init(cf);
}


static ngx_int_t
ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_waf_main_conf_t   *wmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    /*
     * Не в init_main_conf: nginx вызывает его до слияния location conf, то есть
     * до того, как станет известно, какой store кем используется.
     */
    if (ngx_http_waf_body_validate_main(cf, wmcf) != NGX_CONF_OK) {
        return NGX_ERROR;
    }

    /*
     * Парность keep=/resume= -- по листьям дерева location, то есть после
     * того, как все слияния прошли и известно, у кого есть потомки.
     */
    if (ngx_http_waf_check_resume_pairs(cf, wmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* срез снимка против отдачи из обменника -- по тем же листьям. */
    if (ngx_http_waf_check_send_routes(cf, wmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * ACCESS_PHASE, а не PREACCESS: к этому моменту отработали limit_req и
     * limit_conn, то есть до шины не доходит трафик, отсечённый штатными
     * ограничителями nginx.
     */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_access_handler;

    if (ngx_http_waf_variables_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Фаза ответа живёт в фильтрах, а не в фазах: у ответа фаз нет. Порядок
     * регистрации обычный -- модуль встаёт наверх цепочки и видит заголовки
     * до того, как их увидит кто-либо ещё.
     */
    if (ngx_http_waf_filter_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return NGX_OK;                 /* http-блока нет либо waf не настроен */
    }

    if (ngx_http_waf_slot_table_init(cycle, wmcf->max_inflight) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Наборы привязываются к слотам зоны до подключения к шине: сообщение может
     * прийти сразу после рукопожатия, и привязка обязана быть готова раньше.
     */
    if (ngx_http_waf_dataset_bind(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_ds_stream_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Хранилища тел поднимаются до шины: волна с телом публикуется только
     * после размещения, и соединение с хранилищем должно быть готово раньше,
     * чем придёт первый запрос.
     */
    if (ngx_http_waf_body_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_audit_init_worker(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if (wmcf->bus != NULL) {
        ngx_http_waf_bus_t  *bus = wmcf->bus;

        if (ngx_http_waf_bus_inbox_build(bus, cycle, &wmcf->node_id) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_waf_presence_init(bus, cycle) != NGX_OK) {
            return NGX_ERROR;
        }

        if (bus->init_worker(bus, cycle) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_http_waf_exit_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return;
    }

    ngx_http_waf_body_exit_worker(cycle);
    ngx_http_waf_audit_exit_worker(cycle);

    if (wmcf->bus == NULL) {
        return;
    }

    ngx_http_waf_presence_stop(wmcf->bus);

    /*
     * Дренажа висящих вердиктов у транспорта нет (unsupported.md): запросы в
     * полёте при reload закрывает дедлайн фазы.
     */
    ((ngx_http_waf_bus_t *) wmcf->bus)->exit_worker(wmcf->bus, cycle);
}
