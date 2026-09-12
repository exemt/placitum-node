/*
 * Жизненный цикл объектов store: сбор, ключ, размещение драйвером, локатор.
 *
 * Драйверы за vtable, поэтому здесь нет ни одного слова про redis или файлы:
 * этот файл решает, нужен ли объект, что делать с превышением и как выглядит
 * локатор. Объектов три -- заголовки, строка запроса и тело, -- и все они
 * кладутся одним драйвером под своими ключами. Куда именно легли байты, знает
 * только драйвер.
 *
 * Спецификация: docs/body-storage.md.
 */

#include "body/ngx_http_waf_body.h"


#define NGX_HTTP_WAF_BODY_MAX_DRIVERS   8

/* Размер порции при чтении тела из файла. */
#define NGX_HTTP_WAF_BODY_CHUNK         4096


static ngx_int_t ngx_http_waf_body_decide(ngx_http_waf_ctx_t *ctx);
static ngx_chain_t *ngx_http_waf_body_source(ngx_http_waf_ctx_t *ctx);
static ngx_int_t ngx_http_waf_body_collect(ngx_http_waf_ctx_t *ctx,
    off_t total, off_t place);
static ngx_int_t ngx_http_waf_body_key(ngx_http_waf_ctx_t *ctx,
    ngx_str_t *key, ngx_str_t *suffix);
static ngx_uint_t ngx_http_waf_store_is_external(
    ngx_http_waf_body_store_t *store);
static ngx_int_t ngx_http_waf_headers_collect(ngx_http_waf_ctx_t *ctx,
    ngx_str_t *out);
static ngx_int_t ngx_http_waf_args_collect(ngx_http_waf_ctx_t *ctx,
    ngx_str_t *out);
static ngx_int_t ngx_http_waf_meta_place_one(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_int_t ngx_http_waf_meta_result(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_meta_on_put(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_store_del(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_body_op_t *op, ngx_uint_t keep);
static void ngx_http_waf_body_release_phase(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase);
static void ngx_http_waf_body_release_all(ngx_http_waf_ctx_t *ctx);
static ngx_uint_t ngx_http_waf_phase_follows(ngx_http_waf_ctx_t *ctx);
static ngx_uint_t ngx_http_waf_archive_kept(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase);
static char *ngx_http_waf_obj_names(ngx_uint_t mask);
static size_t ngx_http_waf_locator_object_size(ngx_http_waf_locator_t *loc);
static off_t ngx_http_waf_body_length(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_body_encoding(ngx_http_request_t *r,
    ngx_http_waf_locator_t *loc);
static void ngx_http_waf_body_encoding_out(ngx_http_request_t *r,
    ngx_http_waf_locator_t *loc);
static void ngx_http_waf_body_on_put(ngx_http_waf_body_op_t *op);
static void ngx_http_waf_body_cleanup(void *data);
static void ngx_http_waf_body_abandon(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_body_unavailable(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t reason, ngx_uint_t policy);
static char *ngx_http_waf_body_validate_phase(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase);
static ngx_uint_t ngx_http_waf_body_route_mask(ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase, ngx_http_waf_mask_t *mask);
static ngx_uint_t ngx_http_waf_name_listed(ngx_array_t *list, ngx_str_t *name);
static void ngx_http_waf_capture_hash(ngx_str_t *src, u_char hex[64]);
static ngx_int_t ngx_http_waf_args_filter(ngx_http_request_t *r, ngx_str_t *src,
    ngx_array_t *deny, ngx_array_t *mask, ngx_str_t *out);
static size_t ngx_http_waf_store_need(ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase,
    ngx_uint_t obj);
static size_t ngx_http_waf_ovr_reload_need(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static size_t ngx_http_waf_reload_size(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static size_t ngx_http_waf_store_need_ctx(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_uint_t ngx_http_waf_archive_may_take(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj);
static ngx_uint_t ngx_http_waf_reload_need(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj);
static ngx_int_t ngx_http_waf_meta_place_blob(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj, ngx_str_t *blob);
static ngx_int_t ngx_http_waf_meta_reload_one(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t obj);
static ngx_uint_t ngx_http_waf_body_reload_wider(ngx_http_waf_ctx_t *ctx);
static void ngx_http_waf_jw_namelist(ngx_http_waf_jw_t *jw, const char *field,
    ngx_array_t *list);


/*
 * Реестр драйверов. Массив, а не список: драйверов единицы, поиск бывает только
 * при разборе конфигурации, и регистрация из preconfiguration стороннего модуля
 * не должна ничего аллоцировать.
 */
static ngx_http_waf_body_driver_t
    *ngx_http_waf_body_drivers[NGX_HTTP_WAF_BODY_MAX_DRIVERS];
static ngx_uint_t  ngx_http_waf_body_ndrivers;

/*
 * Число тел, размещённых этим воркером и ещё не удалённых. Ограничитель не про
 * размер одного тела, а про суммарный объём в полёте: без него медленный
 * инспектор превращает любой всплеск загрузок в исчерпание памяти хранилища.
 */
static ngx_uint_t  ngx_http_waf_body_holds;


static ngx_str_t  ngx_http_waf_body_unavail_names[] = {
    ngx_string("available"),
    ngx_string("oversize"),
    ngx_string("store_error"),
    ngx_string("store_unconfigured")
};


/* Суффикс ключа. Короткий: ключ читают глазами при разборе инцидентов. */
static ngx_str_t  ngx_http_waf_body_phase_tag[] = {
    ngx_string("req"),
    ngx_string("rsp"),
    ngx_string("frm"),
    ngx_string("frm")
};


static ngx_str_t  ngx_http_waf_body_content_encoding =
    ngx_string("content-encoding");


/*
 * Значение поля store в локаторе. Это ярус, а не имя экземпляра: обменник в
 * контуре один, называть нечего, а различать "лежит в горячем" и "уехало в
 * архив" читателю записи всё равно необходимо -- второе ставит агент.
 */
static ngx_str_t  ngx_http_waf_store_hot = ngx_string("hot");


#define ngx_http_waf_hdr_room(len)   ((len) * 6 + 8)


/*
 * Описание объекта обменника. Суффикс ключа короткий: ключ читают глазами при
 * разборе инцидентов. Имя поля -- то же самое и в сообщении инспектору, и в
 * секции store аудита, иначе одно и то же место в запросе называлось бы в
 * контуре двумя словами.
 */
typedef struct {
    ngx_str_t    name;                 /* поле в секции store              */
    ngx_str_t    suffix;               /* суффикс ключа; тело -- без него  */
    ngx_int_t  (*collect)(ngx_http_waf_ctx_t *ctx, ngx_str_t *out);
} ngx_http_waf_obj_t;


static ngx_http_waf_obj_t  ngx_http_waf_objs[NGX_HTTP_WAF_OBJ_COUNT] = {
    { ngx_string("headers"), ngx_string("hdr"), ngx_http_waf_headers_collect },
    { ngx_string("args"),    ngx_string("arg"), ngx_http_waf_args_collect    },
    { ngx_string("body"),    ngx_null_string,   NULL                         }
};


/*
 * Сколько байт объекта кладётся до волн: снимок, ровно то, что видят
 * инспекторы. Без "=" у capture -- весь объект (как прочитали). Ноль --
 * класть некого.
 *
 * Архив и превью размещение снимка не расширяют: их оригинал докладывает
 * reload уже после вердикта (ngx_http_waf_reload_size), когда известно, нужен
 * ли он кому-то вообще. Снимок в 4k при архиве в 128k стоит волне ровно 4k, а
 * на исходе, где архив объект не берёт, 128k не кладутся вовсе.
 */
static size_t
ngx_http_waf_store_need(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase,
    ngx_uint_t obj)
{
    size_t                      need, one;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[phase];

    need = 0;

    if (sh->capture & NGX_HTTP_WAF_OBJ_BIT(obj)) {
        one = sh->capture_limit[obj];

        if (one == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE) {
            return (size_t) -1;
        }

        if (one > need) {
            need = one;
        }
    }

    /*
     * У кадра масок нет, и весь кадр лежит в буфере до вердикта: снимок, архив
     * и превью -- три независимых окна в один и тот же буфер, а не оригинал за
     * срезом. Поэтому архив и превью кадра расширяют размещение сами, без
     * reload: инспектору локатор всё равно режется по capture (store section),
     * а агенту и записи достаётся столько, сколько названо им.
     */
    if (ngx_http_waf_phase_is_frame(phase)) {

        if (sh->archive & NGX_HTTP_WAF_OBJ_BIT(obj)) {
            one = sh->archive_limit[obj];

            if (one == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE) {
                return (size_t) -1;
            }

            if (one > need) {
                need = one;
            }
        }

        if (sh->preview[obj] > need) {
            need = sh->preview[obj];
        }
    }

    return need;
}


/*
 * Сколько оригинала просит положить сосед (глаголы записи с
 * source original): у archive -- предел просьбы либо целиком, у audit --
 * бюджет превью (предел просьбы либо маршрута). Ноль -- просьба объекта не
 * касается. Считается в момент перекладки, когда все волны уже ответили.
 */
static size_t
ngx_http_waf_ovr_reload_need(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    size_t                      need, one;
    ngx_http_waf_ovr_part_t    *part;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    need = 0;
    part = &ngx_http_waf_audit_ovr_cur(ctx)->archive;

    if (ngx_http_waf_ovr_original(part, obj)) {
        need = (part->has_limit & NGX_HTTP_WAF_OBJ_BIT(obj))
               ? part->limit[obj] : (size_t) -1;
    }

    part = &ngx_http_waf_audit_ovr_cur(ctx)->audit;

    if (ngx_http_waf_ovr_original(part, obj)) {
        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
        sh   = &wlcf->shoot[ctx->phase];
        one  = (part->has_limit & NGX_HTTP_WAF_OBJ_BIT(obj))
               ? part->limit[obj] : sh->preview[obj];

        if (need != (size_t) -1 && one > need) {
            need = one;
        }
    }

    return need;
}


/*
 * Сколько оригинала докладывает reload: максимум строк reload маршрута
 * (archive, preview; "=capture" -- в размере снимка) и просьбы соседа.
 * Целиком -- (size_t) -1, ноль -- оригинал никто не просил.
 */
static size_t
ngx_http_waf_reload_size(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    size_t                      need, one;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];
    need = 0;

    if (sh->archive_reload & NGX_HTTP_WAF_OBJ_BIT(obj)) {
        one = sh->archive_reload_limit[obj];

        if (one == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE) {
            one = sh->capture_limit[obj];
        }

        if (one == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE
            || one == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE)
        {
            return (size_t) -1;
        }

        if (one > need) {
            need = one;
        }
    }

    if (sh->preview_reload & NGX_HTTP_WAF_OBJ_BIT(obj)) {
        one = sh->preview_reload_limit[obj];

        if (one == NGX_HTTP_WAF_RELOAD_LIMIT_CAPTURE) {
            one = sh->capture_limit[obj];
        }

        if (one == NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE
            || one == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE)
        {
            return (size_t) -1;
        }

        if (one > need) {
            need = one;
        }
    }

    one = ngx_http_waf_ovr_reload_need(ctx, obj);

    if (one == (size_t) -1) {
        return (size_t) -1;
    }

    return one > need ? one : need;
}


/*
 * Размер put по месту: до волн -- снимок, при перекладке перед агентом
 * (reloading) -- оригинал в размере reload. Сборщики объектов и решение о
 * теле зовут это, не зная, который из двух put они делают.
 */
static size_t
ngx_http_waf_store_need_ctx(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->ph->reloading) {
        return ngx_http_waf_reload_size(ctx, obj);
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return ngx_http_waf_store_need(wlcf, ctx->phase, obj);
}


/*
 * Стоит ли докладывать оригинал ради архива. На исходе, на котором архив
 * объект не берёт, класть его незачем -- ключ всё равно уйдёт под DEL, а
 * это и есть весь трафик маршрута с when=deny. Пока исход не маршрутный
 * (впереди фаза ответа, чей отказ считается и объектам запроса) либо его
 * ещё может сорвать подъём подмены (waf_send request body=store читает
 * обменник уже после reload, и сбой при политике block -- отказ), оригинал
 * кладётся: лишний put дешевле архива без оригинала.
 */
static ngx_uint_t
ngx_http_waf_archive_may_take(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj)
{
    ngx_uint_t                  verdict;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    if (ngx_http_waf_phase_follows(ctx)) {
        return 1;
    }

    if (ctx->phase == NGX_HTTP_WAF_PHASE_REQUEST
        && ngx_http_waf_send_of(wlcf, ctx->phase, NGX_HTTP_WAF_OBJ_BODY)
           == NGX_HTTP_WAF_SEND_STORE)
    {
        return 1;
    }

    verdict = ngx_http_waf_route_verdict(ctx);

    return (sh->archive_when[obj] & (1u << verdict)) != 0;
}


/*
 * Что перекладывать перед агентом. Объект, оригинала которого никто не
 * просил, не трогаем: инспекторы волны уже закрыты, а агенту и записи
 * хватит того, что лежит.
 *
 * Reload велит либо маршрут (waf_archive/waf_preview reload), либо сосед
 * просьбой записи с source original; просьба "как снято" глушит
 * reload маршрута у названных объектов. Оригинал только ради архива не
 * кладётся на исходе, где архив объект не берёт.
 */
static ngx_uint_t
ngx_http_waf_reload_need(ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t obj)
{
    ngx_uint_t                  store_only;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[ctx->phase];

    if (ngx_http_waf_reload_size(ctx, obj) == 0) {
        return 0;
    }

    if (ngx_http_waf_ovr_reload_need(ctx, obj) != 0) {
        return 1;
    }

    store_only = ngx_http_waf_ovr_store(&ngx_http_waf_audit_ovr_cur(ctx)->archive,
                                       obj)
                 || ngx_http_waf_ovr_store(&ngx_http_waf_audit_ovr_cur(ctx)->audit,
                                          obj);

    if (store_only) {
        return 0;
    }

    if (sh->preview_reload & NGX_HTTP_WAF_OBJ_BIT(obj)) {
        return 1;
    }

    if (!(sh->archive_reload & NGX_HTTP_WAF_OBJ_BIT(obj))) {
        return 0;
    }

    return ngx_http_waf_archive_may_take(ctx, wlcf, obj);
}


/*
 * Маска объектов словами, для сообщения об ошибке конфигурации. Оператору надо
 * прочитать, чего именно не хватает, а не сопоставлять биты. Буфер статический
 * и это осознанно: функция вызывается только при разборе конфигурации, из
 * одного потока, и ровно один раз перед отказом загрузиться.
 */
static char *
ngx_http_waf_obj_names(ngx_uint_t mask)
{
    static u_char  buf[64];

    ngx_uint_t   i;
    u_char      *p;

    p = buf;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (p != buf) {
            *p++ = ',';
            *p++ = ' ';
        }

        p = ngx_copy(p, ngx_http_waf_objs[i].name.data,
                     ngx_http_waf_objs[i].name.len);
    }

    *p = '\0';

    return (char *) buf;
}


/* --- реестр --------------------------------------------------------------- */

ngx_int_t
ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_t *drv)
{
    if (ngx_http_waf_body_driver_find(&drv->name) != NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_waf_body_ndrivers >= NGX_HTTP_WAF_BODY_MAX_DRIVERS) {
        return NGX_ERROR;
    }

    ngx_http_waf_body_drivers[ngx_http_waf_body_ndrivers++] = drv;

    return NGX_OK;
}


ngx_http_waf_body_driver_t *
ngx_http_waf_body_driver_find(ngx_str_t *name)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_http_waf_body_ndrivers; i++) {
        if (ngx_http_waf_body_drivers[i]->name.len == name->len
            && ngx_memcmp(ngx_http_waf_body_drivers[i]->name.data, name->data,
                          name->len) == 0)
        {
            return ngx_http_waf_body_drivers[i];
        }
    }

    return NULL;
}


ngx_int_t
ngx_http_waf_body_drivers_init(ngx_conf_t *cf)
{
    if (ngx_http_waf_body_ndrivers != 0) {
        return NGX_OK;                 /* повторная загрузка конфигурации */
    }

    if (ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_none())
            != NGX_OK
        || ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_inline())
            != NGX_OK
        || ngx_http_waf_body_driver_register(ngx_http_waf_body_driver_redis())
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* --- директивы ------------------------------------------------------------ */

/*
 * waf_store driver=<driver> [опции драйвера];
 *
 * Обменник в контуре один, и потому у него нет имени: называют то, из чего
 * выбирают. Маршрут его не выбирает и не может от него отказаться -- горячее
 * хранилище общее для всех нод, всех инспекторов и агента, и локальное
 * "здесь другое" означало бы, что объект, найденный по локатору на одной
 * ноде, не находится на другой.
 */
static char *
ngx_http_waf_store_parse(ngx_conf_t *cf, ngx_http_waf_body_store_t **target,
    const char *directive)
{
    char                        *rv;
    ngx_str_t                   *args, name, value;
    ngx_uint_t                   i;
    ngx_http_waf_body_store_t   *store;
    ngx_http_waf_body_driver_t  *drv;

    args = cf->args->elts;

    if (*target != NULL) {
        return "is duplicate";
    }

    /*
     * driver= разбирается до остальных опций, а не по порядку: конфигурацию
     * экземпляра создаёт сам драйвер, и до того, как он известен, опции
     * складывать некуда.
     */
    drv = NULL;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_http_waf_split(&args[i], &name, &value) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: invalid option \"%V\" in %s, "
                               "expected key=value", &args[i], directive);
            return NGX_CONF_ERROR;
        }

        if (name.len == 6 && ngx_strncmp(name.data, "driver", 6) == 0) {

            drv = ngx_http_waf_body_driver_find(&value);
            if (drv == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "waf: unknown store driver \"%V\"", &value);
                return NGX_CONF_ERROR;
            }

            break;
        }
    }

    if (drv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: %s has no driver=", directive);
        return NGX_CONF_ERROR;
    }

    store = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_body_store_t));
    if (store == NULL) {
        return NGX_CONF_ERROR;
    }

    store->driver = drv;

    if (drv->create_conf != NULL) {
        store->conf = drv->create_conf(cf);
        if (store->conf == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        (void) ngx_http_waf_split(&args[i], &name, &value);

        if (name.len == 6 && ngx_strncmp(name.data, "driver", 6) == 0) {
            continue;
        }

        if (drv->set_option == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: store driver \"%V\" takes no options",
                               &drv->name);
            return NGX_CONF_ERROR;
        }

        rv = drv->set_option(cf, store->conf, &name, &value);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    *target = store;

    if (drv->validate_conf != NULL) {
        return drv->validate_conf(cf, store->conf);
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_store_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    return ngx_http_waf_store_parse(cf, &wmcf->body_store, "waf_store");
}


char *
ngx_http_waf_sets_store_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    char  *rv;

    rv = ngx_http_waf_store_parse(cf, &wmcf->sets_store, "waf_sets_store");
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!(wmcf->sets_store->driver->caps & NGX_HTTP_WAF_BODY_CAP_GET)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_sets_store driver \"%V\" cannot read "
                           "objects", &wmcf->sets_store->driver->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_waf_sets_get(ngx_str_t *key, off_t max, ngx_pool_t *pool,
    ngx_log_t *log, void (*handler)(ngx_http_waf_body_op_t *op), void *data,
    ngx_http_waf_body_op_t **out)
{
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_body_store_t  *store;
    ngx_http_waf_main_conf_t   *wmcf;

    *out = NULL;

    wmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->sets_store == NULL) {
        return NGX_ERROR;
    }

    store = wmcf->sets_store;

    if (store->driver->get == NULL) {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf  = store->conf;
    op->pool        = pool;
    op->log         = log;
    op->locator.key = *key;
    op->len         = max;
    op->handler     = handler;
    op->data_ctx    = data;
    op->status      = NGX_ERROR;

    *out = op;

    return store->driver->get(op);
}


/* --- валидация ------------------------------------------------------------ */

char *
ngx_http_waf_body_validate(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf)
{
    char        *rv;
    ngx_uint_t   phase;

    if (!wlcf->enable) {
        return NGX_CONF_OK;
    }

    /*
     * Каждая фаза кладёт своё и в свой срок. Проверяется поэтому каждая: у
     * фазы ответа свой снимок, свой архив и свой срок волны, и обменник, которого
     * хватало запросу, ответу может не подойти. Фазы, на которых ничего не
     * настроено, выходят на подсчёте нужного -- класть по ним нечего.
     */
    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        rv = ngx_http_waf_body_validate_phase(cf, wmcf, wlcf, phase);

        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_body_validate_phase(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_uint_t phase)
{
    ngx_uint_t                   i, need, want_meta;
    ngx_str_t                   *pname;
    ngx_http_waf_wave_t         *waves;
    ngx_http_waf_body_store_t   *store;
    ngx_http_waf_body_driver_t  *drv;
    ngx_http_waf_shoot_conf_t   *sh;

    sh    = &wlcf->shoot[phase];
    pname = ngx_http_waf_phase_name(phase);

    store = wmcf->body_store;

    if (sh->archive != 0) {

        if (wlcf->waves[phase] == NULL || wlcf->waves[phase]->nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive %V needs inspectors on the "
                               "route; inspect none leaves nothing to archive "
                               "after", pname);
            return NGX_CONF_ERROR;
        }

        /*
         * Забирает объекты агент. Без сокета до него не дойдёт ни одна запись
         * аудита, значит и владение передавать некому: ключи доживали бы до
         * retain_ttl и умирали непрочитанными, а конфигурация выглядела бы
         * сохраняющей.
         */
        if (wmcf->agent_socket.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive needs waf_agent_socket: the "
                               "agent is what moves objects to the archive and "
                               "cleans the store");
            return NGX_CONF_ERROR;
        }

        /*
         * Архивация -- это отложенное чтение чужим процессом. Инлайн живёт в
         * сообщении и умирает вместе с ним, none не кладёт вовсе: агенту не по
         * чему прийти, и объявленная архивация была бы конфигурацией, которая
         * выглядит сохраняющей и ничего не сохраняет.
         */
        if (!ngx_http_waf_store_is_external(store)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: waf_archive requires waf_store with an "
                               "external driver (not none/inline)");
            return NGX_CONF_ERROR;
        }

        if (!(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: store driver \"%V\" has no remote readers "
                               "capability, so the agent cannot pick up what "
                               "waf_archive keeps",
                               &store->driver->name);
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Обменник нужен тем, кто реально кладёт объекты: инспекторам -- то, что
     * в capture; агенту -- archive и preview body. Маршрут без инспекторов
     * и без этих осей обменник не трогает, даже если дефолтный capture
     * inherited (headers args).
     */
    need  = NGX_HTTP_WAF_BODY_NONE;
    waves = (wlcf->waves[phase] != NULL) ? wlcf->waves[phase]->elts : NULL;
    want_meta = 0;

    for (i = 0; waves != NULL && i < wlcf->waves[phase]->nelts; i++) {
        if (waves[i].body_need > need) {
            need = waves[i].body_need;
        }

        want_meta |= waves[i].obj_need
                     & (NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
                        | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS));
    }

    want_meta |= sh->archive
                 & (NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
                    | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS));

    if ((sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
        && waves != NULL && wlcf->waves[phase]->nelts != 0
        && need < NGX_HTTP_WAF_BODY_FULL)
    {
        need = NGX_HTTP_WAF_BODY_FULL;
    }

    if ((sh->archive & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
        && need < NGX_HTTP_WAF_BODY_FULL)
    {
        need = NGX_HTTP_WAF_BODY_FULL;
    }

    if (sh->preview[NGX_HTTP_WAF_OBJ_BODY] != 0
        && need == NGX_HTTP_WAF_BODY_NONE)
    {
        need = NGX_HTTP_WAF_BODY_PREVIEW;
    }

    if (need == NGX_HTTP_WAF_BODY_NONE && want_meta == 0) {
        return NGX_CONF_OK;
    }

    if (!ngx_http_waf_store_is_external(store)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: this route places %s, which needs waf_store "
                           "with an external driver (not none/inline)",
                           ngx_http_waf_obj_names(
                               want_meta
                               | ((need != NGX_HTTP_WAF_BODY_NONE)
                                  ? NGX_HTTP_WAF_OBJ_BIT(
                                        NGX_HTTP_WAF_OBJ_BODY)
                                  : 0)));
        return NGX_CONF_ERROR;
    }

    drv = store->driver;

    if (need != NGX_HTTP_WAF_BODY_NONE
        && drv->max_object != 0
        && (off_t) wlcf->body_limit[phase] > drv->max_object)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_body_limit %V %uz exceeds the %O byte "
                           "object limit of store driver \"%V\"",
                           pname, wlcf->body_limit[phase],
                           drv->max_object, &drv->name);
        return NGX_CONF_ERROR;
    }

    {
        ngx_http_waf_mask_t  used;

        if (!(drv->caps & NGX_HTTP_WAF_BODY_CAP_REMOTE_READERS)
            && ngx_http_waf_body_route_mask(wlcf, phase, &used))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: this route places objects for inspectors, "
                               "but store driver \"%V\" has no remote readers "
                               "capability", &drv->name);
            return NGX_CONF_ERROR;
        }
    }

    if (!(drv->caps & NGX_HTTP_WAF_BODY_CAP_TTL)
        && !(drv->caps & NGX_HTTP_WAF_BODY_CAP_DELETE))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "waf: store driver \"%V\" supports neither ttl nor "
                           "delete; placed objects will accumulate",
                           &drv->name);
    }

    return NGX_CONF_OK;
}


char *
ngx_http_waf_body_validate_main(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf)
{
    (void) cf;
    (void) wmcf;

    /*
     * Обменнику больше нечего проверять здесь: он один, объявлен или нет, и
     * "объявлен, но никем не используется" перестало быть возможным состоянием
     * -- ссылаться на него неоткуда.
     */
    return NGX_CONF_OK;
}


static ngx_uint_t
ngx_http_waf_body_route_mask(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase,
    ngx_http_waf_mask_t *mask)
{
    ngx_uint_t            i;
    ngx_http_waf_wave_t  *waves;

    *mask = 0;

    if (wlcf->waves[phase] == NULL) {
        return 0;
    }

    waves = wlcf->waves[phase]->elts;

    for (i = 0; i < wlcf->waves[phase]->nelts; i++) {
        *mask |= waves[i].all;
    }

    return (*mask != 0);
}


static ngx_uint_t
ngx_http_waf_store_is_external(ngx_http_waf_body_store_t *store)
{
    ngx_str_t  *name;

    if (store == NULL || store->driver == NULL) {
        return 0;
    }

    name = &store->driver->name;

    if (name->len == 4 && ngx_strncmp(name->data, "none", 4) == 0) {
        return 0;
    }

    if (name->len == 6 && ngx_strncmp(name->data, "inline", 6) == 0) {
        return 0;
    }

    return 1;
}


/* --- воркер --------------------------------------------------------------- */

static ngx_int_t
ngx_http_waf_store_init_worker(ngx_cycle_t *cycle,
    ngx_http_waf_body_store_t *store)
{
    if (store == NULL || store->driver->init_worker == NULL) {
        return NGX_OK;
    }

    return store->driver->init_worker(cycle, store->conf);
}


ngx_int_t
ngx_http_waf_body_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t   *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return NGX_OK;
    }

    ngx_http_waf_body_holds = 0;

    if (ngx_http_waf_store_init_worker(cycle, wmcf->body_store) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Состояние наборов -- свой экземпляр драйвера, свои соединения. */
    return ngx_http_waf_store_init_worker(cycle, wmcf->sets_store);
}


static void
ngx_http_waf_store_exit_worker(ngx_cycle_t *cycle,
    ngx_http_waf_body_store_t *store)
{
    if (store != NULL && store->driver->exit_worker != NULL) {
        store->driver->exit_worker(cycle, store->conf);
    }
}


void
ngx_http_waf_body_exit_worker(ngx_cycle_t *cycle)
{
    ngx_http_waf_main_conf_t   *wmcf;

    wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_module);

    if (wmcf == NULL) {
        return;
    }

    ngx_http_waf_store_exit_worker(cycle, wmcf->body_store);
    ngx_http_waf_store_exit_worker(cycle, wmcf->sets_store);
}


/* --- горячий путь --------------------------------------------------------- */

ngx_uint_t
ngx_http_waf_body_wave_need(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    waves = wlcf->waves[ctx->phase];

    if (waves == NULL || wave >= waves->nelts) {
        return NGX_HTTP_WAF_BODY_NONE;
    }

    /*
     * Пересечение с waf_capture уже учтено при построении волн: разрешения
     * маршрута -- свойство конфигурации, и проверять их на каждом запросе
     * значило бы считать одно и то же заново.
     */
    return ((ngx_http_waf_wave_t *) waves->elts)[wave].body_need;
}


ngx_uint_t
ngx_http_waf_meta_wave_need(ngx_http_waf_ctx_t *ctx, ngx_uint_t wave)
{
    ngx_uint_t                need, meta;
    ngx_array_t              *waves;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    meta = NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_HEADERS)
           | NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_ARGS);

    waves = wlcf->waves[ctx->phase];

    need = 0;

    if (waves != NULL && wave < waves->nelts) {
        need = ((ngx_http_waf_wave_t *) waves->elts)[wave].obj_need & meta;
    }

    return need;
}


/*
 * Заголовки и строка запроса -- одним заходом цикла событий. Драйвер
 * складывает команды в свой буфер и отправляет их не дожидаясь ответов,
 * поэтому второй объект не платит своего round-trip: к хранилищу мы ходим
 * столько же раз, сколько ходили за одними заголовками.
 *
 * Отсюда и счётчик незакрытых операций вместо флага: пока он не ноль, ответ
 * получен не на все, и публиковать волну рано.
 */
ngx_int_t
ngx_http_waf_meta_place(ngx_http_waf_ctx_t *ctx, ngx_uint_t need)
{
    ngx_uint_t  i;

    /*
     * Решение принято здесь и навсегда: обработчик фазы входит повторно после
     * каждого асинхронного ответа, и без этого признака объекты размещались бы
     * заново на каждом входе.
     */
    ctx->ph->meta_settled = 1;

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (!(need & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (ngx_http_waf_meta_place_one(ctx, i) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx->ph->meta_pending != 0) {
        return NGX_AGAIN;
    }

    return ngx_http_waf_meta_result(ctx);
}


/*
 * Итог размещения метаобъектов. Недоступность любого из них решается одной
 * политикой маршрута: инспектор, которому обещали заголовки, одинаково слеп и
 * когда их не положили, и когда не положили строку запроса.
 */
static ngx_int_t
ngx_http_waf_meta_result(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  i;

    if (ctx->ph->body_policy != NGX_HTTP_WAF_POLICY_BLOCK) {
        return NGX_OK;
    }

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (ctx->ph->meta[i] != NULL
            && ctx->ph->meta[i]->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_meta_place_one(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    ngx_str_t  blob;

    if (ctx->ph->meta[obj] != NULL) {
        return NGX_OK;
    }

    if (ngx_http_waf_objs[obj].collect(ctx, &blob) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_waf_meta_place_blob(ctx, obj, &blob);
}


/* Собранный объект -- в обменник. Сборка отдельно: reload сверяет её с тем, что лежит. */
static ngx_int_t
ngx_http_waf_meta_place_blob(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj,
    ngx_str_t *blobp)
{
    ngx_int_t                   rc;
    ngx_str_t                   key, blob;
    ngx_uint_t                  pending;
    ngx_pool_cleanup_t         *cln;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_locator_t     *loc;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    blob = *blobp;

    /*
     * Класть нечего: строки запроса в запросе не было. Это не недоступность,
     * поэтому локатора нет вовсе -- инспектор получит null и не обязан
     * различать "не прислали" и "не смогли положить".
     */
    if (blob.len == 0) {
        return NGX_OK;
    }

    ctx->ph->store_blob[obj] = blob;

    loc = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_locator_t));
    if (loc == NULL) {
        return NGX_ERROR;
    }

    ctx->ph->meta[obj] = loc;

    loc->size     = (off_t) blob.len;
    loc->complete = 1;

    wlcf  = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh    = &wlcf->shoot[ctx->phase];
    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    if (!ngx_http_waf_store_is_external(store)) {
        loc->unavailable = NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED;
        ctx->ph->body_policy = wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY];
        return NGX_OK;
    }

    if (ngx_http_waf_body_holds >= wmcf->body_max_holds) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: waf_body_max_holds %ui reached, %V not placed",
                      wmcf->body_max_holds, &ngx_http_waf_objs[obj].name);
        loc->unavailable = NGX_HTTP_WAF_BODY_STORE_ERROR;
        ctx->ph->body_policy = wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY];
        return NGX_OK;
    }

    if (ngx_http_waf_body_key(ctx, &key, &ngx_http_waf_objs[obj].suffix)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf   = store->conf;
    op->pool         = r->pool;
    op->log          = r->connection->log;
    op->rid.data     = ctx->rid_hex;
    op->rid.len      = NGX_HTTP_WAF_RID_HEX_LEN;
    op->phase        = ctx->phase;
    op->obj          = obj;
    op->len          = (off_t) blob.len;
    op->data         = blob;
    op->handler      = ngx_http_waf_meta_on_put;
    op->data_ctx     = ctx;
    op->retain       = (sh->archive & NGX_HTTP_WAF_OBJ_BIT(obj)) ? 1 : 0;

    op->locator        = *loc;
    op->locator.store  = ngx_http_waf_store_hot;
    op->locator.driver = store->driver->name;
    op->locator.key    = key;
    op->locator.size   = (off_t) blob.len;

    if (!ctx->ph->store_cleanup) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_body_cleanup;
        cln->data    = ctx;
        ctx->ph->store_cleanup = 1;
    }

    op->hold = (ctx->ph->meta_op[obj] == NULL);
    ctx->ph->meta_op[obj] = op;

    if (op->hold) {
        ngx_http_waf_body_holds++;
    }

    /*
     * Драйвер имеет право вызвать колбэк изнутри put: соединение может
     * оказаться оборванным ровно в момент отправки. Счётчик до и после
     * различает этот случай от настоящего асинхронного ответа надёжнее флага --
     * объектов в полёте бывает больше одного.
     */
    pending = ++ctx->ph->meta_pending;

    ctx->ph->meta_in_put = 1;
    rc = store->driver->put(op);
    ctx->ph->meta_in_put = 0;

    if (rc != NGX_AGAIN && ctx->ph->meta_pending == pending) {
        ngx_http_waf_meta_on_put(op);
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_waf_name_listed(ngx_array_t *list, ngx_str_t *name)
{
    ngx_str_t   *item;
    ngx_uint_t   i;

    if (list == NULL || list->nelts == 0) {
        return 0;
    }

    item = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (item[i].len == name->len
            && ngx_strncasecmp(item[i].data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void
ngx_http_waf_capture_hash(ngx_str_t *src, u_char hex[64])
{
    u_char                 digest[32];
    ngx_http_waf_sha256_t  sha;

    ngx_http_waf_sha256_init(&sha);
    ngx_http_waf_sha256_update(&sha, src->data, src->len);
    ngx_http_waf_sha256_final(&sha, digest);
    (void) ngx_hex_dump(hex, digest, 32);
}


/*
 * Заголовки фазы парами. У запроса источник -- r->headers_in, у ответа --
 * пары, собранные при входе в фазу: список headers_out плюс поля, которые
 * nginx держит отдельно (content-type, длина).
 *
 * Обе фазы приводятся к одному массиву пар, и дальше код один: форма объекта в
 * обменнике и списки mask= / deny= у фаз общие, а два почти одинаковых цикла
 * однажды разошлись бы ровно в маскировании.
 */
ngx_array_t *
ngx_http_waf_header_pairs(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t           i;
    ngx_keyval_t        *kv;
    ngx_array_t         *pairs;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        return ngx_http_waf_response_headers(ctx);
    }

    pairs = ngx_array_create(r->pool, 16, sizeof(ngx_keyval_t));
    if (pairs == NULL) {
        return NULL;
    }

    part = &r->headers_in.headers.part;
    h    = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        kv = ngx_array_push(pairs);
        if (kv == NULL) {
            return NULL;
        }

        kv->key   = h[i].key;
        kv->value = h[i].value;
    }

    return pairs;
}


static ngx_int_t
ngx_http_waf_headers_collect(ngx_http_waf_ctx_t *ctx, ngx_str_t *out)
{
    size_t                    size, limit, vroom;
    u_char                   *buf, *mark, hex[64];
    ngx_str_t                 value;
    ngx_uint_t                i, first;
    ngx_keyval_t             *kv;
    ngx_array_t              *pairs, *mask, *deny;
    ngx_http_waf_jw_t         jw;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    wlcf  = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh    = &wlcf->shoot[ctx->phase];
    limit = ngx_http_waf_store_need_ctx(ctx, NGX_HTTP_WAF_OBJ_HEADERS);

    mask = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_HEADERS]
                    [NGX_HTTP_WAF_AXIS_MASK];
    deny = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_HEADERS]
                    [NGX_HTTP_WAF_AXIS_DENY];

    if (limit == (size_t) -1) {
        limit = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
    }

    pairs = ngx_http_waf_header_pairs(ctx);
    if (pairs == NULL) {
        return NGX_ERROR;
    }

    kv   = pairs->elts;
    size = 2;

    for (i = 0; i < pairs->nelts; i++) {

        vroom = ngx_http_waf_hdr_room(kv[i].value.len);

        if (mask != NULL && mask->nelts != 0
            && vroom < ngx_http_waf_hdr_room(64))
        {
            vroom = ngx_http_waf_hdr_room(64);
        }

        size += ngx_http_waf_hdr_room(kv[i].key.len) + vroom + 8;
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_http_waf_jw_init(&jw, buf, size);
    ngx_http_waf_jw_lit(&jw, "[");

    first = 1;

    for (i = 0; i < pairs->nelts; i++) {

        if (!ctx->ph->store_raw
            && ngx_http_waf_name_listed(deny, &kv[i].key))
        {
            continue;
        }

        value = kv[i].value;

        if (!ctx->ph->store_raw
            && ngx_http_waf_name_listed(mask, &kv[i].key))
        {
            ngx_http_waf_capture_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
        }

        /*
         * Режем по целым парам: обрезанный JSON инспектору не разобрать.
         * Пара, которая не влезает в capture_limit, остаётся за скобкой,
         * как и все после неё. Пустой массив -- валидный JSON.
         */
        mark = jw.pos;

        if (!first) {
            ngx_http_waf_jw_lit(&jw, ",");
        }

        ngx_http_waf_jw_lit(&jw, "[");
        ngx_http_waf_jw_str(&jw, &kv[i].key);
        ngx_http_waf_jw_lit(&jw, ",");
        ngx_http_waf_jw_str(&jw, &value);
        ngx_http_waf_jw_lit(&jw, "]");

        if (limit != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
            && ngx_http_waf_jw_len(&jw) + 1 > limit)
        {
            jw.pos = mark;
            break;
        }

        first = 0;
    }

    ngx_http_waf_jw_lit(&jw, "]");

    if (!ngx_http_waf_jw_ok(&jw)) {
        return NGX_ERROR;
    }

    out->data = buf;
    out->len  = ngx_http_waf_jw_len(&jw);

    return NGX_OK;
}


/*
 * Строка запроса как пришла, без разбора на пары -- пока оператор не назвал
 * mask= или deny=. Разбор -- это уже интерпретация, и без списков имён
 * навязывать её инспекторам незачем: в инциденте смотрят провод.
 *
 * Списки заставляют резать и маскировать по имени, иначе deny=token оставил
 * бы секрет в обменнике. Превью по-прежнему читает запрос, не этот блоб.
 */
static ngx_int_t
ngx_http_waf_args_collect(ngx_http_waf_ctx_t *ctx, ngx_str_t *out)
{
    size_t                      limit;
    ngx_array_t                *deny, *mask;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    /*
     * Строка запроса -- объект фазы запроса. У ответа её нет по построению, и
     * попытка снять её там означала бы, что маршрут описан неверно; конфигурация
     * такого не принимает, а здесь остаётся страховка.
     */
    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        ngx_str_null(out);
        return NGX_OK;
    }

    wlcf  = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh    = &wlcf->shoot[ctx->phase];
    limit = ngx_http_waf_store_need_ctx(ctx, NGX_HTTP_WAF_OBJ_ARGS);

    if (limit == (size_t) -1) {
        limit = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
    }

    deny = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_ARGS]
                    [NGX_HTTP_WAF_AXIS_DENY];
    mask = sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][NGX_HTTP_WAF_OBJ_ARGS]
                    [NGX_HTTP_WAF_AXIS_MASK];

    if (!ctx->ph->store_raw
        && ((deny != NULL && deny->nelts != 0)
            || (mask != NULL && mask->nelts != 0)))
    {
        if (ngx_http_waf_args_filter(ctx->request, &ctx->request->args,
                                     deny, mask, out)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        *out = ctx->request->args;
    }

    if (limit != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE && out->len > limit) {
        out->len = limit;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_args_filter(ngx_http_request_t *r, ngx_str_t *src,
    ngx_array_t *deny, ngx_array_t *mask, ngx_str_t *out)
{
    u_char     *p, *last, *dst, *buf, hex[64];
    size_t      n, pairs;
    ngx_str_t   name, value;
    ngx_uint_t  first, had_eq;

    if (src->len == 0) {
        *out = *src;
        return NGX_OK;
    }

    pairs = 1;
    last  = src->data + src->len;

    for (p = src->data; p < last; p++) {
        if (*p == '&') {
            pairs++;
        }
    }

    /* Хеш длиннее исходного значения, и mask может добавить '='. */
    n = src->len + pairs * 66 + 1;
    buf = ngx_pnalloc(r->pool, n);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    dst   = buf;
    first = 1;
    p     = src->data;

    while (p < last) {

        name.data = p;
        had_eq    = 0;

        while (p < last && *p != '=' && *p != '&') {
            p++;
        }

        name.len = (size_t) (p - name.data);

        if (p < last && *p == '=') {
            had_eq = 1;
            p++;
            value.data = p;

            while (p < last && *p != '&') {
                p++;
            }

            value.len = (size_t) (p - value.data);

        } else {
            value.data = (u_char *) "";
            value.len  = 0;
        }

        if (p < last && *p == '&') {
            p++;
        }

        if (ngx_http_waf_name_listed(deny, &name)) {
            continue;
        }

        if (ngx_http_waf_name_listed(mask, &name)) {
            ngx_http_waf_capture_hash(&value, hex);
            value.data = hex;
            value.len  = 64;
            had_eq     = 1;
        }

        if (!first) {
            *dst++ = '&';
        }

        first = 0;

        if (name.len > 0) {
            dst = ngx_cpymem(dst, name.data, name.len);
        }

        if (had_eq) {
            *dst++ = '=';

            if (value.len > 0) {
                dst = ngx_cpymem(dst, value.data, value.len);
            }
        }
    }

    out->data = buf;
    out->len  = (size_t) (dst - buf);

    return NGX_OK;
}


/*
 * Итог размещения одного метаобъекта. Вызывается и синхронно из place_one, и
 * из колбэка драйвера; запрос возвращается в фазы, только когда закрыт
 * последний объект, -- иначе волна ушла бы с локатором, которого ещё нет.
 */
static void
ngx_http_waf_meta_on_put(ngx_http_waf_body_op_t *op)
{
    ngx_uint_t                reason;
    ngx_http_waf_ctx_t       *ctx = op->data_ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx->ph->meta_pending--;

    if (op->status == NGX_OK) {
        *ctx->ph->meta[op->obj] = op->locator;
        ctx->ph->meta_placed   |= NGX_HTTP_WAF_OBJ_BIT(op->obj);

        /* Лёг оригинал: маски снимка на этом объекте больше не лежат. */
        if (ctx->ph->reloading) {
            ctx->ph->raw |= NGX_HTTP_WAF_OBJ_BIT(op->obj);
        }

    } else if (ctx->ph->reloading) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: body store failed to reload %V; agent may see "
                      "the inspector view", &ngx_http_waf_objs[op->obj].name);

        if (op->hold) {
            ngx_http_waf_body_holds--;
            op->hold = 0;
            ctx->ph->meta_op[op->obj] = NULL;
        }

    } else {
        wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: body store \"%V\" failed to place %O bytes of %V",
                      &op->locator.store, op->len,
                      &ngx_http_waf_objs[op->obj].name);

        /*
         * Причину драйвер вправе уточнить: none и inline размещают не по
         * отказу, а потому, что размещать им негде.
         */
        reason = (op->locator.unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
                     ? op->locator.unavailable
                     : (ngx_uint_t) NGX_HTTP_WAF_BODY_STORE_ERROR;

        ctx->ph->meta[op->obj]->unavailable = reason;
        ctx->ph->meta[op->obj]->complete    = 0;

        ctx->ph->body_policy =
            (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_TRIM)
                ? NGX_HTTP_WAF_POLICY_BLOCK
                : wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY];

        if (op->hold) {
            ngx_http_waf_body_holds--;
            op->hold = 0;
        }

        ctx->ph->meta_op[op->obj] = NULL;
    }

    if (ctx->ph->meta_pending == 0 && !ctx->ph->meta_in_put) {
        if (ctx->ph->reloading && ctx->ph->body_in_put && !ctx->ph->body_settled) {
            return;
        }

        ngx_http_waf_body_resumed(ctx,
            ctx->ph->reloading ? NGX_OK : ngx_http_waf_meta_result(ctx));
    }
}


ngx_int_t
ngx_http_waf_body_place(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t      *r = ctx->request;
    ngx_http_waf_locator_t  *loc;

    if (!ctx->ph->reloading && (ctx->ph->locator != NULL || ctx->ph->body_placed)) {
        return NGX_OK;                 /* тело уже размещено этой фазой */
    }

    if (ctx->ph->reloading && ctx->ph->locator != NULL) {

        /*
         * У тела масок нет, и reload для него -- только ширина: положенное
         * снимком уже оригинал, докладывать есть смысл лишь шире него. Те же
         * байты тем же ключом второй раз не кладутся.
         */
        if (!ngx_http_waf_body_reload_wider(ctx)) {
            return NGX_OK;
        }

        /*
         * Локатор после первого put держит размер положенного, а не тела:
         * решение и хеш считаются от тела целиком, поэтому длина берётся
         * заново из того же источника.
         */
        ctx->ph->locator->size = ngx_http_waf_body_length(ctx);
        ctx->ph->body_placed   = 0;
        ctx->ph->body_settled  = 0;
        return ngx_http_waf_body_decide(ctx);
    }

    loc = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_locator_t));
    if (loc == NULL) {
        return NGX_ERROR;
    }

    ctx->ph->locator = loc;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        ngx_http_waf_body_encoding_out(r, loc);

        loc->declared_size = (r->headers_out.content_length_n > 0)
                                 ? r->headers_out.content_length_n
                                 : 0;

    } else if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        /*
         * У кадра кодировки нет: сжатие вебсокета -- расширение, и кадры с
         * ним модуль не инспектирует вовсе. Заявленная длина -- из заголовка
         * кадра, и она же фактическая.
         */
        ngx_str_set(&loc->encoding, "identity");
        loc->declared_size = ngx_http_waf_body_length(ctx);

    } else {
        ngx_http_waf_body_encoding(r, loc);

        loc->declared_size = (r->headers_in.content_length_n > 0)
                                 ? r->headers_in.content_length_n
                                 : 0;
    }

    loc->size = ngx_http_waf_body_length(ctx);

    if (loc->size == 0) {
        /*
         * Тела нет вовсе. Это не недоступность: инспектор получит null и не
         * обязан различать "не прислали" и "не смогли положить".
         */
        ctx->ph->locator = NULL;
        return NGX_OK;
    }

    return ngx_http_waf_body_decide(ctx);
}


static ngx_int_t
ngx_http_waf_body_decide(ngx_http_waf_ctx_t *ctx)
{
    off_t                       place;
    size_t                      need, limit;
    ngx_int_t                   rc;
    ngx_str_t                   key;
    ngx_uint_t                  keep, policy;
    ngx_pool_cleanup_t         *cln;
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_wave_t        *wave;
    ngx_http_waf_locator_t     *loc = ctx->ph->locator;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    wlcf  = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    sh    = &wlcf->shoot[ctx->phase];
    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    wave = ngx_http_waf_current_wave(ctx);

    /*
     * Срез уже выбран фазой, поэтому и архив здесь -- её. Класть с retain_ttl
     * приходится заранее: вердикта в момент put ещё нет, а продлить ключ
     * задним числом обменник не обязан -- при отказе от архивации объект просто
     * удаляется на освобождении.
     */
    keep = (sh->archive & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY)) != 0;
    need = ngx_http_waf_store_need_ctx(ctx, NGX_HTTP_WAF_OBJ_BODY);

    /*
     * Один put на максимум трёх осей. Волне, архиву и превью хватает одного
     * префикса; агент потом ещё режет archive limit при PUT в S3. Ноль --
     * класть некого: превью без обменника возьмёт тело из запроса.
     */
    if (need == 0) {

        if (wave != NULL && wave->body_need == NGX_HTTP_WAF_BODY_META) {
            place = 0;

            if (ngx_http_waf_body_collect(ctx, loc->size, place) != NGX_OK) {
                ngx_http_waf_body_unavailable(ctx,
                                              NGX_HTTP_WAF_BODY_STORE_ERROR,
                                              wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);
                return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                           ? NGX_ERROR : NGX_OK;
            }

            loc->has_sha256 = 1;
            loc->complete   = 0;
            return NGX_OK;
        }

        ctx->ph->locator = NULL;
        return NGX_OK;
    }

    place = loc->size;

    limit  = wlcf->body_limit[ctx->phase];
    policy = wlcf->body_limit_policy[ctx->phase];

    if (loc->size > (off_t) limit) {

        /*
         * Превью само по себе вердикт не двигает. Если тело нужно только
         * ему, put не делаем: бюджет превью уже не больше body_limit, и
         * секция возьмёт префикс из запроса.
         */
        if (policy != NGX_HTTP_WAF_POLICY_TRIM
            && !keep
            && !(sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
            && (wave == NULL || wave->body_need == NGX_HTTP_WAF_BODY_NONE
                || wave->body_need == NGX_HTTP_WAF_BODY_META))
        {
            ctx->ph->locator = NULL;
            return NGX_OK;
        }

        if (policy != NGX_HTTP_WAF_POLICY_TRIM) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "waf: body of %O bytes exceeds waf_body_limit %uz",
                          loc->size, limit);

            ngx_http_waf_body_unavailable(ctx, NGX_HTTP_WAF_BODY_OVERSIZE,
                                          policy);

            return (policy == NGX_HTTP_WAF_POLICY_BLOCK)
                       ? NGX_ERROR : NGX_OK;
        }

        /*
         * trim: размещается префикс, а контрольная сумма считается по телу
         * целиком -- она связывает событие с архивом, а в архиве оригинал.
         */
        place = (off_t) limit;
    }

    if (need != (size_t) -1 && place > (off_t) need) {
        place = (off_t) need;
    }

    loc->truncated = (place < loc->size) ? 1 : 0;

    /*
     * Хеш считается по телу целиком независимо от того, сколько из него легло:
     * он связывает событие с архивом, а в архиве оригинал.
     */
    if (ngx_http_waf_body_collect(ctx, loc->size, place) != NGX_OK) {
        ngx_http_waf_body_unavailable(ctx, NGX_HTTP_WAF_BODY_STORE_ERROR,
                                      wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

        return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                   ? NGX_ERROR : NGX_OK;
    }

    loc->has_sha256 = 1;
    loc->complete   = loc->truncated ? 0 : 1;
    ctx->ph->store_blob[NGX_HTTP_WAF_OBJ_BODY] = loc->inline_data;

    /*
     * body=meta: длина, контрольная сумма и кодировка -- всё, что просили, и
     * ради этого в хранилище идти не надо. Локатор без store -- не отказ:
     * инспектор получил ровно то, что заявил в needs.
     */
    if (place == 0) {
        return NGX_OK;
    }

    if (store == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: body of %O bytes needs a store, none configured",
                      place);

        ngx_http_waf_body_unavailable(ctx,
                                      NGX_HTTP_WAF_BODY_STORE_UNCONFIGURED,
                                      wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

        return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                   ? NGX_ERROR : NGX_OK;
    }

    if (ngx_http_waf_body_holds >= wmcf->body_max_holds) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "waf: waf_body_max_holds %ui reached, body not placed",
                      wmcf->body_max_holds);

        ngx_http_waf_body_unavailable(ctx, NGX_HTTP_WAF_BODY_STORE_ERROR,
                                      wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

        return (wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY] == NGX_HTTP_WAF_POLICY_BLOCK)
                   ? NGX_ERROR : NGX_OK;
    }

    if (ngx_http_waf_body_key(ctx, &key, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf   = store->conf;
    op->pool         = r->pool;
    op->log          = r->connection->log;
    op->rid.data     = ctx->rid_hex;
    op->rid.len      = NGX_HTTP_WAF_RID_HEX_LEN;
    op->phase        = ctx->phase;
    op->obj          = NGX_HTTP_WAF_OBJ_BODY;
    op->len          = place;
    op->data         = loc->inline_data;
    op->handler      = ngx_http_waf_body_on_put;
    op->data_ctx     = ctx;
    op->retain       = keep;

    op->locator        = *loc;
    op->locator.store  = ngx_http_waf_store_hot;
    op->locator.driver = store->driver->name;
    op->locator.key    = key;
    op->locator.size   = place;

    /*
     * В сообщении поедет ключ, а не байты: дублировать тело в каждом сообщении
     * волны, уже положив его в хранилище, незачем.
     */
    ngx_str_null(&op->locator.inline_data);
    ngx_str_null(&loc->inline_data);

    if (!ctx->ph->store_cleanup) {
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_body_cleanup;
        cln->data    = ctx;
        ctx->ph->store_cleanup = 1;
    }

    op->hold = (ctx->ph->body_op == NULL);
    ctx->ph->body_op = op;

    if (op->hold) {
        ngx_http_waf_body_holds++;
    }

    /*
     * Драйвер имеет право вызвать колбэк изнутри put: соединение может оказаться
     * оборванным ровно в момент отправки. Флаг различает этот случай от
     * настоящего асинхронного ответа, в котором запрос возвращает в фазы сам
     * колбэк, а не этот стек.
     */
    ctx->ph->body_in_put = 1;
    rc = store->driver->put(op);
    ctx->ph->body_in_put = 0;

    if (rc == NGX_AGAIN && !ctx->ph->body_settled) {
        return NGX_AGAIN;
    }

    if (!ctx->ph->body_settled) {
        ngx_http_waf_body_on_put(op);
    }

    return (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE
            && ctx->ph->body_policy == NGX_HTTP_WAF_POLICY_BLOCK)
               ? NGX_ERROR : NGX_OK;
}


/*
 * Итог размещения. Вызывается и синхронно из decide(), и из колбэка драйвера.
 * Из колбэка запрос возвращается в фазы здесь же -- больше некому.
 */
static void
ngx_http_waf_body_on_put(ngx_http_waf_body_op_t *op)
{
    ngx_uint_t                reason;
    ngx_http_waf_ctx_t       *ctx = op->data_ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx->ph->body_settled = 1;

    if (op->status == NGX_OK) {
        *ctx->ph->locator        = op->locator;
        ctx->ph->body_placed     = 1;
        ctx->ph->body_placed_len = op->len;

        if (!ctx->ph->body_in_put) {
            ngx_http_waf_body_resumed(ctx, NGX_OK);
        }

        return;
    }

    if (ctx->ph->reloading) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "waf: body store failed to reload body; agent may see "
                      "the inspector view");

        if (op->hold) {
            ngx_http_waf_body_holds--;
            op->hold = 0;
            ctx->ph->body_op = NULL;
        } else {
            ctx->ph->body_placed = 1;
        }

        if (!ctx->ph->body_in_put) {
            ngx_http_waf_body_resumed(ctx, NGX_OK);
        }

        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                  "waf: body store \"%V\" failed to place %O bytes",
                  &op->locator.store, op->len);

    /*
     * Причину драйвер вправе уточнить: none и inline размещают не по отказу, а
     * потому, что размещать им негде, и подменять это на store_error значило бы
     * послать инспектора искать неисправность там, где её нет.
     *
     * Тихая потеря тела означала бы тихое отключение проверки, поэтому любая из
     * причин видна инспектору в локаторе и решается политикой.
     */
    reason = (op->locator.unavailable != NGX_HTTP_WAF_BODY_AVAILABLE)
                 ? op->locator.unavailable
                 : (ngx_uint_t) NGX_HTTP_WAF_BODY_STORE_ERROR;

    ngx_http_waf_body_unavailable(ctx, reason, wlcf->exception[ctx->phase][NGX_HTTP_WAF_EXC_BODY]);

    if (op->hold) {
        ngx_http_waf_body_holds--;
        op->hold = 0;
    }

    ctx->ph->body_op = NULL;

    if (!ctx->ph->body_in_put) {
        ngx_http_waf_body_resumed(ctx,
            (ctx->ph->body_policy == NGX_HTTP_WAF_POLICY_BLOCK)
                ? NGX_ERROR : NGX_OK);
    }
}


/*
 * Освобождение объектов обменника. Удаляется не всё: объект, названный в
 * waf_archive, модуль оставляет жить -- владение ключом перешло агенту, и
 * удалит его он, переложив содержимое в архив.
 *
 * Счётчик удержаний уменьшается в обоих случаях: он считает объекты, за
 * которые отвечает этот воркер, а за переданные агенту он больше не отвечает.
 * Иначе маршрут с архивацией упирался бы в waf_body_max_holds на первой же
 * тысяче запросов.
 */
void
ngx_http_waf_body_release(ngx_http_waf_ctx_t *ctx)
{
    /*
     * Объекты фазы запроса переживают её вердикт, если маршрут ведёт фазу
     * ответа: они едут её инспектору секцией request_store, и удалить их
     * раньше значило бы прислать ключ, по которому уже ничего нет. Инспектор
     * при этом не ошибётся -- он получит пустые заголовки запроса и молча
     * доиграет фазы 1-2 по пустому контексту, -- и это худший из возможных
     * исходов: правила отработают не на том, что было в запросе.
     */
    if (ngx_http_waf_phase_follows(ctx)) {
        return;
    }

    /*
     * Кадр здесь не снимает ничего. Своё он отпускает в конце кадра
     * (ngx_http_waf_body_frame_end), уже после записи аудита: набор архива
     * решается по тому, что запись скажет о кадре -- отказ, подмена, счёт, --
     * а это известно только там. Объекты рукопожатия нужны каждому
     * следующему кадру, их заберёт cleanup пула запроса при закрытии
     * соединения.
     */
    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return;
    }

    /*
     * Фазы кончились. Снимаются объекты всех, что бежали: фаза запроса могла
     * отложить своё освобождение ради request_store, и этот момент -- тот, до
     * которого она откладывала.
     */
    ngx_http_waf_body_release_all(ctx);
}


void
ngx_http_waf_body_frame_end(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_phase_ctx_t  *ph;

    if (!ngx_http_waf_phase_is_frame(ctx->phase)) {
        return;
    }

    ph = &ctx->phases[ctx->phase];

    /*
     * Штатный момент освобождения объекта кадра: запись аудита уже
     * собрана, и набор архива (ngx_http_waf_archive_mask) посчитан по ней.
     * Объект, названный в waf_archive, остаётся агенту, остальное снимается.
     */
    if (ph->body_op != NULL && ph->body_placed) {
        ngx_http_waf_body_release_phase(ctx, ctx->phase);
    }

    /*
     * Операция в полёте: пул кадра сейчас умрёт, драйвер отцепит запись
     * своим cleanup, а счётчик удержаний уменьшить больше некому -- та же
     * логика, что у ngx_http_waf_body_abandon() для пула запроса.
     */
    if (ph->body_op != NULL) {
        ngx_http_waf_body_holds--;
        ph->body_op = NULL;
    }
}


static void
ngx_http_waf_body_release_all(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t  phase;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {
        ngx_http_waf_body_release_phase(ctx, phase);
    }
}


static void
ngx_http_waf_body_release_phase(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase)
{
    ngx_uint_t                 i, keep;
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    keep = ngx_http_waf_archive_kept(ctx, phase);

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

        if (ph->meta_op[i] == NULL
            || !(ph->meta_placed & NGX_HTTP_WAF_OBJ_BIT(i)))
        {
            continue;
        }

        ngx_http_waf_store_del(ctx, ph->meta_op[i],
                               keep & NGX_HTTP_WAF_OBJ_BIT(i));

        ph->meta_op[i]   = NULL;
        ph->meta_placed &= ~NGX_HTTP_WAF_OBJ_BIT(i);
    }

    if (ph->body_op != NULL && ph->body_placed) {
        ngx_http_waf_store_del(ctx, ph->body_op,
                               keep & NGX_HTTP_WAF_OBJ_BIT(
                                          NGX_HTTP_WAF_OBJ_BODY));

        ph->body_op     = NULL;
        ph->body_placed = 0;
    }

    /*
     * Промежуточные версии объекта: их положил инспектор, а прибирает модуль
     * -- ключ он знает, а инспектор о судьбе запроса ничего не знает и удалять
     * своё вслепую не может. Отданная версия здесь не встречается: её удаляет
     * сразу после чтения тот, кто её поднял. Архив к цепочке отношения не
     * имеет -- он держит оригинал, поэтому keep тут не спрашивается.
     */
    if (ph->stale != NULL) {
        ngx_str_t   *key = ph->stale->elts;
        ngx_uint_t   n;

        for (n = 0; n < ph->stale->nelts; n++) {
            ngx_http_waf_store_del_key(ctx, &key[n]);
        }

        ph->stale->nelts = 0;
    }
}


/*
 * Ведёт ли маршрут ещё одну фазу после текущей. Отказ фазы запроса это
 * отменяет: ответа приложения после него не будет вовсе -- клиент получает
 * страницу каталога, и инспектировать нечего.
 */
static ngx_uint_t
ngx_http_waf_phase_follows(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return 0;
    }

    if (ctx->ph->verdict == NGX_HTTP_WAF_V_DENY || ctx->ph->fail_blocked) {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    /*
     * Кадры -- тоже поздняя фаза: их инспектор восстанавливает контекст
     * рукопожатия по request_store, и объекты запроса обязаны дожить до
     * закрытия соединения. Апгрейда может и не случиться -- тогда они
     * проживут до конца запроса и снимутся cleanup пула.
     */
    return (wlcf->waves[NGX_HTTP_WAF_PHASE_RESPONSE] != NULL
            && wlcf->waves[NGX_HTTP_WAF_PHASE_RESPONSE]->nelts != 0)
           || (wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_C2S] != NULL
               && wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_C2S]->nelts != 0)
           || (wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_S2C] != NULL
               && wlcf->waves[NGX_HTTP_WAF_PHASE_FRAME_S2C]->nelts != 0);
}


/*
 * Нужно ли фазе запроса ждать исхода маршрута, прежде чем записать набор
 * архива: впереди фаза, где инспекторов ещё спрашивают.
 *
 * Ждать приходится всегда, когда такая фаза есть. Глаголы записи принимает
 * любой спрошенный инспектор, и сосед с поздней фазы вправе сказать "писать"
 * и "архивировать" про запрос, чья запись без этого уже ушла бы; решение о
 * записи одно на запрос, и принимать его до последней волны значило бы не
 * услышать. Раньше сюда смотрели ещё и объекты с when=, но это подмножество:
 * набор архива тоже решается исходом.
 */
ngx_uint_t
ngx_http_waf_archive_pending(ngx_http_waf_ctx_t *ctx)
{
    return ngx_http_waf_phase_follows(ctx) ? 1 : 0;
}


/*
 * Что из объектов фазы забирает агент. У текущей фазы маска считается здесь и
 * запоминается; у чужой она уже посчитана её собственной записью аудита. Не
 * посчитана -- записи не было, и передавать объекты некому.
 */
static ngx_uint_t
ngx_http_waf_archive_kept(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase)
{
    if (phase == ctx->phase) {
        return ngx_http_waf_archive_mask(ctx);
    }

    return ctx->phases[phase].archive_settled ? ctx->phases[phase].archive : 0;
}


static void
ngx_http_waf_store_del(ngx_http_waf_ctx_t *ctx, ngx_http_waf_body_op_t *op,
    ngx_uint_t keep)
{
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    ngx_http_waf_body_holds--;

    if (keep) {
        return;                        /* ключ забрал агент */
    }

    wmcf  = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    store = wmcf->body_store;

    if (store == NULL
        || !(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_DELETE)
        || store->driver->del == NULL)
    {
        return;                        /* остаётся на TTL или lifecycle */
    }

    (void) store->driver->del(op);
}


ngx_str_t *
ngx_http_waf_body_phase_tag_name(ngx_uint_t phase)
{
    return &ngx_http_waf_body_phase_tag[
               phase >= NGX_HTTP_WAF_NPHASE ? 0 : phase];
}


/*
 * Чтение rewrite-объекта. Ключ уже проверен разбором реплая на префикс
 * <node>:<rid>:rsp:, поэтому здесь только механика: op, драйвер, колбэк.
 * В body_holds объект не входит: он не наш, срок его жизни держит TTL,
 * который поставил инспектор.
 */
ngx_int_t
ngx_http_waf_store_get(ngx_http_waf_ctx_t *ctx, ngx_str_t *key, off_t max,
    void (*handler)(ngx_http_waf_body_op_t *op), ngx_http_waf_body_op_t **out)
{
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    *out = NULL;

    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    if (store == NULL
        || !(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_GET)
        || store->driver->get == NULL)
    {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return NGX_ERROR;
    }

    op->store_conf = store->conf;
    op->pool       = r->pool;
    op->log        = r->connection->log;
    op->rid.data   = ctx->rid_hex;
    op->rid.len    = NGX_HTTP_WAF_RID_HEX_LEN;
    op->phase      = ctx->phase;
    op->obj        = NGX_HTTP_WAF_OBJ_BODY;
    op->len        = max;
    op->handler    = handler;
    op->data_ctx   = ctx;

    op->locator.store  = ngx_http_waf_store_hot;
    op->locator.driver = store->driver->name;
    op->locator.key    = *key;

    op->status = NGX_ERROR;

    *out = op;

    return store->driver->get(op);
}


void
ngx_http_waf_store_del_key(ngx_http_waf_ctx_t *ctx, ngx_str_t *key)
{
    ngx_http_request_t         *r = ctx->request;
    ngx_http_waf_body_op_t     *op;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_body_store_t  *store;

    wmcf  = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    store = wmcf->body_store;

    if (store == NULL
        || !(store->driver->caps & NGX_HTTP_WAF_BODY_CAP_DELETE)
        || store->driver->del == NULL)
    {
        return;                        /* объект умрёт по TTL инспектора */
    }

    op = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_body_op_t));
    if (op == NULL) {
        return;
    }

    op->store_conf  = store->conf;
    op->pool        = r->pool;
    op->log         = r->connection->log;
    op->locator.key = *key;

    (void) store->driver->del(op);
}


/* --- архивация ------------------------------------------------------------ */

ngx_uint_t
ngx_http_waf_archive_mask(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                  i, mask, placed, verdict, forced;
    ngx_http_waf_locator_t     *loc;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_audit_ovr_t   *ovr;

    if (ctx->ph->archive_settled) {
        return ctx->ph->archive;
    }

    ctx->ph->archive_settled = 1;
    ctx->ph->archive         = 0;

    /*
     * Записи не было -- некому и прийти. Так закрывается запрос, оборванный
     * до вердикта: объекты освобождает cleanup пула, и оставлять их агенту,
     * который о них не узнает, значило бы держать их до retain_ttl впустую.
     */
    if (!ctx->ph->logged) {
        return 0;
    }

    /*
     * У кадра запись идёт по своей политике (waf_audit_frames), и кадр без
     * записи объектов агенту не передаёт: оставить ключ, за которым никто не
     * придёт, значило бы держать его до retain_ttl впустую -- на болтливом
     * сокете это обменник, забитый пропущенными кадрами.
     */
    if (ngx_http_waf_phase_is_frame(ctx->phase)
        && !ngx_http_waf_frame_audit_wanted(ctx))
    {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];
    ovr  = ngx_http_waf_audit_ovr_cur(ctx);

    /*
     * Сосед переопределил архив глаголом записи. off -- объекты
     * не оставлять, что бы ни велел маршрут. on -- оставить вопреки when= и
     * даже там, где waf_archive нет вовсе: названные им объекты, иначе набор
     * маршрута, иначе всё, что снято. Без агента on ничего не значит: у
     * объекта, которого некому забрать, не должно быть владельца.
     *
     * Свой when= у просьбы, если назван, заменяет маршрутный целиком -- как
     * срок и набор: "сохрани, но только если откажем" пишется в самой
     * просьбе, а не наследуется от строки, о которой отправитель не знает.
     */
    if (ovr->archive.set == NGX_HTTP_WAF_SET_OFF) {
        return 0;
    }

    forced = (ovr->archive.set == NGX_HTTP_WAF_SET_ON
              && ngx_http_waf_audit_enabled());

    if (sh->archive == 0 && !forced) {
        return 0;
    }

    placed = ctx->ph->meta_placed
             | (ctx->ph->body_placed
                    ? NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY) : 0);

    if (forced) {
        /*
         * Названные с set on; никого не назвали -- набор маршрута, а без
         * него всё снятое, минус исключённые просьбой.
         */
        mask = ngx_http_waf_ovr_on(&ovr->archive);

        if (mask == 0) {
            mask = (sh->archive != 0 ? sh->archive : NGX_HTTP_WAF_OBJ_ALL)
                   & ~ovr->archive.off;
        }

        mask &= placed;

    } else {
        mask = sh->archive & placed;
    }

    /*
     * Исход -- маршрута, не фазы: when=deny у запроса срабатывает и тогда,
     * когда отказала фаза ответа. Запись фазы запроса ради этого отложена до
     * исхода (ngx_http_waf_archive_pending), и здесь он уже известен.
     */
    verdict = ngx_http_waf_route_verdict(ctx);

    /*
     * Исход, названный самой просьбой: она перекрывает when= маршрута целиком,
     * и объекты у неё общие -- как срок. Не подошёл -- архива нет вовсе, в том
     * числе у объектов, которые маршрут увёз бы сам: последний сказавший прав,
     * и половинчатый набор был бы не тем, о чём просили.
     */
    if (forced && ovr->archive.has_when
        && !(ovr->archive.when & (1u << verdict)))
    {
        return 0;
    }

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        /*
         * Исход считается тем же способом, что и для записи аудита: набор
         * выбирается по тому, что запись скажет о запросе, а не по внутреннему
         * состоянию, -- иначе "сохраняем отказы" однажды разошлось бы с тем,
         * что в логе названо отказом. Условие своё у каждого вида: строка
         * директивы настраивает только названные в ней объекты.
         */
        if (!forced && !(sh->archive_when[i] & (1u << verdict))) {
            mask &= ~NGX_HTTP_WAF_OBJ_BIT(i);
            continue;
        }

        /*
         * Недоступный объект в обменнике не лежит, а идти агенту не за чем: его
         * локатор несёт причину, а не ключ.
         */
        loc = ngx_http_waf_store_locator(ctx, i);

        if (loc == NULL
            || loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE
            || loc->key.len == 0)
        {
            mask &= ~NGX_HTTP_WAF_OBJ_BIT(i);
        }
    }

    ctx->ph->archive = mask;

    return mask;
}


/*
 * Секция archive: "вид объекта" -> условия его записи. Срок числом, а не именем
 * класса: класс требовал реестра, синхронного у модуля, агента и правил
 * бакета, а срок не требует ничего -- его читает и применяет тот, кто кладёт.
 * Ноль означает "хранить вечно"; отсутствие срока -- это решение оператора, и
 * нулевым временем жизни оно быть не может.
 *
 * Рядом со сроком едет предел записи. Режет по нему агент: в обменнике объект
 * лежит целиком, потому что его мог попросить инспектор, и урезать общий
 * объект ради настройки архива модуль не вправе. Ноль -- "весь объект".
 */
static void
ngx_http_waf_jw_namelist(ngx_http_waf_jw_t *jw, const char *field,
    ngx_array_t *list)
{
    ngx_str_t   *item;
    ngx_uint_t   i;

    if (list == NULL || list->nelts == 0) {
        return;
    }

    ngx_http_waf_jw_lit(jw, ",\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) field, ngx_strlen(field));
    ngx_http_waf_jw_lit(jw, "\":[");

    item = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &item[i]);
    }

    ngx_http_waf_jw_lit(jw, "]");
}


ngx_int_t
ngx_http_waf_obj_find(ngx_str_t *name, ngx_uint_t *index)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        if (name->len == ngx_http_waf_objs[i].name.len
            && ngx_strncmp(name->data, ngx_http_waf_objs[i].name.data,
                           name->len) == 0)
        {
            *index = i;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void
ngx_http_waf_action_archive_write(ngx_http_waf_jw_t *jw,
    ngx_http_waf_action_t *a)
{
    ngx_uint_t                i, bit, first;
    ngx_http_waf_ovr_part_t  *spec = &a->spec;

    if (spec->has_ttl) {
        ngx_http_waf_jw_lit(jw, ",\"ttl\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) spec->ttl);
    }

    /*
     * Исход просьбы -- как пришёл, множеством: по записи должно читаться не
     * только "просили сохранить", но и "просили сохранить, если откажем", --
     * иначе пустой архив на допуске выглядит потерей объекта.
     */
    if (spec->has_when) {
        ngx_http_waf_jw_lit(jw, ",\"when\":[");
        first = 1;

        if (spec->when & (1u << NGX_HTTP_WAF_V_ALLOW)) {
            ngx_http_waf_jw_lit(jw, "\"allow\"");
            first = 0;
        }

        if (spec->when & (1u << NGX_HTTP_WAF_V_DENY)) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            ngx_http_waf_jw_lit(jw, "\"deny\"");
        }

        ngx_http_waf_jw_lit(jw, "]");
    }

    /* По объектам, как пришло: сторона, размер, источник. */
    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit = NGX_HTTP_WAF_OBJ_BIT(i);

        if (!(spec->named & bit)) {
            continue;
        }

        ngx_http_waf_jw_lit(jw, ",");
        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
        ngx_http_waf_jw_lit(jw, ":{");

        first = 1;

        if (spec->off & bit) {
            ngx_http_waf_jw_lit(jw, "\"set\":\"off\"");
            first = 0;
        }

        if (spec->has_limit & bit) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            ngx_http_waf_jw_lit(jw, "\"limit\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) spec->limit[i]);
            first = 0;
        }

        if (spec->source[i] != NGX_HTTP_WAF_SOURCE_NONE) {
            if (!first) {
                ngx_http_waf_jw_lit(jw, ",");
            }

            if (spec->source[i] == NGX_HTTP_WAF_SOURCE_STORE) {
                ngx_http_waf_jw_lit(jw, "\"source\":\"store\"");

            } else {
                ngx_http_waf_jw_lit(jw, "\"source\":\"original\"");
            }
        }

        ngx_http_waf_jw_lit(jw, "}");
    }
}


void
ngx_http_waf_archive_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t mask)
{
    time_t                      ttl;
    size_t                      limit;
    ngx_uint_t                  i, first;
    ngx_array_t               **lists;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;
    ngx_http_waf_audit_ovr_t   *ovr;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    sh   = &wlcf->shoot[ctx->phase];
    ovr  = ngx_http_waf_audit_ovr_cur(ctx);

    ngx_http_waf_jw_lit(jw, ",\"archive\":{");

    for (i = 0, first = 1; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(mask & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (!first) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        first = 0;

        /*
         * Срок и предел -- маршрута, если сосед не назвал своих:
         * archive on без ttl и limit значит "как записано", а у объекта, не
         * названного в waf_archive, записанное -- вечно и целиком.
         */
        ttl   = sh->archive_ttl[i];
        limit = sh->archive_limit[i];

        if (ovr->archive.set == NGX_HTTP_WAF_SET_ON) {
            if (ovr->archive.has_ttl) {
                ttl = ovr->archive.ttl;
            }

            if (ovr->archive.has_limit & NGX_HTTP_WAF_OBJ_BIT(i)) {
                limit = ovr->archive.limit[i];
            }
        }

        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
        ngx_http_waf_jw_lit(jw, ":{\"ttl\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) ttl);

        if (limit != NGX_HTTP_WAF_ARCHIVE_LIMIT_WHOLE) {
            ngx_http_waf_jw_lit(jw, ",\"limit\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) limit);
        }

        if (i < NGX_HTTP_WAF_META_COUNT) {
            lists = sh->lists[NGX_HTTP_WAF_LIST_ARCHIVE][i];

            ngx_http_waf_jw_namelist(jw, "allow",
                                     lists[NGX_HTTP_WAF_AXIS_ALLOW]);
            ngx_http_waf_jw_namelist(jw, "mask",
                                     lists[NGX_HTTP_WAF_AXIS_MASK]);
            ngx_http_waf_jw_namelist(jw, "deny",
                                     lists[NGX_HTTP_WAF_AXIS_DENY]);

            /*
             * Имена, чьи значения в объекте уже хеш: маска снимка, если объект
             * так и остался видом инспекторов (reload его не перекладывал). Агент
             * такие имена второй раз не хеширует, иначе хеш в архиве не сошёлся
             * бы ни с записью, ни с тем, что видели инспекторы.
             */
            if (!(ctx->ph->raw & NGX_HTTP_WAF_OBJ_BIT(i))) {
                ngx_http_waf_jw_namelist(jw, "hashed",
                    sh->lists[NGX_HTTP_WAF_LIST_CAPTURE][i]
                             [NGX_HTTP_WAF_AXIS_MASK]);
            }
        }

        ngx_http_waf_jw_lit(jw, "}");
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Удаление привязано к пулу запроса, а не только к разрешению вердикта.
 * Разрешение -- лишь один из путей: запрос уходит и по отказу, и по обрыву
 * соединения, и по внутренней ошибке, а тело в хранилище остаётся при любом из
 * них. TTL -- страховка от падения воркера между put и del, а не основной
 * механизм: при десятках тысяч запросов в секунду опора на него даёт хранилищу
 * пиковую нагрузку в произведении RPS на TTL.
 */
static void
ngx_http_waf_body_cleanup(void *data)
{
    /*
     * Здесь откладывать уже некуда: запрос кончился, следующей фазы не будет
     * ни при каком исходе, -- поэтому не ngx_http_waf_body_release(). Запись,
     * отложенная до фазы ответа, которая так и не пришла, уходит отсюда --
     * до освобождения: набор архива считается в ней.
     */
    ngx_http_waf_audit_flush_deferred(data);
    ngx_http_waf_body_release_all(data);
    ngx_http_waf_body_abandon(data);
}


/*
 * Операции, застигнутые уничтожением пула в полёте. Драйвер их к этому моменту
 * уже отцепил, колбэка не будет, и уменьшить счётчик удержаний больше некому:
 * ngx_http_waf_body_release() их пропускает, потому что размещение не
 * состоялось и удалять в обменнике нечего. Ключ, если он всё-таки доедет до
 * хранилища, снимет ttl обменника.
 *
 * Только из cleanup пула: на любом другом пути операция ещё жива, и такой же
 * декремент разошёлся бы с колбэком, а беззнаковый счётчик от лишнего
 * уменьшения уходит в переполнение и снимает потолок вовсе.
 */
static void
ngx_http_waf_body_abandon(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, phase;
    ngx_http_waf_phase_ctx_t  *ph;

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        ph = &ctx->phases[phase];

        for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {

            if (ph->meta_op[i] == NULL) {
                continue;
            }

            ngx_http_waf_body_holds--;
            ph->meta_op[i] = NULL;
        }

        if (ph->body_op != NULL) {
            ngx_http_waf_body_holds--;
            ph->body_op = NULL;
        }
    }
}


/* --- сбор тела ------------------------------------------------------------ */

/*
 * Откуда фаза берёт тело. У запроса это буферы, прочитанные nginx; у ответа --
 * цепочка, которую удерживает фильтр. Форма одна -- ngx_chain_t, -- поэтому
 * дальше по коду разницы между фазами нет.
 */
static ngx_chain_t *
ngx_http_waf_body_source(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t  *r = ctx->request;

    if (ctx->phase == NGX_HTTP_WAF_PHASE_RESPONSE) {
        return ctx->hold;
    }

    if (ngx_http_waf_phase_is_frame(ctx->phase)) {
        return ngx_http_waf_frame_source(ctx);
    }

    if (r->request_body == NULL) {
        return NULL;
    }

    return r->request_body->bufs;
}


static off_t
ngx_http_waf_body_length(ngx_http_waf_ctx_t *ctx)
{
    off_t         len;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_http_waf_body_source(ctx);

    if (cl == NULL) {
        return 0;
    }

    len = 0;

    for ( /* void */ ; cl != NULL; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {
            len += b->file_last - b->file_pos;

        } else {
            len += b->last - b->pos;
        }
    }

    return len;
}


/*
 * Content-Encoding запроса. В ngx_http_headers_in_t его нет -- это заголовок
 * ответа в терминах nginx, -- поэтому ищется в общем списке.
 */
/*
 * Content-Encoding ответа. Тело не разжимается: инспектор обязан знать, что
 * перед ним gzip, и решить сам -- смотреть его нечем, а сделать вид, что это
 * текст, значило бы пропустить утечку с чистой совестью.
 *
 * Поле в headers_out отдельное, а не в списке: nginx держит его указателем на
 * запись, и брать его из общего обхода незачем.
 */
static void
ngx_http_waf_body_encoding_out(ngx_http_request_t *r,
    ngx_http_waf_locator_t *loc)
{
    ngx_str_set(&loc->encoding, "identity");

    if (r->headers_out.content_encoding != NULL
        && r->headers_out.content_encoding->value.len != 0)
    {
        loc->encoding = r->headers_out.content_encoding->value;
    }
}


static void
ngx_http_waf_body_encoding(ngx_http_request_t *r, ngx_http_waf_locator_t *loc)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    ngx_str_set(&loc->encoding, "identity");

    part = &r->headers_in.headers.part;
    h    = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                return;
            }

            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].key.len == ngx_http_waf_body_content_encoding.len
            && ngx_strncasecmp(h[i].key.data,
                               ngx_http_waf_body_content_encoding.data,
                               h[i].key.len) == 0)
        {
            /*
             * Тело не разжимается: инспектор должен знать, что перед ним
             * закодированные байты, а не считать их текстом.
             */
            if (h[i].value.len != 0) {
                loc->encoding = h[i].value;
            }

            return;
        }
    }
}


/*
 * Тело в один буфер, попутно SHA-256 по всей длине.
 *
 * Размещение -- одна операция после чтения целиком: хеш локатора требует
 * полного прохода, и потокового put нет. Тело в файле читается здесь же:
 * при client_body_temp_path на tmpfs это копирование из страничного кеша, а
 * неблокирующее чтение файла в цикле событий потребовало бы пула потоков --
 * см. docs/nginx/module/known-issues.md.
 */
static ngx_int_t
ngx_http_waf_body_collect(ngx_http_waf_ctx_t *ctx, off_t total, off_t place)
{
    ngx_chain_t  *source = ngx_http_waf_body_source(ctx);

    off_t                   left, taken, pos;
    size_t                  avail, copy;
    u_char                 *p;
    u_char                  chunk[NGX_HTTP_WAF_BODY_CHUNK];
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_http_request_t     *r = ctx->request;
    ngx_http_waf_sha256_t   sha;

    p = ngx_pnalloc(r->pool, (size_t) place);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ctx->ph->locator->inline_data.data = p;
    ctx->ph->locator->inline_data.len  = (size_t) place;

    ngx_http_waf_sha256_init(&sha);

    left  = total;
    taken = 0;

    for (cl = source; cl != NULL && left > 0; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {

            for (pos = b->file_pos; pos < b->file_last && left > 0; /* void */) {

                avail = (size_t) ngx_min((off_t) sizeof(chunk),
                                         b->file_last - pos);

                n = ngx_read_file(b->file, chunk, avail, pos);
                if (n <= 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "waf: reading the body file \"%V\" failed",
                                  &b->file->name);
                    return NGX_ERROR;
                }

                ngx_http_waf_sha256_update(&sha, chunk, (size_t) n);

                if (taken < place) {
                    copy = (size_t) ngx_min((off_t) n, place - taken);
                    ngx_memcpy(p + taken, chunk, copy);
                    taken += (off_t) copy;
                }

                pos  += n;
                left -= n;
            }

            continue;
        }

        avail = (size_t) ngx_min((off_t) (b->last - b->pos), left);

        ngx_http_waf_sha256_update(&sha, b->pos, avail);

        if (taken < place) {
            copy = (size_t) ngx_min((off_t) avail, place - taken);
            ngx_memcpy(p + taken, b->pos, copy);
            taken += (off_t) copy;
        }

        left -= (off_t) avail;
    }

    ngx_http_waf_sha256_final(&sha, ctx->ph->locator->sha256);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_body_key(ngx_http_waf_ctx_t *ctx, ngx_str_t *key,
    ngx_str_t *suffix)
{
    u_char                    *p;
    size_t                     len;
    ngx_str_t                 *tag;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    tag = &ngx_http_waf_body_phase_tag[
              ctx->phase >= NGX_HTTP_WAF_NPHASE ? 0 : ctx->phase];

    /*
     * <node>:<rid>:<phase>[:suffix]. Позиционный ключ, а не хеш содержимого:
     * хеш потребовал бы полного прохода по телу до начала записи, то есть
     * закрыл бы потоковое размещение навсегда, и дал бы дедупликацию, при
     * которой разрешённый запрос удаляет ключ, ещё нужный другому.
     */
    len = wmcf->node_id.len + 1 + NGX_HTTP_WAF_RID_HEX_LEN + 1 + tag->len;

    if (suffix != NULL && suffix->len != 0) {
        len += 1 + suffix->len;
    }

    p = ngx_pnalloc(ctx->request->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    key->data = p;

    p = ngx_copy(p, wmcf->node_id.data, wmcf->node_id.len);
    *p++ = ':';
    p = ngx_copy(p, ctx->rid_hex, NGX_HTTP_WAF_RID_HEX_LEN);
    *p++ = ':';
    p = ngx_copy(p, tag->data, tag->len);

    if (suffix != NULL && suffix->len != 0) {
        *p++ = ':';
        p = ngx_copy(p, suffix->data, suffix->len);
    }

    key->len = (size_t) (p - key->data);

    return NGX_OK;
}


static void
ngx_http_waf_body_unavailable(ngx_http_waf_ctx_t *ctx, ngx_uint_t reason,
    ngx_uint_t policy)
{
    ngx_http_waf_locator_t  *loc = ctx->ph->locator;

    loc->unavailable = reason;
    loc->complete    = 0;

    ngx_str_null(&loc->inline_data);
    ngx_str_null(&loc->key);
    ngx_str_null(&loc->hint);

    /*
     * Политика запоминается здесь, а не выбирается в fail_policy: превышение
     * размера и отказ хранилища управляются разными директивами, и выбирать по
     * состоянию значило бы применять waf_exception … body к тому, чем
     * распоряжается второе слово waf_body_limit.
     */
    ctx->ph->body_policy = (policy == NGX_HTTP_WAF_POLICY_TRIM)
                           ? NGX_HTTP_WAF_POLICY_BLOCK
                           : policy;
}


/* --- диагностика ---------------------------------------------------------- */

u_char *
ngx_http_waf_body_debug(ngx_http_waf_ctx_t *ctx, u_char *p, u_char *last)
{
    ngx_uint_t               i;
    ngx_http_waf_locator_t  *loc;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        loc = ngx_http_waf_store_locator(ctx, i);

        if (loc == NULL) {
            continue;
        }

        if (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE) {
            p = ngx_slprintf(p, last, " %V=unavailable:%V/%O",
                             &ngx_http_waf_objs[i].name,
                             &ngx_http_waf_body_unavail_names[loc->unavailable],
                             loc->size);
            continue;
        }

        if (loc->store.len != 0) {
            p = ngx_slprintf(p, last, " %V=%V:%V/%O",
                             &ngx_http_waf_objs[i].name, &loc->store,
                             &loc->driver, loc->size);
        }
    }

    return p;
}


/* --- локатор в сообщении -------------------------------------------------- */

static size_t
ngx_http_waf_locator_object_size(ngx_http_waf_locator_t *loc)
{
    if (loc == NULL) {
        return sizeof("null") - 1;
    }

    return sizeof("{\"store\":\"\",\"driver\":\"\",\"key\":\"\","
                  "\"size\":,\"declared_size\":,\"sha256\":\"\","
                  "\"complete\":false,\"truncated\":false,\"encoding\":\"\","
                  "\"expires_at\":,\"hint\":\"\",\"unavailable\":\"\"}")
           + 6 * (loc->store.len + loc->driver.len + loc->key.len
                  + loc->encoding.len + loc->hint.len)
           + 64 + 4 * NGX_INT_T_LEN + 32;
}


ngx_http_waf_locator_t *
ngx_http_waf_store_locator(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    return ngx_http_waf_store_locator_phase(ctx, ctx->phase, obj);
}


/*
 * Локатор чужой фазы. Нужен фазе ответа: контекст запроса едет инспектору
 * секцией request_store, и брать его неоткуда, кроме слота фазы запроса.
 */
ngx_http_waf_locator_t *
ngx_http_waf_store_locator_phase(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    return (obj == NGX_HTTP_WAF_OBJ_BODY) ? ph->locator : ph->meta[obj];
}


/*
 * Актуальная версия объекта: её видит следующая волна и она уходит получателю
 * при waf_send … =store. Оригинал остаётся в ph->locator и только там -- по
 * нему живут аудит, архив и превью, и одно поле на две правды означало бы
 * выбор между записью и отдачей.
 */
ngx_http_waf_locator_t *
ngx_http_waf_store_locator_live(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_http_waf_phase_ctx_t  *ph = &ctx->phases[phase];

    if (obj == NGX_HTTP_WAF_OBJ_BODY && ph->live != NULL) {
        return ph->live;
    }

    return ngx_http_waf_store_locator_phase(ctx, phase, obj);
}


ngx_uint_t
ngx_http_waf_obj_visible_phase(ngx_http_waf_ctx_t *ctx, ngx_uint_t phase,
    ngx_uint_t obj)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    return (wlcf->shoot[phase].capture & NGX_HTTP_WAF_OBJ_BIT(obj)) != 0;
}


size_t
ngx_http_waf_store_size(ngx_http_waf_ctx_t *ctx)
{
    size_t      size;
    ngx_uint_t  i, phase;

    /*
     * Место считается на обе секции сразу: на фазе ответа к объектам ответа
     * добавляются объекты запроса, и считать их порознь значило бы держать два
     * почти одинаковых счётчика.
     */
    size = 2 * sizeof(",\"request_store\":{}");

    for (phase = 0; phase < NGX_HTTP_WAF_NPHASE; phase++) {

        if (phase != NGX_HTTP_WAF_PHASE_REQUEST && phase != ctx->phase) {
            continue;
        }

        for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
            size += ngx_http_waf_objs[i].name.len + sizeof("\"\":,")
                    + ngx_http_waf_locator_object_size(
                          ngx_http_waf_store_locator_phase(ctx, phase, i));
        }
    }

    return size;
}


/*
 * Та же оценка, но по конфигурации: настоящих локаторов при nginx -t ещё нет,
 * а знать верхнюю границу надо заранее -- сообщение, не пролезающее в
 * max_payload шины, роняет волну целиком.
 */
size_t
ngx_http_waf_store_max_size(ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf, size_t client_max)
{
    size_t                      size;
    ngx_uint_t                  i;
    ngx_http_waf_locator_t      loc;
    ngx_http_waf_body_store_t  *store = wmcf->body_store;

    (void) wlcf;

    ngx_memzero(&loc, sizeof(ngx_http_waf_locator_t));

    if (store != NULL) {
        loc.store  = ngx_http_waf_store_hot;
        loc.driver = store->driver->name;
    }

    /* <node>:<rid>:<phase>:<суффикс>, оба тега по три байта. */
    loc.key.len = wmcf->node_id.len + NGX_HTTP_WAF_RID_HEX_LEN + 3 + 3 + 3;

    /*
     * Подсказка -- адрес узла хранилища, его ставит драйвер в рантайме;
     * кодировка приходит из Content-Encoding, то есть от клиента.
     */
    loc.hint.len     = NGX_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
    loc.encoding.len = client_max;

    size = sizeof(",\"store\":{}");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        size += ngx_http_waf_objs[i].name.len + sizeof("\"\":,")
                + ngx_http_waf_locator_object_size(&loc);
    }

    return size;
}


void
ngx_http_waf_locator_write(ngx_http_waf_jw_t *jw, ngx_http_waf_locator_t *loc,
    ngx_uint_t flags)
{
    u_char      hex[64];
    ngx_uint_t  body_meta;

    if (loc == NULL) {
        ngx_http_waf_jw_lit(jw, "null");
        return;
    }

    body_meta = flags & NGX_HTTP_WAF_LOC_BODY;

    ngx_http_waf_jw_lit(jw, "{");

    if (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE) {
        ngx_http_waf_jw_lit(jw, "\"unavailable\":");
        ngx_http_waf_jw_str(jw,
                        &ngx_http_waf_body_unavail_names[loc->unavailable]);

        ngx_http_waf_jw_lit(jw, ",\"size\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) loc->size);

        if (body_meta) {
            ngx_http_waf_jw_lit(jw, ",\"declared_size\":");
            ngx_http_waf_jw_int(jw, (ngx_int_t) loc->declared_size);
        }

        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    ngx_http_waf_jw_lit(jw, "\"size\":");
    ngx_http_waf_jw_int(jw, (ngx_int_t) loc->size);

    if (body_meta && loc->has_sha256) {
        (void) ngx_hex_dump(hex, loc->sha256, 32);

        ngx_http_waf_jw_lit(jw, ",\"sha256\":");
        ngx_http_waf_jw_string(jw, hex, 64);
    }

    if (body_meta) {
        if (loc->complete) {
            ngx_http_waf_jw_lit(jw, ",\"complete\":true");
        } else {
            ngx_http_waf_jw_lit(jw, ",\"complete\":false");
        }

        if (loc->truncated) {
            ngx_http_waf_jw_lit(jw, ",\"truncated\":true");
        } else {
            ngx_http_waf_jw_lit(jw, ",\"truncated\":false");
        }

        ngx_http_waf_jw_lit(jw, ",\"encoding\":");
        ngx_http_waf_jw_str(jw, &loc->encoding);
    }

    /*
     * Адресация -- только когда по ней ещё можно что-то достать. Ключ
     * удалённого объекта в сообщении означал бы, что читатель пойдёт за ним и
     * не найдёт, а различить "обменник потерял" и "обменник уже почистили" ему будет
     * нечем.
     */
    if (!(flags & NGX_HTTP_WAF_LOC_ADDRESS)) {
        ngx_http_waf_jw_lit(jw, "}");
        return;
    }

    if (loc->store.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"store\":");
        ngx_http_waf_jw_str(jw, &loc->store);

        ngx_http_waf_jw_lit(jw, ",\"driver\":");
        ngx_http_waf_jw_str(jw, &loc->driver);

        ngx_http_waf_jw_lit(jw, ",\"key\":");
        ngx_http_waf_jw_str(jw, &loc->key);
    }

    if (loc->expires_at != 0) {
        ngx_http_waf_jw_lit(jw, ",\"expires_at\":");
        ngx_http_waf_jw_int(jw, (ngx_int_t) loc->expires_at);
    }

    if (loc->hint.len != 0) {
        ngx_http_waf_jw_lit(jw, ",\"hint\":");
        ngx_http_waf_jw_str(jw, &loc->hint);
    }

    ngx_http_waf_jw_lit(jw, "}");
}


/*
 * Что инспектор заявил на этом маршруте, уже пересечённое с waf_capture.
 * Едет в сообщении, чтобы инспектору не приходилось держать копию
 * конфигурации у себя: "почему не приехало тело" -- вопрос к маршруту, и
 * ответ на него должен быть виден в самом сообщении.
 */
void
ngx_http_waf_needs_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_inspector_t *insp)
{
    ngx_uint_t                i, need, first;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    need = wlcf->shoot[ctx->phase].capture;

    (void) insp;

    ngx_http_waf_jw_lit(jw, ",\"needs\":[");

    for (i = 0, first = 1; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (!(need & NGX_HTTP_WAF_OBJ_BIT(i))) {
            continue;
        }

        if (!first) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        first = 0;
        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
    }

    ngx_http_waf_jw_lit(jw, "]");
}


size_t
ngx_http_waf_needs_size(void)
{
    size_t      size;
    ngx_uint_t  i;

    size = sizeof(",\"needs\":[]");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        size += ngx_http_waf_objs[i].name.len + sizeof("\",");
    }

    return size;
}


/*
 * Секция store сообщения инспектору. Три объекта одной формы под своими
 * именами: разбирать их инспектору одним и тем же кодом, а логеру -- тем же,
 * которым он разбирает секцию store в аудите.
 *
 * Объект, которого инспектор не просил, получает null, даже когда он размещён
 * для других: инспектор объявляет, что ему нужно, а не получает всё подряд.
 */
void
ngx_http_waf_store_write(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_inspector_t *insp)
{
    ngx_http_waf_store_write_phase(jw, ctx, ctx->phase, "store");
}


/*
 * Объекты названной фазы под названным именем секции. Форма одна на все фазы:
 * "store" -- объекты текущей, "request_store" -- объекты фазы запроса, и
 * разбирать их инспектор обязан одним кодом.
 */
void
ngx_http_waf_store_write_phase(ngx_http_waf_jw_t *jw, ngx_http_waf_ctx_t *ctx,
    ngx_uint_t phase, const char *section)
{
    ngx_uint_t               i;
    ngx_http_waf_locator_t  *loc;

    ngx_http_waf_jw_lit(jw, ",\"");
    ngx_http_waf_jw_raw(jw, (const u_char *) section, ngx_strlen(section));
    ngx_http_waf_jw_lit(jw, "\":{");

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {

        if (i != 0) {
            ngx_http_waf_jw_lit(jw, ",");
        }

        ngx_http_waf_jw_str(jw, &ngx_http_waf_objs[i].name);
        ngx_http_waf_jw_lit(jw, ":");

        /*
         * Актуальная версия -- только у своей фазы. Контекст чужой (секция
         * request_store на ответе и кадрах) показывает оригинал: версию фазы
         * запроса удалил тот, кто её отдал апстриму, и ключ на неё был бы
         * ключом в пустоту. Оригинал же дожил -- его держит поздняя фаза.
         */
        loc = (phase == ctx->phase)
                  ? ngx_http_waf_store_locator_live(ctx, phase, i)
                  : ngx_http_waf_store_locator_phase(ctx, phase, i);

        if (loc == NULL || !ngx_http_waf_obj_visible_phase(ctx, phase, i)) {
            ngx_http_waf_jw_lit(jw, "null");
            continue;
        }

        {
            ngx_http_waf_locator_t    shown;
            ngx_http_waf_loc_conf_t  *wlcf;
            size_t                    cap;

            shown = *loc;
            wlcf  = ngx_http_get_module_loc_conf(ctx->request,
                                                 ngx_http_waf_module);
            cap   = wlcf->shoot[phase].capture_limit[i];

            /*
             * Срез -- свойство снимка, а не версии инспектора: тот положил
             * объект целиком и назвал его размер сам. Резать его по capture
             * значило бы сказать следующей волне, что цепочка усечена, хотя
             * усечён был оригинал.
             */
            if (phase == ctx->phase && loc == ctx->phases[phase].live) {
                cap = NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE;
            }

            if (cap != NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
                && shown.size > (off_t) cap)
            {
                shown.size = (off_t) cap;
            }

            /*
             * Размер, хеш, полнота и кодировка -- это про тело: у заголовков и
             * строки запроса нет ни усечения, ни Content-Encoding. Адресация
             * инспектору нужна всегда: он читает объект, пока тот жив.
             * size в локаторе режется по capture, даже если в Redis больше.
             */
            ngx_http_waf_locator_write(jw, &shown,
                NGX_HTTP_WAF_LOC_ADDRESS
                | ((i == NGX_HTTP_WAF_OBJ_BODY) ? NGX_HTTP_WAF_LOC_BODY : 0));
        }
    }

    ngx_http_waf_jw_lit(jw, "}");
}


ngx_uint_t
ngx_http_waf_store_reload_needs_body(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_request_t       *r = ctx->request;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->ph->body_ready || ctx->ph->body_discarded) {
        return 0;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    /*
     * Тело, нужное только архиву или превью, читается здесь, после вердикта.
     * Та же проверка, что у самого reload: на исходе, где архив тело не берёт,
     * его незачем и читать -- иначе allow с when=deny дочитывал бы мегабайт
     * ради put, который тут же уйдёт под DEL.
     */
    if (!ngx_http_waf_reload_need(ctx, wlcf, NGX_HTTP_WAF_OBJ_BODY)) {
        return 0;
    }

    return (r->headers_in.content_length_n > 0 || r->headers_in.chunked);
}


/*
 * Оригинал метаобъекта поверх снимка. Собирается заново (store_raw: без
 * списков снимка, в размере reload) и сверяется с тем, что уже лежит:
 * списки могли ничего не тронуть, а размер -- не вырасти, и тогда второй put
 * положил бы те же байты тем же ключом. Объект, который снимок положить не
 * смог, кладётся заново -- это единственная попытка починить его для агента.
 */
static ngx_int_t
ngx_http_waf_meta_reload_one(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    ngx_str_t                blob;
    ngx_http_waf_locator_t  *loc = ctx->ph->meta[obj];

    if (ngx_http_waf_objs[obj].collect(ctx, &blob) != NGX_OK) {
        return NGX_ERROR;
    }

    if (loc != NULL
        && loc->unavailable == NGX_HTTP_WAF_BODY_AVAILABLE
        && loc->key.len != 0
        && blob.len == ctx->ph->store_blob[obj].len
        && ngx_memcmp(blob.data, ctx->ph->store_blob[obj].data, blob.len) == 0)
    {
        ctx->ph->raw |= NGX_HTTP_WAF_OBJ_BIT(obj);
        return NGX_OK;
    }

    ctx->ph->meta[obj] = NULL;

    return ngx_http_waf_meta_place_blob(ctx, obj, &blob);
}


/*
 * Шире ли reload того, что тело уже положило. Снимок, который не лёг
 * (превышение, отказ обменника), докладывать не к чему: агент видит причину в
 * локаторе, а второй заход в то же решение повторил бы и отказ.
 */
static ngx_uint_t
ngx_http_waf_body_reload_wider(ngx_http_waf_ctx_t *ctx)
{
    off_t                     place;
    size_t                    need, limit;
    ngx_http_waf_locator_t   *loc = ctx->ph->locator;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (loc->unavailable != NGX_HTTP_WAF_BODY_AVAILABLE) {
        return 0;
    }

    /*
     * Вне фазы запроса reload шире снимка не бывает (nginx -t), а источник
     * тела ответа к этому моменту уже мог подменить инспектор: цепочка
     * удержания -- то, что уйдёт клиенту, а не то, что пришло от апстрима.
     * Перечитывать её под ключ оригинала нельзя.
     */
    if (ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return 0;
    }

    need = ngx_http_waf_store_need_ctx(ctx, NGX_HTTP_WAF_OBJ_BODY);

    if (need == 0) {
        return 0;
    }

    wlcf  = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    limit = wlcf->body_limit[ctx->phase];
    place = ngx_http_waf_body_length(ctx);

    if (place > (off_t) limit) {

        if (wlcf->body_limit_policy[ctx->phase] != NGX_HTTP_WAF_POLICY_TRIM) {
            return 0;
        }

        place = (off_t) limit;
    }

    if (need != (size_t) -1 && place > (off_t) need) {
        place = (off_t) need;
    }

    return place > ctx->ph->body_placed_len;
}


/*
 * Суффиксы ключей, которыми модуль сам называет свои объекты: их не вправе
 * взять инспектор под свой rewrite-объект, иначе подъём подмены прочитал и
 * удалил бы заголовки запроса, которых ждёт агент.
 */
ngx_uint_t
ngx_http_waf_obj_suffix_reserved(ngx_str_t *suffix)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {
        if (suffix->len == ngx_http_waf_objs[i].suffix.len
            && ngx_memcmp(suffix->data, ngx_http_waf_objs[i].suffix.data,
                          suffix->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


ngx_int_t
ngx_http_waf_store_reload(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t                 rc;
    ngx_uint_t                i;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->ph->store_reloaded) {
        return NGX_OK;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    ctx->ph->store_raw      = 1;
    ctx->ph->reloading      = 1;
    ctx->ph->reload_issuing = 1;

    for (i = 0; i < NGX_HTTP_WAF_META_COUNT; i++) {
        if (!ngx_http_waf_reload_need(ctx, wlcf, i)) {
            continue;
        }

        if (ngx_http_waf_meta_reload_one(ctx, i) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "waf: failed to reload %V for the agent",
                          &ngx_http_waf_objs[i].name);
        }
    }

    if (ngx_http_waf_reload_need(ctx, wlcf, NGX_HTTP_WAF_OBJ_BODY)
        && ctx->ph->body_ready)
    {
        rc = ngx_http_waf_body_place(ctx);

        if (rc == NGX_AGAIN) {
            ctx->ph->reload_issuing = 0;
            return NGX_AGAIN;
        }
    }

    ctx->ph->reload_issuing = 0;

    if (ctx->ph->meta_pending != 0
        || (ctx->ph->body_op != NULL && !ctx->ph->body_settled))
    {
        return NGX_AGAIN;
    }

    ctx->ph->store_raw      = 0;
    ctx->ph->store_reloaded = 1;
    ctx->ph->reloading      = 0;

    return NGX_OK;
}
