/*
 * Зона разделяемой памяти локального слоя.
 *
 * Зона одна на конфигурацию, и её отсутствие при объявленных локальных
 * директивах -- ошибка загрузки, а не молчаливое отключение проверок: набор
 * правил, который выглядит применённым и не применяется, хуже отсутствующего.
 *
 * Разметка зоны -- ngx_http_waf_shm_t с массивами слотов фиксированной длины.
 * Это не расточительство, а условие корректности reload: старые воркеры
 * продолжают работать в той же зоне, и разметка, зависящая от числа наборов или
 * правил, означала бы, что после добавления одной директивы они читают чужую
 * память. Всё, что зависит от конфигурации, привязывается к слотам по имени.
 */

#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


/*
 * Минимум на зону. Слаб съедает страницу на служебные структуры, дерево
 * счётчиков растёт по узлу на ключ, а набор данных требует непрерывного куска;
 * зона меньше этого не работает, а выясняется это под нагрузкой.
 */
#define NGX_HTTP_WAF_SHM_MIN_SIZE   (256 * 1024)

/*
 * Оценка места на одну запись набора и запас под всё остальное в зоне:
 * разметку, счётчики частоты, предохранители, кеш кадров. См.
 * ngx_http_waf_shm_fit().
 */
#define NGX_HTTP_WAF_DS_BYTES_PER_ENTRY  128
#define NGX_HTTP_WAF_SHM_RESERVE         (256 * 1024)


static ngx_int_t ngx_http_waf_shm_init_zone(ngx_shm_zone_t *zone, void *data);


/*
 * Разметка этого воркера. Статическая переменная, а не поиск по циклу на каждое
 * обращение: в горячем пути локального слоя не должно быть ничего, кроме самой
 * проверки.
 */
static ngx_http_waf_shm_t  *ngx_http_waf_shm_ctx;


ngx_http_waf_shm_t *
ngx_http_waf_shm(void)
{
    return ngx_http_waf_shm_ctx;
}


char *
ngx_http_waf_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;

    ssize_t     size;
    ngx_str_t  *args;

    args = cf->args->elts;

    if (wmcf->shm_zone != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_shm_zone is already declared as \"%V\"",
                           &wmcf->shm_name);
        return NGX_CONF_ERROR;
    }

    size = ngx_parse_size(&args[2]);

    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid zone size \"%V\"", &args[2]);
        return NGX_CONF_ERROR;
    }

    if (size < NGX_HTTP_WAF_SHM_MIN_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: zone \"%V\" is too small, minimum is %d bytes",
                           &args[1], NGX_HTTP_WAF_SHM_MIN_SIZE);
        return NGX_CONF_ERROR;
    }

    /*
     * Тег -- адрес модуля: зона с тем же именем, заведённая другим модулем, это
     * ошибка конфигурации, и ngx_shared_memory_add обязан её увидеть, а не
     * отдать нам чужую разметку.
     */
    wmcf->shm_zone = ngx_shared_memory_add(cf, &args[1], (size_t) size,
                                           &ngx_http_waf_module);
    if (wmcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * data остаётся пустым до инициализации зоны: nginx передаёт в init
     * значение data предыдущего поколения, и хранить в нём что-либо, кроме
     * разметки, значит получить при reload не разметку, а конфигурацию.
     */
    wmcf->shm_zone->init = ngx_http_waf_shm_init_zone;

    wmcf->shm_name = args[1];

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_waf_shm_required(ngx_conf_t *cf, const char *directive)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (wmcf != NULL && wmcf->shm_zone != NULL) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: %s requires waf_shm_zone to be declared",
                       directive);

    return NGX_ERROR;
}


/*
 * Влезут ли объявленные наборы в зону.
 *
 * Список знает свой размер: `limit=` у waf_local_dataset -- это потолок
 * состава, и место под него надо иметь заранее. Зона, в которую объявленное
 * не влезает, -- это дыра: край возьмёт часть состава, а на остальном будет
 * отвечать «записи нет», то есть пропускать ровно то, что обязан резать, и
 * молча. Поэтому не загружаемся -- как и с инспекторами без шины.
 *
 * Оценка на запись -- по самому дорогому уровню, overlay: узел там это
 * offsetof(rbtree_node, color) + offsetof(live_node, data) + значение, а слаб
 * округляет аллокацию к своему классу, то есть 128 байт на адрес. База дешевле
 * даже с двойной пересборкой (у IPv4 три uint32 и uint64 хеша -- 20 байт, 40
 * на пике), поэтому одна оценка покрывает оба. Записи длиннее полусотни байт
 * уедут в следующий класс слаба; для них остаётся отказ на самой записи.
 */
ngx_int_t
ngx_http_waf_shm_fit(ngx_conf_t *cf)
{
    off_t                      need;
    ngx_uint_t                 i, entries;
    ngx_http_waf_dataset_t    *ds;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (wmcf == NULL || wmcf->shm_zone == NULL || wmcf->datasets == NULL) {
        return NGX_OK;
    }

    ds   = wmcf->datasets->elts;
    need = NGX_HTTP_WAF_SHM_RESERVE;

    for (i = 0; i < wmcf->datasets->nelts; i++) {
        /*
         * У внутреннего набора состав известен точно -- он в конфигурации;
         * у активного его присылает keeper, и заранее известен только потолок.
         */
        entries = ds[i].mode == NGX_HTTP_WAF_DS_MODE_INTERNAL
                      ? (ds[i].entries != NULL ? ds[i].entries->nelts : 0)
                      : ds[i].max;

        need += (off_t) entries * NGX_HTTP_WAF_DS_BYTES_PER_ENTRY;
    }

    if (need <= (off_t) wmcf->shm_zone->shm.size) {
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: zone \"%V\" of %uz bytes does not fit the "
                       "declared datasets: they need about %O bytes "
                       "(%d per entry plus %d of overhead). Raise "
                       "waf_shm_zone or lower limit= on the datasets",
                       &wmcf->shm_name, wmcf->shm_zone->shm.size, need,
                       NGX_HTTP_WAF_DS_BYTES_PER_ENTRY,
                       NGX_HTTP_WAF_SHM_RESERVE);

    return NGX_ERROR;
}


/*
 * Инициализация зоны. Вызывается в мастере при загрузке и при reload; data
 * непуст, когда зона того же имени и размера уже существует, то есть при
 * reload разметка переиспользуется вместе с накопленным состоянием -- иначе
 * каждый reload сбрасывал бы и счётчики частоты, и наборы данных, и открытые
 * breaker'ы.
 */
static ngx_int_t
ngx_http_waf_shm_init_zone(ngx_shm_zone_t *zone, void *data)
{
    ngx_http_waf_shm_t  *shm = data;

    size_t            len;
    ngx_slab_pool_t  *shpool;

    /*
     * Зона переиспользуется: разметка та же, а таблица кеша кадров могла ещё
     * не заводиться -- прежняя конфигурация о кеше не знала. Доводится здесь,
     * из того же слаба.
     */
    if (shm != NULL) {
        ngx_http_waf_shm_ctx = shm;
        return ngx_http_waf_fcache_init(shm, zone);
    }

    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (zone->shm.exists) {
        /*
         * Зона унаследована от мастера при бинарном обновлении: разметка уже
         * построена, и строить её заново значило бы потерять состояние, которое
         * старые воркеры продолжают использовать.
         */
        ngx_http_waf_shm_ctx = shpool->data;
        zone->data           = shpool->data;

        return ngx_http_waf_fcache_init(shpool->data, zone);
    }

    shm = ngx_slab_calloc(shpool, sizeof(ngx_http_waf_shm_t));
    if (shm == NULL) {
        return NGX_ERROR;
    }

    shm->shpool = shpool;

    ngx_rbtree_init(&shm->rate, &shm->rate_sentinel,
                    ngx_http_waf_rate_insert_value);
    ngx_queue_init(&shm->rate_lru);

    shpool->data = shm;

    /*
     * Строка контекста слаба печатается в сообщении об исчерпании зоны. Без неё
     * администратор видит "ngx_slab_alloc() failed" без указания, какая зона
     * кончилась, а зон в конфигурации обычно несколько.
     */
    len = sizeof(" in waf zone \"\"") - 1 + zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in waf zone \"%V\"%Z", &zone->shm.name);

    ngx_http_waf_shm_ctx = shm;
    zone->data           = shm;

    return ngx_http_waf_fcache_init(shm, zone);
}
