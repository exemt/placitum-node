/*
 * Circuit breaker инспектора.
 *
 * Состояние общее для воркеров и лежит в shm-зоне. Иначе каждый воркер
 * независимо переучивается, что инспектор недоступен, и отключает его в разное
 * время: на восьми воркерах это восемь разных мнений об одном сервисе, и ни
 * одно из них не видно в метриках целиком.
 *
 * Отказом считается отсутствие годного вердикта к дедлайну. Молчание и мусор
 * здесь неотличимы нарочно: ответ, не прошедший проверку, для волны и есть
 * молчание (docs/verdict-protocol.md#ограничения-канала), и если не считать его
 * отказом, то присылать мусор становится выгоднее, чем не отвечать вовсе.
 *
 * Отказом не считается вердикт: deny, redirect и счёт -- это работающий
 * инспектор, и отключать его за то, что он блокирует трафик, значит дать
 * атакующему выключатель защиты.
 *
 * Мьютекса здесь нет: счётчики окна атомарные, а решение принимается по доле на
 * окне в секунды. Гонка на границе окна стоит одного лишнего или недостающего
 * ответа в статистике, а общий для воркеров мьютекс стоил бы на каждом ответе.
 *
 * Спецификация: docs/execution-model.md#circuit-breaker.
 */

#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


#define NGX_HTTP_WAF_BREAKER_CLOSED     0
#define NGX_HTTP_WAF_BREAKER_HALF       1
#define NGX_HTTP_WAF_BREAKER_OPEN       2

/*
 * Минимум наблюдений, до которого доля не считается. Без него первый же
 * таймаут единственного запроса за окно даёт долю 100% и выключает инспектор
 * целиком -- на маршруте с редким трафиком это происходит регулярно и выглядит
 * как случайное отключение защиты.
 */
#define NGX_HTTP_WAF_BREAKER_MIN_SAMPLES  20


static void ngx_http_waf_breaker_open(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now);
static void ngx_http_waf_breaker_close(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now);


ngx_int_t
ngx_http_waf_breaker_allow(ngx_uint_t index, ngx_http_waf_inspector_t *insp)
{
    ngx_msec_t               now, probe;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_breaker_t  *b;

    shm = ngx_http_waf_shm();

    /*
     * Без зоны breaker не работает вовсе. Держать его состояние в памяти
     * воркера было бы хуже, чем не держать: воркеры расходились бы в решениях,
     * а конфигурация выглядела бы работающей.
     */
    if (!insp->breaker || shm == NULL) {
        return NGX_OK;
    }

    b = &shm->breakers[index];

    if (b->state == NGX_HTTP_WAF_BREAKER_CLOSED) {
        return NGX_OK;
    }

    now   = ngx_current_msec;
    probe = (ngx_msec_t) b->probe_at;

    /*
     * Проба -- ровно одна на период, и право её сделать разыгрывается между
     * воркерами одним cmp_set. Иначе "ограниченная доля запросов" на восьми
     * воркерах означала бы восемь проб вместо одной, то есть восстановление
     * проверялось бы нагрузкой на неработающий сервис.
     */
    if ((ngx_msec_int_t) (now - probe) >= 0
        && ngx_atomic_cmp_set(&b->probe_at, (ngx_atomic_uint_t) probe,
                              (ngx_atomic_uint_t) (now + insp->breaker_probe)))
    {
        b->state = NGX_HTTP_WAF_BREAKER_HALF;

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "waf: circuit breaker probe for inspector \"%V\"",
                      &insp->name);

        return NGX_OK;
    }

    return NGX_DECLINED;
}


void
ngx_http_waf_breaker_result(ngx_uint_t index, ngx_http_waf_inspector_t *insp,
    ngx_uint_t timed_out)
{
    ngx_msec_t               now, epoch;
    ngx_uint_t               state, attempts, failures;
    ngx_http_waf_shm_t      *shm;
    ngx_http_waf_breaker_t  *b;

    shm = ngx_http_waf_shm();

    if (!insp->breaker || shm == NULL) {
        return;
    }

    b   = &shm->breakers[index];
    now = ngx_current_msec;

    /*
     * Скользящее окно приближено сменяемым: на истечении окна счётчики
     * обнуляются целиком. Точное скользящее окно требует кольца корзин, то есть
     * записи в несколько ячеек на каждый ответ; выигрыш в точности здесь не
     * стоит этой цены, потому что решение принимается по доле, а не по
     * абсолютному числу.
     */
    epoch = (ngx_msec_t) b->epoch;

    if ((ngx_msec_int_t) (now - epoch) >= (ngx_msec_int_t) insp->breaker_window
        && ngx_atomic_cmp_set(&b->epoch, (ngx_atomic_uint_t) epoch,
                              (ngx_atomic_uint_t) now))
    {
        b->attempts = 0;
        b->failures = 0;
    }

    (void) ngx_atomic_fetch_add(&b->attempts, 1);

    if (timed_out) {
        (void) ngx_atomic_fetch_add(&b->failures, 1);
    }

    state = (ngx_uint_t) b->state;

    /*
     * Полуоткрытое состояние решается исходом пробы, а не долей: проба для того
     * и делается, чтобы ответ одного запроса что-то значил.
     */
    if (state == NGX_HTTP_WAF_BREAKER_HALF) {

        if (timed_out) {
            ngx_http_waf_breaker_open(b, insp, now);

        } else {
            ngx_http_waf_breaker_close(b, insp, now);
        }

        return;
    }

    if (state == NGX_HTTP_WAF_BREAKER_OPEN) {
        return;                        /* поздний ответ уже отключённого */
    }

    attempts = (ngx_uint_t) b->attempts;
    failures = (ngx_uint_t) b->failures;

    if (attempts < NGX_HTTP_WAF_BREAKER_MIN_SAMPLES || failures == 0) {
        return;
    }

    if (failures * 10000 / attempts >= insp->breaker_threshold) {
        ngx_http_waf_breaker_open(b, insp, now);
    }
}


static void
ngx_http_waf_breaker_open(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now)
{
    b->probe_at = (ngx_atomic_uint_t) (now + insp->breaker_probe);
    b->epoch    = (ngx_atomic_uint_t) now;
    b->attempts = 0;
    b->failures = 0;
    b->state    = NGX_HTTP_WAF_BREAKER_OPEN;

    /*
     * Уровень WARN, а не INFO: инспектор фактически выключен, и на маршруте, где
     * блокировка держится на его счёте, это тихое ослабление защиты.
     */
    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "waf: circuit breaker opened for inspector \"%V\", "
                  "probing every %M ms", &insp->name, insp->breaker_probe);
}


static void
ngx_http_waf_breaker_close(ngx_http_waf_breaker_t *b,
    ngx_http_waf_inspector_t *insp, ngx_msec_t now)
{
    b->epoch    = (ngx_atomic_uint_t) now;
    b->attempts = 0;
    b->failures = 0;
    b->state    = NGX_HTTP_WAF_BREAKER_CLOSED;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "waf: circuit breaker closed for inspector \"%V\"",
                  &insp->name);
}
