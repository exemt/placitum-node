/*
 * Волны маршрута: группировка waf_inspect по номеру wave=.
 *
 * Всё считается при загрузке конфигурации и превращается в битовые маски. В
 * горячем пути не остаётся ни поиска по строке, ни обхода графа: волна -- это
 * три слова, и условие "все ответили" -- одно сравнение.
 */

#include "ngx_http_waf.h"
#include "bus/ngx_http_waf_bus.h"
#include "codec/ngx_http_waf_codec.h"


static void ngx_http_waf_resume_cleanup(void *data);


ngx_http_waf_binding_t *
ngx_http_waf_binding_find(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index,
    ngx_uint_t phase)
{
    ngx_uint_t               i;
    ngx_http_waf_binding_t  *b;

    if (wlcf->inspects[phase] == NULL) {
        return NULL;
    }

    b = wlcf->inspects[phase]->elts;

    for (i = 0; i < wlcf->inspects[phase]->nelts; i++) {
        if (b[i].index == index) {
            return &b[i];
        }
    }

    return NULL;
}


/*
 * Доедет ли просьба до адресата на этом маршруте.
 *
 * Имя адресата проверено по реестру, но реестр -- это объявления контура, а
 * не набор маршрута: имя может быть объявлено в http {} и не стоять здесь ни
 * одной строкой waf_inspect. Тогда просьба не доходит ни до кого, и до сих
 * пор это была молчаливая потеря -- канал рекомендательный, и "никто не
 * применил" выглядит ровно так же, как "применить было некому".
 *
 * В своей фазе адресат обязан стоять строго позже отправителя: волна, которая
 * уже высказалась, секцию prior больше не читает. На последующих фазах волна
 * не важна -- prior сквозная, и просьба фазы запроса доживает до фазы ответа
 * и до кадров.
 */
ngx_uint_t
ngx_http_waf_action_deliverable(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t to,
    ngx_uint_t phase, ngx_uint_t wave)
{
    ngx_uint_t               p;
    ngx_http_waf_binding_t  *b;

    b = ngx_http_waf_binding_find(wlcf, to, phase);

    if (b != NULL && b->wave > wave) {
        return 1;
    }

    for (p = phase + 1; p < NGX_HTTP_WAF_NPHASE; p++) {
        if (ngx_http_waf_binding_find(wlcf, to, p) != NULL) {
            return 1;
        }
    }

    return 0;
}


/* --- продолжение между фазами --------------------------------------------- */

/*
 * Спросят ли инспектора снова. Смотрятся фазы после названной: продолжение
 * выдаёт та, что раньше, а resume= пишется на той, что потребляет. Кадры сюда
 * попадут сами собой -- их фазы стоят в перечислении после ответа.
 */
ngx_uint_t
ngx_http_waf_resume_wanted(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index,
    ngx_uint_t phase)
{
    ngx_http_waf_binding_t  *b;

    /*
     * Явно, по keep= на строке запроса, а не выведено из resume= поздней
     * фазы. Выведенное нигде не написано: читая строку запроса, нельзя было
     * понять, что за ней кто-то вернётся, -- и наоборот, resume= на ответе
     * молча означал работу для инспектора фазы запроса. Парность двух строк
     * проверена при загрузке (ngx_http_waf_check_resume_pairs), поэтому
     * здесь достаточно одной.
     */
    if (phase != NGX_HTTP_WAF_PHASE_REQUEST) {
        return 0;
    }

    b = ngx_http_waf_binding_find(wlcf, index, phase);

    return b != NULL && b->keep;
}


ngx_int_t
ngx_http_waf_check_resume_pairs(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf)
{
    ngx_uint_t                 i, n, phase, later;
    ngx_array_t               *list;
    ngx_http_waf_binding_t    *b, *rb;
    ngx_http_waf_loc_conf_t  **confs, *wlcf;

    if (wmcf->loc_confs == NULL) {
        return NGX_OK;
    }

    confs = wmcf->loc_confs->elts;

    for (n = 0; n < wmcf->loc_confs->nelts; n++) {
        wlcf = confs[n];

        /*
         * Только листья: сервер с keep=on на запросе и resume= в каждом
         * location сам по себе пары не составляет, но каждый его маршрут
         * согласован. Выключенный уровень не спрашивает никого, и его пары
         * никого не держат.
         */
        if (wlcf->has_children || !wlcf->enable) {
            continue;
        }

        list = wlcf->inspects[NGX_HTTP_WAF_PHASE_REQUEST];

        if (list != NULL) {
            b = list->elts;

            for (i = 0; i < list->nelts; i++) {

                if (!b[i].keep) {
                    continue;
                }

                later = ngx_http_waf_resume_phase(wlcf, b[i].index,
                                                  NGX_HTTP_WAF_PHASE_REQUEST);

                if (later == NGX_HTTP_WAF_NPHASE) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf: \"%V\" keeps its state on "
                                       "request (keep=on) but no later "
                                       "phase resumes it in location "
                                       "\"%V\"; add resume= on response "
                                       "or drop keep=",
                                       &b[i].name, &wlcf->name);
                    return NGX_ERROR;
                }
            }
        }

        for (phase = NGX_HTTP_WAF_PHASE_REQUEST + 1;
             phase < NGX_HTTP_WAF_NPHASE;
             phase++)
        {
            list = wlcf->inspects[phase];

            if (list == NULL) {
                continue;
            }

            b = list->elts;

            for (i = 0; i < list->nelts; i++) {

                if (b[i].resume == NGX_HTTP_WAF_RESUME_OFF) {
                    continue;
                }

                rb = ngx_http_waf_binding_find(wlcf, b[i].index,
                                               NGX_HTTP_WAF_PHASE_REQUEST);

                if (rb == NULL || !rb->keep) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "waf: \"%V\" resumes on %V but its "
                                       "request line does not keep the "
                                       "state in location \"%V\"; add "
                                       "keep=on to waf_inspect request %V",
                                       &b[i].name,
                                       ngx_http_waf_phase_name(phase),
                                       &wlcf->name, &b[i].name);
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}


/*
 * Срез снимка при отдаче объекта из обменника -- предупреждение: объект,
 * уложившийся в срез, поднимется, объект шире среза -- сбой подъёма по
 * waf_exception … body (умолчание -- отказ), и раскладку стоит показать
 * заранее, а не первым отказом в журнале. Заголовков и строки запроса это не
 * касается: их правки ложатся по имени поверх оригинала.
 *
 * Права на подмену в реестре больше нет (mutate= снят), поэтому проверка
 * смотрит на маршрут, а не на имена: спрашивают ли на фазе хоть кого-то и
 * отдаётся ли объект из обменника. Ошибки "подмена против monitor" здесь тоже
 * больше нет -- отпущенный ответ уже у клиента, но это исход рантайма (WARN и
 * applied:false), а не негодная конфигурация: с правом у всех она валила бы
 * законные маршруты, где на ответе стоит один modsec. Проверка по листьям, как
 * у пар keep=/resume=.
 *
 * Смотрится только СКАЗАННОЕ оператором (`send[ph][obj]` не UNSET): store --
 * теперь умолчание всех объектов, и на подставленном оно превратило бы
 * предупреждение в шум на каждом маршруте со срезом тела, включая те, где
 * никто ничего не подменяет.
 */
ngx_int_t
ngx_http_waf_check_send_routes(ngx_conf_t *cf,
    ngx_http_waf_main_conf_t *wmcf)
{
    ngx_uint_t                  n, ph, obj;
    ngx_array_t                *list;
    ngx_http_waf_loc_conf_t   **confs, *wlcf;
    ngx_http_waf_shoot_conf_t  *sh;

    if (wmcf->loc_confs == NULL) {
        return NGX_OK;
    }

    confs = wmcf->loc_confs->elts;

    for (n = 0; n < wmcf->loc_confs->nelts; n++) {
        wlcf = confs[n];

        if (wlcf->has_children || !wlcf->enable) {
            continue;
        }

        for (ph = 0; ph < NGX_HTTP_WAF_NPHASE; ph++) {
            list = wlcf->inspects[ph];

            if (list == NULL || list->nelts == 0) {
                continue;
            }

            sh = &wlcf->shoot[ph];

            for (obj = 0; obj < NGX_HTTP_WAF_OBJ_COUNT; obj++) {

                if (obj != NGX_HTTP_WAF_OBJ_BODY
                    || !(sh->capture & NGX_HTTP_WAF_OBJ_BIT(obj))
                    || sh->capture_limit[obj]
                       == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE
                    || wlcf->send[ph][obj] != NGX_HTTP_WAF_SEND_STORE)
                {
                    continue;
                }

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "waf: location \"%V\" sends the %V %V "
                                   "from the store (waf_send %V %V=store) "
                                   "while \"waf_capture %V %V=%uz\" takes a "
                                   "prefix; an object wider than the slice "
                                   "cannot be served from the store and its "
                                   "rewrite fails per waf_exception <phase> "
                                   "body -- capture the whole object or send "
                                   "the original",
                                   &wlcf->name,
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   ngx_http_waf_phase_name(ph),
                                   ngx_http_waf_obj_name(obj),
                                   sh->capture_limit[obj]);
            }
        }
    }

    return NGX_OK;
}


ngx_uint_t
ngx_http_waf_resume_phase(ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t index,
    ngx_uint_t phase)
{
    ngx_uint_t               later;
    ngx_http_waf_binding_t  *b;

    for (later = phase + 1; later < NGX_HTTP_WAF_NPHASE; later++) {

        b = ngx_http_waf_binding_find(wlcf, index, later);

        if (b != NULL && b->resume != NGX_HTTP_WAF_RESUME_OFF) {
            return later;
        }
    }

    return NGX_HTTP_WAF_NPHASE;
}


ngx_str_t *
ngx_http_waf_resume_subject(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    ngx_http_waf_binding_t   *b;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (ctx->cont == NULL || ctx->cont[index].subject.len == 0) {
        return NULL;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    b    = ngx_http_waf_binding_find(wlcf, index, ctx->phase);

    if (b == NULL || b->resume == NGX_HTTP_WAF_RESUME_OFF) {
        return NULL;
    }

    /*
     * Срок обещал экземпляр, и после него состояния может уже не быть. Идти по
     * личному subject всё равно можно -- он ответит, -- но переигровка выйдет
     * дороже на лишний круг по шине, а результат будет тот же.
     */
    if ((ngx_msec_int_t) (ngx_current_msec - ctx->cont[index].expires) >= 0) {
        return NULL;
    }

    return &ctx->cont[index].subject;
}


/*
 * Запрос кончился, а состояние у инспектора осталось. Так бывает чаще, чем
 * кажется: отказал другой инспектор на волне раньше, фаза ответа обошлась
 * стороной (204, 304, апгрейд, подзапрос), клиент оборвался, апстрим не
 * ответил. Во всех этих случаях экземпляр держит транзакцию, которую никто не
 * спросит, и держит её до своего срока -- то есть память на каждый такой
 * запрос.
 *
 * Отсюда сообщение в один конец: «не нужно, брось». Оно ничего не ждёт и
 * ничего не гарантирует; срок на стороне инспектора остаётся страховкой. Тот
 * же порядок, что у объектов обменника: удаляем явно, ttl -- на случай падения
 * между двумя действиями.
 *
 * Адрес -- общая тема освобождений инспектора, а не личная тема экземпляра.
 * Причина в том самом «отказал другой инспектор раньше»: волна замыкается на
 * его вердикте, наш ответ приходит в закрытый слот и отбрасывается вместе с
 * продолжением, и личного адреса модуль в этом случае не знает вовсе. Общая
 * тема доходит до всех экземпляров; ключ есть только у одного, остальные
 * ничего не находят и ничего не делают.
 */
static void
ngx_http_waf_resume_cleanup(void *data)
{
    ngx_http_waf_resume_release(data);
}


void
ngx_http_waf_resume_release(ngx_http_waf_ctx_t *ctx)
{
    u_char                     buf[512];
    u_char                     sbuf[256];
    u_char                    *p;
    ngx_str_t                  payload, subject;
    ngx_uint_t                 i, phase, denied;
    ngx_http_waf_jw_t          jw;
    ngx_http_waf_bus_t        *bus;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->resume_asked == 0) {
        return;
    }


    bus = ngx_http_waf_bus_current();

    if (bus == NULL || bus->publish_audit == NULL) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    /*
     * Причина одна на запрос и грубая: инспектору она нужна не для решения --
     * решать по ней нечего, -- а чтобы в его логе было видно, почему липкость
     * на этом маршруте не срабатывает. Отказ и обход одинаковы по счётчикам и
     * совершенно различны по смыслу.
     */
    denied = 0;

    for (i = 0; i < NGX_HTTP_WAF_NPHASE; i++) {
        if (ctx->phases[i].verdict == NGX_HTTP_WAF_V_DENY) {
            denied = 1;
            break;
        }
    }

    for (i = 0; i < wmcf->inspectors.nelts; i++) {

        if (!(ctx->resume_asked & (1ULL << i))) {
            continue;
        }

        ctx->resume_asked &= ~(1ULL << i);

        phase = ngx_http_waf_resume_phase(wlcf, i, NGX_HTTP_WAF_PHASE_REQUEST);

        if (phase == NGX_HTTP_WAF_NPHASE) {
            phase = NGX_HTTP_WAF_PHASE_RESPONSE;
        }

        /*
         * Адрес строится на стеке, а не в пуле запроса: этот код исполняется
         * из уборки пула, а nginx обнуляет r->pool перед ngx_destroy_pool().
         * Аллокация здесь -- разыменование NULL, и найти это можно только
         * падением воркера.
         */
        subject.data = sbuf;
        p = ngx_slprintf(sbuf, sbuf + sizeof(sbuf), "%V.release",
                         &insp[i].subject);
        subject.len = (size_t) (p - sbuf);

        /*
         * Конверт тот же, что у сообщения инспекции: экземпляр проверяет имя и
         * фазу теми же правилами, и освобождение от чужого имени отвергается
         * там же, где отвергается чужой вердикт.
         */
        ngx_http_waf_jw_init(&jw, buf, sizeof(buf));

        ngx_http_waf_jw_lit(&jw, "{\"v\":");
        ngx_http_waf_jw_int(&jw, NGX_HTTP_WAF_PROTOCOL_VERSION);
        ngx_http_waf_jw_lit(&jw, ",\"rid\":\"");
        ngx_http_waf_jw_raw(&jw, (const u_char *) ctx->rid_hex,
                            NGX_HTTP_WAF_RID_HEX_LEN);
        ngx_http_waf_jw_lit(&jw, "\",\"inspector\":");
        ngx_http_waf_jw_str(&jw, &insp[i].name);
        ngx_http_waf_jw_lit(&jw, ",\"phase\":");
        ngx_http_waf_jw_str(&jw, ngx_http_waf_phase_name(phase));
        ngx_http_waf_jw_lit(&jw, ",\"release\":{\"token\":\"");
        ngx_http_waf_jw_raw(&jw, (const u_char *) ctx->ray_hex,
                            NGX_HTTP_WAF_RAY_HEX_LEN);
        ngx_http_waf_jw_lit(&jw, "\",\"reason\":");

        /*
         * Двумя ветками, а не тернарником: jw_lit -- макрос, он берёт длину
         * через sizeof литерала, и у тернарника это размер указателя.
         */
        if (denied) {
            ngx_http_waf_jw_lit(&jw, "\"deny\"");

        } else {
            ngx_http_waf_jw_lit(&jw, "\"skip\"");
        }

        ngx_http_waf_jw_lit(&jw, "}}");

        if (!ngx_http_waf_jw_ok(&jw)) {
            continue;
        }

        payload.data = buf;
        payload.len  = ngx_http_waf_jw_len(&jw);

        (void) bus->publish_audit(bus, &subject, &payload);

        /*
         * Строкой, а не молча: липкость либо работает, либо тихо не работает, и
         * разницу между «продолжение не понадобилось» и «продолжение
         * потерялось» больше взять неоткуда.
         */
        ngx_log_error(NGX_LOG_INFO, ctx->request->connection->log, 0,
                      "waf: continuation released for \"%V\", ray %*s",
                      &insp[i].name,
                      (size_t) NGX_HTTP_WAF_RAY_HEX_LEN, ctx->ray_hex);
    }
}


ngx_int_t
ngx_http_waf_resume_ask(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    ngx_pool_cleanup_t  *cln;

    if (ctx->resume_asked & (1ULL << index)) {
        return NGX_OK;                 /* уже просили: волна переспрашивает */
    }

    if (ctx->resume_asked == 0) {
        /*
         * Состояние у инспектора -- то же, что объект в обменнике: держит его
         * чужой процесс, а освободить обязаны мы. Уборка регистрируется на
         * первом вопросе: маршрут без липкости за неё не платит.
         */
        cln = ngx_pool_cleanup_add(ctx->request->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_resume_cleanup;
        cln->data    = ctx;
    }

    ctx->resume_asked |= (1ULL << index);

    return NGX_OK;
}


/*
 * Забыть продолжение: состояние либо уже забрали публикацией следующей фазы,
 * либо экземпляр исчез. Снимается и бит вопроса -- освобождать больше нечего.
 */
void
ngx_http_waf_resume_forget(ngx_http_waf_ctx_t *ctx, ngx_uint_t index)
{
    ctx->resume_asked &= ~(1ULL << index);

    if (ctx->cont != NULL) {
        ngx_str_null(&ctx->cont[index].subject);
    }
}


ngx_int_t
ngx_http_waf_resume_keep(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_str_t *subject, ngx_msec_t ttl)
{
    u_char                    *p;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (ctx->cont == NULL) {
        ctx->cont = ngx_pcalloc(ctx->request->pool,
                                wmcf->inspectors.nelts
                                    * sizeof(ngx_http_waf_cont_t));
        if (ctx->cont == NULL) {
            return NGX_ERROR;
        }
    }

    /*
     * Копия в пул запроса: ответ инспектора живёт до конца разбора, а
     * пользуется subject следующая фаза -- к тому времени буфера уже нет.
     */
    p = ngx_pnalloc(ctx->request->pool, subject->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, subject->data, subject->len);

    ctx->cont[index].subject.data = p;
    ctx->cont[index].subject.len  = subject->len;
    ctx->cont[index].expires      = ngx_current_msec + ttl;

    return NGX_OK;
}


ngx_array_t *
ngx_http_waf_waves_build(ngx_conf_t *cf, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_uint_t phase)
{
    ngx_uint_t                  i, n, wave, first, cap_body;
    ngx_array_t                *waves;
    ngx_http_waf_wave_t        *w;
    ngx_http_waf_mask_t         bit;
    ngx_http_waf_binding_t     *b;
    ngx_http_waf_inspector_t   *insp;
    ngx_http_waf_shoot_conf_t  *sh = &wlcf->shoot[phase];

    insp = wmcf->inspectors.elts;

    for (i = 0; i < wmcf->inspectors.nelts; i++) {
        wlcf->profiles[i] = insp[i].profile;
    }

    waves = ngx_array_create(cf->pool, 2, sizeof(ngx_http_waf_wave_t));
    if (waves == NULL) {
        return NULL;
    }

    if (wlcf->inspects[phase] == NULL || wlcf->inspects[phase]->nelts == 0) {
        return waves;
    }

    b = wlcf->inspects[phase]->elts;
    n = wlcf->inspects[phase]->nelts;

    first    = 1;
    cap_body = (sh->capture & NGX_HTTP_WAF_OBJ_BIT(NGX_HTTP_WAF_OBJ_BODY))
               != 0;

    for (wave = 0; wave <= NGX_HTTP_WAF_MAX_WAVE; wave++) {

        w = NULL;

        for (i = 0; i < n; i++) {

            if (b[i].phase != phase || b[i].wave != wave) {
                continue;
            }

            if (w == NULL) {
                w = ngx_array_push(waves);
                if (w == NULL) {
                    return NULL;
                }

                ngx_memzero(w, sizeof(ngx_http_waf_wave_t));
                w->obj_need = sh->capture;

                if (first && cap_body) {
                    if (sh->capture_limit[NGX_HTTP_WAF_OBJ_BODY]
                        == NGX_HTTP_WAF_CAPTURE_LIMIT_WHOLE)
                    {
                        w->body_need = NGX_HTTP_WAF_BODY_FULL;

                    } else {
                        w->body_need    = NGX_HTTP_WAF_BODY_PREVIEW;
                        w->body_preview =
                            sh->capture_limit[NGX_HTTP_WAF_OBJ_BODY];
                    }
                }

                first = 0;
            }

            bit = (ngx_http_waf_mask_t) 1 << b[i].index;
            w->all |= bit;

            /*
             * off попадает и в all: включённый соседом он публикуется как
             * обязательный, а в passive/mandatory конфигурации его нет --
             * действующие маски считает ngx_http_waf_wave_*().
             *
             * vote -- обязательный по ожиданию (его очки нужны сумме) и
             * помечен отдельно: вердикт такого читается как очки.
             */
            if (b[i].mode == NGX_HTTP_WAF_MODE_OFF) {
                w->off |= bit;

            } else if (b[i].mode == NGX_HTTP_WAF_MODE_PASSIVE) {
                w->passive |= bit;

            } else if (b[i].mode == NGX_HTTP_WAF_MODE_VOTE) {
                w->mandatory |= bit;
                w->vote      |= bit;

            } else {
                w->mandatory |= bit;
            }
        }
    }

    return waves;
}
