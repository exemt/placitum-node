/*
 * Разрешение вердикта фазы.
 *
 * Всё, что зависит от порядка прихода ответов, -- это гонка, поэтому исход
 * считается один раз по накопленным ответам, а не по мере их поступления.
 * Единственное намеренное исключение -- выбор виновника отказа в режиме
 * waf_deny_mode fast, и он выражен явно полем order.
 *
 * Лестница решения -- verdict-protocol.md#разрешение-конфликтов:
 *
 *   1. явный deny                      -> deny по ответу этого инспектора
 *   2. total >= waf_score_deny         -> deny с кодом SCORE_THRESHOLD
 *   3. явный redirect                  -> redirect по ответу инспектора
 *   4. иначе                              allow
 *
 * Из накопленного счёта следует только отказ. Челлендж модуль не назначает:
 * кому и когда доказывать, что он человек, решает сервис, который этот
 * челлендж ведёт, -- он видит и счёт предыдущих волн, и вердикты в prior, и
 * присылает готовый redirect. Модуль ниже порога отказа просто не мешает.
 *
 * Пассивные и совещательные инспекторы не участвуют ни в одной ступени: их
 * вклад идёт в теневую сумму и в лог.
 */

#include "ngx_http_waf.h"
#include "local/ngx_http_waf_local.h"


static ngx_http_waf_reply_t *ngx_http_waf_pick(ngx_http_waf_ctx_t *ctx,
    ngx_uint_t verdict, ngx_uint_t *index);


static ngx_str_t  ngx_http_waf_verdict_names[] = {
    ngx_string("allow"),
    ngx_string("score"),
    ngx_string("redirect"),
    ngx_string("deny"),
    ngx_string("error")
};


/*
 * Имя фазы на проводе. У кадров оно одно на оба направления: инспектор видит
 * phase "frame" и stream.direction, а не две разные фазы.
 */
static ngx_str_t  ngx_http_waf_phase_names[] = {
    ngx_string("request"),
    ngx_string("response"),
    ngx_string("frame"),
    ngx_string("frame")
};


/* Порядок -- ngx_http_waf_do_e. */
static ngx_str_t  ngx_http_waf_do_names[] = {
    ngx_string("challenge"),
    ngx_string("threshold"),
    ngx_string("skip"),
    ngx_string("reauth"),
    ngx_string("note"),
    ngx_string("mutate"),
    ngx_string("active"),
    ngx_string("passive"),
    ngx_string("off"),
    ngx_string("vote"),
    ngx_string("audit"),
    ngx_string("archive"),
    ngx_string("mark"),
    ngx_string("score"),
    ngx_string("ban")
};


/* Порядок -- ngx_http_waf_apply_e. */
static ngx_str_t  ngx_http_waf_apply_names[] = {
    ngx_string("request"),
    ngx_string("ip"),
    ngx_string("asn"),
    ngx_string("session"),
    ngx_string("conn"),
    ngx_string("response")
};


/* Порядок -- ngx_http_waf_code_e. */
static ngx_str_t  ngx_http_waf_code_names[] = {
    ngx_string(""),
    ngx_string("local_list"),
    ngx_string("local_rate"),
    ngx_string("inspector"),
    ngx_string("score"),
    ngx_string("fail_timeout"),
    ngx_string("fail_absent"),
    ngx_string("fail_bus"),
    ngx_string("fail_body"),
    ngx_string("fail_inspector"),
    ngx_string("fail_overload"),
    ngx_string("local_upgrade")
};


/* Порядок -- ngx_http_waf_exc_e. */
static ngx_str_t  ngx_http_waf_exc_names[] = {
    ngx_string("timeout"),
    ngx_string("absent"),
    ngx_string("bus"),
    ngx_string("body"),
    ngx_string("inspector"),
    ngx_string("overload")
};


/* Порядок -- ngx_http_waf_deny_scope_e. */
static ngx_str_t  ngx_http_waf_deny_scope_names[] = {
    ngx_string(""),
    ngx_string("address"),
    ngx_string("network"),
    ngx_string("country"),
    ngx_string("asn"),
    ngx_string("session"),
    ngx_string("request")
};


/* Порядок -- ngx_http_waf_entry_state_e. */
static ngx_str_t  ngx_http_waf_entry_state_names[] = {
    ngx_string(""),
    ngx_string("timeout"),
    ngx_string("absent"),
    ngx_string("skipped"),
    ngx_string("off")
};


ngx_str_t *
ngx_http_waf_verdict_name(ngx_uint_t verdict)
{
    /*
     * Граница по последнему имени таблицы, а не по V_DENY: инспектор, который
     * не смог проверить, печатался бы в записи как "allow" -- ровно то враньё,
     * ради которого заведён error.
     */
    if (verdict > NGX_HTTP_WAF_V_ERROR) {
        verdict = NGX_HTTP_WAF_V_ALLOW;
    }

    return &ngx_http_waf_verdict_names[verdict];
}


ngx_str_t *
ngx_http_waf_do_name(ngx_uint_t verb)
{
    if (verb > NGX_HTTP_WAF_DO_LAST) {
        verb = NGX_HTTP_WAF_DO_LAST;
    }

    return &ngx_http_waf_do_names[verb];
}


ngx_str_t *
ngx_http_waf_apply_name(ngx_uint_t axis)
{
    if (axis > NGX_HTTP_WAF_APPLY_LAST) {
        axis = NGX_HTTP_WAF_APPLY_REQUEST;
    }

    return &ngx_http_waf_apply_names[axis];
}


ngx_str_t *
ngx_http_waf_phase_name(ngx_uint_t phase)
{
    if (phase >= NGX_HTTP_WAF_NPHASE) {
        phase = NGX_HTTP_WAF_PHASE_REQUEST;
    }

    return &ngx_http_waf_phase_names[phase];
}


/*
 * Маска фаз адресата -- словом провода: request, response либо frame (обе
 * стороны кадров одним словом, как у первого слова waf_inspect). Маска
 * приходит из разбора теми же тремя словами, поэтому другой здесь не бывает;
 * на всякий случай неизвестная печатается как frame -- единственная, что
 * шире одного слота.
 */
ngx_str_t *
ngx_http_waf_to_phase_name(ngx_uint_t phases)
{
    static ngx_str_t  frame = ngx_string("frame");

    if (phases == NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_REQUEST)) {
        return &ngx_http_waf_phase_names[NGX_HTTP_WAF_PHASE_REQUEST];
    }

    if (phases == NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_PHASE_RESPONSE)) {
        return &ngx_http_waf_phase_names[NGX_HTTP_WAF_PHASE_RESPONSE];
    }

    return &frame;
}


ngx_str_t *
ngx_http_waf_code_name(ngx_uint_t code)
{
    if (code > NGX_HTTP_WAF_CODE_LOCAL_UPGRADE) {
        code = NGX_HTTP_WAF_CODE_NONE;
    }

    return &ngx_http_waf_code_names[code];
}


/*
 * Код срыва волны -> класс события waf_exception. Всё, что не срыв, попадает
 * в timeout: это недостижимо (политику спрашивают только на сорванной волне),
 * а выбирать между молчанием и падением не из чего.
 */
ngx_uint_t
ngx_http_waf_exc_of(ngx_uint_t code)
{
    switch (code) {

    case NGX_HTTP_WAF_CODE_FAIL_ABSENT:
        return NGX_HTTP_WAF_EXC_ABSENT;

    case NGX_HTTP_WAF_CODE_FAIL_BUS:
        return NGX_HTTP_WAF_EXC_BUS;

    case NGX_HTTP_WAF_CODE_FAIL_BODY:
        return NGX_HTTP_WAF_EXC_BODY;

    case NGX_HTTP_WAF_CODE_FAIL_INSPECTOR:
        return NGX_HTTP_WAF_EXC_INSPECTOR;

    case NGX_HTTP_WAF_CODE_FAIL_OVERLOAD:
        return NGX_HTTP_WAF_EXC_OVERLOAD;

    default:
        return NGX_HTTP_WAF_EXC_TIMEOUT;
    }
}


ngx_str_t *
ngx_http_waf_exc_name(ngx_uint_t exc)
{
    if (exc >= NGX_HTTP_WAF_EXC_COUNT) {
        exc = NGX_HTTP_WAF_EXC_TIMEOUT;
    }

    return &ngx_http_waf_exc_names[exc];
}


/*
 * Слово с провода в код. Линейный перебор словаря из шести значений: таблица
 * короче любого индекса, который под неё завели бы, а вызывается разбор один
 * раз на ответ с deny.
 */
ngx_uint_t
ngx_http_waf_deny_scope_parse(ngx_str_t *word)
{
    ngx_uint_t  i;

    for (i = NGX_HTTP_WAF_SCOPE_ADDRESS; i <= NGX_HTTP_WAF_SCOPE_REQUEST; i++) {
        if (word->len == ngx_http_waf_deny_scope_names[i].len
            && ngx_strncmp(word->data, ngx_http_waf_deny_scope_names[i].data,
                           word->len) == 0)
        {
            return i;
        }
    }

    return NGX_HTTP_WAF_SCOPE_NONE;
}


ngx_str_t *
ngx_http_waf_deny_scope_name(ngx_uint_t scope)
{
    if (scope > NGX_HTTP_WAF_SCOPE_REQUEST) {
        scope = NGX_HTTP_WAF_SCOPE_NONE;
    }

    return &ngx_http_waf_deny_scope_names[scope];
}


ngx_str_t *
ngx_http_waf_entry_state_name(ngx_uint_t state)
{
    if (state > NGX_HTTP_WAF_ENTRY_OFF) {
        state = NGX_HTTP_WAF_ENTRY_ANSWERED;
    }

    return &ngx_http_waf_entry_state_names[state];
}


ngx_int_t
ngx_http_waf_score_deny_at(ngx_http_waf_ctx_t *ctx)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);

    /*
     * У фазы запроса и фазы ответа отдельные суммы и отдельные пороги: они
     * измеряют разное, и складывать подозрительность запроса с
     * подозрительностью ответа означало бы блокировать ответ за грехи уже
     * пропущенного запроса.
     */
    return wlcf->score_deny[ctx->phase];
}


/*
 * Учёт одного ответа. Вызывается в момент прихода, потому что адресат суммы
 * (боевая или теневая) известен сразу, а хранить необработанные ответы, чтобы
 * сложить их потом, значит удваивать работу без причины.
 */
void
ngx_http_waf_account(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    reply->order = ++ctx->ph->order;

    /*
     * Перенаправлять некого: заголовки ответа уже собраны, а у кадра
     * соединение установлено. Вердикт отбрасывается целиком, а не понижается
     * до allow молча -- в логе он остаётся, и расхождение конфигурации
     * маршрута с поведением инспектора видно.
     */
    if (reply->verdict == NGX_HTTP_WAF_V_REDIRECT
        && ctx->phase != NGX_HTTP_WAF_PHASE_REQUEST)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: redirect from inspector %ui dropped on phase %V: "
                      "there is nobody left to redirect", index,
                      ngx_http_waf_phase_name(ctx->phase));

        reply->verdict = NGX_HTTP_WAF_V_ALLOW;
        return;
    }

    /*
     * Совещательный голос: deny -- это сто очков. Число кладётся в score
     * самого ответа: аудит и prior печатают его тем же полем, что и у
     * вердикта score, -- "что легло в сумму", -- и объяснение итога сходится
     * без знания режимов маршрута. Сам вердикт остаётся deny: соседям и
     * журналу важно, что инспектор сказал, а не как модуль это прочёл.
     */
    if (reply->vote && reply->verdict == NGX_HTTP_WAF_V_DENY) {
        reply->score = NGX_HTTP_WAF_SCORE_MAX;

    } else if (reply->verdict != NGX_HTTP_WAF_V_SCORE) {
        return;
    }

    if (reply->score <= 0) {
        return;
    }

    /*
     * Пассивный идёт в теневую сумму. Смысл теневой суммы -- увидеть, каким
     * был бы счёт после перевода инспектора в боевые, не влияя на трафик.
     * Множителя нет: сколько инспектор прислал, столько и легло.
     */
    if (reply->passive) {
        ctx->ph->shadow += reply->score;

    } else {
        ctx->ph->score += reply->score;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: inspector %ui scored %i, total %i",
                   index, reply->score, ctx->ph->score);
}


/*
 * Действия принятого ответа -- в живой набор запроса.
 *
 * Здесь, а не в разборе: пассивность отправителя -- свойство маршрута, а не
 * ответа, и проставить её обязан модуль. Пассивный инспектор не должен влиять
 * на трафик чужими руками, поэтому его просьбы едут с меткой, а применять их
 * или нет, решает правило в профиле получателя.
 *
 * Ключ записи -- from + to + do + code: повтор заменяет прежнюю запись, так
 * инспектор уточняет сказанное на поздней фазе, не тратя место в бюджете.
 * Переполнение отбрасывает новые: вытеснять старые нельзя -- тогда болтливый
 * инспектор стирает чужие просьбы, и отказ получается тихим и чужим.
 */
void
ngx_http_waf_actions_merge(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply, ngx_uint_t wave)
{
    ngx_uint_t                 i, j, found;
    ngx_http_waf_action_t     *src, *live, *slot;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (reply->actions == NULL || reply->actions->nelts == 0) {
        return;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    if (wlcf->actions_max == 0) {
        return;
    }

    if (ctx->actions == NULL) {
        ctx->actions = ngx_array_create(ctx->request->pool, 4,
                                        sizeof(ngx_http_waf_action_t));
        if (ctx->actions == NULL) {
            return;
        }
    }

    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];
    src  = reply->actions->elts;

    for (i = 0; i < reply->actions->nelts; i++) {

        src[i].from    = index;
        src[i].phase   = ctx->phase;
        src[i].wave    = wave;
        src[i].passive = reply->passive;

        /*
         * Управляющий глагол исполняет модуль, и прямо здесь: следующая волна
         * публикуется по действующим маскам, а они меняются этой просьбой.
         * Отклонённая просьба в набор не попадает -- соседям её показывать
         * не о чем, причина уже в логе.
         */
        if (ngx_http_waf_do_control(src[i].verb)
            && ngx_http_waf_control_apply(ctx, &src[i]) != NGX_OK)
        {
            continue;
        }

        /*
         * Глагол записи -- тоже здесь: запись фазы собирается после волн, и
         * маска архива считается по тому, что к тому моменту сказано.
         */
        if (ngx_http_waf_do_audit(src[i].verb)
            && ngx_http_waf_audit_ovr_apply(ctx, &src[i]) != NGX_OK)
        {
            continue;
        }

        /*
         * Маркер -- тоже здесь: множество собирается по ходу волн, а печатает
         * его запись фазы. Не поместившийся в множество остаётся в наборе
         * действий: его высказали, и это факт записи, -- но метки в ней не
         * будет, и расхождение видно на месте.
         */
        if (ngx_http_waf_do_mark(src[i].verb)) {
            (void) ngx_http_waf_markers_add(ctx, &src[i]);
        }

        /*
         * Бан -- тоже здесь, на приёме ответа: запись в набор нужна не этому
         * запросу (его судьбу решает вердикт), а следующим, и чем раньше она
         * уедет к keeper, тем меньше их проскочит. Несостоявшаяся запись
         * просьбу из набора не убирает: её высказали, и это факт записи, а
         * почему не вышло -- сказано в логе края.
         */
        if (ngx_http_waf_do_ban(src[i].verb)) {
            (void) ngx_http_waf_ban_apply(ctx, &src[i]);
        }

        /*
         * Очки -- тоже здесь: порог смотрят по закрытии волны, и к тому
         * моменту сумма обязана быть собрана. Отклонённая просьба (пассивный
         * отправитель) в набор не попадает -- причина уже в логе.
         */
        if (ngx_http_waf_do_score(src[i].verb)
            && ngx_http_waf_score_apply(ctx, &src[i]) != NGX_OK)
        {
            continue;
        }

        live  = ctx->actions->elts;
        found = 0;

        /*
         * Ось и корзина -- часть ключа замены: "один факт на две оси -- два
         * действия" (docs/inspector-actions.md), и с одним поводом они обязаны
         * жить рядом, а не затирать друг друга. То же у note с разными
         * корзинами: селектор различает просьбы, которые ключ без него склеил
         * бы в одну.
         */
        for (j = 0; j < ctx->actions->nelts; j++) {

            if (live[j].from != src[i].from
                || live[j].to != src[i].to
                || live[j].to_phases != src[i].to_phases
                || live[j].verb != src[i].verb
                || live[j].apply != src[i].apply
                || live[j].code.len != src[i].code.len
                || live[j].counter.len != src[i].counter.len
                || live[j].group.len != src[i].group.len
                || live[j].marker.len != src[i].marker.len)
            {
                continue;
            }

            if (live[j].code.len != 0
                && ngx_memcmp(live[j].code.data, src[i].code.data,
                              src[i].code.len) != 0)
            {
                continue;
            }

            if (live[j].counter.len != 0
                && ngx_memcmp(live[j].counter.data, src[i].counter.data,
                              src[i].counter.len) != 0)
            {
                continue;
            }

            /* Группа -- часть ключа, сторона -- нет: "включить, потом выключить" -- замена. */
            if (live[j].group.len != 0
                && ngx_memcmp(live[j].group.data, src[i].group.data,
                              src[i].group.len) != 0)
            {
                continue;
            }

            /*
             * Метка -- часть ключа: две разные метки одного отправителя --
             * две просьбы, а не уточнение одной. Ключ без неё склеил бы их,
             * и в аудите осталась бы последняя.
             */
            if (live[j].marker.len != 0
                && ngx_memcmp(live[j].marker.data, src[i].marker.data,
                              src[i].marker.len) != 0)
            {
                continue;
            }

            live[j] = src[i];
            found   = 1;
            break;
        }

        if (found) {
            continue;
        }

        if (ctx->actions->nelts >= wlcf->actions_max) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: action \"%V\" from inspector \"%V\" dropped: "
                          "waf_actions_max reached",
                          ngx_http_waf_do_name(src[i].verb), &insp->name);
            continue;
        }

        slot = ngx_array_push(ctx->actions);
        if (slot == NULL) {
            return;
        }

        *slot = src[i];
    }
}


/*
 * Сессии принятого ответа -- в запись запроса.
 *
 * Здесь, а не в разборе, по той же причине, что и действия: пассивность
 * отправителя -- свойство маршрута, и метку ставит модуль. Запись пассивного
 * в аудит попадает -- это единственное место, где видно, кого назвала бы
 * калитка, будь она боевой, -- но с меткой.
 *
 * Ключ записи -- отправитель + источник + id: повтор заменяет прежнюю запись
 * (фаза ответа уточняет сказанное на запросе), переполнение отбрасывает
 * новые -- вытеснять чужие нельзя, иначе болтливый инспектор стирает
 * записи соседей.
 */
void
ngx_http_waf_sessions_merge(ngx_http_waf_ctx_t *ctx, ngx_uint_t index,
    ngx_http_waf_reply_t *reply)
{
    ngx_uint_t                 i, j, found;
    ngx_http_waf_session_t    *src, *live, *slot;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (reply->sessions == NULL || reply->sessions->nelts == 0) {
        return;
    }

    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[index];

    if (ctx->sessions == NULL) {
        ctx->sessions = ngx_array_create(ctx->request->pool, 2,
                                         sizeof(ngx_http_waf_session_t));
        if (ctx->sessions == NULL) {
            return;
        }
    }

    src = reply->sessions->elts;

    for (i = 0; i < reply->sessions->nelts; i++) {

        src[i].by      = index;
        src[i].passive = reply->passive;

        live  = ctx->sessions->elts;
        found = 0;

        for (j = 0; j < ctx->sessions->nelts; j++) {

            if (live[j].by != src[i].by
                || live[j].source.len != src[i].source.len
                || live[j].id.len != src[i].id.len)
            {
                continue;
            }

            if (ngx_memcmp(live[j].source.data, src[i].source.data,
                           src[i].source.len) != 0)
            {
                continue;
            }

            if (src[i].id.len != 0
                && ngx_memcmp(live[j].id.data, src[i].id.data,
                              src[i].id.len) != 0)
            {
                continue;
            }

            live[j] = src[i];
            found   = 1;
            break;
        }

        if (found) {
            continue;
        }

        if (ctx->sessions->nelts >= NGX_HTTP_WAF_SESSIONS_MAX) {
            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: session \"%V\" from inspector \"%V\" dropped: "
                          "too many sessions on the request",
                          &src[i].source, &insp->name);
            continue;
        }

        slot = ngx_array_push(ctx->sessions);
        if (slot == NULL) {
            return;
        }

        *slot = src[i];
    }
}


/*
 * Маркер принятого ответа -- в множество меток записи.
 *
 * Множество, а не список высказываний: в записи стоит метка, а не "modsec
 * сказал bot-farm, и counter сказал bot-farm". Кто и по какому поводу просил,
 * видно в actions той же записи -- туда просьба ложится всегда, в том числе
 * не поместившаяся сюда.
 *
 * Пассивного отправителя слушают, как и у глаголов записи: метка трафика не
 * касается вовсе, а "что пометил бы включённый инспектор" -- ровно тот
 * вопрос, ради которого пассивный режим и держат.
 */
ngx_int_t
ngx_http_waf_markers_add(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    ngx_uint_t                 i;
    ngx_str_t                 *live, *slot;
    ngx_http_waf_inspector_t  *insp;
    ngx_http_waf_main_conf_t  *wmcf;

    if (a->marker.len == 0) {
        return NGX_DECLINED;
    }

    if (ctx->markers == NULL) {
        ctx->markers = ngx_array_create(ctx->request->pool, 4,
                                        sizeof(ngx_str_t));
        if (ctx->markers == NULL) {
            return NGX_ERROR;
        }
    }

    live = ctx->markers->elts;

    for (i = 0; i < ctx->markers->nelts; i++) {

        if (live[i].len == a->marker.len
            && ngx_memcmp(live[i].data, a->marker.data, a->marker.len) == 0)
        {
            return NGX_OK;
        }
    }

    if (ctx->markers->nelts >= NGX_HTTP_WAF_MARKERS_MAX) {
        wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
        insp = &((ngx_http_waf_inspector_t *) wmcf->inspectors.elts)[a->from];

        ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                      "waf: marker \"%V\" from inspector \"%V\" dropped: "
                      "too many markers on the request", &a->marker,
                      &insp->name);

        return NGX_DECLINED;
    }

    slot = ngx_array_push(ctx->markers);
    if (slot == NULL) {
        return NGX_ERROR;
    }

    *slot = a->marker;

    return NGX_OK;
}


/*
 * Очки на маршруте.
 *
 * value просьбы сдвигает вклад отправителя: reply->score -- это "что легло в
 * сумму", и после просьбы он обязан сходиться с суммой так же, как до неё,
 * иначе арифметику итога в аудите не собрать. Вклад держится в -100..100 (один
 * инспектор не сильнее сотни ни в какую сторону), сумма фазы ниже нуля не
 * уходит: снять можно только то, что набрано, и на столько же уменьшается
 * применённая часть просьбы. Пассивный не просит: на трафик он не влияет ни
 * вердиктом, ни очками. Совещательный -- просит: он участник решения.
 */
ngx_int_t
ngx_http_waf_score_apply(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    ngx_int_t                  was, now, applied;
    ngx_http_waf_reply_t      *reply;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_inspector_t  *insp;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    if (a->passive) {
        if (!wlcf->score_warned) {
            wlcf->score_warned = 1;

            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: score action from inspector \"%V\" refused: "
                          "the sender is passive on this route "
                          "(reported once)", &insp[a->from].name);
        }

        return NGX_DECLINED;
    }

    if (ctx->ph->replies == NULL || a->from >= wmcf->inspectors.nelts) {
        return NGX_DECLINED;
    }

    reply = &ctx->ph->replies[a->from];

    was = reply->score;
    now = was + a->value;

    if (now > NGX_HTTP_WAF_SCORE_MAX) {
        now = NGX_HTTP_WAF_SCORE_MAX;

    } else if (now < -NGX_HTTP_WAF_SCORE_MAX) {
        now = -NGX_HTTP_WAF_SCORE_MAX;
    }

    applied = now - was;

    if (ctx->ph->score + applied < 0) {
        applied = -ctx->ph->score;
    }

    reply->score   = was + applied;
    ctx->ph->score += applied;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: score action from %ui: %i asked, %i applied, "
                   "total %i", a->from, a->value, applied, ctx->ph->score);

    return NGX_OK;
}


/*
 * Что глагол делает с масками: режим один на инспектора, последний сказавший
 * прав -- четыре бита взаимно исключают друг друга.
 */
void
ngx_http_waf_control_set(ngx_http_waf_control_t *ctl, ngx_uint_t verb,
    ngx_http_waf_mask_t bit)
{
    ctl->active  &= ~bit;
    ctl->passive &= ~bit;
    ctl->off     &= ~bit;
    ctl->vote    &= ~bit;

    switch (verb) {

    case NGX_HTTP_WAF_DO_ACTIVE:
        ctl->active |= bit;
        break;

    case NGX_HTTP_WAF_DO_PASSIVE:
        ctl->passive |= bit;
        break;

    case NGX_HTTP_WAF_DO_OFF:
        ctl->off |= bit;
        break;

    case NGX_HTTP_WAF_DO_VOTE:
        ctl->vote |= bit;
        break;
    }
}


/*
 * Исполнение управляющего глагола.
 *
 * Разрешения не требуется: управляющие глаголы принимает любой вызов от
 * любого инспектора, спрошенного на маршруте. Проверяется одно -- адресат
 * действительно стоит здесь: в названной фазе, а без поля phase -- хоть в
 * одной; иначе режим ставят строке, которой на маршруте нет, и просьба тихо
 * пропадает. Молчать про это нельзя: обе стороны выглядят исправными, а
 * инспектора то не зовут, то зовут не так, как задумано.
 *
 * Адресат -- вызов, и у имени их столько, на скольких фазах оно стоит: без
 * phase режим получают все, с phase -- вызов названной фазы (frame -- обе
 * стороны кадров). Маски по фазам независимы: passive на ответе не трогает
 * запрос.
 *
 * Пассивный отправитель управлять не может: его просьбы едут соседям с
 * меткой, и решают те, а здесь решать некому, кроме модуля, -- и он
 * отказывает. Ось conn существует только на кадрах.
 */
ngx_int_t
ngx_http_waf_control_apply(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    static ngx_str_t           everyone = ngx_string("*");
    ngx_uint_t                 p, phases, accepted;
    const char                *why;
    ngx_http_waf_mask_t        bit;
    ngx_http_waf_control_t    *conn;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_inspector_t  *insp;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    why      = NULL;
    accepted = 0;
    phases   = (a->to_phases != 0) ? a->to_phases
                                   : (NGX_HTTP_WAF_PH_BIT(NGX_HTTP_WAF_NPHASE)
                                      - 1);

    if (a->to == NGX_HTTP_WAF_ACTION_ALL) {
        why = "control verbs need an addressee";

    } else if (a->passive) {
        why = "the sender is passive on this route";

    } else if (a->apply == NGX_HTTP_WAF_APPLY_CONN
               && !ngx_http_waf_phase_is_frame(ctx->phase))
    {
        why = "apply=conn exists only on frames";

    } else {
        for (p = 0; p < NGX_HTTP_WAF_NPHASE; p++) {
            if ((phases & NGX_HTTP_WAF_PH_BIT(p))
                && ngx_http_waf_binding_find(wlcf, a->to, p) != NULL)
            {
                accepted = 1;
                break;
            }
        }

        if (!accepted) {
            why = (a->to_phases != 0)
                  ? "the addressee is not called on this route in that phase"
                  : "the addressee is not called on this route";
        }
    }

    if (why != NULL) {
        if (!wlcf->control_warned) {
            wlcf->control_warned = 1;

            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: control action \"%V\" from inspector "
                          "\"%V\" to \"%V\" refused: %s (reported once)",
                          ngx_http_waf_do_name(a->verb), &insp[a->from].name,
                          (a->to == NGX_HTTP_WAF_ACTION_ALL)
                              ? &everyone : &insp[a->to].name,
                          why);
        }

        return NGX_DECLINED;
    }

    bit  = 1ULL << a->to;
    conn = (a->apply == NGX_HTTP_WAF_APPLY_CONN)
           ? ngx_http_waf_frame_control(ctx) : NULL;

    /*
     * Бит ставится во все названные фазы, а не только туда, где адресат
     * стоит: маска фазы без его строки безвредна -- волна берёт её через
     * w->all, -- а выяснять привязку заново на каждой волне незачем.
     */
    for (p = 0; p < NGX_HTTP_WAF_NPHASE; p++) {
        if ((phases & NGX_HTTP_WAF_PH_BIT(p)) == 0) {
            continue;
        }

        ngx_http_waf_control_set(&ctx->ctl[p], a->verb, bit);

        if (conn != NULL) {
            ngx_http_waf_control_set(&conn[p], a->verb, bit);
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: control %V from %ui to %ui applied, phases %ui",
                   ngx_http_waf_do_name(a->verb), a->from, a->to, phases);

    return NGX_OK;
}


/*
 * Что глагол записи делает с состоянием: у каждого из двух своё поле,
 * archive on переписывает срок, предел и набор целиком -- повтор с тем же
 * глаголом заменяет прежнюю просьбу, а не дописывает её.
 */
static void
ngx_http_waf_audit_ovr_set(ngx_http_waf_audit_ovr_t *ovr,
    ngx_http_waf_action_t *a)
{
    ngx_http_waf_ovr_part_t  *part;

    part = (a->verb == NGX_HTTP_WAF_DO_AUDIT) ? &ovr->audit : &ovr->archive;

    *part     = a->spec;
    part->set = a->set;
}


/*
 * Исполнение глагола записи: audit -- журнал, archive -- архив этого запроса.
 *
 * Разрешения не требуется: сказать своё про запись маршрута вправе любой
 * спрошенный инспектор -- адресат здесь не вызов соседа, а запись самого
 * запроса.
 *
 * Пассивного отправителя, в отличие от управляющих глаголов, слушают: в
 * решение по трафику запись не входит, а "спрашивать ради лога" -- ровно тот
 * режим, в котором улики и нужны.
 */
ngx_int_t
ngx_http_waf_audit_ovr_apply(ngx_http_waf_ctx_t *ctx, ngx_http_waf_action_t *a)
{
    const char                *why;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;
    ngx_http_waf_inspector_t  *insp;

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);
    insp = wmcf->inspectors.elts;

    why = NULL;

    if (a->apply == NGX_HTTP_WAF_APPLY_RESPONSE
        && ngx_http_waf_phase_is_frame(ctx->phase))
    {
        /*
         * Не отбраковка ответа целиком: одна и та же строка профиля
         * (modsec на кадрах) бежит и на запросе, и на кадрах, и ронять
         * инспектора в молчуны из-за неё нельзя.
         */
        why = "frames have no response record";
    }

    if (why != NULL) {
        if (!wlcf->audit_ovr_warned) {
            wlcf->audit_ovr_warned = 1;

            ngx_log_error(NGX_LOG_WARN, ctx->request->connection->log, 0,
                          "waf: audit action \"%V\" from inspector \"%V\" "
                          "refused: %s (reported once)",
                          ngx_http_waf_do_name(a->verb), &insp[a->from].name,
                          why);
        }

        return NGX_DECLINED;
    }

    /*
     * Ось называет запись: request -- запись запроса (на кадре -- этот
     * кадр, а просьба с рукопожатия -- все кадры соединения: её состояние
     * кадр наследует, stream/ngx_http_waf_frame.c), response -- запись
     * ответа этой транзакции. С фазы ответа доступны обе: запись запроса
     * на маршруте с грантом ждёт исхода (ngx_http_waf_archive_pending).
     */
    ngx_http_waf_audit_ovr_set(
        &ctx->audit_ovr[(a->apply == NGX_HTTP_WAF_APPLY_RESPONSE)
                        ? NGX_HTTP_WAF_OVR_RESPONSE : NGX_HTTP_WAF_OVR_REQUEST],
        a);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "waf: audit action %V from %ui applied",
                   ngx_http_waf_do_name(a->verb), a->from);

    return NGX_OK;
}


/*
 * Кого волна не публикует: записанные с mode=off, которым никто не поставил
 * active/passive/vote, и те, кому сосед поставил off.
 *
 * Волна принадлежит текущей фазе, и маски управления берутся её экземпляра:
 * глагол с полем phase лёг только туда, без поля -- во все.
 */
ngx_http_waf_mask_t
ngx_http_waf_wave_off(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_control_t  *ctl = &ctx->ctl[ctx->phase];

    return (w->all & ctl->off)
           | (w->off & ~(ctl->active | ctl->passive | ctl->vote));
}


/*
 * Записанный режим держится, пока глагол не поставил другой: сосед, сказавший
 * active или vote, снимает записанный passive, и наоборот.
 */
ngx_http_waf_mask_t
ngx_http_waf_wave_passive(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_mask_t      live;
    ngx_http_waf_control_t  *ctl = &ctx->ctl[ctx->phase];

    live = w->all & ~ngx_http_waf_wave_off(ctx, w);

    return (ctl->passive | (w->passive & ~(ctl->active | ctl->vote))) & live;
}


ngx_http_waf_mask_t
ngx_http_waf_wave_vote(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_mask_t      live;
    ngx_http_waf_control_t  *ctl = &ctx->ctl[ctx->phase];

    live = w->all & ~ngx_http_waf_wave_off(ctx, w);

    return (ctl->vote | (w->vote & ~(ctl->active | ctl->passive))) & live;
}


/*
 * Обязательные -- все живые, кроме пассивных: совещательные тоже здесь, их
 * очки нужны сумме, и молчание такого включает политику дедлайна как у
 * боевого.
 */
ngx_http_waf_mask_t
ngx_http_waf_wave_mandatory(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    ngx_http_waf_mask_t  live;

    live = w->all & ~ngx_http_waf_wave_off(ctx, w);

    return live & ~ngx_http_waf_wave_passive(ctx, w);
}


ngx_http_waf_mask_t
ngx_http_waf_wave_gating(ngx_http_waf_ctx_t *ctx, ngx_http_waf_wave_t *w)
{
    return ngx_http_waf_wave_mandatory(ctx, w) & ~ngx_http_waf_wave_vote(ctx, w);
}


void
ngx_http_waf_resolve_verdict(ngx_http_waf_ctx_t *ctx)
{
    ngx_int_t              threshold;
    ngx_uint_t             index;
    ngx_http_waf_reply_t  *reply;

    ctx->ph->decisive       = NULL;
    ctx->ph->decisive_index = 0;
    ctx->ph->by_score       = 0;
    ctx->ph->code           = NGX_HTTP_WAF_CODE_NONE;
    index               = 0;

    /* 1. Явный deny выше порога: он утверждает факт, а не оценку. */
    reply = ngx_http_waf_pick(ctx, NGX_HTTP_WAF_V_DENY, &index);

    if (reply != NULL) {
        ctx->ph->verdict        = NGX_HTTP_WAF_V_DENY;
        ctx->ph->decisive       = reply;
        ctx->ph->decisive_index = index;
        ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;
        ctx->state          = NGX_HTTP_WAF_ST_DENY;
        return;
    }

    /* 2. Порог блокировки. */
    threshold = ngx_http_waf_score_deny_at(ctx);

    if (threshold > 0 && ctx->ph->score >= threshold) {
        ctx->ph->verdict  = NGX_HTTP_WAF_V_DENY;
        ctx->ph->by_score = 1;
        ctx->ph->code     = NGX_HTTP_WAF_CODE_SCORE;
        ctx->state    = NGX_HTTP_WAF_ST_DENY;
        return;
    }

    /* 3. Явный redirect: цель уже проверена при разборе ответа. */
    reply = ngx_http_waf_pick(ctx, NGX_HTTP_WAF_V_REDIRECT, &index);

    if (reply != NULL) {
        ctx->ph->verdict        = NGX_HTTP_WAF_V_REDIRECT;
        ctx->ph->decisive       = reply;
        ctx->ph->decisive_index = index;
        ctx->ph->code           = NGX_HTTP_WAF_CODE_INSPECTOR;
        ctx->state          = NGX_HTTP_WAF_ST_REDIRECT;
        return;
    }

    /* 4. Иначе пропуск -- либо политика отказа, если вердикта не хватило. */
    ctx->ph->verdict = NGX_HTTP_WAF_V_ALLOW;

    ctx->state = (ctx->ph->fail != NGX_HTTP_WAF_CODE_NONE)
                     ? NGX_HTTP_WAF_ST_FAILED
                     : NGX_HTTP_WAF_ST_ALLOW;
}


/*
 * Ответ, определяющий исход. В режиме fast -- пришедший первым: короткое
 * замыкание уже сэкономило остаток бюджета, и притворяться, что выбор был
 * другим, незачем. В режиме deterministic -- наивысший по порядку объявления
 * waf_inspector, то есть с наименьшим индексом.
 */
static ngx_http_waf_reply_t *
ngx_http_waf_pick(ngx_http_waf_ctx_t *ctx, ngx_uint_t verdict,
    ngx_uint_t *index)
{
    ngx_uint_t                 i, n, best_order;
    ngx_http_waf_reply_t      *reply, *best;
    ngx_http_waf_loc_conf_t   *wlcf;
    ngx_http_waf_main_conf_t  *wmcf;

    if (ctx->ph->replies == NULL) {
        return NULL;
    }

    wlcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_waf_module);
    wmcf = ngx_http_get_module_main_conf(ctx->request, ngx_http_waf_module);

    n          = wmcf->inspectors.nelts;
    best       = NULL;
    best_order = 0;

    for (i = 0; i < n; i++) {
        reply = &ctx->ph->replies[i];

        if (!reply->received || reply->verdict != verdict) {
            continue;
        }

        /*
         * Пассивный не гейтит: его deny попадает в лог и в debug-заголовок, но
         * исхода не меняет. Ровно для этого режим и существует -- увидеть, что
         * инспектор заблокировал бы, ничего не заблокировав. Совещательный не
         * гейтит тоже: его deny уже лёг в сумму сотней очков, а redirect
         * остаётся в журнале.
         */
        if (reply->passive || reply->vote) {
            continue;
        }

        if (best == NULL) {
            best       = reply;
            best_order = reply->order;
            *index     = i;
            continue;
        }

        if (wlcf->deny_mode[ctx->phase] == NGX_HTTP_WAF_DENY_FAST
            && reply->order < best_order)
        {
            best       = reply;
            best_order = reply->order;
            *index     = i;
        }
    }

    return best;
}
