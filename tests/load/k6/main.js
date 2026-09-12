// Точка входа генератора. Сценарий выбирается переменной SCENARIO, состав
// трафика -- переменными долей; и то и другое описано в README.md и
// scenarios.md.
//
//     docker compose -f compose.load.yml --profile gen run --rm k6 run /scripts/main.js

import http from 'k6/http';
import exec from 'k6/execution';
import { Counter, Trend } from 'k6/metrics';

import { skeletons, F } from './lib/corpus.js';
import { buildRequest, inspectorLatency, FLAVOR_NAME } from './lib/request.js';
import { buildOptions, CONFIG } from './lib/options.js';
import { seeded } from './lib/rand.js';

export const options = buildOptions();

// 303 и 403 -- штатные исходы, а не ошибки: редирект на челлендж по вердикту
// инспектора и отказ по вердикту или порогу. Без этого http_req_failed показывал
// бы долю ошибок, равную доле заблокированного трафика, то есть был бы бесполезен.
http.setResponseCallback(http.expectedStatuses(200, 303, 403, 503));

const M_WAF = 'http_req_duration{branch:waf,flavor:normal,phase:measure}';
const M_CTL = 'http_req_duration{branch:control,flavor:normal,phase:measure}';
const M_WAF_ALL = 'http_req_duration{branch:waf,flavor:normal}';
const M_CTL_ALL = 'http_req_duration{branch:control,flavor:normal}';

const unexpected = new Counter('unexpected_status');
const aborted = new Counter('client_aborted');
const abortRaced = new Counter('client_abort_raced');
const inspectorMs = new Trend('waf_inspector_ms');

const N = skeletons.length;
const SEED = Number(__ENV.CORPUS_SEED || 20260813);
const WARMUP_MS = parseDuration(__ENV.WARMUP || '30s');

// Сценарий поиска потолка стенда идёт целиком по ветке waf off: измеряется
// генератор, балансировщик, origin и сеть, но не модуль.
const FORCE_CONTROL = CONFIG.SCENARIO === 'ceiling';

// Индекс в корпусе берётся из PRNG, засеянного зерном прогона и номером VU.
//
// Обход постоянным шагом здесь был бы ошибкой, и не очевидной: если у всех VU
// шаг один, а стартовое смещение кратно этому же шагу, весь флот идёт по одной
// арифметической прогрессии плотной группой. При 20 VU по 150 итераций из
// 20000 записей корпуса реально используются около 170 -- трафик выглядит
// разнообразным, а на деле это полторы сотни повторяющихся запросов.
let rnd = null;
let vuHex = null;
let seq = 0;

export default function () {
    if (rnd === null) {
        rnd = seeded((SEED ^ Math.imul(exec.vu.idInTest, 0x9e3779b1)) >>> 0);
        vuHex = exec.vu.idInTest.toString(16).padStart(8, '0');
    }

    const sk = skeletons[Math.floor(rnd() * N)];
    const req = buildRequest(sk, marker(), FORCE_CONTROL);

    req.params.tags.phase =
        exec.instance.currentTestRunDuration >= WARMUP_MS ? 'measure' : 'warmup';

    const res = http.request(req.method, req.url, req.body, req.params);

    if (req.flavor === F.ABORT) {
        // Обрыв -- цель этого запроса, а не сбой. Если ответ всё же успел
        // прийти, это не ошибка, но и не то, что сценарий хотел проверить.
        if (res.status === 0) {
            aborted.add(1);
        } else {
            abortRaced.add(1);
        }
        return;
    }

    if (res.status !== req.expected) {
        unexpected.add(1, {
            flavor: FLAVOR_NAME[req.flavor],
            expected: String(req.expected),
            got: String(res.status),
        });
    }

    if (req.flavor === F.DEBUG) {
        const ms = inspectorLatency(res);
        if (ms !== null) {
            inspectorMs.add(ms);
        }
    }
}

function marker() {
    seq++;
    return vuHex + seq.toString(16).padStart(24, '0');
}

function parseDuration(s) {
    const m = /^(\d+)(ms|s|m|h)?$/.exec(String(s).trim());
    if (!m) {
        return 0;
    }
    const v = Number(m[1]);
    switch (m[2]) {
        case 'ms': return v;
        case 'm': return v * 60000;
        case 'h': return v * 3600000;
        default: return v * 1000;
    }
}

// --------------------------------------------------------------- отчёт ----

export function handleSummary(data) {
    const report = textReport(data);
    const dir = `/results/${CONFIG.RUN_ID}`;

    const out = { stdout: report };
    out[`${dir}/summary.json`] = JSON.stringify(data, null, 2);
    out[`${dir}/report.txt`] = report;

    return out;
}

function textReport(data) {
    const L = [];
    const m = data.metrics;

    // Если прогрев накрыл весь прогон, разрез phase:measure пуст -- тогда
    // берётся тот же разрез без него, и об этом говорится в заголовке секции.
    const measured = q(m[M_WAF], 'p(99)') !== null;
    const waf = measured ? m[M_WAF] : m[M_WAF_ALL];
    const ctl = measured ? m[M_CTL] : m[M_CTL_ALL];

    const wafP99 = q(waf, 'p(99)');
    const ctlP99 = q(ctl, 'p(99)');
    const wafP50 = q(waf, 'med');
    const ctlP50 = q(ctl, 'med');

    // Замеров может не быть вовсе: контрольная ветка отключена CONTROL_RATIO=0
    // либо весь прогон уложился в прогрев. Разница квантилей в этом случае --
    // не ноль, а отсутствующая величина, и показывать её нулём нельзя.
    const wafN = count(waf);
    const ctlN = count(ctl);

    L.push('=========================================================');
    L.push(` прогон ${CONFIG.RUN_ID}   сценарий ${CONFIG.SCENARIO}`);
    L.push('=========================================================');
    L.push('');

    L.push('-- интенсивность ----------------------------------------');
    L.push(row('запросов', count(m.http_reqs)));
    L.push(row('фактический rps', rate(m.http_reqs)));
    L.push(row('итераций пропущено', count(m.dropped_iterations)));
    L.push('');

    L.push(measured
        ? '-- задержка, чистые ветки, прогрев отброшен -------------'
        : '-- задержка, чистые ветки, ВКЛЮЧАЯ ПРОГРЕВ ---------------');
    L.push(row('waf on     p50 / p99', `${fmt(wafP50)} / ${fmt(wafP99)} ms   (${wafN} замеров)`));
    L.push(row('waf off    p50 / p99', `${fmt(ctlP50)} / ${fmt(ctlP99)} ms   (${ctlN} замеров)`));

    if (wafN !== '0' && ctlN !== '0') {
        L.push(row('добавленная p99', `${fmt(wafP99 - ctlP99)} ms`));
        L.push(row('добавленная p50', `${fmt(wafP50 - ctlP50)} ms`));
    } else {
        L.push(row('добавленная задержка', 'нет данных: пустая ветка'));
    }
    L.push('');

    if (q(m.waf_inspector_ms, 'med') !== null) {
        L.push('-- инспектор, из X-WAF-Debug на маршруте /debug/ ---------');
        L.push(row('p50 / p99', `${fmt(q(m.waf_inspector_ms, 'med'))} / ${fmt(q(m.waf_inspector_ms, 'p(99)'))} ms`));
        L.push(row('замеров', count(m.waf_inspector_ms)));
        L.push('');
    }

    L.push('-- корректность -----------------------------------------');
    L.push(row('неожидаемых кодов', count(m.unexpected_status)));
    L.push(row('оборвано клиентом', count(m.client_aborted)));
    L.push(row('обрыв не успел', count(m.client_abort_raced)));
    L.push('');

    L.push('-- пороги -----------------------------------------------');
    let failed = 0;
    for (const [name, metric] of Object.entries(m)) {
        if (!metric.thresholds) {
            continue;
        }
        for (const [expr, t] of Object.entries(metric.thresholds)) {
            if (t.ok === false) {
                failed++;
                L.push(`  ПРОВАЛ  ${name} ${expr}`);
            }
        }
    }
    if (failed === 0) {
        L.push('  все пороги пройдены');
    }
    L.push('');

    return L.join('\n') + '\n';
}

function row(label, value) {
    return `  ${label.padEnd(34, '.')} ${value}`;
}

function q(metric, stat) {
    if (!metric || !metric.values || metric.values[stat] === undefined) {
        return null;
    }
    return metric.values[stat];
}

function count(metric) {
    if (!metric || !metric.values) {
        return '0';
    }
    return String(metric.values.count !== undefined ? metric.values.count : 0);
}

function rate(metric) {
    if (!metric || !metric.values || metric.values.rate === undefined) {
        return 'n/a';
    }
    return metric.values.rate.toFixed(0);
}

function fmt(v) {
    return v === null ? 'n/a' : v.toFixed(2);
}
