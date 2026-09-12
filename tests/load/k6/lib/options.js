// Сценарии и пороги. Описание каждого сценария и обоснование критериев -- в
// scenarios.md; здесь только их машинное выражение.

import { envNum } from './env.js';

const SCENARIO = __ENV.SCENARIO || 'smoke';
const RATE = envNum('RATE', 2000);
const DURATION = __ENV.DURATION || '2m';
const RUN_ID = __ENV.RUN_ID || 'manual';

// Порог на добавленную задержку задаётся явно там, где он осмыслен. По
// умолчанию отключён: на незнакомой машине он либо ничего не ловит, либо
// красит прогон в красный из-за фона, а не из-за модуля.
const P99_WAF_MS = envNum('P99_WAF_MS', 0);

function vus(rate) {
    const pre = envNum('PRE_VUS', 0);
    const max = envNum('MAX_VUS', 0);

    return {
        // Оценка по закону Литтла с запасом: VU занят на всё время запроса.
        preAllocatedVUs: pre || clamp(Math.ceil(rate * 0.05), 20, 2000),
        maxVUs: max || clamp(Math.ceil(rate * 0.5), 100, 8000),
    };
}

function clamp(v, lo, hi) {
    return Math.min(hi, Math.max(lo, v));
}

function scenario() {
    switch (SCENARIO) {

        case 'smoke':
            return {
                executor: 'constant-arrival-rate',
                rate: 50, timeUnit: '1s', duration: '60s',
                preAllocatedVUs: 20, maxVUs: 200,
            };

        // Потолок самого стенда: ветка waf off, ступенчатый рост до отказа.
        // Обязателен первым -- без него остальные числа не интерпретируются.
        case 'ceiling':
            return {
                executor: 'ramping-arrival-rate',
                startRate: 5000, timeUnit: '1s',
                stages: [
                    { target: 5000, duration: '60s' },
                    { target: 10000, duration: '60s' },
                    { target: 15000, duration: '60s' },
                    { target: 20000, duration: '60s' },
                    { target: 30000, duration: '60s' },
                    { target: 40000, duration: '60s' },
                ],
                preAllocatedVUs: 500, maxVUs: 8000,
            };

        case 'ramp':
            return {
                executor: 'ramping-arrival-rate',
                startRate: Math.max(500, Math.floor(RATE / 8)), timeUnit: '1s',
                stages: rampStages(RATE),
                ...vus(RATE * 2),
            };

        // Критерий выхода этапа 1: десять миллионов запросов без роста RSS.
        case 'soak':
            return {
                executor: 'constant-arrival-rate',
                rate: RATE, timeUnit: '1s',
                duration: `${Math.ceil(10000000 / RATE)}s`,
                ...vus(RATE),
            };

        case 'steady':
        default:
            return {
                executor: 'constant-arrival-rate',
                rate: RATE, timeUnit: '1s', duration: DURATION,
                ...vus(RATE),
            };
    }
}

function rampStages(peak) {
    const stages = [];
    const step = Math.max(500, Math.floor(peak / 8));
    for (let r = step; r <= peak; r += step) {
        stages.push({ target: r, duration: '60s' });
    }
    return stages;
}

export function buildOptions() {
    const thresholds = {
        // Генератор не выдержал заданную интенсивность -- измерен генератор,
        // а не система. Прогон недействителен независимо от остальных чисел.
        dropped_iterations: ['count==0'],

        // Код ответа, которого сценарий не ожидал. Общего порога «нет ошибок»
        // не существует: 503 при waf_exception ... timeout deny -- это успех.
        unexpected_status: ['count==0'],
    };

    // Пороги на подметриках объявлены и ради самих порогов, и ради отчёта:
    // k6 показывает в сводке только те разрезы по тегам, у которых есть порог.
    //
    // Основная пара -- phase:measure и flavor:normal. Прогрев отброшен: первые
    // секунды содержат установку соединений и прогрев JIT в инспекторе.
    // Флаворы с заданной паузой отброшены тоже, иначе p99 ветки waf измерял бы
    // паузу, которую мы сами и задали.
    thresholds[`http_req_duration{branch:waf,flavor:normal,phase:measure}`] =
        P99_WAF_MS > 0 ? [`p(99)<${P99_WAF_MS}`] : ['p(99)<3600000'];
    thresholds['http_req_duration{branch:control,flavor:normal,phase:measure}'] = ['p(99)<3600000'];

    // Запасная пара без разделения на прогрев: нужна, когда прогрев накрыл весь
    // прогон (короткий сценарий, большой WARMUP), и основная пара пуста.
    thresholds['http_req_duration{branch:waf,flavor:normal}'] = ['p(99)<3600000'];
    thresholds['http_req_duration{branch:control,flavor:normal}'] = ['p(99)<3600000'];

    // Ветки целиком, со всеми флаворами: их показывает панель Grafana.
    thresholds['http_req_duration{branch:waf}'] = ['p(99)<3600000'];
    thresholds['http_req_duration{branch:control}'] = ['p(99)<3600000'];

    return {
        discardResponseBodies: true,
        scenarios: { [SCENARIO]: scenario() },
        thresholds,
        // count здесь обязателен: без него сводка не сообщает, сколько
        // замеров попало в разрез по тегам, и пустую подметрику невозможно
        // отличить от подметрики, где все значения оказались нулевыми.
        summaryTrendStats: ['count', 'avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
        tags: { run_id: RUN_ID },
    };
}

export const CONFIG = { SCENARIO, RATE, DURATION, RUN_ID };
