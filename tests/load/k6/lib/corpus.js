// Корпус запросов: скелеты и тела.
//
// Разделение бюджета энтропии описано в traffic-model.md. Коротко: то, что
// укладывается в сотни байт (путь, аргументы, заголовки), собирается на каждый
// запрос; то, что измеряется килобайтами (тела), берётся из готового набора и
// делается уникальным подстановкой маркера в начало.
//
// И скелеты, и тела лежат в SharedArray -- одна копия на все VU. Класть тела в
// модульную константу нельзя: init-контекст исполняется в каждом VU, и при
// тысяче VU набор тел умножился бы на тысячу.

import { SharedArray } from 'k6/data';
import { seeded, between, pick, alnum, hex, shuffle } from './rand.js';
import { envNum } from './env.js';

const SEED = envNum('CORPUS_SEED', 20260813);
const SIZE = envNum('CORPUS_SIZE', 20000);
const BODY_PROFILE = __ENV.BODY_PROFILE || 'mixed';

export const BOUNDARY = 'wafload7MA4YWxkTrZu0gW';

// Флаворы: чем именно этот запрос отличается от обычного. Признак выбирается
// заранее и лежит в скелете, чтобы прогон с тем же зерном давал ту же смесь.
export const F = {
    NORMAL: 0,
    DENY: 1,
    SCORE_LOW: 2,
    REDIRECT: 3,
    SCORE_DENY: 4,
    SLOW_OK: 5,
    SLOW_TIMEOUT: 6,
    SILENT: 7,
    DEBUG: 8,
    ABORT: 9,
};

// --------------------------------------------------------------- тела ----

// Раскладка размерных корзин. Обоснование границ -- в traffic-model.md; коротко:
// профиль mixed ограничен 64 KB, потому что дальше упирается полоса, а не CPU.
function bodyLayout(profile) {
    if (profile === 'large') {
        return [
            { min: 65536, max: 524288, count: 12, weight: 0.40 },
            { min: 524288, max: 1048576, count: 8, weight: 0.40 },
            // Заведомо за max_payload шины: граница должна проверяться, а не
            // обходиться стороной.
            { min: 1100000, max: 1300000, count: 4, weight: 0.20 },
        ];
    }

    return [
        { min: 512, max: 8192, count: 96, weight: 0.67 },
        { min: 8192, max: 65536, count: 32, weight: 0.33 },
    ];
}

const LAYOUT = bodyLayout(BODY_PROFILE);

const KINDS = ['json', 'form', 'multipart'];

// Длина того, что подставляется перед телом на каждом запросе. Нужна, чтобы
// итоговый размер попадал в корзину, а не превышал её на длину маркера.
const PREFIX_LEN = {
    json: '{"m":"'.length + 32 + '",'.length,
    form: 'm='.length + 32 + '&'.length,
    multipart: mpPrefix('0'.repeat(32)).length,
};

function mpPrefix(marker) {
    return `--${BOUNDARY}\r\nContent-Disposition: form-data; name="m"\r\n\r\n${marker}\r\n`;
}

function bodyTail(kind, padLen, block) {
    const pad = repeatTo(block, padLen);

    if (kind === 'json') {
        return `"pad":"${pad}"}`;
    }

    if (kind === 'form') {
        return `pad=${pad}`;
    }

    return `--${BOUNDARY}\r\nContent-Disposition: form-data; name="pad"\r\n\r\n${pad}\r\n--${BOUNDARY}--\r\n`;
}

function tailOverhead(kind) {
    return bodyTail(kind, 0, '').length;
}

function repeatTo(block, n) {
    if (n <= 0) {
        return '';
    }
    return block.repeat(Math.ceil(n / block.length)).slice(0, n);
}

export const bodies = new SharedArray('bodies', function () {
    const rnd = seeded(SEED ^ 0x5f356495);
    const out = [];

    // Один случайный блок на весь набор, дальше повторение. Посимвольная
    // генерация мегабайтного тела заняла бы больше времени, чем весь прогон, а
    // содержимое тела ни на что не влияет: до этапа 6 модуль его не читает и
    // шлёт инспектору "body": null.
    const block = alnum(rnd, 2048);

    for (const bucket of LAYOUT) {
        for (let i = 0; i < bucket.count; i++) {
            const kind = pick(rnd, KINDS);
            const size = between(rnd, bucket.min, bucket.max);
            const padLen = size - PREFIX_LEN[kind] - tailOverhead(kind);

            out.push({
                k: kind,
                t: bodyTail(kind, padLen, block),
                n: size,
            });
        }
    }

    return out;
});

// Смещение корзины во flat-массиве: скелет хранит абсолютный индекс.
function bucketOffsets() {
    const offs = [];
    let acc = 0;
    for (const b of LAYOUT) {
        offs.push(acc);
        acc += b.count;
    }
    return offs;
}

// Собирает тело целиком: уникальный маркер плюс готовый хвост. Маркер нужен,
// чтобы у запросов различались содержимое и SHA-256 локатора, иначе любой кеш
// или дедупликация в хранилище тела получили бы неправдоподобную долю
// попаданий.
export function renderBody(entry, marker) {
    if (entry.k === 'json') {
        return `{"m":"${marker}",${entry.t}`;
    }
    if (entry.k === 'form') {
        return `m=${marker}&${entry.t}`;
    }
    return mpPrefix(marker) + entry.t;
}

export function contentType(kind) {
    if (kind === 'json') {
        return 'application/json';
    }
    if (kind === 'form') {
        return 'application/x-www-form-urlencoded';
    }
    return `multipart/form-data; boundary=${BOUNDARY}`;
}

// ------------------------------------------------------------ скелеты ----

// Значения правдоподобные, а не случайные байты: мусор в accept-encoding уводит
// сам nginx на другой путь исполнения и смешивает измерения.
const HEADERS = [
    ['user-agent', [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'curl/8.5.0',
        'okhttp/4.12.0',
    ]],
    ['accept', [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8',
        'application/json',
        '*/*',
    ]],
    ['accept-language', ['ru-RU,ru;q=0.9,en-US;q=0.8', 'en-US,en;q=0.5', 'de-DE,de;q=0.9']],
    ['accept-encoding', ['gzip, deflate', 'gzip', 'identity']],
    ['referer', [
        'https://shop.example.com/catalog',
        'https://shop.example.com/search?q=shoes',
        'https://partner.example.net/',
    ]],
    ['origin', ['https://shop.example.com', 'https://admin.example.com']],
    ['x-forwarded-for', null],
    ['x-request-id', null],
    ['x-correlation-id', null],
    ['x-client-version', ['1.4.2', '2.0.0-rc3', '3.11.7']],
    ['authorization', null],
    ['cache-control', ['no-cache', 'max-age=0']],
    ['dnt', ['1']],
    ['sec-fetch-mode', ['navigate', 'cors', 'no-cors']],
    ['sec-fetch-site', ['same-origin', 'cross-site', 'none']],
    ['sec-ch-ua-platform', ['"Windows"', '"macOS"', '"Linux"']],
    ['upgrade-insecure-requests', ['1']],
    ['te', ['trailers']],
    ['x-tenant', ['acme', 'globex', 'initech']],
    ['x-feature-flags', null],
];

const PATHS = [
    () => '/orders',
    (r) => `/orders/${between(r, 1, 9999999)}`,
    (r) => `/users/${between(r, 1, 999999)}/orders`,
    () => '/search',
    (r) => `/catalog/${pick(r, ['shoes', 'bags', 'tools', 'books'])}`,
    (r) => `/static/${hex(r, 16)}.${pick(r, ['js', 'css', 'png'])}`,
    () => '/cart/checkout',
    (r) => `/v2/items/${hex(r, 8)}`,
];

// x-forwarded-for задаёт request.js: иначе случайный адрес попал бы
// в blocklist инспектора и доля отказов стала бы неуправляемой.
const ARGS = ['utm_source', 'utm_campaign', 'page', 'per_page', 'sort', 'order', 'q', 'filter', 'lang', 'ref'];
const COOKIES = ['sid', 'lang', 'theme', 'ab_group', 'cart', 'consent'];

const METHODS_MIXED = [
    ['GET', 0.60], ['POST', 0.30], ['PUT', 0.05], ['DELETE', 0.05],
];

function weightedPick(rnd, table) {
    const r = rnd();
    let acc = 0;
    for (const [value, w] of table) {
        acc += w;
        if (r < acc) {
            return value;
        }
    }
    return table[table.length - 1][0];
}

function flavorTable() {
    const attack = envNum('ATTACK_RATIO', 0.05);
    const score = envNum('SCORE_RATIO', 0.05);
    const slow = envNum('SLOW_RATIO', 0.02);
    const timeout = envNum('TIMEOUT_RATIO', 0);
    const silent = envNum('SILENT_RATIO', 0);
    const debug = envNum('DEBUG_RATIO', 0.01);
    const abort = envNum('ABORT_RATIO', 0);

    // Доля счёта делится на две ступени, а не на три: челлендж больше не следует
    // из счёта, и его флавор задаётся вердиктом инспектора отдельно.
    const table = [
        [F.DENY, attack],
        [F.SCORE_LOW, score / 2],
        [F.SCORE_DENY, score / 2],
        [F.REDIRECT, envNum('REDIRECT_RATIO', 0.01)],
        [F.SLOW_OK, slow],
        [F.SLOW_TIMEOUT, timeout],
        [F.SILENT, silent],
        [F.DEBUG, debug],
        [F.ABORT, abort],
    ];

    const used = table.reduce((s, [, w]) => s + w, 0);
    table.push([F.NORMAL, Math.max(0, 1 - used)]);

    return table;
}

export const skeletons = new SharedArray('skeletons', function () {
    const rnd = seeded(SEED);
    const flavors = flavorTable();
    const offsets = bucketOffsets();
    const controlRatio = envNum('CONTROL_RATIO', 0.10);
    const out = [];

    for (let i = 0; i < SIZE; i++) {
        const control = rnd() < controlRatio;
        const flavor = control ? F.NORMAL : weightedPick(rnd, flavors);

        // В профиле large тело нужно на каждом запросе, иначе корзины
        // недостижимы: смысл профиля именно в размере.
        const method = BODY_PROFILE === 'large'
            ? 'POST'
            : weightedPick(rnd, METHODS_MIXED);

        out.push({
            m: method,
            p: pick(rnd, PATHS)(rnd),
            q: buildQuery(rnd),
            h: buildHeaders(rnd),
            b: buildBodyRef(rnd, method, offsets),
            f: flavor,
            c: control,
        });
    }

    return out;
});

function buildQuery(rnd) {
    const n = between(rnd, 0, 8);
    if (n === 0) {
        return '';
    }

    const parts = [];
    const used = {};

    for (let i = 0; i < n; i++) {
        const name = pick(rnd, ARGS);
        if (used[name]) {
            continue;
        }
        used[name] = true;
        parts.push(`${name}=${alnum(rnd, between(rnd, 0, 24))}`);
    }

    return parts.join('&');
}

function buildHeaders(rnd) {
    const names = shuffle(rnd, HEADERS.slice());
    const count = between(rnd, 8, 25);
    const obj = {};

    for (let i = 0; i < names.length && Object.keys(obj).length < count; i++) {
        const [name, values] = names[i];
        obj[name] = values ? pick(rnd, values) : generatedValue(rnd, name);
    }

    // Собственные заголовки приложения: добор до нужного числа именами, которых
    // нет в пуле.
    let extra = 0;
    while (Object.keys(obj).length < count) {
        obj[`x-app-${extra}`] = alnum(rnd, between(rnd, 4, 40));
        extra++;
    }

    // Единицы процентов запросов несут очень длинное значение: граница
    // waf_header_value_max и буфера заголовков nginx.
    if (rnd() < 0.02) {
        obj['x-app-blob'] = alnum(rnd, between(rnd, 2048, 3800));
    }

    obj['cookie'] = buildCookies(rnd);

    return obj;
}

function generatedValue(rnd, name) {
    switch (name) {
        case 'x-forwarded-for':
            return `${between(rnd, 1, 223)}.${between(rnd, 0, 255)}.${between(rnd, 0, 255)}.${between(rnd, 1, 254)}`;
        case 'authorization':
            return `Bearer ${alnum(rnd, 64)}`;
        case 'x-feature-flags':
            return `${pick(rnd, ['a', 'b', 'c'])}=1,${pick(rnd, ['d', 'e'])}=0`;
        default:
            return hex(rnd, 32);
    }
}

function buildCookies(rnd) {
    const n = between(rnd, 1, 6);
    const parts = [];
    const used = {};

    for (let i = 0; i < n; i++) {
        const name = pick(rnd, COOKIES);
        if (used[name]) {
            continue;
        }
        used[name] = true;
        parts.push(`${name}=${alnum(rnd, between(rnd, 4, 32))}`);
    }

    return parts.join('; ');
}

function buildBodyRef(rnd, method, offsets) {
    if (method === 'GET' || method === 'DELETE') {
        return -1;
    }

    const r = rnd();
    let acc = 0;

    for (let i = 0; i < LAYOUT.length; i++) {
        acc += LAYOUT[i].weight;
        if (r < acc) {
            return offsets[i] + Math.floor(rnd() * LAYOUT[i].count);
        }
    }

    const last = LAYOUT.length - 1;
    return offsets[last] + Math.floor(rnd() * LAYOUT[last].count);
}
