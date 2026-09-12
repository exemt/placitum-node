// Сборка запроса из скелета и вычисление ожидаемого кода ответа.
//
// Вердиктом управляет генератор: инспектор адреса смотрит на client_ip,
// а realip на /api/ читает X-Forwarded-For. Отказ -- 203.0.113.10 из
// blocklist, остальное -- публичный адрес вне списков.

import { F, bodies, renderBody, contentType } from './corpus.js';
import { envNum } from './env.js';

const TARGET = __ENV.TARGET || 'http://haproxy:8080';

const DEADLINE_MS = envNum('WAF_DEADLINE_MS', 200);

// Клиент обрывает соединение заведомо раньше дедлайна: проверяется
// освобождение слота при обрыве, а не скорость инспектора.
const ABORT_TIMEOUT = `${Math.max(5, Math.floor(DEADLINE_MS / 10))}ms`;

const BLOCK_IP = '203.0.113.10';
const ALLOW_IP = '8.8.8.8';

export const FLAVOR_NAME = {
    [F.NORMAL]: 'normal',
    [F.DENY]: 'deny',
    [F.SCORE_LOW]: 'score_low',
    [F.REDIRECT]: 'redirect',
    [F.SCORE_DENY]: 'score_deny',
    [F.SLOW_OK]: 'slow_ok',
    [F.SLOW_TIMEOUT]: 'slow_timeout',
    [F.SILENT]: 'silent',
    [F.DEBUG]: 'debug',
    [F.ABORT]: 'abort',
};

export function buildRequest(sk, marker, forceControl) {
    const control = forceControl || sk.c;
    const flavor = control ? F.NORMAL : sk.f;

    const prefix = control ? '/nowaf' : (flavor === F.DEBUG ? '/debug' : '/api');
    const url = TARGET + prefix + sk.p + (sk.q ? `?${sk.q}` : '');

    // Копия, а не сам объект скелета: SharedArray отдаёт копию при обращении,
    // но флаворные заголовки не должны попасть в общий набор ни при каких
    // обстоятельствах.
    const headers = Object.assign({}, sk.h);

    let body = null;

    if (sk.b >= 0) {
        const entry = bodies[sk.b];
        body = renderBody(entry, marker);
        headers['content-type'] = contentType(entry.k);
    }

    let expected = 200;
    let timeout = undefined;

    // ip отвечает allow или deny. Флаворы счёта, редиректа, задержки и
    // молчания больше нечем задать: заглушки нет. DENY и SCORE_DENY --
    // отказ по адресу; остальное -- allow, чтобы доли смеси не ломали
    // ожидаемые коды.
    switch (flavor) {
        case F.DENY:
        case F.SCORE_DENY:
        case F.REDIRECT:
            headers['x-forwarded-for'] = BLOCK_IP;
            expected = 403;
            break;

        case F.ABORT:
            headers['x-forwarded-for'] = ALLOW_IP;
            expected = 0;
            timeout = ABORT_TIMEOUT;
            break;

        default:
            headers['x-forwarded-for'] = ALLOW_IP;
            break;
    }

    const params = {
        headers,
        tags: {
            branch: control ? 'control' : 'waf',
            flavor: FLAVOR_NAME[flavor],
        },
        redirects: 0,
    };

    if (timeout !== undefined) {
        params.timeout = timeout;
    }

    return { method: sk.m, url, body, params, expected, flavor };
}

// Латентность инспектора из X-WAF-Debug. Формат заголовка:
//   rid=<hex> v=allow score=0 shadow=0 wave=0 ip=allow/.../3ms
// Это единственный способ увидеть время ожидания вердикта отдельно от времени
// запроса, пока у модуля нет метрик.
const DEBUG_LATENCY = /(?:^|\s)ip=[^\s]*?\/(\d+)ms/;

export function inspectorLatency(res) {
    const h = res.headers['X-Waf-Debug'] || res.headers['X-WAF-Debug'];
    if (!h) {
        return null;
    }

    const m = DEBUG_LATENCY.exec(h);
    return m ? Number(m[1]) : null;
}
