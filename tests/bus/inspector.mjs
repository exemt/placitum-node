/**
 * Поддельный инспектор: подписка на subject, разбор сообщения, ответ в
 * reply-to. Клиент NATS написан здесь же -- протокол текстовый, а зависимость
 * ради четырёх глаголов стоила бы дороже.
 *
 * Поведение задаётся окружением, чтобы одним образом закрывать все ветки
 * разрешения вердикта:
 *
 *     SUBJECT     на что подписаться            (waf.req.ip)
 *     NAME        имя инспектора в ответе       (ip)
 *     VERDICT     allow | score | deny | silent
 *     SCORE       число для verdict=score
 *     RESPONSE    имя записи каталога для deny
 *     DELAY_MS    задержка перед ответом        (0)
 *     ACTIONS     JSON-массив действий к ответу (docs/inspector-actions.md)
 *     DUMP        писать разобранное сообщение в stdout
 *     BODY_DENY_RE  регулярное выражение по телу из обменника: совпало -- deny,
 *                   иначе VERDICT. Тело читается из Redis по локатору
 *                   store.body (REDIS_URL); без локатора -- VERDICT
 */

import { connect as tcp } from "node:net";

const url = new URL(process.env.NATS_URL ?? "nats://nats:4222");
const subject = process.env.SUBJECT ?? "waf.req.ip";
const name = process.env.NAME ?? "ip";
const verdict = process.env.VERDICT ?? "allow";
const score = Number(process.env.SCORE ?? 50);
const response = process.env.RESPONSE ?? "";
const delay = Number(process.env.DELAY_MS ?? 0);
const dump = process.env.DUMP === "1";

// Разбирается на старте, а не на каждом ответе: битый JSON здесь -- ошибка
// прогона, и падать она должна до первого запроса, а не тихо на каждом.
const actions = process.env.ACTIONS ? JSON.parse(process.env.ACTIONS) : null;
// Секция sessions: кого этот инспектор «узнал». Модуль её не толкует, а
// возвращает соседям следующих волн и фаз -- это и проверяется.
const sessions = process.env.SESSIONS ? JSON.parse(process.env.SESSIONS) : null;
const bodyRe = process.env.BODY_DENY_RE ? new RegExp(process.env.BODY_DENY_RE) : null;

/*
 * Клиент Redis на четыре строки RESP: только GET, ответы строго по порядку.
 * Нужен ровно затем, чтобы подделка могла решать по содержимому кадра, как
 * настоящий инспектор, -- иначе прогон кадров проверял бы только провод.
 */
const redis = (() => {
  if (!bodyRe) {
    return null;
  }

  const ru = new URL(process.env.REDIS_URL ?? "redis://redis:6379");
  const sock = tcp({ host: ru.hostname, port: Number(ru.port || 6379) });
  const queue = [];
  let rbuf = Buffer.alloc(0);

  sock.setNoDelay(true);
  sock.on("error", (e) => process.stdout.write(`redis: ${e.message}\n`));

  sock.on("data", (chunk) => {
    rbuf = Buffer.concat([rbuf, chunk]);

    for (;;) {
      const end = rbuf.indexOf("\r\n");

      if (end === -1) {
        return;
      }

      const head = rbuf.subarray(0, end).toString("latin1");

      if (head[0] === "$") {
        const n = Number(head.slice(1));

        if (n < 0) {
          rbuf = rbuf.subarray(end + 2);
          queue.shift()?.(null);
          continue;
        }

        if (rbuf.length < end + 2 + n + 2) {
          return;
        }

        const data = Buffer.from(rbuf.subarray(end + 2, end + 2 + n));
        rbuf = rbuf.subarray(end + 2 + n + 2);
        queue.shift()?.(data);
        continue;
      }

      // +OK, :n, -ERR: для GET это всё "нет данных"
      rbuf = rbuf.subarray(end + 2);
      queue.shift()?.(null);
    }
  });

  return {
    get(key) {
      return new Promise((resolve) => {
        queue.push(resolve);
        sock.write(`*2\r\n$3\r\nGET\r\n$${Buffer.byteLength(key)}\r\n${key}\r\n`);
      });
    },
  };
})();

const socket = tcp({ host: url.hostname, port: Number(url.port || 4222) });

let buf = "";
let ready = false;

socket.setNoDelay(true);

socket.on("data", (chunk) => {
  buf += chunk.toString("binary");

  for (;;) {
    const end = buf.indexOf("\r\n");

    if (end === -1) {
      return;
    }

    const line = buf.slice(0, end);

    if (line.startsWith("INFO")) {
      buf = buf.slice(end + 2);

      socket.write("CONNECT " + JSON.stringify({
        verbose: false, pedantic: false, headers: true,
        no_responders: true, name: `fake-${name}`,
      }) + "\r\n");

      socket.write(`SUB ${subject} 1\r\n`);
      socket.write("PING\r\n");
      continue;
    }

    if (line === "PING") {
      buf = buf.slice(end + 2);
      socket.write("PONG\r\n");
      continue;
    }

    if (line === "PONG") {
      buf = buf.slice(end + 2);

      if (!ready) {
        ready = true;
        process.stdout.write(`inspector ${name} on ${subject}\n`);
      }

      continue;
    }

    if (line.startsWith("MSG") || line.startsWith("HMSG")) {
      const parts = line.split(/\s+/);
      const withHeaders = line.startsWith("HMSG");

      // MSG  <subject> <sid> [reply-to] <#bytes>
      // HMSG <subject> <sid> [reply-to] <#hdr> <#total>
      const total = Number(parts.at(-1));
      const hdrLen = withHeaders ? Number(parts.at(-2)) : 0;
      const reply = parts.length >= (withHeaders ? 6 : 5) ? parts[3] : "";

      if (buf.length < end + 2 + total + 2) {
        return;
      }

      const payload = buf.slice(end + 2 + hdrLen, end + 2 + total);
      buf = buf.slice(end + 2 + total + 2);

      handle(payload, reply);
      continue;
    }

    // -ERR и прочее: в стенде это отладочная информация, не режим работы.
    process.stdout.write(`nats: ${line}\n`);
    buf = buf.slice(end + 2);
  }
});

function handle(payload, reply) {
  let req;

  try {
    req = JSON.parse(payload);
  } catch (e) {
    process.stdout.write(`bad json: ${e.message}\n`);
    return;
  }

  if (dump) {
    process.stdout.write("REQ " + JSON.stringify({
      rid: req.rid, phase: req.phase, wave: req.wave, inspector: req.inspector,
      uri: req.http?.uri,
      needs: req.needs, store: req.store, request_store: req.request_store,
      response: req.response, prior: req.prior, score: req.score,
      sessions: req.sessions,
      profile: req.route?.profile,
    }) + "\n");
  }

  if (verdict === "silent" || !reply) {
    return;
  }

  if (redis && req.store?.body?.key && !req.store.body.unavailable) {
    redis.get(req.store.body.key).then((body) => {
      const matched = body !== null && bodyRe.test(body.toString("latin1"));

      if (dump) {
        process.stdout.write(`BODY ${req.rid} ${body === null ? "missing" : body.length + " bytes"}`
          + ` matched=${matched}\n`);
      }

      answer(req, reply, matched ? "deny" : verdict, matched ? "FAKE_BODY_MATCH" : null);
    });
    return;
  }

  answer(req, reply, verdict, null);
}

function answer(req, reply, verdict, code) {
  const out = { v: req.v, rid: req.rid, inspector: req.inspector ?? name, verdict };

  if (verdict === "score") {
    out.score = score;
    out.reason = { code: "FAKE_SCORE" };
  }

  if (verdict === "deny") {
    out.reason = { code: code ?? "FAKE_DENY" };

    if (response) {
      out.response = { name: response };
    }
  }

  // Действия от вердикта не зависят: их прикладывают и к allow, и это основной
  // случай -- инспектор чаще рассказывает, чем блокирует.
  if (actions) {
    out.actions = actions;
  }

  if (sessions) {
    out.sessions = sessions;
  }

  const body = JSON.stringify(out);

  const send = () => {
    socket.write(`PUB ${reply} ${Buffer.byteLength(body)}\r\n${body}\r\n`);

    if (dump) {
      process.stdout.write("REP " + body + "\n");
    }
  };

  if (delay > 0) {
    setTimeout(send, delay);
  } else {
    send();
  }
}

socket.on("error", (e) => {
  process.stdout.write(`socket: ${e.message}\n`);
  process.exit(1);
});
