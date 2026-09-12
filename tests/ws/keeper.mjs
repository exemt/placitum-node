/**
 * Поддельный keeper для стенда кадров: истина активных наборов без Postgres.
 *
 * Настоящий keeper (docs/keeper.md) держит состав в памяти и пишет его в
 * Postgres контроллера; стенду кадров склад не нужен, а нужен провод: ответ
 * на снапшот и хвост, дельты и тики с (epoch, seq, hash), приём событий
 * писателей с ответом. Правила зеркала, по которым модуль сверяет состав,
 * -- те же, поэтому хеш считается байт в байт как у keeper: XOR SipHash-2-4
 * значений под ключом эпохи (keeper/internal/set/siphash.go).
 *
 * Наборы заводятся по первому обращению: определений здесь нет, а стенд
 * называет набор в waf_local_dataset и пишет в него событием счётчика.
 * Журнала хвоста нет: since с отставанием отвечает snapshot_required, и
 * зеркало перечитывает набор целиком -- для стенда это дешевле журнала.
 *
 *     NATS_URL   адрес шины (nats://nats:4222)
 *     DUMP       печатать кадры провода
 */

import { randomBytes } from "node:crypto";
import { connect as tcp } from "node:net";

const url = new URL(process.env.NATS_URL ?? "nats://nats:4222");
const dump = process.env.DUMP === "1";

/* --- SipHash-2-4 ------------------------------------------------------- */

const MASK = (1n << 64n) - 1n;

const rotl = (x, b) => ((x << BigInt(b)) | (x >> BigInt(64 - b))) & MASK;

function sipRound(v) {
  v[0] = (v[0] + v[1]) & MASK;
  v[1] = rotl(v[1], 13);
  v[1] ^= v[0];
  v[0] = rotl(v[0], 32);
  v[2] = (v[2] + v[3]) & MASK;
  v[3] = rotl(v[3], 16);
  v[3] ^= v[2];
  v[0] = (v[0] + v[3]) & MASK;
  v[3] = rotl(v[3], 21);
  v[3] ^= v[0];
  v[2] = (v[2] + v[1]) & MASK;
  v[1] = rotl(v[1], 17);
  v[1] ^= v[2];
  v[2] = rotl(v[2], 32);
}

/** SipHash-2-4 строки под 16-байтовым ключом, как у keeper и модуля. */
function siphash(key, text) {
  const k0 = key.readBigUInt64LE(0);
  const k1 = key.readBigUInt64LE(8);
  const v = [
    k0 ^ 0x736f6d6570736575n,
    k1 ^ 0x646f72616e646f6dn,
    k0 ^ 0x6c7967656e657261n,
    k1 ^ 0x7465646279746573n,
  ];

  const b = Buffer.from(text, "utf8");
  const n = b.length;
  const full = n - (n % 8);

  for (let i = 0; i < full; i += 8) {
    const m = b.readBigUInt64LE(i);
    v[3] ^= m;
    sipRound(v);
    sipRound(v);
    v[0] ^= m;
  }

  let last = (BigInt(n) << 56n) & MASK;

  for (let i = full; i < n; i++) {
    last |= BigInt(b[i]) << BigInt(8 * (i - full));
  }

  v[3] ^= last;
  sipRound(v);
  sipRound(v);
  v[0] ^= last;
  v[2] ^= 0xffn;

  for (let i = 0; i < 4; i++) {
    sipRound(v);
  }

  return v[0] ^ v[1] ^ v[2] ^ v[3];
}

const hex64 = (v) => v.toString(16).padStart(16, "0");

/* --- наборы ------------------------------------------------------------- */

const sets = new Map();

function setOf(name) {
  let s = sets.get(name);

  if (!s) {
    s = {
      name,
      epoch: hex64(randomBytes(8).readBigUInt64LE(0)),
      key: randomBytes(16),
      // Нумерация от часов, как у keeper: любой номер новой эпохи больше
      // любого, что ушёл до рестарта.
      seq: Date.now(),
      hash: 0n,
      entries: new Map(),
    };
    sets.set(name, s);
    process.stdout.write(`set ${name} epoch ${s.epoch}\n`);
  }

  return s;
}

function head(s, op) {
  return { v: 3, set: s.name, epoch: s.epoch, seq: s.seq, op, hash: hex64(s.hash) };
}

function entryOf(value, rec) {
  return { value, exp: rec.exp, origin: rec.origin, reason: rec.reason };
}

/* --- NATS --------------------------------------------------------------- */

const socket = tcp({ host: url.hostname, port: Number(url.port || 4222) });

let buf = "";
let ready = false;

socket.setNoDelay(true);

function pub(subject, payload, reply = "") {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const to = reply ? ` ${reply}` : "";

  socket.write(`PUB ${subject}${to} ${Buffer.byteLength(body)}\r\n${body}\r\n`);

  if (dump) {
    process.stdout.write(`PUB ${subject} ${body}\n`);
  }
}

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
        no_responders: true, name: "fake-keeper",
      }) + "\r\n");

      socket.write("SUB waf.sets.*.snapshot 1\r\n");
      socket.write("SUB waf.sets.*.since 2\r\n");
      socket.write("SUB waf.sets.*.event 3\r\n");
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
        process.stdout.write("keeper on waf.sets.*\n");
      }

      continue;
    }

    if (line.startsWith("MSG") || line.startsWith("HMSG")) {
      const parts = line.split(/\s+/);
      const withHeaders = line.startsWith("HMSG");
      const total = Number(parts.at(-1));
      const hdrLen = withHeaders ? Number(parts.at(-2)) : 0;
      const reply = parts.length >= (withHeaders ? 6 : 5) ? parts[3] : "";

      if (buf.length < end + 2 + total + 2) {
        return;
      }

      const payload = Buffer.from(buf.slice(end + 2 + hdrLen, end + 2 + total), "binary")
        .toString("utf8");
      buf = buf.slice(end + 2 + total + 2);

      handle(parts[1], payload, reply);
      continue;
    }

    process.stdout.write(`nats: ${line}\n`);
    buf = buf.slice(end + 2);
  }
});

socket.on("error", (e) => {
  process.stdout.write(`socket: ${e.message}\n`);
  process.exit(1);
});

/* --- обработка ---------------------------------------------------------- */

function handle(subject, payload, reply) {
  const [, , name, kind] = subject.split(".");
  const s = setOf(name);

  let req;

  try {
    req = JSON.parse(payload);
  } catch {
    if (reply) {
      pub(reply, { ok: false, error: "bad_request" });
    }
    return;
  }

  if (dump) {
    process.stdout.write(`REQ ${subject} ${payload}\n`);
  }

  switch (kind) {
    case "snapshot": {
      /* Одна страница: стенд держит десятки записей, не миллионы. */
      const frame = {
        ...head(s, "snapshot"),
        key: s.key.toString("hex"),
        next: "",
        entries: [...s.entries].map(([value, rec]) => entryOf(value, rec)),
      };
      process.stdout.write(`snapshot ${name} -> ${req.from ?? "?"} (${s.entries.size} entries)\n`);
      pub(reply, frame);
      return;
    }

    case "since": {
      if (req.epoch !== s.epoch || Number(req.after) !== s.seq) {
        pub(reply, { v: 3, set: name, op: "snapshot_required" });
        return;
      }

      pub(reply, { ...head(s, "since"), changes: [] });
      return;
    }

    case "event":
      event(s, req, reply);
      return;

    default:
      return;
  }
}

function event(s, ev, reply) {
  const answer = (out) => {
    if (reply) {
      pub(reply, out);
    }
  };

  const value = typeof ev.value === "string" ? ev.value.trim() : "";

  if (value === "" || (ev.op !== "add" && ev.op !== "remove")) {
    answer({ ok: false, error: "bad_op" });
    return;
  }

  if (!ev.origin) {
    answer({ ok: false, error: "no_origin" });
    return;
  }

  if (ev.op === "add") {
    const ttl = Number(ev.ttl ?? 0);

    if (!(ttl > 0) && !ev.forever) {
      answer({ ok: false, error: "no_ttl" });
      return;
    }

    const exp = ev.forever ? 0 : Date.now() + ttl * 1000;
    const rec = { exp, origin: ev.origin, reason: ev.reason ?? "" };

    /* Повтор значения продлевает срок, хеш состава не меняется. */
    if (!s.entries.has(value)) {
      s.hash ^= siphash(s.key, value);
    }

    s.entries.set(value, rec);
    s.seq += 1;

    process.stdout.write(`add ${s.name} ${value} ttl=${ttl} by ${ev.origin} (${ev.reason ?? ""}) seq ${s.seq}\n`);
    pub(`waf.sets.${s.name}`, { ...head(s, "add"), entries: [entryOf(value, rec)] });
    answer({ ok: true, seq: s.seq, epoch: s.epoch });
    return;
  }

  remove(s, value, ev.origin, ev.reason ?? "");
  answer({ ok: true, seq: s.seq, epoch: s.epoch });
}

function remove(s, value, origin, reason) {
  const rec = s.entries.get(value);

  if (!rec) {
    return;
  }

  s.entries.delete(value);
  s.hash ^= siphash(s.key, value);
  s.seq += 1;

  process.stdout.write(`remove ${s.name} ${value} by ${origin} (${reason}) seq ${s.seq}\n`);
  pub(`waf.sets.${s.name}`, {
    ...head(s, "remove"),
    entries: [{ value, exp: rec.exp, origin, reason }],
  });
}

/* Истечение -- изменение: keeper метёт сам и издаёт remove в общей нумерации. */
setInterval(() => {
  const now = Date.now();

  for (const s of sets.values()) {
    for (const [value, rec] of s.entries) {
      if (rec.exp > 0 && rec.exp <= now) {
        remove(s, value, "keeper", "EXPIRED");
      }
    }
  }
}, 1000);

/* Тик раз в две секунды на набор: живость и сверка одним сообщением. */
setInterval(() => {
  if (!ready) {
    return;
  }

  for (const s of sets.values()) {
    pub(`waf.sets.${s.name}`, head(s, "tick"));
  }
}, 2000);
