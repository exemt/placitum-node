/**
 * Нагрузка на кадры: эхо через модуль, лестница скоростей до упора.
 *
 *     node nginx/tests/ws/load.mjs
 *     node nginx/tests/ws/load.mjs --paths /echo/,/pipe/ --size 1k-12k --seconds 10
 *     node nginx/tests/ws/load.mjs --rates 100,300,800 --conns 10 --json out.json
 *
 * Из Git Bash -- с MSYS_NO_PATHCONV=1: иначе `--paths /ws/` превращается в
 * путь Git, и рукопожатие получает 400.
 *
 * Тот же стенд, что у run.mjs (ws.conf), без rewrite: его /ws2/ под поток не
 * годится. Локации на одном эхо, чтобы цена раскладывалась по слоям:
 *
 *   /echo/    waf off -- проксирование как есть, эталон стенда;
 *   /frames/  модуль без инспекторов -- кадрирование, снимок в обменник, gate;
 *   /pipe/    боевой маршрут чата: счётчик входа и выхода на обеих сторонах,
 *             облегчённый CRS (SQLi и XSS) на кадрах клиента, gate на обеих
 *             сторонах (monitor на кадрах модуль пока не умеет), дедлайн 1s;
 *   /ws/      полный CRS + json на кадрах клиента, gate, дедлайн 1s;
 *   /ladder/  лестница квоты: счётчик двух корзин первой волной и rewrite по
 *             просьбе второй, обе стороны, сборка фрагментов включена, дедлайн
 *             1s; корзины неприличные, порог не берётся.
 *
 * `--fragments N` режет каждое сообщение на N кадров (первый text без fin,
 * дальше continuation): так меряется цена сборки на /ladder/. Эхо возвращает
 * фрагменты как получило, и клиент собирает их сам, поэтому на /echo/ это
 * честный эталон той же нагрузки. `--scale N` поднимает N экземпляров counter
 * и rewrite в одной queue group: так видно, делится ли потолок инспектора.
 *
 * По умолчанию -- лестница: со 100 сообщений в секунду, каждая ступень в
 * полтора раза выше, пока не упрёмся: отказы (закрытые соединения, эхо не
 * вернулось), сокет не принимает предложенную скорость, или p99 вырос выше
 * порога (`--p99`, мс) либо втрое против первой ступени. `--rates` задаёт
 * ступени явно и до упора не идёт.
 *
 * Тела -- случайной длины в диапазоне `--size` (по умолчанию 1k-12k): кадр
 * чата не 128 байт, и CRS с локатором платят за длину. Клиент -- в этом
 * процессе, на своём RFC 6455 (ws.mjs): каждое сообщение несёт номер, и по эху
 * меряется задержка «отправил -> вернулось». Скорость держится расписанием:
 * тик раз в 2 мс досылает всё, что по расписанию уже пора. Когда сокет не
 * принимает (gate держит кадр, TCP упёрся в буферы), недосланное списывается,
 * а не догоняется залпом -- в отчёте видна предложенная нагрузка, а не
 * намерение.
 *
 * На каждую ступень: сколько предложили, сколько вернулось, потери (эха нет
 * за время слива), закрытые соединения, p50/p90/p99 задержки и загрузка
 * контейнеров посреди ступени (`docker stats`). В конце -- счётчики лога
 * модуля: allow/deny кадров и строки ошибок.
 */

import { spawn, spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { OP, clientKey, decodeFrames, encodeFrame } from "./ws.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const image = process.env.WAF_NGINX_IMAGE ?? "waf-nginx";
const nodeImage = process.env.WAF_NODE_IMAGE ?? "node:22-alpine";
const natsImage = process.env.WAF_NATS_IMAGE ?? "nats:2.12-alpine";
const redisImage = process.env.WAF_REDIS_IMAGE ?? "redis:7.4-alpine";
const modsecImage = process.env.WAF_MODSEC_IMAGE ?? "waf-inspector-modsec";
const jsonImage = process.env.WAF_JSON_IMAGE ?? "waf-json";
const counterImage = process.env.WAF_COUNTER_IMAGE ?? "waf-counter";
const rewriteImage = process.env.WAF_REWRITE_IMAGE ?? "waf-rewrite";
const goImage = process.env.WAF_GO_IMAGE ?? "golang:1.25-alpine";
const tag = `waf-ws-load-${process.pid}`;
const net = `${tag}-net`;
const sockVolume = `${tag}-sock`;

// --- параметры ------------------------------------------------------------

function parseArgs(argv) {
  const out = {};

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    if (!a.startsWith("--")) continue;

    const eq = a.indexOf("=");

    if (eq !== -1) {
      out[a.slice(2, eq)] = a.slice(eq + 1);
    } else {
      out[a.slice(2)] = argv[i + 1];
      i++;
    }
  }

  return out;
}

/** `128`, `4k`, `1k-12k` -- байты; диапазон -- случайная длина в нём. */
function parseSize(text) {
  const one = (s) => {
    const m = /^(\d+)([km]?)$/i.exec(s.trim());

    if (m === null) throw new Error(`размер: ${s}`);

    return Number(m[1]) * ({ "": 1, k: 1024, m: 1024 * 1024 })[m[2].toLowerCase()];
  };
  const parts = text.split("-");

  return parts.length === 1 ? [one(parts[0]), one(parts[0])] : [one(parts[0]), one(parts[1])];
}

const args = parseArgs(process.argv.slice(2));
const fixedRates = args.rates === undefined ? null : args.rates.split(",").map(Number);
const rampStart = Number(args.start ?? 100);
const rampFactor = Number(args.factor ?? 1.5);
const rampMax = Number(args["max-rate"] ?? 20000);
const p99Limit = Number(args.p99 ?? 100);
const seconds = Number(args.seconds ?? 10);
// Соединений много и каждое не спешит: под gate в полёте один кадр на
// соединение, и 2000/с через двадцать сокетов упёрлись бы не в модуль, а в
// «сто в секунду по одному» на сокет. Пятьдесят по сорок -- ближе к чату.
const conns = Number(args.conns ?? 50);
const [sizeMin, sizeMax] = parseSize(args.size ?? "1k-12k");
const paths = (args.paths ?? "/echo/,/pipe/").split(",");
const drainMs = Number(args.drain ?? 5000);
const warmupSeconds = Number(args.warmup ?? 2);
const fragments = Math.max(1, Number(args.fragments ?? 1));
// Экземпляров counter и rewrite: та же queue group, шина делит кадры между
// ними. Один -- цена пути на одном ядре, несколько -- как она делится.
const scale = Math.max(1, Number(args.scale ?? 1));
const jsonOut = args.json;

const TIER = {
  "/echo/": "waf off",
  "/frames/": "модуль без инспекторов: снимок, gate",
  "/pipe/": "счётчик вход/выход + облегчённый CRS, gate обе стороны, дедлайн 1s",
  "/ws/": "полный CRS + json, gate, дедлайн 1s",
  "/ws2/": "counter + rewrite обе стороны",
  "/ladder/": "лестница квоты: две корзины + rewrite по просьбе, обе стороны, сборка, дедлайн 1s",
};

const sizeText = (sizeMin === sizeMax ? `${sizeMin} B` : `${sizeMin}–${sizeMax} B`)
  + (fragments > 1 ? ` ×${fragments} фрагм.` : "");

// --- стенд ----------------------------------------------------------------

function docker(a) {
  // Лог модуля на info -- строка на кадр: за прогон десятки мегабайт, а
  // умолчание spawnSync -- мегабайт, и счётчики считались бы по обрывку.
  return spawnSync("docker", a, { encoding: "utf8", maxBuffer: 1024 * 1024 * 1024 });
}

function hostPath(p) {
  return p.replace(/\\/g, "/");
}

/**
 * Сбой стенда -- исключение, не process.exit(): на Windows stdout и stderr
 * процесса -- асинхронные каналы, и exit сразу после console.error глотает
 * сообщение. Исключение доходит до finally (стенд снимается) и печатается
 * самим node -- синхронно.
 */
function fail(message) {
  throw new Error(message);
}

function run(label, a) {
  const r = docker(a);

  if (r.status !== 0) {
    fail(`${label}: ${r.error?.message ?? ""}${r.stderr || r.stdout}`);
  }

  return r;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function up() {
  docker(["network", "create", net]);
  docker(["volume", "create", sockVolume]);

  // Приёмник аудита -- как у run.mjs: без сокета датаграммы теряются молча,
  // а отказ пишет запись. Под нагрузкой это часть цены.
  run("agent", [
    "run", "-d", "--rm", "--name", `${tag}-agent`, "--network", net,
    "-v", `${hostPath(join(here, "..", "bus"))}:/app:ro`,
    "-v", `${sockVolume}:/run/waf`,
    "-w", "/app", goImage, "go", "run", "agent.go",
  ]);

  run("nats", [
    "run", "-d", "--rm", "--name", `${tag}-nats`, "--network", net,
    "--network-alias", "nats", natsImage, "-js",
  ]);

  // Истина живого набора blocklist -- поддельный keeper, как у run.mjs:
  // без него модуль на каждом повторе пишет ошибку «is keeper up?».
  run("keeper", [
    "run", "-d", "--rm", "--name", `${tag}-keeper`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-v", `${hostPath(here)}:/app:ro`,
    "-w", "/app", nodeImage, "node", "keeper.mjs",
  ]);

  run("redis", [
    "run", "-d", "--rm", "--name", `${tag}-redis`, "--network", net,
    "--network-alias", "redis", redisImage,
  ]);

  run("echo", [
    "run", "-d", "--rm", "--name", `${tag}-echo`, "--network", net,
    "--network-alias", "echo",
    "-v", `${hostPath(here)}:/app:ro`,
    "-w", "/app", nodeImage, "node", "echo.mjs",
  ]);

  // Профиль light -- каталог рядом с этим файлом, подмонтирован в дерево
  // профилей образа. Неизвестный профиль -- отказ, а не тихий откат на
  // default: иначе прогон мерил бы полный CRS, думая, что облегчённый.
  run("modsec", [
    "run", "-d", "--rm", "--name", `${tag}-rules`, "--network", net,
    "-v", `${hostPath(join(here, "modsec-light"))}:/app/profiles/http/light:ro`,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_MODSEC_SUBJECT=waf.frm.modsec",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
    "-e", "WAF_MODSEC_NAME=modsec",
    "-e", `WAF_MODSEC_LOG=${process.env.WAF_MODSEC_LOG ?? "warn"}`,
    modsecImage,
  ]);

  run("json", [
    "run", "-d", "--rm", "--name", `${tag}-json`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_JSON_SUBJECT=waf.frm.json",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "WAF_JSON_NAME=json",
    "-e", "WAF_JSON_LOG=warn",
    jsonImage,
  ]);

  // Счётчик -- профиль wsload из образа: вход по соединению, выход по адресу.
  run("counter", [
    "run", "-d", "--rm", "--name", `${tag}-counter`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_COUNTER_SUBJECT=waf.frm.counter",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
    "-e", "WAF_COUNTER_NAME=counter",
    "-e", `WAF_COUNTER_LOG=${process.env.WAF_COUNTER_LOG ?? "warn"}`,
    counterImage,
  ]);

  // Подмена по просьбе -- вторая волна лестницы (/ladder/): без просьбы
  // отвечает REWRITE_NOOP, и это часть цены пути.
  run("rewrite", [
    "run", "-d", "--rm", "--name", `${tag}-rewrite`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_REWRITE_SUBJECT=waf.frm.rewrite",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "WAF_REWRITE_NAME=rewrite",
    "-e", `WAF_REWRITE_LOG=${process.env.WAF_REWRITE_LOG ?? "warn"}`,
    rewriteImage,
  ]);

  // Копии в ту же queue group: шина раздаёт кадры по кругу, и потолок
  // одного экземпляра делится на число копий.
  for (let i = 2; i <= scale; i++) {
    run(`counter${i}`, [
      "run", "-d", "--rm", "--name", `${tag}-counter${i}`, "--network", net,
      "-e", "NATS_URL=nats://nats:4222",
      "-e", "WAF_COUNTER_SUBJECT=waf.frm.counter",
      "-e", "REDIS_URL=redis://redis:6379",
      "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
      "-e", "WAF_COUNTER_NAME=counter",
      "-e", `WAF_COUNTER_LOG=${process.env.WAF_COUNTER_LOG ?? "warn"}`,
      counterImage,
    ]);
    run(`rewrite${i}`, [
      "run", "-d", "--rm", "--name", `${tag}-rewrite${i}`, "--network", net,
      "-e", "NATS_URL=nats://nats:4222",
      "-e", "WAF_REWRITE_SUBJECT=waf.frm.rewrite",
      "-e", "REDIS_URL=redis://redis:6379",
      "-e", "WAF_REWRITE_NAME=rewrite",
      "-e", `WAF_REWRITE_LOG=${process.env.WAF_REWRITE_LOG ?? "warn"}`,
      rewriteImage,
    ]);
  }

  const pause = new Int32Array(new SharedArrayBuffer(4));
  let agentReady = false;

  for (let i = 0; i < 240; i++) {
    if (docker(["logs", `${tag}-agent`]).stdout.includes("agent on ")) {
      agentReady = true;
      break;
    }

    Atomics.wait(pause, 0, 0, 500);
  }

  if (!agentReady) {
    fail(`agent не поднялся:\n${docker(["logs", `${tag}-agent`]).stdout}`);
  }

  let keeperReady = false;

  for (let i = 0; i < 60; i++) {
    if (docker(["logs", `${tag}-keeper`]).stdout.includes("keeper on ")) {
      keeperReady = true;
      break;
    }

    Atomics.wait(pause, 0, 0, 500);
  }

  if (!keeperReady) {
    fail(`keeper не поднялся:\n${docker(["logs", `${tag}-keeper`]).stdout}`);
  }

  run("nginx", [
    "run", "-d", "--rm", "--name", `${tag}-nginx`, "--network", net,
    "-p", "127.0.0.1:0:8080",
    "-v", `${hostPath(here)}:/t:ro`,
    "-v", `${sockVolume}:/run/waf`,
    "--entrypoint", "nginx",
    image, "-c", "/t/ws.conf", "-g", "daemon off;",
  ]);

  const port = docker(["port", `${tag}-nginx`, "8080/tcp"]).stdout.trim()
    .split(":").pop();

  if (!port) {
    fail(`nginx не поднялся:\n${docker(["logs", `${tag}-nginx`]).stdout}`);
  }

  return Number(port);
}

const EXTRA = Array.from({ length: Math.max(0, scale - 1) }, (_, i) => i + 2)
  .flatMap((i) => [`counter${i}`, `rewrite${i}`]);

const CONTAINERS = ["nginx", "rules", "json", "counter", "rewrite", ...EXTRA,
  "echo", "redis", "keeper", "nats", "agent"];

function down() {
  for (const c of CONTAINERS) {
    docker(["stop", "-t", "1", `${tag}-${c}`]);
  }

  docker(["network", "rm", net]);
  docker(["volume", "rm", sockVolume]);
}

function alive(name) {
  return docker(["inspect", "-f", "{{.State.Running}}", `${tag}-${name}`]).stdout.trim() === "true";
}

// --- клиент ---------------------------------------------------------------

function handshake(port, path) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port }, () => {
      socket.setNoDelay(true);
      socket.write([
        `GET ${path}chat HTTP/1.1`,
        "Host: app.example.com",
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Key: ${clientKey()}`,
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Protocol: chat.v2",
        "Origin: https://app.example.com",
        "User-Agent: waf-ws-load/1",
        "", "",
      ].join("\r\n"));

      socket.once("data", (chunk) => {
        const split = chunk.indexOf("\r\n\r\n");
        const head = chunk.subarray(0, split).toString("latin1");
        const rest = chunk.subarray(split + 4);
        const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0);

        socket.setTimeout(0);
        resolve({ socket, status, rest });
      });
    });

    socket.setTimeout(10000, () => reject(new Error("таймаут рукопожатия")));
    socket.once("error", reject);
  });
}

async function connectOrDie(port, path) {
  for (let i = 0; i < 60; i++) {
    try {
      const hs = await handshake(port, path);

      if (hs.status !== 101) {
        throw new Error(`${path}: рукопожатие ${hs.status}, ожидалось 101`);
      }

      return hs;
    } catch (e) {
      if (/ожидалось 101/.test(String(e.message))) throw e;
      await sleep(200);
    }
  }

  console.error(docker(["logs", `${tag}-nginx`]).stdout);
  throw new Error("стенд не поднялся");
}

/**
 * Соединение под нагрузкой: расписание, номера отправленных и их время,
 * разбор эха с подсчётом задержки. Эхо возвращает нагрузку как есть, и
 * номер читается из её начала.
 */
function openConn(port, path, id, lat) {
  return connectOrDie(port, path).then(({ socket, rest }) => {
    const c = {
      id,
      socket,
      // Сдвиг расписания: доля периода, своя у каждого соединения. Без него
      // все пятьдесят шлют в один тик -- залп из 50 кадров по 12 КБ раз в
      // полсекунды, и modsec не успевает за 500 мс таймаута волны; клиенты
      // чата так не ходят.
      phase: Math.random(),
      sent: 0,
      skipped: 0,
      echoed: 0,
      blocked: false,
      closed: false,
      closeCode: undefined,
      times: [],
      buf: rest,
      bad: 0,
      // Сборка эха из фрагментов: без сборки в модуле эхо возвращает
      // сообщение теми же кусками, и номер лежит в первом из них.
      parts: [],
    };

    const onFrames = (chunk) => {
      c.buf = Buffer.concat([c.buf, chunk]);
      const { frames, rest: left } = decodeFrames(c.buf);
      c.buf = left;

      for (const f of frames) {
        if (f.opcode === OP.close) {
          c.closed = true;
          c.closeCode = f.payload.length >= 2 ? f.payload.readUInt16BE(0) : 1005;
          continue;
        }

        if (f.opcode !== OP.text && f.opcode !== OP.cont) {
          continue;
        }

        if (f.opcode === OP.text) {
          c.parts = [];
        }

        c.parts.push(f.payload);

        if (!f.fin) {
          continue;
        }

        const payload = c.parts.length === 1 ? c.parts[0] : Buffer.concat(c.parts);
        c.parts = [];

        // {"type":"msg","text":"<id>:<seq>:..."} -- номер сразу после кавычки.
        const text = payload.toString("latin1", 0, 48);
        const at = text.indexOf('"text":"');
        const m = at === -1 ? null : /^(\d+):(\d+):/.exec(text.slice(at + 8));

        if (m === null || Number(m[1]) !== id) {
          c.bad++;
          continue;
        }

        const seq = Number(m[2]);
        const t = c.times[seq];

        if (t !== undefined) {
          lat.push(performance.now() - t);
          c.times[seq] = undefined;
          c.echoed++;
        }
      }
    };

    if (rest.length > 0) onFrames(Buffer.alloc(0));

    socket.on("data", onFrames);
    socket.on("drain", () => { c.blocked = false; });
    socket.on("close", () => { c.closed = true; });
    socket.on("error", () => { c.closed = true; });

    return c;
  });
}

/**
 * Кадр сообщения: по контракту json (type=msg, text), случайной длины в
 * диапазоне размера -- кадр чата не одинаков, и CRS платит за длину.
 */
function frameFor(id, seq) {
  const head = `${id}:${seq}:`;
  const shell = '{"type":"msg","text":""}'.length;
  const size = sizeMin + Math.floor(Math.random() * (sizeMax - sizeMin + 1));
  const pad = Math.max(0, size - shell - head.length);
  const payload = Buffer.from(`{"type":"msg","text":"${head}${"x".repeat(pad)}"}`);

  if (fragments === 1 || payload.length < fragments) {
    return encodeFrame({ opcode: OP.text, mask: true, payload });
  }

  // Сообщение кусками: первый text без fin, дальше continuation, последний
  // с fin. Уходят одним write -- порядок на проводе тот же, что у клиента.
  const step = Math.ceil(payload.length / fragments);
  const out = [];

  for (let i = 0, k = 0; i < payload.length; i += step, k++) {
    const last = i + step >= payload.length;

    out.push(encodeFrame({
      fin: last,
      opcode: k === 0 ? OP.text : OP.cont,
      mask: true,
      payload: payload.subarray(i, Math.min(i + step, payload.length)),
    }));
  }

  return Buffer.concat(out);
}

const CPU_OF = ["nginx", "rules", "json", "counter", "rewrite", ...EXTRA, "echo", "redis", "agent"];

/** Загрузка контейнеров; копии инспекторов складываются в свою колонку. */
function cpuSample() {
  return new Promise((resolve) => {
    const p = spawn("docker", [
      "stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}}",
      ...CPU_OF.map((n) => `${tag}-${n}`),
    ]);
    let out = "";

    p.stdout.on("data", (d) => { out += d; });
    p.on("error", () => resolve({}));
    p.on("close", () => {
      const cpu = {};

      for (const line of out.split("\n")) {
        const [name, perc] = line.trim().split(/\s+/);

        if (name && perc) {
          const key = name.replace(`${tag}-`, "").replace(/\d+$/, "");
          cpu[key] = (cpu[key] ?? 0) + Number(perc.replace("%", ""));
        }
      }

      resolve(cpu);
    });
  });
}

function pct(sorted, q) {
  if (sorted.length === 0) return NaN;
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))];
}

/**
 * Одна ступень: свежие соединения, расписание на secs, слив до drainMs.
 * При warmup -- только греет и ничего не считает.
 */
async function runLevel(port, path, rate, secs, { warmup = false } = {}) {
  const lat = [];
  const cs = await Promise.all(
    Array.from({ length: conns }, (_, i) => openConn(port, path, i, lat)),
  );
  const perConn = rate / conns;
  const t0 = performance.now();
  let cpu = {};
  let sampling = null;

  await new Promise((resolve) => {
    const timer = setInterval(() => {
      const now = performance.now();
      const el = now - t0;

      if (el >= secs * 1000) {
        clearInterval(timer);
        resolve();
        return;
      }

      // Снимок загрузки с четверти ступени: `docker stats` думает секунды
      // две, и его дожидаются после слива, а не бросают.
      if (!warmup && sampling === null && el >= (secs * 1000) / 4) {
        sampling = cpuSample();
      }

      for (const c of cs) {
        if (c.closed) continue;

        // Первое сообщение -- через долю периода (сдвиг соединения), дальше по
        // расписанию: за secs секунд уходит около secs * perConn сообщений.
        const due = Math.floor((el * perConn) / 1000 - c.phase) + 1 - c.sent - c.skipped;

        if (due <= 0) continue;

        // Сокет не принимает: недосланное списывается, залпом не догоняется.
        if (c.blocked) {
          c.skipped += due;
          continue;
        }

        for (let k = 0; k < due; k++) {
          const seq = c.sent;
          c.times[seq] = performance.now();
          const ok = c.socket.write(frameFor(c.id, seq));
          c.sent++;

          if (!ok) {
            c.blocked = true;
            c.skipped += due - k - 1;
            break;
          }
        }
      }
    }, 2);
  });

  const deadline = performance.now() + drainMs;

  while (performance.now() < deadline && cs.some((c) => !c.closed && c.echoed < c.sent)) {
    await sleep(20);
  }

  if (sampling !== null) cpu = await sampling;

  const sent = cs.reduce((n, c) => n + c.sent, 0);
  const echoed = cs.reduce((n, c) => n + c.echoed, 0);
  const skipped = cs.reduce((n, c) => n + c.skipped, 0);
  const closed = cs.filter((c) => c.closed).length;
  const bad = cs.reduce((n, c) => n + c.bad, 0);
  const codes = {};

  for (const c of cs) {
    if (c.closeCode !== undefined) codes[c.closeCode] = (codes[c.closeCode] ?? 0) + 1;
  }

  for (const c of cs) {
    if (!c.closed) {
      c.socket.write(encodeFrame({ opcode: OP.close, mask: true, payload: Buffer.from([0x03, 0xe8]) }));
    }
  }

  await sleep(100);

  for (const c of cs) c.socket.destroy();

  if (warmup) return null;

  lat.sort((a, b) => a - b);

  return {
    path,
    rate,
    seconds: secs,
    conns,
    size: [sizeMin, sizeMax],
    sent,
    offered: sent / secs,
    echoed,
    echoRate: echoed / secs,
    lost: sent - echoed,
    skipped,
    closed,
    closeCodes: codes,
    bad,
    p50: pct(lat, 0.5),
    p90: pct(lat, 0.9),
    p99: pct(lat, 0.99),
    max: lat.length === 0 ? NaN : lat[lat.length - 1],
    cpu,
  };
}

// --- отчёт ----------------------------------------------------------------

const f1 = (n) => (Number.isNaN(n) ? "—" : n.toFixed(1));
const pad = (s, w) => String(s).padStart(w);

/**
 * Чем ступень плоха. `base` -- первая ступень локации: рост задержек
 * считается от неё, а не от абсолюта, чтобы стенд с медленным Docker не
 * упирался в порог на первой же сотне.
 */
function verdict(r, base) {
  if (r.closed > 0) return "закрыто";
  if (r.lost > 0) return "потери";
  if (r.offered < r.rate * 0.95) return "не принял";
  if (base !== undefined && r.p99 > Math.max(p99Limit, base.p99 * 3)) return "рост задержек";
  return "ok";
}

function printTier(path, rows) {
  const base = rows[0];

  console.log(
    `\n${path}  ${TIER[path] ?? ""}   соединений ${conns}, кадр ${sizeText}, ${seconds} s на ступень` +
    (scale > 1 ? `, counter и rewrite ×${scale}` : ""),
  );
  console.log(
    `${pad("цель", 6)} ${pad("предл.", 7)} ${pad("эхо/с", 7)} ${pad("потерь", 6)} ${pad("закр.", 5)} ` +
    `${pad("p50", 7)} ${pad("p90", 7)} ${pad("p99", 7)} ${pad("max", 8)}  ` +
    `${pad("nginx%", 6)} ${pad("modsec%", 7)} ${pad("cnt%", 6)} ${pad("rw%", 6)} ${pad("json%", 6)} ${pad("redis%", 6)} ${pad("echo%", 6)}  итог`,
  );

  for (const r of rows) {
    console.log(
      `${pad(r.rate, 6)} ${pad(f1(r.offered), 7)} ${pad(f1(r.echoRate), 7)} ${pad(r.lost, 6)} ${pad(r.closed, 5)} ` +
      `${pad(f1(r.p50), 7)} ${pad(f1(r.p90), 7)} ${pad(f1(r.p99), 7)} ${pad(f1(r.max), 8)}  ` +
      `${pad(f1(r.cpu.nginx ?? NaN), 6)} ${pad(f1(r.cpu.rules ?? NaN), 7)} ${pad(f1(r.cpu.counter ?? NaN), 6)} ` +
      `${pad(f1(r.cpu.rewrite ?? NaN), 6)} ` +
      `${pad(f1(r.cpu.json ?? NaN), 6)} ${pad(f1(r.cpu.redis ?? NaN), 6)} ${pad(f1(r.cpu.echo ?? NaN), 6)}  ${verdict(r, base)}` +
      (r.closed > 0 ? `  close ${JSON.stringify(r.closeCodes)}` : "") +
      (r.bad > 0 ? `  чужих кадров ${r.bad}` : ""),
    );
  }
}

function logCounts() {
  const log = docker(["logs", `${tag}-nginx`]);
  const text = (log.stdout ?? "") + (log.stderr ?? "");
  const count = (re) => (text.match(re) ?? []).length;
  const reasons = {};

  for (const m of text.matchAll(/frame session closed \(([^)]*)\), close (\d+)/g)) {
    const key = `${m[1]} / ${m[2]}`;
    reasons[key] = (reasons[key] ?? 0) + 1;
  }

  return {
    allowFrames: count(/allow phase frame/g),
    denyFrames: count(/deny phase frame/g),
    noVerdict: count(/no verdict \(/g),
    sessions: count(/frame session closed/g),
    reasons,
    errors: count(/\[(error|crit|alert|emerg)\]/g),
    errorLines: text.split("\n").filter((l) => /\[(error|crit|alert|emerg)\]/.test(l)).slice(0, 10),
  };
}

// --- прогон ---------------------------------------------------------------

const results = [];
const ceilings = {};
let port = 0;

try {
  port = up();

  for (let i = 0; i < 100; i++) {
    const ready = (name) => {
      const out = docker(["logs", `${tag}-${name}`]);
      return /"connected"|msg=connected| connected /.test(out.stdout + out.stderr);
    };

    if (["rules", "json", "counter", "rewrite", ...EXTRA].every(ready)) break;
    await sleep(300);
  }

  // Инспектор, не переживший старт (профиль не скомпилировался), -- это не
  // «медленно поднимается», а сломанный стенд: закрытия дальше ничего бы не
  // сказали.
  for (const name of ["rules", "json", "counter", "rewrite", ...EXTRA]) {
    if (!alive(name)) {
      const out = docker(["logs", `${tag}-${name}`]);
      fail(`${name} не поднялся:\n${out.stdout}${out.stderr}`);
    }
  }

  console.log(
    `стенд на 127.0.0.1:${port}; ` +
    (fixedRates !== null
      ? `ступени ${fixedRates.join(", ")} сообщений/с`
      : `лестница с ${rampStart}/с, шаг ×${rampFactor}, до ${rampMax}/с или до упора`),
  );

  for (const path of paths) {
    // Первые кадры дороже: CRS и счётчик прогреваются, обменник и шина тоже.
    if (warmupSeconds > 0) {
      await runLevel(port, path, fixedRates?.[0] ?? rampStart, warmupSeconds, { warmup: true });
    }

    const rows = [];
    let rate = fixedRates?.[0] ?? rampStart;
    let step = 0;

    for (;;) {
      const r = await runLevel(port, path, rate, seconds);
      const v = verdict(r, rows[0]);

      rows.push(r);
      results.push(r);
      process.stderr.write(`  ${path} ${rate}/с: эхо ${f1(r.echoRate)}/с, p50 ${f1(r.p50)} p99 ${f1(r.p99)} мс, ${v}\n`);

      step++;

      if (fixedRates !== null) {
        if (step >= fixedRates.length) break;
        rate = fixedRates[step];
        continue;
      }

      if (v !== "ok") {
        ceilings[path] = { clean: rows.filter((x) => verdict(x, rows[0]) === "ok").at(-1)?.rate ?? 0, hit: rate, why: v };
        break;
      }

      rate = Math.ceil((rate * rampFactor) / 50) * 50;

      if (rate > rampMax) {
        ceilings[path] = { clean: rows.at(-1).rate, hit: undefined, why: "лестница кончилась" };
        break;
      }
    }

    printTier(path, rows);
  }

  if (fixedRates === null) {
    console.log("");

    for (const path of paths) {
      const c = ceilings[path];

      if (c === undefined) continue;

      console.log(
        c.hit === undefined
          ? `потолок ${path}: чисто до ${c.clean}/с, выше лестница не шла`
          : `потолок ${path}: чисто до ${c.clean}/с, упёрлись на ${c.hit}/с — ${c.why}`,
      );
    }
  }

  const counts = logCounts();
  console.log(
    `\nлог модуля: allow phase frame ${counts.allowFrames}, deny phase frame ${counts.denyFrames}, ` +
    `no verdict ${counts.noVerdict}, сессий закрыто ${counts.sessions}, строк ошибок ${counts.errors}`,
  );

  for (const [key, n] of Object.entries(counts.reasons)) {
    console.log(`  ${pad(n, 6)}  ${key}`);
  }

  if (counts.errorLines.length > 0) {
    console.log(counts.errorLines.join("\n"));
  }

  if (jsonOut) {
    writeFileSync(jsonOut, JSON.stringify(
      { conns, size: [sizeMin, sizeMax], seconds, results, ceilings, log: counts }, null, 2,
    ));
    console.log(`json: ${jsonOut}`);
  }

  if (process.env.WAF_WS_VERBOSE) {
    console.error("--- nginx ---\n" + docker(["logs", `${tag}-nginx`]).stdout);
    console.error("--- modsec ---\n" + docker(["logs", `${tag}-rules`]).stdout);
    console.error("--- counter ---\n" + docker(["logs", `${tag}-counter`]).stdout);
    console.error("--- rewrite ---\n" + docker(["logs", `${tag}-rewrite`]).stdout);
    console.error("--- json ---\n" + docker(["logs", `${tag}-json`]).stdout);
  }
} finally {
  down();
}
