/**
 * Прогон WebSocket через модуль: рукопожатие, кадры в обе стороны, разбор
 * байтов на клиенте.
 *
 *     node nginx/tests/ws/run.mjs
 *
 * Своя сеть docker, восемь контейнеров, все удаляются в конце: чужие стенды не
 * трогаются. Клиент живёт в этом процессе -- так виден каждый кадр, а не
 * только итог библиотеки. Инспекторы кадров настоящие: modsec с CRS судит
 * кадр как поле формы, json сверяет сообщение со схемой его типа, counter
 * считает кадры обеих сторон, rewrite подменяет полезную нагрузку в обе.
 *
 * Что проверяется и где граница покрытия первой итерации -- в
 * docs/nginx/tests/websocket.md.
 */

import { spawnSync } from "node:child_process";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { OP, accept, assemble, clientKey, decodeFrames, encodeFrame, opcodeName }
  from "./ws.mjs";

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
const tag = `waf-ws-${process.pid}`;
const net = `${tag}-net`;
const sockVolume = `${tag}-sock`;

function docker(args) {
  return spawnSync("docker", args, { encoding: "utf8" });
}

function hostPath(p) {
  return p.replace(/\\/g, "/");
}

let failed = 0;

function check(label, got, want) {
  if (got === want) {
    console.log(`ok   ${label}`);
    return true;
  }

  console.error(`FAIL ${label}: ${JSON.stringify(got)}, ожидалось ${JSON.stringify(want)}`);
  failed += 1;
  return false;
}

function run(label, args) {
  const r = docker(args);

  if (r.status !== 0) {
    console.error(`${label}: ${r.stderr || r.stdout}`);
    down();
    process.exit(1);
  }

  return r;
}

function up() {
  docker(["network", "create", net]);
  docker(["volume", "create", sockVolume]);

  /*
   * Приёмник записей аудита вместо агента -- тот же agent.go, что у стенда
   * шины. Поднимается первым: сокет создаёт он, и модуль, не найдя его при
   * старте, промахнётся мимо всех записей. Без него аудит кадров и сессий
   * проверялся бы только строками лога.
   */
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

  /*
   * Истина живых наборов -- поддельный keeper (keeper.mjs): отвечает модулю
   * на снапшот и хвост, принимает события счётчика и издаёт дельты с тем же
   * хешем, что настоящий. Без него набор blocklist на /quota/ не готов, и
   * бан по квоте не доехал бы до края.
   */
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

  // Настоящий инспектор правил, а не подделка: покрытие кадров -- это CRS на
  // содержимом кадра, и подделка проверила бы только провод. Тот же образ,
  // что на запросах, другой subject.
  run("modsec", [
    "run", "-d", "--rm", "--name", `${tag}-rules`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_MODSEC_SUBJECT=waf.frm.modsec",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
    "-e", "WAF_MODSEC_NAME=modsec",
    "-e", "WAF_MODSEC_LOG=info",
    modsecImage,
  ]);

  // Контракт сообщений: профиль ws из образа -- чат с типами msg и join.
  run("json", [
    "run", "-d", "--rm", "--name", `${tag}-json`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_JSON_SUBJECT=waf.frm.json",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "WAF_JSON_NAME=json",
    "-e", "WAF_JSON_LOG=info",
    jsonImage,
  ]);

  // Счётчик и подмена -- те же образы, что на запросах, профиль ws из образа.
  run("counter", [
    "run", "-d", "--rm", "--name", `${tag}-counter`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_COUNTER_SUBJECT=waf.frm.counter",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
    "-e", "WAF_COUNTER_NAME=counter",
    "-e", "WAF_COUNTER_LOG=info",
    counterImage,
  ]);

  run("rewrite", [
    "run", "-d", "--rm", "--name", `${tag}-rewrite`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_REWRITE_SUBJECT=waf.frm.rewrite",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "WAF_REWRITE_NAME=rewrite",
    "-e", "WAF_REWRITE_LOG=info",
    rewriteImage,
  ]);

  /*
   * go run собирает приёмник секунды: сокет появляется только после сборки,
   * а датаграмма без сокета молча теряется -- первые рукопожатия ушли бы в
   * никуда. Ждём его строку готовности до старта nginx.
   */
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
    console.error(docker(["logs", `${tag}-agent`]).stdout);
    down();
    process.exit(1);
  }

  // Keeper обязан быть на месте до старта nginx: модуль запрашивает снапшот
  // набора при подключении к шине, а без ответа ждёт таймер повтора.
  let keeperReady = false;

  for (let i = 0; i < 60; i++) {
    if (docker(["logs", `${tag}-keeper`]).stdout.includes("keeper on ")) {
      keeperReady = true;
      break;
    }

    Atomics.wait(pause, 0, 0, 500);
  }

  if (!keeperReady) {
    console.error(docker(["logs", `${tag}-keeper`]).stdout);
    down();
    process.exit(1);
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
    console.error(docker(["logs", `${tag}-nginx`]).stdout);
    down();
    process.exit(1);
  }

  return Number(port);
}

function down() {
  docker(["stop", "-t", "1", `${tag}-nginx`]);
  docker(["stop", "-t", "1", `${tag}-rules`]);
  docker(["stop", "-t", "1", `${tag}-json`]);
  docker(["stop", "-t", "1", `${tag}-counter`]);
  docker(["stop", "-t", "1", `${tag}-rewrite`]);
  docker(["stop", "-t", "1", `${tag}-echo`]);
  docker(["stop", "-t", "1", `${tag}-redis`]);
  docker(["stop", "-t", "1", `${tag}-keeper`]);
  docker(["stop", "-t", "1", `${tag}-nats`]);
  docker(["stop", "-t", "1", `${tag}-agent`]);
  docker(["network", "rm", net]);
  docker(["volume", "rm", sockVolume]);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Рукопожатие руками: нужен и заголовок ответа, и сокет, который после 101
 * продолжает жить как поток кадров.
 */
function handshake(port, { ua = "waf-ws-test/1", origin = "https://app.example.com",
  path = "/ws/chat", subprotocol = "chat.v2", extensions = "" } = {}) {

  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port }, () => {
      const key = clientKey();

      socket.write([
        `GET ${path} HTTP/1.1`,
        // Имя, а не адрес: Host с числовым IP CRS считает сигналом (920350),
        // и каждый кадр набирал бы очки за клиента стенда, а не за содержимое.
        "Host: app.example.com",
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Key: ${key}`,
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Protocol: ${subprotocol}`,
        ...(extensions === "" ? [] : [`Sec-WebSocket-Extensions: ${extensions}`]),
        `Origin: ${origin}`,
        `User-Agent: ${ua}`,
        "", "",
      ].join("\r\n"));

      socket.once("data", (chunk) => {
        const split = chunk.indexOf("\r\n\r\n");
        const head = chunk.subarray(0, split).toString("latin1");
        const rest = chunk.subarray(split + 4);
        const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0);

        resolve({ socket, status, head, rest, key });
      });
    });

    socket.setTimeout(10000, () => reject(new Error("таймаут рукопожатия")));
    socket.on("error", reject);
  });
}

/** Читалка кадров: копит байты и отдаёт собранные сообщения. */
function reader(socket, seed = Buffer.alloc(0)) {
  let buf = seed;
  const out = [];
  let ended = false;

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const { frames, rest } = decodeFrames(buf);
    buf = rest;
    out.push(...frames);
  });

  socket.on("end", () => { ended = true; });
  socket.on("close", () => { ended = true; });

  return {
    frames: out,
    get ended() { return ended; },
    async wait(n, ms = 3000) {
      const until = Date.now() + ms;

      while (out.length < n && Date.now() < until) {
        await sleep(20);
      }

      return out.length >= n;
    },
    async waitEnd(ms = 3000) {
      const until = Date.now() + ms;

      while (!ended && Date.now() < until) {
        await sleep(20);
      }

      return ended;
    },
  };
}

async function connectOrDie(port, opts = {}) {
  // Стенд поднимается не мгновенно, а ретрай тут дешевле, чем sleep наугад.
  for (let i = 0; i < 60; i++) {
    try {
      return await handshake(port, opts);
    } catch {
      await sleep(200);
    }
  }

  console.error(docker(["logs", `${tag}-nginx`]).stdout);
  console.error(docker(["logs", `${tag}-echo`]).stdout);
  throw new Error("стенд не поднялся");
}

/** Обычный GET без апгрейда: код ответа и заголовки. */
function plainGet(port, path) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port }, () => {
      socket.write([
        `GET ${path} HTTP/1.1`,
        "Host: app.example.com",
        "User-Agent: waf-ws-test/1",
        "Connection: close",
        "", "",
      ].join("\r\n"));
    });

    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => { buf = Buffer.concat([buf, chunk]); });
    socket.on("end", () => {
      const head = buf.toString("latin1").split("\r\n\r\n")[0] ?? "";
      resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0), head });
    });
    socket.setTimeout(5000, () => reject(new Error("таймаут GET")));
    socket.on("error", reject);
  });
}

/** Кадр Close, который клиент получил в этой сессии, и его код с причиной. */
function closeOf(rx) {
  const frame = rx.frames.find((f) => f.opcode === OP.close);

  if (frame === undefined) {
    return { code: undefined, reason: undefined };
  }

  return {
    code: frame.payload.readUInt16BE(0),
    reason: frame.payload.subarray(2).toString("utf8"),
  };
}

const text = (payload) => encodeFrame({ opcode: OP.text, mask: true, payload: Buffer.from(payload) });

const port = up();

try {
  // Инспекторы компилируют правила и подписываются не сразу: пока их нет,
  // волна кадра закрывается по "нет подписчиков" и политике. Ждём обоих.
  for (let i = 0; i < 100; i++) {
    const rules = docker(["logs", `${tag}-rules`]);
    const json = docker(["logs", `${tag}-json`]);
    const counter = docker(["logs", `${tag}-counter`]);
    const rewrite = docker(["logs", `${tag}-rewrite`]);
    const up = (out) => /"connected"|msg=connected| connected /.test(out.stdout + out.stderr);

    if (up(rules) && up(json) && up(counter) && up(rewrite)) {
      break;
    }

    await sleep(300);
  }

  const hs = await connectOrDie(port);

  // --- рукопожатие проходит фазу запроса -----------------------------------
  check("рукопожатие: 101", hs.status, 101);
  check("рукопожатие: Sec-WebSocket-Accept сходится",
    /sec-websocket-accept:\s*(\S+)/i.exec(hs.head)?.[1], accept(hs.key));
  check("рукопожатие: подпротокол зафиксирован",
    /sec-websocket-protocol:\s*(\S+)/i.exec(hs.head)?.[1], "chat.v2");
  check("рукопожатие: модуль вынес вердикт",
    /x-waf-debug:.*v=allow/i.test(hs.head), true);

  const rx = reader(hs.socket, hs.rest);

  // --- c2s: сообщение по контракту проходит обоих инспекторов и доходит ----
  //
  // Дважды одно и то же: первый раз кадр судят modsec и json, второй --
  // кеш вердикта (waf_frame_cache frame:c2s на /ws/): тот же хеш на том же
  // маршруте, шина его не видит. Эхо приходит оба раза.
  const hello = JSON.stringify({ type: "msg", text: "привет" });
  hs.socket.write(text(hello));
  hs.socket.write(text(hello));

  await rx.wait(2);
  check("c2s: эхо вернулось дважды", assemble(rx.frames).length >= 2, true);
  check("c2s: содержимое цело", assemble(rx.frames)[0]?.payload.toString("utf8"), hello);
  check("c2s: повтор из кеша дошёл", assemble(rx.frames)[1]?.payload.toString("utf8"), hello);

  // --- c2s: инъекция -- CRS набирает порог, json типа не знает -------------
  //
  // Приёмочный тест этапа кадров: раньше эта строка утверждала, что кадр
  // доставлен приложению. Теперь ожидается Close 1008 из записи каталога
  // ws_policy, и приложение кадра не видит.
  const attack = JSON.stringify({ q: "1' OR 1=1-- " });
  hs.socket.write(text(attack));

  await rx.wait(3);

  let close = closeOf(rx);
  check("c2s: кадр с атакой -- клиенту пришёл Close", close.code !== undefined, true);
  check("c2s: код закрытия 1008 из каталога", close.code, 1008);
  check("c2s: причина из записи ws_policy", close.reason, "policy violation");
  check("c2s: эхо атаки не пришло",
    assemble(rx.frames).some((m) => !m.control && m.payload.toString("utf8") === attack), false);
  check("c2s: соединение закрыто", await rx.waitEnd(), true);

  hs.socket.destroy();

  // --- вторая сессия: сообщение не по схеме своего типа --------------------
  //
  // Для CRS это чистый JSON, для контракта -- msg без обязательного text.
  // Отказ здесь только у json: так видно, что кадр судит именно схема.
  const hs2 = await connectOrDie(port);
  check("схема: 101", hs2.status, 101);

  const rx2 = reader(hs2.socket, hs2.rest);
  hs2.socket.write(text(JSON.stringify({ type: "msg" })));

  await rx2.wait(1);
  close = closeOf(rx2);
  check("схема: msg без text -- Close 1008", close.code, 1008);
  check("схема: причина из записи ws_policy", close.reason, "policy violation");
  check("схема: соединение закрыто", await rx2.waitEnd(), true);

  hs2.socket.destroy();

  // --- третья сессия: контрольные кадры и сторона s2c ----------------------
  const hs3 = await connectOrDie(port);
  check("третья сессия: 101", hs3.status, 101);

  const rx3 = reader(hs3.socket, hs3.rest);

  const join = JSON.stringify({ type: "join", room: "lobby" });
  hs3.socket.write(text(join));
  await rx3.wait(1);
  check("join: по схеме, эхо вернулось", assemble(rx3.frames)[0]?.payload.toString("utf8"), join);

  // Инициатива приложения: слово push-leak внутри валидного сообщения.
  hs3.socket.write(text(JSON.stringify({ type: "msg", text: "push-leak" })));
  await rx3.wait(3);

  const pushed = assemble(rx3.frames).filter((m) => !m.control)
    .map((m) => m.payload.toString("utf8"));
  check("s2c: утечка от приложения доставлена клиенту (сторона не разбирается)",
    pushed.some((t) => /SQL syntax/.test(t)), true);

  hs3.socket.write(encodeFrame({ opcode: OP.ping, mask: true, payload: Buffer.from("ping") }));
  await rx3.wait(4);
  check("ping: пришёл pong", rx3.frames.some((f) => f.opcode === OP.pong), true);

  // Кадры сервера немаскированы -- иначе клиент обязан рвать соединение.
  check("s2c: кадры не маскируются", rx3.frames.every((f) => f.masked === false), true);

  hs3.socket.write(encodeFrame({
    opcode: OP.close, mask: true,
    payload: Buffer.from([0x03, 0xe8]),   // 1000
  }));

  await rx3.wait(5);
  check("close: приложение ответило close", rx3.frames.some((f) => f.opcode === OP.close), true);

  hs3.socket.destroy();

  // --- четвёртая сессия: двоичный кадр -------------------------------------
  //
  // modsec двоичное пропускает (MODSEC_FRAME_BINARY), json по политике opcode
  // отказывает: контракт про текст, а двоичный кадр -- не наш документ.
  const hs4 = await connectOrDie(port);
  check("binary: 101", hs4.status, 101);

  const rx4 = reader(hs4.socket, hs4.rest);
  hs4.socket.write(encodeFrame({
    opcode: OP.binary, mask: true, payload: Buffer.from([0x00, 0x01, 0x02, 0xfe, 0xff]),
  }));

  await rx4.wait(1);
  close = closeOf(rx4);
  check("binary: двоичный кадр -- Close 1008 по политике opcode", close.code, 1008);
  check("binary: эха не было",
    assemble(rx4.frames).some((m) => !m.control && opcodeName[m.opcode] === "binary"), false);
  check("binary: соединение закрыто", await rx4.waitEnd(), true);

  hs4.socket.destroy();

  // --- пятая сессия: фрагменты со сборкой ----------------------------------
  //
  // waf_frame_reassemble on: модуль склеивает фрагменты в буфере, судит
  // сообщение целиком и отдаёт его приложению одним кадром. Половина JSON
  // порознь не разбирается, а вместе -- сообщение по контракту: эхо
  // возвращается, соединение живо. Ping между фрагментами уходит вперёд
  // сообщения и получает pong.
  const hs5 = await connectOrDie(port);
  check("фрагменты: 101", hs5.status, 101);

  const rx5 = reader(hs5.socket, hs5.rest);
  hs5.socket.write(encodeFrame({
    fin: false, opcode: OP.text, mask: true, payload: Buffer.from('{"type":"msg",'),
  }));
  hs5.socket.write(encodeFrame({ opcode: OP.ping, mask: true, payload: Buffer.from("mid") }));
  hs5.socket.write(encodeFrame({
    fin: false, opcode: OP.cont, mask: true, payload: Buffer.from('"text":'),
  }));
  hs5.socket.write(encodeFrame({
    fin: true, opcode: OP.cont, mask: true, payload: Buffer.from('"hi"}'),
  }));

  await rx5.wait(2);
  const assembled5 = assemble(rx5.frames).filter((m) => !m.control);
  check("фрагменты: собранное сообщение дошло до приложения и вернулось эхом",
    assembled5[0]?.payload.toString("utf8"), '{"type":"msg","text":"hi"}');
  check("фрагменты: сообщение ушло одним кадром (эхо -- один кадр)",
    rx5.frames.filter((f) => f.opcode === OP.text || f.opcode === OP.cont).length, 1);
  check("фрагменты: ping между фрагментами получил pong",
    rx5.frames.some((f) => f.opcode === OP.pong), true);
  check("фрагменты: соединение живо, Close не было",
    rx5.frames.some((f) => f.opcode === OP.close), false);

  hs5.socket.destroy();

  // --- шестая сессия: /ws2/ -- обе стороны, подмена в обе ----------------
  //
  // Слово клиента маскируется ДО апстрима: эхо отражает то, что получило.
  // Секрет приложения маскируется ДО клиента: эхо отдаёт оригинал, клиент
  // видит маску. Обе стороны идут через счётчик, суда над ними тут нет.
  const hs6 = await connectOrDie(port, { path: "/ws2/chat" });
  check("подмена: 101", hs6.status, 101);

  const rx6 = reader(hs6.socket, hs6.rest);
  hs6.socket.write(text("hello badword"));
  await rx6.wait(1);
  check("подмена c2s: приложение получило маску, эхо вернуло её",
    assemble(rx6.frames)[0]?.payload.toString("utf8"), "hello ***");

  hs6.socket.write(text("token secret-123 here"));
  await rx6.wait(2);
  check("подмена s2c: клиент видит маску вместо секрета приложения",
    assemble(rx6.frames)[1]?.payload.toString("utf8"), "token secret-*** here");
  check("подмена: соединение живо, Close не было",
    rx6.frames.some((f) => f.opcode === OP.close), false);

  hs6.socket.destroy();

  // --- сессия 6б: /ws2/ -- подмена собранного сообщения --------------------
  //
  // Слово разрезано между фрагментами: "hello bad" + "word". Без сборки
  // ни один фрагмент не содержит badword и маска не сработала бы; со
  // сборкой подмена видит сообщение целиком, а приложение получает один
  // кадр "hello ***". Запись кадра на /ws2/ (all) помнит, из скольких
  // кадров он собран.
  const hs6b = await connectOrDie(port, { path: "/ws2/chat" });
  check("сборка+подмена: 101", hs6b.status, 101);

  const rx6b = reader(hs6b.socket, hs6b.rest);
  hs6b.socket.write(encodeFrame({
    fin: false, opcode: OP.text, mask: true, payload: Buffer.from("hello bad"),
  }));
  hs6b.socket.write(encodeFrame({
    fin: true, opcode: OP.cont, mask: true, payload: Buffer.from("word"),
  }));

  await rx6b.wait(1);
  check("сборка+подмена: слово, разрезанное фрагментами, замаскировано целиком",
    assemble(rx6b.frames)[0]?.payload.toString("utf8"), "hello ***");
  check("сборка+подмена: соединение живо",
    rx6b.frames.some((f) => f.opcode === OP.close), false);

  hs6b.socket.destroy();

  // --- седьмая сессия: /ws2/ -- счётчик закрывает поток кадров --------------
  //
  // Корзина ws_frames по соединению вмещает пять кадров: шесть подряд без
  // паузы доливают её за порог, и суд того же кадра закрывает соединение
  // записью ws_policy -- как и любой отказ на кадре.
  const hs7 = await connectOrDie(port, { path: "/ws2/chat" });
  check("счётчик: 101", hs7.status, 101);

  const rx7 = reader(hs7.socket, hs7.rest);

  for (let i = 1; i <= 6; i++) {
    hs7.socket.write(text(`f${i}`));
  }

  check("счётчик: поток кадров закрыт", await rx7.waitEnd(5000), true);
  close = closeOf(rx7);
  check("счётчик: Close 1008 из записи ws_policy", close.code, 1008);

  const echoed = assemble(rx7.frames).filter((m) => !m.control).length;
  check("счётчик: не все шесть кадров дошли до приложения", echoed < 6, true);

  hs7.socket.destroy();

  // --- локальный слой на кадрах: /local/ -----------------------------------
  //
  // Лимит count=frames по соединению: 2r/s burst=2 -- четвёртый кадр
  // подряд отсекается до шины, Close 1008 из записи ws_flood, и до счётчика
  // он не доходит.
  const hsL1 = await connectOrDie(port, { path: "/local/chat" });
  check("локальный лимит: 101", hsL1.status, 101);

  const rxL1 = reader(hsL1.socket, hsL1.rest);

  for (const w of ["a", "b", "c", "d"]) {
    hsL1.socket.write(text(w));
  }

  check("локальный лимит: поток кадров закрыт", await rxL1.waitEnd(5000), true);
  close = closeOf(rxL1);
  check("локальный лимит: Close 1008", close.code, 1008);
  check("локальный лимит: причина из записи ws_flood", close.reason, "too many frames");
  check("локальный лимит: четвёртый кадр до приложения не дошёл",
    assemble(rxL1.frames).filter((m) => !m.control).length < 4, true);

  hsL1.socket.destroy();

  // Проверка по набору с переменной кадра: двоичный опкод в списке
  // ws_binary -- отказ локальным слоем, Close 1008 из записи ws_policy,
  // инспектор кадра не видит.
  const hsL2 = await connectOrDie(port, { path: "/local/chat" });
  check("локальный список: 101", hsL2.status, 101);

  const rxL2 = reader(hsL2.socket, hsL2.rest);
  hsL2.socket.write(encodeFrame({
    opcode: OP.binary, mask: true, payload: Buffer.from([0x01, 0x02, 0x03]),
  }));

  check("локальный список: соединение закрыто", await rxL2.waitEnd(5000), true);
  close = closeOf(rxL2);
  check("локальный список: Close 1008 по опкоду из набора", close.code, 1008);
  check("локальный список: причина из записи ws_policy", close.reason, "policy violation");
  check("локальный список: эха не было",
    assemble(rxL2.frames).some((m) => !m.control), false);

  hsL2.socket.destroy();

  // Ограничитель контрольных кадров: waf_frame_control_rate 2r/s -- из
  // шести ping подряд до приложения доходят первые два (всплеск -- секунда
  // частоты), остальные не пересылаются; соединение при этом живо.
  const hsL3 = await connectOrDie(port, { path: "/local/chat" });
  check("контрольные кадры: 101", hsL3.status, 101);

  const rxL3 = reader(hsL3.socket, hsL3.rest);

  for (let i = 0; i < 6; i++) {
    hsL3.socket.write(encodeFrame({ opcode: OP.ping, mask: true, payload: Buffer.from(`p${i}`) }));
  }

  await rxL3.wait(2);
  await sleep(300);

  const pongs = rxL3.frames.filter((f) => f.opcode === OP.pong).length;
  check("контрольные кадры: pong пришли только на пропущенные ping", pongs >= 1 && pongs <= 3, true);
  check("контрольные кадры: соединение живо",
    rxL3.frames.some((f) => f.opcode === OP.close), false);

  hsL3.socket.write(text("after"));
  await rxL3.wait(pongs + 1);
  check("контрольные кадры: кадр данных после флуда доходит",
    assemble(rxL3.frames).some((m) => !m.control && m.payload.toString("utf8") === "after"), true);

  hsL3.socket.destroy();

  // --- квота: лестница из двух корзин счётчика на /quota/ ------------------
  //
  // Первая корзина -- три кадра по соединению: два кадра проходят эхом, с
  // третьего счётчик первой волной просит rewrite_quota (do: mutate, group:
  // quota_error, set: on, повод WS_QUOTA) включить группу, и вторая волна подменяет кадр
  // сообщением об ошибке -- приложение получает его вместо сообщения, эхо
  // возвращает клиенту. Вторая корзина -- шесть кадров по адресу: шестой
  // кладёт адрес в живой набор blocklist (событие keeper, дельта модулю), и
  // локальный слой закрывает сессию на седьмом кадре, а новое рукопожатие с
  // того же адреса получает 403 ещё на фазе запроса.
  const quotaError = '{"error":"quota exceeded"}';
  const hsQ = await connectOrDie(port, { path: "/quota/chat" });
  check("квота: 101", hsQ.status, 101);

  const rxQ = reader(hsQ.socket, hsQ.rest);

  hsQ.socket.write(text("q1"));
  hsQ.socket.write(text("q2"));
  await rxQ.wait(2);

  const quotaEcho = () => assemble(rxQ.frames).filter((m) => !m.control)
    .map((m) => m.payload.toString("utf8"));

  check("квота: первые два кадра проходят эхом", quotaEcho().slice(0, 2).join(","), "q1,q2");

  for (const q of ["q3", "q4", "q5", "q6"]) {
    hsQ.socket.write(text(q));
  }

  await rxQ.wait(6);
  check("квота: с третьего кадра приложение получает сообщение об ошибке (просьба mutate → rewrite)",
    quotaEcho().slice(2, 6).every((t) => t === quotaError), true);
  check("квота: шесть кадров -- шесть эх, соединение живо",
    quotaEcho().length === 6 && !rxQ.frames.some((f) => f.opcode === OP.close), true);

  // Бан едет асинхронно: счётчик → keeper → дельта → зеркало модуля.
  await sleep(800);

  hsQ.socket.write(text("q7"));
  check("квота: седьмой кадр -- адрес в blocklist, сессия закрыта локальным слоем",
    await rxQ.waitEnd(5000), true);
  close = closeOf(rxQ);
  check("квота: Close 1008 с именем набора", close.code === 1008 && close.reason === "blocklist", true);
  check("квота: седьмой кадр до приложения не дошёл", quotaEcho().length, 6);

  hsQ.socket.destroy();

  const bannedHs = await handshake(port, { path: "/quota/chat" });
  check("квота: новое рукопожатие с забаненного адреса -- 403 на фазе запроса", bannedHs.status, 403);
  bannedHs.socket.destroy();

  const keeperLog = docker(["logs", `${tag}-keeper`]).stdout;
  check("keeper: событие счётчика записало адрес в blocklist",
    /add blocklist \S+ ttl=60 by counter/.test(keeperLog), true);

  // --- рукопожатие websocket-пути: расширения и обычный GET ----------------
  //
  // На /ws/ снятия нет: предложение сжатия доходит до приложения, и эхо
  // подтверждает его в 101. На /ws2/ модуль снимает permessage-deflate до
  // проксирования -- 101 без расширения, кадры пойдут открытыми. Обычный GET
  // на /ws2/ -- 426 из записи upgrade_required, до приложения не доходя.
  const hsExt = await connectOrDie(port, { extensions: "permessage-deflate; client_max_window_bits" });
  check("расширения: без снятия предложение доходит до приложения",
    /sec-websocket-extensions:\s*permessage-deflate/i.test(hsExt.head), true);
  hsExt.socket.destroy();

  const hsStrip = await connectOrDie(port, {
    path: "/ws2/chat", extensions: "permessage-deflate; client_max_window_bits",
  });
  check("расширения: /ws2/ снимает permessage-deflate -- 101 без него",
    /sec-websocket-extensions/i.test(hsStrip.head), false);
  check("расширения: рукопожатие при этом состоялось", hsStrip.status, 101);
  hsStrip.socket.destroy();

  const plain = await plainGet(port, "/ws2/chat");
  check("require_upgrade: обычный GET на websocket-путь -- 426", plain.status, 426);

  // --- рукопожатие отвергается локальным слоем ------------------------------
  const bad = await handshake(port, { ua: "sqlmap/1.0" });

  check("отказ на рукопожатии: 403", bad.status, 403);
  check("отказ на рукопожатии: апгрейда не было",
    /101 switching/i.test(bad.head), false);

  bad.socket.destroy();

  await sleep(300);

  // --- сколько записей увидел модуль ----------------------------------------
  const logs = docker(["logs", `${tag}-nginx`]).stdout
    + docker(["logs", `${tag}-nginx`]).stderr;

  const count = (re) => (logs.match(re) ?? []).length;

  check("лог: четырнадцать записей на рукопожатия", count(/waf: allow phase request/g), 14);
  // плохой UA, GET без апгрейда и рукопожатие с забаненного адреса
  check("лог: три отказа рукопожатия записаны", count(/waf: deny phase request/g), 3);
  check("лог: снятие расширения записано", count(/stripped 1 websocket extension/g), 1);
  check("лог: отказ без апгрейда записан", count(/request without websocket upgrade/g), 1);
  // сессия 1: hello дважды; сессия 3: join и push-leak; сессия 5: собранное;
  // сессия 6: два кадра туда и два эха обратно; сессия 7: сколько успело до
  // отказа -- по времени.
  check("лог: пропущенные кадры", count(/waf: allow phase frame/g) >= 9, true);
  // сессия 1: инъекция; 2: схема; 4: двоичный; 7: счётчик; /local/: лимит и
  // список; /quota/: бан. Фрагменты (сессия 5) теперь собираются и проходят.
  check("лог: семь отказанных кадров", count(/waf: deny phase frame/g), 7);
  check("лог: четырнадцать сессий кадров закрыты", count(/waf: frame session closed/g), 14);
  // /ws2/: две подмены и собранное сообщение; /quota/: четыре кадра ошибкой
  check("лог: семь подмен полезной нагрузки", count(/waf: (c2s|s2c) frame payload rewritten/g), 7);
  check("лог: подмена в обе стороны",
    /c2s frame payload rewritten/.test(logs) && /s2c frame payload rewritten/.test(logs), true);
  check("лог: набор blocklist принял снапшот и дельту keeper",
    /dataset "blocklist" applied snapshot/.test(logs) && /dataset "blocklist" applied add seq/.test(logs), true);
  check("лог: бан по квоте закрыл кадр локальным слоем",
    /local block by dataset "blocklist"/.test(logs), true);
  check("лог: зеркало набора не разошлось с keeper", /diverged/.test(logs), false);
  // сессия 5 (/ws/) и сессия 6б (/ws2/): по одному собранному сообщению
  check("лог: два сообщения собраны из фрагментов", count(/message of \d+ bytes reassembled from/g), 2);
  // сессия 1: второе hello -- из кеша; на /ws2/ счётчик кеш запрещает, и
  // повторов там быть не должно
  check("лог: один вердикт из кеша", count(/reason "FRAME_CACHE"/g), 1);
  check("лог: отказ локального слоя на кадре записан правилом",
    /local rate limit exceeded for key/.test(logs) && /local block by dataset "ws_binary"/.test(logs), true);
  check("лог: контрольные кадры сверх частоты отброшены",
    count(/control frames above waf_frame_control_rate are dropped/g), 1);

  for (const bad of ["[alert]", "[emerg]", "segfault"]) {
    if (logs.includes(bad)) {
      console.error(`FAIL в логе ${bad}`);
      failed += 1;
    }
  }

  // --- записи аудита у приёмника ---------------------------------------------
  // /ws/ пишет кадры по умолчанию (deny: отказ, подмена, счёт), /ws2/ -- все
  // спрошенные. Сессия закрывается записью phase=session у каждого
  // соединения, и кадры с сессией помнят рукопожатие через conn_id.
  const recs = docker(["logs", `${tag}-agent`]).stdout.split("\n")
    .filter((line) => line.startsWith("REC "))
    .map((line) => JSON.parse(line.slice(4)));

  const requests = recs.filter((r) => r.phase === "request");
  const frames = recs.filter((r) => r.phase === "frame");
  const sessions = recs.filter((r) => r.phase === "session");
  const handshakes = new Set(requests.map((r) => r.ray));

  check("аудит: рукопожатия записаны", requests.length >= 14, true);
  check("аудит: семь отказанных кадров",
    frames.filter((r) => r.verdict === "deny").length, 7);
  check("аудит: семь подмен записаны",
    frames.filter((r) => r.frame?.rewritten === true).length, 7);
  // /quota/ пишет все кадры: у подменённых видно, что просьба mutate дошла
  // -- rewrite_quota среди участников, а у седьмого код local_list.
  const quota = frames.filter((r) => r.route?.location === "/quota/");
  check("аудит: кадры квоты записаны с участниками", quota.length, 7);
  check("аудит: у подменённых кадров квоты rewrite_quota среди участников",
    quota.filter((r) => r.frame?.rewritten === true)
      .every((r) => Object.keys(r.inspectors ?? {}).includes("rewrite_quota")), true);
  // mode=off: пока счётчик не включил, rewrite_quota в записи стоит со
  // state off -- его не спрашивали, и по аудиту видно почему; у подменённых
  // просьба active записана среди действий кадра.
  const quiet = quota.filter((r) => r.verdict === "allow" && r.frame?.rewritten !== true);
  check("аудит: до просьбы rewrite_quota не зовут (state off)",
    quiet.length > 0 && quiet.every((r) => r.inspectors?.rewrite_quota?.state === "off"), true);
  check("аудит: просьба active записана среди действий подменённого кадра",
    quota.filter((r) => r.frame?.rewritten === true)
      .every((r) => (r.actions ?? []).some((a) => a.do === "active" && a.to === "rewrite_quota")), true);
  check("аудит: собранное сообщение записано с числом фрагментов",
    frames.some((r) => r.frame?.fragments === 2 && r.frame?.rewritten === true), true);
  check("аудит: отказ локального слоя на кадре -- код local_rate и local_list",
    frames.some((r) => r.verdict === "deny" && r.code === "local_rate")
      && frames.some((r) => r.verdict === "deny" && r.code === "local_list"), true);
  check("аудит: кадры обеих сторон на /ws2/",
    frames.some((r) => r.frame?.direction === "c2s") && frames.some((r) => r.frame?.direction === "s2c"),
    true);
  check("аудит: кадр под ray рукопожатия",
    frames.every((r) => r.ray === r.frame?.conn_id && handshakes.has(r.ray)), true);
  check("аудит: адрес кадра (ray, сторона, номер) уникален",
    new Set(frames.map((r) => `${r.ray}/${r.frame?.direction}/${r.frame?.seq}`)).size,
    frames.length);
  check("аудит: срез полезной нагрузки у отказанного кадра",
    frames.some((r) => r.verdict === "deny" && (r.frame?.payload_preview ?? "") !== ""), true);

  // Превью и архив кадров. На /ws/ стоит waf_preview frame:c2s body=512 и
  // waf_archive frame:c2s body when=deny: у отказанного кадра в записи есть
  // body_preview (та же колонка, что у тела запроса) и секция store.archive
  // с адресом объекта -- ключ :frm остался агенту. На /ws2/ превью обеих
  // сторон есть у каждой записи, архива нет: секции archive там не бывает.
  const deniedWs = frames.filter((r) => r.verdict === "deny" && r.route?.location === "/ws/");
  const ws2 = frames.filter((r) => r.route?.location === "/ws2/");
  check("превью: body_preview у отказанных кадров /ws/",
    deniedWs.length > 0 && deniedWs.every((r) => (r.body_preview ?? "") !== ""), true);
  check("превью: обе стороны на /ws2/ несут body_preview",
    ws2.some((r) => r.frame?.direction === "s2c" && (r.body_preview ?? "") !== "")
      && ws2.some((r) => r.frame?.direction === "c2s" && (r.body_preview ?? "") !== ""), true);
  check("архив: у отказанных кадров /ws/ секция archive и адрес объекта :frm",
    deniedWs.every((r) => typeof r.store?.archive?.body?.ttl === "number"
      && /:frm$/.test(r.store?.body?.key ?? "")), true);
  check("архив: у кадров /ws2/ архива нет",
    ws2.length > 0 && ws2.every((r) => r.store?.archive === undefined), true);

  // Обменник после прогона: объект, названный в waf_archive, остаётся под
  // retain_ttl и виден здесь; всё остальное модуль снял вместе с кадром.
  // Подмены инспектора rewrite лежат под своим суффиксом (:frm:out) и в
  // выборку *:frm не попадают.
  //
  // Исключение — кадр, захваченный уже во время закрытия соединения (сосед
  // получил отказ): нагрузка успевает лечь в обменник, вердикта никто не
  // выносит, и ключ ждёт ttl обменника. Таких ровно по одному на каждое
  // закрытое по политике соединение — это гонка завершения фазы кадров, не
  // архив; здесь она описана границей, а не проверяется штучно. Поэтому
  // свежий обменник = архивированные ключи плюс эти застрявшие.
  const kept = docker(["exec", `${tag}-redis`, "redis-cli", "--scan", "--pattern", "*:frm"]).stdout
    .split("\n").map((l) => l.trim()).filter((l) => l !== "");
  // Отказ локального слоя (лимит, список) закрывает соединение до обменника:
  // кадр в обменник не клался, застревать нечему.
  const localDenied = new Set(frames
    .filter((r) => r.verdict === "deny" && /^local_/.test(r.code ?? ""))
    .map((r) => r.ray));
  const policyClosed = sessions
    .filter((r) => r.session?.close_reason === "waf_deny" && !localDenied.has(r.ray)).length;
  check("обменник: каждый архивированный кадр лежит в обменнике",
    deniedWs.length > 0 && deniedWs.every((r) => kept.includes(r.store?.body?.key)), true);
  check("обменник: сверх архива — только застрявшие при закрытии кадры",
    kept.length, deniedWs.length + policyClosed);
  check("аудит: четырнадцать сессий", sessions.length, 14);
  check("аудит: сессия под ray рукопожатия",
    sessions.every((r) => r.ray === r.session?.conn_id && handshakes.has(r.ray)), true);
  check("аудит: семь сессий с отказом",
    sessions.filter((r) => (r.session?.frames_denied ?? 0) > 0).length, 7);
  check("аудит: у сессии есть причина закрытия",
    sessions.every((r) => (r.session?.close_reason ?? "") !== ""), true);
  // Рукопожатия без кадров (расширения, plain) тоже сессии: с нулями.
  check("аудит: двенадцать сессий с кадрами",
    sessions.filter((r) => (r.session?.frames_c2s ?? 0) + (r.session?.frames_s2c ?? 0) > 0).length, 12);
  // Итоги сессии видят кеш, сборку и отброшенные контрольные кадры.
  check("аудит: сессия с вердиктом из кеша",
    sessions.filter((r) => (r.session?.frames_cached ?? 0) > 0).length, 1);
  check("аудит: две сессии с собранными сообщениями",
    sessions.filter((r) => (r.session?.messages_reassembled ?? 0) > 0).length, 2);
  check("аудит: сессия с отброшенными контрольными кадрами",
    sessions.filter((r) => (r.session?.control_dropped ?? 0) > 0).length, 1);
  check("аудит: подменённый кадр записан подменённым",
    frames.filter((r) => r.frame?.rewritten === true).every((r) => r.verdict === "allow"), true);

  // source=sent на /ws2/: запись показывает ДОСТАВЛЕННУЮ версию подменённого
  // кадра, не оригинал. c2s "hello badword" -> upstream "hello ***";
  // s2c "token secret-123 here" -> клиенту "token secret-*** here". В записи
  // body_preview обязан нести маскированное и НЕ нести секрет, а флаг
  // body_preview_source — "sent". Оригинал в архив /ws2/ не уезжает (архива
  // нет), но принцип «запись = доставленное» проверяется здесь.
  const rw = frames.filter((r) => r.frame?.rewritten === true && r.route?.location === "/ws2/");
  check("source=sent: у всех трёх подмен /ws2/ запись помечена sent",
    rw.length === 3 && rw.every((r) => r.body_preview_source === "sent"), true);
  check("source=sent: в записи доставленная версия (маскированная)",
    rw.every((r) => (r.body_preview ?? "").includes("***")), true);
  check("source=sent: оригинальный секрет в запись не попал",
    rw.every((r) => !/badword|secret-123/.test(r.body_preview ?? "")), true);
  check("source=sent: c2s-подмена показывает hello ***",
    rw.some((r) => r.frame?.direction === "c2s" && (r.body_preview ?? "").includes("hello ***")), true);
  check("source=sent: s2c-подмена показывает secret-*** (доставлено клиенту)",
    rw.some((r) => r.frame?.direction === "s2c" && (r.body_preview ?? "").includes("secret-***")), true);

  if (process.env.WAF_WS_VERBOSE) {
    console.error("--- audit ---\n" + recs.map((r) => JSON.stringify(r)).join("\n"));
  }

  if (failed !== 0 || process.env.WAF_WS_VERBOSE) {
    console.error("--- nginx ---\n" + logs);
    console.error("--- modsec ---\n" + docker(["logs", `${tag}-rules`]).stdout);
    console.error("--- json ---\n" + docker(["logs", `${tag}-json`]).stdout);
    console.error("--- counter ---" + "\n" + docker(["logs", `${tag}-counter`]).stdout);
    console.error("--- rewrite ---" + "\n" + docker(["logs", `${tag}-rewrite`]).stdout);
  }
} finally {
  down();
}

console.log(failed === 0 ? "\nпрогон вебсокета пройден" : `\nнеудач: ${failed}`);
process.exit(failed === 0 ? 0 : 1);
