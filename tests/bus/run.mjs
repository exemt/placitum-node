/**
 * Прогон волн через шину: NATS, четыре поддельных инспектора, nginx с
 * модулем.
 *
 *     node nginx/tests/bus/run.mjs
 *
 * Своя сеть docker, свои контейнеры, свой эфемерный порт -- чужие стенды не
 * трогаются. Это средний слой проверки: дешевле tests/e2e (ни настоящих
 * инспекторов, ни контроллера, ни агента), но, в отличие от nginx -t и
 * дымового прогона, доходит до размещения объектов в обменнике, публикации волны,
 * ожидания вердикта и его применения.
 */

import { spawnSync } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const image = process.env.WAF_NGINX_IMAGE ?? "waf-nginx";
const nodeImage = process.env.WAF_NODE_IMAGE ?? "node:22-alpine";
const natsImage = process.env.WAF_NATS_IMAGE ?? "nats:2.12-alpine";
const redisImage = process.env.WAF_REDIS_IMAGE ?? "redis:7.4-alpine";
const modsecImage = process.env.WAF_MODSEC_IMAGE ?? "waf-inspector-modsec";
const goImage = process.env.WAF_GO_IMAGE ?? "golang:1.25-alpine";
const tag = `waf-bus-${process.pid}`;
const net = `${tag}-net`;
const sockVolume = `${tag}-run`;

const inspectors = [
  { name: "allower", subject: "waf.req.allow", env: ["VERDICT=allow"] },
  { name: "scorer", subject: "waf.req.score", env: ["VERDICT=score", "SCORE=60"] },
  { name: "denier", subject: "waf.req.deny", env: ["VERDICT=deny", "RESPONSE=blocked"] },
  { name: "mute", subject: "waf.req.mute", env: ["VERDICT=silent"] },
  {
    name: "asker",
    subject: "waf.req.ask",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      { to: "scorer", do: "challenge", apply: "request", code: "FAKE_GREYLIST" },
      { do: "note", apply: "ip", code: "FAKE_SEEN", value: 60 },
    ])],
  },
  {
    name: "asker_unknown",
    subject: "waf.req.ask.unknown",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      { to: "nosuch", do: "challenge", apply: "request", code: "FAKE_GREYLIST" },
    ])],
  },
  {
    name: "asker_badverb",
    subject: "waf.req.ask.badverb",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      { do: "explode", apply: "request", code: "FAKE_BAD" },
    ])],
  },
  {
    name: "asker_badaxis",
    subject: "waf.req.ask.badaxis",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      { do: "challenge", apply: "asn", code: "FAKE_BAD" },
    ])],
  },
  /* Очки на маршруте: исполняет модуль, поля to нет, знак свободен. */
  {
    name: "pointer",
    subject: "waf.req.points",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      { do: "score", apply: "request", value: 40, code: "FAKE_POINTS" },
    ])],
  },
  {
    name: "cutter",
    subject: "waf.req.cut",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      { do: "score", apply: "request", value: -30, code: "FAKE_CUT" },
    ])],
  },
  {
    name: "auditor",
    subject: "waf.req.audit",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      /*
       * Журнал: писать вопреки сэмплу, а в запись положить превью заголовков
       * оригиналом на 4 КБ -- на маршруте waf_preview нет вовсе. Архив:
       * заголовки оригиналом со сроком с провода -- без waf_archive.
       */
      { do: "audit", apply: "request", set: "on", code: "FAKE_WATCH",
        headers: { limit: 4096, source: "original" } },
      { do: "archive", apply: "request", set: "on", ttl: 123,
        headers: { source: "original" } },
      /*
       * Запись ответа -- своя: превью заголовков ответа и тело ответа в
       * архив со своим сроком. Там, где фазы ответа нет, уходит в пустоту.
       */
      { do: "audit", apply: "response", set: "on", code: "FAKE_WATCH_RSP",
        headers: { limit: 2048 } },
      { do: "archive", apply: "response", set: "on", ttl: 321,
        body: { source: "store" } },
    ])],
  },
  {
    name: "rsp_auditor",
    subject: "waf.rsp.audit",
    env: ["VERDICT=allow", "ACTIONS=" + JSON.stringify([
      /* С фазы ответа -- про обе записи: запись запроса ждёт исхода и слышит. */
      { do: "audit", apply: "request", set: "on", code: "FAKE_LATE" },
      { do: "archive", apply: "request", set: "on", ttl: 222,
        headers: { source: "store" } },
      { do: "audit", apply: "response", set: "on", code: "FAKE_LATE",
        headers: { limit: 512 } },
      { do: "archive", apply: "response", set: "on", ttl: 333,
        body: { source: "store" } },
    ])],
  },
  {
    name: "gate",
    subject: "waf.req.gate",
    env: ["VERDICT=allow", "SESSIONS=" + JSON.stringify([
      { source: "corp", kind: "own", user: "alice", id: "sid-alice",
        verified: true, groups: ["ops", "dev"] },
    ])],
  },
  { name: "req_quiet", subject: "waf.req.quiet", env: ["VERDICT=allow"] },
  { name: "rsp_allow", subject: "waf.rsp.allow", env: ["VERDICT=allow"] },
  { name: "rsp_deny", subject: "waf.rsp.deny", env: ["VERDICT=deny", "RESPONSE=blocked"] },
  { name: "rsp_slow", subject: "waf.rsp.slow", env: ["VERDICT=allow", "DELAY_MS=3000"] },
];

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
    return;
  }

  console.error(`FAIL ${label}: ${JSON.stringify(got)}, ожидалось ${JSON.stringify(want)}`);
  failed += 1;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function up() {
  docker(["network", "create", net]);
  docker(["volume", "create", sockVolume]);

  /*
   * Приёмник итогов вместо агента. Поднимается первым: сокет создаёт он, и
   * модуль, не найдя его при старте, промахнётся мимо всех записей.
   */
  const agent = docker([
    "run", "-d", "--rm", "--name", `${tag}-agent`, "--network", net,
    "-v", `${hostPath(here)}:/app:ro`, "-v", `${sockVolume}:/run/waf`,
    "-w", "/app", goImage, "go", "run", "agent.go",
  ]);

  if (agent.status !== 0) {
    console.error(agent.stderr || agent.stdout);
    process.exit(1);
  }

  const nats = docker([
    "run", "-d", "--rm", "--name", `${tag}-nats`, "--network", net,
    "--network-alias", "nats", natsImage, "-js",
  ]);

  if (nats.status !== 0) {
    console.error(nats.stderr || nats.stdout);
    process.exit(1);
  }

  const redis = docker([
    "run", "-d", "--rm", "--name", `${tag}-redis`, "--network", net,
    "--network-alias", "redis", redisImage,
  ]);

  if (redis.status !== 0) {
    console.error(redis.stderr || redis.stdout);
    down();
    process.exit(1);
  }

  for (const insp of inspectors) {
    const args = [
      "run", "-d", "--rm", "--name", `${tag}-${insp.name}`, "--network", net,
      "-v", `${hostPath(here)}:/app:ro`, "-w", "/app",
      "-e", `SUBJECT=${insp.subject}`, "-e", `NAME=${insp.name}`,
      "-e", "DUMP=1",
    ];

    for (const e of insp.env) {
      args.push("-e", e);
    }

    args.push(nodeImage, "node", "inspector.mjs");

    const r = docker(args);

    if (r.status !== 0) {
      console.error(r.stderr || r.stdout);
      down();
      process.exit(1);
    }
  }

  /*
   * Настоящий инспектор рядом с поддельными: подделки закрывают ветки
   * разрешения вердикта, а этот -- форму провода. Расхождение в секции
   * response или в request_store подделка не заметит, потому что читает то же,
   * что и пишет.
   */
  const modsec = docker([
    "run", "-d", "--rm", "--name", `${tag}-modsec`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_MODSEC_SUBJECT=waf.rsp.modsec",
    // Тело ответа едет локатором: без адреса обменника инспектор увидит только
    // заголовки, и правила фазы 4 не сработают ни на чём.
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
    "-e", "WAF_MODSEC_NAME=modsec",
    "-e", "WAF_MODSEC_LOG=info",
    modsecImage,
  ]);

  if (modsec.status !== 0) {
    console.error(modsec.stderr || modsec.stdout);
    down();
    process.exit(1);
  }

  /*
   * Тот же образ с выключенным реестром липкости: continue не выдаётся
   * никогда, и на его маршрутах видно, что делает пара keep/resume без
   * состояния -- prefer переигрывает, require отказывает. Свой subject, чтобы
   * сообщения рабочего modsec сюда не попадали.
   */
  const lost = docker([
    "run", "-d", "--rm", "--name", `${tag}-modsec-lost`, "--network", net,
    "-e", "NATS_URL=nats://nats:4222",
    "-e", "WAF_MODSEC_SUBJECT=waf.rsp.modsec.lost",
    "-e", "REDIS_URL=redis://redis:6379",
    "-e", "REDIS_INTERNAL_URL=redis://redis:6379",
    "-e", "WAF_MODSEC_NAME=modsec_lost",
    "-e", "WAF_MODSEC_LOG=info",
    "-e", "WAF_MODSEC_RESUME_MAX=0",
    modsecImage,
  ]);

  if (lost.status !== 0) {
    console.error(lost.stderr || lost.stdout);
    down();
    process.exit(1);
  }

  const nginx = docker([
    "run", "-d", "--rm", "--name", `${tag}-nginx`, "--network", net,
    "-p", "127.0.0.1:0:8080",
    "-v", `${hostPath(here)}:/t:ro`, "-v", `${sockVolume}:/run/waf`,
    "--entrypoint", "nginx",
    image, "-c", "/t/bus.conf", "-g", "daemon off;",
  ]);

  if (nginx.status !== 0) {
    console.error(nginx.stderr || nginx.stdout);
    down();
    process.exit(1);
  }

  return `${tag}-nginx`;
}

function down() {
  for (const insp of inspectors) {
    docker(["stop", "-t", "1", `${tag}-${insp.name}`]);
  }

  docker(["stop", "-t", "1", `${tag}-nginx`]);
  docker(["stop", "-t", "1", `${tag}-modsec`]);
  docker(["stop", "-t", "1", `${tag}-modsec-lost`]);
  docker(["stop", "-t", "1", `${tag}-redis`]);
  docker(["stop", "-t", "1", `${tag}-nats`]);
  docker(["stop", "-t", "1", `${tag}-agent`]);
  docker(["network", "rm", net]);
  docker(["volume", "rm", sockVolume]);
}

function request(path, args = []) {
  const r = docker([
    "exec", `${tag}-nginx`, "curl", "-s", "-i", "-o", "-", "-m", "10",
    ...args, `http://127.0.0.1:8080${path}`,
  ]);

  return r.stdout ?? "";
}

function status(raw) {
  return Number(/^HTTP\/[\d.]+ (\d{3})/.exec(raw)?.[1] ?? 0);
}

function body(raw) {
  const split = raw.indexOf("\r\n\r\n");
  return split === -1 ? "" : raw.slice(split + 4);
}

function debug(raw) {
  return /^x-waf-debug:\s*(.+)$/im.exec(raw)?.[1]?.trim() ?? "";
}

function field(raw, key) {
  return new RegExp(`${key}=([^\\s]+)`).exec(debug(raw))?.[1] ?? "";
}

const container = up();

try {
  let ready = false;

  for (let i = 0; i < 100; i++) {
    if (status(request("/allow/index.html")) === 200) {
      ready = true;
      break;
    }

    await sleep(200);
  }

  if (!ready) {
    console.error(docker(["logs", `${tag}-nginx`]).stdout);
    console.error(docker(["logs", `${tag}-allower`]).stdout);
    throw new Error("стенд не поднялся");
  }

  // --- вердикт allow --------------------------------------------------------
  const allow = request("/allow/index.html");
  check("allow: статус", status(allow), 200);
  check("allow: вердикт в диагностике", field(allow, "v"), "allow");

  // --- score ниже порога ----------------------------------------------------
  const under = request("/score-under/index.html");
  check("score под порогом: статус", status(under), 200);
  check("score под порогом: сумма в диагностике", field(under, "score"), "60");

  // --- score выше порога ----------------------------------------------------
  const over = request("/score-over/index.html");
  check("score над порогом: страница каталога", status(over), 418);
  check("score над порогом: вердикт", field(over, "v"), "deny");

  // --- явный deny -----------------------------------------------------------
  const deny = request("/deny/index.html");
  check("deny: страница каталога", status(deny), 403);
  check("deny: вердикт", field(deny, "v"), "deny");

  // --- две волны ------------------------------------------------------------
  const waves = request("/waves/index.html");
  check("две волны: статус", status(waves), 200);
  check("две волны: счёт второй волны учтён", field(waves, "score"), "60");
  check("две волны: последняя волна в диагностике", field(waves, "wave"), "1");

  // --- молчун и политика дедлайна -------------------------------------------
  const tblock = request("/timeout-block/index.html");
  check("дедлайн block: 503", status(tblock), 503);

  const tpass = request("/timeout-pass/index.html");
  check("дедлайн pass: запрос прошёл", status(tpass), 200);

  // --- пассивный инспектор --------------------------------------------------
  const passive = request("/passive/index.html");
  check("passive deny: запрос прошёл", status(passive), 200);
  check("passive deny: счёт в тени, не в сумме", field(passive, "score"), "0");

  // Поздняя волна пассивного соседа не видит: проверяется ниже, по сообщению,
  // которое получил scorer на этом маршруте.
  const passivePrior = request("/passive-prior/index.html");
  check("passive prior: запрос прошёл", status(passivePrior), 200);

  // --- личности с ранней волны ----------------------------------------------
  const gateRoute = request("/sessions/index.html");
  check("sessions: запрос прошёл", status(gateRoute), 200);

  const gatePassiveRoute = request("/sessions-passive/index.html");
  check("sessions passive: запрос прошёл", status(gatePassiveRoute), 200);

  // --- совещательный голос --------------------------------------------------
  const vote = request("/vote/index.html");
  check("vote deny: запрос прошёл", status(vote), 200);
  check("vote deny: сотня в живой сумме", field(vote, "score"), "100");

  const voteOver = request("/vote-over/index.html");
  check("vote deny над порогом: отказ по сумме", status(voteOver), 418);
  check("vote deny над порогом: исход по счёту, не вердиктом", field(voteOver, "by"), "score");

  const voteScore = request("/vote-score/index.html");
  check("vote score: запрос прошёл", status(voteScore), 200);
  check("vote score: заявка в живой сумме", field(voteScore, "score"), "60");

  const votePrior = request("/vote-prior/index.html");
  check("vote prior: запрос прошёл", status(votePrior), 200);

  // --- очки на маршруте -----------------------------------------------------
  const points = request("/points/index.html");
  check("очки: запрос прошёл", status(points), 200);
  check("очки: просьба легла в сумму", field(points, "score"), "40");

  const pointsOver = request("/points-over/index.html");
  check("очки + вердикт: отказ по сумме", status(pointsOver), 418);
  check("очки + вердикт: исход по счёту", field(pointsOver, "by"), "score");

  const pointsCut = request("/points-cut/index.html");
  check("снять очки: запрос прошёл под порог", status(pointsCut), 200);
  check("снять очки: сумма уменьшилась", field(pointsCut, "score"), "30");

  const pointsPassive = request("/points-passive/index.html");
  check("очки от пассивного: отброшены, отказ по сумме", status(pointsPassive), 418);
  check("очки от пассивного: сумма нетронута", field(pointsPassive, "score"), "60");

  // --- канал действий -------------------------------------------------------
  //
  // Доставка проверяется ниже, по сообщениям получателя; здесь -- только то,
  // что видно клиенту. Ошибка в действии не должна стоить трафика, кроме
  // случая, когда она отбраковывает весь ответ.
  check("действия: запрос прошёл", status(request("/actions/index.html")), 200);
  check("действия off: запрос прошёл", status(request("/actions-off/index.html")), 200);
  check("действия: незнакомый адресат не стоит ответа",
    status(request("/actions-unknown-to/index.html")), 200);

  check("действия: незнакомый глагол отбраковывает ответ целиком",
    status(request("/actions-bad-verb/index.html")), 503);
  check("действия: ось не для глагола -- то же самое",
    status(request("/actions-bad-axis/index.html")), 503);

  // --- что увидел инспектор -------------------------------------------------
  const seen = docker(["logs", `${tag}-allower`]).stdout;
  const req = (seen.match(/^REQ (.+)$/m) ?? [])[1];

  check("сообщение инспектору: есть", Boolean(req), true);

  if (req) {
    const msg = JSON.parse(req);

    check("сообщение: фаза", msg.phase, "request");
    check("сообщение: имя инспектора", msg.inspector, "allower");
    check("сообщение: заголовки в needs", msg.needs?.includes("headers"), true);
    check("сообщение: секции request_store на фазе запроса нет",
      msg.request_store?.headers ?? null, null);
    check("сообщение: секции response на фазе запроса нет",
      msg.response ?? null, null);
  }

  // Волна 1 видит вердикт волны 0 в prior -- на этом строятся решения
  // поздних инспекторов.
  const wavesSeen = docker(["logs", `${tag}-scorer`]).stdout;
  const prior = (wavesSeen.match(/^REQ (.+"prior":\[[^\]]+\].+)$/m) ?? [])[1];

  check("prior: волна 1 видит ответ волны 0", Boolean(prior), true);

  if (prior) {
    const msg = JSON.parse(prior);
    check("prior: имя предшественника", msg.prior?.[0]?.inspector, "allower");
    check("prior: волна предшественника", msg.prior?.[0]?.wave, 0);
  }

  // Сообщения получателя по маршрутам: логи одного контейнера на все ветки,
  // поэтому разбираются они по uri, а не по порядку.
  const parsed = wavesSeen
    .split("\n")
    .filter((l) => l.startsWith("REQ "))
    .map((l) => JSON.parse(l.slice(4)));

  const seenFor = (uri) => parsed.find((m) => m.uri === uri);
  const priorOf = (msg, name) => (msg?.prior ?? []).find((p) => p.inspector === name);

  // Пассивный отправитель в prior не попадает вовсе. Проверяется на маршруте,
  // где он стоит волной раньше получателя: запись либо есть, либо её нет, и
  // третьего состояния у этого решения быть не должно.
  const passiveSeen = seenFor("/passive-prior/index.html");

  check("passive prior: поздняя волна получила сообщение", Boolean(passiveSeen), true);

  if (passiveSeen) {
    const seenNames = (passiveSeen.prior ?? []).map((p) => p.inspector);

    check("passive prior: записи пассивного нет", seenNames.includes("denier"), false);
    check("passive prior: и никакой другой не появился", seenNames.length, 0);
  }

  /*
   * Личности с ранней волны: модуль возвращает соседям то, что калитка
   * сказала о клиенте. Проверяется на маршруте, где она стоит волной раньше
   * получателя, -- по этой секции счётчик ключует корзины человеком, а не
   * кукой, которую клиент вращает.
   */
  const gateSeen = seenFor("/sessions/index.html");

  check("sessions: поздняя волна получила сообщение", Boolean(gateSeen), true);

  if (gateSeen) {
    const one = (gateSeen.sessions ?? [])[0];

    check("sessions: запись доехала", (gateSeen.sessions ?? []).length, 1);
    check("sessions: имя отправителя", one?.inspector, "gate");
    check("sessions: источник входа", one?.source, "corp");
    check("sessions: вид сессии", one?.kind, "own");
    check("sessions: логин", one?.user, "alice");
    check("sessions: идентификатор сессии", one?.id, "sid-alice");
    check("sessions: проверенность", one?.verified, true);
    check("sessions: группы массивом", JSON.stringify(one?.groups ?? []),
      JSON.stringify(["ops", "dev"]));
  }

  // Пассивная калитка личностей не называет: у наблюдения нет рук.
  const gatePassive = seenFor("/sessions-passive/index.html");

  check("sessions passive: поздняя волна получила сообщение", Boolean(gatePassive), true);

  if (gatePassive) {
    check("sessions passive: секции нет вовсе", gatePassive.sessions ?? null, null);
  }

  // Совещательный -- участник решения, и соседям он виден: вердикт как сказан,
  // score -- что легло в сумму.
  const voteSeen = seenFor("/vote-prior/index.html");

  check("vote prior: поздняя волна получила сообщение", Boolean(voteSeen), true);

  if (voteSeen) {
    const entry = priorOf(voteSeen, "denier");

    check("vote prior: запись совещательного есть", Boolean(entry), true);
    check("vote prior: вердикт как сказан", entry?.verdict, "deny");
    check("vote prior: score -- что легло в сумму", entry?.score, 100);
    check("vote prior: weighted больше не едет", "weighted" in (entry ?? {}), false);
  }

  // Очки соседям не доставляют: след -- в score отправителя в prior.
  const pointsSeen = seenFor("/points-over/index.html");

  check("очки в prior: поздняя волна получила сообщение", Boolean(pointsSeen), true);

  if (pointsSeen) {
    const entry = priorOf(pointsSeen, "pointer");

    check("очки в prior: вердикт отправителя как сказан", entry?.verdict, "allow");
    check("очки в prior: очки легли в score отправителя", entry?.score, 40);
    check("очки в prior: сама просьба соседу не едет", (entry?.actions ?? []).length, 0);
  }

  // Действия: адресное и широковещательное доезжают одинаково, и получатель
  // не отличает одно от другого -- поля to в доставленном нет.
  const acted = seenFor("/actions/index.html");
  check("действия: поздняя волна получила сообщение", Boolean(acted), true);

  if (acted) {
    const from = priorOf(acted, "asker");
    const byCode = (c) => (from?.actions ?? []).find((a) => a.code === c);

    check("действия: запись отправителя на месте", Boolean(from), true);
    check("действия: доехали оба", from?.actions?.length, 2);
    check("действия: поля to в доставленном нет",
      (from?.actions ?? []).every((a) => a.to === undefined), true);

    check("действия: глагол адресного", byCode("FAKE_GREYLIST")?.do, "challenge");
    check("действия: ось адресного", byCode("FAKE_GREYLIST")?.apply, "request");
    check("действия: ось широковещательного", byCode("FAKE_SEEN")?.apply, "ip");
    check("действия: число широковещательного", byCode("FAKE_SEEN")?.value, 60);
  }

  // waf_actions_max 0: канал выключен, вердикты продолжают ездить.
  const actedOff = seenFor("/actions-off/index.html");
  check("действия off: сообщение есть", Boolean(actedOff), true);

  if (actedOff) {
    const from = priorOf(actedOff, "asker");

    check("действия off: вердикт отправителя доехал", from?.verdict, "allow");
    check("действия off: действий нет", from?.actions ?? null, null);
  }

  // Незнакомый адресат стоит действия, но не ответа.
  const unknownTo = seenFor("/actions-unknown-to/index.html");
  check("действия: сообщение после незнакомого адресата есть", Boolean(unknownTo), true);

  if (unknownTo) {
    const from = priorOf(unknownTo, "asker_unknown");

    check("действия: ответ отправителя жив", from?.verdict, "allow");
    check("действия: действие отброшено", from?.actions ?? null, null);
  }

  // --- фаза ответа ----------------------------------------------------------
  //
  // Ответ держится до вердикта, поэтому здесь проверяется не только код, но и
  // тело: удержанная цепочка обязана дойти до клиента ровно той же.
  const direct = request("/index.html");
  const held = request("/rsp-allow/index.html");

  check("фаза ответа: allow отдаёт ответ", status(held), 200);
  check("фаза ответа: тело не пострадало от удержания",
    body(held), body(direct));
  check("фаза ответа: вердикт фазы в диагностике", field(held, "v"), "allow");

  const denied = request("/rsp-deny/index.html");

  check("фаза ответа: deny отдаёт страницу каталога", status(denied), 403);
  check("фаза ответа: тело приложения не ушло клиенту",
    body(denied).includes("nginx"), true);
  check("фаза ответа: ответа приложения в теле нет",
    body(denied) === body(direct), false);

  const monitored = request("/rsp-monitor/index.html");
  check("waf_hold response monitor: ответ ушёл не дожидаясь вердикта",
    status(monitored), 200);
  check("waf_hold response monitor: тело целое", body(monitored), body(direct));

  const rspTimeout = request("/rsp-timeout/index.html");
  check("фаза ответа: молчун и block дают 503", status(rspTimeout), 503);

  const both = request("/both/index.html");
  check("обе фазы: запрос прошёл", status(both), 200);

  /*
   * Объекты фазы запроса живут до конца фазы ответа. Запрос уходит в фон и
   * висит на медленном инспекторе; пока он висит, ключи фазы запроса обязаны
   * быть в обменнике -- их адрес уже уехал инспектору секцией request_store.
   *
   * Смотрится последняя из трёх попыток: к ней фаза запроса заведомо
   * закончилась, и найденный ключ означает именно переживший её объект.
   * Префикс узла в шаблоне обязателен: в том же Redis лежат объекты пробы
   * инспектора, и они к фазам стенда отношения не имеют.
   */
  docker([
    "exec", `${tag}-nginx`, "sh", "-c",
    "curl -s -o /dev/null -m 20 http://127.0.0.1:8080/rsp-hold/index.html &",
  ]);

  let reqKeys = "";

  /*
   * Ключ появляется, когда curl в фоне дошёл до размещения, а медленный
   * инспектор держит фазу ответа три секунды: ждём ключ, а не гадаем, успел
   * ли фоновый процесс стартовать раньше первого скана.
   */
  for (let i = 0; i < 60 && reqKeys === ""; i++) {
    reqKeys = docker([
      "exec", `${tag}-redis`, "redis-cli", "--scan", "--pattern", "bus:*:req:hdr",
    ]).stdout.trim();

    if (reqKeys === "") {
      await sleep(100);
    }
  }

  check("объекты запроса живы, пока идёт фаза ответа", Boolean(reqKeys), true);

  const holdDone = request("/rsp-hold/index.html");

  check("фаза ответа: медленный инспектор уложился в дедлайн",
    status(holdDone), 200);
  check("объекты запроса сняты после фазы ответа",
    docker([
      "exec", `${tag}-redis`, "redis-cli", "--scan", "--pattern", "bus:*:req:hdr",
    ]).stdout.trim(), "");

  // Что увидел инспектор фазы ответа.
  const rspSeen = docker(["logs", `${tag}-rsp_allow`]).stdout;
  const rspReq = (rspSeen.match(/^REQ (.+)$/m) ?? [])[1];

  check("сообщение фазы ответа: есть", Boolean(rspReq), true);

  if (rspReq) {
    const msg = JSON.parse(rspReq);

    check("сообщение фазы ответа: фаза", msg.phase, "response");
    check("сообщение фазы ответа: статус апстрима", msg.response?.status, 200);
    check("сообщение фазы ответа: заголовки ответа приехали",
      Array.isArray(msg.response?.headers) && msg.response.headers.length > 0,
      true);
    check("сообщение фазы ответа: set-cookie не отправляется",
      (msg.response?.headers ?? []).some((h) => /set-cookie/i.test(h[0])),
      false);
  }

  // Маршрут с обеими фазами: контекст запроса приезжает секцией request_store.
  const bothSeen = docker(["logs", `${tag}-rsp_allow`]).stdout
    .split("\n").filter((l) => l.startsWith("REQ "));

  const withContext = bothSeen
    .map((l) => JSON.parse(l.slice(4)))
    .find((m) => m.request_store?.headers);

  check("request_store: объекты фазы запроса доехали", Boolean(withContext),
    true);

  if (withContext) {
    check("request_store: ключ фазы запроса",
      /:req/.test(withContext.request_store.headers.key ?? ""), true);
    check("store фазы ответа пуст: снимка ответа ещё нет",
      withContext.store?.headers ?? null, null);
  }

  // --- снимок фазы ответа -----------------------------------------------------
  const captured = request("/rsp-capture/index.html");
  check("снимок ответа: запрос прошёл", status(captured), 200);
  check("снимок ответа: тело не пострадало", body(captured), body(direct));

  const capSeen = docker(["logs", `${tag}-rsp_allow`]).stdout
    .split("\n").filter((l) => l.startsWith("REQ "))
    .map((l) => JSON.parse(l.slice(4)))
    .find((m) => m.store?.headers);

  check("снимок ответа: заголовки в обменнике", Boolean(capSeen), true);

  if (capSeen) {
    check("снимок ответа: ключ объекта фазы ответа",
      /:rsp:hdr$/.test(capSeen.store.headers.key ?? ""), true);
    check("снимок ответа: тело в обменнике",
      /:rsp$/.test(capSeen.store.body?.key ?? ""), true);
    check("снимок ответа: инлайновых заголовков больше нет",
      capSeen.response?.headers ?? null, null);
    check("снимок ответа: needs называет оба объекта",
      (capSeen.needs ?? []).sort().join(","), "body,headers");
  }

  // --- настоящий modsec на фазах 3-4 ---------------------------------------
  //
  // Инспектор поднимается дольше подделок: набор CRS компилируется при старте.
  // Готовность -- строка connected: к ней уже подняты обе подписки, групповая и
  // личная, а личная и есть та, куда поедет продолжение.
  let modsecReady = false;

  for (let i = 0; i < 100; i++) {
    if (/"msg":"connected".*"resume_inbox":"waf\.rsp\.modsec\./.test(
          docker(["logs", `${tag}-modsec`]).stdout)) {
      modsecReady = true;
      break;
    }

    await sleep(300);
  }

  check("modsec: инспектор поднялся с личным subject", modsecReady, true);

  const clean = request("/rsp-modsec-ok/");
  check("modsec: чистый ответ проходит", status(clean), 200);

  const status500 = request("/rsp-modsec/");
  check("modsec: ответ 500 отказан по порогу", status(status500), 418);
  check("modsec: отказ пришёл от порога, а не от движка",
    field(status500, "v"), "deny");

  // Утечка в теле: правила фазы 4. Без снимка тела этот отказ невозможен, и
  // именно он отличает "смотрим ответ" от "смотрим заголовки ответа".
  const leak = request("/rsp-leak/");
  check("modsec: утечка в теле отказана", status(leak), 418);

  /*
   * Липкость: тот же инспектор на обеих фазах. Проверяется по его же логу --
   * resumed=true означает, что фазы 3-4 доиграны на транзакции фазы запроса.
   */
  const sticky = request("/rsp-sticky/");

  check("липкость: утечка в теле отказана", status(sticky), 418);

  /*
   * Фаза 4 отдельно от CRS: профиль canary держит одно правило на
   * RESPONSE_BODY. Метка в теле -- отказ, та же метка в заголовке -- нет.
   * Пара нужна целиком: один маршрут доказывал бы только, что движок где-то
   * нашёл подстроку.
   */
  /*
   * Брошенное продолжение: отказ пришёл раньше нашей волны, фазы ответа не
   * будет, и состояние в памяти инспектора надо снять сообщением, а не сроком.
   */
  const abandoned = request("/rsp-abandoned/index.html");

  check("брошенное продолжение: запрос отказан", status(abandoned), 403);

  const canary = request("/rsp-canary/");
  const canaryHdr = request("/rsp-canary-hdr/");

  check("фаза 4: метка в теле отказана", status(canary), 418);
  check("фаза 4: метка в заголовке пропущена", status(canaryHdr), 200);
  check("фаза 4: тело ответа не ушло клиенту",
    /WAF-CANARY/.test(body(canary)), false);

  const gz = request("/rsp-leak/", ["-H", "Accept-Encoding: gzip"]);

  // Клиент просил gzip, но маршрут снимает тело: Accept-Encoding в апстрим не
  // ушёл, тело приехало текстом, и утечка найдена.
  check("accept-encoding: снято -- утечка найдена в несжатом теле",
    status(gz), 418);

  // Обратная сторона: сжатие не снято -- инспектор видит gzip и не находит
  // ничего. Цена настройки, а не сюрприз.
  const gzOff = request("/rsp-leak-gz/", ["-H", "Accept-Encoding: gzip"]);

  check("accept-encoding off: апстрим сжал ответ",
    /content-encoding:\s*gzip/i.test(gzOff), true);
  check("accept-encoding off: утечка в сжатом теле не найдена",
    status(gzOff), 200);

  const modsecLog = docker(["logs", `${tag}-modsec`]).stdout;

  check("modsec: тело ответа доехало и дало счёт",
    /"uri":"\/rsp-leak\/".*"crs_anomaly_score":[1-9]/.test(modsecLog), true);

  check("modsec: вердикт фазы ответа записан",
    /"phase":"response"/.test(modsecLog), true);
  check("modsec: правила фазы 3 сработали и дали счёт",
    /"crs_anomaly_score":[1-9]/.test(modsecLog), true);

  // Липкий путь и откат -- рядом, на одном прогоне: маршрут с resume=
  // доигрывает транзакцию фазы запроса, маршрут без него переигрывает фазы 1-2.
  const lines = modsecLog.split("\n");
  const stickyLine = lines.find((l) =>
    /"uri":"\/rsp-sticky\/"/.test(l) && /"phase":"response"/.test(l));
  const replayLine = lines.find((l) =>
    /"uri":"\/rsp-leak\/"/.test(l) && /"phase":"response"/.test(l));

  check("фаза 4: правило нашлось в логе инспектора",
    /"uri":"\/rsp-canary\/".*"reason":"CRS_ANOMALY"/.test(modsecLog), true);

  // Строки инспектора про липкость -- глазами: WAF_DUMP=1.
  if (process.env.WAF_DUMP) {
    for (const line of lines.filter((l) => /resumed|released/.test(l))) {
      console.log("modsec:", line);
    }
  }

  check("брошенное продолжение: состояние снято сообщением",
    /"msg":"resume state released".*"reason":"deny"/.test(modsecLog), true);

  check("липкость: фаза ответа продолжила транзакцию",
    /"resumed":true/.test(stickyLine ?? ""), true);
  check("липкость: сообщение пришло в личный subject",
    /"personal":true/.test(stickyLine ?? ""), true);
  check("откат: без resume= фазы 1-2 переигрываются",
    /"resumed":false/.test(replayLine ?? ""), true);

  /*
   * Состояние потеряно. Экземпляр modsec_lost continue не выдаёт (реестр
   * выключен), поэтому фаза ответа на его маршрутах всегда приходит в
   * групповой subject без транзакции. Дальше решает require= строки ответа.
   */
  const lostPrefer = request("/rsp-lost-prefer/");
  const lostRequire = request("/rsp-lost-require/");

  // prefer: переигровка по контексту запроса -- утечка найдена и без состояния.
  check("потеря состояния, prefer: утечка найдена переигровкой",
    status(lostPrefer), 418);

  // require: чистый ответ, отказ только от потери состояния. Его выносит
  // инспектор, а не политика модуля: v=deny с причиной инспектора.
  check("потеря состояния, require: запрос отказан", status(lostRequire), 403);
  check("потеря состояния, require: отказ вынес инспектор",
    field(lostRequire, "v"), "deny");

  const lostLog = docker(["logs", `${tag}-modsec-lost`]).stdout;
  const lostLines = lostLog.split("\n");
  const lostPreferLine = lostLines.find((l) =>
    /"uri":"\/rsp-lost-prefer\/"/.test(l) && /"phase":"response"/.test(l));

  // Фаза запроса отработала штатно (строка вердикта без "phase" -- это она),
  // реестра нет (resume_max=0), и parked в её деталях не появлялось.
  check("потеря состояния: фаза запроса отработала, парковать было нечем",
    /"msg":"verdict","rid":"[^"]+","inspector":"modsec_lost","wave":0,"method":"GET","uri":"\/rsp-lost-prefer\/"/
      .test(lostLog) && /"resume_max":0/.test(lostLog), true);
  check("потеря состояния, prefer: resumed=false, сообщение в групповом subject",
    /"resumed":false/.test(lostPreferLine ?? "") && /"personal":false/.test(lostPreferLine ?? ""),
    true);
  check("потеря состояния, require: error в логе инспектора",
    /"level":"ERROR".*"msg":"resume required but state is gone".*"uri":"\/rsp-lost-require\/"/
      .test(lostLog), true);

  if (process.env.WAF_DUMP) {
    for (const line of lostLines.filter((l) => /resume|rsp-lost/.test(l))) {
      console.log("modsec-lost:", line);
    }
  }

  if (process.env.WAF_DUMP) {
    console.log("sticky:", stickyLine ?? "(нет строки)");
    console.log("replay:", replayLine ?? "(нет строки)");
  }

  /*
   * Глаголы записи -- после проверок обменника: archive on оставляет ключ
   * заголовков агенту, а подделка агента ключи не чистит, и скан "req:hdr
   * не осталось" нашёл бы его.
   */
  check("запись по просьбе: запрос прошёл", status(request("/audit-on/index.html")), 200);
  check("обе записи с фазы запроса: запрос прошёл", status(request("/audit-rsp/index.html")), 200);
  check("обе записи с фазы ответа: запрос прошёл", status(request("/audit-rsp-late/index.html")), 200);

  // Журнал без инспекторов: запрос с телом и ответ приложения. Архив оставляет
  // ключи агенту -- поэтому здесь, после сканов "ключей не осталось".
  check("журнал запроса: POST с телом дошёл до апстрима",
    status(request("/journal-req/?q=journal", [
      "-X", "POST", "-H", "X-Journal-Secret: s3cr3t-journal",
      "-H", "Content-Type: text/plain", "--data", "journal-body-payload",
    ])), 200);
  check("журнал ответа: ответ приложения дошёл целиком",
    body(request("/journal-rsp/")).includes("WAF-CANARY-0badc0de"), true);
  check("журнал отказа: локальный слой отказал",
    status(request("/journal-deny/", [
      "-X", "POST", "-A", "journal-bad-agent",
      "-H", "Content-Type: text/plain", "--data", "journal-deny-payload",
    ])), 403);
  await sleep(300);

  // --- запись аудита --------------------------------------------------------
  //
  // Записей столько, сколько фаз бежало. Превью и секция archive живут только
  // здесь: инспектору они не едут, и проверить их больше негде.
  const records = docker(["logs", `${tag}-agent`]).stdout
    .split("\n").filter((l) => l.startsWith("REC "))
    .map((l) => {
      try {
        return JSON.parse(l.slice(4));
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  check("аудит: записи доходят", records.length > 0, true);

  // Запись целиком -- глазами: WAF_DUMP=1 печатает её вместо разбора по полям.
  if (process.env.WAF_DUMP) {
    for (const rec of records) {
      console.log(JSON.stringify(rec, null, 2));
    }
  }

  // --- глаголы записи: журнал и архив по просьбе соседа ---------------------
  //
  // На /audit-on/ сэмпл нулевой и waf_archive нет: запись и секция archive
  // существуют только потому, что попросил auditor. Разрешения на это не
  // требуется -- просить вправе любой спрошенный инспектор.
  const auditOn = records.find((rec) => /\/audit-on\/index\.html$/.test(rec.http?.uri ?? ""));

  check("запись по просьбе: запись есть при waf_audit_sample 0", Boolean(auditOn), true);

  if (auditOn) {
    const acts = auditOn.actions ?? [];
    check("запись по просьбе: действие audit в записи",
      acts.some((a) => a.do === "audit" && a.set === "on" && a.to === undefined), true);
    check("запись по просьбе: действие archive с параметрами",
      acts.some((a) => a.do === "archive" && a.set === "on" && a.ttl === 123
        && a.headers?.source === "original" && a.body === undefined), true);
    check("архив по просьбе: срок с провода", auditOn.store?.archive?.headers?.ttl, 123);
    check("запись по просьбе: превью заголовков без waf_preview на маршруте",
      Array.isArray(auditOn.headers_preview) && auditOn.headers_preview.length > 0, true);
    check("запись по просьбе: действие audit несёт предел и источник объекта",
      acts.some((a) => a.do === "audit" && a.headers?.limit === 4096
        && a.headers?.source === "original"), true);
    check("архив по просьбе: только названные объекты", auditOn.store?.archive?.args, undefined);
    check("архив по просьбе: локатор заголовков адресный",
      Boolean(auditOn.store?.headers?.key), true);
    check("запись по просьбе: вердикт allow", auditOn.verdict, "allow");
    // Просьба про ответ там, где фазы ответа нет, ушла в пустоту: запись
    // запроса её не подобрала.
    check("запись по просьбе: превью тела в записи запроса нет", auditOn.body_preview, undefined);
    check("архив по просьбе: тело в архив запроса не попало", auditOn.store?.archive?.body, undefined);
  }

  // --- обе записи с фазы запроса (apply request + apply response) ----------
  //
  // На /audit-rsp/ сэмпл нулевой: обе записи есть только по просьбе auditor.
  // У каждой своё переопределение: срок архива заголовков запроса -- 123,
  // тела ответа -- 321, и они не перепутаны.
  const rspRecs = records.filter((rec) => /\/audit-rsp\/index\.html$/.test(rec.http?.uri ?? ""));
  const bothReq = rspRecs.find((rec) => rec.phase === "request");
  const bothRsp = rspRecs.find((rec) => rec.phase === "response");

  check("обе записи с фазы запроса: запись запроса есть", Boolean(bothReq), true);
  check("обе записи с фазы запроса: запись ответа есть", Boolean(bothRsp), true);

  if (bothReq) {
    check("обе записи с фазы запроса: срок архива заголовков запроса свой",
      bothReq.store?.archive?.headers?.ttl, 123);
    check("обе записи с фазы запроса: тело в архив запроса не попало",
      bothReq.store?.archive?.body, undefined);
  }

  if (bothRsp) {
    const acts = bothRsp.actions ?? [];
    check("обе записи с фазы запроса: срок архива тела ответа с провода",
      bothRsp.store?.archive?.body?.ttl, 321);
    check("обе записи с фазы запроса: заголовки ответа в архив не названы",
      bothRsp.store?.archive?.headers, undefined);
    check("обе записи с фазы запроса: превью заголовков ответа без waf_preview",
      Array.isArray(bothRsp.headers_preview) && bothRsp.headers_preview.length > 0, true);
    check("обе записи с фазы запроса: действие с осью response в записи ответа",
      acts.some((a) => a.do === "archive" && a.apply === "response" && a.ttl === 321), true);
    check("обе записи с фазы запроса: обе записи об одном запросе", bothRsp.ray, bothReq?.ray);
  }

  // --- обе записи с фазы ответа ----------------------------------------------
  //
  // На /audit-rsp-late/ просит только rsp_auditor с фазы ответа. Запись
  // запроса на маршруте с грантом ждёт исхода -- и слышит его просьбу.
  const lateRecs = records.filter((rec) => /\/audit-rsp-late\/index\.html$/.test(rec.http?.uri ?? ""));
  const lateReq = lateRecs.find((rec) => rec.phase === "request");
  const lateRsp = lateRecs.find((rec) => rec.phase === "response");

  check("обе записи с фазы ответа: запись запроса есть", Boolean(lateReq), true);
  check("обе записи с фазы ответа: запись ответа есть", Boolean(lateRsp), true);

  if (lateReq) {
    check("обе записи с фазы ответа: срок архива заголовков запроса с провода",
      lateReq.store?.archive?.headers?.ttl, 222);
    check("обе записи с фазы ответа: тело в архив запроса не попало",
      lateReq.store?.archive?.body, undefined);
  }

  if (lateRsp) {
    check("обе записи с фазы ответа: срок архива тела ответа с провода",
      lateRsp.store?.archive?.body?.ttl, 333);
    check("обе записи с фазы ответа: превью заголовков ответа без waf_preview",
      Array.isArray(lateRsp.headers_preview) && lateRsp.headers_preview.length > 0, true);
  }

  // --- журнал без инспекторов -------------------------------------------------
  //
  // /journal-req/ и /journal-rsp/ никого не спрашивают, а записи и архив есть:
  // превью заголовков, строки и тела у запроса, заголовков и тела у ответа.
  // Объекты лежат в обменнике под rid, а не под прочерками, и маска снимка на
  // заголовках действует и в превью, и в обменнике.
  const jReq = records.find((rec) => rec.phase === "request"
    && /\/journal-req\/$/.test(rec.http?.uri ?? ""));
  const jRsp = records.find((rec) => rec.phase === "response"
    && /\/journal-rsp\/$/.test(rec.http?.uri ?? ""));

  check("журнал запроса: запись есть", Boolean(jReq), true);
  check("журнал ответа: запись фазы ответа есть", Boolean(jRsp), true);

  if (jReq) {
    check("журнал запроса: в составе только модуль",
      Object.keys(jReq.inspectors ?? {}).join(","), "module");
    check("журнал запроса: превью тела", /journal-body-payload/.test(jReq.body_preview ?? ""), true);
    check("журнал запроса: превью строки",
      JSON.stringify(jReq.args_preview ?? []).includes("journal"), true);
    check("журнал запроса: секрет в превью замаскирован",
      JSON.stringify(jReq.headers_preview ?? []).includes("s3cr3t-journal"), false);
    check("журнал запроса: архив заголовков, строки и тела",
      [jReq.store?.archive?.headers?.ttl, jReq.store?.archive?.args?.ttl,
        jReq.store?.archive?.body?.ttl].join(","), "3600,3600,3600");
    check("журнал запроса: ключ под rid, не под прочерками",
      /^bus:[0-9a-f]+:req:hdr$/.test(jReq.store?.headers?.key ?? ""), true);

    const hdrKept = docker([
      "exec", `${tag}-redis`, "redis-cli", "GET", jReq.store?.headers?.key ?? "none",
    ]).stdout;
    check("журнал запроса: заголовки лежат в обменнике", /x-journal-secret/i.test(hdrKept), true);
    check("журнал запроса: в обменнике секрет -- sha256, не значение",
      hdrKept.includes("s3cr3t-journal"), false);

    const bodyKept = docker([
      "exec", `${tag}-redis`, "redis-cli", "GET", jReq.store?.body?.key ?? "none",
    ]).stdout;
    check("журнал запроса: тело лежит в обменнике", bodyKept.includes("journal-body-payload"), true);
  }

  if (jRsp) {
    check("журнал ответа: в составе только модуль",
      Object.keys(jRsp.inspectors ?? {}).join(","), "module");
    check("журнал ответа: код приложения", jRsp.http?.upstream_status, 200);
    check("журнал ответа: превью заголовков ответа",
      JSON.stringify(jRsp.headers_preview ?? []).toLowerCase().includes("content-type"), true);
    check("журнал ответа: превью тела -- ответ, а не запрос",
      /WAF-CANARY-0badc0de/.test(jRsp.body_preview ?? ""), true);
    check("журнал ответа: архив заголовков и тела",
      [jRsp.store?.archive?.headers?.ttl, jRsp.store?.archive?.body?.ttl].join(","), "3600,3600");

    const rspKept = docker([
      "exec", `${tag}-redis`, "redis-cli", "GET", jRsp.store?.body?.key ?? "none",
    ]).stdout;
    check("журнал ответа: тело ответа лежит в обменнике", rspKept.includes("WAF-CANARY-0badc0de"), true);
  }

  // Отказ локального слоя без инспекторов: запись с исходом deny, и when=deny
  // у архива выпадает -- заголовки и тело отказанного запроса остаются агенту.
  const jDeny = records.find((rec) => rec.phase === "request"
    && /\/journal-deny\/$/.test(rec.http?.uri ?? ""));

  check("журнал отказа: запись с исходом deny", jDeny?.verdict, "deny");

  if (jDeny) {
    check("журнал отказа: архив заголовков и тела when=deny",
      [jDeny.store?.archive?.headers?.ttl, jDeny.store?.archive?.body?.ttl].join(","), "3600,3600");
    check("журнал отказа: превью тела отказанного запроса",
      /journal-deny-payload/.test(jDeny.body_preview ?? ""), true);

    const denyKept = docker([
      "exec", `${tag}-redis`, "redis-cli", "GET", jDeny.store?.body?.key ?? "none",
    ]).stdout;
    check("журнал отказа: тело лежит в обменнике", denyKept.includes("journal-deny-payload"), true);
  }

  const leakRecords = records.filter((rec) => /rsp-leak\/$/.test(rec.http?.uri ?? ""));
  const auditRsp = leakRecords.find((rec) => rec.phase === "response");
  const auditReq = leakRecords.find((rec) => rec.phase === "request");

  check("аудит: запись фазы запроса", Boolean(auditReq), true);
  check("аудит: запись фазы ответа", Boolean(auditRsp), true);

  if (auditReq && auditRsp) {
    check("аудит: обе записи об одном запросе", auditReq.ray, auditRsp.ray);
  }

  if (auditRsp) {
    check("аудит: превью заголовков ответа",
      JSON.stringify(auditRsp.headers_preview ?? []).toLowerCase()
        .includes("content-type"), true);
    check("аудит: превью тела ответа",
      /SQL syntax/.test(auditRsp.body_preview ?? ""), true);
    // Секция archive живёт внутри store: это разметка на локаторах, а не
    // отдельный список.
    check("аудит: секция archive у фазы ответа",
      Boolean(auditRsp.store?.archive?.headers
              || auditRsp.store?.archive?.body), true);
    check("аудит: вердикт фазы ответа", auditRsp.verdict, "deny");

    /*
     * Код приложения отдельно от нашего. Приложение ответило 200, клиент
     * получил 418 -- и в записи видно оба, иначе "мы закрыли успешный ответ"
     * не отличить от "приложение упало".
     */
    check("аудит: код приложения в записи", auditRsp.http.upstream_status, 200);
    check("аудит: код клиенту -- наш", auditRsp.http.status, 418);
    check("аудит: у фазы запроса кода приложения нет",
      auditReq?.http.upstream_status, undefined);

    // Раздел http описывает ту фазу, о которой запись: заголовки ответа, а не
    // запроса. У запроса их три коротких, у ответа -- Content-Type, длина и
    // отладочный, то есть заметно больше.
    check("аудит: размер заголовков ответа",
      auditRsp.http.headers_size > (auditReq?.http.headers_size ?? 0), true);
    check("аудит: тип содержимого ответа",
      auditRsp.http.content_type, "text/html");

    /*
     * Архивированные объекты живут retain_ttl обменника (5m), а не его ttl (30s):
     * ключ уехал агенту, и умереть до того, как тот придёт, ему нельзя.
     */
    const now = Date.now() / 1000;

    check("аудит: заголовки ответа держатся дольше ttl",
      auditRsp.store.headers.expires_at - now > 60, true);
    check("аудит: тело ответа держится дольше ttl",
      auditRsp.store.body.expires_at - now > 60, true);
  }

  const logs = docker(["logs", `${tag}-nginx`]).stdout
    + docker(["logs", `${tag}-nginx`]).stderr;

  check("лог: запись фазы ответа",
    /waf: allow phase response/.test(logs), true);
  check("лог: отказ фазы ответа",
    /waf: deny phase response/.test(logs), true);

  for (const bad of ["[alert]", "[emerg]", "segfault"]) {
    if (logs.includes(bad)) {
      console.error(`FAIL в логе ${bad}`);
      console.error(logs.split("\n").filter((l) => l.includes(bad)).join("\n"));
      failed += 1;
    }
  }

  check("лог: отказ по вердикту записан",
    /waf: deny phase request/.test(logs), true);
} finally {
  down();
}

console.log(failed === 0 ? "\nпрогон шины пройден" : `\nнеудач: ${failed}`);
process.exit(failed === 0 ? 0 : 1);
