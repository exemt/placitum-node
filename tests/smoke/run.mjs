/**
 * Дымовой прогон: живой nginx с модулем, без шины и без обменника.
 *
 * nginx -t (nginx/tests/unit) проверяет разбор конфигурации и не создаёт ни
 * одного контекста запроса. Всё, что живёт в горячем пути -- жизненный цикл
 * ctx, локальный слой, вердикт, строка лога, -- виден только на трафике, и
 * этот прогон закрывает самый дешёвый его срез: один контейнер, свой порт,
 * ничего общего с чужими стендами.
 *
 *     node nginx/tests/smoke/run.mjs
 */

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const image = process.env.WAF_NGINX_IMAGE ?? "waf-nginx";
const name = `waf-smoke-${process.pid}`;

function docker(args, opts = {}) {
  return spawnSync("docker", args, { encoding: "utf8", ...opts });
}

function dockerPath(p) {
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

function start() {
  const run = docker([
    "run", "-d", "--rm", "--name", name,
    "-p", "127.0.0.1:0:8080",
    "-v", `${dockerPath(here)}:/t:ro`,
    "--entrypoint", "nginx",
    image, "-c", "/t/smoke.conf", "-g", "daemon off;",
  ]);

  if (run.status !== 0) {
    console.error(run.stderr || run.stdout);
    process.exit(1);
  }

  const port = docker(["port", name, "8080/tcp"]).stdout.trim().split(":").pop();

  if (!port) {
    console.error("не удалось узнать порт контейнера");
    stop();
    process.exit(1);
  }

  return `http://127.0.0.1:${port}`;
}

function stop() {
  docker(["stop", "-t", "1", name]);
}

// Ответ приходит из самого контейнера: так прогон не зависит от того, есть ли
// curl на машине и как у неё с сетью до опубликованного порта.
function request(path, args = []) {
  const r = docker([
    "exec", name, "curl", "-s", "-i", "-o", "-", "-m", "5",
    ...args, `http://127.0.0.1:8080${path}`,
  ]);

  return r.stdout ?? "";
}

function status(raw) {
  const m = /^HTTP\/[\d.]+ (\d{3})/.exec(raw);
  return m ? Number(m[1]) : 0;
}

function header(raw, name) {
  const m = new RegExp(`^${name}:\\s*(.+)$`, "im").exec(raw);
  return m ? m[1].trim() : "";
}

function ready(base) {
  for (let i = 0; i < 50; i++) {
    if (status(request("/static/index.html")) !== 0) {
      return true;
    }

    spawnSync("docker", ["exec", name, "sleep", "0.1"]);
  }

  return false;
}

const base = start();

try {
  if (!ready(base)) {
    console.error("nginx не поднялся");
    console.error(docker(["logs", name]).stdout);
    process.exit(1);
  }

  // Обычный запрос: волн нет, вердикт allow, контекст доживает до лога.
  const plain = request("/index.html");
  check("allow: статус", status(plain), 200);
  check("allow: диагностика вердикта",
    /v=allow/.test(header(plain, "X-WAF-Debug")), true);

  // Локальный слой: правило по значению переменной, отказ страницей каталога.
  const denied = request("/index.html", ["-A", "sqlmap/1.0"]);
  check("local block: статус", status(denied), 403);
  check("local block: диагностика", /v=deny/i.test(header(denied, "X-WAF-Debug")),
    true);

  // allow локального слоя выше block: тот же UA проходит.
  check("local allow: статус",
    status(request("/allowlisted/index.html", ["-A", "sqlmap/1.0"])), 200);

  // Снимок выключен целиком: маршрут обязан оставаться рабочим.
  check("capture none: статус", status(request("/static/index.html")), 200);

  // Повторные запросы в одном соединении: слот и контекст переиспользуются.
  for (let i = 0; i < 20; i++) {
    if (status(request("/index.html")) !== 200) {
      check(`повтор ${i}`, false, true);
      break;
    }
  }

  const logs = docker(["logs", name]).stdout + docker(["logs", name]).stderr;

  for (const bad of ["[emerg]", "[alert]", "segfault", "panic", "assertion"]) {
    if (logs.includes(bad)) {
      console.error(`FAIL в логе ${bad}`);
      console.error(logs.split("\n").filter((l) => l.includes(bad)).join("\n"));
      failed += 1;
    }
  }

  // Строка итога пишется на фазу, и на живом трафике она обязана быть у
  // каждого исхода: без неё запрос не найти ни в логе, ни в аудите.
  check("лог: вердикт allow", /waf: allow phase request/.test(logs), true);
  check("лог: вердикт deny", /waf: deny phase request/.test(logs), true);
  check("лог: сработало правило локального слоя",
    /local block by dataset "badua"/.test(logs), true);

  // ray у каждого запроса свой: он единственный ключ склейки с аудитом.
  const rays = new Set(logs.match(/ray [0-9a-f-]{36}/g) ?? []);

  check("лог: ray уникален на запрос", rays.size >= 3, true);
} finally {
  stop();
}

console.log(failed === 0 ? "\nдымовой прогон пройден" : `\nнеудач: ${failed}`);
process.exit(failed === 0 ? 0 : 1);
