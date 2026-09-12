/**
 * nginx -t на все unit confs и на examples/*.conf
 * Ожидание: «ЗАВЕРШИТЬСЯ НЕУДАЧЕЙ» в файле → -t падает, иначе проходит.
 */

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const unitDir = join(root, "nginx", "tests", "unit");
const examplesDir = join(root, "docs", "directives", "examples");

function dockerPath(p) {
  return p.replace(/\\/g, "/");
}
const image = process.env.WAF_NGINX_IMAGE ?? "waf-nginx";

function mustFail(text) {
  return text.includes("ЗАВЕРШИТЬСЯ НЕУДАЧЕЙ");
}

function nginxT(hostDir, file, hosts = []) {
  const args = ["run", "--rm", "--entrypoint", "nginx", "-v", `${dockerPath(hostDir)}:/t:ro`];
  for (const h of hosts) {
    args.push("--add-host", `${h}:127.0.0.1`);
  }
  args.push(image, "-t", "-c", `/t/${file}`);
  return spawnSync("docker", args, { encoding: "utf8" });
}

function check(label, hostDir, file, fail, hosts) {
  const r = nginxT(hostDir, file, hosts);
  const ok = r.status === 0;
  const pass = fail ? !ok : ok;
  if (!pass) {
    console.error(`FAIL ${label}${fail ? " (expected -t fail)" : ""}`);
    if (r.stdout) process.stderr.write(r.stdout);
    if (r.stderr) process.stderr.write(r.stderr);
    return 1;
  }
  console.log(`ok   ${label}`);
  return 0;
}

let failed = 0;

for (const file of readdirSync(unitDir).filter((n) => n.endsWith(".conf")).sort()) {
  const text = readFileSync(join(unitDir, file), "utf8");
  failed += check(file, unitDir, file, mustFail(text));
}

const exampleHosts = ["nats-1", "nats-2", "nats-3", "nats", "redis", "redis-internal", "app", "api"];
for (const file of ["1-api.conf", "2-routes.conf", "3-local.conf"]) {
  failed += check(`examples/${file}`, examplesDir, file, false, exampleHosts);
}

process.exit(failed === 0 ? 0 : 1);
