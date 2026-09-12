# Снимок внутреннего состояния стенда.
#
# У модуля своих метрик пока нет (waf_status -- этап 13), поэтому внутреннее
# состояние собирается из того, что отдают соседи: соединения nginx, таблица
# состояний балансировщика, счётчики шины и подписки на ней. Что именно из
# этого чем является -- в observability.md.
#
#     ./scripts/inside.ps1                       # в консоль
#     ./scripts/inside.ps1 -Out results/x -Label after
#
# Снимок безопасно снимать под нагрузкой: все источники -- это чтение уже
# посчитанных значений, дополнительной работы они не создают.

[CmdletBinding()]
param(
    [string]$Out,
    [string]$Label = 'snapshot',
    [switch]$Pin
)

# Continue, а не Stop: снимок состояния -- вспомогательное действие, и его
# частичный отказ (недоступный контейнер, перезапустившийся демон) не должен
# ронять прогон, ради которого он снимается.
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')

$composeArgs = @('-f', 'compose.load.yml')
if ($Pin) { $composeArgs += @('-f', 'compose.pin.yml') }

# Параметр называется CommandArgs, а не Args: $Args -- автоматическая
# переменная PowerShell, и объявление параметра с таким именем не переопределяет
# её, а тихо ломает вызов.
function Invoke-Compose {
    param([string[]]$CommandArgs)
    & docker compose @composeArgs @CommandArgs 2>&1
}

function Emit {
    param([string]$Name, [string[]]$Lines)

    if ($Out) {
        $dir = Join-Path $Out $Label
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $Lines | Set-Content -Path (Join-Path $dir "$Name.txt") -Encoding utf8
    } else {
        Write-Host ""
        Write-Host "=== $Name " -NoNewline -ForegroundColor Cyan
        Write-Host ('=' * [Math]::Max(1, 56 - $Name.Length)) -ForegroundColor Cyan
        $Lines | ForEach-Object { Write-Host $_ }
    }
}

# --- nginx: соединения и запросы по каждому узлу ---------------------------
#
# stub_status -- единственный источник, который показывает, сколько соединений
# узел держит прямо сейчас и сколько из них ждут. Ожидание вердикта выглядит
# здесь как рост reading/writing при неизменном числе запросов в секунду.

$edgeIds = (Invoke-Compose @('ps', '-q', 'edge')) | Where-Object { $_ -match '^[0-9a-f]{12,}$' }

$lines = @()
$n = 0
foreach ($id in $edgeIds) {
    $n++
    $name = (& docker inspect -f '{{.Name}}' $id).TrimStart('/')
    $lines += "--- $name"
    $lines += (& docker exec $id curl -s --max-time 3 http://127.0.0.1:8080/nginx_status 2>&1)
    $lines += ""
}
if ($n -eq 0) { $lines = @('узлы edge не запущены') }
Emit -Name 'nginx-stub-status' -Lines $lines

# --- haproxy: таблица состояний -------------------------------------------
#
# CSV страницы статистики: по каждому узлу текущие и максимальные сессии,
# очередь, коды ответов, состояние проверки здоровья. В строке под полторы
# сотни колонок, поэтому нужные выбираются по именам из заголовка, а не по
# номерам: набор колонок зависит от версии HAProxy.
#
# Запрос идёт curl'ом из контейнера edge, а не wget'ом из самого haproxy:
# busybox wget не сохраняет суффикс ;csv в пути и получает HTML-страницу.

$want = @('pxname', 'svname', 'status', 'scur', 'smax', 'slim', 'qcur', 'rate',
          'hrsp_2xx', 'hrsp_3xx', 'hrsp_4xx', 'hrsp_5xx', 'econ', 'eresp',
          'ctime', 'rtime', 'ttime')

$lines = @()
if ($edgeIds) {
    $csv = & docker exec ($edgeIds | Select-Object -First 1) `
        curl -s --max-time 3 'http://haproxy:8404/;csv' 2>&1

    $map = @{}
    foreach ($row in $csv) {
        $f = $row -split ','

        if ($row -like '# pxname*') {
            for ($i = 0; $i -lt $f.Count; $i++) {
                $map[($f[$i] -replace '^#\s*', '')] = $i
            }
            $lines += ($want -join ',')
            continue
        }

        if ($map.Count -eq 0 -or $f.Count -lt $map.Count) { continue }
        $lines += (($want | ForEach-Object { $f[$map[$_]] }) -join ',')
    }
}
if (-not $lines) { $lines = @('статистика haproxy недоступна') }
Emit -Name 'haproxy-stat' -Lines $lines

# --- NATS -------------------------------------------------------------------
#
# varz: сообщения, байты, медленные потребители. Ненулевые slow_consumers
# означают, что очередь не разбирает инспектор, и задержка вердикта в этот
# момент к модулю отношения не имеет.

foreach ($endpoint in @('varz', 'connz', 'subsz')) {
    $body = Invoke-Compose @('exec', '-T', 'nats', 'wget', '-qO-', "http://127.0.0.1:8222/$endpoint")
    Emit -Name "nats-$endpoint" -Lines $body
}

# --- ресурсы ----------------------------------------------------------------

$stats = & docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' 2>&1 |
    Where-Object { $_ -match 'wafload' }
Emit -Name 'docker-stats' -Lines $stats

# --- диагностика модуля -----------------------------------------------------
#
# На уровне warn сюда попадают исчерпание таблицы слотов, ошибки шины и разбор
# ответов инспектора. Пусто -- это нормальный результат.

$logs = Invoke-Compose @('logs', '--tail', '200', '--no-color', 'edge')
Emit -Name 'edge-log' -Lines $logs

$logs = Invoke-Compose @('logs', '--tail', '100', '--no-color', 'inspector')
Emit -Name 'inspector-log' -Lines $logs

if ($Out) {
    Write-Host "снимок '$Label' записан в $(Join-Path $Out $Label)"
}
