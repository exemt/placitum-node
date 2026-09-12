# Прогон целиком: поднять стенд, снять состояние до, нагрузить, снять после,
# сложить артефакты в results/<RUN_ID>.
#
#     ./scripts/run.ps1 -Scenario smoke
#     ./scripts/run.ps1 -Scenario steady -Rate 5000 -Duration 5m -Edges 3 -Obs
#     ./scripts/run.ps1 -Scenario ceiling -Through direct
#
# Стенд после прогона остаётся поднятым: разбирать результат почти всегда
# приходится по живому стенду. Убрать -- ключом -Down либо
# docker compose -f compose.load.yml down -v.

[CmdletBinding()]
param(
    [ValidateSet('smoke', 'steady', 'ramp', 'ceiling', 'soak')]
    [string]$Scenario = 'smoke',

    [int]$Rate = 2000,
    [string]$Duration = '2m',
    [string]$Warmup = '30s',

    [int]$Edges = 1,
    [int]$Inspectors = 1,
    [int]$EdgeWorkers = 4,

    # lb -- через балансировщик, direct -- мимо него. Разница между профилями
    # при прочих равных и есть цена балансировщика.
    [ValidateSet('lb', 'direct')]
    [string]$Through = 'lb',

    [ValidateSet('mixed', 'large')]
    [string]$BodyProfile = 'mixed',

    [string]$Deadline = '200ms',
    [ValidateSet('deny', 'pass')]
    [string]$OnTimeout = 'deny',
    [int]$MaxInflight = 4096,

    # Доли трафика. Значения по умолчанию заданы в .env.example; здесь только
    # то, что чаще всего меняют от прогона к прогону.
    [double]$ControlRatio = 0.10,
    [double]$AttackRatio = 0.05,
    [double]$ScoreRatio = 0.05,
    # Доля вердиктов redirect, то есть челленджей. Отдельным ключом, а не долей
    # счёта: из счёта редирект не следует, его присылает инспектор.
    [double]$RedirectRatio = 0.01,
    [double]$SlowRatio = 0.02,
    [double]$TimeoutRatio = 0,
    [double]$SilentRatio = 0,
    [double]$AbortRatio = 0,
    # Доля запросов на маршрут /debug/, где модуль отдаёт X-WAF-Debug. Только
    # с них снимается латентность инспектора, поэтому нулём её ставят лишь в
    # прогонах на потолок.
    [double]$DebugRatio = 0.01,

    # Задержки инспектора для медленных запросов: одна заведомо внутри
    # дедлайна, другая заведомо за ним. Генератор по ним же вычисляет
    # ожидаемый код ответа.
    [int]$SlowDelayOk = 50,
    [int]$SlowDelayTimeout = 400,

    [int]$Seed = 20260813,
    [int]$CorpusSize = 20000,

    [switch]$Obs,
    [switch]$Pin,
    [switch]$NoBuild,
    [switch]$Down
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

# Два сценария задают интенсивность и длительность сами, и заданные ключами
# значения к ним не применяются. Приводим их здесь, иначе манифест запишет
# запрошенное вместо фактического, и прогон нельзя будет ни повторить, ни
# сопоставить с графиками.
switch ($Scenario) {
    'smoke' {
        $Rate = 50
        $Duration = '60s'
    }
    'soak' {
        $Duration = '{0}s' -f [int][math]::Ceiling(10000000 / $Rate)
    }
}

$runId = '{0}-{1}' -f $Scenario, (Get-Date -Format 'yyyyMMdd-HHmmss')
$resultsDir = Join-Path $root "results/$runId"
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

Write-Host "прогон $runId" -ForegroundColor Green
Write-Host "артефакты: $resultsDir"

# --- окружение для compose --------------------------------------------------
#
# compose подставляет ${...} из окружения процесса, поэтому все параметры
# прогона выставляются здесь, а не передаются флагами.

$env:RUN_ID = $runId
$env:SCENARIO = $Scenario
$env:RATE = $Rate
$env:DURATION = $Duration
$env:WARMUP = $Warmup
$env:TARGET = if ($Through -eq 'lb') { 'http://haproxy:8080' } else { 'http://edge:8080' }

$env:EDGE_WORKERS = $EdgeWorkers
$env:BODY_PROFILE = $BodyProfile

$env:WAF_DEADLINE = $Deadline
$env:WAF_INSPECTOR_TIMEOUT = $Deadline
$env:WAF_ON_TIMEOUT = $OnTimeout
$env:WAF_MAX_INFLIGHT = $MaxInflight

# Генератору дедлайн нужен числом: по нему он вычисляет, каким должен быть код
# ответа у запроса с заданной задержкой инспектора.
$env:WAF_DEADLINE_MS = [int](($Deadline -replace '[^\d]', ''))
if ($Deadline -match 's$' -and $Deadline -notmatch 'ms$') {
    $env:WAF_DEADLINE_MS = [int]($env:WAF_DEADLINE_MS) * 1000
}

# Инвариантная культура обязательна. PowerShell форматирует [double] по
# текущей локали, и на русской системе 0.05 уходит в окружение как "0,05".
# JavaScript читает такую строку как NaN, любое сравнение с NaN ложно, и доля
# трафика молча превращается в ноль: прогон проходит, отчёт выглядит здоровым,
# а ветки трафика в нём просто нет. Генератор такое значение теперь отвергает
# (k6/lib/env.js), но чинить надо здесь.
function Num {
    param([double]$Value)
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

$env:CONTROL_RATIO = Num $ControlRatio
$env:ATTACK_RATIO = Num $AttackRatio
$env:SCORE_RATIO = Num $ScoreRatio
$env:REDIRECT_RATIO = Num $RedirectRatio
$env:SLOW_RATIO = Num $SlowRatio
$env:TIMEOUT_RATIO = Num $TimeoutRatio
$env:SILENT_RATIO = Num $SilentRatio
$env:ABORT_RATIO = Num $AbortRatio
$env:DEBUG_RATIO = Num $DebugRatio

$env:SLOW_DELAY_OK = $SlowDelayOk
$env:SLOW_DELAY_TIMEOUT = $SlowDelayTimeout

$env:CORPUS_SEED = $Seed
$env:CORPUS_SIZE = $CorpusSize

$composeArgs = @('-f', 'compose.load.yml')
if ($Pin) { $composeArgs += @('-f', 'compose.pin.yml') }
if ($Obs) {
    $composeArgs += @('--profile', 'obs')
    $env:K6_PROMETHEUS_RW_SERVER_URL = 'http://prometheus:9090/api/v1/write'
} else {
    $env:K6_PROMETHEUS_RW_SERVER_URL = ''
}

# --- подъём -----------------------------------------------------------------

if (-not $NoBuild) {
    Write-Host "сборка образов..." -ForegroundColor DarkGray
    & docker compose @composeArgs build
    if ($LASTEXITCODE -ne 0) { throw "сборка не удалась" }
}

Write-Host "подъём стенда: edge=$Edges inspector=$Inspectors" -ForegroundColor DarkGray
& docker compose @composeArgs up -d --wait --remove-orphans `
    --scale edge=$Edges --scale inspector=$Inspectors
if ($LASTEXITCODE -ne 0) { throw "стенд не поднялся" }

# --- манифест ---------------------------------------------------------------
#
# Пишется до нагрузки: прогон, упавший на середине, тоже нужно уметь
# воспроизвести. Без версии модуля и зерна корпуса результат не сравним ни с
# чем, а значит бесполезен.

$manifest = [ordered]@{
    run_id      = $runId
    started_at  = (Get-Date).ToUniversalTime().ToString('o')
    scenario    = $Scenario
    generator   = 'k6'
    target      = $env:TARGET
    through     = $Through
    topology    = [ordered]@{
        edges        = $Edges
        edge_workers = $EdgeWorkers
        inspectors   = $Inspectors
        pinned       = [bool]$Pin
    }
    load        = [ordered]@{
        rate     = $Rate
        duration = $Duration
        warmup   = $Warmup
    }
    waf         = [ordered]@{
        deadline          = $Deadline
        inspector_timeout = $Deadline
        on_timeout        = $OnTimeout
        max_inflight      = $MaxInflight
        score_deny        = 100
    }
    traffic     = [ordered]@{
        body_profile  = $BodyProfile
        corpus_seed   = $Seed
        corpus_size   = $CorpusSize
        control_ratio = $ControlRatio
        attack_ratio   = $AttackRatio
        score_ratio    = $ScoreRatio
        redirect_ratio = $RedirectRatio
        slow_ratio    = $SlowRatio
        timeout_ratio = $TimeoutRatio
        silent_ratio  = $SilentRatio
        abort_ratio   = $AbortRatio
        debug_ratio   = $DebugRatio
        slow_delay_ok      = $SlowDelayOk
        slow_delay_timeout = $SlowDelayTimeout
    }
    host        = [ordered]@{
        os        = [System.Environment]::OSVersion.VersionString
        cpu_count = [System.Environment]::ProcessorCount
    }
}

try {
    $manifest.git = [ordered]@{
        commit = (& git rev-parse HEAD 2>$null)
        dirty  = [bool](& git status --porcelain 2>$null)
    }
} catch {
    $manifest.git = @{ commit = 'unknown' }
}

try {
    $manifest.images = (& docker compose @composeArgs images --format json 2>$null | Out-String).Trim()
} catch { }

$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -Path (Join-Path $resultsDir 'manifest.json') -Encoding utf8

# --- прогон -----------------------------------------------------------------

# Снимок обёрнут: он полезен, но прогон без него всё равно состоится, а вот
# прогон, упавший на сборе диагностики, не состоится вовсе.
function Snapshot {
    param([string]$Label)

    try {
        & (Join-Path $PSScriptRoot 'inside.ps1') -Out $resultsDir -Label $Label -Pin:$Pin
    } catch {
        Write-Host "снимок '$Label' снять не удалось: $_" -ForegroundColor Yellow
    }
}

Write-Host "снимок состояния до нагрузки" -ForegroundColor DarkGray
Snapshot 'before'

$statsJob = Start-Job -FilePath (Join-Path $PSScriptRoot 'stats.ps1') `
    -ArgumentList (Join-Path $resultsDir 'stats.csv'), 5

try {
    $k6Args = @('run')
    if ($Obs) { $k6Args += @('--out', 'experimental-prometheus-rw') }
    $k6Args += '/scripts/main.js'

    Write-Host ""
    Write-Host "нагрузка: $Scenario, цель $($env:TARGET)" -ForegroundColor Green
    Write-Host ""

    & docker compose @composeArgs run --rm k6 @k6Args
    $k6Exit = $LASTEXITCODE

} finally {
    Stop-Job $statsJob -ErrorAction SilentlyContinue
    Remove-Job $statsJob -Force -ErrorAction SilentlyContinue
}

Write-Host "снимок состояния после нагрузки" -ForegroundColor DarkGray
Snapshot 'after'

# --- итог -------------------------------------------------------------------

$manifest.finished_at = (Get-Date).ToUniversalTime().ToString('o')
$manifest.k6_exit = $k6Exit
$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -Path (Join-Path $resultsDir 'manifest.json') -Encoding utf8

Write-Host ""
if ($k6Exit -eq 0) {
    Write-Host "прогон завершён, пороги пройдены" -ForegroundColor Green
} else {
    # k6 возвращает 99, когда прогон отработал, но порог не выполнен: это
    # результат теста, а не поломка запуска, и различать их обязательно.
    Write-Host "прогон завершён с кодом $k6Exit (99 -- провален порог)" -ForegroundColor Yellow
}
Write-Host "артефакты: $resultsDir"

if ($Obs) {
    $grafanaPort = if ($env:PORT_GRAFANA) { $env:PORT_GRAFANA } else { '13000' }
    Write-Host "grafana: http://localhost:$grafanaPort/d/waf-load"
}
$statsPort = if ($env:PORT_LB_STATS) { $env:PORT_LB_STATS } else { '18404' }
Write-Host "haproxy: http://localhost:$statsPort/"

if ($Down) {
    & docker compose @composeArgs down -v
}

exit $k6Exit
