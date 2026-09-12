# Выборка CPU и памяти по контейнерам в CSV на всё время прогона.
#
# Дублирует cAdvisor намеренно: на Docker Desktop он поднимается не всегда, а
# критерий сценария soak -- «RSS не растёт» -- нужен независимо от того,
# заработал ли стек наблюдения. Ряд получается редкий (шаг в секундах), но для
# тренда памяти этого достаточно.
#
# Запускается фоном из run.ps1; отдельно нужен, только если стенд поднят руками.
#
#     ./scripts/stats.ps1 -Path results/x/stats.csv -IntervalSec 5

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [int]$IntervalSec = 5,
    [string]$Filter = 'wafload'
)

$ErrorActionPreference = 'Continue'

'ts,name,cpu_percent,mem_bytes,mem_percent,net_rx_bytes,net_tx_bytes,pids' |
    Set-Content -Path $Path -Encoding utf8

function ToBytes {
    param([string]$Text)

    if ($Text -notmatch '^([0-9.]+)\s*([KMGT]?i?B)$') { return 0 }

    $value = [double]$Matches[1]
    switch ($Matches[2]) {
        'B'   { return [long]$value }
        'KB'  { return [long]($value * 1000) }
        'KiB' { return [long]($value * 1024) }
        'MB'  { return [long]($value * 1000000) }
        'MiB' { return [long]($value * 1048576) }
        'GB'  { return [long]($value * 1000000000) }
        'GiB' { return [long]($value * 1073741824) }
        default { return [long]$value }
    }
}

while ($true) {
    $ts = (Get-Date).ToUniversalTime().ToString('o')

    $rows = & docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.PIDs}}' 2>$null

    foreach ($row in $rows) {
        if ($row -notmatch [regex]::Escape($Filter)) { continue }

        $f = $row -split '\|'
        if ($f.Count -lt 6) { continue }

        $mem = ($f[2] -split '/')[0].Trim()
        $net = $f[4] -split '/'

        $line = @(
            $ts
            $f[0]
            $f[1].TrimEnd('%')
            (ToBytes $mem)
            $f[3].TrimEnd('%')
            (ToBytes $net[0].Trim())
            (ToBytes $net[1].Trim())
            $f[5]
        ) -join ','

        Add-Content -Path $Path -Value $line
    }

    Start-Sleep -Seconds $IntervalSec
}
