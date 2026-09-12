-- Профиль поиска потолка. Единственная задача -- узнать, сколько запросов в
-- секунду вообще держит стенд.
--
-- Латентность отсюда в критерии не входит никогда: wrk работает по закрытой
-- модели, то есть при росте задержки сам снижает интенсивность, и измеренный
-- квантиль оказывается тем лучше, чем хуже ведёт себя система (coordinated
-- omission). Числа, на которых стоят пороги, даёт только k6 в режиме
-- constant-arrival-rate -- см. README.md#выбор-инструмента.
--
--     docker run --rm --network wafload_default -v ${PWD}/wrk:/w \
--         williamyeh/wrk -t8 -c400 -d60s -s /w/corpus.lua http://haproxy:8080
--
-- Запросы формируются целиком заранее и дальше только перебираются: в горячем
-- пути не остаётся ни одной операции со строками, иначе потолок измерял бы
-- интерпретатор Lua.

local CORPUS   = tonumber(os.getenv("WRK_CORPUS")   or "2000")
local SEED     = tonumber(os.getenv("WRK_SEED")     or "20260813")
local CONTROL  = tonumber(os.getenv("WRK_CONTROL")  or "0.10")
local BODY_MAX = tonumber(os.getenv("WRK_BODY_MAX") or "8192")

local reqs = {}
local pos  = 0

local paths = {
    "/orders", "/orders/1042", "/users/77/orders", "/search",
    "/catalog/shoes", "/catalog/tools", "/cart/checkout", "/v2/items/9ab3",
}

local agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "curl/8.5.0",
    "okhttp/4.12.0",
}

local args = { "utm_source", "page", "sort", "q", "filter", "lang", "ref" }

local alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

local function rand_string(n)
    local t = {}
    for i = 1, n do
        local k = math.random(#alnum)
        t[i] = alnum:sub(k, k)
    end
    return table.concat(t)
end

function setup(thread)
    thread:set("tid", tonumber(thread:get("tid") or 0) or 0)
end

function init(args_)
    -- Своё зерно на поток: иначе все потоки перебирают один и тот же порядок.
    math.randomseed(SEED + (tonumber(wrk.thread and 0 or 0) or 0) + os.time() % 1)

    local block = rand_string(1024)

    for i = 1, CORPUS do
        local control = math.random() < CONTROL
        local prefix  = control and "/nowaf" or "/api"

        local path = prefix .. paths[math.random(#paths)]

        local nargs = math.random(0, 5)
        if nargs > 0 then
            local parts = {}
            for j = 1, nargs do
                parts[j] = args[math.random(#args)] .. "=" .. rand_string(math.random(1, 16))
            end
            path = path .. "?" .. table.concat(parts, "&")
        end

        local headers = {}
        headers["User-Agent"]      = agents[math.random(#agents)]
        headers["Accept"]          = "*/*"
        headers["Accept-Language"] = "ru-RU,ru;q=0.9,en-US;q=0.8"
        headers["X-Request-Id"]    = rand_string(32)
        headers["X-Forwarded-For"] = string.format("%d.%d.%d.%d",
            math.random(1, 223), math.random(0, 255),
            math.random(0, 255), math.random(1, 254))
        headers["Cookie"]          = "sid=" .. rand_string(24) .. "; lang=ru"

        local method = "GET"
        local body   = nil

        if math.random() < 0.4 then
            method = "POST"
            local size = math.random(512, BODY_MAX)
            local pad  = block:rep(math.ceil(size / 1024)):sub(1, size)
            body = '{"m":"' .. rand_string(32) .. '","pad":"' .. pad .. '"}'
            headers["Content-Type"] = "application/json"
        end

        reqs[i] = wrk.format(method, path, headers, body)
    end
end

function request()
    pos = pos + 1
    if pos > CORPUS then
        pos = 1
    end
    return reqs[pos]
end

local bad = 0

function response(status)
    -- 403 и 303 здесь не ожидаются: профиль потолка не включает флаворы,
    -- вызывающие отказ и челлендж.
    if status ~= 200 then
        bad = bad + 1
    end
end

function done(summary, latency)
    io.write("\n")
    io.write(string.format("запросов        %d\n", summary.requests))
    io.write(string.format("длительность    %.1fs\n", summary.duration / 1000000))
    io.write(string.format("rps             %.0f\n",
        summary.requests / (summary.duration / 1000000)))
    io.write(string.format("не 200          %d\n", bad))
    io.write(string.format("ошибок сокета   %d\n",
        summary.errors.connect + summary.errors.read +
        summary.errors.write + summary.errors.timeout))
    io.write("\n")
    io.write("латентность ниже приведена справочно и в критерии не входит:\n")
    io.write(string.format("  p50 %.2fms  p99 %.2fms  max %.2fms\n",
        latency:percentile(50) / 1000,
        latency:percentile(99) / 1000,
        latency.max / 1000))
end
