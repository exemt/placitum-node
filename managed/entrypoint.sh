#!/bin/sh
# Порядок здесь обратный обычному: сначала поднимается nginx с заглушкой, и
# только потом агент. Агент применяет поколение через `nginx -s reload`, а
# перезагружать нечего, пока мастер не запущен -- на пустой ноде первое
# поколение просто не приехало бы.
set -e

mkdir -p /var/run/waf /var/lib/waf/store
chmod 0755 /var/run/waf

# Заглушка живёт ровно до первого поколения: контроллер пришлёт свой файл и
# перезапишет её. Отдельный порт, чтобы не спорить с тем, что приедет.
if [ ! -f /etc/nginx/nginx.conf.prev ]; then
    cat > /etc/nginx/nginx.conf <<'EOF'
events {}

http {
    server {
        listen 8079;
        location = /healthz { return 200 "bootstrap\n"; }
        location / { return 503 "waiting for controller generation\n"; }
    }
}
EOF
fi

# Отладка ядра nginx: WAF_NGINX_DEBUG=on поднимает мастер из nginx-debug --
# того же nginx образа, собранного с --with-debug. Без этого `error_log ...
# debug` показывает только строки модуля (он собран с отладкой всегда), а
# события, буферы и апстрим ядра вырезаны из обычного бинаря. Флаг стартовый:
# бинарь мастера на ходу не меняется, нужен рестарт контейнера.
#
# Агенту -- тот же бинарь (WAF_NGINX_BIN): `nginx -t` обязан проверять конфиг
# тем, кто его исполнит, иначе debug_connection в поколении отвергался бы
# обычным бинарём как неизвестная директива.
NGINX_BIN=nginx
case "${WAF_NGINX_DEBUG:-off}" in
    on|1|true|yes)
        NGINX_BIN=nginx-debug
        export WAF_NGINX_BIN="${WAF_NGINX_BIN:-nginx-debug}"
        echo "waf-node: WAF_NGINX_DEBUG=on, master is nginx-debug" >&2
        ;;
esac

"$NGINX_BIN" -g 'daemon on;'

exec waf-agent "$@"
