#!/bin/sh
# nginx starts first with a stub and the agent second: the agent applies generations with
# nginx -s reload, which needs a running master.
set -e

mkdir -p /var/run/waf /var/lib/waf/store
chmod 0755 /var/run/waf

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

# WAF_NGINX_DEBUG=on runs the master from nginx-debug, so that error_log debug shows core events too.
# The agent checks configurations with the same binary.
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
