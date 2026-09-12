#!/bin/sh
# Том /var/run/waf приезжает root-овым. Сокет должен писать wafagent,
# а sendto делает воркер nginx — другой uid, поэтому каталог 0755, сокет 0666.
set -e
mkdir -p /var/run/waf
chown wafagent:wafagent /var/run/waf
chmod 0755 /var/run/waf
exec su-exec wafagent:wafagent "$@"
