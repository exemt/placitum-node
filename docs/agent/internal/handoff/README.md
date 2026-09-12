# internal/handoff

Unix datagram от модуля nginx. Не шина вердиктов и не `WAF_AUDIT`.

Модуль: `sendto(MSG_DONTWAIT)` на `waf_agent_socket`. Агент читает и отдаёт
байты в `audit.Decode` → `audit.Publish`. Промах — потеря события, не запроса.

Путь по умолчанию — `/var/run/waf/verdict.sock` (`WAF_VERDICT_SOCK`).

Сокетов на ноде теперь два, и приёмник у них общий: `ServeOpts` берёт свои
размеры датаграммы и очереди приёма. Второй — строки лога nginx
(internal/nginxlog (`docs/nginx/agent/internal/nginxlog/README.md`)), и держать под строку текста тот
же восьмимегабайтный буфер, что под превью тела, незачем.
