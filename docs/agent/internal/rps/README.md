# internal/rps

Скользящее окно 10 с по итогам с unix-сокета. `Add(status, verdict)` на каждый
datagram, `Rate` — сумма корзин / 10, `Status` — те же корзины по классу ответа
2xx / 3xx / 4xx / 5xx. Уходит в кадр присутствия полями `rps` и `codes`.
