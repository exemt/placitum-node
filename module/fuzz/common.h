/*
 * Общее для фазз-харнессов: минимальное окружение nginx без мастера и без
 * цикла событий. Ровно столько, сколько нужно парсерам: страница памяти для
 * пулов, лог в stderr (молчащий по умолчанию), фиктивный cycle с пулом,
 * дерево таймеров, индекс модуля в conf-массивах запроса.
 */

#ifndef _WAF_FUZZ_COMMON_H_INCLUDED_
#define _WAF_FUZZ_COMMON_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

#include "ngx_http_waf.h"
#include "codec/ngx_http_waf_codec.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


extern ngx_log_t  waf_fuzz_log;

/* Однократная инициализация окружения; безопасно звать на каждом входе. */
void  waf_fuzz_init(void);

/* Пул на один вход фаззера. */
ngx_pool_t  *waf_fuzz_pool(void);

/* Копия входа в пул как ngx_str_t. */
ngx_int_t  waf_fuzz_payload(ngx_pool_t *pool, const uint8_t *data, size_t size,
               ngx_str_t *out);


#endif /* _WAF_FUZZ_COMMON_H_INCLUDED_ */
