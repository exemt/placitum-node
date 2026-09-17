#include "codec/ngx_http_waf_codec.h"


static ngx_int_t ngx_http_waf_jp_unit(ngx_http_waf_jp_t *jp, u_char *unit,
    size_t *n);
static ngx_int_t ngx_http_waf_jp_hex4(ngx_http_waf_jp_t *jp, uint32_t *out);
static ngx_int_t ngx_http_waf_jp_string_skip(ngx_http_waf_jp_t *jp);
static ngx_int_t ngx_http_waf_jp_key_skip(ngx_http_waf_jp_t *jp);
static ngx_int_t ngx_http_waf_jp_number_skip(ngx_http_waf_jp_t *jp);


static ngx_inline u_char *
ngx_http_waf_utf8_encode(u_char *p, uint32_t u)
{
    if (u < 0x80) {
        *p++ = (u_char) u;

    } else if (u < 0x800) {
        *p++ = (u_char) (0xc0 | (u >> 6));
        *p++ = (u_char) (0x80 | (u & 0x3f));

    } else if (u < 0x10000) {
        *p++ = (u_char) (0xe0 | (u >> 12));
        *p++ = (u_char) (0x80 | ((u >> 6) & 0x3f));
        *p++ = (u_char) (0x80 | (u & 0x3f));

    } else {
        *p++ = (u_char) (0xf0 | (u >> 18));
        *p++ = (u_char) (0x80 | ((u >> 12) & 0x3f));
        *p++ = (u_char) (0x80 | ((u >> 6) & 0x3f));
        *p++ = (u_char) (0x80 | (u & 0x3f));
    }

    return p;
}


/*
 * Length of the well-formed UTF-8 sequence at p, or 0 with *bad set to the
 * length of its ill-formed prefix, the part one U+FFFD stands for.
 */

static size_t
ngx_http_waf_utf8_valid(const u_char *p, size_t n, size_t *bad)
{
    u_char  c, lo, hi;
    size_t  i, need;

    c = p[0];

    if (c < 0x80) {
        return 1;
    }

    lo = 0x80;
    hi = 0xbf;

    if (c >= 0xc2 && c <= 0xdf) {
        need = 1;

    } else if (c == 0xe0) {
        need = 2;
        lo = 0xa0;

    } else if (c >= 0xe1 && c <= 0xef) {
        need = 2;

        if (c == 0xed) {
            hi = 0x9f;
        }

    } else if (c == 0xf0) {
        need = 3;
        lo = 0x90;

    } else if (c >= 0xf1 && c <= 0xf3) {
        need = 3;

    } else if (c == 0xf4) {
        need = 3;
        hi = 0x8f;

    } else {
        *bad = 1;
        return 0;
    }

    for (i = 1; i <= need; i++) {

        if (i == n || p[i] < lo || p[i] > hi) {
            *bad = i;
            return 0;
        }

        lo = 0x80;
        hi = 0xbf;
    }

    return need + 1;
}


void
ngx_http_waf_jw_init(ngx_http_waf_jw_t *jw, u_char *buf, size_t size)
{
    jw->start    = buf;
    jw->pos      = buf;
    jw->end      = buf + size;
    jw->overflow = 0;
}


void
ngx_http_waf_jw_raw(ngx_http_waf_jw_t *jw, const u_char *data, size_t len)
{
    if ((size_t) (jw->end - jw->pos) < len) {
        jw->overflow = 1;
        return;
    }

    jw->pos = ngx_cpymem(jw->pos, data, len);
}


void
ngx_http_waf_jw_string(ngx_http_waf_jw_t *jw, const u_char *data, size_t len)
{
    u_char               c;
    size_t               i, n, bad;
    static const u_char  hex[] = "0123456789abcdef";

    ngx_http_waf_jw_raw(jw, (const u_char *) "\"", 1);

    i = 0;

    while (i < len) {
        c = data[i];

        if (c >= 0x80) {
            n = ngx_http_waf_utf8_valid(&data[i], len - i, &bad);

            if (n != 0) {
                ngx_http_waf_jw_raw(jw, &data[i], n);
                i += n;

            } else {
                ngx_http_waf_jw_raw(jw, (const u_char *) "\xef\xbf\xbd", 3);
                i += bad;
            }

            continue;
        }

        i++;

        if (c == '"' || c == '\\') {
            if (jw->end - jw->pos < 2) {
                jw->overflow = 1;
                return;
            }

            *jw->pos++ = '\\';
            *jw->pos++ = c;
            continue;
        }

        if (c >= 0x20) {
            if (jw->pos == jw->end) {
                jw->overflow = 1;
                return;
            }

            *jw->pos++ = c;
            continue;
        }

        switch (c) {
        case '\n': ngx_http_waf_jw_lit(jw, "\\n"); continue;
        case '\r': ngx_http_waf_jw_lit(jw, "\\r"); continue;
        case '\t': ngx_http_waf_jw_lit(jw, "\\t"); continue;
        case '\b': ngx_http_waf_jw_lit(jw, "\\b"); continue;
        case '\f': ngx_http_waf_jw_lit(jw, "\\f"); continue;
        default:
            if (jw->end - jw->pos < 6) {
                jw->overflow = 1;
                return;
            }

            *jw->pos++ = '\\';
            *jw->pos++ = 'u';
            *jw->pos++ = '0';
            *jw->pos++ = '0';
            *jw->pos++ = hex[(c >> 4) & 0xf];
            *jw->pos++ = hex[c & 0xf];
        }
    }

    ngx_http_waf_jw_raw(jw, (const u_char *) "\"", 1);
}


void
ngx_http_waf_jw_int(ngx_http_waf_jw_t *jw, ngx_int_t v)
{
    u_char   buf[NGX_INT64_LEN + 1];
    u_char  *p;

    p = ngx_sprintf(buf, "%i", v);

    ngx_http_waf_jw_raw(jw, buf, (size_t) (p - buf));
}


void
ngx_http_waf_jp_init(ngx_http_waf_jp_t *jp, ngx_str_t *payload,
    ngx_pool_t *pool)
{
    jp->pos   = payload->data;
    jp->end   = payload->data + payload->len;
    jp->pool  = pool;
    jp->error = NULL;
    jp->first = 0;
}


static void
ngx_http_waf_jp_ws(ngx_http_waf_jp_t *jp)
{
    u_char  c;

    while (jp->pos < jp->end) {
        c = *jp->pos;

        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            return;
        }

        jp->pos++;
    }
}


static ngx_int_t
ngx_http_waf_jp_open(ngx_http_waf_jp_t *jp, u_char open)
{
    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != open) {
        jp->error = "expected object or array";
        return NGX_ERROR;
    }

    jp->pos++;
    jp->first = 1;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_object(ngx_http_waf_jp_t *jp)
{
    return ngx_http_waf_jp_open(jp, '{');
}


ngx_int_t
ngx_http_waf_jp_array(ngx_http_waf_jp_t *jp)
{
    return ngx_http_waf_jp_open(jp, '[');
}


static ngx_int_t
ngx_http_waf_jp_next(ngx_http_waf_jp_t *jp, u_char close)
{
    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end) {
        jp->error = "truncated message";
        return NGX_ERROR;
    }

    if (*jp->pos == close) {
        jp->pos++;
        jp->first = 0;
        return NGX_DONE;
    }

    if (jp->first) {
        jp->first = 0;
        return NGX_OK;
    }

    if (*jp->pos != ',') {
        jp->error = "expected comma";
        return NGX_ERROR;
    }

    jp->pos++;
    ngx_http_waf_jp_ws(jp);

    if (jp->pos < jp->end && *jp->pos == close) {
        jp->error = "trailing comma";
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_member(ngx_http_waf_jp_t *jp, ngx_str_t *key)
{
    ngx_int_t  rc;

    rc = ngx_http_waf_jp_next(jp, '}');
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_waf_jp_string(jp, key) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != ':') {
        jp->error = "expected colon after member name";
        return NGX_ERROR;
    }

    jp->pos++;
    ngx_http_waf_jp_ws(jp);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_element(ngx_http_waf_jp_t *jp)
{
    ngx_int_t  rc;

    rc = ngx_http_waf_jp_next(jp, ']');
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_waf_jp_ws(jp);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_end(ngx_http_waf_jp_t *jp)
{
    ngx_http_waf_jp_ws(jp);

    if (jp->pos != jp->end) {
        jp->error = "trailing data after the document";
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_string(ngx_http_waf_jp_t *jp, ngx_str_t *out)
{
    u_char  *p, *dst;
    size_t   size;

    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != '"') {
        jp->error = "expected string";
        return NGX_ERROR;
    }

    for (p = jp->pos + 1; p < jp->end; p++) {

        if (*p == '"') {
            break;
        }

        if (*p == '\\' && ++p == jp->end) {
            break;
        }
    }

    if (p == jp->end) {
        jp->error = "unterminated string";
        return NGX_ERROR;
    }

    /* no escape decodes to more bytes than it takes on the wire */

    size = (size_t) (p - jp->pos - 1);

    dst = ngx_pnalloc(jp->pool, size);
    if (dst == NULL) {
        jp->error = "no memory";
        return NGX_ERROR;
    }

    return ngx_http_waf_jp_string_buf(jp, dst, size, out);
}


static ngx_int_t
ngx_http_waf_jp_string_skip(ngx_http_waf_jp_t *jp)
{
    ngx_str_t  dummy;

    return ngx_http_waf_jp_string_buf(jp, NULL, 0, &dummy) == NGX_ERROR
               ? NGX_ERROR : NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_string_buf(ngx_http_waf_jp_t *jp, u_char *buf, size_t size,
    ngx_str_t *out)
{
    u_char      unit[4];
    size_t      n, room;
    ngx_uint_t  full;

    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != '"') {
        jp->error = "expected string";
        return NGX_ERROR;
    }

    jp->pos++;

    room = size;
    full = 0;

    for ( ;; ) {

        if (jp->pos == jp->end) {
            jp->error = "unterminated string";
            return NGX_ERROR;
        }

        if (*jp->pos == '"') {
            jp->pos++;
            break;
        }

        if (ngx_http_waf_jp_unit(jp, unit, &n) != NGX_OK) {
            return NGX_ERROR;
        }

        if (full || room < n) {
            full = 1;
            continue;
        }

        ngx_memcpy(buf + (size - room), unit, n);
        room -= n;
    }

    if (full) {
        ngx_str_null(out);
        return NGX_DECLINED;
    }

    out->data = buf;
    out->len  = size - room;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_jp_unit(ngx_http_waf_jp_t *jp, u_char *unit, size_t *n)
{
    u_char    c, *save;
    size_t    bad;
    uint32_t  cp, low;

    c = *jp->pos;

    if (c < 0x20) {
        jp->error = "control character in string";
        return NGX_ERROR;
    }

    if (c >= 0x80) {
        *n = ngx_http_waf_utf8_valid(jp->pos, (size_t) (jp->end - jp->pos),
                                     &bad);
        if (*n == 0) {
            jp->error = "invalid UTF-8 in string";
            return NGX_ERROR;
        }

        ngx_memcpy(unit, jp->pos, *n);
        jp->pos += *n;

        return NGX_OK;
    }

    jp->pos++;
    *n = 1;

    if (c != '\\') {
        unit[0] = c;
        return NGX_OK;
    }

    if (jp->pos == jp->end) {
        jp->error = "unterminated string";
        return NGX_ERROR;
    }

    c = *jp->pos++;

    switch (c) {
    case '"':  unit[0] = '"';  return NGX_OK;
    case '\\': unit[0] = '\\'; return NGX_OK;
    case '/':  unit[0] = '/';  return NGX_OK;
    case 'b':  unit[0] = '\b'; return NGX_OK;
    case 'f':  unit[0] = '\f'; return NGX_OK;
    case 'n':  unit[0] = '\n'; return NGX_OK;
    case 'r':  unit[0] = '\r'; return NGX_OK;
    case 't':  unit[0] = '\t'; return NGX_OK;
    case 'u':  break;
    default:
        jp->error = "unknown escape sequence";
        return NGX_ERROR;
    }

    if (ngx_http_waf_jp_hex4(jp, &cp) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cp >= 0xdc00 && cp <= 0xdfff) {
        cp = 0xfffd;

    } else if (cp >= 0xd800 && cp <= 0xdbff) {
        save = jp->pos;

        if (jp->end - jp->pos >= 6 && jp->pos[0] == '\\' && jp->pos[1] == 'u')
        {
            jp->pos += 2;

            if (ngx_http_waf_jp_hex4(jp, &low) != NGX_OK) {
                return NGX_ERROR;
            }

            if (low >= 0xdc00 && low <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);

            } else {
                jp->pos = save;
                cp = 0xfffd;
            }

        } else {
            cp = 0xfffd;
        }
    }

    *n = (size_t) (ngx_http_waf_utf8_encode(unit, cp) - unit);

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_jp_hex4(ngx_http_waf_jp_t *jp, uint32_t *out)
{
    u_char    c;
    uint32_t  v;
    ngx_uint_t i;

    if (jp->end - jp->pos < 4) {
        jp->error = "truncated \\u escape";
        return NGX_ERROR;
    }

    v = 0;

    for (i = 0; i < 4; i++) {
        c = *jp->pos++;

        if (c >= '0' && c <= '9') {
            v = (v << 4) + (uint32_t) (c - '0');

        } else if (c >= 'a' && c <= 'f') {
            v = (v << 4) + (uint32_t) (c - 'a' + 10);

        } else if (c >= 'A' && c <= 'F') {
            v = (v << 4) + (uint32_t) (c - 'A' + 10);

        } else {
            jp->error = "invalid \\u escape";
            return NGX_ERROR;
        }
    }

    *out = v;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_int(ngx_http_waf_jp_t *jp, ngx_int_t *out)
{
    u_char     c;
    uint64_t   v, d;
    ngx_uint_t digits, negative;

    ngx_http_waf_jp_ws(jp);

    negative = 0;

    if (jp->pos < jp->end && *jp->pos == '-') {
        negative = 1;
        jp->pos++;
    }

    v      = 0;
    digits = 0;

    while (jp->pos < jp->end) {
        c = *jp->pos;

        if (c < '0' || c > '9') {
            break;
        }

        if (digits == 1 && v == 0) {
            jp->error = "leading zero in number";
            return NGX_ERROR;
        }

        d = (uint64_t) (c - '0');

        if (v > ((uint64_t) NGX_MAX_INT_T_VALUE - d) / 10) {
            jp->error = "number out of range";
            return NGX_ERROR;
        }

        v = v * 10 + d;
        digits++;
        jp->pos++;
    }

    if (digits == 0) {
        jp->error = "expected integer";
        return NGX_ERROR;
    }

    if (jp->pos < jp->end
        && (*jp->pos == '.' || *jp->pos == 'e' || *jp->pos == 'E'))
    {
        jp->error = "expected integer, got fractional number";
        return NGX_ERROR;
    }

    *out = negative ? -(ngx_int_t) v : (ngx_int_t) v;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_jp_literal(ngx_http_waf_jp_t *jp, const char *lit, size_t len)
{
    if ((size_t) (jp->end - jp->pos) < len
        || ngx_strncmp(jp->pos, lit, len) != 0)
    {
        return NGX_ERROR;
    }

    jp->pos += len;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_bool(ngx_http_waf_jp_t *jp, ngx_uint_t *out)
{
    ngx_http_waf_jp_ws(jp);

    if (ngx_http_waf_jp_literal(jp, "true", 4) == NGX_OK) {
        *out = 1;
        return NGX_OK;
    }

    if (ngx_http_waf_jp_literal(jp, "false", 5) == NGX_OK) {
        *out = 0;
        return NGX_OK;
    }

    jp->error = "expected boolean";

    return NGX_ERROR;
}


ngx_uint_t
ngx_http_waf_jp_null(ngx_http_waf_jp_t *jp)
{
    ngx_http_waf_jp_ws(jp);

    return ngx_http_waf_jp_literal(jp, "null", 4) == NGX_OK;
}


static ngx_int_t
ngx_http_waf_jp_key_skip(ngx_http_waf_jp_t *jp)
{
    if (ngx_http_waf_jp_string_skip(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != ':') {
        jp->error = "expected colon after member name";
        return NGX_ERROR;
    }

    jp->pos++;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_jp_digits(ngx_http_waf_jp_t *jp)
{
    u_char  *start;

    start = jp->pos;

    while (jp->pos < jp->end && *jp->pos >= '0' && *jp->pos <= '9') {
        jp->pos++;
    }

    if (jp->pos == start) {
        jp->error = "invalid number";
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_jp_number_skip(ngx_http_waf_jp_t *jp)
{
    if (jp->pos < jp->end && *jp->pos == '-') {
        jp->pos++;
    }

    if (jp->pos < jp->end && *jp->pos == '0') {
        jp->pos++;

    } else if (ngx_http_waf_jp_digits(jp) != NGX_OK) {
        return NGX_ERROR;
    }

    if (jp->pos < jp->end && *jp->pos == '.') {
        jp->pos++;

        if (ngx_http_waf_jp_digits(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (jp->pos < jp->end && (*jp->pos == 'e' || *jp->pos == 'E')) {
        jp->pos++;

        if (jp->pos < jp->end && (*jp->pos == '+' || *jp->pos == '-')) {
            jp->pos++;
        }

        if (ngx_http_waf_jp_digits(jp) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_jp_skip(ngx_http_waf_jp_t *jp)
{
    u_char      c, stack[NGX_HTTP_WAF_JSON_MAX_DEPTH];
    ngx_uint_t  b, depth;

    depth = 0;

    for ( ;; ) {
        ngx_http_waf_jp_ws(jp);

        if (jp->pos == jp->end) {
            jp->error = "truncated value";
            return NGX_ERROR;
        }

        c = *jp->pos;

        switch (c) {

        case '{':
        case '[':
            if (depth == NGX_HTTP_WAF_JSON_MAX_DEPTH) {
                jp->error = "message nested too deeply";
                return NGX_ERROR;
            }

            stack[depth++] = (u_char) (c == '{' ? '}' : ']');

            jp->pos++;
            ngx_http_waf_jp_ws(jp);

            if (jp->pos < jp->end && *jp->pos == stack[depth - 1]) {
                jp->pos++;
                depth--;
                break;
            }

            if (c == '{' && ngx_http_waf_jp_key_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;

        case '"':
            if (ngx_http_waf_jp_string_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case 't':
        case 'f':
            if (ngx_http_waf_jp_bool(jp, &b) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case 'n':
            if (!ngx_http_waf_jp_null(jp)) {
                jp->error = "unexpected value";
                return NGX_ERROR;
            }

            break;

        default:
            if (c != '-' && (c < '0' || c > '9')) {
                jp->error = "unexpected character";
                return NGX_ERROR;
            }

            if (ngx_http_waf_jp_number_skip(jp) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        for ( ;; ) {

            if (depth == 0) {
                return NGX_OK;
            }

            ngx_http_waf_jp_ws(jp);

            if (jp->pos == jp->end) {
                jp->error = "truncated value";
                return NGX_ERROR;
            }

            if (*jp->pos == stack[depth - 1]) {
                jp->pos++;
                depth--;
                continue;
            }

            if (*jp->pos != ',') {
                jp->error = "expected comma";
                return NGX_ERROR;
            }

            jp->pos++;

            if (stack[depth - 1] == '}'
                && ngx_http_waf_jp_key_skip(jp) != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;
        }
    }
}
