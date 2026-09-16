#include "codec/ngx_http_waf_codec.h"


static ngx_int_t ngx_http_waf_jp_hex4(ngx_http_waf_jp_t *jp, uint32_t *out);


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
    u_char           c;
    size_t           i;
    static const u_char  hex[] = "0123456789abcdef";

    ngx_http_waf_jw_raw(jw, (const u_char *) "\"", 1);

    for (i = 0; i < len; i++) {
        c = data[i];

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
        return NGX_DONE;
    }

    if (*jp->pos == ',') {
        jp->pos++;
        ngx_http_waf_jp_ws(jp);

        if (jp->pos < jp->end && *jp->pos == close) {
            jp->error = "trailing comma";
            return NGX_ERROR;
        }
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
ngx_http_waf_jp_string(ngx_http_waf_jp_t *jp, ngx_str_t *out)
{
    u_char  *dst;

    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != '"') {
        jp->error = "expected string";
        return NGX_ERROR;
    }

    dst = ngx_pnalloc(jp->pool, (size_t) (jp->end - jp->pos));
    if (dst == NULL) {
        jp->error = "no memory";
        return NGX_ERROR;
    }

    return ngx_http_waf_jp_string_buf(jp, dst,
                                      (size_t) (jp->end - jp->pos), out);
}


static ngx_int_t
ngx_http_waf_jp_string_skip(ngx_http_waf_jp_t *jp)
{
    while (jp->pos < jp->end) {

        if (*jp->pos == '\\') {
            jp->pos += 2;
            continue;
        }

        if (*jp->pos == '"') {
            jp->pos++;
            return NGX_OK;
        }

        jp->pos++;
    }

    jp->error = "unterminated string";

    return NGX_ERROR;
}


ngx_int_t
ngx_http_waf_jp_string_buf(ngx_http_waf_jp_t *jp, u_char *buf, size_t size,
    ngx_str_t *out)
{
    u_char    *dst, *last, *p;
    uint32_t   cp, low;

    ngx_http_waf_jp_ws(jp);

    if (jp->pos == jp->end || *jp->pos != '"') {
        jp->error = "expected string";
        return NGX_ERROR;
    }

    jp->pos++;

    dst  = buf;
    last = buf + size;
    p    = dst;

    while (jp->pos < jp->end) {

        if (*jp->pos == '"') {
            jp->pos++;

            out->data = dst;
            out->len  = (size_t) (p - dst);

            return NGX_OK;
        }

        if (*jp->pos < 0x20) {
            jp->error = "control character in string";
            return NGX_ERROR;
        }

        if (*jp->pos != '\\') {

            if (p == last) {
                ngx_str_null(out);

                return ngx_http_waf_jp_string_skip(jp) == NGX_OK
                           ? NGX_DECLINED : NGX_ERROR;
            }

            *p++ = *jp->pos++;
            continue;
        }

        if ((size_t) (last - p) < 4) {
            ngx_str_null(out);

            return ngx_http_waf_jp_string_skip(jp) == NGX_OK
                       ? NGX_DECLINED : NGX_ERROR;
        }

        jp->pos++;

        if (jp->pos == jp->end) {
            break;
        }

        switch (*jp->pos) {
        case '"':  *p++ = '"';  jp->pos++; continue;
        case '\\': *p++ = '\\'; jp->pos++; continue;
        case '/':  *p++ = '/';  jp->pos++; continue;
        case 'b':  *p++ = '\b'; jp->pos++; continue;
        case 'f':  *p++ = '\f'; jp->pos++; continue;
        case 'n':  *p++ = '\n'; jp->pos++; continue;
        case 'r':  *p++ = '\r'; jp->pos++; continue;
        case 't':  *p++ = '\t'; jp->pos++; continue;
        case 'u':  break;
        default:
            jp->error = "unknown escape sequence";
            return NGX_ERROR;
        }

        jp->pos++;

        if (ngx_http_waf_jp_hex4(jp, &cp) != NGX_OK) {
            return NGX_ERROR;
        }

        if (cp >= 0xd800 && cp <= 0xdbff
            && jp->end - jp->pos >= 6
            && jp->pos[0] == '\\' && jp->pos[1] == 'u')
        {
            jp->pos += 2;

            if (ngx_http_waf_jp_hex4(jp, &low) != NGX_OK) {
                return NGX_ERROR;
            }

            if (low >= 0xdc00 && low <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);

            } else {
                p = ngx_http_waf_utf8_encode(p, cp);
                cp = low;
            }
        }

        p = ngx_http_waf_utf8_encode(p, cp);
    }

    jp->error = "unterminated string";

    return NGX_ERROR;
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
    uint64_t   v;
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

        if (v > (uint64_t) NGX_MAX_INT_T_VALUE / 10) {
            jp->error = "number out of range";
            return NGX_ERROR;
        }

        v = v * 10 + (uint64_t) (c - '0');
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


ngx_int_t
ngx_http_waf_jp_skip(ngx_http_waf_jp_t *jp)
{
    u_char      c;
    ngx_str_t   dummy;
    ngx_int_t   n;
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
            if (++depth > NGX_HTTP_WAF_JSON_MAX_DEPTH) {
                jp->error = "message nested too deeply";
                return NGX_ERROR;
            }

            jp->pos++;
            continue;

        case '}':
        case ']':
            if (depth == 0) {
                jp->error = "unbalanced brackets";
                return NGX_ERROR;
            }

            jp->pos++;
            depth--;
            break;

        case ',':
        case ':':
            jp->pos++;
            continue;

        case '"':
            if (ngx_http_waf_jp_string(jp, &dummy) != NGX_OK) {
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

            n = 0;

            while (jp->pos < jp->end) {
                c = *jp->pos;

                if ((c >= '0' && c <= '9') || c == '-' || c == '+'
                    || c == '.' || c == 'e' || c == 'E')
                {
                    jp->pos++;
                    n++;
                    continue;
                }

                break;
            }

            if (n == 0) {
                jp->error = "unexpected character";
                return NGX_ERROR;
            }
        }

        if (depth == 0) {
            return NGX_OK;
        }
    }
}
