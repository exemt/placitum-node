#include "ngx_http_waf.h"
#include "body/ngx_http_waf_body.h"

#if (NGX_LINUX)
#include <sys/mman.h>
#include <fcntl.h>
#endif


/*
 * Objects the agent takes that the exchange cannot serve ride with the audit
 * record: one memory file per record, its descriptor passed over the agent
 * socket next to the datagram. The exchange keeps the copy the inspectors saw;
 * the record carries the object the agent asked for. Headers and the query
 * string go whole -- the agent applies the name lists, then cuts -- and the
 * body at the archive size. It is the original only when the archive asked for
 * it; otherwise it is the slice under the capture masks, so nothing is written
 * into the exchange twice and the request never waits for it.
 */

static ngx_int_t ngx_http_waf_attach_one(ngx_http_waf_ctx_t *ctx, int fd,
    ngx_uint_t obj, off_t *offset);


ngx_int_t
ngx_http_waf_attach_write(int fd, u_char *data, size_t len)
{
    ssize_t  n;

    while (len > 0) {
        n = write(fd, data, len);

        if (n < 0) {
            if (ngx_errno == NGX_EINTR) {
                continue;
            }

            return NGX_ERROR;
        }

        data += n;
        len  -= (size_t) n;
    }

    return NGX_OK;
}


void
ngx_http_waf_attach_prepare(ngx_http_waf_ctx_t *ctx)
{
    ngx_uint_t                 i, keep, want, bit;
    ngx_http_waf_phase_ctx_t  *ph = ctx->ph;
#if (NGX_LINUX)
    off_t                      offset;
    int                        fd;
    ngx_int_t                  rc;
#endif

    if (ph->attach_planned) {
        return;
    }

    ph->attach_planned = 1;
    ph->attach_fd      = -1;

    keep = ngx_http_waf_archive_mask(ctx);
    want = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit = NGX_HTTP_WAF_OBJ_BIT(i);

        if ((keep & bit) && !ngx_http_waf_store_serves(ctx, i)) {
            want |= bit;
        }
    }

    if (want == 0) {
        return;
    }

#if (NGX_LINUX)

    fd = memfd_create("waf-record", MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, ngx_errno,
                      "waf: memfd_create() for the agent failed; %s stay "
                      "out of the archive", ngx_http_waf_obj_names(want));
        ph->archive &= ~want;
        return;
    }

    offset = 0;

    for (i = 0; i < NGX_HTTP_WAF_OBJ_COUNT; i++) {
        bit = NGX_HTTP_WAF_OBJ_BIT(i);

        if (!(want & bit)) {
            continue;
        }

        rc = ngx_http_waf_attach_one(ctx, fd, i, &offset);

        if (rc == NGX_OK) {
            ph->attached |= bit;

            if (i != NGX_HTTP_WAF_OBJ_BODY
                && ngx_http_waf_archive_original(ctx, i))
            {
                ph->attach_raw |= bit;
            }

            continue;
        }

        /*
         * The object did not ride along: a real failure (NGX_ERROR) may have
         * left a partial write behind, so drop the file back to the last good
         * offset -- otherwise the objects that follow would be described one
         * span short. An empty object (NGX_DECLINED) is not a failure and is
         * not logged: it simply has nothing to archive.
         */

        ph->archive &= ~bit;

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "waf: %V could not be attached to the record and "
                          "stays out of the archive",
                          ngx_http_waf_obj_name(i));

            if (ftruncate(fd, offset) == -1
                || lseek(fd, offset, SEEK_SET) == (off_t) -1)
            {
                break;
            }
        }
    }

    if (ph->attached == 0) {
        (void) close(fd);
        return;
    }

    (void) fcntl(fd, F_ADD_SEALS,
                 F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

    ph->attach_fd = fd;

    return;

#else

    ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                  "waf: record attachments need Linux; %s stay out of the "
                  "archive", ngx_http_waf_obj_names(want));
    ph->archive &= ~want;

#endif
}


static ngx_int_t
ngx_http_waf_attach_one(ngx_http_waf_ctx_t *ctx, int fd, ngx_uint_t obj,
    off_t *offset)
{
    size_t                   limit;
    ngx_int_t                rc;
    ngx_str_t                blob;
    ngx_uint_t               truncated;
    ngx_http_waf_locator_t  *loc;

    loc = ngx_pcalloc(ctx->request->pool, sizeof(ngx_http_waf_locator_t));
    if (loc == NULL) {
        return NGX_ERROR;
    }

    limit = ngx_http_waf_archive_wants(ctx, obj,
                                       ngx_http_waf_route_verdict(ctx));

    if (obj == NGX_HTTP_WAF_OBJ_BODY) {
        rc = ngx_http_waf_body_attach(ctx, fd, limit, loc);

        if (rc == NGX_DECLINED) {
            return NGX_DECLINED;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        /*
         * Headers and the query string go whole: they are bounded by the
         * header buffers, and the agent applies the name lists before it cuts
         * to the archive size -- a name the lists drop must not take the room
         * of one they keep.
         */

        rc = ngx_http_waf_meta_collect(ctx, obj, NGX_HTTP_WAF_AGENT_WHOLE,
                                       ngx_http_waf_archive_original(ctx, obj),
                                       &blob, &truncated);

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (blob.len == 0) {
            return NGX_DECLINED;
        }

        if (ngx_http_waf_attach_write(fd, blob.data, blob.len) != NGX_OK) {
            return NGX_ERROR;
        }

        loc->size = (off_t) blob.len;
    }

    loc->offset = *offset;
    *offset    += loc->size;

    ctx->ph->attach_loc[obj] = loc;

    return NGX_OK;
}


void
ngx_http_waf_attach_close(ngx_http_waf_ctx_t *ctx)
{
    if (ctx->ph->attach_planned && ctx->ph->attach_fd != -1) {
        (void) close(ctx->ph->attach_fd);
        ctx->ph->attach_fd = -1;
    }
}


int
ngx_http_waf_attach_fd(ngx_http_waf_ctx_t *ctx)
{
    return ctx->ph->attach_planned ? ctx->ph->attach_fd : -1;
}


ngx_http_waf_locator_t *
ngx_http_waf_audit_locator(ngx_http_waf_ctx_t *ctx, ngx_uint_t obj)
{
    if (ctx->ph->attached & NGX_HTTP_WAF_OBJ_BIT(obj)) {
        return ctx->ph->attach_loc[obj];
    }

    return ngx_http_waf_store_locator(ctx, obj);
}
