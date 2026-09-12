/*
 * SHA-256 (FIPS 180-4).
 *
 * Своя реализация, а не OpenSSL: в nginx нет ngx_sha256, а модуль собирается с
 * --with-compat и не должен требовать ssl-сборки только ради контрольной суммы
 * тела. Хеш едет в локатор, по нему инспектор кеширует вердикт, а система
 * аудита связывает событие с архивом.
 */

#include "body/ngx_http_waf_body.h"


static void ngx_http_waf_sha256_block(ngx_http_waf_sha256_t *sha,
    const u_char *p);


static const uint32_t  ngx_http_waf_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


#define ngx_http_waf_ror(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))

#define ngx_http_waf_s0(x)                                                    \
    (ngx_http_waf_ror(x, 2) ^ ngx_http_waf_ror(x, 13) ^ ngx_http_waf_ror(x, 22))

#define ngx_http_waf_s1(x)                                                    \
    (ngx_http_waf_ror(x, 6) ^ ngx_http_waf_ror(x, 11) ^ ngx_http_waf_ror(x, 25))

#define ngx_http_waf_g0(x)                                                    \
    (ngx_http_waf_ror(x, 7) ^ ngx_http_waf_ror(x, 18) ^ ((x) >> 3))

#define ngx_http_waf_g1(x)                                                    \
    (ngx_http_waf_ror(x, 17) ^ ngx_http_waf_ror(x, 19) ^ ((x) >> 10))


void
ngx_http_waf_sha256_init(ngx_http_waf_sha256_t *sha)
{
    sha->bytes = 0;
    sha->used  = 0;

    sha->h[0] = 0x6a09e667;
    sha->h[1] = 0xbb67ae85;
    sha->h[2] = 0x3c6ef372;
    sha->h[3] = 0xa54ff53a;
    sha->h[4] = 0x510e527f;
    sha->h[5] = 0x9b05688c;
    sha->h[6] = 0x1f83d9ab;
    sha->h[7] = 0x5be0cd19;
}


void
ngx_http_waf_sha256_update(ngx_http_waf_sha256_t *sha, const u_char *data,
    size_t len)
{
    size_t  take;

    sha->bytes += len;

    if (sha->used != 0) {
        take = 64 - sha->used;

        if (take > len) {
            ngx_memcpy(sha->block + sha->used, data, len);
            sha->used += len;
            return;
        }

        ngx_memcpy(sha->block + sha->used, data, take);

        ngx_http_waf_sha256_block(sha, sha->block);

        data     += take;
        len      -= take;
        sha->used = 0;
    }

    while (len >= 64) {
        ngx_http_waf_sha256_block(sha, data);
        data += 64;
        len  -= 64;
    }

    if (len != 0) {
        ngx_memcpy(sha->block, data, len);
        sha->used = len;
    }
}


void
ngx_http_waf_sha256_final(ngx_http_waf_sha256_t *sha, u_char result[32])
{
    size_t    used;
    uint64_t  bits;

    bits = sha->bytes * 8;
    used = sha->used;

    sha->block[used++] = 0x80;

    if (used > 56) {
        ngx_memzero(sha->block + used, 64 - used);
        ngx_http_waf_sha256_block(sha, sha->block);
        used = 0;
    }

    ngx_memzero(sha->block + used, 56 - used);

    sha->block[56] = (u_char) (bits >> 56);
    sha->block[57] = (u_char) (bits >> 48);
    sha->block[58] = (u_char) (bits >> 40);
    sha->block[59] = (u_char) (bits >> 32);
    sha->block[60] = (u_char) (bits >> 24);
    sha->block[61] = (u_char) (bits >> 16);
    sha->block[62] = (u_char) (bits >> 8);
    sha->block[63] = (u_char) bits;

    ngx_http_waf_sha256_block(sha, sha->block);

    for (used = 0; used < 8; used++) {
        result[used * 4]     = (u_char) (sha->h[used] >> 24);
        result[used * 4 + 1] = (u_char) (sha->h[used] >> 16);
        result[used * 4 + 2] = (u_char) (sha->h[used] >> 8);
        result[used * 4 + 3] = (u_char) sha->h[used];
    }
}


static void
ngx_http_waf_sha256_block(ngx_http_waf_sha256_t *sha, const u_char *p)
{
    uint32_t    w[64], a, b, c, d, e, f, g, h, t1, t2;
    ngx_uint_t  i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t) p[i * 4] << 24)
               | ((uint32_t) p[i * 4 + 1] << 16)
               | ((uint32_t) p[i * 4 + 2] << 8)
               | (uint32_t) p[i * 4 + 3];
    }

    for (i = 16; i < 64; i++) {
        w[i] = ngx_http_waf_g1(w[i - 2]) + w[i - 7]
               + ngx_http_waf_g0(w[i - 15]) + w[i - 16];
    }

    a = sha->h[0];
    b = sha->h[1];
    c = sha->h[2];
    d = sha->h[3];
    e = sha->h[4];
    f = sha->h[5];
    g = sha->h[6];
    h = sha->h[7];

    for (i = 0; i < 64; i++) {
        t1 = h + ngx_http_waf_s1(e) + ((e & f) ^ (~e & g))
             + ngx_http_waf_sha256_k[i] + w[i];
        t2 = ngx_http_waf_s0(a) + ((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    sha->h[0] += a;
    sha->h[1] += b;
    sha->h[2] += c;
    sha->h[3] += d;
    sha->h[4] += e;
    sha->h[5] += f;
    sha->h[6] += g;
    sha->h[7] += h;
}
