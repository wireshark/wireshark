/*
 *  FIPS-180-2 compliant SHA-2 implementation (only sha256 so far)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
#include <string.h>
#include <glib.h>

#include "sha2.h"

/* the K array */
static const guint32 K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};


#define GET_UINT32(n,b,i)                               \
    {                                                   \
        (n) = ( (guint32) (b)[(i)    ] << 24 )          \
            | ( (guint32) (b)[(i) + 1] << 16 )          \
            | ( (guint32) (b)[(i) + 2] <<  8 )          \
            | ( (guint32) (b)[(i) + 3]       );         \
    }

#define PUT_UINT32(n,b,i)                       \
    {                                           \
        (b)[(i)    ] = (guint8) ( (n) >> 24 );  \
        (b)[(i) + 1] = (guint8) ( (n) >> 16 );  \
        (b)[(i) + 2] = (guint8) ( (n) >>  8 );  \
        (b)[(i) + 3] = (guint8) ( (n)       );  \
    }

/* Initialize the hash state */
void sha256_starts( sha256_context *ctx )
{
    ctx->total = 0;
    ctx->state[0] = 0x6A09E667UL;
    ctx->state[1] = 0xBB67AE85UL;
    ctx->state[2] = 0x3C6EF372UL;
    ctx->state[3] = 0xA54FF53AUL;
    ctx->state[4] = 0x510E527FUL;
    ctx->state[5] = 0x9B05688CUL;
    ctx->state[6] = 0x1F83D9ABUL;
    ctx->state[7] = 0x5BE0CD19UL;
}

static void sha256_process( sha256_context *ctx, const guint8 *data )
{
    guint32 i, temp1, temp2, W[64], A, B, C, D, E, F, G, H;

    /* init W */
    GET_UINT32( W[0],  data,  0 );
    GET_UINT32( W[1],  data,  4 );
    GET_UINT32( W[2],  data,  8 );
    GET_UINT32( W[3],  data, 12 );
    GET_UINT32( W[4],  data, 16 );
    GET_UINT32( W[5],  data, 20 );
    GET_UINT32( W[6],  data, 24 );
    GET_UINT32( W[7],  data, 28 );
    GET_UINT32( W[8],  data, 32 );
    GET_UINT32( W[9],  data, 36 );
    GET_UINT32( W[10], data, 40 );
    GET_UINT32( W[11], data, 44 );
    GET_UINT32( W[12], data, 48 );
    GET_UINT32( W[13], data, 52 );
    GET_UINT32( W[14], data, 56 );
    GET_UINT32( W[15], data, 60 );

#define RR(x,n) ((x << (32 - n)) | ((x & 0xFFFFFFFF) >> n))
#define S0(x) (RR(x, 7) ^ RR(x, 18) ^ (x >> 3))
#define S1(x) (RR(x, 17) ^ RR(x, 19) ^ (x >> 10))

    for (i = 16; i < 64 ; i++)
    {
        W[i] = W[i - 16] + S0(W[i - 15]) + W[i - 7] + S1(W[i - 2]);
    }

    /* Compression */
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

#undef S0
#undef S1
#define S0(x) (RR(x, 2) ^ RR(x, 13) ^ RR(x, 22))
#define S1(x) (RR(x, 6) ^ RR(x, 11) ^ RR(x, 25))
#define CH(x,y,z) (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) (((x | y) & z) | (x & y))

    for (i = 0; i < 64; ++i) {
        temp1 = H + S1(E) + CH(E, F, G) + K[i] + W[i];
        temp2 = S0(A) + MAJ(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;

    }

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

void sha256_update( sha256_context *ctx, const guint8 *input, guint32 length )
{
    guint32 left, fill;

    if( ! length ) return;

    left = (guint32)(ctx->total % SHA256_BLOCK_SIZE);
    fill = SHA256_BLOCK_SIZE - left;

    ctx->total += length;

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (const void *) input, fill );
        sha256_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= SHA256_BLOCK_SIZE )
    {
        sha256_process( ctx, input );
        length -= SHA256_BLOCK_SIZE;
        input  += SHA256_BLOCK_SIZE;
    }

    if( length )
    {
        memcpy( (void *) (ctx->buffer + left),
                (const void *) input, length );
    }
}

static guint8 sha256_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sha256_finish( sha256_context *ctx, guint8 digest[SHA256_DIGEST_LEN] )
{
    guint32 last, padn;
    guint64 total_length;
    guint8 msglen[8];

    total_length = ctx->total * 8;

    last = (guint32)(ctx->total % SHA256_BLOCK_SIZE);
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    PUT_UINT32( total_length >> 32, msglen, 0 );
    PUT_UINT32( total_length,  msglen, 4 );

    sha256_update( ctx, sha256_padding, padn );
    sha256_update( ctx, msglen, 8 );

    PUT_UINT32( ctx->state[0], digest,  0 );
    PUT_UINT32( ctx->state[1], digest,  4 );
    PUT_UINT32( ctx->state[2], digest,  8 );
    PUT_UINT32( ctx->state[3], digest, 12 );
    PUT_UINT32( ctx->state[4], digest, 16 );
    PUT_UINT32( ctx->state[5], digest, 20 );
    PUT_UINT32( ctx->state[6], digest, 24 );
    PUT_UINT32( ctx->state[7], digest, 28 );
}

void sha256_hmac_starts( sha256_hmac_context *hctx, const guint8 *key, guint32 keylen )
{
    guint32 i;
    guint8 k_ipad[SHA256_BLOCK_SIZE];
    guint8 key_compress[SHA256_DIGEST_LEN];

    memset( k_ipad, 0x36, SHA256_BLOCK_SIZE );
    memset( hctx->k_opad, 0x5C, SHA256_BLOCK_SIZE );

    if (keylen > SHA256_BLOCK_SIZE)
    {
        sha256_starts( &hctx->ctx );
        sha256_update( &hctx->ctx, key, keylen );
        sha256_finish( &hctx->ctx, key_compress );
        key = key_compress;
        keylen = SHA256_DIGEST_LEN;
    }

    for( i = 0; i < keylen; i++ )
    {
        k_ipad[i] ^= key[i];
        hctx->k_opad[i] ^= key[i];
    }

    sha256_starts( &hctx->ctx );
    sha256_update( &hctx->ctx, k_ipad, SHA256_BLOCK_SIZE );
}

void sha256_hmac_update( sha256_hmac_context *hctx, const guint8 *buf, guint32 buflen )
{
    sha256_update( &hctx->ctx, buf, buflen );
}

void sha256_hmac_finish( sha256_hmac_context *hctx, guint8 digest[SHA256_DIGEST_LEN] )
{
    guint8 tmpbuf[SHA256_DIGEST_LEN];

    sha256_finish( &hctx->ctx, tmpbuf );

    sha256_starts( &hctx->ctx );
    sha256_update( &hctx->ctx, hctx->k_opad, SHA256_BLOCK_SIZE );
    sha256_update( &hctx->ctx, tmpbuf, SHA256_DIGEST_LEN );
    sha256_finish( &hctx->ctx, digest );
}

void sha256_hmac( const guint8 *key, guint32 keylen, const guint8 *buf, guint32 buflen,
                  guint8 digest[SHA256_DIGEST_LEN] )
{
    sha256_hmac_context hctx;

    sha256_hmac_starts( &hctx, key, keylen );
    sha256_hmac_update( &hctx, buf, buflen );
    sha256_hmac_finish( &hctx, digest );
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
