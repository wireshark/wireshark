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

 */

#ifndef _SHA2_H
#define _SHA2_H

#include "ws_symbol_export.h"

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_SIZE 64

typedef struct
{
    guint64 total;
    guint32 state[8];
    guint8 buffer[SHA256_BLOCK_SIZE];
}
    sha256_context;

WS_DLL_PUBLIC
void sha256_starts( sha256_context *ctx );
WS_DLL_PUBLIC
void sha256_update( sha256_context *ctx, const guint8 *input, guint32 length );
WS_DLL_PUBLIC
void sha256_finish( sha256_context *ctx, guint8 digest[SHA256_DIGEST_LEN] );


typedef struct {
    sha256_context ctx;
    guint8 k_opad[SHA256_BLOCK_SIZE];
}
    sha256_hmac_context;

WS_DLL_PUBLIC
void sha256_hmac_starts( sha256_hmac_context *hctx, const guint8 *key, guint32 keylen );
WS_DLL_PUBLIC
void sha256_hmac_update( sha256_hmac_context *hctx, const guint8 *buf, guint32 buflen );
WS_DLL_PUBLIC
void sha256_hmac_finish( sha256_hmac_context *hctx, guint8 digest[SHA256_DIGEST_LEN] );
WS_DLL_PUBLIC
void sha256_hmac( const guint8 *key, guint32 keylen, const guint8 *buf, guint32 buflen,
                  guint8 digest[SHA256_DIGEST_LEN] );



#endif /* _SHA2_H */

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
