/*
 * Copyright (C) 2003-2005 Benny Prijono <benny@prijono.org>
 * Copyright (C) 2012      C Elston, Katalix Systems Ltd <celston@katalix.com>
 *
 * MD5 code from pjlib-util http://www.pjsip.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *  2012-08-21 - C Elston - Split md5_hmac function to allow incremental usage.
 *
 */
#ifndef __MD5_H__ /**@todo Should this be _CRYPT_MD5_H__ ?*/
#define __MD5_H__

#include "ws_symbol_export.h"

/**
 * @file md5.h
 * @brief MD5 Functions
 */

/* Don't define this group for Wireshark
 * @defgroup PJLIB_UTIL_MD5 MD5 Functions
 * @ingroup PJLIB_UTIL
 * @{
 */

#define md5_byte_t guint8

/** MD5 context. */
typedef struct md5_state_s
{
	guint32 buf[4];
	guint32 bits[2];
	guint32 in[16];
} md5_state_t;

/** Initialize the algorithm.
 *  @param pms		MD5 context.
 */
WS_DLL_PUBLIC
void md5_init(md5_state_t *pms);

/** Append a string to the message.
 *  @param pms		MD5 context.
 *  @param data		Data.
 *  @param nbytes	Length of data.
 */
WS_DLL_PUBLIC
void md5_append( md5_state_t *pms,
			     const guint8 *data, size_t nbytes);

/** Finish the message and return the digest.
 *  @param pms		MD5 context.
 *  @param digest	16 byte digest.
 */
WS_DLL_PUBLIC
void md5_finish(md5_state_t *pms, guint8 digest[16]);

typedef struct md5_hmac_state_s
{
    md5_state_t ctx;
    guint8 k_opad[65];
} md5_hmac_state_t;

WS_DLL_PUBLIC
void md5_hmac_init(md5_hmac_state_t *hctx,
                   const guint8* key, size_t key_len);

WS_DLL_PUBLIC
void md5_hmac_append(md5_hmac_state_t *hctx,
                     const guint8* text, size_t text_len);

WS_DLL_PUBLIC
void md5_hmac_finish(md5_hmac_state_t *hctx, guint8 digest[16]);

WS_DLL_PUBLIC
void md5_hmac(const guint8* text, size_t text_len, const guint8* key,
              size_t key_len, guint8 digest[16]);

/*
 * @}
 */

#endif	/* _CRYPT_MD5_H__ */
