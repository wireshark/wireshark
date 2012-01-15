/* $Id$ */
/* 
 * Copyright (C) 2003-2005 Benny Prijono <benny@prijono.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
#ifndef __MD5_H__ /**@todo Should this be _CRYPT_MD5_H__ ?*/
#define __MD5_H__

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
void md5_init(md5_state_t *pms);

/** Append a string to the message. 
 *  @param pms		MD5 context.
 *  @param data		Data.
 *  @param nbytes	Length of data.
 */
void md5_append( md5_state_t *pms, 
			     const guint8 *data, size_t nbytes);

/** Finish the message and return the digest. 
 *  @param pms		MD5 context.
 *  @param digest	16 byte digest.
 */
void md5_finish(md5_state_t *pms, guint8 digest[16]);


void md5_hmac(const guint8* text, size_t text_len, const guint8* key, size_t key_len, guint8 digest[16]);

/*
 * @}
 */

#endif	/* _CRYPT_MD5_H__ */
