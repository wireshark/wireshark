/*
 *  hmac.c
 *  
 *  HMAC: Keyed-Hashing for Message Authentication
 * 
 *  code copied from RFC 2104
 *
 * $Id:$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/emem.h>
#include <epan/tvbuff.h>
#include <epan/crypt/airpdcap_sha1.h>
#include <epan/crypt/crypt-md5.h>

#include "hmac.h"


/*
 ** Function: hmac_sha1
 */

void hmac_sha1(const guint8* text,gint text_len, const guint8* key, gint key_len, guint8 digest[20]) {
	SHA1_CONTEXT context;
	guint8 k_ipad[65];    /* inner padding -
		* key XORd with ipad
		*/
	guint8 k_opad[65];    /* outer padding -
		* key XORd with opad
		*/
	guint8 tk[20];
	int i;
	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
		
		SHA1_CONTEXT      tctx;
		
		sha1_init(&tctx);
		sha1_loop(&tctx, key, key_len);
		sha1_result(&tctx, tk);
		
		key = tk;
		key_len = 20;
	}
	
	/*
	 * the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 
	 
	 
	 Krawczyk, et. al.            Informational                      [Page 8]
	 
	 RFC 2104                          HMAC                     February 1997
	 
	 
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */
	
	/* start out by storing key in pads */
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_len);
	bcopy( key, k_opad, key_len);
	
	/* XOR key with ipad and opad values */
	for (i=0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/*
	 * perform inner SHA1
	 */
	sha1_init(&context);                   /* init context for 1st
		* pass */
	sha1_loop(&context, k_ipad, 64);      /* start with inner pad */
	sha1_loop(&context, text, text_len); /* then text of datagram */
	sha1_result(&context, digest);          /* finish up 1st pass */
	/*
	 * perform outer SHA1
	 */
	sha1_init(&context);                   /* init context for 2nd
		* pass */
	sha1_loop(&context, k_opad, 64);     /* start with outer pad */
	sha1_loop(&context, digest, 16);     /* then results of 1st
		* hash */
	sha1_result(&context, digest);          /* finish up 2nd pass */
}


