/* eax.h
 * Encryption and decryption routines implementing the EAX' encryption mode
 * Copyright 2010, Edward J. Beroset, edward.j.beroset@us.elster.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef	_EAX_H
#define	_EAX_H

#include <glib.h>
#include "ws_symbol_export.h"

typedef struct tagMAC_T
{
    guint8 Mac[4];
} MAC_T;

#define EAX_MODE_CLEARTEXT_AUTH     1
#define EAX_MODE_CIPHERTEXT_AUTH    2

#define EAX_SIZEOF_KEY              16

/*!
 Decrypts cleartext data using EAX' mode (see ANSI Standard C12.22-2008).

 @param[in]	pN	pointer to cleartext (canonified form)
 @param[in]	pK	pointer to secret key
 @param[in,out] pC	pointer to ciphertext
 @param[in]	SizeN	byte length of cleartext (pN) buffer
 @param[in]	SizeK	byte length of secret key (pK)
 @param[in]	SizeC	byte length of ciphertext (pC) buffer
 @param[in]	pMac	four-byte Message Authentication Code
 @param[in]	Mode	EAX_MODE_CLEARTEXT_AUTH or EAX_MODE_CIPHERTEXT_AUTH
 @return		TRUE if message has been authenticated; FALSE if not
			authenticated, invalid Mode or error
 */
WS_DLL_PUBLIC
gboolean Eax_Decrypt(guint8 *pN, guint8 *pK, guint8 *pC,
                 guint32 SizeN, guint32 SizeK, guint32 SizeC, MAC_T *pMac,
		 guint8 Mode);

#endif
