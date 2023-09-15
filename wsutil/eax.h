/** @file
 * Encryption and decryption routines implementing the EAX' encryption mode
 * Copyright 2010, Edward J. Beroset, edward.j.beroset@us.elster.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef	_EAX_H
#define	_EAX_H

#include <wireshark.h>

typedef struct tagMAC_T
{
    uint8_t Mac[4];
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
 @return		true if message has been authenticated; false if not
			authenticated, invalid Mode or error
 */
WS_DLL_PUBLIC
bool Eax_Decrypt(uint8_t *pN, uint8_t *pK, uint8_t *pC,
                 uint32_t SizeN, uint32_t SizeK, uint32_t SizeC, MAC_T *pMac,
		 uint8_t Mode);

#endif
