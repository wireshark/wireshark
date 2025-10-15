/* dot11decrypt_wep.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <wsutil/crc32.h>
#include <wsutil/wsgcrypt.h>

int Dot11DecryptWepDecrypt(
	const unsigned char *seed,
	size_t seed_len,
	unsigned char *cypher_text,
	size_t data_len)
{
	int ret = 1/*DOT11DECRYPT_RET_UNSUCCESS*/;
	gcry_cipher_hd_t chd;
	uint8_t icv[4];
	uint32_t icv_le;
	uint32_t crc32;

	if (gcry_cipher_open(&chd, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0)) {
		goto err_cipher_out;
	}
	if (gcry_cipher_setkey(chd, seed, seed_len)) {
		goto err_out;
	}
	/* Decrypt data (RC4) */
	if (gcry_cipher_encrypt(chd, cypher_text, data_len, NULL, 0)) {
		goto err_out;
	}
	/* Decrypt icv (RC4) */
	if (gcry_cipher_encrypt(chd, icv, 4, cypher_text + data_len, 4)) {
		goto err_out;
	}
	/* Integrity check (CRC32 on decrypted data) */
	crc32 = crc32_ccitt(cypher_text, (unsigned int)data_len);
	icv_le = GUINT32_FROM_LE(*(uint32_t *)icv);
	ret = (crc32 == icv_le) ? 0 : 1; /* DOT11DECRYPT_RET_SUCCESS/UNSUCCESS */

err_out:
	gcry_cipher_close(chd);
err_cipher_out:
	return ret;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
