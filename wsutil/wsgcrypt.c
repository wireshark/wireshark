/* wsgcrypt.c
 * Helper functions for libgcrypt
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2017 Erik de Jong
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
 *
 */

#include "wsgcrypt.h"

gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen)
{
	gcry_md_hd_t hmac_handle;
	gcry_error_t result = gcry_md_open(&hmac_handle, algo, GCRY_MD_FLAG_HMAC);
	if (result) {
		return result;
	}
	result = gcry_md_setkey(hmac_handle, key, keylen);
	if (result) {
		gcry_md_close(hmac_handle);
		return result;
	}
	gcry_md_write(hmac_handle, buffer, length);
	memcpy(digest, gcry_md_read(hmac_handle, 0), gcry_md_get_algo_dlen(algo));
	gcry_md_close(hmac_handle);
	return GPG_ERR_NO_ERROR;
}

void crypt_des_ecb(guint8 *output, const guint8 *buffer, const guint8 *key56)
{
	guint8 key64[8];
	gcry_cipher_hd_t handle;

	memset(output, 0x00, 8);

	/* Transform 56 bits key into 64 bits DES key */
	key64[0] = key56[0];
	key64[1] = (key56[0] << 7) | (key56[1] >> 1);
	key64[2] = (key56[1] << 6) | (key56[2] >> 2);
	key64[3] = (key56[2] << 5) | (key56[3] >> 3);
	key64[4] = (key56[3] << 4) | (key56[4] >> 4);
	key64[5] = (key56[4] << 3) | (key56[5] >> 5);
	key64[6] = (key56[5] << 2) | (key56[6] >> 6);
	key64[7] = (key56[6] << 1);

	if (gcry_cipher_open(&handle, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0)) {
		return;
	}
	if (gcry_cipher_setkey(handle, key64, 8)) {
		gcry_cipher_close(handle);
		return;
	}
	gcry_cipher_encrypt(handle, output, 8, buffer, 8);
	gcry_cipher_close(handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
