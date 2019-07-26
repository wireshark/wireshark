/* wsgcrypt.c
 * Helper functions for libgcrypt
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2017 Erik de Jong
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wsgcrypt.h"
#include "ws_attributes.h"

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

#if GCRYPT_VERSION_NUMBER >= 0x010600
gcry_error_t ws_cmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen)
{
	gcry_mac_hd_t cmac_handle;
	gcry_error_t result = gcry_mac_open(&cmac_handle, algo, 0, NULL);
	if (result) {
		return result;
	}
	result = gcry_mac_setkey(cmac_handle, key, keylen);
	if (result) {
		gcry_mac_close(cmac_handle);
		return result;
	}
	gcry_mac_write(cmac_handle, buffer, length);
	result = gcry_mac_read(cmac_handle, digest, &keylen);
	gcry_mac_close(cmac_handle);
	return result;
}
#else
gcry_error_t ws_cmac_buffer(int algo _U_, void *digest _U_, const void *buffer _U_, size_t length _U_, const void *key _U_, size_t keylen _U_)
{
	return GPG_ERR_UNSUPPORTED_ALGORITHM;
}
#endif

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

size_t rsa_decrypt_inplace(const guint len, guchar* data, gcry_sexp_t pk, gboolean pkcs1_padding, char **err)
{
	gint        rc = 0;
	size_t      decr_len = 0, i = 0;
	gcry_sexp_t s_data = NULL, s_plain = NULL;
	gcry_mpi_t  encr_mpi = NULL, text = NULL;

	*err = NULL;

	/* create mpi representation of encrypted data */
	rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG, data, len, NULL);
	if (rc != 0 ) {
		*err = g_strdup_printf("can't convert data to mpi (size %d):%s", len, gcry_strerror(rc));
		return 0;
	}

	/* put the data into a simple list */
	rc = gcry_sexp_build(&s_data, NULL, "(enc-val(rsa(a%m)))", encr_mpi);
	if (rc != 0) {
		*err = g_strdup_printf("can't build encr_sexp:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_decrypt(&s_plain, s_data, pk);
	if (rc != 0)
	{
		*err = g_strdup_printf("can't decrypt key:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* convert plain text sexp to mpi format */
	text = gcry_sexp_nth_mpi(s_plain, 0, 0);
	if (! text) {
		*err = g_strdup("can't convert sexp to mpi");
		decr_len = 0;
		goto out;
	}

	/* compute size requested for plaintext buffer */
	rc = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &decr_len, text);
	if (rc != 0) {
		*err = g_strdup_printf("can't compute decr size:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* sanity check on out buffer */
	if (decr_len > len) {
		*err = g_strdup_printf("decrypted data is too long ?!? (%" G_GSIZE_MODIFIER "u max %d)", decr_len, len);
		decr_len = 0;
		goto out;
	}

	/* write plain text to newly allocated buffer */
	rc = gcry_mpi_print(GCRYMPI_FMT_USG, data, len, &decr_len, text);
	if (rc != 0) {
		*err = g_strdup_printf("can't print decr data to mpi (size %" G_GSIZE_MODIFIER "u):%s", decr_len, gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	if (pkcs1_padding) {
		/* strip the padding*/
		rc = 0;
		for (i = 1; i < decr_len; i++) {
			if (data[i] == 0) {
				rc = (gint) i+1;
				break;
			}
		}

		decr_len -= rc;
		memmove(data, data+rc, decr_len);
	}

out:
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_plain);
	gcry_mpi_release(encr_mpi);
	gcry_mpi_release(text);
	return decr_len;
}

gcry_error_t
hkdf_expand(int hashalgo, const guint8 *prk, guint prk_len, const guint8 *info, guint info_len,
            guint8 *out, guint out_len)
{
	// Current maximum hash output size: 48 bytes for SHA-384.
	guchar	        lastoutput[48];
	gcry_md_hd_t    h;
	gcry_error_t    err;
	const guint     hash_len = gcry_md_get_algo_dlen(hashalgo);

	/* Some sanity checks */
	if (!(out_len > 0 && out_len <= 255 * hash_len) ||
	    !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
		return GPG_ERR_INV_ARG;
	}

	err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
	if (err) {
		return err;
	}

	for (guint offset = 0; offset < out_len; offset += hash_len) {
		gcry_md_reset(h);
		gcry_md_setkey(h, prk, prk_len);                    /* Set PRK */
		if (offset > 0) {
			gcry_md_write(h, lastoutput, hash_len);     /* T(1..N) */
		}
		gcry_md_write(h, info, info_len);                   /* info */
		gcry_md_putc(h, (guint8) (offset / hash_len + 1));  /* constant 0x01..N */

		memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
		memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
	}

	gcry_md_close(h);
	return 0;
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
