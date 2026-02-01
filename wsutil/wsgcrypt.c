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

gcry_error_t
crypt_des_ecb(uint8_t *output, const uint8_t *buffer, const uint8_t *key56)
{
	uint8_t key64[8];
	gcry_cipher_hd_t handle;
	gcry_error_t err;

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

	if ((err = gcry_cipher_open(&handle, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0))) {
		return err;
	}
	if ((err = gcry_cipher_setkey(handle, key64, 8))) {
		gcry_cipher_close(handle);
		return err;
	}
	err = gcry_cipher_encrypt(handle, output, 8, buffer, 8);
	gcry_cipher_close(handle);
	return err;
}

size_t rsa_decrypt_inplace(const unsigned len, unsigned char* data, gcry_sexp_t pk, bool pkcs1_padding, char **err)
{
	gcry_error_t rc = 0;
	size_t       decr_len = 0;
	gcry_sexp_t  s_data = NULL, s_plain = NULL;
	gcry_mpi_t   encr_mpi = NULL;
	const char  *text;

	*err = NULL;

	/* create mpi representation of encrypted data */
	rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG, data, len, NULL);
	if (rc != 0 ) {
		*err = ws_strdup_printf("can't convert data to mpi (size %d):%s", len, gcry_strerror(rc));
		return 0;
	}

	/* put the data into a simple list */
	rc = gcry_sexp_build(&s_data, NULL, "(enc-val(flags %s)(rsa(a%m)))", pkcs1_padding ? "pkcs1" : "raw", encr_mpi);
	if (rc != 0) {
		*err = ws_strdup_printf("can't build encr_sexp:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_decrypt(&s_plain, s_data, pk);
	if (rc != 0)
	{
		*err = ws_strdup_printf("can't decrypt key:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* get pointer to plaintext buffer and its length */
        text = gcry_sexp_nth_data(s_plain, 1, &decr_len);
	if (!text) {
		*err = g_strdup("can't retrieve plaintext from sexp");
		decr_len = 0;
		goto out;
	}

	/* sanity check on out buffer */
	if (decr_len > len) {
		*err = ws_strdup_printf("decrypted data is too long ?!? (%zu max %d)", decr_len, len);
		decr_len = 0;
		goto out;
	}

	/* write plain text to newly allocated buffer */
        memcpy(data, text, decr_len);

out:
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_plain);
	gcry_mpi_release(encr_mpi);
	return decr_len;
}

size_t rsa_decrypt(const unsigned len, const unsigned char* data, uint8_t** plain, gcry_sexp_t pk, const char* flags, char **err)
{
	gcry_error_t rc = 0;
	size_t       decr_len = 0;
	gcry_sexp_t  s_data = NULL, s_plain = NULL;
	gcry_mpi_t   encr_mpi = NULL;
        const char  *text;

	*err = NULL;

	/* create mpi representation of encrypted data */
	rc = gcry_mpi_scan(&encr_mpi, GCRYMPI_FMT_USG, data, len, NULL);
	if (rc != 0 ) {
		*err = ws_strdup_printf("can't convert data to mpi (size %d):%s", len, gcry_strerror(rc));
		return 0;
	}

	/* put the data into a simple list */
	rc = gcry_sexp_build(&s_data, NULL, "(enc-val(flags %s)(rsa(a%m)))", flags ? flags : "raw", encr_mpi);
	if (rc != 0) {
		*err = ws_strdup_printf("can't build encr_sexp:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* pass it to libgcrypt */
	rc = gcry_pk_decrypt(&s_plain, s_data, pk);
	if (rc != 0)
	{
		*err = ws_strdup_printf("can't decrypt key:%s", gcry_strerror(rc));
		decr_len = 0;
		goto out;
	}

	/* get pointer to plaintext buffer and its length */
	/* (We don't use gcry_sexp_nth_buffer to avoid making
	 * plain have to be freed with gcry_free; we don't care
	 * about not zeroing the decrypted data.) */
	text = gcry_sexp_nth_data(s_plain, 1, &decr_len);
	if (!text) {
		*err = g_strdup("can't retrieve plaintext from sexp");
		decr_len = 0;
		goto out;
	}

	/* write plain text to newly allocated buffer */
	*plain = g_memdup2(text, decr_len);

out:
	gcry_sexp_release(s_data);
	gcry_sexp_release(s_plain);
	gcry_mpi_release(encr_mpi);
	return decr_len;
}

gcry_error_t
hkdf_expand(int hashalgo, const uint8_t *prk, unsigned prk_len, const uint8_t *info, unsigned info_len,
            uint8_t *out, unsigned out_len)
{
	// Current maximum hash output size: 48 bytes for SHA-384.
	unsigned char	        lastoutput[48];
	gcry_md_hd_t    h;
	gcry_error_t    err;
	const unsigned  hash_len = gcry_md_get_algo_dlen(hashalgo);

	/* Some sanity checks */
	if (!(out_len > 0 && out_len <= 255 * hash_len) ||
	    !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
		return GPG_ERR_INV_ARG;
	}

	err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
	if (err) {
		return err;
	}

	for (unsigned offset = 0; offset < out_len; offset += hash_len) {
		gcry_md_reset(h);
		err = gcry_md_setkey(h, prk, prk_len);              /* Set PRK */
		if (err) {
		    gcry_md_close(h);
		    return err;
		}
		if (offset > 0) {
			gcry_md_write(h, lastoutput, hash_len);     /* T(1..N) */
		}
		gcry_md_write(h, info, info_len);                   /* info */
		gcry_md_putc(h, (uint8_t) (offset / hash_len + 1));  /* constant 0x01..N */

		memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
		memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
	}

	gcry_md_close(h);
	return 0;
}

gcry_error_t
hpke_extract(uint16_t kdf_id, const uint8_t *salt, unsigned salt_len, const uint8_t *suite_id, const char *label,
             const uint8_t *ikm, unsigned ikm_len, uint8_t *out)
{
    int hashalgo;
    gcry_md_hd_t hmac_handle;
    switch (kdf_id) {
        case HPKE_HKDF_SHA256:
            hashalgo = GCRY_MD_SHA256;
            break;
        case HPKE_HKDF_SHA384:
            hashalgo = GCRY_MD_SHA384;
            break;
        case HPKE_HKDF_SHA512:
            hashalgo = GCRY_MD_SHA512;
            break;
        default:
            return GPG_ERR_DIGEST_ALGO;
    }
    gcry_error_t result = gcry_md_open(&hmac_handle, hashalgo, GCRY_MD_FLAG_HMAC);
    if (result) {
		return result;
    }
    result = gcry_md_setkey(hmac_handle, salt, salt_len);
    if (result) {
		gcry_md_close(hmac_handle);
        return result;
    }
    gcry_md_write(hmac_handle, HPKE_VERSION_ID, sizeof(HPKE_VERSION_ID) - 1);
    gcry_md_write(hmac_handle, suite_id, HPKE_SUIT_ID_LEN);
    gcry_md_write(hmac_handle, label, strlen(label));
    gcry_md_write(hmac_handle, ikm, ikm_len);
    memcpy(out, gcry_md_read(hmac_handle, 0), hpke_hkdf_len(kdf_id));
    gcry_md_close(hmac_handle);
    return GPG_ERR_NO_ERROR;
}

uint16_t
hpke_hkdf_len(uint16_t kdf_id)
{
    switch (kdf_id) {
        case HPKE_HKDF_SHA256:
            return HASH_SHA2_256_LENGTH;
        case HPKE_HKDF_SHA384:
            return HASH_SHA2_384_LENGTH;
        case HPKE_HKDF_SHA512:
            return HASH_SHA2_512_LENGTH;
        default:
            return 0;
    }
}

uint16_t
hpke_aead_key_len(uint16_t aead_id)
{
    switch (aead_id) {
	case HPKE_AEAD_AES_128_GCM:
            return AEAD_AES_128_GCM_KEY_LENGTH;
        case HPKE_AEAD_AES_256_GCM:
            return AEAD_AES_256_GCM_KEY_LENGTH;
        case HPKE_AEAD_CHACHA20POLY1305:
            return AEAD_CHACHA20POLY1305_KEY_LENGTH;
        default:
            return 0;
    }
}

uint16_t
hpke_aead_nonce_len(uint16_t aead_id)
{
    switch (aead_id) {
	case HPKE_AEAD_AES_128_GCM:
        case HPKE_AEAD_AES_256_GCM:
        case HPKE_AEAD_CHACHA20POLY1305:
            return HPKE_AEAD_NONCE_LENGTH;
        default:
            return 0;
    }
}

void
hpke_suite_id(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id, uint8_t *suite_id)
{
    uint8_t offset = 0;
    memcpy(suite_id, HPKE_SUIT_PREFIX, sizeof(HPKE_SUIT_PREFIX) - 1);
    offset += sizeof(HPKE_SUIT_PREFIX) - 1;
    suite_id[offset++] = (kem_id >> 8) & 0xFF;
    suite_id[offset++] = kem_id & 0xFF;
    suite_id[offset++] = (kdf_id >> 8) & 0xFF;
    suite_id[offset++] = kdf_id & 0xFF;
    suite_id[offset++] = (aead_id >> 8) & 0xFF;
    suite_id[offset++] = aead_id & 0xFF;
}

static gcry_error_t
hpke_expand(uint16_t kdf_id, const uint8_t *prk, const uint8_t *suite_id, const char *label,
            const uint8_t *info, uint8_t *out, uint16_t out_len)
{
    int hashalgo;
    GByteArray * labeled_info = g_byte_array_new();
    uint16_t out_len_be = GUINT16_TO_BE(out_len);
    gcry_error_t result;
    switch (kdf_id) {
	case HPKE_HKDF_SHA256:
            hashalgo = GCRY_MD_SHA256;
            break;
        case HPKE_HKDF_SHA384:
            hashalgo = GCRY_MD_SHA384;
            break;
	case HPKE_HKDF_SHA512:
            hashalgo = GCRY_MD_SHA512;
            break;
        default:
            return GPG_ERR_DIGEST_ALGO;
    }
    g_byte_array_append(labeled_info, (uint8_t *)&out_len_be, 2);
    g_byte_array_append(labeled_info, (const uint8_t*)HPKE_VERSION_ID, sizeof(HPKE_VERSION_ID) - 1);
    g_byte_array_append(labeled_info, suite_id, HPKE_SUIT_ID_LEN);
    g_byte_array_append(labeled_info, (const uint8_t*)label, (unsigned)strlen(label));
    g_byte_array_append(labeled_info, info, (unsigned)(1 + hpke_hkdf_len(kdf_id) * 2));
    result = hkdf_expand(hashalgo, prk, (unsigned)hpke_hkdf_len(kdf_id), labeled_info->data, labeled_info->len, out, out_len);
    g_byte_array_free(labeled_info, TRUE);
    return result;
}

gcry_error_t
hpke_key_schedule(uint16_t kdf_id, uint16_t aead_id, const uint8_t *salt, unsigned salt_len, const uint8_t *suite_id,
                  const uint8_t *ikm, unsigned ikm_len, uint8_t mode, uint8_t *key, uint8_t *base_nonce)
{
    uint8_t secret[HPKE_MAX_KDF_LEN];
    uint8_t context[HPKE_MAX_KDF_LEN * 2 + 1];
    size_t kdf_len = hpke_hkdf_len(kdf_id);
    context[0] = mode;
    gcry_error_t result = hpke_extract(kdf_id, NULL, 0, suite_id, "psk_id_hash", NULL, 0, context + 1);
    if (result) {
        return result;
    }
    result = hpke_extract(kdf_id, NULL, 0, suite_id, "info_hash", ikm, ikm_len, context + 1 + kdf_len);
    if (result) {
        return result;
    }
    result = hpke_extract(kdf_id, salt, salt_len, suite_id, "secret", NULL, 0, secret);
    if (result) {
        return result;
    }
    result = hpke_expand(kdf_id, secret, suite_id, "key", context, key, hpke_aead_key_len(aead_id));
    if (result) {
        return result;
    }
    result = hpke_expand(kdf_id, secret, suite_id, "base_nonce", context, base_nonce, hpke_aead_nonce_len(aead_id));
    return result;
}

gcry_error_t
hpke_setup_aead(gcry_cipher_hd_t* cipher, uint16_t aead_id, uint8_t *key)
{
    gcry_error_t err;
    switch (aead_id) {
        case HPKE_AEAD_AES_128_GCM:
            err = gcry_cipher_open(cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
            break;
        case HPKE_AEAD_AES_256_GCM:
            err = gcry_cipher_open(cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
            break;
        case HPKE_AEAD_CHACHA20POLY1305:
            err = gcry_cipher_open(cipher, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0);
            break;
        default:
            return GPG_ERR_CIPHER_ALGO;
    }
    if (err)
		return err;
    return gcry_cipher_setkey(*(cipher), key, hpke_aead_key_len(aead_id));
}

gcry_error_t
hpke_set_nonce(gcry_cipher_hd_t cipher, uint64_t seq, uint8_t *base_nonce, size_t nonce_len)
{
    size_t i;
    uint8_t *nonce = (uint8_t *)wmem_alloc0(NULL, nonce_len);
    gcry_error_t err;

    for (i = 1; i < 9; i++) {
        nonce[nonce_len - i] = seq & 255;
        seq >>= 8;
    }
    for (i = 0; i < nonce_len; i++) {
        nonce[i] ^= base_nonce[i];
    }
    err = gcry_cipher_setiv(cipher, nonce, nonce_len);
    wmem_free(NULL, nonce);
    return err;
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
