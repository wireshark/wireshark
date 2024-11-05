/** @file
 *
 * Wrapper around libgcrypt's include file gcrypt.h.
 * For libgcrypt 1.5.0, including gcrypt.h directly brings up lots of
 * compiler warnings about deprecated definitions.
 * Try to work around these warnings to ensure a clean build with -Werror.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSGCRYPT_H__
#define __WSGCRYPT_H__

#include <wireshark.h>
#include <gcrypt.h>

#define HASH_MD5_LENGTH                    16
#define HASH_SHA1_LENGTH                   20
#define HASH_SHA2_224_LENGTH               28
#define HASH_SHA2_256_LENGTH               32
#define HASH_SHA2_384_LENGTH               48
#define HASH_SHA2_512_LENGTH               64
#define AEAD_AES_128_GCM_KEY_LENGTH        16
#define AEAD_AES_256_GCM_KEY_LENGTH        32
#define AEAD_CHACHA20POLY1305_KEY_LENGTH   32
#define AEAD_MAX_KEY_LENGTH                32
#define HPKE_AEAD_NONCE_LENGTH             12
#define HPKE_HKDF_SHA256                    1
#define HPKE_HKDF_SHA384                    2
#define HPKE_HKDF_SHA512                    3
#define HPKE_AEAD_AES_128_GCM               1
#define HPKE_AEAD_AES_256_GCM               2
#define HPKE_AEAD_CHACHA20POLY1305          3
#define HPKE_SUIT_ID_LEN                   10
#define HPKE_SUIT_PREFIX               "HPKE"
#define HPKE_VERSION_ID             "HPKE-v1"
#define HPKE_MAX_KDF_LEN HASH_SHA2_512_LENGTH
#define HPKE_MODE_BASE                      0
#define HPKE_MODE_PSK                       1
#define HPKE_MODE_AUTH                      2
#define HPKE_MODE_AUTH_PSK                  3

/* Convenience function to calculate the HMAC from the data in BUFFER
   of size LENGTH with key KEY of size KEYLEN using the algorithm ALGO avoiding the creating of a
   hash object. The hash is returned in the caller provided buffer
   DIGEST which must be large enough to hold the digest of the given
   algorithm. */
WS_DLL_PUBLIC gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen);

WS_DLL_PUBLIC gcry_error_t ws_cmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen);

/* Convenience function to encrypt 8 bytes in BUFFER with DES using the 56 bits KEY expanded to
   64 bits as key, encrypted data is returned in OUTPUT which must be at least 8 bytes large */
WS_DLL_PUBLIC void crypt_des_ecb(uint8_t *output, const uint8_t *buffer, const uint8_t *key56);

/* Convenience function for RSA decryption. Returns decrypted length on success, 0 on failure */
WS_DLL_PUBLIC size_t rsa_decrypt_inplace(const unsigned len, unsigned char* data, gcry_sexp_t pk, bool pkcs1_padding, char **err);

/**
 * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
 * HKDF-Expand(PRK, info, L) -> OKM
 *
 * @param hashalgo  [in] Libgcrypt hash algorithm identifier.
 * @param prk       [in] Pseudo-random key.
 * @param prk_len   [in] Length of prk.
 * @param info      [in] Optional context (can be NULL if info_len is zero).
 * @param info_len  [in] Length of info.
 * @param out       [out] Output keying material.
 * @param out_len   [in] Size of output keying material.
 * @return 0 on success and an error code otherwise.
 */
WS_DLL_PUBLIC gcry_error_t
hkdf_expand(int hashalgo, const uint8_t *prk, unsigned prk_len, const uint8_t *info, unsigned info_len,
            uint8_t *out, unsigned out_len);

/*
 * Calculate HKDF-Extract(salt, IKM) -> PRK according to RFC 5869.
 * Caller MUST ensure that 'prk' is large enough to store the digest from hash
 * algorithm 'hashalgo' (e.g. 32 bytes for SHA-256).
 */
static inline gcry_error_t
hkdf_extract(int hashalgo, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}

WS_DLL_PUBLIC size_t
hpke_hkdf_len(uint16_t kdf_id);

WS_DLL_PUBLIC size_t
hpke_aead_key_len(uint16_t aead_id);

WS_DLL_PUBLIC size_t
hpke_aead_nonce_len(uint16_t aead_id);

WS_DLL_PUBLIC void
hpke_suite_id(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id, uint8_t *suite_id);

WS_DLL_PUBLIC gcry_error_t
hpke_key_schedule(uint16_t kdf_id, uint16_t aead_id, const uint8_t *salt, unsigned salt_len, const uint8_t *suite_id,
                  const uint8_t *ikm, unsigned ikm_len, uint8_t mode, uint8_t *key, uint8_t *base_nonce);

WS_DLL_PUBLIC gcry_error_t
hpke_setup_aead(gcry_cipher_hd_t* cipher, uint16_t aead_id, uint8_t *key);

WS_DLL_PUBLIC gcry_error_t
hpke_set_nonce(gcry_cipher_hd_t cipher, uint64_t seq, uint8_t *base_nonce, size_t nonce_len);

#endif /* __WSGCRYPT_H__ */
