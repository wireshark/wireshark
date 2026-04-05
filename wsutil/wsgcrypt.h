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

/**
 * @brief Compute HMAC over a buffer using the specified algorithm.
 *
 * Convenience function to calculate the HMAC from the data in `buffer`
 * of size `length` with key `key` of size `keylen` using the algorithm `algo`,
 * without explicitly creating a hash object. The result is written to the
 * caller-provided `digest` buffer, which must be large enough to hold the
 * digest for the selected algorithm.
 *
 * @param algo     HMAC algorithm identifier (e.g., GCRY_MD_SHA256).
 * @param digest   Output buffer for the computed HMAC.
 * @param buffer   Input data buffer.
 * @param length   Length of the input data in bytes.
 * @param key      Key used for HMAC computation.
 * @param keylen   Length of the key in bytes.
 * @return         GPG error code (0 on success).
 */
WS_DLL_PUBLIC gcry_error_t ws_hmac_buffer(int algo, void *digest,
                    const void *buffer, size_t length,
                    const void *key, size_t keylen);


/**
 * @brief Compute CMAC over a buffer using the specified algorithm.
 *
 * Convenience function to calculate the CMAC from the data in `buffer`
 * of size `length` with key `key` of size `keylen` using the algorithm `algo`.
 * The result is written to the caller-provided `digest` buffer, which must be
 * large enough to hold the digest for the selected algorithm.
 *
 * @param algo     CMAC algorithm identifier (e.g., GCRY_CIPHER_AES).
 * @param digest   Output buffer for the computed CMAC.
 * @param buffer   Input data buffer.
 * @param length   Length of the input data in bytes.
 * @param key      Key used for CMAC computation.
 * @param keylen   Length of the key in bytes.
 * @return         GPG error code (0 on success).
 */
WS_DLL_PUBLIC gcry_error_t ws_cmac_buffer(int algo, void *digest,
                    const void *buffer, size_t length,
                    const void *key, size_t keylen);


/**
 * @brief Encrypt 8 bytes using DES in ECB mode.
 *
 * Convenience function to encrypt 8 bytes from `buffer` using DES with a 56-bit key
 * expanded to 64 bits. The encrypted output is written to `output`, which must be
 * at least 8 bytes in size.
 *
 * @param output   Destination buffer for encrypted data (must be ≥ 8 bytes).
 * @param buffer   Source buffer containing 8 bytes of plaintext.
 * @param key56    56-bit DES key (expanded internally to 64 bits).
 */
WS_DLL_PUBLIC void crypt_des_ecb(uint8_t *output, const uint8_t *buffer, const uint8_t *key56);


/**
 * @brief Perform RSA decryption in-place.
 *
 * Decrypts the data in `data` using the RSA private key `pk`. The decryption is
 * performed in-place, and the function returns the length of the decrypted data
 * on success, or 0 on failure. Optionally applies PKCS#1 padding if `pkcs1_padding`
 * is true. If an error occurs, a descriptive message may be returned in `err`.
 *
 * @param len             Length of the encrypted input data.
 * @param data            Buffer containing encrypted data; overwritten with plaintext.
 * @param pk              RSA private key (gcry_sexp_t).
 * @param pkcs1_padding   Whether to apply PKCS#1 padding during decryption.
 * @param err             Optional pointer to receive error message (may be NULL).
 * @return                Length of decrypted data on success, 0 on failure.
 */
WS_DLL_PUBLIC size_t rsa_decrypt_inplace(const unsigned len, unsigned char* data,
                                         gcry_sexp_t pk, bool pkcs1_padding, char **err);


/**
 * @brief Perform HKDF-Expand as defined in RFC 5869.
 *
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

/**
 * @brief Perform HKDF-Extract as defined in RFC 5869.
 *
 * Computes the HMAC-based extract phase of the HKDF key derivation function:
 * HKDF-Extract(salt, IKM) → PRK. The salt is used as the HMAC key and the input
 * keying material (IKM) as the message. The resulting pseudo-random key (PRK)
 * is written to the caller-provided buffer.
 *
 * @param hashalgo   Libgcrypt hash algorithm identifier (e.g., GCRY_MD_SHA256).
 * @param salt       Optional salt value used as the HMAC key.
 * @param salt_len   Length of the salt in bytes.
 * @param ikm        Input keying material.
 * @param ikm_len    Length of the input keying material in bytes.
 * @param prk        Output buffer for the pseudo-random key. Must be large enough
 *                   to hold the digest size of the selected hash algorithm.
 * @return           0 on success, or a Libgcrypt error code on failure.
 */
static inline gcry_error_t
hkdf_extract(int hashalgo, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}

/**
 * @brief Return the output length of the HKDF for a given KDF identifier.
 *
 * Convenience function for Hybrid Public Key Encryption (HPKE) as specified in RFC 9180.
 * Returns the length of the HKDF output in bytes for the specified key derivation function (KDF).
 * The returned value must fit within a 16-bit integer to ensure compatibility with I2OSP(L, 2)
 * used in the ExpandedLabel construction.
 *
 * @param kdf_id  Identifier for the KDF algorithm (e.g., HPKE_KDF_HKDF_SHA256).
 * @return        Length of the HKDF output in bytes.
 */
WS_DLL_PUBLIC uint16_t
hpke_hkdf_len(uint16_t kdf_id);


/**
 * @brief Return the key length for a given AEAD algorithm identifier.
 *
 * Convenience function for Hybrid Public Key Encryption (HPKE) as specified in RFC 9180.
 * Returns the length in bytes of the symmetric key required by the AEAD algorithm.
 *
 * @param aead_id  AEAD algorithm identifier (e.g., HPKE_AEAD_AES_GCM_128).
 * @return         Key length in bytes.
 */
WS_DLL_PUBLIC uint16_t
hpke_aead_key_len(uint16_t aead_id);


/**
 * @brief Return the nonce length for a given AEAD algorithm identifier.
 *
 * Returns the length in bytes of the nonce required by the AEAD algorithm,
 * as specified in RFC 9180 for HPKE.
 *
 * @param aead_id  AEAD algorithm identifier.
 * @return         Nonce length in bytes.
 */
WS_DLL_PUBLIC uint16_t
hpke_aead_nonce_len(uint16_t aead_id);


/**
 * @brief Construct the HPKE suite identifier.
 *
 * Builds the suite ID byte string from the KEM, KDF, and AEAD identifiers,
 * as defined in RFC 9180. The resulting suite ID is written to the caller-provided
 * buffer `suite_id`, which must be at least 6 bytes long.
 *
 * @param kem_id     KEM algorithm identifier.
 * @param kdf_id     KDF algorithm identifier.
 * @param aead_id    AEAD algorithm identifier.
 * @param suite_id   Output buffer for the suite ID (must be ≥ 6 bytes).
 */
WS_DLL_PUBLIC void
hpke_suite_id(uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id, uint8_t *suite_id);


/**
 * @brief Derive HPKE key and base nonce using the key schedule.
 *
 * Implements the HPKE key schedule as defined in RFC 9180. Derives the symmetric
 * encryption key and base nonce from the input keying material (IKM), suite ID,
 * and optional salt, using the specified KDF and AEAD identifiers.
 *
 * @param kdf_id      KDF algorithm identifier.
 * @param aead_id     AEAD algorithm identifier.
 * @param salt        Optional salt value for key derivation.
 * @param salt_len    Length of the salt in bytes.
 * @param suite_id    Suite identifier (must be 6 bytes).
 * @param ikm         Input keying material.
 * @param ikm_len     Length of the IKM in bytes.
 * @param mode        HPKE mode (e.g., base, PSK, auth).
 * @param key         Output buffer for the derived symmetric key.
 * @param base_nonce  Output buffer for the derived base nonce.
 * @return            0 on success, or a Libgcrypt error code on failure.
 */
WS_DLL_PUBLIC gcry_error_t
hpke_key_schedule(uint16_t kdf_id, uint16_t aead_id,
                  const uint8_t *salt, unsigned salt_len,
                  const uint8_t *suite_id,
                  const uint8_t *ikm, unsigned ikm_len,
                  uint8_t mode, uint8_t *key, uint8_t *base_nonce);


/**
 * @brief Initialize AEAD cipher context for HPKE.
 *
 * Sets up the AEAD cipher handle using the specified AEAD algorithm and key.
 * This function prepares the cipher for encryption or decryption operations.
 *
 * @param cipher   Pointer to the cipher handle to initialize.
 * @param aead_id  AEAD algorithm identifier.
 * @param key      Symmetric key for AEAD encryption/decryption.
 * @return         0 on success, or a Libgcrypt error code on failure.
 */
WS_DLL_PUBLIC gcry_error_t
hpke_setup_aead(gcry_cipher_hd_t* cipher, uint16_t aead_id, uint8_t *key);


/**
 * @brief Set the nonce for an AEAD cipher using sequence number and base nonce.
 *
 * Computes the AEAD nonce by XORing the base nonce with the sequence number,
 * as specified in RFC 9180. Updates the cipher context with the resulting nonce.
 *
 * @param cipher      AEAD cipher handle.
 * @param seq         Sequence number for the message.
 * @param base_nonce  Base nonce derived from the key schedule.
 * @param nonce_len   Length of the nonce in bytes.
 * @return            0 on success, or a Libgcrypt error code on failure.
 */
WS_DLL_PUBLIC gcry_error_t
hpke_set_nonce(gcry_cipher_hd_t cipher, uint64_t seq,
               uint8_t *base_nonce, size_t nonce_len);


#endif /* __WSGCRYPT_H__ */
