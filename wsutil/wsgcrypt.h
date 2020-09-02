/* wsgcrypt.h
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

#include <ws_diag_control.h>
#include "ws_symbol_export.h"
#include <glib.h>

DIAG_OFF(deprecated-declarations)

#include <gcrypt.h>

DIAG_ON(deprecated-declarations)

/*
 * Define HAVE_LIBGCRYPT_AEAD here, because it's used in several source
 * files.
 */
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
/* Whether to provide support for authentication in addition to decryption. */
#define HAVE_LIBGCRYPT_AEAD
#endif

/*
 * Define some other "do we have?" items as well.
 */
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
/* Whether ChaCh20 PNE can be supported. */
#define HAVE_LIBGCRYPT_CHACHA20
/* Whether AEAD_CHACHA20_POLY1305 can be supported. */
#define HAVE_LIBGCRYPT_CHACHA20_POLY1305
#endif

#define HASH_MD5_LENGTH      16
#define HASH_SHA1_LENGTH     20
#define HASH_SHA2_224_LENGTH 28
#define HASH_SHA2_256_LENGTH 32
#define HASH_SHA2_384_LENGTH 48
#define HASH_SHA2_512_LENGTH 64

/* Convenience function to calculate the HMAC from the data in BUFFER
   of size LENGTH with key KEY of size KEYLEN using the algorithm ALGO avoiding the creating of a
   hash object. The hash is returned in the caller provided buffer
   DIGEST which must be large enough to hold the digest of the given
   algorithm. */
WS_DLL_PUBLIC gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen);

WS_DLL_PUBLIC gcry_error_t ws_cmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen);

/* Convenience function to encrypt 8 bytes in BUFFER with DES using the 56 bits KEY expanded to
   64 bits as key, encrypted data is returned in OUTPUT which must be at least 8 bytes large */
WS_DLL_PUBLIC void crypt_des_ecb(guint8 *output, const guint8 *buffer, const guint8 *key56);

/* Convenience function for RSA decryption. Returns decrypted length on success, 0 on failure */
WS_DLL_PUBLIC size_t rsa_decrypt_inplace(const guint len, guchar* data, gcry_sexp_t pk, gboolean pkcs1_padding, char **err);

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
hkdf_expand(int hashalgo, const guint8 *prk, guint prk_len, const guint8 *info, guint info_len,
            guint8 *out, guint out_len);

/*
 * Calculate HKDF-Extract(salt, IKM) -> PRK according to RFC 5869.
 * Caller MUST ensure that 'prk' is large enough to store the digest from hash
 * algorithm 'hashalgo' (e.g. 32 bytes for SHA-256).
 */
static inline gcry_error_t
hkdf_extract(int hashalgo, const guint8 *salt, size_t salt_len, const guint8 *ikm, size_t ikm_len, guint8 *prk)
{
    /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}


#endif /* __WSGCRYPT_H__ */
