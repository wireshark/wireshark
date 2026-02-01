/** @file
 *
 * Functions for RSA private key reading and use
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RSA_H__
#define __RSA_H__

#include <wireshark.h>
#include <gcrypt.h>

#ifdef HAVE_LIBGNUTLS
#include <stdio.h>
#include <gnutls/abstract.h>

/**
 * @brief Converts a GnuTLS RSA private key to a Libgcrypt S-expression.
 *
 * Translates a GnuTLS-managed RSA private key into a Libgcrypt `gcry_sexp_t` structure
 * for use in cryptographic operations such as signing or decryption.
 * On failure, sets an error message in `err`.
 *
 * @param priv_key The GnuTLS RSA private key to convert.
 * @param err Pointer to a string for error reporting (set on failure).
 * @return A Libgcrypt S-expression representing the RSA key, or NULL on error.
 */
WS_DLL_PUBLIC gcry_sexp_t rsa_privkey_to_sexp(gnutls_x509_privkey_t priv_key, char **err);

/**
 * @brief Load an RSA private key from specified file
 *
 * @param fp the file that contain the key data
 * @param [out] err   error message upon failure; NULL upon success
 * @return a pointer to the loaded key on success, or NULL upon failure
 */
WS_DLL_PUBLIC gnutls_x509_privkey_t rsa_load_pem_key(FILE* fp, char **err);

/**
 * @brief Load a RSA private key from a PKCS#12 file (DER or PEM format)
 *
 * @param fp          the file that contains the key data
 * @param cert_passwd password to decrypt the PKCS#12 file
 * @param [out] err   error message upon failure; NULL upon success
 * @return a pointer to the loaded key on success; NULL upon failure
 *
 * @note This returns the first private key found. A PKCS#12 file can in
 * theory contain many keys, but this is rare in practice.
 */
WS_DLL_PUBLIC gnutls_x509_privkey_t rsa_load_pkcs12(FILE* fp, const char *cert_passwd, char** err);
#endif

/**
 * @brief Frees an RSA private key object.
 *
 * Releases memory and resources associated with a previously allocated RSA private key.
 *
 * @param key Pointer to the RSA private key object to free.
 */
WS_DLL_PUBLIC void rsa_private_key_free(void * key);


#endif /* __RSA_H__ */
