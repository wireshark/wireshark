/* rsa.h
 *
 * Functions for RSA private key reading and use
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
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

#ifndef __RSA_H__
#define __RSA_H__

#include "ws_symbol_export.h"
#include "wsgcrypt.h"

#ifdef HAVE_LIBGNUTLS
#include <stdio.h>
#include <gnutls/abstract.h>
WS_DLL_PUBLIC gcry_sexp_t rsa_privkey_to_sexp(gnutls_x509_privkey_t priv_key, char **err);

/**
 * Load an RSA private key from specified file
 * @param fp the file that contain the key data
 * @param [out] err   error message upon failure; NULL upon success
 * @return a pointer to the loaded key on success, or NULL upon failure
 */
WS_DLL_PUBLIC gnutls_x509_privkey_t rsa_load_pem_key(FILE* fp, char **err);

/**
 * Load a RSA private key from a PKCS#12 file (DER or PEM format)
 * @param fp          the file that contains the key data
 * @param cert_passwd password to decrypt the PKCS#12 file
 * @param [out] err   error message upon failure; NULL upon success
 * @return a pointer to the loaded key on success; NULL upon failure
 */
WS_DLL_PUBLIC gnutls_x509_privkey_t rsa_load_pkcs12(FILE* fp, const char *cert_passwd, char** err);
#endif

WS_DLL_PUBLIC void rsa_private_key_free(gpointer key);


#endif /* __RSA_H__ */
