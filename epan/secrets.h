/** @file
 * Secrets management and processing.
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SECRETS_H__
#define __SECRETS_H__

#include <inttypes.h>
#include <stdbool.h>

#include <glib.h>
#include "ws_symbol_export.h"
#include "cfile.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Interfaces for management and processing of secrets provided by external
 * sources (wiretap, key files, HSMs, etc.). Dissectors can register themselves
 * as consumers of these secrets.
 *
 * Future idea: provide helper functions to manage external files. Typically
 * these secrets can be erased when the file is truncated or deleted+created.
 * Additionally, these secrets are not tied to the lifetime of a capture file.
 *
 * Future idea: add a method for dissectors to mark secrets as "in use" such
 * that unused entries can be removed when saving those secrets to file.
 * Intended use case: read large TLS key log file (which is infrequently
 * truncated by the user) and store only the bare minimum keys.
 */

void secrets_init(void);
void secrets_cleanup(void);

#if 0
/**
 * Lifetime of provided secrets.
 * HSM: tie information to epan scope? (but if disconnected, clear state?)
 * wiretap pcang DSB: scoped to (capture) file.
 * tls.keylog_file pref: epan-scoped (but if the file is deleted, clear it)
 */
enum secrets_scope {
    SECRETS_SCOPE_EPAN,
    SECRETS_SCOPE_FILE,
};
#endif

#ifdef HAVE_LIBGNUTLS
/** Identifier for a RSA public key (a SHA-1 hash). */
struct cert_key_id {
    uint8_t key_id[20];
};
typedef struct cert_key_id cert_key_id_t;
#endif  /* HAVE_LIBGNUTLS */


/**
 * Callback for the wiretap secrets provider (wtap_new_secrets_callback_t).
 */
WS_DLL_PUBLIC void
secrets_wtap_callback(uint32_t secrets_type, const void *secrets, unsigned size);

/**
 * Receives a new block of secrets from an external source (wiretap or files).
 */
typedef void (*secrets_block_callback_t)(const void *secrets, unsigned size);

/**
 * Registers a consumer for pcapng Decryption Secrets Block (DSB). Only one
 * dissector can register a type.
 *
 * @param secrets_type A Secrets Type as defined in wiretap/secrets-types.h
 * @param cb Callback to be invoked for new secrets.
 */
WS_DLL_PUBLIC void
secrets_register_type(uint32_t secrets_type, secrets_block_callback_t cb);

typedef unsigned (*secret_inject_count_func)(void);
typedef bool (*secret_inject_export_func)(capture_file* cf);
typedef char* (*secret_export_func)(size_t* length);

/**
 * Registers a producer for pcapng Decryption Secrets Block (DSB).
 *
 * @param name Protocol abbreviation used by the UI to display secret type
 * @param count_func Callback function to provide number of secrets
 * @param inject_func Callback function to inject secrets into pcapng file
 * @param export_func Callback function to provide a stringified version of the secrets
 */
WS_DLL_PUBLIC void
secrets_register_inject_type(const char* name, secret_inject_count_func count_func, secret_inject_export_func inject_func, secret_export_func export_func);

typedef enum {
    SECRETS_EXPORT_SUCCESS = 0,
    SECRETS_INVALID_CAPTURE_FILE,
    SECRETS_UNKNOWN_PROTOCOL,
    SECRETS_NO_SECRETS,
    SECRETS_EXPORT_FAILED,
} secrets_export_values;

/**
 * Return the current number of secrets from a single registered protocol
 *
 * @param name Registered protocol abbreviation
 * @return Number of secrets registered to that protocol
 */
WS_DLL_PUBLIC unsigned
secrets_get_count(const char* name);

/**
 * Export the data for a pcapng Decryption Secrets Block (DSB) from a single registered
 * protocol.
 *
 * @param name Registered protocol abbreviation
 * @param cf Capture file to export to
 * @return Enumerated value for success or possible errors
 */
WS_DLL_PUBLIC secrets_export_values
secrets_export_dsb(const char* name, capture_file* cf);

/**
 * Export the data for secrets as a character string from a single registered protocol.
 *
 * @param name Registered protocol abbreviation
 * @param secrets Returned secret data. Caller is responsibile for g_ allocated memory returned
 * @param secrets_len Returned length of secrets data
 * @param num_secrets Number of secrets in the data
 * @return Enumerated value for success or possible errors
 */
WS_DLL_PUBLIC secrets_export_values
secrets_export(const char* name, char** secrets, size_t* secrets_len, unsigned* num_secrets);

/**
 * Iterate through all of the registered secret injection protocols and call
 * callback
 *
 * @param func Function to be called on each injector
 * @param param Optional data to be passed into the function as well
 */
WS_DLL_PUBLIC void
secrets_inject_foreach(GHFunc func, void* param);


#ifdef HAVE_LIBGNUTLS
/**
 * Retrieve a list of available key URIs. PKCS #11 token URIs begin with
 * "pkcs11:".
 *
 * @return A list of strings, free with g_slist_free_full(keys, g_free).
 */
WS_DLL_PUBLIC GSList *
secrets_get_available_keys(void);

/**
 * Checks whether a given PKCS #11 token or key file is valid.
 *
 * @param uri A value from secrets_get_available_keys() or a file path.
 * @param password A token PIN or key file password, may be NULL.
 * @param need_password Set to true if a password may be required. Nullable.
 * @param error The error string on failure, clean up with g_free. Nullable.
 * @return true if the key was valid, false otherwise.
 */
WS_DLL_PUBLIC bool
secrets_verify_key(const char *uri, const char *password, bool *need_password, char **error);

/** Returns a new hash table, mapping cert_key_id_t -> gnutls_privkey_t. */
GHashTable *privkey_hash_table_new(void);

/**
 * Tries to decrypt the given buffer using a private key identified by key_id.
 * The private key was loaded through the 'rsa_keys' UAT.
 *
 * @param key_id Identifier for the public key.
 * @param encr Encrypted input.
 * @param encr_len Size of encrypted input.
 * @param out Decrypted contents on success, free with g_free.
 * @param out_len Size of decrypted contents on success.
 * @return 0 if a private key was available and decryption succeeded, a negative
 * error code otherwise.
 */
WS_DLL_PUBLIC int
secrets_rsa_decrypt(const cert_key_id_t *key_id, const uint8_t *encr, int encr_len, uint8_t **out, int *out_len);
#endif  /* HAVE_LIBGNUTLS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SECRETS_H__ */
