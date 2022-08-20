/* secrets.c
 * Secrets management and processing.
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

#include "secrets.h"
#include <wiretap/wtap.h>
#include <wsutil/glib-compat.h>
#include <wsutil/wslog.h>

#include <string.h>
#ifdef HAVE_LIBGNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/abstract.h>
# include <wsutil/wsgcrypt.h>
# include <wsutil/rsa.h>
# include <epan/uat.h>
# include <wsutil/report_message.h>
# include <wsutil/file_util.h>
# include <errno.h>
#endif  /* HAVE_LIBGNUTLS */

#ifdef _WIN32
#include <windows.h>
#endif

/** Maps guint32 secrets_type -> secrets_block_callback_t. */
static GHashTable *secrets_callbacks;

#ifdef HAVE_LIBGNUTLS
/** Maps public key IDs (cert_key_id_t) -> gnutls_privkey_t.  */
static GHashTable *rsa_privkeys;

typedef struct {
    char *uri;              /**< User-supplied PKCS #11 URI for token or RSA private key file. */
    char *password;         /**< User-supplied PKCS #11 PIN or RSA private key file password. */
} rsa_privkey_record_t;

static uat_t *rsa_privkeys_uat;
static rsa_privkey_record_t *uat_rsa_privkeys;
static guint uat_num_rsa_privkeys;

static void register_rsa_uats(void);
#endif  /* HAVE_LIBGNUTLS */

#ifdef HAVE_GNUTLS_PKCS11
/** PINs for PKCS #11 keys in rsa_privkeys. Must be cleared after rsa_privkeys. */
static GSList *rsa_privkeys_pkcs11_pins;

typedef struct {
    char *library_path;     /**< PKCS #11 library path. */
} pkcs11_lib_record_t;

static uat_t *pkcs11_libs_uat;
static pkcs11_lib_record_t *uat_pkcs11_libs;
static guint uat_num_pkcs11_libs;
#endif  /* HAVE_GNUTLS_PKCS11 */

void
secrets_init(void)
{
    secrets_callbacks = g_hash_table_new(g_direct_hash, g_direct_equal);
#ifdef HAVE_LIBGNUTLS
    rsa_privkeys = privkey_hash_table_new();
    register_rsa_uats();
#endif  /* HAVE_LIBGNUTLS */
}

void
secrets_cleanup(void)
{
    g_hash_table_destroy(secrets_callbacks);
    secrets_callbacks = NULL;
#ifdef HAVE_LIBGNUTLS
    g_hash_table_destroy(rsa_privkeys);
    rsa_privkeys = NULL;
#ifdef HAVE_GNUTLS_PKCS11
    g_slist_free_full(rsa_privkeys_pkcs11_pins, g_free);
    rsa_privkeys_pkcs11_pins = NULL;
#endif  /* HAVE_GNUTLS_PKCS11 */
#endif  /* HAVE_LIBGNUTLS */
}

void
secrets_register_type(guint32 secrets_type, secrets_block_callback_t cb)
{
    g_hash_table_insert(secrets_callbacks, GUINT_TO_POINTER(secrets_type), (gpointer)cb);
}

void
secrets_wtap_callback(guint32 secrets_type, const void *secrets, guint size)
{
    secrets_block_callback_t cb = (secrets_block_callback_t)g_hash_table_lookup(
            secrets_callbacks, GUINT_TO_POINTER(secrets_type));
    if (cb) {
        cb(secrets, size);
    }
}

#ifdef HAVE_LIBGNUTLS
static guint
key_id_hash(gconstpointer key)
{
    const cert_key_id_t *key_id = (const cert_key_id_t *)key;
    const guint32 *dw = (const guint32 *)key_id->key_id;

    /* The public key' SHA-1 hash (which maps to a private key) has a uniform
     * distribution, hence simply xor'ing them should be sufficient. */
    return dw[0] ^ dw[1] ^ dw[2] ^ dw[3] ^ dw[4];
}

static gboolean
key_id_equal(gconstpointer a, gconstpointer b)
{
    const cert_key_id_t *key_id_a = (const cert_key_id_t *)a;
    const cert_key_id_t *key_id_b = (const cert_key_id_t *)b;

    return !memcmp(key_id_a, key_id_b, sizeof(*key_id_a));
}

GHashTable *
privkey_hash_table_new(void)
{
    return g_hash_table_new_full(key_id_hash, key_id_equal, g_free, (GDestroyNotify)gnutls_privkey_deinit);
}

static void
rsa_privkey_add(const cert_key_id_t *key_id, gnutls_privkey_t pkey)
{
    void *ht_key = g_memdup2(key_id->key_id, sizeof(cert_key_id_t));
    const guint32 *dw = (const guint32 *)key_id->key_id;
    g_hash_table_insert(rsa_privkeys, ht_key, pkey);
    ws_debug("Adding RSA private, Key ID %08x%08x%08x%08x%08x", g_htonl(dw[0]),
            g_htonl(dw[1]), g_htonl(dw[2]), g_htonl(dw[3]), g_htonl(dw[4]));
}

#ifdef HAVE_GNUTLS_PKCS11
/** Provides a fixed PIN to the caller (or failure if the fixed PIN is NULL). */
static int
set_pin_callback(void *userdata, int attempt _U_,
                 const char *token_url _U_, const char *token_label _U_,
                 unsigned int flags, char *pin, size_t pin_max)
{
    const char *fixed_pin = (const char *)userdata;
    size_t fixed_pin_len = fixed_pin ? strlen(fixed_pin) : 0;

    /* Fail if the PIN was not provided, wrong or too long. */
    if (!fixed_pin || (flags & GNUTLS_PIN_WRONG) || fixed_pin_len >= pin_max) {
        return GNUTLS_E_PKCS11_PIN_ERROR;
    }

    memcpy(pin, fixed_pin, fixed_pin_len + 1);
    return 0;
}

static GSList *
get_pkcs11_token_uris(void)
{
    GSList *tokens = NULL;

    for (unsigned i = 0; ; i++) {
        char *uri = NULL;
        int flags;
        int ret = gnutls_pkcs11_token_get_url(i, GNUTLS_PKCS11_URL_GENERIC, &uri);
        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            break;
        }

        if (ret < 0) {
            ws_debug("Failed to query token %u: %s\n", i, gnutls_strerror(ret));
            break;
        }

        ret = gnutls_pkcs11_token_get_flags(uri, &flags);
        if (ret < 0) {
            ws_debug("Failed to query token flags for %s: %s\n", uri, gnutls_strerror(ret));
            gnutls_free(uri);
            continue;
        }

        // The "Trust module" is useless for decryption, so do not return it.
        if ((flags & GNUTLS_PKCS11_TOKEN_TRUSTED)) {
            gnutls_free(uri);
            continue;
        }

        tokens = g_slist_prepend(tokens, g_strdup(uri));
        gnutls_free(uri);
    }

    tokens = g_slist_reverse(tokens);

    return tokens;
}

static gboolean
verify_pkcs11_token(const char *token_uri, const char *pin, gboolean *pin_needed, char **error)
{
    gnutls_pkcs11_obj_t *list = NULL;
    unsigned int nlist = 0;
    int ret;

    /* Set PIN via a global callback since import_url can prompt for one. */
    gnutls_pkcs11_set_pin_function(set_pin_callback, (void *)pin);

    /* This should ask for a PIN if needed. If no PIN is given,
     * GNUTLS_E_PKCS11_PIN_ERROR (-303) is returned. */
    ret = gnutls_pkcs11_obj_list_import_url4(&list, &nlist, token_uri,
            GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY|GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
    if (ret == 0) {
        /* Do not care about the objects, we just wanted to know whether the
         * token and PIN were valid. */
        for (unsigned i = 0; i < nlist; i++) {
            gnutls_pkcs11_obj_deinit(list[i]);
        }
        gnutls_free(list);
    }

    /* Forget about the PIN. */
    gnutls_pkcs11_set_pin_function(NULL, NULL);

    if (pin_needed) {
        *pin_needed = ret == GNUTLS_E_PKCS11_PIN_ERROR;
    }
    if (ret != 0) {
        if (error) {
            *error = g_strdup(gnutls_strerror(ret));
        }
        return FALSE;
    }
    return TRUE;
}

/**
 * Load private RSA keys from a PKCS #11 token. Returns zero on success and a
 * negative error code on failure.
 */
static int
pkcs11_load_keys_from_token(const char *token_uri, const char *pin, char **err)
{
    gnutls_pkcs11_obj_t *list = NULL;
    unsigned int nlist = 0;
    int ret;
    /* An empty/NULL PIN means that none is necessary. */
    char *fixed_pin = pin && pin[0] ? g_strdup(pin) : NULL;
    gboolean pin_in_use = FALSE;

    /* Set PIN via a global callback since import_url can prompt for one. */
    gnutls_pkcs11_set_pin_function(set_pin_callback, fixed_pin);

    /* This might already result in callback for the PIN. */
    ret = gnutls_pkcs11_obj_list_import_url4(&list, &nlist, token_uri,
            GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY|GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
    if (ret < 0) {
        *err = ws_strdup_printf("Failed to iterate through objects for %s: %s", token_uri, gnutls_strerror(ret));
        goto cleanup;
    }

    for (unsigned j = 0; j < nlist; j++) {
        char *obj_uri = NULL;
        gnutls_privkey_t privkey = NULL;
        gnutls_pubkey_t pubkey = NULL;
        cert_key_id_t key_id;
        size_t size;

        if (gnutls_pkcs11_obj_get_type(list[j]) != GNUTLS_PKCS11_OBJ_PRIVKEY) {
            /* Should not happen since we requested private keys only. */
            goto cont;
        }

        ret = gnutls_pkcs11_obj_export_url(list[j], GNUTLS_PKCS11_URL_GENERIC, &obj_uri);
        if (ret < 0) {
            /* Should not happen either if the object is valid. */
            goto cont;
        }

        ret = gnutls_privkey_init(&privkey);
        if (ret < 0) {
            /* Out of memory? */
            goto cont;
        }

        /* Set the PIN to be used during decryption. */
        gnutls_privkey_set_pin_function(privkey, set_pin_callback, fixed_pin);

        /* Can prompt for PIN. Can also invoke the token function set by
         * gnutls_pkcs11_set_token_function (if not set, it will just fail
         * immediately rather than retrying). */
        ret = gnutls_privkey_import_url(privkey, obj_uri, 0);
        if (ret < 0) {
            /* Bad PIN or some other system error? */
            ws_debug("Failed to import private key %s: %s", obj_uri, gnutls_strerror(ret));
            goto cont;
        }

        if (gnutls_privkey_get_pk_algorithm(privkey, NULL) != GNUTLS_PK_RSA) {
            ws_debug("Skipping private key %s, not RSA.", obj_uri);
            goto cont;
        }

        ret = gnutls_pubkey_init(&pubkey);
        if (ret < 0) {
            /* Out of memory? */
            goto cont;
        }

        /* This requires GnuTLS 3.4.0 and will fail on older versions. */
        ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
        if (ret < 0) {
            ws_debug("Failed to import public key %s: %s", obj_uri, gnutls_strerror(ret));
            goto cont;
        }

        size = sizeof(key_id);
        ret = gnutls_pubkey_get_key_id(pubkey, GNUTLS_KEYID_USE_SHA1, key_id.key_id, &size);
        if (ret < 0 || size != sizeof(key_id)) {
            ws_debug("Failed to calculate Key ID for %s: %s", obj_uri, gnutls_strerror(ret));
            goto cont;
        }

        /* Remember the private key. */
        rsa_privkey_add(&key_id, privkey);
        privkey = NULL;
        pin_in_use = TRUE;

cont:
        gnutls_privkey_deinit(privkey);
        gnutls_pubkey_deinit(pubkey);
        gnutls_free(obj_uri);
        gnutls_pkcs11_obj_deinit(list[j]);
    }
    gnutls_free(list);
    if (pin_in_use) {
        /* Remember PINs such they can be freed later. */
        rsa_privkeys_pkcs11_pins = g_slist_prepend(rsa_privkeys_pkcs11_pins, fixed_pin);
        fixed_pin = NULL;
    }
    ret = 0;

cleanup:
    /* Forget about the PIN. */
    gnutls_pkcs11_set_pin_function(NULL, NULL);
    g_free(fixed_pin);
    return ret;
}

/** Load all libraries specified in a UAT. */
static void
uat_pkcs11_libs_load_all(void)
{
    int ret;
    GString *err = NULL;

    for (guint i = 0; i < uat_num_pkcs11_libs; i++) {
        const pkcs11_lib_record_t *rec = &uat_pkcs11_libs[i];
        const char *libname = rec->library_path;
#ifdef _MSC_VER
        // Work around a bug in p11-kit < 0.23.16 on Windows
        HMODULE provider_lib = LoadLibraryA(libname);
        if (! provider_lib || ! GetProcAddress(provider_lib, "C_GetFunctionList")) {
            ret = GNUTLS_E_PKCS11_LOAD_ERROR;
        } else {
#endif
        /* Note: should return success for already loaded libraries.  */
        ret = gnutls_pkcs11_add_provider(libname, NULL);
#ifdef _MSC_VER
        }
        if (provider_lib) {
            FreeLibrary(provider_lib);
        }
#endif
        if (ret) {
            if (!err) {
                err = g_string_new("Error loading PKCS #11 libraries:");
            }
            g_string_append_printf(err, "\n%s: %s", libname, gnutls_strerror(ret));
        }
    }
    if (err) {
        report_failure("%s", err->str);
        g_string_free(err, TRUE);
    }
}

UAT_FILENAME_CB_DEF(pkcs11_libs_uats, library_path, pkcs11_lib_record_t)

static void *
uat_pkcs11_lib_copy_str_cb(void *dest, const void *source, size_t len _U_)
{
    pkcs11_lib_record_t *d = (pkcs11_lib_record_t *)dest;
    const pkcs11_lib_record_t *s = (const pkcs11_lib_record_t *)source;
    d->library_path = g_strdup(s->library_path);
    return dest;
}

static void
uat_pkcs11_lib_free_str_cb(void *record)
{
    pkcs11_lib_record_t *rec = (pkcs11_lib_record_t *)record;
    g_free(rec->library_path);
}
#endif  /* HAVE_GNUTLS_PKCS11 */

UAT_FILENAME_CB_DEF(rsa_privkeys_uats, uri, rsa_privkey_record_t)
UAT_CSTRING_CB_DEF(rsa_privkeys_uats, password, rsa_privkey_record_t)

static void *
uat_rsa_privkey_copy_str_cb(void *dest, const void *source, size_t len _U_)
{
    rsa_privkey_record_t *d = (rsa_privkey_record_t *)dest;
    const rsa_privkey_record_t *s = (const rsa_privkey_record_t *)source;
    d->uri = g_strdup(s->uri);
    d->password = g_strdup(s->password);
    return dest;
}

static void
uat_rsa_privkey_free_str_cb(void *record)
{
    rsa_privkey_record_t *rec = (rsa_privkey_record_t *)record;
    g_free(rec->uri);
    g_free(rec->password);
}

static void
load_rsa_keyfile(const char *filename, const char *password, gboolean save_key, char **err)
{
    gnutls_x509_privkey_t x509_priv_key;
    gnutls_privkey_t privkey = NULL;
    char *errmsg = NULL;
    int ret;
    cert_key_id_t key_id;
    size_t size = sizeof(key_id);

    FILE *fp = ws_fopen(filename, "rb");
    if (!fp) {
        *err = ws_strdup_printf("Error loading RSA key file %s: %s", filename, g_strerror(errno));
        return;
    }

    if (!password || !password[0]) {
        x509_priv_key = rsa_load_pem_key(fp, &errmsg);
    } else {
        /* Assume encrypted PKCS #12 container. */
        x509_priv_key = rsa_load_pkcs12(fp, password, &errmsg);
    }
    fclose(fp);
    if (!x509_priv_key) {
        *err = ws_strdup_printf("Error loading RSA key file %s: %s", filename, errmsg);
        g_free(errmsg);
        return;
    }

    gnutls_privkey_init(&privkey);
    ret = gnutls_privkey_import_x509(privkey, x509_priv_key,
            GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE|GNUTLS_PRIVKEY_IMPORT_COPY);
    if (ret < 0) {
        *err = ws_strdup_printf("Error importing private key %s: %s", filename, gnutls_strerror(ret));
        goto end;
    }
    ret = gnutls_x509_privkey_get_key_id(x509_priv_key, GNUTLS_KEYID_USE_SHA1, key_id.key_id, &size);
    if (ret < 0 || size != sizeof(key_id)) {
        *err = ws_strdup_printf("Error calculating Key ID for %s: %s", filename, gnutls_strerror(ret));
        goto end;
    }

    /* Remember the private key. */
    if (save_key) {
        rsa_privkey_add(&key_id, privkey);
        privkey = NULL;
    }

end:
    gnutls_x509_privkey_deinit(x509_priv_key);
    gnutls_privkey_deinit(privkey);
}

static void
uat_rsa_privkeys_post_update(void)
{
    /* Clear previous keys. */
    g_hash_table_remove_all(rsa_privkeys);
#ifdef HAVE_GNUTLS_PKCS11
    g_slist_free_full(rsa_privkeys_pkcs11_pins, g_free);
    rsa_privkeys_pkcs11_pins = NULL;
#endif  /* HAVE_GNUTLS_PKCS11 */
    GString *errors = NULL;

    for (guint i = 0; i < uat_num_rsa_privkeys; i++) {
        const rsa_privkey_record_t *rec = &uat_rsa_privkeys[i];
        const char *token_uri = rec->uri;
        char *err = NULL;

        if (g_str_has_prefix(token_uri, "pkcs11:")) {
#ifdef HAVE_GNUTLS_PKCS11
            pkcs11_load_keys_from_token(token_uri, rec->password, &err);
#endif  /* HAVE_GNUTLS_PKCS11 */
        } else {
            load_rsa_keyfile(token_uri, rec->password, TRUE, &err);
        }
        if (err) {
            if (!errors) {
                errors = g_string_new("Error processing rsa_privkeys:");
            }
            g_string_append_c(errors, '\n');
            g_string_append(errors, err);
            g_free(err);
        }
    }
    if (errors) {
        report_failure("%s", errors->str);
        g_string_free(errors, TRUE);
    }
}

GSList *
secrets_get_available_keys(void)
{
    GSList *keys = NULL;
#ifdef HAVE_GNUTLS_PKCS11
    keys = g_slist_concat(keys, get_pkcs11_token_uris());
#endif
    return keys;
}

gboolean
secrets_verify_key(const char *uri, const char *password, gboolean *need_password, char **error)
{
    if (need_password) {
        *need_password = FALSE;
    }
    if (error) {
        *error = NULL;
    }

    if (g_str_has_prefix(uri, "pkcs11:")) {
#ifdef HAVE_GNUTLS_PKCS11
        return verify_pkcs11_token(uri, password, need_password, error);
#else
        if (error) {
            *error = g_strdup("PKCS #11 support is not available in this build");
        }
        return FALSE;
#endif
    } else if (g_file_test(uri, G_FILE_TEST_IS_REGULAR)) {
        gchar *err = NULL;
        load_rsa_keyfile(uri, password, FALSE, &err);
        if (need_password) {
            // Assume that failure to load the key is due to password errors.
            // This might not be correct, but fixing this needs more changes.
            *need_password = err != NULL;
        }
        if (err) {
            if (error) {
                *error = err;
            } else {
                g_free(err);
            }
            return FALSE;
        }
        return TRUE;
    } else {
        if (error) {
            *error = g_strdup("Unsupported key URI or path");
        }
        return FALSE;
    }
}

/**
 * Register the UAT definitions such that settings can be loaded from file.
 * Note: relies on uat_load_all to invoke the post_update_cb in order of
 * registration below such that libraries are loaded *before* keys are read.
 */
static void
register_rsa_uats(void)
{
#ifdef HAVE_GNUTLS_PKCS11
    static uat_field_t uat_pkcs11_libs_fields[] = {
        UAT_FLD_FILENAME_OTHER(pkcs11_libs_uats, library_path, "Library Path", NULL, "PKCS #11 provider library file"),
        UAT_END_FIELDS
    };
    pkcs11_libs_uat = uat_new("PKCS #11 Provider Libraries",
            sizeof(pkcs11_lib_record_t),
            "pkcs11_libs",                  /* filename */
            FALSE,                          /* from_profile */
            &uat_pkcs11_libs,               /* data_ptr */
            &uat_num_pkcs11_libs,           /* numitems_ptr */
            0,                              /* does not directly affect dissection */
            NULL,                           /* Help section (currently a wiki page) */
            uat_pkcs11_lib_copy_str_cb,     /* copy_cb */
            NULL,                           /* update_cb */
            uat_pkcs11_lib_free_str_cb,     /* free_cb */
            uat_pkcs11_libs_load_all,       /* post_update_cb */
            NULL,                           /* reset_cb */
            uat_pkcs11_libs_fields);
#endif  /* HAVE_GNUTLS_PKCS11 */

    static uat_field_t uat_rsa_privkeys_fields[] = {
        UAT_FLD_FILENAME_OTHER(rsa_privkeys_uats, uri, "Keyfile or Token URI", NULL, "RSA Key File or PKCS #11 URI for token"),
        UAT_FLD_FILENAME_OTHER(rsa_privkeys_uats, password, "Password", NULL, "RSA Key File password or PKCS #11 Token PIN"),
        UAT_END_FIELDS
    };
    rsa_privkeys_uat = uat_new("RSA Private Keys",
            sizeof(rsa_privkey_record_t),
            "rsa_keys",                     /* filename */
            FALSE,                          /* from_profile */
            &uat_rsa_privkeys,              /* data_ptr */
            &uat_num_rsa_privkeys,          /* numitems_ptr */
            0,                              /* does not directly affect dissection */
            NULL,                           /* Help section (currently a wiki page) */
            uat_rsa_privkey_copy_str_cb,    /* copy_cb */
            NULL,                           /* update_cb */
            uat_rsa_privkey_free_str_cb,    /* free_cb */
            uat_rsa_privkeys_post_update,   /* post_update_cb */
            NULL,                           /* reset_cb */
            uat_rsa_privkeys_fields);
}

int
secrets_rsa_decrypt(const cert_key_id_t *key_id, const guint8 *encr, int encr_len, guint8 **out, int *out_len)
{
    gboolean ret;
    gnutls_datum_t ciphertext = { (guchar *)encr, encr_len };
    gnutls_datum_t plain = { 0 };

    gnutls_privkey_t pkey = (gnutls_privkey_t)g_hash_table_lookup(rsa_privkeys, key_id->key_id);
    if (!pkey) {
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    ret = gnutls_privkey_decrypt_data(pkey, 0, &ciphertext, &plain);
    if (ret == 0) {
        *out = (guint8 *)g_memdup2(plain.data, plain.size);
        *out_len = plain.size;
        gnutls_free(plain.data);
    }

    return ret;
}
#endif  /* HAVE_LIBGNUTLS */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
