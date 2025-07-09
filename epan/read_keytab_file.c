/* read_keytab_file.c
 * Routines for reading Kerberos keytab files
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <wireshark.h>

#include "read_keytab_file.h"
#include "wmem_scopes.h"

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

#ifdef _WIN32
 /* prevent redefinition warnings in krb5's win-mac.h */
#define SSIZE_T_DEFINED
#endif /* _WIN32 */
#include <krb5.h>

krb5_context keytab_krb5_ctx;

static enc_key_t* enc_key_list = NULL;
static unsigned kerberos_longterm_ids;
static wmem_map_t* keytab_file_longterm_keys;
static wmem_map_t* keytab_file_all_keys;
static wmem_map_t* keytab_file_session_keys;

const enc_key_t* keytab_get_enc_key_list(void)
{
    return enc_key_list;
}

void keytab_set_enc_key_list(enc_key_t* list)
{
    enc_key_list = list;
}

const wmem_map_t* keytab_get_file_longterm_keys(void)
{
    return keytab_file_longterm_keys;
}

wmem_map_t* keytab_get_file_all_keys(void)
{
    return keytab_file_all_keys;
}

wmem_map_t* keytab_get_file_session_keys(void)
{
    return keytab_file_session_keys;
}

static bool
enc_key_list_cb(wmem_allocator_t* allocator _U_, wmem_cb_event_t event _U_, void* user_data _U_)
{
    enc_key_list = NULL;
    kerberos_longterm_ids = 0;
    /* keep the callback registered */
    return true;
}

static int
enc_key_cmp_id(const void* k1, const void* k2)
{
    const enc_key_t* key1 = (const enc_key_t*)k1;
    const enc_key_t* key2 = (const enc_key_t*)k2;

    if (key1->fd_num < key2->fd_num) {
        return -1;
    }
    if (key1->fd_num > key2->fd_num) {
        return 1;
    }

    if (key1->id < key2->id) {
        return -1;
    }
    if (key1->id > key2->id) {
        return 1;
    }

    return 0;
}

static gboolean
enc_key_content_equal(const void* k1, const void* k2)
{
    const enc_key_t* key1 = (const enc_key_t*)k1;
    const enc_key_t* key2 = (const enc_key_t*)k2;
    int cmp;

    if (key1->keytype != key2->keytype) {
        return false;
    }

    if (key1->keylength != key2->keylength) {
        return false;
    }

    cmp = memcmp(key1->keyvalue, key2->keyvalue, key1->keylength);
    if (cmp != 0) {
        return false;
    }

    return true;
}

static unsigned
enc_key_content_hash(const void* k)
{
    const enc_key_t* key = (const enc_key_t*)k;
    unsigned ret = 0;

    ret += wmem_strong_hash((const uint8_t*)&key->keytype,
        sizeof(key->keytype));
    ret += wmem_strong_hash((const uint8_t*)&key->keylength,
        sizeof(key->keylength));
    ret += wmem_strong_hash((const uint8_t*)key->keyvalue,
        key->keylength);

    return ret;
}

void
keytab_file_key_map_insert(wmem_map_t* key_map, enc_key_t* new_key)
{
    enc_key_t* existing = NULL;
    enc_key_t* cur = NULL;
    int cmp;

    existing = (enc_key_t*)wmem_map_lookup(key_map, new_key);
    if (existing == NULL) {
        wmem_map_insert(key_map, new_key, new_key);
        return;
    }

    if (key_map != keytab_file_all_keys) {
        /*
         * It should already be linked to the existing key...
         */
        return;
    }

    if (existing->fd_num == -1 && new_key->fd_num != -1) {
        /*
         * We can't reference a learnt key
         * from a longterm key. As they have
         * a shorter lifetime.
         *
         * So just let the learnt key remember the
         * match.
         */
        new_key->same_list = existing;
        new_key->num_same = existing->num_same + 1;
        return;
    }

    /*
     * If a key with the same content (keytype,keylength,keyvalue)
     * already exists, we want the earliest key to be
     * in the list.
     */
    cmp = enc_key_cmp_id(new_key, existing);
    if (cmp == 0) {
        /*
         * It's the same, nothing to do...
         */
        return;
    }
    if (cmp < 0) {
        /* The new key has should be added to the list. */
        new_key->same_list = existing;
        new_key->num_same = existing->num_same + 1;
        wmem_map_insert(key_map, new_key, new_key);
        return;
    }

    /*
     * We want to link the new_key to the existing one.
     *
     * But we want keep the list sorted, so we need to forward
     * to the correct spot.
     */
    for (cur = existing; cur->same_list != NULL; cur = cur->same_list) {
        cmp = enc_key_cmp_id(new_key, cur->same_list);
        if (cmp == 0) {
            /*
             * It's the same, nothing to do...
             */
            return;
        }

        if (cmp < 0) {
            /*
             * We found the correct spot,
             * the new_key should added
             * between existing and existing->same_list
             */
            new_key->same_list = cur->same_list;
            new_key->num_same = cur->num_same;
            break;
        }
    }

    /*
     * finally link new_key to existing
     * and fix up the numbers
     */
    cur->same_list = new_key;
    for (cur = existing; cur != new_key; cur = cur->same_list) {
        cur->num_same += 1;
    }

    return;
}

#endif

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

USES_APPLE_DEPRECATED_API

void
keytab_file_read(const char* filename)
{
    krb5_keytab keytab;
    krb5_error_code ret;
    krb5_keytab_entry key;
    krb5_kt_cursor cursor;
    static bool first_time = true;

    if (filename == NULL || filename[0] == 0) {
        return;
    }

    if (first_time) {
        first_time = false;
        ret = krb5_init_context(&keytab_krb5_ctx);
        if (ret
#ifdef HAVE_MIT_KERBEROS
        && ret != KRB5_CONFIG_CANTOPEN
#endif
        ) {
            return;
        }
    }

    /* should use a file in the wireshark users dir */
    ret = krb5_kt_resolve(keytab_krb5_ctx, filename, &keytab);
    if (ret) {
        ws_critical("KERBEROS ERROR: Badly formatted keytab filename: %s", filename);

        return;
    }

    ret = krb5_kt_start_seq_get(keytab_krb5_ctx, keytab, &cursor);
    if (ret) {
        ws_critical("KERBEROS ERROR: Could not open or could not read from keytab file: %s", filename);
        return;
    }

    do {
        ret = krb5_kt_next_entry(keytab_krb5_ctx, keytab, &key, &cursor);
        if (ret == 0) {
            enc_key_t* new_key;
            int i;
            wmem_strbuf_t* str_principal = wmem_strbuf_new(wmem_epan_scope(), "keytab principal ");

            new_key = wmem_new0(wmem_epan_scope(), enc_key_t);
            new_key->fd_num = -1;
            new_key->id = ++kerberos_longterm_ids;
            new_key->id_str = wmem_strdup_printf(wmem_epan_scope(), "keytab.%u", new_key->id);
            new_key->next = enc_key_list;

            /* generate origin string, describing where this key came from */
            for (i = 0; i < key.principal->length; i++) {
                wmem_strbuf_append_printf(str_principal, "%s%s", (i ? "/" : ""), (key.principal->data[i]).data);
            }
            wmem_strbuf_append_printf(str_principal, "@%s", key.principal->realm.data);
            new_key->key_origin = (char*)wmem_strbuf_get_str(str_principal);
            new_key->keytype = key.key.enctype;
            new_key->keylength = key.key.length;
            memcpy(new_key->keyvalue,
                key.key.contents,
                MIN(key.key.length, KRB_MAX_KEY_LENGTH));

            enc_key_list = new_key;
            ret = krb5_free_keytab_entry_contents(keytab_krb5_ctx, &key);
            if (ret) {
                ws_critical("KERBEROS ERROR: Could not release the entry: %d", ret);
                ret = 0; /* try to continue with the next entry */
            }
            keytab_file_key_map_insert(keytab_file_longterm_keys, new_key);
        }
    } while (ret == 0);

    ret = krb5_kt_end_seq_get(keytab_krb5_ctx, keytab, &cursor);
    if (ret) {
        ws_critical("KERBEROS ERROR: Could not release the keytab cursor: %d", ret);
    }
    ret = krb5_kt_close(keytab_krb5_ctx, keytab);
    if (ret) {
        ws_critical("KERBEROS ERROR: Could not close the key table handle: %d", ret);
    }
}

USES_APPLE_RST

#elif defined (HAVE_LIBNETTLE)


static void
keytab_file_read(const char* service_key_file)
{
    FILE* skf;
    ws_statb64 st;
    service_key_t* sk;
    unsigned char buf[SERVICE_KEY_SIZE];
    int newline_skip = 0, count = 0;

    if (service_key_file != NULL && ws_stat64(service_key_file, &st) == 0) {

        /* The service key file contains raw 192-bit (24 byte) 3DES keys.
         * There can be zero, one (\n), or two (\r\n) characters between
         * keys.  Trailing characters are ignored.
         */

         /* XXX We should support the standard keytab format instead */
        if (st.st_size > SERVICE_KEY_SIZE) {
            if ((st.st_size % (SERVICE_KEY_SIZE + 1) == 0) ||
                (st.st_size % (SERVICE_KEY_SIZE + 1) == SERVICE_KEY_SIZE)) {
                newline_skip = 1;
            }
            else if ((st.st_size % (SERVICE_KEY_SIZE + 2) == 0) ||
                (st.st_size % (SERVICE_KEY_SIZE + 2) == SERVICE_KEY_SIZE)) {
                newline_skip = 2;
            }
        }

        skf = ws_fopen(service_key_file, "rb");
        if (!skf) return;

        while (fread(buf, SERVICE_KEY_SIZE, 1, skf) == 1) {
            sk = g_malloc(sizeof(service_key_t));
            sk->kvno = buf[0] << 8 | buf[1];
            sk->keytype = KEYTYPE_DES3_CBC_MD5;
            sk->length = DES3_KEY_SIZE;
            sk->contents = g_memdup2(buf + 2, DES3_KEY_SIZE);
            sk->origin = g_strdup_printf("3DES service key file, key #%d, offset %ld", count, ftell(skf));
            service_key_list = g_slist_append(service_key_list, (void*)sk);
            if (fseek(skf, newline_skip, SEEK_CUR) < 0) {
                ws_critical("unable to seek...");
                fclose(skf);
                return;
            }
            count++;
        }
        fclose(skf);
    }
}

#endif

void keytab_file_data_init(void)
{
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
    wmem_register_callback(wmem_epan_scope(), enc_key_list_cb, NULL);

    keytab_file_longterm_keys = wmem_map_new(wmem_epan_scope(),
        enc_key_content_hash,
        enc_key_content_equal);
    keytab_file_all_keys = wmem_map_new_autoreset(wmem_epan_scope(),
        wmem_file_scope(),
        enc_key_content_hash,
        enc_key_content_equal);
    keytab_file_session_keys = wmem_map_new_autoreset(wmem_epan_scope(),
        wmem_file_scope(),
        enc_key_content_hash,
        enc_key_content_equal);

#endif
}
