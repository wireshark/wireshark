/* network-boot-analysis.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include "config.h"

#include <glib.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <epan/packet_info.h>
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/tap.h>
#include "network-boot-analysis.h"

/** Storage for known boot clients.
 * Hash table keys are bootclient_key_t. Hash table values are indexes into client_array.
 */
typedef struct _bootclient_hash_t {
    GHashTable *clienttable;    /**< hash table of booting clients. */
    GArray *client_array;        /**< array of boot clients */
} bootclient_hash_t;

typedef guint32 bootclient_seq_t;

typedef struct _bootclient_key_t {
    address client_address;
    bootclient_seq_t seq;
} bootclient_key_t;

typedef struct _bootclient_item_t {
    bootclient_key_t key;
    /* Interesting fields to track for the client go here: */
    unsigned int num_bootp_events;
    /* List of DHCP offers.  Selected offer. Timestamps. */
    /* ProxyDHCP offer. Timestamps. */
    /* Boot file ID. */
    /* Any DHCP dissector errors/warnings. */
    unsigned int num_tftp_events;
    /* Any TFTP dissector errors/warnings. */
    /* List of TFTP files fetched.  Maybe checksums? */
    /* TFTP timestamps. */
} bootclient_item_t;

static bootclient_hash_t bootclients_hash;

static guint
bootclient_hash(gconstpointer v)
{
    const bootclient_key_t *key = (const bootclient_key_t *)v;
    return add_address_to_hash(key->seq, &key->client_address);
}

static gboolean
bootclient_equal(gconstpointer key1, gconstpointer key2)
{
    const bootclient_key_t *k1 = (const bootclient_key_t *)key1;
    const bootclient_key_t *k2 = (const bootclient_key_t *)key2;

    return k1->seq == k2->seq && addresses_equal(&k1->client_address, &k2->client_address);
}


static bootclient_item_t *
bootclient_item_for_address(
    bootclient_hash_t *bch,
    const address *bootclient_address,
    bootclient_seq_t seq)
{
    bootclient_item_t *bootclient_item = NULL;

    if (bch->client_array == NULL) {
        bch->client_array = g_array_sized_new(FALSE, FALSE, sizeof (bootclient_item_t), 10000);
        bch->clienttable = g_hash_table_new_full(bootclient_hash,
                                                 bootclient_equal, /* key_equal_func */
                                                 NULL,             /* key_destroy_func */
                                                 NULL);            /* value_destroy_func */
    } else {
        bootclient_key_t existing_key;
        gpointer idx;
       
        copy_address(&existing_key.client_address, bootclient_address);
        existing_key.seq = seq;

        if (g_hash_table_lookup_extended(bch->clienttable, &existing_key, NULL, &idx)) {
            bootclient_item = &g_array_index(bch->client_array, bootclient_item_t, GPOINTER_TO_UINT(idx));
        }
    }

    if (bootclient_item == NULL) {
        bootclient_item_t new_bootclient_item;
        unsigned int idx;

        copy_address(&new_bootclient_item.key.client_address, bootclient_address);
        new_bootclient_item.key.seq = seq;
        new_bootclient_item.num_bootp_events = 0;
        new_bootclient_item.num_tftp_events = 0;
        g_array_append_val(bch->client_array, new_bootclient_item);
        idx = bch->client_array->len - 1;
        bootclient_item = &g_array_index(bch->client_array, bootclient_item_t, idx);
        g_hash_table_insert(bch->clienttable, &bootclient_item->key, GUINT_TO_POINTER(idx));
    }
    return bootclient_item;
}

/* A BOOTP/DHCP packet has been captured. */
static gboolean
nb_bootp_packet(void *tapdata _U_, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data)
{
    const network_boot_bootp_event *nbe = (const network_boot_bootp_event *)data;
    bootclient_item_t *client = bootclient_item_for_address(&bootclients_hash, &nbe->client_address, 0 /* XXX */);
    
    fprintf(stderr, "[%s]: DHCP#%u, %sXID=%08x", address_to_str(wmem_packet_scope(), &client->key.client_address),
            ++client->num_bootp_events, nbe->is_pxe ? "PXE, " : "", nbe->xid);
    if (nbe->bootfile_name != NULL) {
        fprintf(stderr, ", file=\"%s\"", nbe->bootfile_name);
        g_free(nbe->bootfile_name);
    }
    fprintf(stderr, ".\n");
    return FALSE;
}

static gboolean
nb_tftp_packet(void *tapdata _U_, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data _U_)
{
    const network_boot_tftp_event *nbe = (const network_boot_tftp_event *)data;
    bootclient_item_t *client = bootclient_item_for_address(&bootclients_hash, &nbe->client_address, 0 /* XXX */);

    fprintf(stderr, "[%s]: TFTP#%u, ", address_to_str(wmem_packet_scope(), &client->key.client_address),
            ++client->num_tftp_events);
    fprintf(stderr, "%s%s", nbe->is_first ? "first " : "", nbe->is_complete ? "complete " : "");
    if (nbe->error_text != NULL) {
        fprintf(stderr, "error=\"%s\" ", nbe->error_text);
    }
    if (nbe->file_name != NULL) {
        fprintf(stderr, "filename=\"%s\"", nbe->file_name);
        g_free(nbe->file_name);
    }
    if (nbe->is_complete) {
        fprintf(stderr, " size=%" G_GINT64_MODIFIER "u bytes.\n", nbe->file_size);
    } else {
        fprintf(stderr, "\n");
    }
    return FALSE;
}

/* List of all protocols relevant to network boot.  We'll tap each of them. */
static const struct {
        const char *name;
        tap_packet_cb func;
} taps[] = {
        {"bootp-boot", nb_bootp_packet},
        {"tftp-boot", nb_tftp_packet},
};

void start_networkboot(void)
{
    GString *error_msg = NULL;

    for (unsigned int i = 0; i < array_length(taps) && error_msg == NULL; i++) {
        error_msg = register_tap_listener(taps[i].name, NULL /* tap_data */, NULL, TL_REQUIRES_ERROR_PACKETS,
                          NULL, taps[i].func, NULL);
    }

    if (error_msg) {
        fprintf(stderr, "tshark: Can't register network-boot tap: %s\n", error_msg->str);
        g_string_free(error_msg, TRUE);
    }
}

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
