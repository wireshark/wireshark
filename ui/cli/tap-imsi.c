/* tap-imsi.c
 * IMSI flow statistics
 * Copyright 2024, Wireshark development team
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-e212.h>

#include <wsutil/cmdarg_err.h>

void register_tap_listener_imsi(void);

#define MAX_PROTOCOLS_PER_IMSI 16

typedef struct _imsi_entry_t {
    char *imsi;
    uint32_t packet_count;
    uint32_t first_frame;
    uint32_t last_frame;
    char *protocols[MAX_PROTOCOLS_PER_IMSI];
    int num_protocols;
} imsi_entry_t;

typedef struct _imsi_tapdata_t {
    GHashTable *imsi_hash;  /* key: imsi string, value: imsi_entry_t* */
} imsi_tapdata_t;

static void
imsi_entry_add_protocol(imsi_entry_t *entry, const char *protocol)
{
    if (!protocol)
        return;

    /* Check if protocol already recorded */
    for (int i = 0; i < entry->num_protocols; i++) {
        if (strcmp(entry->protocols[i], protocol) == 0)
            return;
    }

    if (entry->num_protocols < MAX_PROTOCOLS_PER_IMSI) {
        entry->protocols[entry->num_protocols] = g_strdup(protocol);
        entry->num_protocols++;
    }
}

static void
imsi_entry_free(void *data)
{
    imsi_entry_t *entry = (imsi_entry_t *)data;
    g_free(entry->imsi);
    for (int i = 0; i < entry->num_protocols; i++) {
        g_free(entry->protocols[i]);
    }
    g_free(entry);
}

static void
imsi_reset(void *p)
{
    imsi_tapdata_t *tapdata = (imsi_tapdata_t *)p;
    if (tapdata->imsi_hash) {
        g_hash_table_destroy(tapdata->imsi_hash);
    }
    tapdata->imsi_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, imsi_entry_free);
}

static tap_packet_status
imsi_packet(void *p, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
    imsi_tapdata_t *tapdata = (imsi_tapdata_t *)p;
    const tap_imsi_info_t *tap_info = (const tap_imsi_info_t *)pri;
    imsi_entry_t *entry;

    if (!tap_info || !tap_info->imsi)
        return TAP_PACKET_DONT_REDRAW;

    entry = (imsi_entry_t *)g_hash_table_lookup(tapdata->imsi_hash, tap_info->imsi);
    if (!entry) {
        entry = g_new0(imsi_entry_t, 1);
        entry->imsi = g_strdup(tap_info->imsi);
        entry->first_frame = tap_info->frame_number;
        entry->last_frame = tap_info->frame_number;
        entry->packet_count = 1;
        g_hash_table_insert(tapdata->imsi_hash, entry->imsi, entry);
    } else {
        entry->packet_count++;
        if (tap_info->frame_number > entry->last_frame)
            entry->last_frame = tap_info->frame_number;
    }

    imsi_entry_add_protocol(entry, tap_info->protocol);

    return TAP_PACKET_REDRAW;
}

static int
imsi_compare_by_first_frame(const void *a, const void *b)
{
    const imsi_entry_t *ea = *(const imsi_entry_t **)a;
    const imsi_entry_t *eb = *(const imsi_entry_t **)b;
    if (ea->first_frame < eb->first_frame) return -1;
    if (ea->first_frame > eb->first_frame) return 1;
    return 0;
}

static void
imsi_draw(void *p)
{
    imsi_tapdata_t *tapdata = (imsi_tapdata_t *)p;
    GHashTableIter iter;
    void *value;
    GPtrArray *entries;

    if (!tapdata->imsi_hash)
        return;

    entries = g_ptr_array_new();
    g_hash_table_iter_init(&iter, tapdata->imsi_hash);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        g_ptr_array_add(entries, value);
    }

    /* Sort by first appearance */
    g_ptr_array_sort(entries, imsi_compare_by_first_frame);

    printf("================================================================================\n");
    printf("IMSI Statistics\n");
    printf("================================================================================\n");
    printf("%-17s %8s %10s %10s  %s\n", "IMSI", "Packets", "First", "Last", "Protocols");
    printf("%-17s %8s %10s %10s  %s\n", "-----------------", "--------", "----------", "----------", "----------");

    for (unsigned i = 0; i < entries->len; i++) {
        imsi_entry_t *entry = (imsi_entry_t *)g_ptr_array_index(entries, i);
        GString *proto_str = g_string_new("");

        for (int j = 0; j < entry->num_protocols; j++) {
            if (j > 0) g_string_append(proto_str, ", ");
            g_string_append(proto_str, entry->protocols[j]);
        }

        printf("%-17s %8u %10u %10u  %s\n",
               entry->imsi,
               entry->packet_count,
               entry->first_frame,
               entry->last_frame,
               proto_str->str);

        g_string_free(proto_str, TRUE);
    }

    printf("================================================================================\n");
    printf("Total IMSIs: %u\n", entries->len);
    printf("================================================================================\n");

    g_ptr_array_free(entries, TRUE);
}

static void
imsi_finish(void *p)
{
    imsi_tapdata_t *tapdata = (imsi_tapdata_t *)p;
    if (tapdata->imsi_hash) {
        g_hash_table_destroy(tapdata->imsi_hash);
    }
    g_free(tapdata);
}

static bool
imsi_init(const char *opt_arg _U_, void *userdata _U_)
{
    GString *error_string;
    imsi_tapdata_t *tapdata;

    tapdata = g_new0(imsi_tapdata_t, 1);
    tapdata->imsi_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, imsi_entry_free);

    error_string = register_tap_listener("imsi", tapdata, NULL, TL_REQUIRES_NOTHING,
                                         imsi_reset, imsi_packet, imsi_draw, imsi_finish);

    if (error_string) {
        cmdarg_err("Couldn't register imsi tap: %s", error_string->str);
        imsi_finish(tapdata);
        g_string_free(error_string, TRUE);
        return false;
    }

    return true;
}

static stat_tap_ui imsi_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "imsi",
    imsi_init,
    0,
    NULL
};

void
register_tap_listener_imsi(void)
{
    register_stat_tap_ui(&imsi_ui, NULL);
}
