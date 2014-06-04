/* export_object_tftp.c
 * Routines for aving objects (files) found in TFTP sessions
 * See also: export_object.c / export_object.h for common code
 * Initial file, prototypes and general structure initially copied
 * from export_object_smb.c
 *
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-tftp.h>
#include <epan/tap.h>

#include "export_object.h"

/* A list of block list entries to delete from cleanup callback when window is closed. */
typedef struct eo_info_dynamic_t {
    gchar  *filename;
    GSList *block_list;
} eo_info_dynamic_t;
static GSList *s_dynamic_info_list = NULL;

/* Tap function */
gboolean
eo_tftp_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
           const void *data)
{
    export_object_list_t *object_list = (export_object_list_t *)tapdata;
    const tftp_eo_t *eo_info = (const tftp_eo_t *)data;
    export_object_entry_t *entry;

    GSList *block_iterator;
    guint  payload_data_offset = 0;
    eo_info_dynamic_t *dynamic_info;

    /* These values will be freed when the Export Object window is closed. */
    entry = (export_object_entry_t*)g_malloc(sizeof(export_object_entry_t));

    /* Remember which frame had the last block of the file */
    entry->pkt_num = pinfo->fd->num;

    /* Copy filename */
    entry->filename = g_strdup(g_path_get_basename(eo_info->filename));

    /* Iterate over list of blocks and concatenate into contiguous memory */
    entry->payload_len = eo_info->payload_len;
    entry->payload_data = (guint8 *)g_try_malloc((gsize)entry->payload_len);
    for (block_iterator = eo_info->block_list; block_iterator; block_iterator = block_iterator->next) {
        file_block_t *block = (file_block_t*)block_iterator->data;
        memcpy(entry->payload_data + payload_data_offset,
               block->data,
               block->length);
        payload_data_offset += block->length;
    }

    /* These 2 fields not used */
    entry->hostname = NULL;
    entry->content_type = NULL;

    /* Add to list of entries to be cleaned up.  eo_info is only packet scope, so
       need to make list only of block list now */
    dynamic_info = (eo_info_dynamic_t*)g_malloc(sizeof(eo_info_dynamic_t));
    dynamic_info->filename = eo_info->filename;
    dynamic_info->block_list = eo_info->block_list;
    s_dynamic_info_list = g_slist_append(s_dynamic_info_list, (eo_info_dynamic_t*)dynamic_info);

    /* Pass out entry to the GUI */
    object_list_add_entry(object_list, entry);

    return TRUE; /* State changed - window should be redrawn */
}

/* Clean up the stored parts of a single tapped entry */
static void cleanup_tftp_eo(eo_info_dynamic_t *dynamic_info)
{
    GSList *block_iterator;
    /* Free the filename */
    g_free(dynamic_info->filename);

    /* Walk list of block items */
    for (block_iterator = dynamic_info->block_list; block_iterator; block_iterator = block_iterator->next) {
        file_block_t *block = (file_block_t*)(block_iterator->data);
        /* Free block data */
        wmem_free(NULL, block->data);

        /* Free block itself */
        g_free(block);
    }
}

/* Callback for freeing up data supplied with taps.  The taps themselves only have
   packet scope, so only store/free dynamic memory pointers */
void eo_tftp_cleanup(void)
{
    /* Cleanup each entry in the global list */
    GSList *dynamic_iterator;
    for (dynamic_iterator = s_dynamic_info_list; dynamic_iterator; dynamic_iterator = dynamic_iterator->next) {
        eo_info_dynamic_t *dynamic_info = (eo_info_dynamic_t*)dynamic_iterator->data;
        cleanup_tftp_eo(dynamic_info);
    }
    /* List is empty again */
    s_dynamic_info_list = NULL;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
