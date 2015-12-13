/* capture_dissectors.c
 * Routines for handling capture dissectors
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include "packet.h"

#include "capture_dissectors.h"

struct capture_dissector_handle
{
    gint linktype;
    capture_dissector_t dissector;
    protocol_t* protocol;
};

static GHashTable *registered_capture_dissectors = NULL;

void capture_dissector_init(void)
{
    registered_capture_dissectors = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
}

void capture_dissector_cleanup(void)
{
    g_hash_table_destroy(registered_capture_dissectors);
    registered_capture_dissectors = NULL;
}

void register_capture_dissector(gint linktype, capture_dissector_t dissector, const int proto)
{
    struct capture_dissector_handle *handle;

    /* Make sure the registration is unique */
    g_assert(g_hash_table_lookup(registered_capture_dissectors, GUINT_TO_POINTER(linktype)) == NULL);

    handle                = wmem_new(wmem_epan_scope(), struct capture_dissector_handle);
    handle->linktype      = linktype;
    handle->dissector     = dissector;
    handle->protocol      = find_protocol_by_id(proto);

    g_hash_table_insert(registered_capture_dissectors, GUINT_TO_POINTER(linktype), (gpointer) handle);
}

void call_capture_dissector(gint linktype, const guchar *pd, int offset, int len, packet_counts *ld, const union wtap_pseudo_header *pseudo_header)
{
    struct capture_dissector_handle* handle = (struct capture_dissector_handle *)g_hash_table_lookup(registered_capture_dissectors, GUINT_TO_POINTER(linktype));
    if (handle == NULL)
        return;

    handle->dissector(pd, offset, len, ld, pseudo_header);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
