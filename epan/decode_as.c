/* decode_as.c
 * Routines for dissector Decode As handlers
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

#include "decode_as.h"
#include "packet.h"
#include <stdio.h>
#include <stdlib.h>

GList *decode_as_list = NULL;

void register_decode_as(decode_as_t* reg)
{
    dissector_table_t decode_table;

    /* Ensure valid functions */
    DISSECTOR_ASSERT(reg->populate_list);
    DISSECTOR_ASSERT(reg->reset_value);
    DISSECTOR_ASSERT(reg->change_value);

    decode_table = find_dissector_table(reg->table_name);
    if (decode_table != NULL)
    {
        dissector_table_allow_decode_as(decode_table);
    }

    decode_as_list = g_list_append(decode_as_list, reg);
}


struct decode_as_default_populate
{
    decode_as_add_to_list_func add_to_list;
    gpointer ui_element;
};

static void
decode_proto_add_to_list (const gchar *table_name, gpointer value, gpointer user_data)
{
    struct decode_as_default_populate* populate = (struct decode_as_default_populate*)user_data;
    const gchar     *proto_name;
    gint       i;
    dissector_handle_t handle;


    handle = (dissector_handle_t)value;
    proto_name = dissector_handle_get_short_name(handle);

    i = dissector_handle_get_protocol_index(handle);
    if (i >= 0 && !proto_is_protocol_enabled(find_protocol_by_id(i)))
        return;

    populate->add_to_list(table_name, proto_name, value, populate->ui_element);
}

void decode_as_default_populate_list(const gchar *table_name, decode_as_add_to_list_func add_to_list, gpointer ui_element)
{
    struct decode_as_default_populate populate;

    populate.add_to_list = add_to_list;
    populate.ui_element = ui_element;

    dissector_table_foreach_handle(table_name, decode_proto_add_to_list, &populate);
}

gboolean decode_as_default_reset(const gchar *name, gconstpointer pattern)
{
    switch (get_dissector_table_selector_type(name)) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        dissector_reset_uint(name, GPOINTER_TO_UINT(pattern));
        return TRUE;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        dissector_reset_string(name, (!pattern)?"":(gchar *) pattern);
        return TRUE;
    default:
        return FALSE;
    };

    return TRUE;
}

gboolean decode_as_default_change(const gchar *name, gconstpointer pattern, gpointer handle, gchar *list_name _U_)
{
    dissector_handle_t* dissector = (dissector_handle_t*)handle;
    if (dissector != NULL) {
        switch (get_dissector_table_selector_type(name)) {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            dissector_change_uint(name, GPOINTER_TO_UINT(pattern), *dissector);
            return TRUE;
        case FT_STRING:
        case FT_STRINGZ:
        case FT_UINT_STRING:
        case FT_STRINGZPAD:
            dissector_change_string(name, (!pattern)?"":(gchar *) pattern, *dissector);
            return TRUE;
        default:
            return FALSE;
        };

        return FALSE;
    }

    return TRUE;
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
