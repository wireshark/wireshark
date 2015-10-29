/* dissector_filters.c
 * Routines for dissector-generated conversation filters for use as
 * display and color filters
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

#include "dissector_filters.h"


GList *conv_filter_list = NULL;


void register_conversation_filter(const char *proto_name, const char *display_name,
                                        is_filter_valid_func is_filter_valid, build_filter_string_func build_filter_string) {
    conversation_filter_t *entry;

    entry = (conversation_filter_t *)g_malloc(sizeof(conversation_filter_t));

    entry->proto_name           = proto_name;
    entry->display_name         = display_name;
    entry->is_filter_valid      = is_filter_valid;
    entry->build_filter_string  = build_filter_string;

    conv_filter_list = g_list_append(conv_filter_list, entry);
}

struct conversation_filter_s* find_conversation_filter(const char *name)
{
    GList *list_entry = conv_filter_list;
    conversation_filter_t* filter;

    while (list_entry != NULL) {
        filter = (conversation_filter_t*)list_entry->data;
        if (!strcmp(filter->proto_name, name))
            return filter;

        list_entry = g_list_next(list_entry);
    }

    return NULL;
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
