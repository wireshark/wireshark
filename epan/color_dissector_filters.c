/* color_dissector_filters.c
 * Routines for dissector generated display filters
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

#include "color_dissector_filters.h"


GList *color_conv_filter_list = NULL;


void register_color_conversation_filter(const char *proto_name, const char *display_name,
                                        is_color_conv_valid_func is_filter_valid, build_color_conv_string_func build_filter_string) {
    color_conversation_filter_t *entry;

    entry = (color_conversation_filter_t *)g_malloc(sizeof(color_conversation_filter_t));

    entry->proto_name           = proto_name;
    entry->display_name         = display_name;
    entry->is_filter_valid      = is_filter_valid;
    entry->build_filter_string  = build_filter_string;

    color_conv_filter_list = g_list_append(color_conv_filter_list, entry);
}

struct color_conversation_filter_s* find_color_conversation_filter(const char *name)
{
    GList *list_entry = color_conv_filter_list;
    color_conversation_filter_t* color_filter;

    while (list_entry != NULL) {
        color_filter = (color_conversation_filter_t*)list_entry->data;
        if (!strcmp(color_filter->proto_name, name))
            return color_filter;

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
