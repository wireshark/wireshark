/* dissector_filters.c
 * Routines for dissector generated display filters
 *
 * $Id$
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


GList *dissector_filter_list = NULL;


void register_dissector_filter(const char *name, is_filter_valid_func is_filter_valid, build_filter_string_func build_filter_string) {
    dissector_filter_t *entry;

    entry = g_malloc(sizeof(dissector_filter_t));

    entry->name                 = name;
    entry->is_filter_valid      = is_filter_valid;
    entry->build_filter_string  = build_filter_string;

    dissector_filter_list = g_list_append(dissector_filter_list, entry);
}

