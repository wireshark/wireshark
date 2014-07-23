/* conversation_ui.c
 * Copied from gtk/conversations_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
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

#include "conversation_ui.h"
#include "utf8_entities.h"

const char *column_titles[CONV_NUM_COLUMNS] = {
    "Address A",
    "Port A",
    "Address B",
    "Port B",
    "Packets",
    "Bytes",
    "Packets A " UTF8_RIGHTWARDS_ARROW " B",
    "Bytes A " UTF8_RIGHTWARDS_ARROW " B",
    "Packets B " UTF8_RIGHTWARDS_ARROW " A",
    "Bytes B " UTF8_RIGHTWARDS_ARROW " A",
    "Rel Start",
    "Duration",
    "bps A " UTF8_RIGHTWARDS_ARROW " B",
    "bps B " UTF8_RIGHTWARDS_ARROW " A"
};

const char *conn_a_title = "Connection A";
const char *conn_b_title = "Connection B";



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
