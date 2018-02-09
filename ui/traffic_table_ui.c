/* traffic_table_ui.c
 * Copied from gtk/conversations_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/
#include "config.h"

#include <glib.h>

#include "traffic_table_ui.h"
#include <wsutil/utf8_entities.h>

const char *conv_column_titles[CONV_NUM_COLUMNS] = {
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
    "Bits/s A " UTF8_RIGHTWARDS_ARROW " B",
    "Bits/s B " UTF8_RIGHTWARDS_ARROW " A"
};

const char *conv_conn_a_title = "Connection A";
const char *conv_conn_b_title = "Connection B";
const char *conv_abs_start_title = "Abs Start";

const char *endp_column_titles[ENDP_NUM_GEO_COLUMNS] = {
    "Address",
    "Port",
    "Packets",
    "Bytes",
    "Tx Packets",
    "Tx Bytes",
    "Rx Packets",
    "Rx Bytes",
    "Country",
    "City",
    "AS Number",
    "AS Organization"
};

const char *endp_conn_title = "Connection";

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
