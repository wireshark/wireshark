/* packet-llc.h
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

#ifndef __PACKET_LLC_H__
#define __PACKET_LLC_H__

#include "ws_symbol_export.h"

void capture_llc(const guchar *, int, int, packet_counts *);

extern const value_string sap_vals[];

void capture_snap(const guchar *, int, int, packet_counts *);

void dissect_snap(tvbuff_t *, int, packet_info *, proto_tree *,
    proto_tree *, int, int, int, int, int);

/*
 * Add an entry for a new OUI.
 */
WS_DLL_PUBLIC
void llc_add_oui(guint32, const char *, const char *, hf_register_info *);

/*
 * SNAP information about the PID for a particular OUI:
 *
 *	the dissector table to use with the PID's value;
 *	the field to use for the PID.
 */
typedef struct {
	dissector_table_t table;
	hf_register_info *field_info;
} oui_info_t;

/*
 * Return the oui_info_t for the PID for a particular OUI value, or NULL
 * if there isn't one.
 */
oui_info_t *get_snap_oui_info(guint32);

#endif
