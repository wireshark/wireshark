/* packet-llc.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LLC_H__
#define __PACKET_LLC_H__

#include "ws_symbol_export.h"

extern const value_string sap_vals[];

void dissect_snap(tvbuff_t *, int, packet_info *, proto_tree *,
    proto_tree *, int, int, int, int, int);

/*
 * Add an entry for a new OUI.
 */
WS_DLL_PUBLIC
void llc_add_oui(guint32, const char *, const char *, hf_register_info *, const int);

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
