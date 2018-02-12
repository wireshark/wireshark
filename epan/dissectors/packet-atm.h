/* packet-atm.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ATM_H__
#define __PACKET_ATM_H__

gboolean atm_is_oam_cell(const guint16 vci, const guint8 pt); /*For pw-atm dissector*/

extern const value_string atm_pt_vals[]; /*For pw-atm dissector*/

#endif
