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

bool atm_is_oam_cell(const uint16_t vci, const uint8_t pt); /*For pw-atm dissector*/

extern const value_string atm_pt_vals[]; /*For pw-atm dissector*/

#endif
