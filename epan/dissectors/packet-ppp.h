/* packet-ppp.h
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

#ifndef __PACKET_PPP_H__
#define __PACKET_PPP_H__

#include <epan/params.h>
#include "ws_symbol_export.h"

tvbuff_t *decode_fcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fh_tree, int fcs_decode, int proto_offset);

/*
 * Used by the GTP dissector as well.
 */
extern value_string_ext ppp_vals_ext;

/*
 * Used by CHDLC dissector as well.
 */
extern const enum_val_t fcs_options[];

#endif
