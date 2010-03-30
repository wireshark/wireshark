/* packet-q708.h
 * Routine and tables for analyzing an ISPC according to Q.708
 * Copyright 2010, Gerasimos Dimitriadis <dimeg [AT] intracom.gr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_Q708_H__
#define __PACKET_Q708_H__

#include <epan/value_string.h>

extern const value_string q708_sanc_areas[];
extern const value_string q708_ispc_point_name[];
extern const value_string q708_ispc_operator_name[];

void analyze_q708_ispc(tvbuff_t *tvb, proto_tree *tree, int offset, int length, guint16 ispc);

#endif /* __PACKET_Q708_H__ */
