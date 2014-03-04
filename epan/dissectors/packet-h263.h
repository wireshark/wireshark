/* packet-h263.h
 *
 * Common variables for H.263 dissectors
 *
 * Copyright 2003 Niklas Ogren <niklas.ogren@7l.se>
 * Seven Levels Consultants AB
 *
 * Copyright 2008 Richard van der Hoff, MX Telecom
 * <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied structure from packet-h261.c
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

#ifndef __PACKET_H263_H__
#define __PACKET_H263_H__

/* Source format types */
#define H263_SRCFORMAT_FORB	0  /* forbidden */
#define H263_SRCFORMAT_SQCIF	1
#define H263_SRCFORMAT_QCIF	2
#define H263_SRCFORMAT_CIF	3
#define H263_SRCFORMAT_4CIF	4
#define H263_SRCFORMAT_16CIF	5
#define H263_PLUSPTYPE		7

extern const value_string h263_srcformat_vals[];

/* XXX: these ought to be reworked to use the normal call_dissector interface. */
int dissect_h263_picture_layer( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint length, gboolean is_rfc4626);
int dissect_h263_group_of_blocks_layer( tvbuff_t *tvb, proto_tree *tree, gint offset, gboolean is_rfc4626);


#endif

