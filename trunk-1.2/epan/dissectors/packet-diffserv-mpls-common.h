/* packet-diffserv-mpls-common.h
 * Routines for the common part of Diffserv MPLS signaling protocols
 * Author: Endoh Akira (endoh@netmarks.co.jp)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __PACKET_DSMPLS_H__
#define __PACKET_DSMPLS_H__

#define PHBID_DSCP_MASK  0xFC00
#define PHBID_CODE_MASK  0xFFF0
#define PHBID_BIT14_MASK 2
#define PHBID_BIT15_MASK 1

#define MAPNB_DESCRIPTION       "Number of MAP entries"
#define MAP_DESCRIPTION         "MAP entry"
#define EXP_DESCRIPTION         "EXP bit code"
#define PHBID_DESCRIPTION       "PHBID"
#define PHBID_DSCP_DESCRIPTION  "DSCP"
#define PHBID_CODE_DESCRIPTION  "PHB id code"
#define PHBID_BIT14_DESCRIPTION "Bit 14"
#define PHBID_BIT15_DESCRIPTION "Bit 15"


extern const value_string phbid_bit14_vals[];

extern const value_string phbid_bit15_vals[];

void
dissect_diffserv_mpls_common(tvbuff_t *tvb, proto_tree *tree, int type,
			     int offset, int **hfindexes, gint **etts);

#endif
