/* packet-diffserv-mpls-common.h
 * Routines for the common part of Diffserv MPLS signaling protocols
 * Author: Endoh Akira (endoh@netmarks.co.jp)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
			     int offset, int **hfindexes, int **etts);

#endif
