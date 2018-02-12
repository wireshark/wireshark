/* packet-ldp.h
 * Declarations of exported routines from LDP dissector
 * Copyright 2004, Carlos Pignataro <cpignata@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LDP_H__
#define __PACKET_LDP_H__

/*
 * Used by MPLS Echo dissector as well.
 */
extern const value_string fec_vc_types_vals[];
extern const value_string fec_types_vals[];

#endif
