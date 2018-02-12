/* packet-nsh.h
 *
 * Routines for Network Service Header
 * draft-ietf-sfc-nsh-01
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NSH_H__
#define __PACKET_NSH_H__

/*Network Service Header (NSH) Next Protocol field values */

#define NSH_IPV4            1
#define NSH_IPV6            2
#define NSH_ETHERNET        3
#define NSH_NSH             4
#define NSH_MPLS            5
#define NSH_EXPERIMENT_1    254
#define NSH_EXPERIMENT_2    255

#endif /* __PACKET_NSH_H__ */
