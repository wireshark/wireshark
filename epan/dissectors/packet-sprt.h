/* packet-sprt.h
 *
 * Routines for SPRT dissection
 * SPRT = Simple Packet Relay Transport
 *
 * Written by Jamison Adcock <jamison.adcock@cobham.com>
 * for Sparta Inc., dba Cobham Analytic Solutions
 * This code is largely based on the RTP parsing code
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_SPRT_H
#define _PACKET_SPRT_H

void sprt_add_address(packet_info *pinfo,
                      address *addr,
                      int port,
                      int other_port,
                      const char *setup_method,
                      uint32_t setup_frame_number);



#endif /* _PACKET_SPRT_H */
