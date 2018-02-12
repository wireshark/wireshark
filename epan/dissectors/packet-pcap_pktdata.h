/* packet-pcap_pktdata.h
 * Data exported from the dissector for packet data from a pcap or pcapng
 * file or from a "remote pcap" protocol.
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Link-layer header type values.
 *
 * Includes both the official documented values from
 *
 *    http://www.tcpdump.org/linktypes.html
 *
 * and values not listed there.  The names are, in most cases, the
 * LINKTYPE_ names with LINKTYPE_ stripped off.
 */
WS_DLL_PUBLIC const value_string link_type_vals[];
