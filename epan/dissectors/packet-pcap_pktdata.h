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
