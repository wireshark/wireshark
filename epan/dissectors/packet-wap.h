/* packet-wap.h
 *
 * Declarations for WAP packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#ifndef __PACKET_WAP_H__
#define __PACKET_WAP_H__

#include <glib.h>
#include <epan/packet.h>

/* Port Numbers as per IANA */
/* < URL:http://www.iana.org/assignments/port-numbers/ > */
#define UDP_PORT_WSP			9200		/* wap-wsp			*/
#define UDP_PORT_WTP_WSP		9201		/* wap-wsp-wtp		*/
#define UDP_PORT_WTLS_WSP		9202		/* wap-wsp-s		*/
#define UDP_PORT_WTLS_WTP_WSP		9203		/* wap-wsp-wtp-s	*/
#define UDP_PORT_WSP_PUSH		2948		/* wap-wsp		*/
#define UDP_PORT_WTLS_WSP_PUSH		2949		/* wap-wsp-s		*/

/*
 * Note:
 *   There are four dissectors for the WAP protocol:
 *     WTLS
 *     WTP
 *     WSP
 *     WMLC
 *   Which of these are necessary is determined by the port number above.
 *   I.e. port 9200 (wap-wsp) indicates WSP data and possibly WMLC (depending on
 *   the WSP PDU).
 *   Port 9203 (wap-wsp-wtp-s), on the other hand, has WTLS, WTP, WSP and
 *   possibly WMLC data in that order in the packet.
 *
 *   Therefore the dissectors are chained as follows:
 *
 *   Port        Dissectors
 *   9200                     WSP  ->  WMLC
 *   9201            WTP  ->  WSP  ->  WMLC
 *   9202  WTLS  ->           WSP  ->  WMLC
 *   9203  WTLS  ->  WTP  ->  WSP  ->  WMLC
 *
 *   2948                     WSP  ->  WMLC (Push)
 *   2949  WTLS  ->           WSP  ->  WMLC (Push)
 *
 *   At present, only the unencrypted parts of WTLS can be analysed. Therefore
 *   the WTP and WSP dissectors are not called.
 */

#define HF_EMPTY	( -1 )
#define ETT_EMPTY	( -1 )

/* Utility function for reading Uintvar encoded values */
guint tvb_get_guintvar (tvbuff_t *, guint , guint *);

/* Character set encoding */
extern value_string_ext wap_mib_enum_vals_character_sets_ext;

/*
 * Misc TODO:
 *
 * WMLC Dissector
 * Check Protocol display
 * Check Protocol information display
 * Check CONNECT/CONNECT REPLY headers
 * Check add_headers code
 * Check Content-Length code
 *
 */

#endif /* packet-wap.h */
