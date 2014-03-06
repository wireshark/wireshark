/* packet-sdp.h
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 * 2005 Alejandro Vaquero <alejandro.vaquero@verso.com>, add support for tap
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

typedef struct _sdp_packet_info {
		gchar summary_str[50];		/* SDP summary string for VoIP calls graph analysis */
} sdp_packet_info;

enum sdp_exchange_type
{
	SDP_EXCHANGE_OFFER = 0,
	SDP_EXCHANGE_ANSWER_ACCEPT,
	SDP_EXCHANGE_ANSWER_REJECT
};

extern void setup_sdp_transport(tvbuff_t *tvb, packet_info *pinfo, enum sdp_exchange_type type, int request_frame, const gboolean delay);
/* Handles duplicate OFFER packets so they don't end up processed by dissect_sdp().  This can probably
 * be removed when all higher layer dissectors properly handle SDP themselves with setup_sdp_transport()
 */
extern void setup_sdp_transport_resend(int current_frame, int request_frame);
