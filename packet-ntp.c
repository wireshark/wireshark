/* packet-ntp.c
 * Routines for NTP packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-ntp.c,v 1.1 1999/10/14 05:10:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-ntp.h"

static int proto_ntp = -1;
static int hf_ntp_flags = -1;
static int hf_ntp_stratum = -1;
static int hf_ntp_ppoll = -1;
static int hf_ntp_precision = -1;
static int hf_ntp_rootdelay = -1;
static int hf_ntp_rootdispersion = -1;
static int hf_ntp_refid = -1;
static int hf_ntp_reftime = -1;
static int hf_ntp_org = -1;
static int hf_ntp_rec = -1;
static int hf_ntp_xmt = -1;
static int hf_ntp_keyid = -1;
static int hf_ntp_mac = -1;

void
dissect_ntp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *ntp_tree, *ti;
	struct ntp_packet *pkt;

	/* get at least a full packet structure */
	if ( !BYTES_ARE_IN_FRAME(offset, 48) ) /* 48 without keyid or mac */
		return;

	pkt = (struct ntp_packet *) &pd[offset];
	
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NTP");

	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, "NTP");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ntp, offset, END_OF_FRAME, NULL);
		ntp_tree = proto_item_add_subtree(ti, ETT_NTP);

		proto_tree_add_item(ntp_tree, hf_ntp_flags, offset, 1, pkt->flags);
		proto_tree_add_item(ntp_tree, hf_ntp_stratum, offset+1, 1, pkt->stratum);
		proto_tree_add_item(ntp_tree, hf_ntp_ppoll, offset+2, 1, pkt->ppoll);
		proto_tree_add_item(ntp_tree, hf_ntp_precision, offset+3, 1, pkt->precision);
		proto_tree_add_item(ntp_tree, hf_ntp_rootdelay, offset+4, 4, pkt->rootdelay);
		proto_tree_add_item(ntp_tree, hf_ntp_rootdispersion, offset+8, 4, pkt->rootdispersion);
		proto_tree_add_item(ntp_tree, hf_ntp_refid, offset+12, 4, pkt->refid);
		proto_tree_add_item(ntp_tree, hf_ntp_reftime, offset+16, 8, pkt->reftime);
		proto_tree_add_item(ntp_tree, hf_ntp_org, offset+24, 8, pkt->org);
		proto_tree_add_item(ntp_tree, hf_ntp_rec, offset+32, 8, pkt->rec);
		proto_tree_add_item(ntp_tree, hf_ntp_xmt, offset+40, 8, pkt->xmt);

		if ( BYTES_ARE_IN_FRAME(offset, 50) )
			proto_tree_add_item(ntp_tree, hf_ntp_keyid, offset+48, 4, pkt->keyid);
		if ( BYTES_ARE_IN_FRAME(offset, 53) )
			proto_tree_add_item(ntp_tree, hf_ntp_mac, offset+52, END_OF_FRAME, pkt->mac);
	}
}

void
proto_register_ntp(void)
{
	static hf_register_info hf[] = {
			{ &hf_ntp_flags, {	
				"Flags", "ntp.flags", FT_BYTES, BASE_HEX, 
				NULL, 0, "Flags (Leap/Version/Mode)" }},
			{ &hf_ntp_stratum, {	
				"Peer Clock Stratum", "ntp.stratum", FT_BYTES, BASE_HEX, 
				NULL, 0, "Peer Clock Stratum" }},
			{ &hf_ntp_ppoll, {	
				"Peer Polling Interval", "ntp.ppoll", FT_BYTES, BASE_HEX, 
				NULL, 0, "Peer Polling Interval" }},
			{ &hf_ntp_precision, {	
				"Peer Clock Precision", "ntp.precision", FT_BYTES, BASE_HEX, 
				NULL, 0, "Peer Clock Precision" }},
			{ &hf_ntp_rootdelay, {	
				"Distance to Primary", "ntp.rootdelay", FT_BYTES, BASE_HEX, 
				NULL, 0, "Distance to Primary" }},
			{ &hf_ntp_rootdispersion, {	
				"Clock Dispersion", "ntp.rootdispersion", FT_BYTES, BASE_HEX, 
				NULL, 0, "Clock Dispersion" }},
			{ &hf_ntp_refid, {	
				"Reference Clock ID", "ntp.refid", FT_BYTES, BASE_HEX, 
				NULL, 0, "Reference Clock ID" }},
			{ &hf_ntp_reftime, {	
				"Reference Clock Update Time", "ntp.reftime", FT_BYTES, BASE_HEX, 
				NULL, 0, "Reference Clock Update Time" }},
			{ &hf_ntp_org, {	
				"Originate Time Stamp", "ntp.org", FT_BYTES, BASE_HEX, 
				NULL, 0, "Originate Time Stamp" }},
			{ &hf_ntp_rec, {	
				"Receive Time Stamp", "ntp.rec", FT_BYTES, BASE_HEX, 
				NULL, 0, "Receive Time Stamp" }},
			{ &hf_ntp_xmt, {	
				"Transmit Time Stamp", "ntp.xmt", FT_BYTES, BASE_HEX, 
				NULL, 0, "Transmit Time Stamp" }},
			{ &hf_ntp_keyid, {	
				"Key ID", "ntp.keyid", FT_BYTES, BASE_HEX, 
				NULL, 0, "Key ID" }},
			{ &hf_ntp_mac, {	
				"Message Authentication Code", "ntp.mac", FT_BYTES, BASE_HEX, 
				NULL, 0, "Message Authentication Code" }},
        };

	proto_ntp = proto_register_protocol("Network Time Protocol", "ntp");
	proto_register_field_array(proto_ntp, hf, array_length(hf));
}
