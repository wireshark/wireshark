/* packet-frame.c
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * $Id: packet-frame.c,v 1.6 2001/01/03 06:55:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2000 Gerald Combs
 *
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

#include <glib.h>
#include "packet.h"
#include "timestamp.h"
#include "tvbuff.h"
#include "packet-frame.h"

static int proto_frame = -1;
static int hf_frame_arrival_time = -1;
static int hf_frame_time_delta = -1;
static int hf_frame_time_relative = -1;
static int hf_frame_number = -1;
static int hf_frame_packet_len = -1;
static int hf_frame_capture_len = -1;
static int hf_frame_p2p_dir = -1;
static int proto_short = -1;
int proto_malformed = -1;

static gint ett_frame = -1;

static const value_string p2p_dirs[] = {
	{ P2P_DIR_SENT,	"Sent" },
	{ P2P_DIR_RECV, "Received" },
	{ 0, NULL }
};

static dissector_table_t wtap_encap_dissector_table;
	
void
dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*fh_tree;
	proto_item	*ti;
	struct timeval	tv;
	int		cap_len, pkt_len;

	pinfo->current_proto = "Frame";

	if (pinfo->fd->lnk_t == WTAP_ENCAP_LAPD ||
			pinfo->fd->lnk_t == WTAP_ENCAP_PPP_WITH_PHDR) {

		pinfo->p2p_dir = pinfo->pseudo_header->p2p.sent ? P2P_DIR_SENT : P2P_DIR_RECV;
	}

	/* Put in frame header information. */
	if (tree) {

	  cap_len = tvb_length(tvb);
	  pkt_len = tvb_reported_length(tvb);

	  ti = proto_tree_add_protocol_format(tree, proto_frame, tvb, 0, tvb_length(tvb),
	    "Frame %u (%u on wire, %u captured)", pinfo->fd->num, pkt_len, cap_len);

	  fh_tree = proto_item_add_subtree(ti, ett_frame);

	  tv.tv_sec = pinfo->fd->abs_secs;
	  tv.tv_usec = pinfo->fd->abs_usecs;

	  proto_tree_add_time(fh_tree, hf_frame_arrival_time, tvb,
		0, 0, &tv);

	  tv.tv_sec = pinfo->fd->del_secs;
	  tv.tv_usec = pinfo->fd->del_usecs;

	  proto_tree_add_time(fh_tree, hf_frame_time_delta, tvb,
		0, 0, &tv);

	  tv.tv_sec = pinfo->fd->rel_secs;
	  tv.tv_usec = pinfo->fd->rel_usecs;

	  proto_tree_add_time(fh_tree, hf_frame_time_relative, tvb,
		0, 0, &tv);

	  proto_tree_add_uint(fh_tree, hf_frame_number, tvb,
		0, 0, pinfo->fd->num);

	  proto_tree_add_uint_format(fh_tree, hf_frame_packet_len, tvb,
		0, 0, pkt_len, "Packet Length: %d byte%s", pkt_len,
		plurality(pkt_len, "", "s"));
		
	  proto_tree_add_uint_format(fh_tree, hf_frame_capture_len, tvb,
		0, 0, cap_len, "Capture Length: %d byte%s", cap_len,
		plurality(cap_len, "", "s"));

	  /* Check for existences of P2P pseudo header */
	  if (pinfo->p2p_dir != P2P_DIR_UNKNOWN) {
		  proto_tree_add_uint(fh_tree, hf_frame_p2p_dir, tvb,
				  0, 0, pinfo->p2p_dir);
	  }
	}


	TRY {
		if (!dissector_try_port(wtap_encap_dissector_table, pinfo->fd->lnk_t,
					tvb, pinfo, tree)) {

			if (check_col(pinfo->fd, COL_PROTOCOL))
				col_set_str(pinfo->fd, COL_PROTOCOL, "UNKNOWN");
			if (check_col(pinfo->fd, COL_INFO))
				col_add_fstr(pinfo->fd, COL_INFO, "WTAP_ENCAP = 0x%x", pinfo->fd->lnk_t);
			dissect_data(tvb, 0, pinfo, tree);
		}
	}
	CATCH(BoundsError) {
		if (check_col(pinfo->fd, COL_INFO))
			col_append_str(pinfo->fd, COL_INFO, "[Short Frame]");
		proto_tree_add_protocol_format(tree, proto_short, tvb, 0, 0,
				"[Short Frame: %s]", pinfo->current_proto );
	}
	CATCH(ReportedBoundsError) {
		if (check_col(pinfo->fd, COL_INFO))
			col_append_str(pinfo->fd, COL_INFO, "[Malformed Frame]");
		proto_tree_add_protocol_format(tree, proto_malformed, tvb, 0, 0,
				"[Malformed Frame: %s]", pinfo->current_proto );
	}
	ENDTRY;
}

void
proto_register_frame(void)
{
	static hf_register_info hf[] = {
		{ &hf_frame_arrival_time,
		{ "Arrival Time",		"frame.time", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
			""}},

		{ &hf_frame_time_delta,
		{ "Time delta from previous packet",	"frame.time_delta", FT_RELATIVE_TIME, BASE_NONE, NULL,
			0x0,
			"" }},

		{ &hf_frame_time_relative,
		{ "Time relative to first packet",	"frame.time_relative", FT_RELATIVE_TIME, BASE_NONE, NULL,
			0x0,
			"" }},

		{ &hf_frame_number,
		{ "Frame Number",		"frame.number", FT_UINT32, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_frame_packet_len,
		{ "Total Frame Length",		"frame.pkt_len", FT_UINT32, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_frame_capture_len,
		{ "Capture Frame Length",	"frame.cap_len", FT_UINT32, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_frame_p2p_dir,
		{ "Point-to-Point Direction",	"frame.p2p_dir", FT_UINT8, BASE_DEC, VALS(p2p_dirs), 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_frame,
	};

	wtap_encap_dissector_table = register_dissector_table("wtap_encap");

	proto_frame = proto_register_protocol("Frame", "Frame", "frame");
	proto_register_field_array(proto_frame, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* You can't disable dissection of "Frame", as that would be
	   tantamount to not doing any dissection whatsoever. */
	proto_set_cant_disable(proto_frame);

	proto_short = proto_register_protocol("Short Frame", "Short frame", "short");
	proto_malformed = proto_register_protocol("Malformed Frame",
	    "Malformed frame", "malformed");

	/* "Short Frame" and "Malformed Frame" aren't really protocols,
	   they're error indications; disabling them makes no sense. */
	proto_set_cant_disable(proto_short);
	proto_set_cant_disable(proto_malformed);
}
