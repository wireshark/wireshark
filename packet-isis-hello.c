/* packet-isis-hello.c
 * Routines for decoding isis hello packets and their CLVs
 *
 * $Id: packet-isis-hello.c,v 1.4 2000/03/20 22:52:42 gram Exp $
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-hello.h"

/* hello packets */
static int proto_isis_hello = -1;
static int hf_isis_hello_circuit_reserved = -1;
static int hf_isis_hello_source_id = -1;
static int hf_isis_hello_holding_timer = -1;
static int hf_isis_hello_pdu_length = -1;
static int hf_isis_hello_priority_reserved = -1;
static int hf_isis_hello_lan_id = -1;
static int hf_isis_hello_local_circuit_id = -1;
static int hf_isis_hello_clv_ipv4_int_addr = -1;

static gint ett_isis_hello = -1;
static gint ett_isis_hello_clv_area_addr = -1;
static gint ett_isis_hello_clv_is_neighbors = -1;
static gint ett_isis_hello_clv_padding = -1;
static gint ett_isis_hello_clv_unknown = -1;
static gint ett_isis_hello_clv_nlpid = -1;
static gint ett_isis_hello_clv_auth = -1;
static gint ett_isis_hello_clv_ipv4_int_addr = -1;

static const value_string isis_hello_circuit_type_vals[] = {
	{ ISIS_HELLO_TYPE_RESERVED,	"Reserved 0 (discard PDU)"},
	{ ISIS_HELLO_TYPE_LEVEL_1,	"Level 1 only"},
	{ ISIS_HELLO_TYPE_LEVEL_2,	"Level 2 only"},
	{ ISIS_HELLO_TYPE_LEVEL_12,	"Level 1 and 2"},
	{ 0,		NULL} };

/* 
 * Predclare dissectors for use in clv dissection.
 */
static void dissect_hello_area_address_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_hello_is_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_hello_padding_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_hello_nlpid_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_hello_ip_int_addr_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);
static void dissect_hello_auth_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree);

static const isis_clv_handle_t clv_l1_hello_opts[] = {
	{
		ISIS_CLV_L1H_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_L1H_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_hello_clv_is_neighbors,
		dissect_hello_is_neighbors_clv
	},
	{
		ISIS_CLV_L1H_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_L1H_NLPID,
		"NLPID",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_L1H_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_L1H_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_L1H_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_l2_hello_opts[] = {
	{
		ISIS_CLV_L2H_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_L2H_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_hello_clv_is_neighbors,
		dissect_hello_is_neighbors_clv
	},
	{
		ISIS_CLV_L2H_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_L2H_NLPID,
		"NLPID",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_L2H_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_L2H_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_L2H_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_ptp_hello_opts[] = {
	{
		ISIS_CLV_PTP_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_PTP_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_PTP_NLPID,
		"NLPID",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_PTP_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_PTP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_PTP_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: dissect_hello_nlpid_clv()
 *
 * Description:
 *	Decode for a hello packets NLPID clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_nlpid_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_nlpid_clv(pd, offset, length, fd, tree );
}

/*
 * Name: dissect_hello_ip_int_addr_clv()
 *
 * Description:
 *	Decode for a hello packets ip interface addr clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_ip_int_addr_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_ip_int_clv(pd, offset, length, fd, tree, 
		hf_isis_hello_clv_ipv4_int_addr );
}

/*
 * Name: dissect_hello_auth_clv()
 *
 * Description:
 *	Decode for a hello packets authenticaion clv.  Calls into the
 *	clv common one.  An auth inside a hello packet is a perlink
 *	password.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_auth_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_authentication_clv(pd, offset, length, fd, tree, 
		"Per Link authentication" );
}

/*
 * Name: dissect_hello_area_address_clv()
 *
 * Description:
 *	Decode for a hello packets area address clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_area_address_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
	isis_dissect_area_address_clv(pd, offset, length, fd, tree );
}

/*
 * Name: isis_dissect_is_neighbors_clv()
 * 
 * Description:
 *	Take apart a IS neighbor packet.  A neighbor is n 6 byte packets.
 *	(they tend to be an 802.3 MAC address, but its not required).
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	gint : tree id to use for proto tree.
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
void 
dissect_hello_is_neighbors_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree ) {
	while ( length > 0 ) {
		if (length<6) {
			isis_dissect_unknown(offset, length, tree, fd, 
				"short is neighbor (%d vs 6)", length );
			return;
		}
		/* 
		 * Lets turn the area address into "standard" 0000.0000.etc
		 * format string.  
		 */
		if ( tree ) {
			proto_tree_add_text ( tree, offset, 6, 
				"IS Neighbor: %02x%02x.%02x%02x.%02x%02x",
				pd[offset], pd[offset+1], pd[offset+2],
				pd[offset+3], pd[offset+3], pd[offset+4] );
		}
		offset += 6;
		length -= 6;
	}
}


/*
 * Name: dissect_hello_padding_clv()
 *
 * Description:
 *	Decode for a hello packet's padding clv.  Padding does nothing,
 *	so we just return.
 *
 * Input:
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void
 */
static void 
dissect_hello_padding_clv(const u_char *pd, int offset, guint length, 
		frame_data *fd, proto_tree *tree) {
	/* nothing to do here! */
}

/*
 * Name: isis_dissect_isis_hello()
 * 
 * Description:
 *	This procedure rips apart the various types of ISIS hellos.  L1H and
 *	L2H's are identicle for the most part, while the PTP hello has
 *	a shorter header.
 *
 * Input:
 *	int : hello type, alla packet-isis.h ISIS_TYPE_* values
 *	int : header length of packet.
 *	u_char * : packet data
 *	int offset : our offset into packet data.
 *	frame_data * : frame data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *
 * Output:
 *	void, will modify proto_tree if not NULL.
 */	
void 
isis_dissect_isis_hello(int hello_type, int header_length, 
		const u_char *pd, int offset, frame_data *fd, proto_tree *tree){
	isis_hello_t	*ihp;
	proto_item	*ti;
	proto_tree	*hello_tree = NULL;
	int 		len;
	int		hlen;

	if (hello_type == ISIS_TYPE_PTP_HELLO) {
		hlen = sizeof(*ihp) - 6;	/* make length correct */
	} else {
		hlen = sizeof(*ihp);
	}

	if (!BYTES_ARE_IN_FRAME(offset, hlen)) {
		isis_dissect_unknown(offset, hlen, tree, fd,
			"not enough capture data for header (%d vs %d)",
			hlen, END_OF_FRAME);
		return;
	}

	ihp = (isis_hello_t *) &pd[offset];	

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_hello,
			offset, END_OF_FRAME, NULL);
		hello_tree = proto_item_add_subtree(ti, ett_isis_hello);
		proto_tree_add_uint_format(hello_tree, 
			hf_isis_hello_circuit_reserved,
			offset, 1, ihp->isis_hello_circuit_reserved,
			"Circuit type: %s, reserved(0x%02x == 0)",
				val_to_str(ihp->isis_hello_circuit, 
					isis_hello_circuit_type_vals,
					"Unknown (0x%x)"),
				ihp->isis_hello_creserved
			);

		proto_tree_add_string_format(hello_tree, hf_isis_hello_lan_id,
			offset + 1, 6, ihp->isis_hello_source_id,
			"Lan ID: %02x%02x.%02x%02x.%02x%02x",
				ihp->isis_hello_lan_id[0],
				ihp->isis_hello_lan_id[1],
				ihp->isis_hello_lan_id[2],
				ihp->isis_hello_lan_id[3],
				ihp->isis_hello_lan_id[4],
				ihp->isis_hello_lan_id[5]);
		proto_tree_add_item(hello_tree, hf_isis_hello_holding_timer,
			offset + 7, 2,pntohs(&ihp->isis_hello_holding_timer[0]));
		proto_tree_add_item(hello_tree, hf_isis_hello_pdu_length,
			offset + 9, 2,pntohs(&ihp->isis_hello_pdu_length[0]));
		proto_tree_add_uint_format(hello_tree, 
			hf_isis_hello_priority_reserved,
			offset + 11, 1, ihp->isis_hello_priority_reserved,
			"Priority: %d, reserved(0x%02x == 0)",
				ihp->isis_hello_priority,
				ihp->isis_hello_preserved );
		if (hello_type == ISIS_TYPE_PTP_HELLO) {
			proto_tree_add_item(hello_tree, 
				hf_isis_hello_local_circuit_id,
				offset + 12, 1, ihp->isis_hello_lan_id[0] );
		} else { 
			proto_tree_add_string_format(hello_tree, 
				hf_isis_hello_lan_id, offset + 12, 7, 
				ihp->isis_hello_lan_id,
				"Lan ID: %02x%02x.%02x%02x.%02x%02x-%02d",
					ihp->isis_hello_lan_id[0],
					ihp->isis_hello_lan_id[1],
					ihp->isis_hello_lan_id[2],
					ihp->isis_hello_lan_id[3],
					ihp->isis_hello_lan_id[4],
					ihp->isis_hello_lan_id[5],
					ihp->isis_hello_lan_id[6]);
		}
	}

	offset += hlen;
	len = pntohs(&ihp->isis_hello_pdu_length[0]);
	len -= header_length;
	if (len < 0) {
		isis_dissect_unknown(offset, header_length, tree, fd, 
			"packet header length %d went beyond packet", 
			header_length );
		return;
	}
	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	if (hello_type == ISIS_TYPE_L1_HELLO){
		isis_dissect_clvs ( clv_l1_hello_opts, len, pd, offset, fd, 
			hello_tree, ett_isis_hello_clv_unknown );
	} else if (hello_type == ISIS_TYPE_L2_HELLO) {
		isis_dissect_clvs ( clv_l2_hello_opts, len, pd, offset, fd, 
			hello_tree, ett_isis_hello_clv_unknown );
	} else {
		isis_dissect_clvs ( clv_ptp_hello_opts, len, pd, offset, fd, 
			hello_tree, ett_isis_hello_clv_unknown );
	}
}

/*
 * Name: proto_register_isis_hello()
 *
 * Description:
 *	Register our protocol sub-sets with protocol manager.
 *	NOTE: this procedure is autolinked by the makefile process that
 *		builds register.c
 *
 * Input: 
 *	void
 *
 * Output:
 *	void
 */
void
proto_register_isis_hello(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_hello_circuit_reserved,
		{ "Circuit type",	"isis_hello.circuite_type",
			FT_UINT8, BASE_HEX, NULL, 0x0, "" }},

		{ &hf_isis_hello_source_id,
		{ "Source ID",		"isis_hello.source_id",
			FT_ETHER, BASE_HEX, NULL, 0x0, "" }},

		{ &hf_isis_hello_holding_timer,
		{ "Holding timer",	"isis_hello.holding_timer", 
			FT_UINT16, BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_hello_pdu_length,
		{ "PDU length",           "isis_hello.pdu_length",
			FT_UINT16, BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_hello_priority_reserved,
		 { "Priority",		"isis_hello.priority",FT_UINT8, BASE_DEC, NULL, 
		  ISIS_HELLO_P_RESERVED_MASK, "" }},

		{ &hf_isis_hello_lan_id,
		{ "LAN ID", "isis_hello.lan_id", FT_STRING, BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_hello_local_circuit_id,
		{ "Local circuit ID", "isis_hello.local_circuit_id", FT_UINT8,
		   BASE_DEC, NULL, 0x0, "" }},

		{ &hf_isis_hello_clv_ipv4_int_addr,
		{ "IPv4 interface address", "isis_hello.clv_ipv4_int_addr", FT_IPv4,
		   BASE_NONE, NULL, 0x0, "" }},

	};
	static gint *ett[] = {
		&ett_isis_hello,
		&ett_isis_hello_clv_area_addr,
		&ett_isis_hello_clv_is_neighbors,
		&ett_isis_hello_clv_padding,
		&ett_isis_hello_clv_unknown,
		&ett_isis_hello_clv_nlpid,
		&ett_isis_hello_clv_auth,
		&ett_isis_hello_clv_ipv4_int_addr,
	};

	proto_isis_hello = proto_register_protocol("ISIS hello", "isis_hello");
	proto_register_field_array(proto_isis_hello, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

