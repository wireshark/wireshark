/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified to allow NCP over TCP/IP decodes by James Coe <jammer@cin.net>
 *
 * $Id: packet-ncp.c,v 1.56 2002/05/09 23:50:25 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2000 Gerald Combs
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include "prefs.h"
#include "packet-ipx.h"
#include "packet-ncp-int.h"

int proto_ncp = -1;
static int hf_ncp_ip_ver = -1;
static int hf_ncp_ip_length = -1;
static int hf_ncp_ip_rplybufsize = -1;
static int hf_ncp_ip_sig = -1;
static int hf_ncp_type = -1;
static int hf_ncp_seq = -1;
static int hf_ncp_connection = -1;
static int hf_ncp_task = -1;

gint ett_ncp = -1;

#define TCP_PORT_NCP		524
#define UDP_PORT_NCP		524

#define NCP_RQST_HDR_LENGTH	7
#define NCP_RPLY_HDR_LENGTH	8

/* Hash functions */
gint  ncp_equal (gconstpointer v, gconstpointer v2);
guint ncp_hash  (gconstpointer v);

/* These are the header structures to handle NCP over IP */
#define	NCPIP_RQST	0x446d6454	/* "DmdT" */
#define NCPIP_RPLY	0x744e6350	/* "tNcP" */

struct ncp_ip_header {
	guint32	signature;
	guint32 length;
};

/* This header only appears on NCP over IP request packets */
struct ncp_ip_rqhdr {
	guint32 version;
	guint32 rplybufsize;
};

static const value_string ncp_ip_signature[] = {
	{ NCPIP_RQST, "Demand Transport (Request)" },
	{ NCPIP_RPLY, "Transport is NCP (Reply)" },
	{ 0, NULL },
};

/* The information in this module comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke

  And:
	Programmer's Guide to the NetWare Core Protocol
	Steve Conner & Diane Conner
	(c) 1996 by Steve Conner & Diane Conner
	Published by Annabooks, San Diego, California
        ISBN: 0-929392-31-0

*/

/* Every NCP packet has this common header */
struct ncp_common_header {
	guint16	type;
	guint8	sequence;
	guint8	conn_low;
	guint8	task;
	guint8	conn_high; /* type=0x5555 doesn't have this */
};


static value_string ncp_type_vals[] = {
	{ 0x1111, "Create a service connection" },
	{ 0x2222, "Service request" },
	{ 0x3333, "Service reply" },
	{ 0x5555, "Destroy service connection" },
	{ 0x7777, "Burst mode transfer" },
	{ 0x9999, "Request being processed" },
	{ 0x0000, NULL }
};


static void
dissect_ncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree			*ncp_tree = NULL;
	proto_item			*ti;
	struct ncp_ip_header		ncpiph;
	struct ncp_ip_rqhdr		ncpiphrq;
	struct ncp_common_header	header;
	guint16				nw_connection;
	int				hdr_offset = 0;
	int				commhdr;
	tvbuff_t       			*next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if ( pinfo->ptype == PT_TCP || pinfo->ptype == PT_UDP ) {
		ncpiph.signature	= tvb_get_ntohl(tvb, 0);
		ncpiph.length		= tvb_get_ntohl(tvb, 4);
		hdr_offset += 8;
		if ( ncpiph.signature == NCPIP_RQST ) {
			ncpiphrq.version	= tvb_get_ntohl(tvb, hdr_offset);
			hdr_offset += 4;
			ncpiphrq.rplybufsize	= tvb_get_ntohl(tvb, hdr_offset);
			hdr_offset += 4;
		};
	};

	/* Record the offset where the NCP common header starts */
	commhdr = hdr_offset;

	header.type		= tvb_get_ntohs(tvb, commhdr);
	header.sequence		= tvb_get_guint8(tvb, commhdr+2);
	header.conn_low		= tvb_get_guint8(tvb, commhdr+3);
	header.conn_high	= tvb_get_guint8(tvb, commhdr+5);

	nw_connection = (header.conn_high << 16) + header.conn_low;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ncp, tvb, 0, -1, FALSE);
		ncp_tree = proto_item_add_subtree(ti, ett_ncp);

		if ( pinfo->ptype == PT_TCP || pinfo->ptype == PT_UDP ) {
			proto_tree_add_uint(ncp_tree, hf_ncp_ip_sig, tvb, 0, 4, ncpiph.signature);
			proto_tree_add_uint(ncp_tree, hf_ncp_ip_length, tvb, 4, 4, ncpiph.length);
			if ( ncpiph.signature == NCPIP_RQST ) {
				proto_tree_add_uint(ncp_tree, hf_ncp_ip_ver, tvb, 8, 4, ncpiphrq.version);
				proto_tree_add_uint(ncp_tree, hf_ncp_ip_rplybufsize, tvb, 12, 4, ncpiphrq.rplybufsize);
			};
		};
		proto_tree_add_uint(ncp_tree, hf_ncp_type,	tvb, commhdr + 0, 2, header.type);
		proto_tree_add_uint(ncp_tree, hf_ncp_seq,	tvb, commhdr + 2, 1, header.sequence);
		proto_tree_add_uint(ncp_tree, hf_ncp_connection,tvb, commhdr + 3, 3, nw_connection);
		proto_tree_add_item(ncp_tree, hf_ncp_task,	tvb, commhdr + 4, 1, FALSE);
	}


	if (header.type == 0x1111 || header.type == 0x2222) {
		next_tvb = tvb_new_subset( tvb, hdr_offset, -1, -1 );
		dissect_ncp_request(next_tvb, pinfo, nw_connection,
			header.sequence, header.type, ncp_tree);
	}
	else if (header.type == 0x3333) {
		next_tvb = tvb_new_subset( tvb, hdr_offset, -1, -1 );
		dissect_ncp_reply(next_tvb, pinfo, nw_connection,
			header.sequence, ncp_tree);
	}
	else if (	header.type == 0x5555 ||
			header.type == 0x7777 ||
			header.type == 0x9999		) {

		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Type 0x%04x", header.type);
		}

		if (tree) {
			proto_tree_add_text(ncp_tree, tvb, commhdr + 0, 2, "Type 0x%04x not supported yet", header.type);
		}

		return;
	}
 	else {
		/* The value_string for hf_ncp_type already indicates that this type is unknown.
		 * Just return and do no more parsing. */
 		return;
 	}
}



void
proto_register_ncp(void)
{

  static hf_register_info hf[] = {
    { &hf_ncp_ip_sig,
      { "NCP over IP signature",		"ncp.ip.signature",
        FT_UINT32, BASE_HEX, VALS(ncp_ip_signature), 0x0,
        "", HFILL }},
    { &hf_ncp_ip_length,
      { "NCP over IP length",		"ncp.ip.length",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_ip_ver,
      { "NCP over IP Version",		"ncp.ip.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_ip_rplybufsize,
      { "NCP over IP Reply Buffer Size",	"ncp.ip.replybufsize",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }},
    { &hf_ncp_type,
      { "Type",			"ncp.type",
	FT_UINT16, BASE_HEX, VALS(ncp_type_vals), 0x0,
	"NCP message type", HFILL }},
    { &hf_ncp_seq,
      { "Sequence Number",     	"ncp.seq",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_connection,
      { "Connection Number",    "ncp.connection",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }},
    { &hf_ncp_task,
      { "Task Number",     	"ncp.task",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }}
  };
  static gint *ett[] = {
    &ett_ncp,
  };

  proto_ncp = proto_register_protocol("NetWare Core Protocol", "NCP", "ncp");
  proto_register_field_array(proto_ncp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ncp(void)
{
  dissector_handle_t ncp_handle;

  ncp_handle = create_dissector_handle(dissect_ncp, proto_ncp);
  dissector_add("tcp.port", TCP_PORT_NCP, ncp_handle);
  dissector_add("udp.port", UDP_PORT_NCP, ncp_handle);
  dissector_add("ipx.packet_type", IPX_PACKET_TYPE_NCP, ncp_handle);
  dissector_add("ipx.socket", IPX_SOCKET_NCP, ncp_handle);
}
