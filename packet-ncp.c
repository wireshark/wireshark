/* packet-ncp.c
 * Routines for NetWare Core Protocol
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Modified to allow NCP over TCP/IP decodes by James Coe <jammer@cin.net>
 *
 * $Id: packet-ncp.c,v 1.54 2002/01/21 07:36:37 guy Exp $
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

static gint ett_ncp = -1;

#define TCP_PORT_NCP		524
#define UDP_PORT_NCP		524

#define NCP_RQST_HDR_LENGTH	7
#define NCP_RPLY_HDR_LENGTH	8

/* Hash functions */
gint  ncp_equal (gconstpointer v, gconstpointer v2);
guint ncp_hash  (gconstpointer v);

static guint ncp_packet_init_count = 200;

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


/* NCP packets come in request/reply pairs. The request packets tell the type
 * of NCP request and give a sequence ID. The response, unfortunately, only
 * identifies itself via the sequence ID; you have to know what type of NCP
 * request the request packet contained in order to successfully parse the NCP
 * response. A global method for doing this does not exist in ethereal yet
 * (NFS also requires it), so for now the NCP section will keep its own hash
 * table keeping track of NCP packet types.
 *
 * We construct a conversation specified by the client and server
 * addresses and the connection number; the key representing the unique
 * NCP request then is composed of the pointer to the conversation
 * structure, cast to a "guint" (which may throw away the upper 32
 * bits of the pointer on a P64 platform, but the low-order 32 bits
 * are more likely to differ between conversations than the upper 32 bits),
 * and the sequence number.
 *
 * The value stored in the hash table is the ncp_request_val pointer. This
 * struct tells us the NCP type and gives the ncp2222_record pointer, if
 * ncp_type == 0x2222.
 */
typedef struct {
	conversation_t	*conversation;
	guint8		nw_sequence;
} ncp_request_key;


static GHashTable *ncp_request_hash = NULL;
static GMemChunk *ncp_request_keys = NULL;

/* Hash Functions */
gint  ncp_equal (gconstpointer v, gconstpointer v2)
{
	ncp_request_key	*val1 = (ncp_request_key*)v;
	ncp_request_key	*val2 = (ncp_request_key*)v2;

	if (val1->conversation == val2->conversation &&
	    val1->nw_sequence  == val2->nw_sequence ) {
		return 1;
	}
	return 0;
}

guint ncp_hash  (gconstpointer v)
{
	ncp_request_key	*ncp_key = (ncp_request_key*)v;
	return GPOINTER_TO_UINT(ncp_key->conversation) + ncp_key->nw_sequence;
}

/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in ethereal */
static void
ncp_init_protocol(void)
{
	if (ncp_request_hash)
		g_hash_table_destroy(ncp_request_hash);
	if (ncp_request_keys)
		g_mem_chunk_destroy(ncp_request_keys);

	ncp_request_hash = g_hash_table_new(ncp_hash, ncp_equal);
	ncp_request_keys = g_mem_chunk_new("ncp_request_keys",
			sizeof(ncp_request_key),
			ncp_packet_init_count * sizeof(ncp_request_key), G_ALLOC_AND_FREE);
}

/* After the sequential run, we don't need the ncp_request hash and keys
 * anymore; the lookups have already been done and the vital info
 * saved in the reply-packets' private_data in the frame_data struct. */
static void
ncp_postseq_cleanup(void)
{
	if (ncp_request_hash) {
		g_hash_table_destroy(ncp_request_hash);
		ncp_request_hash = NULL;
	}
	if (ncp_request_keys) {
		g_mem_chunk_destroy(ncp_request_keys);
		ncp_request_keys = NULL;
	}
}

void
ncp_hash_insert(conversation_t *conversation, guint8 nw_sequence,
		const ncp_record *ncp_rec)
{
	ncp_request_key		*request_key;

	/* Now remember the request, so we can find it if we later
	   a reply to it. */
	request_key = g_mem_chunk_alloc(ncp_request_keys);
	request_key->conversation = conversation;
	request_key->nw_sequence = nw_sequence;

	g_hash_table_insert(ncp_request_hash, request_key, (void*)ncp_rec);
}

/* Returns the ncp_rec*, or NULL if not found. */
const ncp_record*
ncp_hash_lookup(conversation_t *conversation, guint8 nw_sequence)
{
	ncp_request_key		request_key;

	request_key.conversation = conversation;
	request_key.nw_sequence = nw_sequence;

	return g_hash_table_lookup(ncp_request_hash, &request_key);
}

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
		ti = proto_tree_add_item(tree, proto_ncp, tvb, 0, tvb_length(tvb), FALSE);
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
			header.sequence, header.type, ncp_tree, tree);
	}
	else if (header.type == 0x3333) {
		next_tvb = tvb_new_subset( tvb, hdr_offset, -1, -1 );
		dissect_ncp_reply(next_tvb, pinfo, nw_connection,
			header.sequence, ncp_tree, tree);
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
  module_t *ncp_module;

  proto_ncp = proto_register_protocol("NetWare Core Protocol", "NCP", "ncp");
  proto_register_field_array(proto_ncp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&ncp_init_protocol);
  register_postseq_cleanup_routine(&ncp_postseq_cleanup);

  /* Register a configuration option for initial size of NCP hash */
  ncp_module = prefs_register_protocol(proto_ncp, NULL);
  prefs_register_uint_preference(ncp_module, "initial_hash_size",
	"Initial Hash Size",
	"Number of entries initially allocated for NCP hash",
	10, &ncp_packet_init_count);
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
