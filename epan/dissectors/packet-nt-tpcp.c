/* packet-tpcp.c
* Routines for Transparent Proxy Cache Protocol packet disassembly
* (c) Copyright Giles Scott <giles.scott1 [AT] btinternet.com>
*
* $Id$
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

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h> /* this is for get_hostname and get_udp_port */

#define UDP_PORT_TPCP   3121

/* TPCP version1/2 PDU format */
typedef struct _tpcppdu_t {
	guint8	version;     /* PDU version 1 */
	guint8	type;	     /* PDU type: 1=request, 2=reply, 3=add filter, 4=rem  filter */
	                     /* Version 2 adds 5=add session 6= remove session */
	guint16	flags;	     /* 0x0001: 0=UDP, 1=TCP*/
	                     /* 0x0002: 0=NONE, 1=DONT REDIRECT */
	                     /* 0x0004: 0=NONE, 1=Xon */
	                     /* 0x0008: 0=NONE, 1=Xoff */
	guint16	id;	     /* request/response identification or TTL */
	guint16	cport;	     /* client UDP or TCP port number */
	guint32	caddr;	     /* client IPv4 address */
	guint32	saddr;	     /* server IPV4 address */
	/* tpcp version 2 only*/
	guint32 vaddr;	     /* Virtual Server IPv4 address */
	guint32 rasaddr;     /* RAS server IPv4 address */
	guint32 signature;   /* 0x74706370 - tpcp */
} tpcpdu_t;


static const value_string type_vals[] = {
	{ 1, "Request" },
	{ 2, "Reply" },
	{ 3, "Add Filter" },
	{ 4, "Remove Filter" },
	/* 5 and 6 are for version 2 only */
	{ 5, "Add Session" },
	{ 6, "Remove Session" },
	{ 0,  NULL }
};

/* TPCP Flags */
#define TF_TPCP_UDPTCP 0x0001
#define TF_TPCP_DONTREDIRECT 0x0002
#define TF_TPCP_XON 0x0004
#define TF_TPCP_XOFF 0x0008


/* Version info */
#define TPCP_VER_1 1
#define TPCP_VER_2 2

#define TPCP_VER_1_LENGTH 16
#define TPCP_VER_2_LENGTH 28

/* things we can do filters on */
static int hf_tpcp_version = -1;
static int hf_tpcp_type = -1;
static int hf_tpcp_flags_tcp = -1;
static int hf_tpcp_flags_redir = -1;
static int hf_tpcp_flags_xon = -1;
static int hf_tpcp_flags_xoff = -1;
static int hf_tpcp_id = -1;
static int hf_tpcp_cport = -1;
static int hf_tpcp_caddr = -1;
static int hf_tpcp_saddr = -1;
static int hf_tpcp_vaddr = -1;
static int hf_tpcp_rasaddr = -1;

static int proto_tpcp = -1;

static gint ett_tpcp = -1;
static gint ett_tpcp_flags = -1;


static void
dissect_tpcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tpcpdu_t    tpcph;
	proto_tree *tpcp_tree = NULL, *field_tree = NULL;
	proto_item *ti, *tf;
	guint8      length    = TPCP_VER_1_LENGTH;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPCP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* need to find out which version!! */
	tpcph.version = tvb_get_guint8(tvb, 0);
	/* as version 1 and 2 are so similar use the same structure, just don't use as much for version 1*/
	/* XXX: Doing a memcpy into a struct is *not* kosher */
	if (tpcph.version == TPCP_VER_1) {
		length = TPCP_VER_1_LENGTH;
		tvb_memcpy(tvb, (guint8 *) &tpcph, 0, length);
	} else if (tpcph.version == TPCP_VER_2){
		length = TPCP_VER_2_LENGTH;
		tvb_memcpy(tvb, (guint8 *) &tpcph, 0, length);
	} else {
		memset (&tpcph, 0, sizeof (tpcph));
	}


	tpcph.id        = g_ntohs(tpcph.id);
	tpcph.flags     = g_ntohs(tpcph.flags);
	tpcph.cport     = g_ntohs(tpcph.cport);
	tpcph.signature = g_ntohl(tpcph.signature);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO,"%s id %d CPort %s CIP %s SIP %s",
		val_to_str_const(tpcph.type, type_vals, "Unknown"),
		tpcph.id,
		get_udp_port(tpcph.cport),
		ip_to_str((guint8 *)&tpcph.caddr),
		ip_to_str((guint8 *)&tpcph.saddr));

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_tpcp, tvb, 0, length,
			"Alteon WebSystems - Transparent Proxy Cache Protocol");

		tpcp_tree = proto_item_add_subtree(ti, ett_tpcp);

		proto_tree_add_uint(tpcp_tree, hf_tpcp_version, tvb, 0, 1, tpcph.version);

		proto_tree_add_uint_format(tpcp_tree, hf_tpcp_type, tvb, 1, 1, tpcph.type,
			"Type: %s (%d)",
			val_to_str_const(tpcph.type, type_vals, "Unknown"), tpcph.type);

		/* flags next , i'll do that when I can work out how to do it :-(   */
		tf = proto_tree_add_text(tpcp_tree, tvb, 2, 2, "Flags: 0x%04x",tpcph.flags);

		field_tree = proto_item_add_subtree(tf, ett_tpcp_flags);
		proto_tree_add_boolean(field_tree, hf_tpcp_flags_tcp, tvb, 2, 2, tpcph.flags);
		proto_tree_add_boolean(field_tree, hf_tpcp_flags_redir, tvb, 2,2, tpcph.flags);
		proto_tree_add_boolean(field_tree, hf_tpcp_flags_xon, tvb, 2, 2, tpcph.flags);
		proto_tree_add_boolean(field_tree, hf_tpcp_flags_xoff, tvb, 2, 2, tpcph.flags);

		proto_tree_add_uint(tpcp_tree, hf_tpcp_id, tvb, 4, 2, tpcph.id);

		proto_tree_add_uint_format(tpcp_tree, hf_tpcp_cport, tvb, 6, 2, tpcph.cport,
			"Client Source port: %s", get_udp_port(tpcph.cport));

		proto_tree_add_ipv4(tpcp_tree, hf_tpcp_caddr, tvb, 8, 4, tpcph.caddr);

		proto_tree_add_ipv4(tpcp_tree, hf_tpcp_saddr, tvb, 12, 4, tpcph.saddr);

		if (tpcph.version == TPCP_VER_2) {
			proto_tree_add_ipv4(tpcp_tree, hf_tpcp_vaddr, tvb, 16, 4, tpcph.vaddr);
			proto_tree_add_ipv4(tpcp_tree, hf_tpcp_rasaddr, tvb, 20, 4, tpcph.rasaddr);
			proto_tree_add_text(tpcp_tree, tvb, 24, 4, "Signature: %u", tpcph.signature);
		}

	}
}

void
proto_register_tpcp(void)
{
	static hf_register_info hf[] = {
		{ &hf_tpcp_version,
		{ "Version",		"tpcp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
		"TPCP version", HFILL }},

		{ &hf_tpcp_type,
		{ "Type",		"tpcp.type", FT_UINT8, BASE_DEC,NULL, 0x0,
		"PDU type", HFILL }},

		{ &hf_tpcp_flags_tcp,
		{ "UDP/TCP",		"tpcp.flags.tcp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TF_TPCP_UDPTCP,
		"Protocol type", HFILL }},

		{ &hf_tpcp_flags_redir,
		{ "No Redirect",	"tpcp.flags.redir", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TF_TPCP_DONTREDIRECT,
		"Don't redirect client", HFILL }},

		{ &hf_tpcp_flags_xon,
		{ "XON",		"tpcp.flags.xon", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TF_TPCP_XON,
		NULL, HFILL }},

		{ &hf_tpcp_flags_xoff,
		{ "XOFF",		"tpcp.flags.xoff", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TF_TPCP_XOFF,
		NULL, HFILL }},

		{ &hf_tpcp_id,
		{ "Client indent",	"tpcp.cid", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_tpcp_cport,
		{ "Client Source Port",	"tpcp.cport", FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_tpcp_caddr,
		{ "Client Source IP address",	"tpcp.caddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_tpcp_saddr,
		{ "Server IP address",	"tpcp.saddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_tpcp_vaddr,
		{ "Virtual Server IP address", "tpcp.vaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

		{ &hf_tpcp_rasaddr,
		{ "RAS server IP address", "tpcp.rasaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},

	};


	static gint *ett[] = {
		&ett_tpcp,
		&ett_tpcp_flags,
	};

	proto_tpcp = proto_register_protocol("Alteon - Transparent Proxy Cache Protocol",
					     "TPCP", "tpcp");
	proto_register_field_array(proto_tpcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tpcp(void)
{
	dissector_handle_t tpcp_handle;

	tpcp_handle = create_dissector_handle(dissect_tpcp, proto_tpcp);
	dissector_add_uint("udp.port", UDP_PORT_TPCP, tpcp_handle);
}
