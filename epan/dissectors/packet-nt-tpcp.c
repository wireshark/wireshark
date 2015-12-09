/* packet-nt-tpcp.c
* Routines for Transparent Proxy Cache Protocol packet disassembly
* (c) Copyright Giles Scott <giles.scott1 [AT] btinternet.com>
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


#include <epan/packet.h>
#include <epan/addr_resolv.h> /* this is for get_hostname and udp_port_to_display */

void proto_register_tpcp(void);
void proto_reg_handoff_tpcp(void);

#define UDP_PORT_TPCP   3121

/* TPCP version1/2 PDU format */
typedef struct _tpcppdu_t {
	guint8	version;     /* PDU version 1 */
	guint8	type;	     /* PDU type: 1=request, 2=reply, 3=add filter, 4=rem  filter */
	                     /* Version 2 adds 5=add session 6= remove session */
	guint16	flags;	     /* 0x0001: 0=UDP, 1=TCP*/
	                     /* 0x0002: 0=NONE, 1=DONT_REDIRECT */
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
static int hf_tpcp_flags = -1;
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
static int hf_tpcp_signature = -1;

static int proto_tpcp = -1;

static gint ett_tpcp = -1;
static gint ett_tpcp_flags = -1;


static int
dissect_tpcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *tpcp_tree = NULL;
	proto_item *ti;
	guint8	version, type;
	guint16	id, cport;

	static const int * tpcp_flags[] = {
		&hf_tpcp_flags_tcp,
		&hf_tpcp_flags_redir,
		&hf_tpcp_flags_xon,
		&hf_tpcp_flags_xoff,
		NULL
		};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPCP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* need to find out which version!! */
	version = tvb_get_guint8(tvb, 0);
	if ((version != TPCP_VER_1) && (version != TPCP_VER_2)) {
		/* Not us */
		return 0;
	}

	ti = proto_tree_add_protocol_format(tree, proto_tpcp, tvb, 0, -1,
					    "Alteon WebSystems - Transparent Proxy Cache Protocol");

	tpcp_tree = proto_item_add_subtree(ti, ett_tpcp);

	proto_tree_add_item(tpcp_tree, hf_tpcp_version, tvb, 0, 1, ENC_BIG_ENDIAN);
	type = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tpcp_tree, hf_tpcp_type, tvb, 1, 1, ENC_BIG_ENDIAN);

	proto_tree_add_bitmask(tpcp_tree, tvb, 2, hf_tpcp_flags, ett_tpcp_flags, tpcp_flags, ENC_NA);

	id = tvb_get_ntohs(tvb, 4);
	proto_tree_add_item(tpcp_tree, hf_tpcp_id, tvb, 4, 2, ENC_BIG_ENDIAN);

	cport = tvb_get_ntohs(tvb, 6);
	proto_tree_add_uint_format_value(tpcp_tree, hf_tpcp_cport, tvb, 6, 2, cport,
					 "%s", udp_port_to_display(wmem_packet_scope(), cport));

	proto_tree_add_item(tpcp_tree, hf_tpcp_caddr, tvb, 8, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tpcp_tree, hf_tpcp_saddr, tvb, 12, 4, ENC_BIG_ENDIAN);

	if (version == TPCP_VER_2) {
		proto_tree_add_item(tpcp_tree, hf_tpcp_vaddr, tvb, 16, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(tpcp_tree, hf_tpcp_rasaddr, tvb, 20, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(tpcp_tree, hf_tpcp_signature, tvb, 24, 4, ENC_BIG_ENDIAN);
	}

	col_add_fstr(pinfo->cinfo, COL_INFO,"%s id %d CPort %s CIP %s SIP %s",
			val_to_str_const(type, type_vals, "Unknown"),
			id,
			udp_port_to_display(wmem_packet_scope(), cport),
			tvb_ip_to_str(tvb, 8),
			tvb_ip_to_str(tvb, 12));

	if (version == TPCP_VER_1)
		return TPCP_VER_1_LENGTH;

	return TPCP_VER_2_LENGTH;
}

void
proto_register_tpcp(void)
{
	static hf_register_info hf[] = {
		{ &hf_tpcp_version,
		{ "Version",		"tpcp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
		"TPCP version", HFILL }},

		{ &hf_tpcp_type,
		{ "Type",		"tpcp.type", FT_UINT8, BASE_DEC, VALS(type_vals), 0x0,
		"PDU type", HFILL }},

		{ &hf_tpcp_flags,
		{ "Flags",		"tpcp.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

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

		{ &hf_tpcp_signature,
		{ "Signature",	"tpcp.signature", FT_UINT32, BASE_DEC, NULL, 0x0,
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
