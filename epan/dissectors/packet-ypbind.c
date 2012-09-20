/* packet-ypbind.c
 * Routines for ypbind dissection
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
 *
 *    2001  Ronnie Sahlberg, added dissectors for the commands
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



#include "packet-rpc.h"
#include "packet-ypbind.h"

static int proto_ypbind = -1;
static int hf_ypbind_procedure_v1 = -1;
static int hf_ypbind_procedure_v2 = -1;
static int hf_ypbind_domain = -1;
static int hf_ypbind_resp_type = -1;
static int hf_ypbind_error = -1;
static int hf_ypbind_addr = -1;
static int hf_ypbind_port = -1;
static int hf_ypbind_setdom_version = -1;

static gint ett_ypbind = -1;


static int
dissect_ypbind_domain_v2_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	/* domain */
	offset = dissect_rpc_string(tvb, tree,
			hf_ypbind_domain, offset, NULL);

	return offset;
}

#define YPBIND_RESP_TYPE_SUCC_VAL	1
#define YPBIND_RESP_TYPE_FAIL_VAL	2
static const value_string resp_type_vals[] = {
	{YPBIND_RESP_TYPE_SUCC_VAL,	"SUCC_VAL"},
	{YPBIND_RESP_TYPE_FAIL_VAL,	"FAIL_VAL"},
	{0, NULL}
};

#define YPBIND_ERROR_ERR	1
#define YPBIND_ERROR_NOSERV	2
#define YPBIND_ERROR_RESC	3
static const value_string error_vals[] = {
	{YPBIND_ERROR_ERR,	"Internal error"},
	{YPBIND_ERROR_NOSERV,	"No bound server for passed domain"},
	{YPBIND_ERROR_RESC,	"System resource allocation failure"},
	{0, NULL}
};

static int
dissect_ypbind_domain_v2_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 type;

	/* response type */
	type=tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_ypbind_resp_type, offset);

	switch(type){
	case YPBIND_RESP_TYPE_SUCC_VAL:
		/* ip address */
		proto_tree_add_item(tree, hf_ypbind_addr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		/* port */
		offset = dissect_rpc_uint32(tvb, tree,
				hf_ypbind_port, offset);

		break;
	case YPBIND_RESP_TYPE_FAIL_VAL:
		/* error */
		offset = dissect_rpc_uint32(tvb, tree,
				hf_ypbind_resp_type, offset);
		break;
	}

	return offset;
}

static int
dissect_ypbind_setdomain_v2_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	/* domain */
	offset = dissect_rpc_string(tvb, tree,
			hf_ypbind_domain, offset, NULL);

	/* ip address */
	proto_tree_add_item(tree, hf_ypbind_addr,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* port */
	offset = dissect_rpc_uint32(tvb, tree,
			hf_ypbind_port, offset);

	/* version */
	offset = dissect_rpc_uint32(tvb, tree,
			hf_ypbind_setdom_version, offset);

	return offset;
}



/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff ypbind1_proc[] = {
	{ YPBINDPROC_NULL,	"NULL",		NULL,				NULL },
	{ YPBINDPROC_DOMAIN,	"DOMAIN",		NULL,				NULL },
	{ YPBINDPROC_SETDOM,	"SETDOMAIN",		NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
static const value_string ypbind1_proc_vals[] = {
	{ YPBINDPROC_NULL,	"NULL" },
	{ YPBINDPROC_DOMAIN,	"DOMAIN" },
	{ YPBINDPROC_SETDOM,	"SETDOMAIN" },
	{ 0,	NULL }
};
/* end of YPBind version 1 */

static const vsff ypbind2_proc[] = {
	{ YPBINDPROC_NULL,	"NULL",		NULL,				NULL },
	{ YPBINDPROC_DOMAIN,	"DOMAIN",
		dissect_ypbind_domain_v2_request, dissect_ypbind_domain_v2_reply},
	{ YPBINDPROC_SETDOM,	"SETDOMAIN",
		dissect_ypbind_setdomain_v2_request, NULL},
	{ 0,    NULL,       NULL,               NULL }
};
static const value_string ypbind2_proc_vals[] = {
	{ YPBINDPROC_NULL,	"NULL" },
	{ YPBINDPROC_DOMAIN,	"DOMAIN" },
	{ YPBINDPROC_SETDOM,	"SETDOMAIN" },
	{ 0,    NULL }
};
/* end of YPBind version 2 */


void
proto_register_ypbind(void)
{
	static hf_register_info hf[] = {
		{ &hf_ypbind_procedure_v1, {
			"V1 Procedure", "ypbind.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(ypbind1_proc_vals), 0, NULL, HFILL }},
		{ &hf_ypbind_procedure_v2, {
			"V2 Procedure", "ypbind.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(ypbind2_proc_vals), 0, NULL, HFILL }},
		{ &hf_ypbind_domain, {
			"Domain", "ypbind.domain", FT_STRING, BASE_NONE,
			NULL, 0, "Name of the NIS/YP Domain", HFILL }},

		{ &hf_ypbind_resp_type, {
			"Response Type", "ypbind.resp_type", FT_UINT32, BASE_DEC,
			VALS(resp_type_vals), 0, NULL, HFILL }},

		{ &hf_ypbind_error, {
			"Error", "ypbind.error", FT_UINT32, BASE_DEC,
			VALS(error_vals), 0, "YPBIND Error code", HFILL }},

		{ &hf_ypbind_addr, {
			"IP Addr", "ypbind.addr", FT_IPv4, BASE_NONE,
			NULL, 0, "IP Address of server", HFILL }},

		{ &hf_ypbind_port, {
			"Port", "ypbind.port", FT_UINT32, BASE_DEC,
			NULL, 0, "Port to use", HFILL }},

		{ &hf_ypbind_setdom_version, {
			"Version", "ypbind.setdom.version", FT_UINT32, BASE_DEC,
			NULL, 0, "Version of setdom", HFILL }},

	};

	static gint *ett[] = {
		&ett_ypbind,
	};

	proto_ypbind = proto_register_protocol("Yellow Pages Bind",
	    "YPBIND", "ypbind");
	proto_register_field_array(proto_ypbind, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ypbind(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_ypbind, YPBIND_PROGRAM, ett_ypbind);
	/* Register the procedure tables */
	rpc_init_proc_table(YPBIND_PROGRAM, 1, ypbind1_proc, hf_ypbind_procedure_v1);
	rpc_init_proc_table(YPBIND_PROGRAM, 2, ypbind2_proc, hf_ypbind_procedure_v2);
}
