/* packet-kerberos4.c
 * Routines for Kerberos v4 packet dissection
 *
 * Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*
 * PDU structure based on the document:
 *
 * Athena Technical Plan
 * Section E.2.1
 * Kerberos Authentication and Authorization System
 * by S. P. Miller, B. C. Neuman, J. I. Schiller, and J. H. Saltzer
 *
 * http://web.mit.edu/Saltzer/www/publications/athenaplan/e.2.1.pdf
 *
 * 7. Appendix I Design Specifications
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_krb4(void);
void proto_reg_handoff_krb4(void);

static int proto_krb4 = -1;
static int hf_krb4_version = -1;
static int hf_krb4_auth_msg_type = -1;
static int hf_krb4_m_type = -1;
static int hf_krb4_byte_order = -1;
static int hf_krb4_name = -1;
static int hf_krb4_instance = -1;
static int hf_krb4_realm = -1;
static int hf_krb4_time_sec = -1;
static int hf_krb4_exp_date = -1;
static int hf_krb4_req_date = -1;
static int hf_krb4_lifetime = -1;
static int hf_krb4_s_name = -1;
static int hf_krb4_s_instance = -1;
static int hf_krb4_kvno = -1;
static int hf_krb4_length = -1;
static int hf_krb4_ticket_length = -1;
static int hf_krb4_request_length = -1;
static int hf_krb4_ticket_blob = -1;
static int hf_krb4_request_blob = -1;
static int hf_krb4_encrypted_blob = -1;
static int hf_krb4_unknown_transarc_blob = -1;

static gint ett_krb4 = -1;
static gint ett_krb4_auth_msg_type = -1;

static dissector_handle_t krb4_handle;

#define UDP_PORT_KRB4    750
#define TRANSARC_SPECIAL_VERSION 0x63

static const value_string byte_order_vals[] = {
	{ 0,	"Big Endian" },
	{ 1,	"Little Endian" },
	{ 0,	NULL }
};

#define AUTH_MSG_KDC_REQUEST		1
#define AUTH_MSG_KDC_REPLY		2
#define AUTH_MSG_APPL_REQUEST		3
#define AUTH_MSG_APPL_REQUEST_MUTUAL	4
#define AUTH_MSG_ERR_REPLY		5
#define AUTH_MSG_PRIVATE		6
#define AUTH_MSG_SAFE			7
#define AUTH_MSG_APPL_ERR		8
#define AUTH_MSG_DIE			63
static const value_string m_type_vals[] = {
	{ AUTH_MSG_KDC_REQUEST,		"KDC Request" },
	{ AUTH_MSG_KDC_REPLY,		"KDC Reply" },
	{ AUTH_MSG_APPL_REQUEST,	"Appl Request" },
	{ AUTH_MSG_APPL_REQUEST_MUTUAL,	"Appl Request Mutual" },
	{ AUTH_MSG_ERR_REPLY,		"Err Reply" },
	{ AUTH_MSG_PRIVATE,		"Private" },
	{ AUTH_MSG_SAFE,		"Safe" },
	{ AUTH_MSG_APPL_ERR,		"Appl Err" },
	{ AUTH_MSG_DIE,			"Die" },
	{ 0,	NULL }
};


static int
dissect_krb4_string(packet_info *pinfo _U_, int hf_index, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	gint length;
	proto_tree_add_item_ret_length(tree, hf_index, tvb, offset, -1, ENC_ASCII|ENC_NA, &length);

	return offset + length;
}

static int
dissect_krb4_kdc_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, const guint encoding, int version)
{
	guint8   lifetime;

	if(version==TRANSARC_SPECIAL_VERSION){
		proto_tree_add_item(tree, hf_krb4_unknown_transarc_blob, tvb, offset, 8, ENC_NA);
		offset+=8;
	}

	/* Name */
	offset=dissect_krb4_string(pinfo, hf_krb4_name, tree, tvb, offset);

	/* Instance */
	offset=dissect_krb4_string(pinfo, hf_krb4_instance, tree, tvb, offset);

	/* Realm */
	offset=dissect_krb4_string(pinfo, hf_krb4_realm, tree, tvb, offset);

	/* Time sec */
	proto_tree_add_item(tree, hf_krb4_time_sec, tvb, offset, 4, ENC_TIME_SECS|encoding);
	offset+=4;

	/* lifetime */
	lifetime=tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_krb4_lifetime, tvb, offset, 1, lifetime, "%d (%d minutes)", lifetime, lifetime*5);
	offset++;

	/* service Name */
	offset=dissect_krb4_string(pinfo, hf_krb4_s_name, tree, tvb, offset);

	/* service Instance */
	offset=dissect_krb4_string(pinfo, hf_krb4_s_instance, tree, tvb, offset);

	return offset;
}


static int
dissect_krb4_kdc_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, const guint encoding)
{
	guint32  length;

	/* Name */
	offset=dissect_krb4_string(pinfo, hf_krb4_name, tree, tvb, offset);

	/* Instance */
	offset=dissect_krb4_string(pinfo, hf_krb4_instance, tree, tvb, offset);

	/* Realm */
	offset=dissect_krb4_string(pinfo, hf_krb4_realm, tree, tvb, offset);

	/* Time sec */
	proto_tree_add_item(tree, hf_krb4_time_sec, tvb, offset, 4, ENC_TIME_SECS|encoding);
	offset+=4;

	/*XXX unknown byte here */
	offset++;

	/* exp date */
	proto_tree_add_item(tree, hf_krb4_exp_date, tvb, offset, 4, ENC_TIME_SECS|encoding);
	offset+=4;

	/* kvno */
	proto_tree_add_item(tree, hf_krb4_kvno, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* length2 */
	proto_tree_add_item_ret_uint(tree, hf_krb4_length, tvb, offset, 2, encoding, &length);
	offset+=2;

	/* encrypted blob */
	proto_tree_add_item(tree, hf_krb4_encrypted_blob, tvb, offset, length, ENC_NA);
	offset+=length;

	return offset;
}


static int
dissect_krb4_appl_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, const guint encoding)
{
	guint8   tlen, rlen;
	guint8   lifetime;

	/* kvno */
	proto_tree_add_item(tree, hf_krb4_kvno, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Realm */
	offset=dissect_krb4_string(pinfo, hf_krb4_realm, tree, tvb, offset);

	/* ticket length */
	tlen=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_krb4_ticket_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* request length */
	rlen=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_krb4_request_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* ticket */
	proto_tree_add_item(tree, hf_krb4_ticket_blob, tvb, offset, tlen, ENC_NA);
	offset+=tlen;

	/* request */
	proto_tree_add_item(tree, hf_krb4_request_blob, tvb, offset, rlen, ENC_NA);
	offset+=rlen;

	/* request time */
	proto_tree_add_item(tree, hf_krb4_req_date, tvb, offset, 4, ENC_TIME_SECS|encoding);
	offset+=4;

	/* lifetime */
	lifetime=tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_krb4_lifetime, tvb, offset, 1, lifetime, "%d (%d minutes)", lifetime, lifetime*5);
	offset++;

	/* service Name */
	offset=dissect_krb4_string(pinfo, hf_krb4_s_name, tree, tvb, offset);

	/* service Instance */
	offset=dissect_krb4_string(pinfo, hf_krb4_s_instance, tree, tvb, offset);

	return offset;
}



static int
dissect_krb4_auth_msg_type(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int version)
{
	proto_tree *tree;
	proto_item *item;
	guint8      auth_msg_type;

	auth_msg_type=tvb_get_guint8(tvb, offset);
	item = proto_tree_add_item(parent_tree, hf_krb4_auth_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	tree = proto_item_add_subtree(item, ett_krb4_auth_msg_type);

	/* m_type */
	proto_tree_add_item(tree, hf_krb4_m_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s",
	   (version==TRANSARC_SPECIAL_VERSION)?"TRANSARC-":"",
	    val_to_str(auth_msg_type>>1, m_type_vals, "Unknown (0x%04x)"));
	proto_item_append_text(item, " %s%s",
	   (version==TRANSARC_SPECIAL_VERSION)?"TRANSARC-":"",
	   val_to_str(auth_msg_type>>1, m_type_vals, "Unknown (0x%04x)"));

	/* byte order */
	proto_tree_add_item(tree, hf_krb4_byte_order, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_item_append_text(item, " (%s)", val_to_str(auth_msg_type&0x01, byte_order_vals, "Unknown (0x%04x)"));

	offset++;
	return offset;
}

static gboolean
dissect_krb4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_tree *tree;
	proto_item *item;
	guint8      version, opcode;
	int         offset = 0;
	guint       encoding;

	/* this should better have the value 4 or it might be a weirdo
	 * Transarc AFS special unknown thing.
	 */
	version=tvb_get_guint8(tvb, offset);
	if((version!=4)&&(version!=TRANSARC_SPECIAL_VERSION)){
		return FALSE;
	}

	opcode=tvb_get_guint8(tvb, offset+1);
	switch(opcode>>1){
	case AUTH_MSG_KDC_REQUEST:
	case AUTH_MSG_KDC_REPLY:
	case AUTH_MSG_APPL_REQUEST:
	case AUTH_MSG_APPL_REQUEST_MUTUAL:
	case AUTH_MSG_ERR_REPLY:
	case AUTH_MSG_PRIVATE:
	case AUTH_MSG_SAFE:
	case AUTH_MSG_APPL_ERR:
	case AUTH_MSG_DIE:
		break;
	default:
		return FALSE;
	}

	/* create a tree for krb4 */
	item = proto_tree_add_item(parent_tree, proto_krb4, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb4);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB4");
	col_clear(pinfo->cinfo, COL_INFO);

	/* version */
	proto_tree_add_item(tree, hf_krb4_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* auth_msg_type */
	offset = dissect_krb4_auth_msg_type(pinfo, tree, tvb, offset, version);

	encoding = opcode&0x01 ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;
	switch(opcode>>1){
	case AUTH_MSG_KDC_REQUEST:
		dissect_krb4_kdc_request(pinfo, tree, tvb, offset, encoding, version);
		break;
	case AUTH_MSG_KDC_REPLY:
		dissect_krb4_kdc_reply(pinfo, tree, tvb, offset, encoding);
		break;
	case AUTH_MSG_APPL_REQUEST:
		dissect_krb4_appl_request(pinfo, tree, tvb, offset, encoding);
		break;
	case AUTH_MSG_APPL_REQUEST_MUTUAL:
	case AUTH_MSG_ERR_REPLY:
	case AUTH_MSG_PRIVATE:
	case AUTH_MSG_SAFE:
	case AUTH_MSG_APPL_ERR:
	case AUTH_MSG_DIE:
		break;
	}
	return TRUE;
}

void
proto_register_krb4(void)
{
	static hf_register_info hf[] = {
		{ &hf_krb4_version,
		  { "Version", "krb4.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Kerberos(v4) version number", HFILL }},
		{ &hf_krb4_auth_msg_type,
		  { "Msg Type", "krb4.auth_msg_type",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Message Type/Byte Order", HFILL }},
		{ &hf_krb4_m_type,
		  { "M Type", "krb4.m_type",
		    FT_UINT8, BASE_HEX, VALS(m_type_vals), 0xfe,
		    "Message Type", HFILL }},
		{ &hf_krb4_byte_order,
		  { "Byte Order", "krb4.byte_order",
		    FT_UINT8, BASE_HEX, VALS(byte_order_vals), 0x01,
		    NULL, HFILL }},
		{ &hf_krb4_name,
		  { "Name", "krb4.name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_instance,
		  { "Instance", "krb4.instance",
		    FT_STRINGZ, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_realm,
		  { "Realm", "krb4.realm",
		    FT_STRINGZ, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_time_sec,
		  { "Time Sec", "krb4.time_sec",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_exp_date,
		  { "Exp Date", "krb4.exp_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_req_date,
		  { "Req Date", "krb4.req_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_lifetime,
		  { "Lifetime", "krb4.lifetime",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Lifetime (in 5 min units)", HFILL }},
		{ &hf_krb4_s_name,
		  { "Service Name", "krb4.s_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_s_instance,
		  { "Service Instance", "krb4.s_instance",
		    FT_STRINGZ, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_kvno,
		  { "Kvno", "krb4.kvno",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Key Version No", HFILL }},
		{ &hf_krb4_length,
		  { "Length", "krb4.length",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Length of encrypted blob", HFILL }},
		{ &hf_krb4_ticket_length,
		  { "Ticket Length", "krb4.ticket.length",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Length of ticket", HFILL }},
		{ &hf_krb4_request_length,
		  { "Request Length", "krb4.request.length",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Length of request", HFILL }},
		{ &hf_krb4_ticket_blob,
		  { "Ticket Blob", "krb4.ticket.blob",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_request_blob,
		  { "Request Blob", "krb4.request.blob",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_encrypted_blob,
		  { "Encrypted Blob", "krb4.encrypted_blob",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_krb4_unknown_transarc_blob,
		  { "Unknown Transarc Blob", "krb4.unknown_transarc_blob",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    "Unknown blob only present in Transarc packets", HFILL }},
	};
	static gint *ett[] = {
		&ett_krb4,
		&ett_krb4_auth_msg_type,
	};

	proto_krb4 = proto_register_protocol("Kerberos v4",
					     "KRB4", "krb4");
	krb4_handle = register_dissector("krb4", dissect_krb4, proto_krb4);
	proto_register_field_array(proto_krb4, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_krb4(void)
{
	dissector_add_uint_with_preference("udp.port", UDP_PORT_KRB4, krb4_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
