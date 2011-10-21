/* packet-cmp.c
 *
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
 * Updated to RFC4210 CMPv2 and associated "Transport Protocols for CMP" draft
 *   Martin Peylo 2008
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/oids.h>
#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-tcp.h"
#include "packet-http.h"
#include <epan/prefs.h>
#include <epan/nstime.h>

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

#define TCP_PORT_CMP 829

/* desegmentation of CMP over TCP */
static gboolean cmp_desegment = TRUE;

static guint cmp_alternate_tcp_port = 0;
static guint cmp_alternate_http_port = 0;
static guint cmp_alternate_tcp_style_http_port = 0;

/* Initialize the protocol and registered fields */
static int proto_cmp = -1;
static int hf_cmp_type_oid = -1;
static int hf_cmp_tcptrans_len = -1;
static int hf_cmp_tcptrans_type = -1;
static int hf_cmp_tcptrans_poll_ref = -1;
static int hf_cmp_tcptrans_next_poll_ref = -1;
static int hf_cmp_tcptrans_ttcb = -1;
static int hf_cmp_tcptrans10_version = -1;
static int hf_cmp_tcptrans10_flags = -1;
#include "packet-cmp-hf.c"

/* Initialize the subtree pointers */
static gint ett_cmp = -1;
#include "packet-cmp-ett.c"

static const char *object_identifier_id;


#include "packet-cmp-fn.c"

static int
dissect_cmp_pdu(tvbuff_t *tvb, proto_tree *tree, asn1_ctx_t *actx)
{
	return dissect_cmp_PKIMessage(FALSE, tvb, 0, actx,tree, -1);
}

#define CMP_TYPE_PKIMSG		0
#define CMP_TYPE_POLLREP	1
#define CMP_TYPE_POLLREQ	2
#define CMP_TYPE_NEGPOLLREP	3
#define CMP_TYPE_PARTIALMSGREP	4
#define CMP_TYPE_FINALMSGREP	5
#define CMP_TYPE_ERRORMSGREP	6
static const value_string cmp_pdu_types[] = {
	{ CMP_TYPE_PKIMSG,		"pkiMsg" },
	{ CMP_TYPE_POLLREP,		"pollRep" },
	{ CMP_TYPE_POLLREQ,		"pollReq" },
	{ CMP_TYPE_NEGPOLLREP,		"negPollRep" },
	{ CMP_TYPE_PARTIALMSGREP,	"partialMsgRep" },
	{ CMP_TYPE_FINALMSGREP,		"finalMsgRep" },
	{ CMP_TYPE_ERRORMSGREP,		"errorMsgRep" },
	{ 0, NULL },
};


static int dissect_cmp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	tvbuff_t   *next_tvb;
	guint32    pdu_len;
	guint8     pdu_type;
	nstime_t   ts;
	proto_item *item=NULL;
	proto_item *ti=NULL;
	proto_tree *tree=NULL;
	proto_tree *tcptrans_tree=NULL;
	asn1_ctx_t asn1_ctx;
	int offset=0;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	if (pdu_type < 10) {
		/* RFC2510 TCP transport */
		ti = proto_tree_add_item(tree, proto_cmp, tvb, offset, 5, ENC_NA);
		tcptrans_tree = proto_item_add_subtree(ti, ett_cmp);
		proto_tree_add_item(tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	} else {
		/* post RFC2510 TCP transport - the former "type" field is now "version" */
		ti = proto_tree_add_text(tree, tvb, offset, 7, "TCP transport");
		tcptrans_tree = proto_item_add_subtree(ti, ett_cmp);
		pdu_type=tvb_get_guint8(tvb, 6);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_version, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_flags, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	}

	col_add_str (pinfo->cinfo, COL_INFO, val_to_str (pdu_type, cmp_pdu_types, "0x%x"));

	switch(pdu_type){
		case CMP_TYPE_PKIMSG:
			next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
			offset += tvb_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_POLLREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			ts.secs = tvb_get_ntohl(tvb, 4);
			ts.nsecs = 0;
			proto_tree_add_time(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, &ts);
			offset += 4;
			break;
		case CMP_TYPE_POLLREQ:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CMP_TYPE_NEGPOLLREP:
			break;
		case CMP_TYPE_PARTIALMSGREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_next_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			ts.secs = tvb_get_ntohl(tvb, 4);
			ts.nsecs = 0;
			proto_tree_add_time(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, &ts);
			offset += 4;

			next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
			offset += tvb_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_FINALMSGREP:
			next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
			offset += tvb_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_ERRORMSGREP:
			/*XXX to be added*/
			break;
	}

	return offset;
}

static void dissect_cmp_tcp_pdu_no_return(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	dissect_cmp_tcp_pdu(tvb, pinfo, parent_tree);
}

static guint get_cmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 plen;

	/*
	 * Get the length of the CMP-over-TCP packet.
	 */
	plen = tvb_get_ntohl(tvb, offset);

	return plen+4;
}


/* CMP over TCP: RFC2510 section 5.2 and "Transport Protocols for CMP" draft */
	static int
dissect_cmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint32 pdu_len;
	guint8 pdu_type;
	int offset=4; /* RFC2510 TCP transport header length */

	/* only attempt to dissect it as CMP over TCP if we have
	 * at least 5 bytes.
	 */
	if (!tvb_bytes_exist(tvb, 0, 5)) {
		return 0;
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	if(pdu_type == 10) {
		/* post RFC2510 TCP transport */
		pdu_type = tvb_get_guint8(tvb, 7);
		offset = 7; /* post RFC2510 TCP transport header length */
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 3 byte for post RFC2510 TCP transport
		 */
		if((pdu_len<=2)||(pdu_len>10000)){
			return 0;
		}
	} else {
		/* RFC2510 TCP transport */
		/* type is between 0 and 6 */
		if(pdu_type>6){
			return 0;
		}
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 1 byte to accomodate the flags byte
		 */
		if((pdu_len<=0)||(pdu_len>10000)){
			return 0;
		}
	}

	/* type 0 contains a PKI message and must therefore be >= 3 bytes
	 * long (flags + BER TAG + BER LENGTH
	 */
	if((pdu_type==0)&&(pdu_len<3)){
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, parent_tree, cmp_desegment, offset, get_cmp_pdu_len,
			dissect_cmp_tcp_pdu_no_return);

	return tvb_length(tvb);
}


	static int
dissect_cmp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	return dissect_cmp_pdu(tvb, tree, &asn1_ctx);
}


/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_cmp_type_oid,
			{ "InfoType", "cmp.type.oid",
				FT_STRING, BASE_NONE, NULL, 0,
				"Type of InfoTypeAndValue", HFILL }},
		{ &hf_cmp_tcptrans_len,
			{ "Length", "cmp.tcptrans.length",
				FT_UINT32, BASE_DEC, NULL, 0,
				"TCP transport Length of PDU in bytes", HFILL }},
		{ &hf_cmp_tcptrans_type,
			{ "Type", "cmp.tcptrans.type",
				FT_UINT8, BASE_DEC, VALS(cmp_pdu_types), 0,
				"TCP transport PDU Type", HFILL }},
		{ &hf_cmp_tcptrans_poll_ref,
			{ "Polling Reference", "cmp.tcptrans.poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_next_poll_ref,
			{ "Next Polling Reference", "cmp.tcptrans.next_poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Next Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_ttcb,
			{ "Time to check Back", "cmp.tcptrans.ttcb",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				"TCP transport Time to check Back", HFILL }},
		{ &hf_cmp_tcptrans10_version,
			{ "Version", "cmp.tcptrans10.version",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport version", HFILL }},
		{ &hf_cmp_tcptrans10_flags,
			{ "Flags", "cmp.tcptrans10.flags",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport flags", HFILL }},
#include "packet-cmp-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_cmp,
#include "packet-cmp-ettarr.c"
	};
	module_t *cmp_module;

	/* Register protocol */
	proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_cmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	cmp_module = prefs_register_protocol(proto_cmp, proto_reg_handoff_cmp);
	prefs_register_bool_preference(cmp_module, "desegment",
			"Reassemble CMP-over-TCP messages spanning multiple TCP segments",
			"Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&cmp_desegment);

	prefs_register_uint_preference(cmp_module, "tcp_alternate_port",
			"Alternate TCP port",
			"Decode this TCP port\'s traffic as CMP. Set to \"0\" to disable.",
			10,
			&cmp_alternate_tcp_port);

	prefs_register_uint_preference(cmp_module, "http_alternate_port",
			"Alternate HTTP port",
			"Decode this TCP port\'s traffic as CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_http_port);

	prefs_register_uint_preference(cmp_module, "tcp_style_http_alternate_port",
			"Alternate TCP-style-HTTP port",
			"Decode this TCP port\'s traffic as TCP-transport-style CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_tcp_style_http_port);
}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	static gboolean inited = FALSE;
	static dissector_handle_t cmp_http_handle;
	static dissector_handle_t cmp_tcp_style_http_handle;
	static dissector_handle_t cmp_tcp_handle;
	static guint cmp_alternate_tcp_port_prev = 0;
	static guint cmp_alternate_http_port_prev = 0;
	static guint cmp_alternate_tcp_style_http_port_prev = 0;

	if (!inited) {
		cmp_http_handle = new_create_dissector_handle(dissect_cmp_http, proto_cmp);
		dissector_add_string("media_type", "application/pkixcmp", cmp_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp", cmp_http_handle);

		cmp_tcp_style_http_handle = new_create_dissector_handle(dissect_cmp_tcp_pdu, proto_cmp);
		dissector_add_string("media_type", "application/pkixcmp-poll", cmp_tcp_style_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp-poll", cmp_tcp_style_http_handle);

		cmp_tcp_handle = new_create_dissector_handle(dissect_cmp_tcp, proto_cmp);
		dissector_add_uint("tcp.port", TCP_PORT_CMP, cmp_tcp_handle);

		oid_add_from_string("Cryptlib-presence-check","1.3.6.1.4.1.3029.3.1.1");
		oid_add_from_string("Cryptlib-PKIBoot","1.3.6.1.4.1.3029.3.1.2");

		oid_add_from_string("HMAC MD5","1.3.6.1.5.5.8.1.1");
		oid_add_from_string("HMAC SHA-1","1.3.6.1.5.5.8.1.2");
		oid_add_from_string("HMAC TIGER","1.3.6.1.5.5.8.1.3");
		oid_add_from_string("HMAC RIPEMD-160","1.3.6.1.5.5.8.1.4");

		oid_add_from_string("sha256WithRSAEncryption","1.2.840.113549.1.1.11");

#include "packet-cmp-dis-tab.c"
		inited = TRUE;
	}

	/* change alternate TCP port if changed in the preferences */
	if (cmp_alternate_tcp_port != cmp_alternate_tcp_port_prev) {
		if (cmp_alternate_tcp_port_prev != 0)
			dissector_delete_uint("tcp.port", cmp_alternate_tcp_port_prev, cmp_tcp_handle);
		if (cmp_alternate_tcp_port != 0)
			dissector_add_uint("tcp.port", cmp_alternate_tcp_port, cmp_tcp_handle);
		cmp_alternate_tcp_port_prev = cmp_alternate_tcp_port;
	}

	/* change alternate HTTP port if changed in the preferences */
	if (cmp_alternate_http_port != cmp_alternate_http_port_prev) {
		if (cmp_alternate_http_port_prev != 0) {
			dissector_delete_uint("tcp.port", cmp_alternate_http_port_prev, NULL);
			dissector_delete_uint("http.port", cmp_alternate_http_port_prev, NULL);
		}
		if (cmp_alternate_http_port != 0)
			http_dissector_add( cmp_alternate_http_port, cmp_http_handle);
		cmp_alternate_http_port_prev = cmp_alternate_http_port;
	}

	/* change alternate TCP-style-HTTP port if changed in the preferences */
	if (cmp_alternate_tcp_style_http_port != cmp_alternate_tcp_style_http_port_prev) {
		if (cmp_alternate_tcp_style_http_port_prev != 0) {
			dissector_delete_uint("tcp.port", cmp_alternate_tcp_style_http_port_prev, NULL);
			dissector_delete_uint("http.port", cmp_alternate_tcp_style_http_port_prev, NULL);
		}
		if (cmp_alternate_tcp_style_http_port != 0)
			http_dissector_add( cmp_alternate_tcp_style_http_port, cmp_tcp_style_http_handle);
		cmp_alternate_tcp_style_http_port_prev = cmp_alternate_tcp_style_http_port;
	}

}

