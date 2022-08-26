/* packet-coap.c
 * Routines for CoAP packet disassembly
 * draft-ietf-core-coap-14.txt
 * draft-ietf-core-block-10.txt
 * draft-ietf-core-observe-16.txt
 * draft-ietf-core-link-format-06.txt
 * Shoichi Sakane <sakane@tanu.org>
 *
 * Changes for draft-ietf-core-coap-17.txt
 * Hauke Mehrtens <hauke@hauke-m.de>
 *
 * Support for CoAP over TCP, TLS and WebSockets
 * https://tools.ietf.org/html/rfc8323
 * Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/wmem_scopes.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include "packet-dtls.h"
#include "packet-coap.h"
#include "packet-http.h"
#include "packet-tcp.h"
#include "packet-tls.h"

void proto_register_coap(void);

static dissector_table_t media_type_dissector_table;

static int proto_coap						= -1;

static int hf_coap_length					= -1;
static int hf_coap_version					= -1;
static int hf_coap_ttype					= -1;
static int hf_coap_token_len					= -1;
static int hf_coap_token					= -1;
static int hf_coap_mid						= -1;

static int hf_coap_response_in					= -1;
static int hf_coap_response_to					= -1;
static int hf_coap_response_time				= -1;
static int hf_coap_request_resend_in				= -1;
static int hf_coap_response_resend_in				= -1;
static int hf_coap_oscore_kid					= -1;
static int hf_coap_oscore_kid_context				= -1;
static int hf_coap_oscore_piv					= -1;

static int hf_block_payload					= -1;
static int hf_block_length					= -1;

static int hf_blocks						= -1;
static int hf_block						= -1;
static int hf_block_overlap					= -1;
static int hf_block_overlap_conflicts				= -1;
static int hf_block_multiple_tails				= -1;
static int hf_block_too_long					= -1;
static int hf_block_error					= -1;
static int hf_block_count					= -1;
static int hf_block_reassembled_in				= -1;
static int hf_block_reassembled_length				= -1;

static gint ett_coap						= -1;

static gint ett_block						= -1;
static gint ett_blocks						= -1;

static expert_field ei_retransmitted				= EI_INIT;

static COAP_COMMON_LIST_T(dissect_coap_hf);

static dissector_handle_t coap_handle;
static dissector_handle_t oscore_handle;

/* CoAP's IANA-assigned TCP/UDP port numbers */
#define DEFAULT_COAP_PORT					5683
#define DEFAULT_COAPS_PORT					5684

/* indicators whether those are to be showed or not */
#define DEFAULT_COAP_CTYPE_VALUE				~0U
#define DEFAULT_COAP_BLOCK_NUMBER				~0U

/*
 * Transaction Type
 */
#define TT_CON 0 // Confirmable
#define TT_NON 1 // Non-Confirmable
static const value_string vals_ttype[] = {
	{ 0, "Confirmable" },
	{ 1, "Non-Confirmable" },
	{ 2, "Acknowledgement" },
	{ 3, "Reset" },
	{ 0, NULL },
};
static const value_string vals_ttype_short[] = {
	{ 0, "CON" },
	{ 1, "NON" },
	{ 2, "ACK" },
	{ 3, "RST" },
	{ 0, NULL },
};

/*
 * Method Code
 * Response Code
 * "c.dd" denotes (c << 5) | dd
 */
static const value_string vals_code[] = {
	{ 0, "Empty Message" },

	/* Method Codes */
	{ 1, "GET" },
	{ 2, "POST" },
	{ 3, "PUT" },
	{ 4, "DELETE" },
	{ 5, "FETCH" },		/* RFC 8132 */
	{ 6, "PATCH" },		/* RFC 8132 */
	{ 7, "iPATCH" },	/* RFC 8132 */

	/* Response Codes */
	{  65, "2.01 Created" },
	{  66, "2.02 Deleted" },
	{  67, "2.03 Valid" },
	{  68, "2.04 Changed" },
	{  69, "2.05 Content" },
	{  95, "2.31 Continue" },
	{ 128, "4.00 Bad Request" },
	{ 129, "4.01 Unauthorized" },
	{ 130, "4.02 Bad Option" },
	{ 131, "4.03 Forbidden" },
	{ 132, "4.04 Not Found" },
	{ 133, "4.05 Method Not Allowed" },
	{ 134, "4.06 Not Acceptable" },
	{ 136, "4.08 Request Entity Incomplete" },	/* RFC 7959 */
	{ 137, "4.09 Conflict" },			/* RFC 8132 */
	{ 140, "4.12 Precondition Failed" },
	{ 141, "4.13 Request Entity Too Large" },
	{ 143, "4.15 Unsupported Content-Format" },
	{ 150, "4.22 Unprocessable Entity" },		/* RFC 8132 */
	{ 157, "4.29 Too Many Requests" },		/* RFC 8516 */
	{ 160, "5.00 Internal Server Error" },
	{ 161, "5.01 Not Implemented" },
	{ 162, "5.02 Bad Gateway" },
	{ 163, "5.03 Service Unavailable" },
	{ 164, "5.04 Gateway Timeout" },
	{ 165, "5.05 Proxying Not Supported" },
	{ 168, "5.08 Hop Limit Reached" },		/* RFC 8768 */

	/* Signalling Codes */
	{ 225, "7.01 CSM" },				/* RFC 8323 */
	{ 226, "7.02 Ping" },				/* RFC 8323 */
	{ 227, "7.03 Pong" },				/* RFC 8323 */
	{ 228, "7.04 Release" },			/* RFC 8323 */
	{ 229, "7.05 Abort" },				/* RFC 8323 */

	{ 0, NULL },
};
value_string_ext coap_vals_code_ext = VALUE_STRING_EXT_INIT(vals_code);

const value_string coap_vals_observe_options[] = {
	{ 0, "Register" },
	{ 1, "Deregister" },
	{ 0, NULL },
};

/*
 * Option Headers
 * No-Option must not be included in this structure, is handled in the function
 * of the dissector, especially.
 */
#define COAP_OPT_IF_MATCH		1
#define COAP_OPT_URI_HOST		3
#define COAP_OPT_ETAG			4
#define COAP_OPT_IF_NONE_MATCH		5
#define COAP_OPT_OBSERVE		6	/* core-observe-16 */
#define COAP_OPT_URI_PORT		7
#define COAP_OPT_LOCATION_PATH		8
#define COAP_OPT_OBJECT_SECURITY	9	/* RFC 8613 */
#define COAP_OPT_URI_PATH		11
#define COAP_OPT_CONTENT_TYPE		12
#define COAP_OPT_MAX_AGE		14
#define COAP_OPT_URI_QUERY		15
#define COAP_OPT_HOP_LIMIT		16	/* RFC 8768 */
#define COAP_OPT_ACCEPT			17
#define COAP_OPT_LOCATION_QUERY		20
#define COAP_OPT_BLOCK2			23	/* RFC 7959 / RFC 8323 */
#define COAP_OPT_BLOCK1			27	/* RFC 7959 / RFC 8323 */
#define COAP_OPT_SIZE2			28	/* RFC 7959 */
#define COAP_OPT_PROXY_URI		35
#define COAP_OPT_PROXY_SCHEME		39
#define COAP_OPT_SIZE1			60

static const value_string vals_opt_type[] = {
	{ COAP_OPT_IF_MATCH,       "If-Match" },
	{ COAP_OPT_URI_HOST,       "Uri-Host" },
	{ COAP_OPT_ETAG,           "Etag" },
	{ COAP_OPT_IF_NONE_MATCH,  "If-None-Match" },
	{ COAP_OPT_URI_PORT,       "Uri-Port" },
	{ COAP_OPT_LOCATION_PATH,  "Location-Path" },
	{ COAP_OPT_OBJECT_SECURITY,"OSCORE" },
	{ COAP_OPT_URI_PATH,       "Uri-Path" },
	{ COAP_OPT_CONTENT_TYPE,   "Content-Format" },
	{ COAP_OPT_MAX_AGE,        "Max-age" },
	{ COAP_OPT_URI_QUERY,      "Uri-Query" },
	{ COAP_OPT_HOP_LIMIT,      "Hop-Limit" },
	{ COAP_OPT_ACCEPT,         "Accept" },
	{ COAP_OPT_LOCATION_QUERY, "Location-Query" },
	{ COAP_OPT_PROXY_URI,      "Proxy-Uri" },
	{ COAP_OPT_PROXY_SCHEME,   "Proxy-Scheme" },
	{ COAP_OPT_SIZE1,          "Size1" },
	{ COAP_OPT_OBSERVE,        "Observe" },
	{ COAP_OPT_BLOCK2,         "Block2" },
	{ COAP_OPT_BLOCK1,         "Block1" },
	{ COAP_OPT_SIZE2,          "Size2" },
	{ 0, NULL },
};

struct coap_option_range_t {
	guint type;
	gint min;
	gint max;
} coi[] = {
	{ COAP_OPT_IF_MATCH,        0,   8 },
	{ COAP_OPT_URI_HOST,        1, 255 },
	{ COAP_OPT_ETAG,            1,   8 },
	{ COAP_OPT_IF_NONE_MATCH,   0,   0 },
	{ COAP_OPT_URI_PORT,        0,   2 },
	{ COAP_OPT_LOCATION_PATH,   0, 255 },
	{ COAP_OPT_OBJECT_SECURITY, 0, 255 },
	{ COAP_OPT_URI_PATH,        0, 255 },
	{ COAP_OPT_CONTENT_TYPE,    0,   2 },
	{ COAP_OPT_MAX_AGE,         0,   4 },
	{ COAP_OPT_URI_QUERY,       1, 255 },
	{ COAP_OPT_HOP_LIMIT,       1,   1 },
	{ COAP_OPT_ACCEPT,          0,   2 },
	{ COAP_OPT_LOCATION_QUERY,  0, 255 },
	{ COAP_OPT_PROXY_URI,       1,1034 },
	{ COAP_OPT_PROXY_SCHEME,    1, 255 },
	{ COAP_OPT_SIZE1,           0,   4 },
	{ COAP_OPT_OBSERVE,         0,   3 },
	{ COAP_OPT_BLOCK2,          0,   3 },
	{ COAP_OPT_BLOCK1,          0,   3 },
	{ COAP_OPT_SIZE2,           0,   4 },
};

static const value_string vals_ctype[] = {
	{  0, "text/plain; charset=utf-8" },
	{ 40, "application/link-format" },
	{ 41, "application/xml" },
	{ 42, "application/octet-stream" },
	{ 47, "application/exi" },
	{ 50, "application/json" },
	{ 51, "application/json-patch+json" },
	{ 52, "application/merge-patch+json" },
	{ 60, "application/cbor" },
	{ 61, "application/cwt" },
	{ 62, "application/multipart-core" },
	{ 96, "application/cose; cose-type=\"cose-encrypt\"" },
	{ 97, "application/cose; cose-type=\"cose-mac\"" },
	{ 98, "application/cose; cose-type=\"cose-sign\"" },
	{ 101, "application/cose-key" },
	{ 102, "application/cose-key-set" },
	{ 110, "application/senml+json" },
	{ 111, "application/sensml+json" },
	{ 112, "application/senml+cbor" },
	{ 113, "application/sensml+cbor" },
	{ 114, "application/senml-exi" },
	{ 115, "application/sensml-exi" },
	{ 256, "application/coap-group+json" },
	{ 271, "application/dots+cbor" },
	{ 272, "application/missing-blocks+cbor-seq" },
	{ 280, "application/pkcs7-mime; smime-type=server-generated-key" },
	{ 281, "application/pkcs7-mime; smime-type=certs-only" },
	{ 284, "application/pkcs8" },
	{ 285, "application/csrattrs" },
	{ 286, "application/pkcs10" },
	{ 287, "application/pkix-cert" },
	{ 310, "application/senml+xml" },
	{ 311, "application/sensml+xml" },
	{ 320, "application/senml-etch+json" },
	{ 322, "application/senml-etch+cbor" },
	{ 432, "application/td+json" },
	{ 1542, "application/vnd.oma.lwm2m+tlv" },
	{ 1543, "application/vnd.oma.lwm2m+json" },
	{ 10000, "application/vnd.ocf+cbor" },
	{ 10001, "application/oscore" },
	{ 11542, "application/vnd.oma.lwm2m+tlv" },
	{ 11543, "application/vnd.oma.lwm2m+json" },
	{ 0, NULL },
};

static const char *nullstr = "(null)";

static reassembly_table coap_block_reassembly_table;

static const fragment_items coap_block_frag_items = {
	/* Fragment subtrees */
	&ett_block,
	&ett_blocks,
	/* Fragment fields */
	&hf_blocks,
	&hf_block,
	&hf_block_overlap,
	&hf_block_overlap_conflicts,
	&hf_block_multiple_tails,
	&hf_block_too_long,
	&hf_block_error,
	&hf_block_count,
	/* Reassembled in field */
	&hf_block_reassembled_in,
	/* Reassembled length field */
	&hf_block_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"Block fragments"
};

void proto_reg_handoff_coap(void);

static conversation_t *
find_or_create_conversation_noaddrb(packet_info *pinfo, gboolean request)
{
	conversation_t *conv=NULL;
	address *addr_a;
	address *addr_b;
	guint32 port_a;
	guint32 port_b;

	if (pinfo->ptype != PT_TCP) {
		if (request) {
			addr_a = &pinfo->src;
			addr_b = &pinfo->dst;
			port_a = pinfo->srcport;
			port_b = pinfo->destport;
		} else {
			addr_a = &pinfo->dst;
			addr_b = &pinfo->src;
			port_a = pinfo->destport;
			port_b = pinfo->srcport;
		}
		/* Have we seen this conversation before? */
		if((conv = find_conversation(pinfo->num, addr_a, addr_b,
					     conversation_pt_to_conversation_type(pinfo->ptype), port_a,
					     port_b, NO_ADDR_B|NO_PORT_B)) != NULL) {
			if (pinfo->num > conv->last_frame) {
				conv->last_frame = pinfo->num;
			}
		} else {
			/* No, this is a new conversation. */
			conv = conversation_new(pinfo->num, &pinfo->src,
						&pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
						pinfo->srcport, pinfo->destport, NO_ADDR2|NO_PORT2);
		}
	} else {
		/* fetch the conversation created by the TCP dissector */
		conv = find_conversation_pinfo(pinfo, 0);
		DISSECTOR_ASSERT(conv);
	}
	return conv;
}

static gint
coap_get_opt_uint(tvbuff_t *tvb, gint offset, gint length)
{
	switch (length) {
	case 0:
		return 0;
	case 1:
		return (guint)tvb_get_guint8(tvb, offset);
	case 2:
		return (guint)tvb_get_ntohs(tvb, offset);
	case 3:
		return (guint)tvb_get_ntoh24(tvb, offset);
	case 4:
		return (guint)tvb_get_ntohl(tvb, offset);
	default:
		return -1;
	}
}

static gint
coap_opt_check(packet_info *pinfo, proto_tree *subtree, guint opt_num, gint opt_length, coap_common_dissect_t *dissect_hf)
{
	int i;

	for (i = 0; i < (int)(array_length(coi)); i++) {
		if (coi[i].type == opt_num)
			break;
	}
	if (i == (int)(array_length(coi))) {
		if (opt_num >= 2048 && opt_num <= 65535) {
			/* private, vendor-specific or reserved for experiments */
			expert_add_info_format(pinfo, subtree, &dissect_hf->ei.opt_unknown_number,
					       "Unknown Option Number %u", opt_num);
		} else {
			expert_add_info_format(pinfo, subtree, &dissect_hf->ei.opt_invalid_number,
					       "Invalid Option Number %u", opt_num);
		}
		return -1;
	}
	if (opt_length < coi[i].min || opt_length > coi[i].max) {
		expert_add_info_format(pinfo, subtree, &dissect_hf->ei.opt_invalid_range,
			"Invalid Option Range: %d (%d < x < %d)", opt_length, coi[i].min, coi[i].max);
	}

	return 0;
}

static void
dissect_coap_opt_hex_string(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str;

	if (opt_length == 0)
		str = nullstr;
	else
		str = tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, opt_length, ' ');

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_NA);

	/* add info to the head of the packet detail */
	proto_item_append_text(item, ": %s", str);
}

static void
dissect_coap_opt_uint(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	guint i = 0;

	if (opt_length != 0) {
		i = coap_get_opt_uint(tvb, offset, opt_length);
	}

	proto_tree_add_uint(subtree, hf, tvb, offset, opt_length, i);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %u", i);
}

static void
dissect_coap_opt_uri_host(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo, int hf)
{
	const guint8 *str;

	proto_tree_add_item_ret_string(subtree, hf, tvb, offset, opt_length, ENC_ASCII, pinfo->pool, &str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));

	/* forming a uri-string
	 *   If the 'uri host' looks an IPv6 address, assuming that the address has
	 *   to be enclosed by brackets.
	 */
	if (strchr(str, ':') == NULL) {
		wmem_strbuf_append_printf(coinfo->uri_str_strbuf, "coap://%s", str);
	} else {
		wmem_strbuf_append_printf(coinfo->uri_str_strbuf, "coap://[%s]", str);
	}
}

static void
dissect_coap_opt_uri_path(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo, int hf)
{
	const guint8 *str = NULL;

	wmem_strbuf_append_c(coinfo->uri_str_strbuf, '/');

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(pinfo->pool, tvb, offset, opt_length, ENC_ASCII);
		wmem_strbuf_append(coinfo->uri_str_strbuf, str);
	}

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_ASCII);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));
}

static void
dissect_coap_opt_uri_query(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo, int hf)
{
	const guint8 *str = NULL;

	wmem_strbuf_append_c(coinfo->uri_query_strbuf,
			     (wmem_strbuf_get_len(coinfo->uri_query_strbuf) == 0) ? '?' : '&');

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(pinfo->pool, tvb, offset, opt_length, ENC_ASCII);
		wmem_strbuf_append(coinfo->uri_query_strbuf, str);
	}

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_ASCII);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));
}

static void
dissect_coap_opt_location_path(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(pinfo->pool, tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_ASCII);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));
}

static void
dissect_coap_opt_location_query(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(pinfo->pool, tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_ASCII);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));
}

/* rfc8613 */
static void
dissect_coap_opt_object_security(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, packet_info *pinfo, coap_info *coinfo, coap_common_dissect_t *dissect_hf, guint8 code_class)
{
	guint8 flag_byte = 0;
	gboolean reserved = FALSE;
	gboolean kid_context_present = FALSE;
	gboolean kid_present = FALSE;
	guint8 piv_len = 0;
	guint8 kid_context_len = 0;
	guint8 kid_len = 0;

	coinfo->object_security = TRUE;

	coinfo->oscore_info->piv = NULL;
	coinfo->oscore_info->piv_len = 0;
	coinfo->oscore_info->request_piv = NULL;
	coinfo->oscore_info->request_piv_len = 0;
	coinfo->oscore_info->kid_context = NULL;
	coinfo->oscore_info->kid_context_len = 0;
	coinfo->oscore_info->kid = NULL;
	coinfo->oscore_info->kid_len = 0;
	coinfo->oscore_info->response = FALSE;

	if (opt_length == 0) { /* option length is zero, means flag byte is 0x00*/
		/* add info to the head of the packet detail */
		proto_item_append_text(head_item, ": 00 (no Flag Byte)");
	} else {
		flag_byte = tvb_get_guint8(tvb, offset);

		proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
		reserved = flag_byte & COAP_OBJECT_SECURITY_RESERVED_MASK;

		proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_kid_context_present, tvb, offset, 1, ENC_BIG_ENDIAN);
		kid_context_present = flag_byte & COAP_OBJECT_SECURITY_KID_CONTEXT_MASK;

		proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_kid_present, tvb, offset, 1, ENC_BIG_ENDIAN);
		kid_present = flag_byte & COAP_OBJECT_SECURITY_KID_MASK;

		proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_piv_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		piv_len = (flag_byte & COAP_OBJECT_SECURITY_PIVLEN_MASK) >> 0;

		/* kid_len is what remains in the option after all other fields are parsed
		we calculate kid_len by subtracting from option length as we parse individual fields */
		kid_len = opt_length;

		offset += 1;
		kid_len -= 1;

		if (reserved) {
			/* how these bits are handled is not yet specified */
			expert_add_info_format(pinfo, subtree, &dissect_hf->ei.opt_object_security_bad, "Unsupported format");
		}

		if (piv_len > 0) {
			proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_piv, tvb, offset, piv_len, ENC_NA);
			coinfo->oscore_info->piv = (guint8 *) tvb_memdup(pinfo->pool, tvb, offset, piv_len);
			coinfo->oscore_info->piv_len = piv_len;

			if (code_class == 0) {
				/* If this is a request, copy PIV to request_piv */
				coinfo->oscore_info->request_piv = (guint8 *) tvb_memdup(pinfo->pool, tvb, offset, piv_len);
				coinfo->oscore_info->request_piv_len = piv_len;
			}

			offset += piv_len;
			kid_len -= piv_len;
		}

		if (kid_context_present) {
			proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_kid_context_len, tvb, offset, 1, ENC_BIG_ENDIAN);
			kid_context_len = tvb_get_guint8(tvb, offset);

			offset += 1;
			kid_len -= 1;

			proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_kid_context, tvb, offset, kid_context_len, ENC_NA);
			coinfo->oscore_info->kid_context = (guint8 *) tvb_memdup(pinfo->pool, tvb, offset, kid_context_len);
			coinfo->oscore_info->kid_context_len = kid_context_len;

			offset += kid_context_len;
			kid_len -= kid_context_len;
		}

		if (kid_present) {
			proto_tree_add_item(subtree, dissect_hf->hf.opt_object_security_kid, tvb, offset, kid_len, ENC_NA);
			coinfo->oscore_info->kid = (guint8 *) tvb_memdup(pinfo->pool, tvb, offset, kid_len);
			coinfo->oscore_info->kid_len = kid_len;

		}

		proto_item_append_text(head_item, ": Key ID:%s, Key ID Context:%s, Partial IV:%s",
				 coinfo->oscore_info->kid == NULL ? nullstr : bytes_to_str(pinfo->pool, coinfo->oscore_info->kid, coinfo->oscore_info->kid_len),
				 coinfo->oscore_info->kid_context == NULL ? nullstr : bytes_to_str(pinfo->pool, coinfo->oscore_info->kid_context, coinfo->oscore_info->kid_context_len),
				 coinfo->oscore_info->piv == NULL ? nullstr : bytes_to_str(pinfo->pool, coinfo->oscore_info->piv, coinfo->oscore_info->piv_len));
	}
}

static void
dissect_coap_opt_proxy_uri(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(pinfo->pool, tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_ASCII);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));
}

static void
dissect_coap_opt_proxy_scheme(tvbuff_t *tvb, packet_info *pinfo, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		str = tvb_get_string_enc(pinfo->pool, tvb, offset, opt_length, ENC_ASCII);
	}

	proto_tree_add_item(subtree, hf, tvb, offset, opt_length, ENC_ASCII);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", format_text_string(pinfo->pool, str));
}

static void
dissect_coap_opt_ctype(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf, coap_info *coinfo)
{
	if (opt_length == 0) {
		coinfo->ctype_value = 0;
	} else {
		coinfo->ctype_value = coap_get_opt_uint(tvb, offset, opt_length);
	}

	coinfo->ctype_str = val_to_str(coinfo->ctype_value, vals_ctype, "Unknown Type %u");

	proto_tree_add_string(subtree, hf, tvb, offset, opt_length, coinfo->ctype_str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", coinfo->ctype_str);
}

static void
dissect_coap_opt_accept(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, int hf)
{
	const guint8 *str = NULL;

	if (opt_length == 0) {
		str = nullstr;
	} else {
		guint value = coap_get_opt_uint(tvb, offset, opt_length);
		str = val_to_str(value, vals_ctype, "Unknown Type %u");
	}

	proto_tree_add_string(subtree, hf, tvb, offset, opt_length, str);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": %s", str);
}

static void
dissect_coap_opt_block(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo, coap_common_dissect_t *dissect_hf)
{
	guint8      val = 0;
	guint       encoded_block_size;
	guint       block_esize;

	if (opt_length == 0) {
		coinfo->block_number = 0;
		val = 0;
	} else {
		coinfo->block_number = coap_get_opt_uint(tvb, offset, opt_length) >> 4;
		val = tvb_get_guint8(tvb, offset + opt_length - 1) & 0x0f;
	}

	proto_tree_add_uint(subtree, dissect_hf->hf.opt_block_number,
	    tvb, offset, opt_length, coinfo->block_number);

	/* More flag in the end of the option */
	coinfo->block_mflag = (val & COAP_BLOCK_MFLAG_MASK) >> 3;
	proto_tree_add_uint(subtree, dissect_hf->hf.opt_block_mflag,
	    tvb, offset + opt_length - 1, 1, val);

	/* block size */
	encoded_block_size = val & COAP_BLOCK_SIZE_MASK;
	block_esize = 1 << (encoded_block_size + 4);
	proto_tree_add_uint_format(subtree, dissect_hf->hf.opt_block_size,
	    tvb, offset + opt_length - 1, 1, encoded_block_size, "Block Size: %u (%u encoded)", block_esize, encoded_block_size);

	/* add info to the head of the packet detail */
	proto_item_append_text(head_item, ": NUM:%u, M:%u, SZX:%u",
	    coinfo->block_number, coinfo->block_mflag, block_esize);
}

static void
dissect_coap_opt_uri_port(tvbuff_t *tvb, proto_item *head_item, proto_tree *subtree, gint offset, gint opt_length, coap_info *coinfo, int hf)
{
	guint port = 0;

	if (opt_length != 0) {
		port = coap_get_opt_uint(tvb, offset, opt_length);
	}

	proto_tree_add_uint(subtree, hf, tvb, offset, opt_length, port);

	proto_item_append_text(head_item, ": %u", port);

	/* forming a uri-string */
	wmem_strbuf_append_printf(coinfo->uri_str_strbuf, ":%u", port);
}

/*
 * dissector for each option of CoAP.
 * return the total length of the option including the header (e.g. delta and length).
 */
static int
dissect_coap_options_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, gint offset, guint8 opt_count, guint *opt_num, gint offset_end, guint8 code_class, coap_info *coinfo, coap_common_dissect_t *dissect_hf)
{
	guint8      opt_jump;
	gint        opt_length, opt_length_ext, opt_delta, opt_delta_ext;
	gint        opt_length_ext_off = 0;
	gint8       opt_length_ext_len = 0;
	gint        opt_delta_ext_off  = 0;
	gint8       opt_delta_ext_len  = 0;
	gint        orig_offset	       = offset;
	proto_tree *subtree;
	proto_item *item;
	char	    strbuf[56];

	opt_jump = tvb_get_guint8(tvb, offset);
	if (0xff == opt_jump)
		return offset;
	offset += 1;

	/*
	 * section 3.1 in coap-17:
	 * Option Delta:  4-bit unsigned integer.  A value between 0 and 12
	 * indicates the Option Delta.  Three values are reserved for special
	 * constructs:
	 *
	 * 13:  An 8-bit unsigned integer follows the initial byte and
	 *      indicates the Option Delta minus 13.
	 *
	 * 14:  A 16-bit unsigned integer in network byte order follows the
	 *      initial byte and indicates the Option Delta minus 269.
	 *
	 * 15:  Reserved for the Payload Marker.  If the field is set to this
	 *      value but the entire byte is not the payload marker, this MUST
	 *      be processed as a message format error.
	 */
	switch (opt_jump & 0xf0) {
	case 0xd0:
		opt_delta_ext = tvb_get_guint8(tvb, offset);
		opt_delta_ext_off = offset;
		opt_delta_ext_len = 1;
		offset += 1;

		opt_delta = 13;
		opt_delta += opt_delta_ext;
		break;
	case 0xe0:
		opt_delta_ext = coap_get_opt_uint(tvb, offset, 2);
		opt_delta_ext_off = offset;
		opt_delta_ext_len = 2;
		offset += 2;

		opt_delta = 269;
		opt_delta += opt_delta_ext;
		break;
	case 0xf0:
		expert_add_info_format(pinfo, coap_tree, &dissect_hf->ei.opt_length_bad,
				"end-of-options marker found, but option length isn't 15");
		return -1;
	default:
		opt_delta = ((opt_jump & 0xf0) >> 4);
		break;
	}
	*opt_num += opt_delta;

	/*
	 * section 3.1 in coap-17:
	 * Option Length:  4-bit unsigned integer.  A value between 0 and 12
	 * indicates the length of the Option Value, in bytes.  Three values
	 * are reserved for special constructs:
	 *
	 * 13:  An 8-bit unsigned integer precedes the Option Value and
	 *      indicates the Option Length minus 13.
	 *
	 * 14:  A 16-bit unsigned integer in network byte order precedes the
	 *      Option Value and indicates the Option Length minus 269.
	 *
	 * 15:  Reserved for future use.  If the field is set to this value,
	 *      it MUST be processed as a message format error.
	 */
	switch (opt_jump & 0x0f) {
	case 0x0d:
		opt_length_ext = tvb_get_guint8(tvb, offset);
		opt_length_ext_off = offset;
		opt_length_ext_len = 1;
		offset += 1;

		opt_length  = 13;
		opt_length += opt_length_ext;
		break;
	case 0x0e:
		opt_length_ext = coap_get_opt_uint(tvb, offset, 2);
		opt_length_ext_off = offset;
		opt_length_ext_len = 2;
		offset += 2;

		opt_length  = 269;
		opt_length += opt_length_ext;
		break;
	case 0x0f:
		expert_add_info_format(pinfo, coap_tree, &dissect_hf->ei.opt_length_bad,
			"end-of-options marker found, but option delta isn't 15");
		return -1;
	default:
		opt_length = (opt_jump & 0x0f);
		break;
	}
	if (opt_length > offset_end - offset) {
		expert_add_info_format(pinfo, coap_tree, &dissect_hf->ei.opt_length_bad,
			"option longer than the package");
		return -1;
	}

	snprintf(strbuf, sizeof(strbuf),
	    "#%u: %s", opt_count, val_to_str(*opt_num, vals_opt_type,
	    *opt_num % 14 == 0 ? "No-Op" : "Unknown Option (%d)"));
	item = proto_tree_add_string(coap_tree, dissect_hf->hf.opt_name,
	    tvb, orig_offset, offset - orig_offset + opt_length, strbuf);
	subtree = proto_item_add_subtree(item, dissect_hf->ett.option);

	coap_opt_check(pinfo, subtree, *opt_num, opt_length, dissect_hf);

	snprintf(strbuf, sizeof(strbuf),
	    "Type %u, %s, %s%s", *opt_num,
	    (*opt_num & 1) ? "Critical" : "Elective",
	    (*opt_num & 2) ? "Unsafe" : "Safe",
	    ((*opt_num & 0x1e) == 0x1c) ? ", NoCacheKey" : "");
	proto_tree_add_string(subtree, dissect_hf->hf.opt_desc,
	    tvb, orig_offset, offset - orig_offset + opt_length, strbuf);

	proto_tree_add_item(subtree, dissect_hf->hf.opt_delta,  tvb, orig_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, dissect_hf->hf.opt_length, tvb, orig_offset, 1, ENC_BIG_ENDIAN);

	if (opt_delta_ext_off && opt_delta_ext_len)
		proto_tree_add_item(subtree, dissect_hf->hf.opt_delta_ext, tvb, opt_delta_ext_off, opt_delta_ext_len, ENC_BIG_ENDIAN);

	if (opt_length_ext_off && opt_length_ext_len)
		proto_tree_add_item(subtree, dissect_hf->hf.opt_length_ext, tvb, opt_length_ext_off, opt_length_ext_len, ENC_BIG_ENDIAN);

	/* offset points the next to its option header */
	switch (*opt_num) {
	case COAP_OPT_CONTENT_TYPE:
		dissect_coap_opt_ctype(tvb, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_ctype, coinfo);
		break;
	case COAP_OPT_MAX_AGE:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_max_age);
		break;
	case COAP_OPT_PROXY_URI:
		dissect_coap_opt_proxy_uri(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_proxy_uri);
		break;
	case COAP_OPT_PROXY_SCHEME:
		dissect_coap_opt_proxy_scheme(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_proxy_scheme);
		break;
	case COAP_OPT_SIZE1:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_size1);
		break;
	case COAP_OPT_ETAG:
		dissect_coap_opt_hex_string(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_etag);
		break;
	case COAP_OPT_URI_HOST:
		dissect_coap_opt_uri_host(tvb, pinfo, item, subtree, offset,
		    opt_length, coinfo, dissect_hf->hf.opt_uri_host);
		break;
	case COAP_OPT_LOCATION_PATH:
		dissect_coap_opt_location_path(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_location_path);
		break;
	case COAP_OPT_URI_PORT:
		dissect_coap_opt_uri_port(tvb, item, subtree, offset,
		    opt_length, coinfo, dissect_hf->hf.opt_uri_port);
		break;
	case COAP_OPT_LOCATION_QUERY:
		dissect_coap_opt_location_query(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_location_query);
		break;
	case COAP_OPT_OBJECT_SECURITY:
		dissect_coap_opt_object_security(tvb, item, subtree, offset,
		    opt_length, pinfo, coinfo, dissect_hf, code_class);
		break;
	case COAP_OPT_URI_PATH:
		dissect_coap_opt_uri_path(tvb, pinfo, item, subtree, offset,
		    opt_length, coinfo, dissect_hf->hf.opt_uri_path);
		break;
	case COAP_OPT_OBSERVE:
		if (code_class == 0) {
			/* Request */
			dissect_coap_opt_uint(tvb, item, subtree, offset,
			    opt_length, dissect_hf->hf.opt_observe_req);
		} else {
			/* Response */
			dissect_coap_opt_uint(tvb, item, subtree, offset,
			    opt_length, dissect_hf->hf.opt_observe_rsp);
		}
		break;
	case COAP_OPT_HOP_LIMIT:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_hop_limit);
		break;
	case COAP_OPT_ACCEPT:
		dissect_coap_opt_accept(tvb, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_accept);
		break;
	case COAP_OPT_IF_MATCH:
		dissect_coap_opt_hex_string(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_if_match);
		break;
	case COAP_OPT_URI_QUERY:
		dissect_coap_opt_uri_query(tvb, pinfo, item, subtree, offset,
		    opt_length, coinfo, dissect_hf->hf.opt_uri_query);
		break;
	case COAP_OPT_BLOCK2:
		coinfo->block_option = 2;
		dissect_coap_opt_block(tvb, item, subtree, offset,
		    opt_length, coinfo, dissect_hf);
		break;
	case COAP_OPT_BLOCK1:
		coinfo->block_option = 1;
		dissect_coap_opt_block(tvb, item, subtree, offset,
		    opt_length, coinfo, dissect_hf);
		break;
	case COAP_OPT_IF_NONE_MATCH:
		break;
	case COAP_OPT_SIZE2:
		dissect_coap_opt_uint(tvb, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_block_size);
		break;
	default:
		dissect_coap_opt_hex_string(tvb, pinfo, item, subtree, offset,
		    opt_length, dissect_hf->hf.opt_unknown);
		break;
	}

	return offset + opt_length;
}

/*
 * options dissector.
 * return offset pointing the next of options. (i.e. the top of the paylaod
 * or the end of the data.
 */
int
dissect_coap_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, gint offset, gint offset_end, guint8 code_class, coap_info *coinfo, coap_common_dissect_t *dissect_hf)
{
	guint  opt_num = 0;
	int    i;
	guint8 endmarker;

	/* loop for dissecting options */
	for (i = 1; offset < offset_end; i++) {
		offset = dissect_coap_options_main(tvb, pinfo, coap_tree,
		    offset, i, &opt_num, offset_end, code_class, coinfo, dissect_hf);
		if (offset == -1)
			return -1;
		if (offset >= offset_end)
			break;
		endmarker = tvb_get_guint8(tvb, offset);
		if (endmarker == 0xff) {
			proto_tree_add_item(coap_tree, dissect_hf->hf.opt_end_marker, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;
		}
	}

	return offset;
}

/*
 * CoAP code dissector.
 * return code value and updates the offset
 * */
guint8
dissect_coap_code(tvbuff_t *tvb, proto_tree *tree, gint *offset, coap_common_dissect_t *dissect_hf, guint8 *code_class)
{
	guint8 code;

	proto_tree_add_item(tree, dissect_hf->hf.code, tvb, *offset, 1, ENC_BIG_ENDIAN);
	code = tvb_get_guint8(tvb, *offset);
	*code_class = code >> 5;
	*offset += 1;

	return code;
}

void
dissect_coap_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *coap_tree, proto_tree *parent_tree, gint offset, gint offset_end, guint8 code_class, coap_info *coinfo, coap_common_dissect_t *dissect_hf, gboolean oscore)
{
	proto_tree *payload_tree;
	proto_item *payload_item, *length_item;
	tvbuff_t   *payload_tvb;
	guint	    payload_length = offset_end - offset;
	const char *coap_ctype_str_dis;
	http_message_info_t message_info;
	char	    str_payload[80];

	/* coinfo->ctype_value == DEFAULT_COAP_CTYPE_VALUE: No Content-Format option present */
	if (coinfo->ctype_value == DEFAULT_COAP_CTYPE_VALUE) {
		/*
		* 5.5.2.  Diagnostic Payload
		*
		* If no Content-Format option is given, the payload of responses
		* indicating a client or server error is a brief human-readable
		* diagnostic message, explaining the error situation. This diagnostic
		* message MUST be encoded using UTF-8 [RFC3629], more specifically
		* using Net-Unicode form [RFC5198].
		*/
		if ((code_class >= 4) && (code_class <= 5)) {
			coinfo->ctype_str = "text/plain; charset=utf-8";
			coap_ctype_str_dis = "text/plain";
		} else {
			/* Assume no Content-Format is opaque octet stream */
			coinfo->ctype_str = "application/octet-stream";
			coap_ctype_str_dis = coinfo->ctype_str;
		}
	}
	/* coinfo->ctype_value == 0: Content-Format option present with length 0 */
	else if (coinfo->ctype_value == 0) {
		/* coinfo->ctype_str is already set by option parsing routine */
		coap_ctype_str_dis = "text/plain";
	} else {
		coap_ctype_str_dis = coinfo->ctype_str;
	}

	snprintf(str_payload, sizeof(str_payload),
			"Payload Content-Format: %s%s, Length: %u",
			coinfo->ctype_str, coinfo->ctype_value == DEFAULT_COAP_CTYPE_VALUE ?
			" (no Content-Format)" : "", payload_length);

	payload_item = proto_tree_add_string(coap_tree, dissect_hf->hf.payload,
					     tvb, offset, payload_length,
					     str_payload);
	payload_tree = proto_item_add_subtree(payload_item, dissect_hf->ett.payload);

	proto_tree_add_string(payload_tree, dissect_hf->hf.payload_desc, tvb, offset, 0, coinfo->ctype_str);
	length_item = proto_tree_add_uint(payload_tree, dissect_hf->hf.payload_length, tvb, offset, 0, payload_length);
	proto_item_set_generated(length_item);
	payload_tvb = tvb_new_subset_length(tvb, offset, payload_length);

	message_info.type = HTTP_OTHERS;
	message_info.media_str = wmem_strbuf_get_str(coinfo->uri_str_strbuf);
	dissector_try_string(media_type_dissector_table, coap_ctype_str_dis,
			     payload_tvb, pinfo, parent_tree, &message_info);

	if (coinfo->object_security && !oscore) {
		proto_item_set_text(payload_item, "Encrypted OSCORE Data");
		call_dissector_with_data(oscore_handle, payload_tvb, pinfo, parent_tree, coinfo->oscore_info);
	}
}

static guint32
coap_frame_length(tvbuff_t *tvb, guint offset, gint *size)
{
	/*
	 * Decode Len and Extended Length according to
	 * https://tools.ietf.org/html/rfc8323#page-10
	 */
	guint8 len = tvb_get_guint8(tvb, offset) >> 4;
	switch (len) {
	default:
		*size = 1;
		return len;
	case 13:
		if (tvb_reported_length_remaining(tvb, offset) < 2) {
			*size = -1;
			return 0;
		}
		*size = 2;
		return tvb_get_guint8(tvb, offset + 1) + 13;
	case 14:
		if (tvb_reported_length_remaining(tvb, offset) < 3) {
			*size = -1;
			return 0;
		}
		*size = 3;
		return tvb_get_ntohs(tvb, offset + 1) + 269;
	case 15:
		if (tvb_reported_length_remaining(tvb, offset) < 5) {
			*size = -1;
			return 0;
		}
		*size = 5;
		return tvb_get_ntohl(tvb, offset + 1) + 65805;
	}
}

static int
dissect_coap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean is_tcp, gboolean is_websocket)
{
	gint              offset = 0;
	proto_item       *coap_root;
	proto_item       *pi;
	proto_tree       *coap_tree;
	gint              length_size = 0;
	guint8            ttype = G_MAXUINT8;
	guint32           token_len;
	guint8            code;
	guint8            code_class;
	guint32           mid = 0;
	gint              coap_length;
	gchar            *coap_token_str;
	coap_info        *coinfo;
	conversation_t   *conversation;
	coap_conv_info   *ccinfo;
	coap_transaction *coap_trans = NULL;
	coap_request_response *coap_req_rsp = NULL;

	// TODO support TCP/WebSocket/TCP with more than one PDU per packet.
	// These probably require a unique coinfo for each.

	/* Allocate information for upper layers */
	coinfo = (coap_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_coap, 0);

	if (coinfo == NULL)
	{
		coinfo = wmem_new0(wmem_file_scope(), coap_info);
		p_add_proto_data(wmem_file_scope(), pinfo, proto_coap, 0, coinfo);
	}

	/* initialize the CoAP length and the content-Format */
	/*
	 * The length of CoAP message is not specified in the CoAP header using
	 * UDP or WebSockets. The lower layers provide it. For TCP/TLS, an
	 * explicit length is present.
	 */
	coap_length = tvb_reported_length(tvb);
	if (is_tcp && !is_websocket) {
		token_len = tvb_get_guint8(tvb, offset) & 0xf;
		coap_length = coap_frame_length(tvb, offset, &length_size);
		if (length_size < 0) {
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return tvb_reported_length(tvb);
		}
		/*
		 * Length of the whole CoAP frame includes the (Extended) Length fields
		 * (1 to 4 bytes), the Code (1 byte) and token length (normally 0 to 8
		 * bytes), plus everything afterwards.
		 */
		coap_length += 1 + token_len + length_size;
		if (coap_length > tvb_reported_length_remaining(tvb, offset)) {
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = coap_length - tvb_reported_length_remaining(tvb, offset);
			return tvb_reported_length(tvb);
		}
	}
	coinfo->ctype_str = "";
	coinfo->ctype_value = DEFAULT_COAP_CTYPE_VALUE;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAP");
	col_clear(pinfo->cinfo, COL_INFO);

	coap_root = proto_tree_add_item(parent_tree, proto_coap, tvb, offset, -1, ENC_NA);
	coap_tree = proto_item_add_subtree(coap_root, ett_coap);

	if (!is_tcp) {
		proto_tree_add_item(coap_tree, hf_coap_version, tvb, offset, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(coap_tree, hf_coap_ttype, tvb, offset, 1, ENC_BIG_ENDIAN);
		ttype = (tvb_get_guint8(tvb, offset) & COAP_TYPE_MASK) >> 4;

		proto_tree_add_item_ret_uint(coap_tree, hf_coap_token_len, tvb, offset, 1, ENC_BIG_ENDIAN, &token_len);
		offset += 1;

		code = dissect_coap_code(tvb, coap_tree, &offset, &dissect_coap_hf, &code_class);

		proto_tree_add_item(coap_tree, hf_coap_mid, tvb, offset, 2, ENC_BIG_ENDIAN);
		mid = tvb_get_ntohs(tvb, offset);
		offset += 2;

		col_add_fstr(pinfo->cinfo, COL_INFO,
			     "%s, MID:%u, %s",
			     val_to_str(ttype, vals_ttype_short, "Unknown %u"),
			     mid,
			     val_to_str_ext(code, &coap_vals_code_ext, "Unknown %u"));

		/* append the header information */
		proto_item_append_text(coap_root,
				       ", %s, %s, MID:%u",
				       val_to_str(ttype, vals_ttype, "Unknown %u"),
				       val_to_str_ext(code, &coap_vals_code_ext, "Unknown %u"),
				       mid);
	} else {
		guint len = coap_length;
		if (is_websocket) {
			len = tvb_get_guint8(tvb, offset) >> 4;
			length_size = 1;
		}
		proto_tree_add_uint(coap_tree, hf_coap_length, tvb, offset, length_size, len);

		proto_tree_add_item_ret_uint(coap_tree, hf_coap_token_len, tvb, offset, 1, ENC_BIG_ENDIAN, &token_len);
		offset += length_size;

		code = dissect_coap_code(tvb, coap_tree, &offset, &dissect_coap_hf, &code_class);

		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
				   val_to_str_ext(code, &coap_vals_code_ext, "Unknown %u"));

		/* append the header information */
		proto_item_append_text(coap_root,
				       ", %s",
				       val_to_str_ext(code, &coap_vals_code_ext, "Unknown %u"));
	}

	/* initialize the external value */
	coinfo->block_option = 0;
	coinfo->block_number = DEFAULT_COAP_BLOCK_NUMBER;
	coinfo->block_mflag  = 0;
	coinfo->uri_str_strbuf   = wmem_strbuf_sized_new(pinfo->pool, 0, 1024);
	coinfo->uri_query_strbuf = wmem_strbuf_sized_new(pinfo->pool, 0, 1024);
	 /* Allocate pointers and static elements of oscore_info_t, arrays are allocated only if object security option is found during option parsing */
	coinfo->oscore_info = wmem_new0(pinfo->pool, oscore_info_t);
	coinfo->object_security = FALSE;
	coap_token_str = NULL;

	if (token_len > 0)
	{
		/* This has to be file scope as the token string is stored in the map
		* for conversation lookup */
		coap_token_str = tvb_bytes_to_str_punct(wmem_file_scope(), tvb, offset, token_len, ' ');
		proto_tree_add_item(coap_tree, hf_coap_token,
				    tvb, offset, token_len, ENC_NA);
		offset += token_len;
	}

	/* process options */
	offset = dissect_coap_options(tvb, pinfo, coap_tree, offset, coap_length, code_class, coinfo, &dissect_coap_hf);
	if (offset == -1)
		return tvb_captured_length(tvb);

	/* Use conversations to track state for request/response */
	conversation = find_or_create_conversation_noaddrb(pinfo, (code_class == 0));

	/* Retrieve or create state structure for this conversation */
	ccinfo = (coap_conv_info *)conversation_get_proto_data(conversation, proto_coap);
	if (!ccinfo) {
		/* No state structure - create it */
		ccinfo = wmem_new(wmem_file_scope(), coap_conv_info);
		ccinfo->messages = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
		conversation_add_proto_data(conversation, proto_coap, ccinfo);
	}

	/* Everything based on tokens */
	if (coap_token_str != NULL) {
		/* Process request/response in conversation */
		if (code != 0) { /* Ignore empty messages */
			/* Try and look up a matching token. If it's the first
			* sight of a request, there shouldn't be one */
			coap_trans = (coap_transaction *)wmem_map_lookup(ccinfo->messages, coap_token_str);
			if (!coap_trans) {
				if ((!PINFO_FD_VISITED(pinfo)) && (code_class == 0)) {
					/* New request - log it */
					coap_trans = wmem_new0(wmem_file_scope(), coap_transaction);
					coap_trans->req_rsp = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
					if (coinfo->uri_str_strbuf) {
						/* Store the URI into CoAP transaction info */
						coap_trans->uri_str_strbuf = wmem_strbuf_new(wmem_file_scope(), wmem_strbuf_get_str(coinfo->uri_str_strbuf));
					}
					if (coinfo->oscore_info) {
						coap_trans->oscore_info = (oscore_info_t *) wmem_memdup(wmem_file_scope(), coinfo->oscore_info, sizeof(oscore_info_t));
						if (coinfo->oscore_info->kid) {
							coap_trans->oscore_info->kid = (guint8 *) wmem_memdup(wmem_file_scope(), coinfo->oscore_info->kid, coinfo->oscore_info->kid_len);
						}
						if (coinfo->oscore_info->kid_context) {
							coap_trans->oscore_info->kid_context = (guint8 *) wmem_memdup(wmem_file_scope(), coinfo->oscore_info->kid_context, coinfo->oscore_info->kid_context_len);
						}
						if (coinfo->oscore_info->piv) {
							coap_trans->oscore_info->request_piv = (guint8 *) wmem_memdup(wmem_file_scope(), coinfo->oscore_info->request_piv, coinfo->oscore_info->request_piv_len);
						}
					}
					wmem_map_insert(ccinfo->messages, coap_token_str, (void *)coap_trans);
				}
			} else {
				if ((code_class >= 2) && (code_class <= 5)) {
					if (coap_trans->uri_str_strbuf) {
						/* Copy the URI stored in matching transaction info into CoAP packet info */
						coinfo->uri_str_strbuf = wmem_strbuf_new(pinfo->pool, wmem_strbuf_get_str(coap_trans->uri_str_strbuf));
					}
					if (coap_trans->oscore_info) {
						/* Copy OSCORE info in matching transaction info into CoAP packet info */
						if (coap_trans->oscore_info->kid) {
							coinfo->oscore_info->kid = (guint8 *) wmem_memdup(pinfo->pool, coap_trans->oscore_info->kid, coap_trans->oscore_info->kid_len);
						}
						coinfo->oscore_info->kid_len = coap_trans->oscore_info->kid_len;

						if (coap_trans->oscore_info->kid_context) {
							coinfo->oscore_info->kid_context = (guint8 *) wmem_memdup(pinfo->pool, coap_trans->oscore_info->kid_context, coap_trans->oscore_info->kid_context_len);
						}
						coinfo->oscore_info->kid_context_len = coap_trans->oscore_info->kid_context_len;

						if (coap_trans->oscore_info->request_piv) {
							coinfo->oscore_info->request_piv = (guint8 *) wmem_memdup(pinfo->pool, coap_trans->oscore_info->request_piv, coap_trans->oscore_info->request_piv_len);
						}
						coinfo->oscore_info->request_piv_len = coap_trans->oscore_info->request_piv_len;
						coinfo->oscore_info->response = TRUE;

					}
				}
			}

			if (coap_trans) {
				coap_req_rsp = (coap_request_response *)wmem_map_lookup(coap_trans->req_rsp, GINT_TO_POINTER(mid));
				if (!PINFO_FD_VISITED(pinfo)) {
					if (!coap_req_rsp) {
						coap_req_rsp = wmem_new0(wmem_file_scope(), coap_request_response);
						wmem_map_insert(coap_trans->req_rsp, GINT_TO_POINTER(mid), (void *)coap_req_rsp);
					}
					if (code_class == 0) {
						/* This is a request */
						if (coap_req_rsp->req_frame == 0) {
							/* Log the first request frame */
							coap_req_rsp->req_frame = pinfo->num;
							coap_req_rsp->req_time = pinfo->abs_ts;
						}
					} else if ((code_class >= 2) && (code_class <= 5)) {
						/* This is a reply */
						if (coap_req_rsp->rsp_frame == 0) {
							/* Log the first matching response frame */
							coap_req_rsp->rsp_frame = pinfo->num;
						}
					}
				}
			}
		}
	}

	/* dissect the payload */
	if (coap_length > offset) {
		if (coinfo->block_number == DEFAULT_COAP_BLOCK_NUMBER) {
			dissect_coap_payload(tvb, pinfo, coap_tree, parent_tree, offset, coap_length,
					     code_class, coinfo, &dissect_coap_hf, FALSE);
		} else {
			proto_tree_add_bytes_format(coap_tree, hf_block_payload, tvb, offset,
						    coap_length - offset, NULL, "Block Payload");
			pi = proto_tree_add_uint(coap_tree, hf_block_length, tvb, offset, 0, coap_length - offset);
			proto_item_set_generated(pi);

			fragment_head *frag_msg = fragment_add_seq_check(&coap_block_reassembly_table, tvb, offset,
									 pinfo, 0, NULL, coinfo->block_number,
									 coap_length - offset, coinfo->block_mflag);
			tvbuff_t *frag_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled CoAP blocks",
								      frag_msg, &coap_block_frag_items, NULL, coap_tree);

			if (frag_tvb) {
				dissect_coap_payload(frag_tvb, pinfo, coap_tree, parent_tree, 0, tvb_reported_length(frag_tvb),
						     code_class, coinfo, &dissect_coap_hf, FALSE);
			}
		}
	}

	/* add informations to the packet list */
	if (coap_token_str != NULL)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", TKN:%s", coap_token_str);
	if (coinfo->block_number != DEFAULT_COAP_BLOCK_NUMBER) {
		/* The M bit is used in Block1 Option in a request and in Block2 Option in a response */
		gboolean mflag_is_used = (((coinfo->block_option == 1) && (code_class == 0)) ||
					  ((coinfo->block_option == 2) && (code_class >= 2) && (code_class <= 5)));
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %sBlock #%u",
				(coinfo->block_mflag || !mflag_is_used) ? "" : "End of ", coinfo->block_number);
	}
	if (wmem_strbuf_get_len(coinfo->uri_str_strbuf) > 0) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", format_text(pinfo->pool, wmem_strbuf_get_str(coinfo->uri_str_strbuf), wmem_strbuf_get_len(coinfo->uri_str_strbuf)));
		/* Add a generated protocol item as well */
		pi = proto_tree_add_string(coap_tree, dissect_coap_hf.hf.opt_uri_path_recon, tvb, 0, 0, wmem_strbuf_get_str(coinfo->uri_str_strbuf));
		proto_item_set_generated(pi);
	}
	if (wmem_strbuf_get_len(coinfo->uri_query_strbuf) > 0)
		col_append_str(pinfo->cinfo, COL_INFO, format_text(pinfo->pool, wmem_strbuf_get_str(coinfo->uri_query_strbuf), wmem_strbuf_get_len(coinfo->uri_query_strbuf)));

	if (coap_req_rsp != NULL) {
		/* Print state tracking in the tree */
		if (code_class == 0) {
			/* This is a request */
			if (coap_req_rsp->rsp_frame) {
				pi = proto_tree_add_uint(coap_tree, hf_coap_response_in,
							 tvb, 0, 0, coap_req_rsp->rsp_frame);
				proto_item_set_generated(pi);
			}
			if ((ttype == TT_CON || ttype == TT_NON) && (coap_req_rsp->req_frame != pinfo->num)) {
				col_append_str(pinfo->cinfo, COL_INFO, " [Retransmission]");
				pi = proto_tree_add_uint(coap_tree, hf_coap_request_resend_in,
							 tvb, 0, 0, coap_req_rsp->req_frame);
				proto_item_set_generated(pi);
				expert_add_info(pinfo, pi, &ei_retransmitted);
			}
		} else if ((code_class >= 2) && (code_class <= 5)) {
			/* This is a reply */
			if (coap_req_rsp->req_frame) {
				nstime_t ns;

				pi = proto_tree_add_uint(coap_tree, hf_coap_response_to,
							 tvb, 0, 0, coap_req_rsp->req_frame);
				proto_item_set_generated(pi);

				nstime_delta(&ns, &pinfo->abs_ts, &coap_req_rsp->req_time);
				pi = proto_tree_add_time(coap_tree, hf_coap_response_time, tvb, 0, 0, &ns);
				proto_item_set_generated(pi);
			}
			if ((ttype == TT_CON || ttype == TT_NON) && (coap_req_rsp->rsp_frame != pinfo->num)) {
				col_append_str(pinfo->cinfo, COL_INFO, " [Retransmission]");
				pi = proto_tree_add_uint(coap_tree, hf_coap_response_resend_in,
							 tvb, 0, 0, coap_req_rsp->rsp_frame);
				proto_item_set_generated(pi);
				expert_add_info(pinfo, pi, &ei_retransmitted);
			}
		}
	}

	if (coap_trans != NULL) {
		if ((code_class >= 2) && (code_class <= 5)) {
			/* This is a reply */
			if (coinfo->object_security && coap_trans->oscore_info) {
				pi = proto_tree_add_bytes(coap_tree, hf_coap_oscore_kid, tvb, 0, coap_trans->oscore_info->kid_len, coap_trans->oscore_info->kid);
				proto_item_set_generated(pi);

				pi = proto_tree_add_bytes(coap_tree, hf_coap_oscore_kid_context, tvb, 0, coap_trans->oscore_info->kid_context_len, coap_trans->oscore_info->kid_context);
				proto_item_set_generated(pi);

				if (coinfo->oscore_info->piv_len) {
					pi = proto_tree_add_bytes(coap_tree, hf_coap_oscore_piv, tvb, 0, coinfo->oscore_info->piv_len, coinfo->oscore_info->piv);
				} else {
					pi = proto_tree_add_bytes(coap_tree, hf_coap_oscore_piv, tvb, 0, coinfo->oscore_info->request_piv_len, coinfo->oscore_info->request_piv);
				}
				proto_item_set_generated(pi);
			}
		}
	}

	return coap_length;
}

static int
dissect_coap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	wmem_list_frame_t *prev_layer;
	const char *name;

	/* retrieve parent protocol */
	prev_layer = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
	if (prev_layer) {
		name = proto_get_protocol_filter_name(GPOINTER_TO_INT(wmem_list_frame_data(prev_layer)));
	} else {
		name = NULL;
	}
	if (proto_is_frame_protocol(pinfo->layers, "websocket")) {
		/* WebSockets */
		return dissect_coap_message(tvb, pinfo, tree, TRUE, TRUE);
	} else if (!g_strcmp0(name, "tcp") || !g_strcmp0(name, "tls")) {
		/* TCP */
		return dissect_coap_message(tvb, pinfo, tree, TRUE, FALSE);
	} else {
		/* Assume UDP */
		return dissect_coap_message(tvb, pinfo, tree, FALSE, FALSE);
	}
}

/*
 * Protocol initialization
 */
void
proto_register_coap(void)
{
	static hf_register_info hf[] = {
		{ &hf_coap_length,
		  { "Length", "coap.length",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Length of the CoAP frame, combining Len and Extended Length (if any) fields", HFILL }
		},
		{ &hf_coap_version,
		  { "Version", "coap.version",
		    FT_UINT8, BASE_DEC, NULL, COAP_VERSION_MASK,
		    NULL, HFILL }
		},
		{ &hf_coap_ttype,
		  { "Type", "coap.type",
		    FT_UINT8, BASE_DEC, VALS(vals_ttype), COAP_TYPE_MASK,
		    NULL, HFILL }
		},
		{ &hf_coap_token_len,
		  { "Token Length", "coap.token_len",
		    FT_UINT8, BASE_DEC, NULL, COAP_TOKEN_LEN_MASK,
		    NULL, HFILL }
		},
		{ &hf_coap_token,
		  { "Token", "coap.token",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_mid,
		  { "Message ID", "coap.mid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_coap_response_in,
		  { "Response In", "coap.response_in",
		    FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
		    "The response to this CoAP request is in this frame", HFILL }
		},
		{ &hf_coap_response_to,
		  { "Request In", "coap.response_to",
		    FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
		    "This is a response to the CoAP request in this frame", HFILL }
		},
		{ &hf_coap_response_time,
		  { "Response Time", "coap.response_time",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "The time between the Call and the Reply", HFILL }
		},
		{ &hf_coap_request_resend_in,
		  { "Retransmission of request in", "coap.request_first_in",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "This request was first sent in this frame", HFILL }
		},
		{ &hf_coap_response_resend_in,
		  { "Retransmission of response in", "coap.response_first_in",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "This response was first sent in this frame", HFILL }
		},
		{ &hf_coap_oscore_kid,
		  { "OSCORE Key ID", "coap.oscore_kid", FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Matched OSCORE Key ID", HFILL }
		},
		{ &hf_coap_oscore_kid_context,
		  { "OSCORE Key ID Context", "coap.oscore_kid_context", FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Matched OSCORE Key ID Context", HFILL }
		},
		{ &hf_coap_oscore_piv,
		  { "OSCORE Partial IV", "coap.oscore_piv", FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Matched OSCORE Partial IV", HFILL }
		},
		{ &hf_block_payload,
		  { "Block Payload", "coap.block_payload",
			FT_BYTES, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_block_length,
		  { "Block Length", "coap.block_length",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_blocks,
		  { "Blocks", "coap.blocks",
			FT_NONE, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_block,
		  { "Block", "coap.block",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_block_overlap,
		  { "Block overlap", "coap.block.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_block_overlap_conflicts,
		  { "Block overlapping with conflicting data", "coap.block.overlap.conflicts",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_block_multiple_tails,
		  { "Block has multiple tails", "coap.block.multiple_tails",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_block_too_long,
		  { "Block too long", "coap.block.too_long",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_block_error,
		  { "Block defragmentation error", "coap.block.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_block_count,
		  { "Block count", "coap.block.count",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_block_reassembled_in,
		  { "Reassembled in", "coap.block.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_block_reassembled_length,
		  { "Reassembled block length", "coap.block.reassembled.length",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},
		COAP_COMMON_HF_LIST(dissect_coap_hf, "coap")
	};

	static gint *ett[] = {
		&ett_coap,
		&ett_block,
		&ett_blocks,
		COAP_COMMON_ETT_LIST(dissect_coap_hf)
	};

	static ei_register_info ei[] = {
		{ &ei_retransmitted,
		  { "coap.retransmitted", PI_SEQUENCE, PI_NOTE,
		    "Retransmitted", EXPFILL }
		},
		COAP_COMMON_EI_LIST(dissect_coap_hf, "coap")
	};

	expert_module_t *expert_coap;

	proto_coap = proto_register_protocol("Constrained Application Protocol", "CoAP", "coap");
	proto_register_field_array(proto_coap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_coap = expert_register_protocol(proto_coap);
	expert_register_field_array(expert_coap, ei, array_length(ei));

	reassembly_table_register (&coap_block_reassembly_table, &addresses_reassembly_table_functions);

	coap_handle = register_dissector("coap", dissect_coap, proto_coap);
}

void
proto_reg_handoff_coap(void)
{
	media_type_dissector_table = find_dissector_table("media_type");
	dissector_add_uint_with_preference("udp.port", DEFAULT_COAP_PORT, coap_handle);
	dtls_dissector_add(DEFAULT_COAPS_PORT, coap_handle);

	/* TCP, TLS, WebSockets (RFC 8323) */
	dissector_add_uint_with_preference("tcp.port", DEFAULT_COAP_PORT, coap_handle);
	ssl_dissector_add(DEFAULT_COAPS_PORT, coap_handle);
	dissector_add_string("tls.alpn", "coap", coap_handle);
	dissector_add_string("ws.protocol", "coap", coap_handle);

	oscore_handle = find_dissector("oscore");
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
