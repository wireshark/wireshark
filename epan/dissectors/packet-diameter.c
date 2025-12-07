/* packet-diameter.c
 * Routines for Diameter packet disassembly
 *
 * Copyright (c) 2001 by David Frascone <dave@frascone.com>
 * Copyright (c) 2007 by Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Support for Request-Answer tracking and Tapping
 * introduced by Abhik Sarkar
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 *
 * RFC 3588, "Diameter Base Protocol" (now RFC 6733)
 * draft-ietf-aaa-diameter-mobileip-16, "Diameter Mobile IPv4 Application"
 *    (now RFC 4004)
 * draft-ietf-aaa-diameter-nasreq-14, "Diameter Network Access Server
 *     Application" (now RFC 4005)
 * drafts/draft-ietf-aaa-diameter-cc-03, "Diameter Credit-Control
 *     Application" (now RFC 4006)
 * draft-ietf-aaa-diameter-sip-app-01, "Diameter Session Initiation
 *     Protocol (SIP) Application" (now RFC 4740)
 * RFC 5779, "Diameter Proxy Mobile IPv6: Mobile Access Gateway and
 *     Local Mobility Anchor Interaction with Diameter Server"
 * 3GPP TS 29.273, V15.2.0
 * http://www.ietf.org/html.charters/aaa-charter.html
 * http://www.iana.org/assignments/radius-types
 * http://www.iana.org/assignments/address-family-numbers
 * http://www.iana.org/assignments/enterprise-numbers
 * http://www.iana.org/assignments/aaa-parameters
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/exported_pdu.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/tfs.h>

#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/ws_padding_to.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <wsutil/strtoi.h>
#include "packet-iana-data.h"
#include "packet-tcp.h"
#include "packet-diameter.h"
#include "packet-tls.h"
#include "packet-dtls.h"
#include "packet-e212.h"
#include "packet-e164.h"
#include "packet-eap.h"
#include "packet-sctp.h"

void proto_register_diameter(void);
void proto_reg_handoff_diameter(void);

/* Diameter Header Flags */
/* RPETrrrrCCCCCCCCCCCCCCCCCCCCCCCC  */
#define DIAM_FLAGS_R 0x80
#define DIAM_FLAGS_P 0x40
#define DIAM_FLAGS_E 0x20
#define DIAM_FLAGS_T 0x10
#define DIAM_FLAGS_RESERVED4 0x08
#define DIAM_FLAGS_RESERVED5 0x04
#define DIAM_FLAGS_RESERVED6 0x02
#define DIAM_FLAGS_RESERVED7 0x01
#define DIAM_FLAGS_RESERVED  0x0f

/* Diameter AVP Flags */
#define AVP_FLAGS_P 0x20
#define AVP_FLAGS_V 0x80
#define AVP_FLAGS_M 0x40
#define AVP_FLAGS_RESERVED3 0x10
#define AVP_FLAGS_RESERVED4 0x08
#define AVP_FLAGS_RESERVED5 0x04
#define AVP_FLAGS_RESERVED6 0x02
#define AVP_FLAGS_RESERVED7 0x01
#define AVP_FLAGS_RESERVED 0x1f          /* 00011111  -- V M P X X X X X */

#define DIAMETER_RFC 1

static int exported_pdu_tap = -1;

/* Conversation Info */
typedef struct _diameter_conv_info_t {
	wmem_tree_t *pdus_tree;
} diameter_conv_info_t;

typedef struct _diam_ctx_t {
	proto_tree *tree;
	packet_info *pinfo;
	wmem_tree_t *avps;
} diam_ctx_t;

typedef struct _diam_avp_t diam_avp_t;
typedef struct _avp_type_t avp_type_t;

typedef const char *(*diam_avp_dissector_t)(diam_ctx_t *, diam_avp_t *, tvbuff_t *, diam_sub_dis_t *);


typedef struct _diam_vnd_t {
	uint32_t code;
	wmem_array_t *vs_avps;
	value_string_ext *vs_avps_ext;
} diam_vnd_t;

struct _diam_avp_t {
	uint32_t code;
	diam_vnd_t *vendor;
	diam_avp_dissector_t dissector_rfc;

	int ett;
	int hf_value;
	void *type_data;
};

#define VND_AVP_VS(v)      ((value_string *)(void *)(wmem_array_get_raw((v)->vs_avps)))
#define VND_AVP_VS_LEN(v)  (wmem_array_get_count((v)->vs_avps))

typedef struct _diam_dictionary_t {
	wmem_tree_t *avps;
	wmem_tree_t *vnds;
	value_string_ext *applications;
} diam_dictionary_t;

typedef struct _avp_constructor_data_t {

	const avp_type_t* type;
	uint32_t code;
	diam_vnd_t* vendor;
	const char* name;
	const value_string* vs;
	void* data;
	wmem_array_t* hf_array;
	GPtrArray* ett_array;
} avp_constructor_data_t;

typedef diam_avp_t *(*avp_constructor_t)(avp_constructor_data_t* constructor_data);

struct _avp_type_t {
	const char *name;
	diam_avp_dissector_t rfc;
	enum ftenum ft;
	int base;
	avp_constructor_t build;
};

typedef struct _address_avp_t {
	int ett;
	int hf_address_type;
	int hf_ipv4;
	int hf_ipv6;
	int hf_e164_str;
	int hf_other;
} address_avp_t;

typedef enum {
	REASSEMBLE_NEVER = 0,
	REASSEMBLE_AT_END,
	REASSEMBLE_BY_LENGTH
} avp_reassemble_mode_t;

typedef struct _proto_avp_t {
	char *name;
	dissector_handle_t handle;
	avp_reassemble_mode_t reassemble_mode;
} proto_avp_t;

static const char *simple_avp(diam_ctx_t *, diam_avp_t *, tvbuff_t *, diam_sub_dis_t *);

static diam_vnd_t unknown_vendor = { 0xffffffff, NULL, NULL };
static diam_vnd_t no_vnd = { 0, NULL, NULL };
static diam_avp_t unknown_avp = {0, &unknown_vendor, simple_avp, -1, -1, NULL };
static const value_string *cmd_vs;
static diam_dictionary_t dictionary = { NULL, NULL, NULL};
static dissector_handle_t data_handle;
static dissector_handle_t eap_handle;

static const value_string diameter_avp_data_addrfamily_vals[]= {
	{1,"IPv4"},
	{2,"IPv6"},
	{3,"NSAP"},
	{4,"HDLC"},
	{5,"BBN"},
	{6,"IEEE-802"},
	{7,"E-163"},
	{8,"E-164"},
	{9,"F-69"},
	{10,"X-121"},
	{11,"IPX"},
	{12,"Appletalk"},
	{13,"Decnet4"},
	{14,"Vines"},
	{15,"E-164-NSAP"},
	{16,"DNS"},
	{17,"DistinguishedName"},
	{18,"AS"},
	{19,"XTPoIPv4"},
	{20,"XTPoIPv6"},
	{21,"XTPNative"},
	{22,"FibrePortName"},
	{23,"FibreNodeName"},
	{24,"GWID"},
	{0,NULL}
};
static value_string_ext diameter_avp_data_addrfamily_vals_ext = VALUE_STRING_EXT_INIT(diameter_avp_data_addrfamily_vals);

static int proto_diameter;
static int hf_diameter_length;
static int hf_diameter_code;
static int hf_diameter_hopbyhopid;
static int hf_diameter_endtoendid;
static int hf_diameter_version;
static int hf_diameter_vendor_id;
static int hf_diameter_application_id;
static int hf_diameter_flags;
static int hf_diameter_flags_request;
static int hf_diameter_flags_proxyable;
static int hf_diameter_flags_error;
static int hf_diameter_flags_T;
static int hf_diameter_flags_reserved4;
static int hf_diameter_flags_reserved5;
static int hf_diameter_flags_reserved6;
static int hf_diameter_flags_reserved7;

static int hf_diameter_avp;
static int hf_diameter_avp_len;
static int hf_diameter_avp_code;
static int hf_diameter_avp_flags;
static int hf_diameter_avp_flags_vendor_specific;
static int hf_diameter_avp_flags_mandatory;
static int hf_diameter_avp_flags_protected;
static int hf_diameter_avp_flags_reserved3;
static int hf_diameter_avp_flags_reserved4;
static int hf_diameter_avp_flags_reserved5;
static int hf_diameter_avp_flags_reserved6;
static int hf_diameter_avp_flags_reserved7;
static int hf_diameter_avp_vendor_id;
static int hf_diameter_avp_data_wrong_length;
static int hf_diameter_avp_pad;

static int hf_diameter_answer_in;
static int hf_diameter_answer_to;
static int hf_diameter_answer_time;

/* AVPs with special/extra decoding */
static int hf_framed_ipv6_prefix_reserved;
static int hf_framed_ipv6_prefix_length;
static int hf_framed_ipv6_prefix_bytes;
static int hf_framed_ipv6_prefix_ipv6;
static int hf_diameter_3gpp2_exp_res;
static int hf_diameter_other_vendor_exp_res;
static int hf_diameter_mip6_feature_vector;
static int hf_diameter_mip6_feature_vector_mip6_integrated;
static int hf_diameter_mip6_feature_vector_local_home_agent_assignment;
static int hf_diameter_mip6_feature_vector_pmip6_supported;
static int hf_diameter_mip6_feature_vector_ip4_hoa_supported;
static int hf_diameter_mip6_feature_vector_local_mag_routing_supported;
static int hf_diameter_3gpp_mip6_feature_vector;
static int hf_diameter_3gpp_mip6_feature_vector_assign_local_ip;
static int hf_diameter_3gpp_mip6_feature_vector_mip4_supported;
static int hf_diameter_3gpp_mip6_feature_vector_optimized_idle_mode_mobility;
static int hf_diameter_3gpp_mip6_feature_vector_gtpv2_supported;
static int hf_diameter_user_equipment_info_imeisv;
static int hf_diameter_user_equipment_info_mac;
static int hf_diameter_user_equipment_info_eui64;
static int hf_diameter_user_equipment_info_modified_eui64;

static int hf_diameter_result_code_cmd_level;
static int hf_diameter_result_code_mscc_level;

static int ett_diameter;
static int ett_diameter_flags;
static int ett_diameter_avp_flags;
static int ett_diameter_avpinfo;
static int ett_unknown;
static int ett_diameter_mip6_feature_vector;
static int ett_diameter_3gpp_mip6_feature_vector;

static expert_field ei_diameter_reserved_bit_set;
static expert_field ei_diameter_avp_len;
static expert_field ei_diameter_avp_no_data;
static expert_field ei_diameter_application_id;
static expert_field ei_diameter_version;
static expert_field ei_diameter_avp_pad;
static expert_field ei_diameter_avp_pad_missing;
static expert_field ei_diameter_code;
static expert_field ei_diameter_avp_code;
static expert_field ei_diameter_avp_vendor_id;
static expert_field ei_diameter_invalid_ipv6_prefix_len;
static expert_field ei_diameter_invalid_avp_len;
static expert_field ei_diameter_invalid_user_equipment_info_value_len;
static expert_field ei_diameter_unexpected_imei_as_user_equipment_info;

/* Tap for Diameter */
static int diameter_tap;

/* For conversations */

static dissector_handle_t diameter_udp_handle;
static dissector_handle_t diameter_tcp_handle;
static dissector_handle_t diameter_sctp_handle;
/* This is IANA registered for TCP and SCTP (and reserved for UDP) */
#define DEFAULT_DIAMETER_PORT_RANGE "3868"
/* This is IANA registered for TLS/TCP and DTLS/SCTP (and reserved for UDP) */
#define DEFAULT_DIAMETER_TLS_PORT 5868

/* desegmentation of Diameter over TCP */
static bool gbl_diameter_desegment = true;

/* do not use IP/Port to search conversation of Diameter */
static bool gbl_diameter_use_ip_port_for_conversation = true;

/* add Association IMSI to all messages in session */
static bool gbl_diameter_session_imsi = false;

static wmem_tree_t *diameter_conversations;

/* Relation between session -> imsi */
static wmem_map_t* diam_session_imsi;

/* Dissector tables */
static dissector_table_t diameter_dissector_table;
static dissector_table_t diameter_3gpp_avp_dissector_table;
static dissector_table_t diameter_ericsson_avp_dissector_table;
static dissector_table_t diameter_verizon_avp_dissector_table;
static dissector_table_t diameter_expr_result_vnd_table;

#define SUBSCRIPTION_ID_TYPE_E164	0
#define SUBSCRIPTION_ID_TYPE_IMSI	1
#define SUBSCRIPTION_ID_TYPE_SIP_URI	2
#define SUBSCRIPTION_ID_TYPE_NAI	3
#define SUBSCRIPTION_ID_TYPE_PRIVATE	4
#define SUBSCRIPTION_ID_TYPE_UNKNOWN (uint32_t)-1

#define USER_EQUIPMENT_INFO_TYPE_IMEISV			0
#define USER_EQUIPMENT_INFO_TYPE_MAC			1
#define USER_EQUIPMENT_INFO_TYPE_EUI64			2
#define USER_EQUIPMENT_INFO_TYPE_MODIFIED_EUI64	3
#define USER_EQUIPMENT_INFO_TYPE_UNKNOWN (uint32_t)-1

static void
export_diameter_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
	exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "diameter", EXP_PDU_TAG_DISSECTOR_NAME);

	exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
	exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
	exp_pdu_data->pdu_tvb = tvb;

	tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);

}

static int
compare_avps(const void *a, const void *b)
{
	const value_string *vsa = (const value_string *)a;
	const value_string *vsb = (const value_string *)b;

	if (vsa->value > vsb->value)
		return 1;
	if (vsa->value < vsb->value)
		return -1;

	return 0;
}

static GHashTable* diameterstat_cmd_str_hash;
#define DIAMETER_NUM_PROCEDURES     1

static void
add_group_str(packet_info *pinfo, diam_sub_dis_t *diam_sub_dis_inf, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (diam_sub_dis_inf->group_avp_str) {
		wmem_strbuf_append(diam_sub_dis_inf->group_avp_str, ", ");
	} else {
		diam_sub_dis_inf->group_avp_str = wmem_strbuf_new(pinfo->pool, "");
	}
	wmem_strbuf_append_vprintf(diam_sub_dis_inf->group_avp_str, fmt, ap);

	va_end(ap);
}

static void
diameterstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
	srt_stat_table *diameter_srt_table;
	int* idx;

    /* XXX - This is a hack/workaround support so resetting/freeing parameters at the dissector
       level doesn't need to be supported. */
	if (diameterstat_cmd_str_hash != NULL)
	{
		g_hash_table_destroy(diameterstat_cmd_str_hash);
	}

	idx = wmem_new0(wmem_epan_scope(), int);
	diameterstat_cmd_str_hash = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(diameterstat_cmd_str_hash, "Unknown", idx);

	/** @todo the filter to use instead of NULL is "diameter.cmd.code"
	 * to enable the filter popup in the service response time dialogue
	 * Note to make it work the command code must be stored rather than the
	 * index.
	 */
	diameter_srt_table = init_srt_table("Diameter Requests", NULL, srt_array, DIAMETER_NUM_PROCEDURES, NULL, NULL, NULL);
	init_srt_table_row(diameter_srt_table, 0, "Unknown");
}

static tap_packet_status
diameterstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
	unsigned i = 0;
	srt_stat_table *diameter_srt_table;
	srt_data_t *data = (srt_data_t *)pss;
	const diameter_req_ans_pair_t *diameter=(const diameter_req_ans_pair_t *)prv;
	int* idx = NULL;

	/* Process only answers where corresponding request is found.
	 * Unpaired diameter messages are currently not supported by statistics.
	 * Return 0, since redraw is not needed. */
	if(!diameter || diameter->processing_request || !diameter->req_frame)
		return TAP_PACKET_DONT_REDRAW;

	diameter_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);

	idx = (int*) g_hash_table_lookup(diameterstat_cmd_str_hash, diameter->cmd_str);
	if (idx == NULL) {
		idx = wmem_new(wmem_epan_scope(), int);
		*idx = (int) g_hash_table_size(diameterstat_cmd_str_hash);
		g_hash_table_insert(diameterstat_cmd_str_hash, (char*) diameter->cmd_str, idx);
		init_srt_table_row(diameter_srt_table, *idx,  (const char*) diameter->cmd_str);
	}

	add_srt_table_data(diameter_srt_table, *idx, &diameter->req_time, pinfo);

	return TAP_PACKET_REDRAW;
}


/* Special decoding of some AVPs */

static int
dissect_diameter_vendor_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_diameter_vendor_id, tvb, 0, 4, ENC_BIG_ENDIAN);

	offset++;
	return offset;
}

static int
dissect_diameter_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	int length = tvb_reported_length(tvb);

	if (gbl_diameter_session_imsi) {
		diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;
		diam_sub_dis->session_id = (const char *)tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_UTF_8|ENC_BIG_ENDIAN);
	}
	return length;
}

static int
dissect_diameter_eap_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	bool save_writable;

	/* Ensure the packet is displayed as Diameter, not EAP */
	save_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
	col_set_writable(pinfo->cinfo, COL_PROTOCOL, false);

	call_dissector(eap_handle, tvb, pinfo, tree);

	col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_writable);
	return tvb_reported_length(tvb);
}

static int
dissect_diameter_3gpp_crbn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	int length = tvb_reported_length(tvb);
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;

	add_group_str(pinfo, diam_sub_dis_inf, "CRBN=%s", tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_UTF_8|ENC_BIG_ENDIAN));
	return length;
}

/* https://www.3gpp2.org/Public_html/X/VSA-VSE.cfm */
static const value_string diameter_3gpp2_exp_res_vals[]= {
	{ 5001,	"Diameter_Error_User_No_WLAN_Subscription"},
	{ 5002,	"Diameter_Error_Roaming_Not_Allowed(Obsoleted)"},
	{ 5003,	"Diameter_Error_User_No_FAP_Subscription"},
	{0,NULL}
};

static int
dissect_diameter_3gpp2_exp_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_item *pi;
	diam_sub_dis_t *diam_sub_dis;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	diam_sub_dis = (diam_sub_dis_t*)data;

	if (tree) {
		pi = proto_tree_add_item(tree, hf_diameter_3gpp2_exp_res, tvb, 0, 4, ENC_BIG_ENDIAN);
		diam_sub_dis->avp_str = (char *)wmem_alloc(pinfo->pool, ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), diam_sub_dis->avp_str, NULL);
		diam_sub_dis->avp_str = strstr(diam_sub_dis->avp_str,": ")+2;
	}

	return 4;
}

static void
dissect_diameter_other_vendor_exp_res(diam_ctx_t *c, tvbuff_t *tvb, proto_tree *tree, diam_sub_dis_t *diam_sub_dis)
{
	proto_item *pi;

	if (tree) {
		pi = proto_tree_add_item(tree, hf_diameter_other_vendor_exp_res, tvb, 0, 4, ENC_BIG_ENDIAN);
		diam_sub_dis->avp_str = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), diam_sub_dis->avp_str, NULL);
		diam_sub_dis->avp_str = strstr(diam_sub_dis->avp_str,": ")+2;
	}
}

/* From RFC 3162 section 2.3 */
static int
dissect_diameter_base_framed_ipv6_prefix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;
	uint32_t prefix_len, prefix_len_bytes;
	proto_item *pi;

	proto_tree_add_item(tree, hf_framed_ipv6_prefix_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
	pi = proto_tree_add_item_ret_uint(tree, hf_framed_ipv6_prefix_length, tvb, 1, 1, ENC_BIG_ENDIAN, &prefix_len);

	if (prefix_len > 128) {
		expert_add_info(pinfo, pi, &ei_diameter_invalid_ipv6_prefix_len);
	}
	prefix_len_bytes = prefix_len / 8;
	if (prefix_len % 8)
		prefix_len_bytes++;

	proto_tree_add_item(tree, hf_framed_ipv6_prefix_bytes, tvb, 2, prefix_len_bytes, ENC_NA);

	/* If we have a fully IPv6 address, display it as such */
	if (prefix_len_bytes == 16) {
		proto_tree_add_item(tree, hf_framed_ipv6_prefix_ipv6, tvb, 2, prefix_len_bytes, ENC_NA);
	} else if (prefix_len_bytes < 16) {
		ws_in6_addr value;
		address addr;

		memset(&value.bytes, 0, sizeof(value));
		tvb_memcpy(tvb, (uint8_t *)&value.bytes, 2, prefix_len_bytes);
		value.bytes[prefix_len_bytes] = value.bytes[prefix_len_bytes] & (0xff<<(prefix_len % 8));
		proto_tree_add_ipv6(tree, hf_framed_ipv6_prefix_ipv6, tvb, 2, prefix_len_bytes, &value);
		set_address(&addr, AT_IPv6, 16, value.bytes);
		diam_sub_dis->avp_str = wmem_strdup_printf(pinfo->pool, "%s/%u", address_to_str(pinfo->pool, &addr), prefix_len);
	}

	return prefix_len_bytes+2;
}

/* AVP Code: 1 User-Name */
/* Do special decoding of the User-Name depending on the interface */
static int
dissect_diameter_user_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;
	uint32_t application_id = 0, cmd_code = 0, str_len;
	const char *imsi = NULL;

	if (diam_sub_dis) {
		application_id = diam_sub_dis->application_id;
		cmd_code = diam_sub_dis->cmd_code;
	}

	switch (application_id) {
	case DIAM_APPID_3GPP_S6A_S6D:
	case DIAM_APPID_3GPP_SLH:
	case DIAM_APPID_3GPP_S7A:
	case DIAM_APPID_3GPP_S13:
		str_len = tvb_reported_length(tvb);
		imsi = dissect_e212_utf8_imsi(tvb, pinfo, tree, 0, str_len);
		if (gbl_diameter_session_imsi && !diam_sub_dis->imsi) {
			diam_sub_dis->imsi = imsi;
		}
		return str_len;
	case DIAM_APPID_3GPP_SWX:
		if (cmd_code != 305) {
			str_len = tvb_reported_length(tvb);
			imsi = dissect_e212_utf8_imsi(tvb, pinfo, tree, 0, str_len);
			if (gbl_diameter_session_imsi && !diam_sub_dis->imsi) {
				diam_sub_dis->imsi = imsi;
			}
			return str_len;
		}
		// cmd_code 305 (Push-Profile), can be either a User Profile
		// Update (8.1.2.3), in which case User-Name is an IMSI as
		// above, or an HSS Reset Indication (8.1.2.4.1), in which
		// case User-Name is a User List containing a wild card
		// or leading digits of IMSI series.
		break;
	case DIAM_APPID_3GPP_SWM:
	case DIAM_APPID_3GPP_STA:
	case DIAM_APPID_3GPP_S6B:
		if (cmd_code == 268) {
			// 3GPP TS 29.273 - For cmd_code 268 (Diameter-EAP),
			// "The identity shall be represented in NAI form as
			// specified in IETF RFC 4282 [15] and shall be formatted
			// as defined in clause 19 of 3GPP TS 23.003 [14]. This
			// IE shall include the leading digit used to
			// differentiate between authentication schemes."
			//
			// Note that SWa uses the STa application ID, and
			// SWd uses the application ID associated with
			// the proxied command (STa here as well).
			//
			// For other command codes, the User-Name is different
			// and does *not* include the leading digit as in EAP.
			str_len = tvb_reported_length(tvb);
			dissect_eap_identity_3gpp(tvb, pinfo, tree, 0, str_len);
			return str_len;
		}
		break;
	}

	return 0;
}

/* AVP Code: 124 MIP6-Feature-Vector */
/* RFC 5447, 5779 */
/* 3GPP TS 29.273, V15.2.0 */
static int
dissect_diameter_mip6_feature_vector(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
	static int * const flags_rfc[] = {
		&hf_diameter_mip6_feature_vector_mip6_integrated,
		&hf_diameter_mip6_feature_vector_local_home_agent_assignment,
		&hf_diameter_mip6_feature_vector_pmip6_supported,
		&hf_diameter_mip6_feature_vector_ip4_hoa_supported,
		&hf_diameter_mip6_feature_vector_local_mag_routing_supported,
		NULL
	};

	static int * const flags_3gpp[] = {
	    &hf_diameter_3gpp_mip6_feature_vector_assign_local_ip,
	    &hf_diameter_3gpp_mip6_feature_vector_mip4_supported,
	    &hf_diameter_3gpp_mip6_feature_vector_optimized_idle_mode_mobility,
	    &hf_diameter_3gpp_mip6_feature_vector_gtpv2_supported,
	    NULL
	};

	uint32_t application_id = 0;
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	DISSECTOR_ASSERT(diam_sub_dis_inf);

	application_id = diam_sub_dis_inf->application_id;

	/* Hide the item created in packet-diameter.c and only show the one created here */
	proto_item_set_hidden(diam_sub_dis_inf->item);

	/* Dissect values defined in RFC 5447, 5779 */
	proto_tree_add_bitmask(tree, tvb, 0, hf_diameter_mip6_feature_vector, ett_diameter_mip6_feature_vector, flags_rfc, ENC_BIG_ENDIAN);

	switch (application_id) {
	case DIAM_APPID_3GPP_STA:
	case DIAM_APPID_3GPP_SWM:
	case DIAM_APPID_3GPP_SWX:
	case DIAM_APPID_3GPP_S6B:
		/* Dissect values defined in TGPP TS 29.273, V15.2.0 */
		proto_tree_add_bitmask(tree, tvb, 0, hf_diameter_3gpp_mip6_feature_vector, ett_diameter_3gpp_mip6_feature_vector, flags_3gpp, ENC_BIG_ENDIAN);
		break;
	}

	return 8;
}

/* AVP Code: 268 Result-Code */
static int
dissect_diameter_result_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
	proto_item *pi;
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	uint32_t result_code;

	if (!diam_sub_dis_inf->dis_gouped) {
		// Do not check length. This is done in function "unsigned32_avp"
		pi = proto_tree_add_item(tree, hf_diameter_result_code_cmd_level, tvb, 0, 4, ENC_BIG_ENDIAN);
		proto_item_set_generated(pi);
		return 4;
	}

	/* AVP: Multiple-Services-Credit-Control(456) */
	if (diam_sub_dis_inf->group_avp_code == 456) {
		// Do not check length. This is done in function "unsigned32_avp"
		pi = proto_tree_add_item(tree, hf_diameter_result_code_mscc_level, tvb, 0, 4, ENC_BIG_ENDIAN);
		proto_item_set_generated(pi);

		result_code = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
		add_group_str(pinfo, diam_sub_dis_inf, "RC=%d", result_code);

		return 4;
	}

	return 0;
}

/* AVP Code: 421 CC-Total-Octets */
static int
dissect_diameter_cc_total_octets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	uint64_t total_octets = tvb_get_uint64(tvb, 0, ENC_BIG_ENDIAN);
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	add_group_str(pinfo, diam_sub_dis_inf, "Total-Octets=%d", total_octets);

	return 16;
}

/* AVP Code: 432 Rating-Group */
static int
dissect_diameter_rating_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	uint32_t rg = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	add_group_str(pinfo, diam_sub_dis_inf, "RG=%d", rg);

	return 4;
}

/* AVP Code: 443 Subscription-Id */
static int
dissect_diameter_subscription_id(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	/* Just reset our global subscription-id-type variable */
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	diam_sub_dis_inf->subscription_id_type = SUBSCRIPTION_ID_TYPE_UNKNOWN;

	return 0;
}

/* AVP Code: 450 Subscription-Id-Type */
static int
dissect_diameter_subscription_id_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	diam_sub_dis_inf->subscription_id_type = tvb_get_ntohl(tvb, 0);

	return 0;
}

/* AVP Code: 444 Subscription-Id-Data */
static int
dissect_diameter_subscription_id_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint32_t str_len;
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	uint32_t subscription_id_type = diam_sub_dis_inf->subscription_id_type;
	const char *id_data = NULL;

	switch (subscription_id_type) {
	case SUBSCRIPTION_ID_TYPE_IMSI:
		str_len = tvb_reported_length(tvb);
		id_data = dissect_e212_utf8_imsi(tvb, pinfo, tree, 0, str_len);
		if (gbl_diameter_session_imsi && !diam_sub_dis_inf->imsi) {
			diam_sub_dis_inf->imsi = id_data;
		}
		add_group_str(pinfo, diam_sub_dis_inf, "IMSI=%s", id_data);
		return str_len;
	case SUBSCRIPTION_ID_TYPE_E164:
		str_len = tvb_reported_length(tvb);
		id_data = dissect_e164_msisdn(tvb, pinfo, tree, 0, str_len, E164_ENC_UTF8);
		add_group_str(pinfo, diam_sub_dis_inf, "MSISDN=%s", id_data);
		return str_len;
	}

	return 0;
}

/* AVP Code: 458 User-Equipment-Info */
static int
dissect_diameter_user_equipment_info(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	/* Just reset our global subscription-id-type variable */
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	diam_sub_dis_inf->user_equipment_info_type = USER_EQUIPMENT_INFO_TYPE_UNKNOWN;

	return 0;
}

/* AVP Code: 459 User-Equipment-Info-Type */
/* RFC 8506 section 8.50 */
static int
dissect_diameter_user_equipment_info_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	diam_sub_dis_inf->user_equipment_info_type = tvb_get_ntohl(tvb, 0);

	return 0;
}

/* AVP Code: 460 User-Equipment-Info-Value */
/* RFC 8506 section 8.51 */
static int
dissect_diameter_user_equipment_info_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint32_t len;
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	uint32_t user_equipment_info_type = diam_sub_dis_inf->user_equipment_info_type;

	switch (user_equipment_info_type) {
	case USER_EQUIPMENT_INFO_TYPE_IMEISV:
		/* RFC 8506 section 8.53, 3GPP TS 23.003 */
		len = tvb_reported_length(tvb);
		/* IMEISV is 16 digits, but often transmitted BCD coded in 8 octets.
		   Some implementations use IMEI (15 digits) instead of IMEISV */
		if (len == 8) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_imeisv, tvb, 0, len, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
			return len;
		} else if (len == 16) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_imeisv, tvb, 0, len, ENC_ASCII);
			return len;
		} else if (len == 15) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_imeisv, tvb, 0, len, ENC_ASCII);
			proto_tree_add_expert(tree, pinfo, &ei_diameter_unexpected_imei_as_user_equipment_info, tvb, 0, len);
			return len;
		}
		proto_tree_add_expert(tree, pinfo, &ei_diameter_invalid_user_equipment_info_value_len, tvb, 0, len);
		break;
	case USER_EQUIPMENT_INFO_TYPE_MAC:
		/* RFC 8506 section 8.54, RFC 5777 section 4.1.7.8 */
		len = tvb_reported_length(tvb);
		if (len == FT_ETHER_LEN) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_mac, tvb, 0, len, ENC_NA);
			return len;
		}
		proto_tree_add_expert(tree, pinfo, &ei_diameter_invalid_user_equipment_info_value_len, tvb, 0, len);
		break;
	case USER_EQUIPMENT_INFO_TYPE_EUI64:
		/* RFC 8506 section 8.55 */
		len = tvb_reported_length(tvb);
		if (len == FT_EUI64_LEN) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_eui64, tvb, 0, len, ENC_BIG_ENDIAN);
			return len;
		}
		proto_tree_add_expert(tree, pinfo, &ei_diameter_invalid_user_equipment_info_value_len, tvb, 0, len);
		break;
	case USER_EQUIPMENT_INFO_TYPE_MODIFIED_EUI64:
		/* RFC 8506 section 8.56, RFC 4291 */
		len = tvb_reported_length(tvb);
		if (len == FT_EUI64_LEN) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_modified_eui64, tvb, 0, len,  ENC_BIG_ENDIAN);
			return len;
		}
		proto_tree_add_expert(tree, pinfo, &ei_diameter_invalid_user_equipment_info_value_len, tvb, 0, len);
		break;
	}

	return 0;
}

/* Call subdissectors for AVPs.
 * This is a separate function to avoid having any local variables that might
 * get clobbered by the exception longjmp() (without having to declare the
 * variables as volatile and deal with casting them).
 */
static void
call_avp_subdissector(uint32_t vendorid, uint32_t code, tvbuff_t *subtvb, packet_info *pinfo, proto_tree *avp_tree, diam_sub_dis_t *diam_sub_dis_inf)
{
	TRY {
		switch (vendorid) {
		case 0:
			dissector_try_uint_with_data(diameter_dissector_table, code, subtvb, pinfo, avp_tree, false, diam_sub_dis_inf);
			break;
		case VENDOR_ERICSSON:
			dissector_try_uint_with_data(diameter_ericsson_avp_dissector_table, code, subtvb, pinfo, avp_tree, false, diam_sub_dis_inf);
			break;
		case VENDOR_VERIZON:
			dissector_try_uint_with_data(diameter_verizon_avp_dissector_table, code, subtvb, pinfo, avp_tree, false, diam_sub_dis_inf);
			break;
		case VENDOR_THE3GPP:
			dissector_try_uint_with_data(diameter_3gpp_avp_dissector_table, code, subtvb, pinfo, avp_tree, false, diam_sub_dis_inf);
			break;
		default:
			break;
		}

		/* Debug
		proto_tree_add_subtree(avp_tree, subtvb, 0, -1, "AVP %u data, Vendor Id %u ",code,vendorid);
		*/
	}
	CATCH_NONFATAL_ERRORS {
		show_exception(subtvb, pinfo, avp_tree, EXCEPT_CODE, GET_MESSAGE);
	}
	ENDTRY;
}

/* Dissect an AVP at offset */
static int
dissect_diameter_avp(diam_ctx_t *c, tvbuff_t *tvb, int offset, diam_sub_dis_t *diam_sub_dis_inf, bool update_col_info)
{
	uint32_t code           = tvb_get_ntohl(tvb,offset);
	uint32_t len            = tvb_get_ntohl(tvb,offset+4);
	uint32_t vendor_flag    = len & 0x80000000;
	uint32_t flags_bits     = (len & 0xFF000000) >> 24;
	uint32_t vendorid       = vendor_flag ? tvb_get_ntohl(tvb,offset+8) : 0 ;
	wmem_tree_key_t k[3];
	diam_avp_t *a;
	proto_item *pi, *avp_item;
	proto_tree *avp_tree, *save_tree;
	tvbuff_t *subtvb;
	diam_vnd_t *vendor;
	const char *code_str;
	const char *avp_str = NULL;
	uint8_t pad_len;

	k[0].length = 1;
	k[0].key = &code;

	k[1].length = 1;
	k[1].key = &vendorid;

	k[2].length = 0;
	k[2].key = NULL;

	a = (diam_avp_t *)wmem_tree_lookup32_array(dictionary.avps,k);

	len &= 0x00ffffff;
	pad_len = WS_PADDING_TO_4(len);

	if (!a) {
		a = &unknown_avp;

		if (vendor_flag) {
			if (! (vendor = (diam_vnd_t *)wmem_tree_lookup32(dictionary.vnds,vendorid) ))
				vendor = &unknown_vendor;
		} else {
			vendor = &no_vnd;
		}
	} else {
		vendor = (diam_vnd_t *)a->vendor;
	}

	if (vendor->vs_avps_ext == NULL) {
		wmem_array_sort(vendor->vs_avps, compare_avps);
		vendor->vs_avps_ext = value_string_ext_new(wmem_epan_scope(), VND_AVP_VS(vendor),
							   VND_AVP_VS_LEN(vendor)+1,
							   wmem_strdup_printf(wmem_epan_scope(), "diameter_vendor_%s",
									   enterprises_lookup(vendorid, "Unknown")));
#if 0
		{ /* Debug code */
			value_string *vendor_avp_vs = VALUE_STRING_EXT_VS_P(vendor->vs_avps_ext);
			int i = 0;
			while (vendor_avp_vs[i].strptr != NULL) {
				ws_warning("%u %s", vendor_avp_vs[i].value, vendor_avp_vs[i].strptr);
				i++;
			}
		}
#endif
	}
	/* Check if the length is sane */
	if (len > (uint32_t)tvb_reported_length_remaining(tvb, offset)) {
		proto_tree_add_expert_format(c->tree, c->pinfo, &ei_diameter_invalid_avp_len, tvb, offset + 4, 4,
			"Wrong AVP(%u) length %u",
			code,
			len);
		return tvb_reported_length(tvb);
	}

	/*
	 * Workaround for a MS-CHAPv2 capture from Bug 15603 that lacks padding.
	 */
	if (tvb_reported_length_remaining(tvb, offset + len) < pad_len) {
		pad_len = (uint32_t)tvb_reported_length_remaining(tvb, offset + len);
	}

	/* Add root of tree for this AVP */
	avp_item = proto_tree_add_item(c->tree, hf_diameter_avp, tvb, offset, len + pad_len, ENC_NA);
	avp_tree = proto_item_add_subtree(avp_item, a->ett);

	pi = proto_tree_add_item(avp_tree,hf_diameter_avp_code,tvb,offset,4,ENC_BIG_ENDIAN);
	code_str = val_to_str_ext_const(code, vendor->vs_avps_ext, "Unknown");
	proto_item_append_text(pi," %s", code_str);

	/* Code */
	if (a == &unknown_avp) {
		proto_tree *tu = proto_item_add_subtree(pi,ett_unknown);
		proto_tree_add_expert_format(tu, c->pinfo, &ei_diameter_avp_code, tvb, offset, 4,
			"Unknown AVP %u (vendor=%s), if you know what this is you can add it to dictionary.xml", code,
			enterprises_lookup(vendorid, "Unknown"));
	}

	offset += 4;

	proto_item_set_text(avp_item,"%s", code_str);

	if (update_col_info) {
		col_append_fstr(c->pinfo->cinfo, COL_INFO, " %s", code_str);
	}

	/* Flags */
	{
		static int * const diameter_avp_flags[] = {
			&hf_diameter_avp_flags_vendor_specific,
			&hf_diameter_avp_flags_mandatory,
			&hf_diameter_avp_flags_protected,
			&hf_diameter_avp_flags_reserved3,
			&hf_diameter_avp_flags_reserved4,
			&hf_diameter_avp_flags_reserved5,
			&hf_diameter_avp_flags_reserved6,
			&hf_diameter_avp_flags_reserved7,
			NULL
		};

		pi = proto_tree_add_bitmask_with_flags(avp_tree, tvb, offset, hf_diameter_avp_flags,
			ett_diameter_avp_flags, diameter_avp_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT);
		if (flags_bits & 0x1f) expert_add_info(c->pinfo, pi, &ei_diameter_reserved_bit_set);

	}
	offset += 1;

	/* Length */
	pi = proto_tree_add_item(avp_tree,hf_diameter_avp_len,tvb,offset,3,ENC_BIG_ENDIAN);
	if (len < (vendor_flag ? 12U : 8U)) {
		/*
		 * "[I]ncluding the AVP Code field, AVP Length field, AVP Flags
		 * field, Vendor-ID field (if present), and the AVP Data field.
		 * If a message is received with an invalid attribute length,
		 * the message MUST be rejected" - RFC 6733, 4.1 AVP Header
		 */
		expert_add_info_format(c->pinfo, pi, &ei_diameter_invalid_avp_len,
			"Invalid AVP length %u < %u",
			len, 8 + (vendor_flag?4:0));
		// Throw(ReportedBoundsError)?
		return tvb_reported_length(tvb);
	}
	offset += 3;

	/* Vendor flag */
	if (vendor_flag) {
		pi = proto_tree_add_item(avp_tree,hf_diameter_avp_vendor_id,tvb,offset,4,ENC_BIG_ENDIAN);
		if (vendor == &unknown_vendor) {
			proto_tree *tu = proto_item_add_subtree(pi,ett_unknown);
			proto_tree_add_expert(tu, c->pinfo, &ei_diameter_avp_vendor_id, tvb, offset, 4);
		}
		offset += 4;
	}

	/* Data is empty so return now */
	if ( len == (uint32_t)(vendor_flag ? 12 : 8) ) {
		/* AVP=Requested-Service-Unit(437) may be empty.
		 *
		 * RFC 4006, 8.16 (page 64):
		 * The Requested-Service-Unit AVP MAY contain the amount of requested
		 * service units or the requested monetary value.  It MUST be present in
		 * the initial interrogation and within the intermediate interrogations
		 * in which new quota is requested.
		 *
		 * Command-Code = "Credit-Control" (272)
		 * ApplicationID = "Diameter Credit Control Application" (4)
		 */
		if (!((code == 437)
		     && (diam_sub_dis_inf->cmd_code == 272)
			 && (diam_sub_dis_inf->parent_message_is_request)
			 && (diam_sub_dis_inf->application_id == 4))) {
			proto_tree_add_expert(avp_tree, c->pinfo, &ei_diameter_avp_no_data, tvb, offset, 0);
		}
		/* pad_len is always 0 in this case, but kept here for consistency */
		return len+pad_len;
	}
	/* If we are dissecting a grouped AVP and find a Vendor Id AVP(266), save it */
	if ((diam_sub_dis_inf->dis_gouped) && (!vendor_flag) && (code==266)) {
		diam_sub_dis_inf->vendor_id = tvb_get_ntohl(tvb,offset);
	}

	subtvb = tvb_new_subset_length(tvb,offset,len-(8+(vendor_flag?4:0)));
	offset += len-(8+(vendor_flag?4:0));

	save_tree = c->tree;
	c->tree = avp_tree;

	/* The Experimental-Result-Code AVP (298) comes inside the Experimental-Result
	 * grouped AVP (297).  The Vendor-ID AVP in the Experimental-Result specifies the
	 * name space of the Experimental-Result-Code.  Unfortunately we don't have a way
	 * to specify, in XML, different Experimental-Result-Code enum values for different
	 * Vendor-IDs so we choose a Vendor-ID whose values get to go in XML (we chose
	 * 3GPP) and handle other Vendor-IDs through the "diameter.vnd_exp_res" dissector
	 * table.
	 */
	if ((diam_sub_dis_inf->dis_gouped)
		&& (!vendor_flag)
		&& (code==298)
		&& (diam_sub_dis_inf->vendor_id != 0)
		&& (diam_sub_dis_inf->vendor_id != VENDOR_THE3GPP))
	{
		/* call subdissector */
		if (!dissector_try_uint_with_data(diameter_expr_result_vnd_table, diam_sub_dis_inf->vendor_id,
					    subtvb, c->pinfo, avp_tree, false, diam_sub_dis_inf)) {
			/* No subdissector for this vendor ID, use the generic one */
			dissect_diameter_other_vendor_exp_res(c, subtvb, avp_tree, diam_sub_dis_inf);
		}

		if (diam_sub_dis_inf->avp_str) {
			proto_item_append_text(avp_item, ": %s", diam_sub_dis_inf->avp_str);
		}
	} else {
		avp_str = a->dissector_rfc(c,a,subtvb, diam_sub_dis_inf);
	}
	c->tree = save_tree;

	diam_sub_dis_inf->avp_str = NULL;
	call_avp_subdissector(vendorid, code, subtvb, c->pinfo, avp_tree, diam_sub_dis_inf);

	/* Let the subdissector have precedence filling in the avp_item string */
	if (diam_sub_dis_inf->avp_str) {
		proto_item_append_text(avp_item, ": %s", diam_sub_dis_inf->avp_str);
	} else if (avp_str) {
		proto_item_append_text(avp_item, ": %s", avp_str);
	}


	if (pad_len) {
		uint8_t i;

		pi = proto_tree_add_item(avp_tree, hf_diameter_avp_pad, tvb, offset, pad_len, ENC_NA);
		for (i=0; i < pad_len; i++) {
			if (tvb_get_uint8(tvb, offset++) != 0) {
				expert_add_info(c->pinfo, pi, &ei_diameter_avp_pad);
				break;
			}
		}
	}
	if ((len + pad_len) % 4) {
		proto_tree_add_expert(avp_tree, c->pinfo, &ei_diameter_avp_pad_missing, tvb, offset, pad_len);
	}

	return len+pad_len;
}

static const char *
address_rfc_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;
	address_avp_t *t = (address_avp_t *)a->type_data;
	int len = tvb_reported_length(tvb);
	proto_item *pi = proto_tree_add_item(c->tree, a->hf_value, tvb, 0, len, ENC_BIG_ENDIAN);
	proto_tree *pt = proto_item_add_subtree(pi,t->ett);
	uint32_t addr_type;
	len = len-2;

	proto_tree_add_item_ret_uint(pt, t->hf_address_type, tvb, 0, 2, ENC_NA, &addr_type);
	/* See packet-iana-data.h and https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml */
	switch (addr_type ) {
		case AFNUM_IP:
			if (len != 4) {
				proto_tree_add_expert_format(pt, c->pinfo, &ei_diameter_avp_len, tvb, 2, len, "Wrong length for IPv4 Address: %d instead of 4", len);
				return "[Malformed]";
			}
			pi = proto_tree_add_item(pt,t->hf_ipv4,tvb,2,4,ENC_BIG_ENDIAN);
			break;
		case AFNUM_IP6:
			if (len != 16) {
				proto_tree_add_expert_format(pt, c->pinfo, &ei_diameter_avp_len, tvb, 2, len, "Wrong length for IPv6 Address: %d instead of 16", len);
				return "[Malformed]";
			}
			pi = proto_tree_add_item(pt,t->hf_ipv6,tvb,2,16,ENC_NA);
			break;
		case AFNUM_E164:
			/* It's unclear what format the e164 address would be encoded in but AVP 3GPP 2008 has
			 * ...value 8, E.164, and the address information is UTF8 encoded.
			 */
			if (tvb_ascii_isprint(tvb, 2, len)) {
				pi = proto_tree_add_item(pt, t->hf_e164_str, tvb, 2, len, ENC_ASCII | ENC_NA);
			} else {
				pi = proto_tree_add_item(pt, t->hf_other, tvb, 2, -1, ENC_BIG_ENDIAN);
			}
			break;
		default:
			pi = proto_tree_add_item(pt,t->hf_other,tvb,2,-1,ENC_BIG_ENDIAN);
			break;
	}

	if (c->tree) {
		label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
		label = strstr(label,": ")+2;
	}

	return label;
}

static const char *
proto_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf)
{
	proto_avp_t *t = (proto_avp_t *)a->type_data;

	col_set_writable(c->pinfo->cinfo, COL_PROTOCOL, false);
	col_set_writable(c->pinfo->cinfo, COL_INFO, false);

	if (!t->handle) {
		t->handle = find_dissector(t->name);
		if (!t->handle) t->handle = data_handle;
	}

	TRY {
		call_dissector_with_data(t->handle, tvb, c->pinfo, c->tree, diam_sub_dis_inf);
	}
	CATCH_NONFATAL_ERRORS {
		show_exception(tvb, c->pinfo, c->tree, EXCEPT_CODE, GET_MESSAGE);
	}
	ENDTRY;

	return "";
}

static const char *
time_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	int len = tvb_reported_length(tvb);
	char *label = NULL;
	proto_item *pi;

	if ( len != 4 ) {
		proto_tree_add_expert_format(c->tree, c->pinfo, &ei_diameter_avp_len, tvb, 0, 4,
				"Bad Timestamp Length: %d instead of 4", len);
		return "[Malformed]";
	}

	if (c->tree) {
		label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
		pi = proto_tree_add_item(c->tree, (a->hf_value), tvb, 0, 4, ENC_TIME_SECS_NTP|ENC_BIG_ENDIAN);
		proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
		label = strstr(label,": ")+2;
	}

	return label;
}

static const char *
address_radius_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;

	address_avp_t *t = (address_avp_t *)a->type_data;
	proto_item *pi = proto_tree_add_item(c->tree,a->hf_value,tvb,0,tvb_reported_length(tvb),ENC_BIG_ENDIAN);
	proto_tree *pt = proto_item_add_subtree(pi,t->ett);
	uint32_t len = tvb_reported_length(tvb);

	switch (len) {
		case 4:
			pi = proto_tree_add_item(pt,t->hf_ipv4,tvb,0,4,ENC_BIG_ENDIAN);
			break;
		case 16:
			pi = proto_tree_add_item(pt,t->hf_ipv6,tvb,0,16,ENC_NA);
			break;
		default:
			pi = proto_tree_add_item(pt,t->hf_other,tvb,0,len,ENC_BIG_ENDIAN);
			expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
					"Bad Address Length (%u)", len);

			break;
	}

	if (c->tree) {
		label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
		label = strstr(label,": ")+2;
	}

	return label;
}

static const char *
simple_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;

	if (c->tree) {
		proto_item *pi = proto_tree_add_item(c->tree,a->hf_value,tvb,0,tvb_reported_length(tvb),ENC_BIG_ENDIAN);
		label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
		label = strstr(label,": ")+2;
	}

	return label;
}

static const char *
utf8_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;

	if (c->tree) {
		proto_item *pi = proto_tree_add_item(c->tree,a->hf_value,tvb,0,tvb_reported_length(tvb),ENC_UTF_8|ENC_BIG_ENDIAN);
		label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
		label = strstr(label,": ")+2;
	}

	return label;
}

static const char *
integer32_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;
	proto_item *pi;

	/* Verify length before adding */
	int length = tvb_reported_length(tvb);
	if (length == 4) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
			label = strstr(label,": ")+2;
		}
	}
	else {
		pi = proto_tree_add_bytes_format(c->tree, hf_diameter_avp_data_wrong_length,
						 tvb, 0, length, NULL,
						"Error!  Bad Integer32 Length");
		expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
					"Bad Integer32 Length (%u)", length);
		proto_item_set_generated(pi);
	}

	return label;
}

static const char *
integer64_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;
	proto_item *pi;

	/* Verify length before adding */
	int length = tvb_reported_length(tvb);
	if (length == 8) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
			label = strstr(label,": ")+2;
		}
	}
	else {
		pi = proto_tree_add_bytes_format(c->tree, hf_diameter_avp_data_wrong_length,
						 tvb, 0, length, NULL,
						"Error!  Bad Integer64 Length");
		expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
				"Bad Integer64 Length (%u)", length);
		proto_item_set_generated(pi);
	}

	return label;
}

static const char *
unsigned32_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf)
{
	char *label = NULL;
	proto_item *pi;

	/* Verify length before adding */
	int length = tvb_reported_length(tvb);
	if (length == 4) {
		if (c->tree) {
			diam_sub_dis_inf->item = pi = proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
			label = strstr(label,": ")+2;
		}
	}
	else {
		pi = proto_tree_add_bytes_format(c->tree, hf_diameter_avp_data_wrong_length,
						 tvb, 0, length, NULL,
						"Error!  Bad Unsigned32 Length");
		expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
					"Bad Unsigned32 Length (%u)", length);
		proto_item_set_generated(pi);
	}

	return label;
}

static const char *
unsigned64_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;
	proto_item *pi;

	/* Verify length before adding */
	int length = tvb_reported_length(tvb);
	if (length == 8) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
			label = strstr(label,": ")+2;
		}
	}
	else {
		pi = proto_tree_add_bytes_format(c->tree, hf_diameter_avp_data_wrong_length,
						 tvb, 0, length, NULL,
						"Error!  Bad Unsigned64 Length");
		expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
				"Bad Unsigned64 Length (%u)", length);
		proto_item_set_generated(pi);
	}

	return label;
}

static const char *
float32_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;
	proto_item *pi;

	/* Verify length before adding */
	int length = tvb_reported_length(tvb);
	if (length == 4) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree,a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
			label = strstr(label,": ")+2;
		}
	}
	else {
		pi = proto_tree_add_bytes_format(c->tree, hf_diameter_avp_data_wrong_length,
						 tvb, 0, length, NULL,
						"Error!  Bad Float32 Length");
		expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
				"Bad Float32 Length (%u)", length);
		proto_item_set_generated(pi);
	}

	return label;
}

static const char *
float64_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf _U_)
{
	char *label = NULL;
	proto_item *pi;

	/* Verify length before adding */
	int length = tvb_reported_length(tvb);
	if (length == 8) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(c->pinfo->pool, ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label, NULL);
			label = strstr(label,": ")+2;
		}
	}
	else {
		pi = proto_tree_add_bytes_format(c->tree, hf_diameter_avp_data_wrong_length,
						 tvb, 0, length, NULL,
						"Error!  Bad Float64 Length");
		expert_add_info_format(c->pinfo, pi, &ei_diameter_avp_len,
				"Bad Float64 Length (%u)", length);
		proto_item_set_generated(pi);
	}

	return label;
}

static const char *
grouped_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf)
{
	int offset = 0;
	int len = tvb_reported_length(tvb);
	wmem_strbuf_t *group_avp_str = NULL;
	const char *group_avp_str_char = NULL;
	proto_item *pi = proto_tree_add_item(c->tree, a->hf_value, tvb , 0 , -1, ENC_BIG_ENDIAN);
	proto_item_set_generated(pi);

	/* Set the flag that we are dissecting a grouped AVP */
	diam_sub_dis_inf->dis_gouped = true;
	diam_sub_dis_inf->group_avp_code = a->code;

	group_avp_str = diam_sub_dis_inf->group_avp_str;
	diam_sub_dis_inf->group_avp_str = NULL;

	while (offset < len) {
		offset += dissect_diameter_avp(c, tvb, offset, diam_sub_dis_inf, false);
	}
	/* Clear info collected in grouped AVP */
	diam_sub_dis_inf->vendor_id  = 0;
	diam_sub_dis_inf->dis_gouped = false;
	diam_sub_dis_inf->group_avp_code = 0;
	diam_sub_dis_inf->avp_str = NULL;

	if (diam_sub_dis_inf->group_avp_str) {
		group_avp_str_char = wmem_strbuf_get_str(diam_sub_dis_inf->group_avp_str);
	}
	diam_sub_dis_inf->group_avp_str = group_avp_str;

	return group_avp_str_char;
}

static int * const diameter_flags_fields[] = {
	&hf_diameter_flags_request,
	&hf_diameter_flags_proxyable,
	&hf_diameter_flags_error,
	&hf_diameter_flags_T,
	&hf_diameter_flags_reserved4,
	&hf_diameter_flags_reserved5,
	&hf_diameter_flags_reserved6,
	&hf_diameter_flags_reserved7,
	NULL
};

static int
dissect_diameter_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint32_t version;
	uint64_t flags_bits;
	uint32_t packet_len;
	proto_item *pi, *cmd_item, *app_item, *version_item;
	proto_tree *diam_tree;
	diam_ctx_t *c = wmem_new0(pinfo->pool, diam_ctx_t);
	int offset;
	const char *cmd_str;
	uint32_t cmd;
	uint32_t hop_by_hop_id, end_to_end_id;
	conversation_t *conversation;
	diameter_conv_info_t *diameter_conv_info;
	diameter_req_ans_pair_t *diameter_pair = NULL;
	wmem_tree_t *pdus_tree;
	wmem_tree_key_t key[3];
	proto_item *it;
	nstime_t ns;
	diam_sub_dis_t *diam_sub_dis_inf = wmem_new0(pinfo->pool, diam_sub_dis_t);

	/* Set default value Subscription-Id-Type and User-Equipment-Info-Type as XXX_UNKNOWN */
	diam_sub_dis_inf->subscription_id_type = SUBSCRIPTION_ID_TYPE_UNKNOWN;
	diam_sub_dis_inf->user_equipment_info_type = USER_EQUIPMENT_INFO_TYPE_UNKNOWN;

	/* Load header fields if not already done */
	if (hf_diameter_code <= 0)
		proto_registrar_get_byname("diameter.code");
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DIAMETER");


	if (have_tap_listener(exported_pdu_tap)){
		export_diameter_pdu(pinfo,tvb);
	}

	pi = proto_tree_add_item(tree,proto_diameter,tvb,0,-1,ENC_NA);
	diam_tree = proto_item_add_subtree(pi,ett_diameter);

	c->tree = diam_tree;
	c->pinfo = pinfo;

	version_item = proto_tree_add_item_ret_uint(diam_tree, hf_diameter_version, tvb, 0, 1, ENC_BIG_ENDIAN, &version);
	if (version != DIAMETER_RFC) {
		expert_add_info(c->pinfo, version_item, &ei_diameter_version);
	}
	proto_tree_add_item_ret_uint(diam_tree, hf_diameter_length, tvb, 1, 3, ENC_BIG_ENDIAN, &packet_len);

	pi = proto_tree_add_bitmask_ret_uint64(diam_tree, tvb, 4, hf_diameter_flags, ett_diameter_flags, diameter_flags_fields, ENC_BIG_ENDIAN, &flags_bits);
	if (flags_bits & 0x0f) {
		expert_add_info(c->pinfo, pi, &ei_diameter_reserved_bit_set);
	}

	diam_sub_dis_inf->parent_message_is_request = (flags_bits & DIAM_FLAGS_R) ? true : false;

	cmd_item = proto_tree_add_item_ret_uint(diam_tree, hf_diameter_code, tvb, 5, 3, ENC_BIG_ENDIAN, &cmd);
	diam_sub_dis_inf->cmd_code = cmd;

	app_item = proto_tree_add_item_ret_uint(diam_tree, hf_diameter_application_id, tvb, 8, 4,
		ENC_BIG_ENDIAN, &diam_sub_dis_inf->application_id);

	if (try_val_to_str_ext(diam_sub_dis_inf->application_id, dictionary.applications) == NULL) {
		proto_tree *tu = proto_item_add_subtree(app_item,ett_unknown);
		proto_tree_add_expert_format(tu, c->pinfo, &ei_diameter_application_id, tvb, 8, 4,
			"Unknown Application Id (%u), if you know what this is you can add it to dictionary.xml", diam_sub_dis_inf->application_id);
	}

	cmd_str = val_to_str_const(cmd, cmd_vs, "Unknown");
	if (strcmp(cmd_str, "Unknown") == 0) {
		expert_add_info(c->pinfo, cmd_item, &ei_diameter_code);
	}


	proto_tree_add_item_ret_uint(diam_tree, hf_diameter_hopbyhopid, tvb, 12, 4, ENC_BIG_ENDIAN, &hop_by_hop_id);
	proto_tree_add_item_ret_uint(diam_tree, hf_diameter_endtoendid, tvb, 16, 4, ENC_BIG_ENDIAN, &end_to_end_id);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s", cmd_str, ((flags_bits>>4)&0x08) ? " Request" : " Answer");
	col_append_str(pinfo->cinfo, COL_INFO, " | ");
	col_set_fence(pinfo->cinfo, COL_INFO);


	/* Conversation tracking stuff */
	if (!gbl_diameter_use_ip_port_for_conversation) {
		pdus_tree = diameter_conversations;
	} else {
		conversation = find_or_create_conversation(pinfo);

		diameter_conv_info = (diameter_conv_info_t *)conversation_get_proto_data(conversation, proto_diameter);
		if (!diameter_conv_info) {
			diameter_conv_info = wmem_new(wmem_file_scope(), diameter_conv_info_t);
			diameter_conv_info->pdus_tree = wmem_tree_new(wmem_file_scope());

			conversation_add_proto_data(conversation, proto_diameter, diameter_conv_info);
		}

		pdus_tree = diameter_conv_info->pdus_tree;
	}

	key[0].length = 1;
	key[0].key = &hop_by_hop_id;
	key[1].length = 1;
	key[1].key = &end_to_end_id;
	key[2].length = 0;
	key[2].key = NULL;

	if (!pinfo->fd->visited) {
		if (flags_bits & DIAM_FLAGS_R) {
			/* This is a request */
			diameter_pair = wmem_new(wmem_file_scope(), diameter_req_ans_pair_t);
			diameter_pair->hop_by_hop_id = hop_by_hop_id;
			diameter_pair->end_to_end_id = end_to_end_id;
			diameter_pair->cmd_code = cmd;
			diameter_pair->result_code = 0;
			diameter_pair->cmd_str = cmd_str;
			diameter_pair->req_frame = pinfo->num;
			diameter_pair->ans_frame = 0;
			diameter_pair->req_time = pinfo->abs_ts;
			wmem_tree_insert32_array(pdus_tree, key, (void *)diameter_pair);
		} else {
			/* This is a answer */
			diameter_pair = (diameter_req_ans_pair_t *)wmem_tree_lookup32_array(pdus_tree, key);

			/* Request should be earlier in the trace than this answer. */
			if (diameter_pair && !diameter_pair->ans_frame && diameter_pair->req_frame < pinfo->num) {
				diameter_pair->ans_frame = pinfo->num;
			}
		}
	} else {
		diameter_pair = (diameter_req_ans_pair_t *)wmem_tree_lookup32_array(pdus_tree, key);
	}

	if (!diameter_pair) {
		/* create a "fake" diameter_pair structure */
		diameter_pair = wmem_new(pinfo->pool, diameter_req_ans_pair_t);
		diameter_pair->hop_by_hop_id = hop_by_hop_id;
		diameter_pair->cmd_code = cmd;
		diameter_pair->result_code = 0;
		diameter_pair->cmd_str = cmd_str;
		diameter_pair->req_frame = 0;
		diameter_pair->ans_frame = 0;
		diameter_pair->req_time = pinfo->abs_ts;
	}
	diameter_pair->processing_request=(flags_bits & DIAM_FLAGS_R)!= 0;

	/* print state tracking info in the tree */
	if (flags_bits & DIAM_FLAGS_R) {
		/* This is a request */
		if (diameter_pair->ans_frame) {
			it = proto_tree_add_uint(diam_tree, hf_diameter_answer_in,
					tvb, 0, 0, diameter_pair->ans_frame);
			proto_item_set_generated(it);
		}
	} else {
		/* This is an answer */
		if (diameter_pair->req_frame) {
			it = proto_tree_add_uint(diam_tree, hf_diameter_answer_to,
					tvb, 0, 0, diameter_pair->req_frame);
			proto_item_set_generated(it);

			nstime_delta(&ns, &pinfo->abs_ts, &diameter_pair->req_time);
			diameter_pair->srt_time = ns;
			it = proto_tree_add_time(diam_tree, hf_diameter_answer_time, tvb, 0, 0, &ns);
			proto_item_set_generated(it);
			/* TODO: Populate result_code in tap record from AVP 268 */
		}
	}

	offset = 20;

	/* Dissect AVPs until the end of the packet is reached */
	while (offset < (int)packet_len) {
		offset += dissect_diameter_avp(c, tvb, offset, diam_sub_dis_inf, false);
	}

	if (gbl_diameter_session_imsi) {
		if (diam_sub_dis_inf->session_id && !wmem_map_contains(diam_session_imsi, diam_sub_dis_inf->session_id) && diam_sub_dis_inf->imsi) {
			wmem_map_insert(diam_session_imsi,
					wmem_strdup(wmem_file_scope(), diam_sub_dis_inf->session_id),
					wmem_strdup(wmem_file_scope(), diam_sub_dis_inf->imsi));
		}
		if (diam_sub_dis_inf->session_id) {
			char *imsi = (char *)wmem_map_lookup(diam_session_imsi, diam_sub_dis_inf->session_id);
			if (imsi) {
				add_assoc_imsi_item(tvb, diam_tree, imsi);
			}
		}
	}

	/* Handle requests for which no answers were found and
	 * answers for which no requests were found in the tap listener.
	 * In case if you don't need unpaired requests/answers use:
	 * if (diameter_pair->processing_request || !diameter_pair->req_frame)
	 *   return;
	 */
	tap_queue_packet(diameter_tap, pinfo, diameter_pair);

	return tvb_reported_length(tvb);
}

static unsigned
get_diameter_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
	/* Get the length of the Diameter packet. */
	return tvb_get_ntoh24(tvb, offset + 1);
}

#define NOT_DIAMETER	0
#define IS_DIAMETER	1
#define NOT_ENOUGH_DATA 2
static int
check_diameter(tvbuff_t *tvb)
{
	uint8_t flags;
	uint32_t msg_len;

	/* Ensure we don't throw an exception trying to do these heuristics */
	if (tvb_captured_length(tvb) < 5)
		return NOT_ENOUGH_DATA;

	/* Check if the Diameter version is 1 */
	if (tvb_get_uint8(tvb, 0) != 1)
		return NOT_DIAMETER;

	/* Diameter minimum message length:
	 *
	 * Version+Length - 4 bytes
	 * Flags+CC - 4 bytes
	 * AppID - 4 bytes
	 * HbH - 4 bytes
	 * E2E - 4 bytes
	 * 2 AVPs (Orig-Host, Orig-Realm), each including:
	 *  * AVP code - 4 bytes
	 *  * AVP flags + length - 4 bytes
	 *  * (no data - what would a reasonable minimum be?)
	 *
	 * --> 36 bytes
	 */
        msg_len = tvb_get_ntoh24(tvb, 1);
	/* Diameter message length field must be a multiple of 4.
         * This is implicit in RFC 3588 (based on the header and that each
         * AVP must align on a 32-bit boundary) and explicit in RFC 6733.
         */
	if ((msg_len < 36) || (msg_len & 0x3))
		return NOT_DIAMETER;

	flags = tvb_get_uint8(tvb, 4);

	/* Check if any of the Reserved flag bits are set */
	if (flags & 0x0f)
		return NOT_DIAMETER;

	/* Check if both the R- and E-bits are set */
	if ((flags & DIAM_FLAGS_R) && (flags & DIAM_FLAGS_E))
		return NOT_DIAMETER;

	return IS_DIAMETER;
}

/*****************************************************************/
/* Main dissection function                                      */
/* Checks if the message looks like Diameter before accepting it */
/*****************************************************************/
static int
dissect_diameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (check_diameter(tvb) != IS_DIAMETER)
		return 0;
	return dissect_diameter_common(tvb, pinfo, tree, data);
}

static int
dissect_diameter_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int is_diam = check_diameter(tvb);

	if (is_diam == NOT_DIAMETER) {
		/* We've probably been given a frame that's not the start of
		 * a PDU.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DIAMETER");
		col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
		call_dissector(data_handle, tvb, pinfo, tree);
	} else if (is_diam == NOT_ENOUGH_DATA) {
		/* Since we're doing our heuristic checks before
		 * tcp_dissect_pdus() (since we can't do heuristics once
		 * we're in there) we sometimes have to ask for more data...
		 */
                pinfo->desegment_offset = 0;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
	} else {
		tcp_dissect_pdus(tvb, pinfo, tree, gbl_diameter_desegment, 4,
				 get_diameter_pdu_len, dissect_diameter_common, data);
	}

	return tvb_reported_length(tvb);
}

static bool
dissect_diameter_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (check_diameter(tvb) != IS_DIAMETER) {
		return false;
	}

	conversation_set_dissector(find_or_create_conversation(pinfo), diameter_tcp_handle);

	tcp_dissect_pdus(tvb, pinfo, tree, gbl_diameter_desegment, 4,
			 get_diameter_pdu_len, dissect_diameter_common, data);

	return true;
}

static int
dissect_diameter_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *pi;
	proto_tree *diam_tree;
	int offset = 0;
	diam_ctx_t *c = wmem_new0(pinfo->pool, diam_ctx_t);
	diam_sub_dis_t *diam_sub_dis_inf = wmem_new0(pinfo->pool, diam_sub_dis_t);

	/* Load header fields if not already done */
	if (hf_diameter_code <= 0)
		proto_registrar_get_byname("diameter.code");

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DIAMETER");
	col_set_str(pinfo->cinfo, COL_INFO, "AVPs:");

	pi = proto_tree_add_item(tree, proto_diameter, tvb, 0, -1, ENC_NA);
	diam_tree = proto_item_add_subtree(pi, ett_diameter);
	c->tree = diam_tree;
	c->pinfo = pinfo;

	/* Dissect AVPs until the end of the packet is reached */
	while (tvb_reported_length_remaining(tvb, offset)) {
		offset += dissect_diameter_avp(c, tvb, offset, diam_sub_dis_inf, true);
	}
	return tvb_reported_length(tvb);
}

/*******************************************************************************************************************
 *
 * START OF DIAMETER XML DATA DICTIONARY PROCESSSING
 *
 * This turns XML data files into (dynamic) hf and ett fields for use by the dissector
 *
 *******************************************************************************************************************/

static char *
alnumerize(char *name)
{
	char *r = name;
	char *w = name;
	char c;

	for (;(c = *r); r++) {
		if (g_ascii_isalnum(c) || c == '_' || c == '-' || c == '.') {
			*(w++) = c;
		}
	}

	*w = '\0';

	return name;
}


static unsigned
reginfo(int *hf_ptr, const char *name, const char *abbr, const char *desc,
	enum ftenum ft, field_display_e base, value_string_ext *vs_ext,
	uint32_t mask, wmem_array_t* hf_array)
{
	hf_register_info hf;

	hf.p_id					= hf_ptr;
	hf.hfinfo.name				= name;
	hf.hfinfo.abbrev			= abbr;
	hf.hfinfo.type				= ft;
	hf.hfinfo.display			= base;
	hf.hfinfo.strings			= NULL;
	hf.hfinfo.bitmask			= mask;
	hf.hfinfo.blurb				= desc;
	/* HFILL */
	HFILL_INIT(hf);

	if (vs_ext) {
		hf.hfinfo.strings = vs_ext;
	}

	wmem_array_append_one(hf_array,hf);
	return wmem_array_get_count(hf_array);
}

static void
basic_avp_reginfo(diam_avp_t *a, const char *name, enum ftenum ft,
		  field_display_e base, value_string_ext *vs_ext, wmem_array_t* hf_array, GPtrArray* ett_array)
{
	hf_register_info hf;
	int *ettp = &(a->ett);

	hf.p_id					= &(a->hf_value);
	hf.hfinfo.name				= NULL;
	hf.hfinfo.abbrev			= NULL;
	hf.hfinfo.type				= ft;
	hf.hfinfo.display			= base;
	hf.hfinfo.strings			= NULL;
	hf.hfinfo.bitmask			= 0x0;
	hf.hfinfo.blurb				= a->vendor->code ?
						    wmem_strdup_printf(wmem_epan_scope(), "vendor=%d code=%d", a->vendor->code, a->code)
						  : wmem_strdup_printf(wmem_epan_scope(), "code=%d", a->code);
	/* HFILL */
	HFILL_INIT(hf);

	hf.hfinfo.name = wmem_strdup(wmem_epan_scope(), name);
	hf.hfinfo.abbrev = alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, NULL));
	if (vs_ext) {
		hf.hfinfo.strings = vs_ext;
	}

	wmem_array_append(hf_array,&hf,1);
	g_ptr_array_add(ett_array,ettp);
}

static diam_avp_t *
build_gen_address_avp(diam_avp_t *a, address_avp_t *t, const char *name, wmem_array_t* hf_array, GPtrArray* ett_array)
{
	int *ettp = &(t->ett);

	a->ett = -1;
	a->hf_value = -1;
	a->type_data = t;

	t->ett = -1;
	t->hf_address_type = -1;
	t->hf_ipv4 = -1;
	t->hf_ipv6 = -1;
	t->hf_e164_str = -1;
	t->hf_other = -1;

	basic_avp_reginfo(a, name, FT_BYTES, BASE_NONE, NULL, hf_array, ett_array);

	reginfo(&(t->hf_address_type), wmem_strconcat(wmem_epan_scope(), name, " Address Family", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".addr_family", NULL)),
		NULL, FT_UINT16, (field_display_e)(BASE_DEC|BASE_EXT_STRING), &diameter_avp_data_addrfamily_vals_ext, 0, hf_array);

	reginfo(&(t->hf_ipv4), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".IPv4", NULL)),
		NULL, FT_IPv4, BASE_NONE, NULL, 0, hf_array);

	reginfo(&(t->hf_ipv6), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".IPv6", NULL)),
		NULL, FT_IPv6, BASE_NONE, NULL, 0, hf_array);

	reginfo(&(t->hf_e164_str), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".E164", NULL)),
		NULL, FT_STRING, BASE_NONE, NULL, 0, hf_array);

	reginfo(&(t->hf_other), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".Bytes", NULL)),
		NULL, FT_BYTES, BASE_NONE, NULL, 0, hf_array);

	g_ptr_array_add(ett_array, ettp);

	return a;
}

/*
 * RFC 6733 says:
 * > AVP numbers 1 through 255 are reserved for reuse of RADIUS attributes,
 * > without setting the Vendor-Id field.
 *
 * This clearly applies not to vendor dictionaries. However, some vendors seem to have
 * translated their RADIUS dictionaries to Diameter with that assumption in mind, while
 * others have not.
 *
 * To make this work universally, the type `ipaddress` is assumed to be using the RADIUS
 * encoding for AVP < 256 and Diameter for AVPs >= 256, while the `address` type will
 * use Diameter encoding for all AVPs
 */
static diam_avp_t *
build_ipaddress_avp(avp_constructor_data_t* constructor_data)
{
	diam_avp_t *a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	address_avp_t *t = wmem_new(wmem_epan_scope(), address_avp_t);

	a->code = constructor_data->code;
	a->vendor = constructor_data->vendor;
/*
 * It seems like the radius AVPs 1-255 will use the defs from RADIUS in which case:
 * https://tools.ietf.org/html/rfc2685
 * Address
 *    The Address field is four octets.  The value 0xFFFFFFFF indicates
 *    that the NAS Should allow the user to select an address (e.g.
 *    Negotiated).  The value 0xFFFFFFFE indicates that the NAS should
 *    select an address for the user (e.g. Assigned from a pool of
 *    addresses kept by the NAS).  Other valid values indicate that the
 *    NAS should use that value as the user's IP address.
 *
 * Where as in Diameter:
 * RFC3588
 * Address
 *    The Address format is derived from the OctetString AVP Base
 *    Format.  It is a discriminated union, representing, for example a
 *    32-bit (IPv4) [IPV4] or 128-bit (IPv6) [IPV6] address, most
 *    significant octet first.  The first two octets of the Address
 *    AVP represents the AddressType, which contains an Address Family
 *    defined in [IANAADFAM].  The AddressType is used to discriminate
 *    the content and format of the remaining octets.
 */
	if (constructor_data->code<256) {
		a->dissector_rfc = address_radius_avp;
	} else {
		a->dissector_rfc = address_rfc_avp;
	}
	return build_gen_address_avp(a, t, constructor_data->name, constructor_data->hf_array, constructor_data->ett_array);
}

static diam_avp_t *
build_address_avp(avp_constructor_data_t* constructor_data)
{
	diam_avp_t *a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	address_avp_t *t = wmem_new(wmem_epan_scope(), address_avp_t);

	a->code = constructor_data->code;
	a->vendor = constructor_data->vendor;
	a->dissector_rfc = address_rfc_avp;

	return build_gen_address_avp(a, t, constructor_data->name, constructor_data->hf_array, constructor_data->ett_array);
}

static diam_avp_t *
build_proto_avp(avp_constructor_data_t* constructor_data)
{
	diam_avp_t *a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	proto_avp_t *t = wmem_new0(wmem_epan_scope(), proto_avp_t);
	int *ettp = &(a->ett);

	a->code = constructor_data->code;
	a->vendor = constructor_data->vendor;
	a->dissector_rfc = proto_avp;
	a->ett = -1;
	a->hf_value = -2;
	a->type_data = t;

	t->name = (char *)constructor_data->data;
	t->handle = NULL;
	t->reassemble_mode = REASSEMBLE_NEVER;

	g_ptr_array_add(constructor_data->ett_array, ettp);

	return a;
}

static diam_avp_t *
build_simple_avp(avp_constructor_data_t* constructor_data)
{
	diam_avp_t *a;
	value_string_ext *vs_ext = NULL;
	field_display_e base;
	unsigned i = 0;

	/*
	 * Only 32-bit or shorter integral types can have a list of values.
	 */
	base = (field_display_e)constructor_data->type->base;
	if (constructor_data->vs != NULL) {
		switch (constructor_data->type->ft) {

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT32:
			break;

		default:
			report_failure("Diameter Dictionary: AVP '%s' has a list of values but isn't of a 32-bit or shorter integral type (%s)\n",
				constructor_data->name, ftype_name(constructor_data->type->ft));
			return NULL;
		}
		while (constructor_data->vs[i].strptr) {
		  i++;
		}
		vs_ext = value_string_ext_new(wmem_epan_scope(), constructor_data->vs, i+1, wmem_strconcat(wmem_epan_scope(), constructor_data->name, "_vals_ext", NULL));
		base = (field_display_e)(base|BASE_EXT_STRING);
	}

	a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	a->code = constructor_data->code;
	a->vendor = constructor_data->vendor;
	a->dissector_rfc = constructor_data->type->rfc;
	a->ett = -1;
	a->hf_value = -1;

	basic_avp_reginfo(a, constructor_data->name, constructor_data->type->ft, base, vs_ext, constructor_data->hf_array, constructor_data->ett_array);

	return a;
}

static diam_avp_t *
build_appid_avp(avp_constructor_data_t* constructor_data)
{
	diam_avp_t *a;
	field_display_e base;

	a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	a->code = constructor_data->code;
	a->vendor = constructor_data->vendor;
	a->dissector_rfc = constructor_data->type->rfc;
	a->ett = -1;
	a->hf_value = -1;

	if (constructor_data->vs != NULL) {
		report_failure("Diameter Dictionary: AVP '%s' (of type AppId) has a list of values but the list won't be used\n",
			constructor_data->name);
	}

	base = (field_display_e)(constructor_data->type->base|BASE_EXT_STRING);

	basic_avp_reginfo(a, constructor_data->name, constructor_data->type->ft, base, dictionary.applications, constructor_data->hf_array, constructor_data->ett_array);
	return a;
}

static const avp_type_t basic_types[] = {
	{"octetstring"			, simple_avp		, FT_BYTES			, BASE_NONE			, build_simple_avp  },
	{"octetstringorutf8"	, simple_avp		, FT_BYTES			, BASE_SHOW_ASCII_PRINTABLE	, build_simple_avp  },
	{"utf8string"			, utf8_avp			, FT_STRING			, BASE_NONE			, build_simple_avp  },
	{"grouped"				, grouped_avp		, FT_BYTES			, BASE_NO_DISPLAY_VALUE			, build_simple_avp  },
	{"integer32"			, integer32_avp		, FT_INT32			, BASE_DEC			, build_simple_avp  },
	{"unsigned32"			, unsigned32_avp	, FT_UINT32			, BASE_DEC			, build_simple_avp  },
	{"integer64"			, integer64_avp		, FT_INT64			, BASE_DEC			, build_simple_avp  },
	{"unsigned64"			, unsigned64_avp	, FT_UINT64			, BASE_DEC			, build_simple_avp  },
	{"float32"				, float32_avp		, FT_FLOAT			, BASE_NONE			, build_simple_avp  },
	{"float64"				, float64_avp		, FT_DOUBLE			, BASE_NONE			, build_simple_avp  },
	{"ipaddress"			, NULL				, FT_NONE			, BASE_NONE			, build_ipaddress_avp },
	{"address"			, NULL				, FT_NONE			, BASE_NONE			, build_address_avp },
	{"diameteruri"			, utf8_avp			, FT_STRING			, BASE_NONE			, build_simple_avp  },
	{"diameteridentity"		, utf8_avp			, FT_STRING			, BASE_NONE			, build_simple_avp  },
	{"ipfilterrule"			, utf8_avp			, FT_STRING			, BASE_NONE			, build_simple_avp  },
	{"qosfilterrule"		, utf8_avp			, FT_STRING			, BASE_NONE			, build_simple_avp  },
	{"time"					, time_avp			, FT_ABSOLUTE_TIME	, ABSOLUTE_TIME_UTC	, build_simple_avp  },
	{"AppId"				, simple_avp		, FT_UINT32			, BASE_DEC			, build_appid_avp   },
	{NULL, NULL, FT_NONE, BASE_NONE, NULL }
};



/*
 * This is like g_str_hash() (as of GLib 2.4.8), but it maps all
 * upper-case ASCII characters to their ASCII lower-case equivalents.
 * We can't use g_strdown(), as that doesn't do an ASCII mapping;
 * in Turkish locales, for example, there are two lower-case "i"s
 * and two upper-case "I"s, with and without dots - the ones with
 * dots map between each other, as do the ones without dots, so "I"
 * doesn't map to "i".
 */
static unsigned
strcase_hash(const void *key)
{
	const char *p = (const char *)key;
	unsigned h = *p;
	char c;

	if (h) {
		if (h >= 'A' && h <= 'Z')
			h = h - 'A' + 'a';
		for (p += 1; *p != '\0'; p++) {
			c = *p;
			if (c >= 'A' && c <= 'Z')
				c = c - 'A' + 'a';
			h = (h << 5) - h + c;
		}
	}

	return h;
}

/*
 * Again, use g_ascii_strcasecmp(), not strcasecmp(), so that only ASCII
 * letters are mapped, and they're mapped to the lower-case ASCII
 * equivalents.
 */
static gboolean
strcase_equal(const void *ka, const void *kb)
{
	const char *a = (const char *)ka;
	const char *b = (const char *)kb;
	return g_ascii_strcasecmp(a,b) == 0;
}


/*******************************************************************************************************************
 *
 * START STRUCTURES FOR LIBXML2 PARSING
 *
 * Structures used created by the XML processing data from/using the libxml2 API\
 * Also includes "helper" functions for populating, cleaning and printing those structures
 *
 *******************************************************************************************************************/

typedef struct ddict_application
{
	xmlChar* name;
	unsigned code;

} ddict_application_t;

static void
ddictionary_clean_application(void* data, void* user_data _U_)
{
	ddict_application_t* a = (ddict_application_t*)data;
	xmlFree(a->name);
	g_free(a);
}

static void
ddictionary_populate_application(void* data, void* user_data)
{
	ddict_application_t* a = (ddict_application_t*)data;
	wmem_array_t* arr = (wmem_array_t*)user_data;
	value_string item;

	item.value = a->code;
	item.strptr = wmem_strdup(wmem_epan_scope(), (const char*)a->name);
	if (!a->name) {
		report_failure("Diameter Dictionary: Invalid Application (empty name): id=%d\n", a->code);
		return;
	}

	wmem_array_append_one(arr, item);
}

static void
ddictionary_print_application(void* data, void* user_data)
{
	ddict_application_t* a = (ddict_application_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "Application: %s[%u]:\n",
		a->name ? (char*)a->name : "-",
		a->code);
}


typedef struct ddict_vendor
{
	xmlChar* name;
	xmlChar* desc;
	unsigned code;

} ddict_vendor_t;

static void ddictionary_clean_vendor(void* data, void* user_data _U_)
{
	ddict_vendor_t* v = (ddict_vendor_t*)data;
	xmlFree(v->name);
	xmlFree(v->desc);
	g_free(v);
}

typedef struct populate_vendor_data
{
	GHashTable* vendors;
	wmem_tree_t* vnds;

} populate_vendor_data_t;

static void
ddictionary_populate_vendor(void* data, void* user_data)
{
	ddict_vendor_t* v = (ddict_vendor_t*)data;
	populate_vendor_data_t* pop_data = (populate_vendor_data_t*)user_data;
	diam_vnd_t* vnd;

	if (v->name == NULL) {
		report_failure("Diameter Dictionary: Invalid Vendor (empty name): code==%d\n", v->code);
		return;
	}

	if (g_hash_table_lookup(pop_data->vendors, v->name))
		return;

	vnd = wmem_new(wmem_epan_scope(), diam_vnd_t);
	vnd->code = v->code;
	vnd->vs_avps = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
	wmem_array_set_null_terminator(vnd->vs_avps);
	wmem_array_bzero(vnd->vs_avps);
	vnd->vs_avps_ext = NULL;
	wmem_tree_insert32(pop_data->vnds, vnd->code, vnd);
	g_hash_table_insert(pop_data->vendors, v->name, vnd);
}

static void
ddictionary_print_vendor(void* data, void* user_data)
{
	ddict_vendor_t* v = (ddict_vendor_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "Vendor: %s[%u]:\n",
		v->name ? (char*)v->name : "-",
		v->code);
}


typedef struct ddict_command
{
	xmlChar* name;
	xmlChar* vendor;
	unsigned code;

} ddict_command_t;

static void
ddictionary_clean_command(void* data, void* user_data _U_)
{
	ddict_command_t* c = (ddict_command_t*)data;
	xmlFree(c->name);
	xmlFree(c->vendor);
	g_free(c);
}

typedef struct populate_command_data
{
	GHashTable* vendors;
	GArray* cmds;

} populate_command_data_t;

static void
ddictionary_populate_command(void* data, void* user_data)
{
	ddict_command_t* c = (ddict_command_t*)data;
	populate_command_data_t* pop_data = (populate_command_data_t*)user_data;

	if (c->vendor == NULL) {
		report_failure("Diameter Dictionary: Invalid Vendor (empty name) for command %s\n",
			c->name ? (char*)c->name : "(null)");
		return;
	}

	if ((diam_vnd_t*)g_hash_table_lookup(pop_data->vendors, c->vendor)) {
		value_string item;

		item.value = c->code;
		item.strptr = wmem_strdup(wmem_epan_scope(), (const char*)c->name);

		g_array_append_val(pop_data->cmds, item);
	}
	else {
		report_failure("Diameter Dictionary: No Vendor: %s\n", c->vendor);
	}
}

static void
ddictionary_print_command(void* data, void* user_data)
{
	ddict_command_t* c = (ddict_command_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "Command: %s[%u] \n",
		c->name ? (char*)c->name : "-",
		c->code);
}


typedef struct ddict_typedefn
{
	xmlChar* name;
	xmlChar* parent;

} ddict_typedefn_t;


static void
ddictionary_clean_typedefn(void* data, void* user_data _U_)
{
	ddict_typedefn_t* t = (ddict_typedefn_t*)data;
	xmlFree(t->name);
	xmlFree(t->parent);
	g_free(t);
}

static void
ddictionary_populate_typedefn(void* data, void* user_data)
{
	GHashTable* types = (GHashTable*)user_data;
	ddict_typedefn_t* t = (ddict_typedefn_t*)data;
	const avp_type_t* parent = NULL;

	/* try to get the parent type */
	if (t->name == NULL) {
		report_failure("Diameter Dictionary: Invalid Type (empty name): parent==%s\n", t->parent ? (char*)t->parent : "(null)");
		return;
	}

	if (g_hash_table_lookup(types, t->name))
		return;

	if (t->parent)
		parent = (avp_type_t*)g_hash_table_lookup(types, t->parent);

	if (parent == NULL)
		parent = &basic_types[0];

	/* insert the parent type for this type */
	g_hash_table_insert(types, t->name, (void*)parent);
}

static void
ddictionary_print_typedefn(void* data, void* user_data)
{
	ddict_typedefn_t* t = (ddict_typedefn_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "Type: %s -> %s \n",
		t->name ? (char*)t->name : "-",
		t->parent ? (char*)t->parent : "");
}

typedef struct ddict_avp
{
	xmlChar* name;
	xmlChar* description;
	xmlChar* vendor;
	xmlChar* type;
	unsigned code;
	GSList* gavps;
	GSList* enums;

} ddict_avp_t;

typedef struct ddict_avp_enum
{
	xmlChar* name;
	unsigned code;
} ddict_avp_enum_t;

typedef struct ddict_gavp
{
	xmlChar* name;
} ddict_gavp_t;

typedef struct ddict_xmlpi
{
	xmlChar* name;
	xmlChar* key;
	xmlChar* value;
} ddict_xmlpi_t;


static void
ddictionary_clean_xmlpi(void* data, void* user_data _U_)
{
	ddict_xmlpi_t* x = (ddict_xmlpi_t*)data;
	xmlFree(x->name);
	xmlFree(x->key);
	xmlFree(x->value);
	g_free(x);
}

static void
ddictionary_clean_gavp(void* data, void* user_data _U_)
{
	ddict_gavp_t* g = (ddict_gavp_t*)data;
	xmlFree(g->name);
	g_free(g);
}

static void
ddictionary_clean_enum(void* data, void* user_data _U_)
{
	ddict_avp_enum_t* e = (ddict_avp_enum_t*)data;
	xmlFree(e->name);
	g_free(e);
}

static void
ddictionary_clean_avp(void* data, void* user_data)
{
	ddict_avp_t* a = (ddict_avp_t*)data;
	xmlFree(a->name);
	xmlFree(a->description);
	xmlFree(a->vendor);
	xmlFree(a->type);

	g_slist_foreach(a->gavps, ddictionary_clean_gavp, user_data);
	g_slist_free(a->gavps);
	g_slist_foreach(a->enums, ddictionary_clean_enum, user_data);
	g_slist_free(a->enums);
	g_free(a);
}

typedef struct populate_avp_data
{
	GHashTable* vendors;
	GHashTable* types;
	GHashTable* build_avps;
	wmem_tree_t* dict_avps;
	GSList* xmlpis;
	wmem_array_t* hf_array;
	GPtrArray* ett_array;

} populate_avp_data_t;

static void
ddictionary_populate_enum(void* data, void* user_data)
{
	ddict_avp_enum_t* e = (ddict_avp_enum_t*)data;
	wmem_array_t* arr = (wmem_array_t*)user_data;

	value_string item = { e->code, wmem_strdup(wmem_epan_scope(), (const char*)e->name) };
	wmem_array_append_one(arr, item);
}

static void
ddictionary_populate_avp(void* data, void* user_data)
{
	ddict_avp_t* a = (ddict_avp_t*)data;
	populate_avp_data_t* pop_data = (populate_avp_data_t*)user_data;

	diam_vnd_t* vnd;
	value_string* vs = NULL;
	const char* vend = a->vendor ? (const char*)a->vendor : "None";
	void* avp_data = NULL;
	const avp_type_t* type = NULL;
	value_string end_value_string = { 0, NULL };

	if (a->name == NULL) {
		report_failure("Diameter Dictionary: Invalid AVP (empty name)\n");
		return;
	}

	if ((vnd = (diam_vnd_t*)g_hash_table_lookup(pop_data->vendors, vend))) {
		value_string vndvs;

		vndvs.value = a->code;
		vndvs.strptr = wmem_strdup(wmem_epan_scope(), (const char*)a->name);

		wmem_array_append_one(vnd->vs_avps, vndvs);
	}
	else {
		report_failure("Diameter Dictionary: No Vendor: %s\n", vend);
		vnd = &unknown_vendor;
	}

	if (a->enums != NULL) {
		wmem_array_t* arr = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
		g_slist_foreach(a->enums, ddictionary_populate_enum, arr);

		wmem_array_sort(arr, compare_avps);
		wmem_array_append_one(arr, end_value_string);
		vs = (value_string*)wmem_array_get_raw(arr);
	}

	for (GSList* elem = pop_data->xmlpis; elem; elem = elem->next) {
		ddict_xmlpi_t* x = (ddict_xmlpi_t*)elem->data;

		if ((strcase_equal(x->name, "avp-proto") && strcase_equal(x->key, a->name))
			|| (a->type && strcase_equal(x->name, "type-proto") && strcase_equal(x->key, a->type))
			) {
			static avp_type_t proto_type = { "proto", proto_avp, FT_UINT32, BASE_HEX, build_proto_avp };
			type = &proto_type;

			avp_data = wmem_strdup(wmem_epan_scope(), (const char*)x->value);
			break;
		}
	}

	if ((type == NULL) && a->type)
		type = (avp_type_t*)g_hash_table_lookup(pop_data->types, a->type);

	if (type == NULL)
		type = &basic_types[0];

	char* avp_name = wmem_strdup(wmem_epan_scope(), (const char*)a->name);
	avp_constructor_data_t avp_constructor = { type, a->code, vnd, avp_name, vs, avp_data, pop_data->hf_array, pop_data->ett_array };
	diam_avp_t* avp = type->build(&avp_constructor);
	if (avp != NULL) {
		g_hash_table_insert(pop_data->build_avps, avp_name, avp);

		wmem_tree_key_t k[3];

		k[0].length = 1;
		k[0].key = &(a->code);
		k[1].length = 1;
		k[1].key = &(vnd->code);
		k[2].length = 0;
		k[2].key = NULL;

		wmem_tree_insert32_array(pop_data->dict_avps, k, avp);
	}
}

static void
ddictionary_print_gavp(void* data, void* user_data)
{
	ddict_gavp_t* g = (ddict_gavp_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "\tGAVP: %s\n",
		g->name ? (char*)g->name : "-");
}

static void
ddictionary_print_avp_enum(void* data, void* user_data)
{
	ddict_avp_enum_t* e = (ddict_avp_enum_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "\tEnum: %s[%u]\n",
		e->name ? (char*)e->name : "-",
		e->code);
}

static void
ddictionary_print_avp(void* data, void* user_data)
{
	ddict_avp_t* a = (ddict_avp_t*)data;
	FILE* fh = (FILE*)user_data;

	fprintf(fh, "AVP: %s[%u:%s] %s %s\n",
		a->name ? (char*)a->name : "-",
		a->code,
		a->vendor ? (char*)a->vendor : "None",
		a->type ? (char*)a->type : "-",
		a->description ? (char*)a->description : "");

	g_slist_foreach(a->gavps, ddictionary_print_gavp, fh);
	g_slist_foreach(a->enums, ddictionary_print_avp_enum, fh);
}

static bool
ddictionary_process_command(xmlNodePtr command, GSList** commands)
{
	ddict_command_t* element = g_new(ddict_command_t, 1);
	element->name = xmlGetProp(command, (const xmlChar*)"name");
	element->vendor = xmlGetProp(command, (const xmlChar*)"vendor-id");
	xmlChar* code = xmlGetProp(command, (const xmlChar*)"code");
	if (code != NULL) {
		ws_strtou32((const char*)code, NULL, &element->code);
		xmlFree(code);
	}

	(*commands) = g_slist_prepend((*commands), element);

	return true;
}

static bool
ddictionary_process_avp(xmlNodePtr avp, GSList** avps)
{
	ddict_avp_t* element = g_new0(ddict_avp_t, 1);

	element->name = xmlGetProp(avp, (const xmlChar*)"name");
	element->description = xmlGetProp(avp, (const xmlChar*)"description");
	element->vendor = xmlGetProp(avp, (const xmlChar*)"vendor-id");
	xmlChar* code = xmlGetProp(avp, (const xmlChar*)"code");
	if (code != NULL) {
		ws_strtou32((const char*)code, NULL, &element->code);
		xmlFree(code);
	}

	//Iterate through the child elements
	for (xmlNodePtr current_node = avp->children; current_node != NULL; current_node = current_node->next) {
		if (current_node->type != XML_ELEMENT_NODE)
			continue;

		if (xmlStrcmp(current_node->name, (const xmlChar*)"type") == 0) {
			element->type = xmlGetProp(current_node, (const xmlChar*)"type-name");
		}
		else if (xmlStrcmp(current_node->name, (const xmlChar*)"enum") == 0) {
			ddict_avp_enum_t* avp_enum = g_new(ddict_avp_enum_t, 1);

			avp_enum->name = xmlGetProp(current_node, (const xmlChar*)"name");
			code = xmlGetProp(current_node, (const xmlChar*)"code");
			if (code != NULL) {
				if (code[0] == '-') {
					//Enumerated values can be 32-bit integers, but treat them as unsigned
					int32_t tmp;
					ws_strtoi32((const char*)code, NULL, &tmp);
					avp_enum->code = (unsigned)tmp;
				}
				else {
					ws_strtou32((const char*)code, NULL, &avp_enum->code);
				}
				xmlFree(code);
			}
			element->enums = g_slist_prepend(element->enums, avp_enum);
		}
		else if (xmlStrcmp(current_node->name, (const xmlChar*)"grouped") == 0) {
			//All AVPs under the grouped element are considered Grouped type
			element->type = xmlStrdup((const xmlChar*)"Grouped");

			for (xmlNodePtr group_children = current_node->children; group_children != NULL; group_children = group_children->next) {
				if (group_children->type != XML_ELEMENT_NODE)
					continue;
				if (xmlStrcmp(group_children->name, (const xmlChar*)"gavp") == 0) {
					ddict_gavp_t* group = g_new(ddict_gavp_t, 1);
					group->name = xmlGetProp(group_children, (const xmlChar*)"name");

					element->gavps = g_slist_prepend(element->gavps, group);
				}
			}

		}
	}

	//Reverse all of the lists so they are in the proper order
	element->enums = g_slist_reverse(element->enums);
	element->gavps = g_slist_reverse(element->gavps);

	(*avps) = g_slist_prepend((*avps), element);
	return true;
}


typedef struct _ddict_t {
	GSList* applications;
	GSList* vendors;
	GSList* cmds;
	GSList* typedefns;
	GSList* avps;
	GSList* xmlpis;
} ddict_t;

static void
ddictionary_new_print(FILE* fh, ddict_t* dict)
{
	g_slist_foreach(dict->applications, ddictionary_print_application, fh);
	g_slist_foreach(dict->vendors, ddictionary_print_vendor, fh);
	g_slist_foreach(dict->cmds, ddictionary_print_command, fh);
	g_slist_foreach(dict->typedefns, ddictionary_print_typedefn, fh);
	g_slist_foreach(dict->avps, ddictionary_print_avp, fh);
}

static void
ddictionary_clean(ddict_t* dict)
{
	g_slist_foreach(dict->applications, ddictionary_clean_application, NULL);
	g_slist_free(dict->applications);
	g_slist_foreach(dict->vendors, ddictionary_clean_vendor, NULL);
	g_slist_free(dict->vendors);
	g_slist_foreach(dict->cmds, ddictionary_clean_command, NULL);
	g_slist_free(dict->cmds);
	g_slist_foreach(dict->typedefns, ddictionary_clean_typedefn, NULL);
	g_slist_free(dict->typedefns);
	g_slist_foreach(dict->avps, ddictionary_clean_avp, NULL);
	g_slist_free(dict->avps);
	g_slist_foreach(dict->xmlpis, ddictionary_clean_xmlpi, NULL);
	g_slist_free(dict->xmlpis);
}

/*******************************************************************************************************************
 *
 * END STRUCTURES FOR LIBXML2 PARSING
 *
 *******************************************************************************************************************/

struct xml_read_data
{
	xmlDocPtr doc;
	const char* filename;
};

static void
ddictionary_read_xml_file(void* param)
{
	struct xml_read_data* data = (struct xml_read_data*)param;
	data->doc = xmlReadFile(data->filename, NULL, XML_PARSE_NOENT|XML_PARSE_NONET);
}

static bool
ddictionary_process_file(const char* dir, const char* filename, ddict_t* dict)
{
	xmlNodePtr root_element = NULL;
	bool status = true;
	struct xml_read_data func_data = {NULL, filename};

	proto_execute_in_directory(dir, ddictionary_read_xml_file, &func_data);

	if (func_data.doc == NULL)
		return false;

	root_element = xmlDocGetRootElement(func_data.doc);
	if (root_element == NULL) {
		status = false;
		goto cleanup;
	}

	// Process the document children for XML pis
	for (xmlNodePtr pi_node = func_data.doc->children; pi_node != NULL; pi_node = pi_node->next) {
		if (pi_node->type != XML_PI_NODE)
			continue;

		if ((xmlStrcmp(pi_node->name, (const xmlChar*)"type-proto") == 0) ||
		    (xmlStrcmp(pi_node->name, (const xmlChar*)"avp-proto") == 0)) {
			ddict_xmlpi_t* element = g_new0(ddict_xmlpi_t, 1);
			element->name = xmlStrdup(pi_node->name);

			//Although the syntax looks like properties, the contents have to be "manually" parsed
			xmlChar* content = xmlNodeGetContent(pi_node);

			char* key_start = strstr((char*)content, "key=\"");
			char* value_start = strstr((char*)content, "value=\"");

			if (key_start) {
				key_start += strlen("key=\"");
				char* key_end = strchr(key_start, '"');
				if (key_end) {
					element->key = xmlStrndup((const xmlChar*)key_start, (int)(key_end - key_start));
				}
			}
			if (value_start) {
				value_start += strlen("key=\"");
				char* value_end = strchr(value_start, '"');
				if (value_end) {
					element->value = xmlStrndup((const xmlChar*)value_start, (int)(value_end - value_start));
				}
			}

			dict->xmlpis = g_slist_prepend(dict->xmlpis, element);
			xmlFree(content);
		}
	}

	// Iterate through top-level child elements
	for (xmlNodePtr current_node = root_element->children; current_node != NULL; current_node = current_node->next) {
		if (current_node->type == XML_ELEMENT_NODE) {
			// Process <base> element
			if (xmlStrcmp(current_node->name, (const xmlChar*)"base") == 0) {

				//Process any <command> elements
				for (xmlNodePtr base_children = current_node->children; base_children != NULL; base_children = base_children->next) {
					if (base_children->type == XML_ELEMENT_NODE) {
						if (xmlStrcmp(base_children->name, (const xmlChar*)"command") == 0) {
							ddictionary_process_command(base_children, &dict->cmds);
						}
						// Process <typedefn> elements
						else if (xmlStrcmp(base_children->name, (const xmlChar*)"typedefn") == 0) {
							ddict_typedefn_t* element = g_new(ddict_typedefn_t, 1);
							element->name = xmlGetProp(base_children, (const xmlChar*)"type-name");
							element->parent = xmlGetProp(base_children, (const xmlChar*)"type-parent");
							dict->typedefns = g_slist_prepend(dict->typedefns, element);
						}
						// Process <avp> elements
						else if (xmlStrcmp(base_children->name, (const xmlChar*)"avp") == 0) {
							ddictionary_process_avp(base_children, &dict->avps);
						}
					}
				}
			}
			// Process <application> elements
			else if (xmlStrcmp(current_node->name, (const xmlChar*)"application") == 0) {
				ddict_application_t* element = g_new0(ddict_application_t, 1);
				element->name = xmlGetProp(current_node, (const xmlChar*)"name");
				xmlChar* id = xmlGetProp(current_node, (const xmlChar*)"id");
				if (id != NULL) {
					ws_strtou32((const char*)id, NULL, &element->code);
					xmlFree(id);
				}

				dict->applications = g_slist_prepend(dict->applications, element);

				for (xmlNodePtr base_children = current_node->children; base_children != NULL; base_children = base_children->next) {
					if (base_children->type == XML_ELEMENT_NODE) {
						//Process any <command> elements
						if (xmlStrcmp(base_children->name, (const xmlChar*)"command") == 0) {
							ddictionary_process_command(base_children, &dict->cmds);
						}
						// Process <avp> elements
						else if (xmlStrcmp(base_children->name, (const xmlChar*)"avp") == 0) {
							ddictionary_process_avp(base_children, &dict->avps);
						}
					}
				}
			}
			// Process <vendor> elements
			else if (xmlStrcmp(current_node->name, (const xmlChar*)"vendor") == 0) {
				ddict_vendor_t* element = g_new0(ddict_vendor_t, 1);
				xmlChar* code = xmlGetProp(current_node, (const xmlChar*)"code");
				element->name = xmlGetProp(current_node, (const xmlChar*)"vendor-id");
				element->desc = xmlGetProp(current_node, (const xmlChar*)"name");
				if (code != NULL) {
					ws_strtou32((const char*)code, NULL, &element->code);
					xmlFree(code);
				}

				dict->vendors = g_slist_prepend(dict->vendors, element);

				for (xmlNodePtr base_children = current_node->children; base_children != NULL; base_children = base_children->next) {
					if (base_children->type == XML_ELEMENT_NODE) {
						// Process <avp> elements
						if (xmlStrcmp(base_children->name, (const xmlChar*)"avp") == 0) {
							ddictionary_process_avp(base_children, &dict->avps);
						}
					}
				}

			}
		}
	}

	//Reverse all of the lists so they are in the proper order
	dict->applications = g_slist_reverse(dict->applications);
	dict->vendors = g_slist_reverse(dict->vendors);
	dict->cmds = g_slist_reverse(dict->cmds);
	dict->typedefns = g_slist_reverse(dict->typedefns);
	dict->avps = g_slist_reverse(dict->avps);
	dict->xmlpis = g_slist_reverse(dict->xmlpis);

cleanup:
	xmlFreeDoc(func_data.doc);

	return status;
}

/* Note: Dynamic "value string arrays" (e.g., vs_avps, ...) are constructed using */
/*       "zero-terminated" GArrays so that they will have the same form as standard        */
/*       value_string arrays created at compile time. Since the last entry in a            */
/*       value_string array must be {0, NULL}, we are assuming that NULL == 0 (hackish).   */
static int
ddictionary_load(wmem_array_t* hf_array, GPtrArray* ett_array)
{
	bool do_dump_dict = getenv("WIRESHARK_DUMP_DIAM_DICT") ? true : false;
	char* dir;
	const avp_type_t* type;
	GHashTable *vendors = g_hash_table_new(strcase_hash, strcase_equal),
		   *build_dict_types = g_hash_table_new(strcase_hash, strcase_equal),
		   *build_dict_avps = g_hash_table_new(strcase_hash, strcase_equal);
	GArray* all_cmds = g_array_new(true, true, sizeof(value_string));
	value_string end_value_string = { 0, NULL };
	ddict_t all_data = { NULL, NULL, NULL, NULL, NULL, NULL};

	dictionary.vnds = wmem_tree_new(wmem_epan_scope());
	dictionary.avps = wmem_tree_new(wmem_epan_scope());

	unknown_vendor.vs_avps = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
	wmem_array_set_null_terminator(unknown_vendor.vs_avps);
	wmem_array_bzero(unknown_vendor.vs_avps);
	no_vnd.vs_avps = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
	wmem_array_set_null_terminator(no_vnd.vs_avps);
	wmem_array_bzero(no_vnd.vs_avps);

	wmem_tree_insert32(dictionary.vnds, 0, &no_vnd);
	g_hash_table_insert(vendors, "None", &no_vnd);

	/* initialize the types hash with the known basic types */
	for (type = basic_types; type->name; type++) {
		g_hash_table_insert(build_dict_types, (char*)type->name, (void*)type);
	}

	/* load the dictionary */
	dir = wmem_strdup_printf(NULL, "%s" G_DIR_SEPARATOR_S "diameter", get_datafile_dir(epan_get_environment_prefix()));
	bool success = ddictionary_process_file(dir, "./dictionary.xml", &all_data);
	wmem_free(NULL, dir);

	if (do_dump_dict)
		ddictionary_new_print(stdout, &all_data);

	/* populate the types */
	g_slist_foreach(all_data.typedefns, ddictionary_populate_typedefn, build_dict_types);

	/* populate the applications */
	if (all_data.applications != NULL)
	{
		wmem_array_t* arr = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
		g_slist_foreach(all_data.applications, ddictionary_populate_application, arr);

		wmem_array_sort(arr, compare_avps);

		//Terminate the value_string list
		wmem_array_append_one(arr, end_value_string);

		/* TODO: Remove duplicates */

		dictionary.applications = value_string_ext_new(wmem_epan_scope(), (value_string*)wmem_array_get_raw(arr),
			wmem_array_get_count(arr),
			wmem_strdup(wmem_epan_scope(), "applications_vals_ext"));
	}

	/* populate the vendors */
	populate_vendor_data_t vendor_populate = { vendors, dictionary.vnds };
	g_slist_foreach(all_data.vendors, ddictionary_populate_vendor, &vendor_populate);

	/* populate the commands */
	populate_command_data_t command_populate = { vendors, all_cmds };
	g_slist_foreach(all_data.cmds, ddictionary_populate_command, &command_populate);

	/* populate the avps */
	populate_avp_data_t avp_populate = { vendors, build_dict_types, build_dict_avps, dictionary.avps, all_data.xmlpis, hf_array, ett_array };
	g_slist_foreach(all_data.avps, ddictionary_populate_avp, &avp_populate);

	cmd_vs = (const value_string*)g_array_free(all_cmds, false);

	/* Clean up */
	g_hash_table_destroy(build_dict_types);
	g_hash_table_destroy(build_dict_avps);
	g_hash_table_destroy(vendors);

	ddictionary_clean(&all_data);

	return success;
}
/*******************************************************************************************************************
 *
 * END OF DIAMETER XML DATA DICTIONARY PROCESSSING
 *
 *******************************************************************************************************************/

/*
 * This does most of the registration work; see register_diameter_fields()
 * for the reason why we split it off.
 */
static void
real_register_diameter_fields(wmem_array_t* hf_array, GPtrArray* ett_array)
{
	expert_module_t* expert_diameter;
	unsigned i, ett_length;

	hf_register_info hf_base[] = {
	{ &hf_diameter_version,
		  { "Version", "diameter.version", FT_UINT8, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }},
	{ &hf_diameter_length,
		  { "Length","diameter.length", FT_UINT24, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }},
	{ &hf_diameter_flags,
		  { "Flags", "diameter.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }},
	{ &hf_diameter_flags_request,
		  { "Request", "diameter.flags.request", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DIAM_FLAGS_R,
			  NULL, HFILL }},
	{ &hf_diameter_flags_proxyable,
		  { "Proxyable", "diameter.flags.proxyable", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DIAM_FLAGS_P,
			  NULL, HFILL }},
	{ &hf_diameter_flags_error,
		  { "Error","diameter.flags.error", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DIAM_FLAGS_E,
			  NULL, HFILL }},
	{ &hf_diameter_flags_T,
		  { "T(Potentially re-transmitted message)","diameter.flags.T", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DIAM_FLAGS_T,
			  NULL, HFILL }},
	{ &hf_diameter_flags_reserved4,
		  { "Reserved","diameter.flags.reserved4", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  DIAM_FLAGS_RESERVED4, NULL, HFILL }},
	{ &hf_diameter_flags_reserved5,
		  { "Reserved","diameter.flags.reserved5", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  DIAM_FLAGS_RESERVED5, NULL, HFILL }},
	{ &hf_diameter_flags_reserved6,
		  { "Reserved","diameter.flags.reserved6", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  DIAM_FLAGS_RESERVED6, NULL, HFILL }},
	{ &hf_diameter_flags_reserved7,
		  { "Reserved","diameter.flags.reserved7", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  DIAM_FLAGS_RESERVED7, NULL, HFILL }},
	{ &hf_diameter_vendor_id,
		  { "VendorId",	"diameter.vendorId", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES,
			  0x0, NULL, HFILL }},
	{ &hf_diameter_application_id,
		  { "ApplicationId", "diameter.applicationId", FT_UINT32, BASE_DEC|BASE_EXT_STRING, VALS_EXT_PTR(dictionary.applications),
			  0x0, NULL, HFILL }},
	{ &hf_diameter_hopbyhopid,
		  { "Hop-by-Hop Identifier", "diameter.hopbyhopid", FT_UINT32,
			  BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_endtoendid,
		  { "End-to-End Identifier", "diameter.endtoendid", FT_UINT32,
			  BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_avp,
		  { "AVP","diameter.avp", FT_BYTES, BASE_NONE,
			  NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_avp_len,
		  { "AVP Length","diameter.avp.len", FT_UINT24, BASE_DEC,
			  NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_avp_code,
		  { "AVP Code", "diameter.avp.code", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_diameter_avp_flags,
		  { "AVP Flags","diameter.avp.flags", FT_UINT8, BASE_HEX,
			  NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_avp_flags_vendor_specific,
		  { "Vendor-Specific", "diameter.flags.vendorspecific", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AVP_FLAGS_V,
			  NULL, HFILL }},
	{ &hf_diameter_avp_flags_mandatory,
		  { "Mandatory", "diameter.flags.mandatory", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AVP_FLAGS_M,
			  NULL, HFILL }},
	{ &hf_diameter_avp_flags_protected,
		  { "Protected","diameter.avp.flags.protected", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AVP_FLAGS_P,
			  NULL, HFILL }},
	{ &hf_diameter_avp_flags_reserved3,
		  { "Reserved","diameter.avp.flags.reserved3", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  AVP_FLAGS_RESERVED3,	NULL, HFILL }},
	{ &hf_diameter_avp_flags_reserved4,
		  { "Reserved","diameter.avp.flags.reserved4", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  AVP_FLAGS_RESERVED4,	NULL, HFILL }},
	{ &hf_diameter_avp_flags_reserved5,
		  { "Reserved","diameter.avp.flags.reserved5", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  AVP_FLAGS_RESERVED5,	NULL, HFILL }},
	{ &hf_diameter_avp_flags_reserved6,
		  { "Reserved","diameter.avp.flags.reserved6", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  AVP_FLAGS_RESERVED6,	NULL, HFILL }},
	{ &hf_diameter_avp_flags_reserved7,
		  { "Reserved","diameter.avp.flags.reserved7", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
			  AVP_FLAGS_RESERVED7,	NULL, HFILL }},
	{ &hf_diameter_avp_vendor_id,
		  { "AVP Vendor Id","diameter.avp.vendorId", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES,
			  0x0, NULL, HFILL }},
	{ &(unknown_avp.hf_value),
		  { "Value","diameter.avp.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_avp_data_wrong_length,
		  { "Data","diameter.avp.invalid-data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_avp_pad,
		  { "Padding","diameter.avp.pad", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_code,
		  { "Command Code", "diameter.cmd.code", FT_UINT32, BASE_DEC, VALS(cmd_vs), 0, NULL, HFILL }},
	{ &hf_diameter_answer_in,
		{ "Answer In", "diameter.answer_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
		"The answer to this diameter request is in this frame", HFILL }},
	{ &hf_diameter_answer_to,
		{ "Request In", "diameter.answer_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
		"This is an answer to the diameter request in this frame", HFILL }},
	{ &hf_diameter_answer_time,
		{ "Response Time", "diameter.resp_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		"The time between the request and the answer", HFILL }},
	{ &hf_framed_ipv6_prefix_reserved,
	    { "Framed IPv6 Prefix Reserved byte", "diameter.framed_ipv6_prefix_reserved",
	    FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_framed_ipv6_prefix_length,
	    { "Framed IPv6 Prefix length (in bits)", "diameter.framed_ipv6_prefix_length",
	    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_framed_ipv6_prefix_bytes,
	    { "Framed IPv6 Prefix as a bytestring", "diameter.framed_ipv6_prefix_bytes",
	    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_framed_ipv6_prefix_ipv6,
	    { "Framed IPv6 Prefix as an IPv6 address", "diameter.framed_ipv6_prefix_ipv6",
	    FT_IPv6, BASE_NONE, NULL, 0, "This field is present only if the prefix length is 128", HFILL }},
	{ &hf_diameter_3gpp2_exp_res,
		{ "Experimental-Result-Code", "diameter.3gpp2.exp_res",
		FT_UINT32, BASE_DEC, VALS(diameter_3gpp2_exp_res_vals), 0x0,	NULL, HFILL }},
	{ &hf_diameter_other_vendor_exp_res,
		{ "Experimental-Result-Code", "diameter.other_vendor.Experimental-Result-Code",
		FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_mip6_feature_vector,
		{ "MIP6-Feature-Vector", "diameter.mip6_feature_vector",
		 FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_mip6_feature_vector_mip6_integrated,
		{ "MIP6_INTEGRATED", "diameter.mip6_feature_vector.mip6_integrated.mip6_integrated",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000001, NULL, HFILL }},
	{ &hf_diameter_mip6_feature_vector_local_home_agent_assignment,
		{ "LOCAL_HOME_AGENT_ASSIGNMENT", "diameter.mip6_feature_vector.local_home_agent_assignment",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000000000000002, NULL, HFILL }},
	{ &hf_diameter_mip6_feature_vector_pmip6_supported,
		{ "PMIP6_SUPPORTED", "diameter.mip6_feature_vector.pmip6_supported",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000010000000000, NULL, HFILL }},
	{ &hf_diameter_mip6_feature_vector_ip4_hoa_supported,
		{ "IP4_HOA_SUPPORTED", "diameter.mip6_feature_vector.ip4_hoa_supported",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000020000000000, NULL, HFILL }},
	{ &hf_diameter_mip6_feature_vector_local_mag_routing_supported,
		{ "LOCAL_MAG_ROUTING_SUPPORTED", "diameter.mip6_feature_vector.local_mag_routing_supported",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000040000000000,NULL, HFILL }},
	{ &hf_diameter_3gpp_mip6_feature_vector,
		{ "MIP6-Feature-Vector [3GPP]", "diameter.3gpp.mip6_feature_vector",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_3gpp_mip6_feature_vector_assign_local_ip,
		{ "MIP6_INTEGRATED", "diameter.3gpp.mip6_feature_vector.assign_local_ip",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000080000000000, NULL, HFILL }},
	{ &hf_diameter_3gpp_mip6_feature_vector_mip4_supported,
		{ "PMIP6_SUPPORTED", "diameter.3gpp.mip6_feature_vector.mip4_supported",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000100000000000, NULL, HFILL }},
	{ &hf_diameter_3gpp_mip6_feature_vector_optimized_idle_mode_mobility,
		{ "OPTIMIZED_IDLE_MODE_MOBILITY", "diameter.3gpp.mip6_feature_vector.optimized_idle_mode_mobility",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000200000000000, NULL, HFILL }},
	{ &hf_diameter_3gpp_mip6_feature_vector_gtpv2_supported,
		{ "GTPv2_SUPPORTED", "diameter.3gpp.mip6_feature_vector.gtpv2_supported",
		FT_BOOLEAN, 64, TFS(&tfs_set_notset), 0x0000400000000000, NULL, HFILL }},
	{ &hf_diameter_user_equipment_info_imeisv,
		{ "IMEISV","diameter.user_equipment_info.imeisv", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_user_equipment_info_mac,
		{ "MAC","diameter.user_equipment_info.mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_user_equipment_info_eui64,
		{ "EUI64","diameter.user_equipment_info.eui64", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_user_equipment_info_modified_eui64,
		{ "Modified EUI64","diameter.user_equipment_info.modified_eui64", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_diameter_result_code_cmd_level,
		{ "Result-Code-Command-Level", "diameter.Result-Code.Command-Level", FT_UINT32, BASE_DEC, NULL, 0x0,	NULL, HFILL }},
	{ &hf_diameter_result_code_mscc_level,
		{ "Result-Code-MSCC-Level", "diameter.Result-Code.MSCC-Level", FT_UINT32, BASE_DEC, NULL, 0x0,	NULL, HFILL }}
	};

	int *ett_base[] = {
		&ett_diameter,
		&ett_diameter_flags,
		&ett_diameter_avp_flags,
		&ett_diameter_avpinfo,
		&ett_unknown,
		&ett_diameter_mip6_feature_vector,
	    &ett_diameter_3gpp_mip6_feature_vector,
		&(unknown_avp.ett)
	};

	static ei_register_info ei[] = {
		{ &ei_diameter_reserved_bit_set, { "diameter.reserved_bit_set", PI_MALFORMED, PI_WARN, "Reserved bit set", EXPFILL }},
		{ &ei_diameter_avp_code, { "diameter.avp.code.unknown", PI_UNDECODED, PI_WARN, "Unknown AVP, if you know what this is you can add it to dictionary.xml", EXPFILL }},
		{ &ei_diameter_avp_vendor_id, { "diameter.unknown_vendor", PI_UNDECODED, PI_WARN, "Unknown Vendor, if you know whose this is you can add it to dictionary.xml", EXPFILL }},
		{ &ei_diameter_avp_no_data, { "diameter.avp.no_data", PI_UNDECODED, PI_WARN, "Data is empty", EXPFILL }},
		{ &ei_diameter_avp_pad, { "diameter.avp.pad.non_zero", PI_MALFORMED, PI_NOTE, "Padding is non-zero", EXPFILL }},
		{ &ei_diameter_avp_pad_missing, { "diameter.avp.pad.missing", PI_MALFORMED, PI_NOTE, "Padding is missing", EXPFILL }},
		{ &ei_diameter_avp_len, { "diameter.avp.invalid-len", PI_MALFORMED, PI_WARN, "Wrong length", EXPFILL }},
		{ &ei_diameter_application_id, { "diameter.applicationId.unknown", PI_UNDECODED, PI_WARN, "Unknown Application Id, if you know what this is you can add it to dictionary.xml", EXPFILL }},
		{ &ei_diameter_version, { "diameter.version.unknown", PI_UNDECODED, PI_WARN, "Unknown Diameter Version (decoding as RFC 3588)", EXPFILL }},
		{ &ei_diameter_code, { "diameter.cmd.code.unknown", PI_UNDECODED, PI_WARN, "Unknown command, if you know what this is you can add it to dictionary.xml", EXPFILL }},
		{ &ei_diameter_invalid_ipv6_prefix_len, { "diameter.invalid_ipv6_prefix_len", PI_MALFORMED, PI_ERROR, "Invalid IPv6 Prefix length", EXPFILL }},
		{ &ei_diameter_invalid_avp_len,{ "diameter.invalid_avp_len", PI_MALFORMED, PI_ERROR, "Invalid AVP length", EXPFILL }},
		{ &ei_diameter_invalid_user_equipment_info_value_len,{ "diameter.invalid_user_equipment_info_value_len", PI_MALFORMED, PI_ERROR, "Invalid User-Equipment-Info-Value length", EXPFILL }},
		{ &ei_diameter_unexpected_imei_as_user_equipment_info,{ "diameter.unexpected_imei_as_user_equipment_info", PI_MALFORMED, PI_ERROR, "Found IMEI as User-Equipment-Info-Value but IMEISV was expected", EXPFILL }},
	};

	wmem_array_append(hf_array, hf_base, array_length(hf_base));
	ett_length = array_length(ett_base);
	for (i = 0; i < ett_length; i++) {
		g_ptr_array_add(ett_array, ett_base[i]);
	}

	proto_register_field_array(proto_diameter, (hf_register_info *)wmem_array_get_raw(hf_array), wmem_array_get_count(hf_array));
	proto_register_subtree_array((int **)ett_array->pdata, ett_array->len);
	expert_diameter = expert_register_protocol(proto_diameter);
	expert_register_field_array(expert_diameter, ei, array_length(ei));

	g_ptr_array_free(ett_array,true);

	diameter_conversations = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
	diam_session_imsi = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
}

static void
register_diameter_fields(const char *unused _U_)
{
#define DIAMETER_DYNAMIC_HF_SIZE		4096
	/*
	 * The hf_base[] array for Diameter refers to a variable
	 * that is set by ddictionary_load(), so we need to call
	 * ddictionary_load() before hf_base[] is initialized.
	 *
	 * To ensure that, we call ddictionary_load() and then
	 * call a routine that defines hf_base[] and does all
	 * the registration work.
	 */
	 /* Pre allocate the arrays big enough to hold the hf:s and etts:s*/
	wmem_array_t* hf_array = wmem_array_sized_new(wmem_epan_scope(), sizeof(hf_register_info), DIAMETER_DYNAMIC_HF_SIZE);
	GPtrArray* ett_array = g_ptr_array_sized_new(DIAMETER_DYNAMIC_HF_SIZE);

	ddictionary_load(hf_array, ett_array);
	real_register_diameter_fields(hf_array, ett_array);
}

void
proto_register_diameter(void)
{
	module_t *diameter_module;

	proto_diameter = proto_register_protocol ("Diameter Protocol", "Diameter", "diameter");

	/* Allow dissector to find be found by name. */
	diameter_sctp_handle = register_dissector("diameter", dissect_diameter, proto_diameter);
	diameter_udp_handle = create_dissector_handle(dissect_diameter, proto_diameter);
	diameter_tcp_handle = register_dissector("diameter.tcp", dissect_diameter_tcp, proto_diameter);
	/* Diameter AVPs without Diameter header, for EAP-TTLS (RFC 5281, Section 10) */
	register_dissector("diameter_avps", dissect_diameter_avps, proto_diameter);

	/* Delay registration of Diameter fields */
	proto_register_prefix("diameter", register_diameter_fields);

	/* Register dissector table(s) to do sub dissection of AVPs (OctetStrings) */
	diameter_dissector_table = register_dissector_table("diameter.base", "Diameter Base AVP", proto_diameter, FT_UINT32, BASE_DEC);
	diameter_3gpp_avp_dissector_table = register_dissector_table("diameter.3gpp", "Diameter 3GPP AVP", proto_diameter, FT_UINT32, BASE_DEC);
	diameter_ericsson_avp_dissector_table = register_dissector_table("diameter.ericsson", "Diameter Ericsson AVP", proto_diameter, FT_UINT32, BASE_DEC);
	diameter_verizon_avp_dissector_table = register_dissector_table("diameter.verizon", "DIAMETER_VERIZON_AVPS", proto_diameter, FT_UINT32, BASE_DEC);

	diameter_expr_result_vnd_table = register_dissector_table("diameter.vnd_exp_res", "Diameter Experimental-Result-Code", proto_diameter, FT_UINT32, BASE_DEC);

	/* Register configuration options */
	diameter_module = prefs_register_protocol(proto_diameter, NULL);
	/* For reading older preference files with "Diameter." preferences */
	prefs_register_module_alias("Diameter", diameter_module);

	/* Desegmentation */
	prefs_register_bool_preference(diameter_module, "desegment",
				       "Reassemble Diameter messages spanning multiple TCP segments",
				       "Whether the Diameter dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &gbl_diameter_desegment);

	/* conversation searching */
	prefs_register_bool_preference(diameter_module, "conversation",
		"Use IP/Port for request/response conversation",
		"Whether the Diameter dissector should use IP addresses and SCTP/TCP ports to find request/response conversation."
		" Conversation search will failed in cases of multi-homed SCTP or multiple TCP (loadshare more) connections."
		" In such cases need disable this option and only combination of End-To-End and Hop-By-Hop will be used to find request/response",
		&gbl_diameter_use_ip_port_for_conversation);

	prefs_register_bool_preference(diameter_module, "session_imsi",
		"Add \"Association IMSI\" to all messages in one session",
		"Take IMSI value of first AVP with E.212 encoding and add field \"Association IMSI\"(e212.assoc.imsi) to all messages"
		" with the same Session-Id",
		&gbl_diameter_session_imsi);

	/*  Register some preferences we no longer support, so we can report
	 *  them as obsolete rather than just illegal.
	 */
	prefs_register_obsolete_preference(diameter_module, "version");
	prefs_register_obsolete_preference(diameter_module, "command_in_header");
	prefs_register_obsolete_preference(diameter_module, "dictionary.name");
	prefs_register_obsolete_preference(diameter_module, "dictionary.use");
	prefs_register_obsolete_preference(diameter_module, "allow_zero_as_app_id");
	prefs_register_obsolete_preference(diameter_module, "suppress_console_output");

	/* Register tap */
	diameter_tap = register_tap("diameter");

	register_srt_table(proto_diameter, NULL, 1, diameterstat_packet, diameterstat_init, NULL);

} /* proto_register_diameter */

void
proto_reg_handoff_diameter(void)
{
	data_handle = find_dissector("data");
	eap_handle = find_dissector_add_dependency("eap", proto_diameter);

	dissector_add_uint("sctp.ppi", DIAMETER_PROTOCOL_ID, diameter_sctp_handle);

	heur_dissector_add("tcp", dissect_diameter_tcp_heur, "Diameter over TCP", "diameter_tcp", proto_diameter, HEURISTIC_DISABLE);

	ssl_dissector_add(DEFAULT_DIAMETER_TLS_PORT, diameter_tcp_handle);
	dtls_dissector_add(DEFAULT_DIAMETER_TLS_PORT, diameter_sctp_handle);

	/* Register special decoding for some AVPs */

	/* AVP Code: 1 User-Name */
	dissector_add_uint("diameter.base", 1, create_dissector_handle(dissect_diameter_user_name, proto_diameter));

	/* AVP Code: 79 EAP-Message (defined in RFC 2869, but used for EAP-TTLS, RFC 5281) */
	dissector_add_uint("diameter.base", 79, create_dissector_handle(dissect_diameter_eap_payload, proto_diameter));

	/* AVP Code: 97 Framed-IPv6-Address */
	dissector_add_uint("diameter.base", 97, create_dissector_handle(dissect_diameter_base_framed_ipv6_prefix, proto_diameter));

	/* AVP Code: 124 MIP6-Feature-Vector */
	dissector_add_uint("diameter.base", 124, create_dissector_handle(dissect_diameter_mip6_feature_vector, proto_diameter));

	/* AVP Code: 263 Session-Id */
	dissector_add_uint("diameter.base", 263, create_dissector_handle(dissect_diameter_session_id, proto_diameter));

	/* AVP Code: 265 Supported-Vendor-Id */
	dissector_add_uint("diameter.base", 265, create_dissector_handle(dissect_diameter_vendor_id, proto_diameter));

	/* AVP Code: 266 Vendor-Id */
	dissector_add_uint("diameter.base", 266, create_dissector_handle(dissect_diameter_vendor_id, proto_diameter));

	/* AVP Code: 268 Result-Code */
	dissector_add_uint("diameter.base", 268, create_dissector_handle(dissect_diameter_result_code, proto_diameter));

	/* AVP Code: 421 CC-Total-Octets */
	dissector_add_uint("diameter.base", 421, create_dissector_handle(dissect_diameter_cc_total_octets, proto_diameter));

	/* AVP Code: 432 Rating-Groupd */
	dissector_add_uint("diameter.base", 432, create_dissector_handle(dissect_diameter_rating_group, proto_diameter));

	/* AVP Code: 443 Subscription-Id */
	dissector_add_uint("diameter.base", 443, create_dissector_handle(dissect_diameter_subscription_id, proto_diameter));

	/* AVP Code: 450 Subscription-Id-Type */
	dissector_add_uint("diameter.base", 450, create_dissector_handle(dissect_diameter_subscription_id_type, proto_diameter));

	/* AVP Code: 444 Subscription-Id-Data */
	dissector_add_uint("diameter.base", 444, create_dissector_handle(dissect_diameter_subscription_id_data, proto_diameter));

	/* AVP Code: 458 User-Equipment-Info */
	dissector_add_uint("diameter.base", 458, create_dissector_handle(dissect_diameter_user_equipment_info, proto_diameter));

	/* AVP Code: 459 User-Equipment-Info-Type */
	dissector_add_uint("diameter.base", 459, create_dissector_handle(dissect_diameter_user_equipment_info_type, proto_diameter));

	/* AVP Code: 460 User-Equipment-Info-Value */
	dissector_add_uint("diameter.base", 460, create_dissector_handle(dissect_diameter_user_equipment_info_value, proto_diameter));

	/* AVP Code: 462 EAP-Payload */
	dissector_add_uint("diameter.base", 462, create_dissector_handle(dissect_diameter_eap_payload, proto_diameter));
	/* AVP Code: 463 EAP-Reissued-Payload */
	dissector_add_uint("diameter.base", 463, create_dissector_handle(dissect_diameter_eap_payload, proto_diameter));

	/* Register dissector for Experimental result code, with 3GPP2's vendor Id */
	dissector_add_uint("diameter.vnd_exp_res", VENDOR_THE3GPP2, create_dissector_handle(dissect_diameter_3gpp2_exp_res, proto_diameter));

	/* AVP Code: 1004 Charging-Rule-Base-Name */
	dissector_add_uint("diameter.3gpp", 1004, create_dissector_handle(dissect_diameter_3gpp_crbn, proto_diameter));

	dissector_add_uint_range_with_preference("tcp.port", DEFAULT_DIAMETER_PORT_RANGE, diameter_tcp_handle);
	dissector_add_uint_range_with_preference("udp.port", "", diameter_udp_handle);
	dissector_add_uint_range_with_preference("sctp.port", DEFAULT_DIAMETER_PORT_RANGE, diameter_sctp_handle);

	exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);

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
