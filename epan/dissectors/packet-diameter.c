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
#include <epan/diam_dict.h>
#include <epan/sctpppids.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/afn.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include "packet-tcp.h"
#include "packet-diameter.h"
#include "packet-tls.h"
#include "packet-dtls.h"
#include "packet-e212.h"
#include "packet-e164.h"

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

#if 0
#define DIAM_LENGTH_MASK  0x00ffffffl
#define DIAM_COMMAND_MASK DIAM_LENGTH_MASK
#define DIAM_GET_FLAGS(dh)                ((dh.flagsCmdCode & ~DIAM_COMMAND_MASK) >> 24)
#define DIAM_GET_VERSION(dh)              ((dh.versionLength & (~DIAM_LENGTH_MASK)) >> 24)
#define DIAM_GET_COMMAND(dh)              (dh.flagsCmdCode & DIAM_COMMAND_MASK)
#define DIAM_GET_LENGTH(dh)               (dh.versionLength & DIAM_LENGTH_MASK)
#endif

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

static gint exported_pdu_tap = -1;

/* Conversation Info */
typedef struct _diameter_conv_info_t {
	wmem_map_t *pdu_trees;
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
	guint32  code;
	wmem_array_t *vs_avps;
	value_string_ext *vs_avps_ext;
} diam_vnd_t;

struct _diam_avp_t {
	guint32 code;
	diam_vnd_t *vendor;
	diam_avp_dissector_t dissector_rfc;

	gint ett;
	int hf_value;
	void *type_data;
};

#define VND_AVP_VS(v)      ((value_string *)(void *)(wmem_array_get_raw((v)->vs_avps)))
#define VND_AVP_VS_LEN(v)  (wmem_array_get_count((v)->vs_avps))

typedef struct _diam_dictionary_t {
	wmem_tree_t *avps;
	wmem_tree_t *vnds;
	value_string_ext *applications;
	value_string *commands;
} diam_dictionary_t;

typedef diam_avp_t *(*avp_constructor_t)(const avp_type_t *, guint32, diam_vnd_t *, const char *,  const value_string *, void *);

struct _avp_type_t {
	const char *name;
	diam_avp_dissector_t rfc;
	enum ftenum ft;
	int base;
	avp_constructor_t build;
};

struct _build_dict {
	wmem_array_t *hf;
	GPtrArray    *ett;
	GHashTable   *types;
	GHashTable   *avps;
};


typedef struct _address_avp_t {
	gint ett;
	int hf_address_type;
	int hf_ipv4;
	int hf_ipv6;
	int hf_e164_str;
	int hf_other;
} address_avp_t;

typedef enum {
	REASEMBLE_NEVER = 0,
	REASEMBLE_AT_END,
	REASEMBLE_BY_LENGTH
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
static diam_dictionary_t dictionary = { NULL, NULL, NULL, NULL };
static struct _build_dict build_dict;
static const value_string *vnd_short_vs;
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

static int proto_diameter = -1;
static int hf_diameter_length = -1;
static int hf_diameter_code = -1;
static int hf_diameter_hopbyhopid =-1;
static int hf_diameter_endtoendid =-1;
static int hf_diameter_version = -1;
static int hf_diameter_vendor_id = -1;
static int hf_diameter_application_id = -1;
static int hf_diameter_flags = -1;
static int hf_diameter_flags_request = -1;
static int hf_diameter_flags_proxyable = -1;
static int hf_diameter_flags_error = -1;
static int hf_diameter_flags_T		= -1;
static int hf_diameter_flags_reserved4 = -1;
static int hf_diameter_flags_reserved5 = -1;
static int hf_diameter_flags_reserved6 = -1;
static int hf_diameter_flags_reserved7 = -1;

static int hf_diameter_avp = -1;
static int hf_diameter_avp_len = -1;
static int hf_diameter_avp_code = -1;
static int hf_diameter_avp_flags = -1;
static int hf_diameter_avp_flags_vendor_specific = -1;
static int hf_diameter_avp_flags_mandatory = -1;
static int hf_diameter_avp_flags_protected = -1;
static int hf_diameter_avp_flags_reserved3 = -1;
static int hf_diameter_avp_flags_reserved4 = -1;
static int hf_diameter_avp_flags_reserved5 = -1;
static int hf_diameter_avp_flags_reserved6 = -1;
static int hf_diameter_avp_flags_reserved7 = -1;
static int hf_diameter_avp_vendor_id = -1;
static int hf_diameter_avp_data_wrong_length = -1;
static int hf_diameter_avp_pad = -1;

static int hf_diameter_answer_in = -1;
static int hf_diameter_answer_to = -1;
static int hf_diameter_answer_time = -1;

/* AVPs with special/extra decoding */
static int hf_framed_ipv6_prefix_reserved = -1;
static int hf_framed_ipv6_prefix_length = -1;
static int hf_framed_ipv6_prefix_bytes = -1;
static int hf_framed_ipv6_prefix_ipv6 = -1;
static int hf_diameter_3gpp2_exp_res = -1;
static int hf_diameter_other_vendor_exp_res = -1;
static int hf_diameter_mip6_feature_vector = -1;
static int hf_diameter_mip6_feature_vector_mip6_integrated = -1;
static int hf_diameter_mip6_feature_vector_local_home_agent_assignment = -1;
static int hf_diameter_mip6_feature_vector_pmip6_supported = -1;
static int hf_diameter_mip6_feature_vector_ip4_hoa_supported = -1;
static int hf_diameter_mip6_feature_vector_local_mag_routing_supported = -1;
static int hf_diameter_3gpp_mip6_feature_vector = -1;
static int hf_diameter_3gpp_mip6_feature_vector_assign_local_ip = -1;
static int hf_diameter_3gpp_mip6_feature_vector_mip4_supported = -1;
static int hf_diameter_3gpp_mip6_feature_vector_optimized_idle_mode_mobility = -1;
static int hf_diameter_3gpp_mip6_feature_vector_gtpv2_supported = -1;
static int hf_diameter_user_equipment_info_imeisv = -1;
static int hf_diameter_user_equipment_info_mac = -1;
static int hf_diameter_user_equipment_info_eui64 = -1;
static int hf_diameter_user_equipment_info_modified_eui64 = -1;

static gint ett_diameter = -1;
static gint ett_diameter_flags = -1;
static gint ett_diameter_avp_flags = -1;
static gint ett_diameter_avpinfo = -1;
static gint ett_unknown = -1;
static gint ett_diameter_mip6_feature_vector = -1;
static gint ett_diameter_3gpp_mip6_feature_vector = -1;

static expert_field ei_diameter_reserved_bit_set = EI_INIT;
static expert_field ei_diameter_avp_len = EI_INIT;
static expert_field ei_diameter_avp_no_data = EI_INIT;
static expert_field ei_diameter_application_id = EI_INIT;
static expert_field ei_diameter_version = EI_INIT;
static expert_field ei_diameter_avp_pad = EI_INIT;
static expert_field ei_diameter_avp_pad_missing = EI_INIT;
static expert_field ei_diameter_code = EI_INIT;
static expert_field ei_diameter_avp_code = EI_INIT;
static expert_field ei_diameter_avp_vendor_id = EI_INIT;
static expert_field ei_diameter_invalid_ipv6_prefix_len = EI_INIT;
static expert_field ei_diameter_invalid_avp_len = EI_INIT;
static expert_field ei_diameter_invalid_user_equipment_info_value_len = EI_INIT;
static expert_field ei_diameter_unexpected_imei_as_user_equipment_info = EI_INIT;

/* Tap for Diameter */
static int diameter_tap = -1;

/* For conversations */

static dissector_handle_t diameter_udp_handle;
static dissector_handle_t diameter_tcp_handle;
static dissector_handle_t diameter_sctp_handle;
static range_t *global_diameter_sctp_port_range;
/* This is IANA registered for TCP and SCTP (and reserved for UDP) */
#define DEFAULT_DIAMETER_PORT_RANGE "3868"
/* This is IANA registered for TLS/TCP and DTLS/SCTP (and reserved for UDP) */
#define DEFAULT_DIAMETER_TLS_PORT 5868

/* desegmentation of Diameter over TCP */
static gboolean gbl_diameter_desegment = TRUE;

/* Dissector tables */
static dissector_table_t diameter_dissector_table;
static dissector_table_t diameter_3gpp_avp_dissector_table;
static dissector_table_t diameter_ericsson_avp_dissector_table;
static dissector_table_t diameter_verizon_avp_dissector_table;
static dissector_table_t diameter_expr_result_vnd_table;

static const char *avpflags_str[] = {
	"---",
	"--P",
	"-M-",
	"-MP",
	"V--",
	"V-P",
	"VM-",
	"VMP",
};

#define SUBSCRIPTION_ID_TYPE_E164	0
#define SUBSCRIPTION_ID_TYPE_IMSI	1
#define SUBSCRIPTION_ID_TYPE_SIP_URI	2
#define SUBSCRIPTION_ID_TYPE_NAI	3
#define SUBSCRIPTION_ID_TYPE_PRIVATE	4
#define SUBSCRIPTION_ID_TYPE_UNKNOWN (guint32)-1

#define USER_EQUIPMENT_INFO_TYPE_IMEISV			0
#define USER_EQUIPMENT_INFO_TYPE_MAC			1
#define USER_EQUIPMENT_INFO_TYPE_EUI64			2
#define USER_EQUIPMENT_INFO_TYPE_MODIFIED_EUI64	3
#define USER_EQUIPMENT_INFO_TYPE_UNKNOWN (guint32)-1

static void
export_diameter_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
	exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "diameter", EXP_PDU_TAG_PROTO_NAME);

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

static GHashTable* diameterstat_cmd_str_hash = NULL;
#define DIAMETER_NUM_PROCEDURES     1

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

	/** @todo the filter to use in stead of NULL is "diameter.cmd.code"
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
	guint i = 0;
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
		g_hash_table_insert(diameterstat_cmd_str_hash, (gchar*) diameter->cmd_str, idx);
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
dissect_diameter_eap_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	gboolean save_writable;

	/* Ensure the packet is displayed as Diameter, not EAP */
	save_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
	col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);

	call_dissector(eap_handle, tvb, pinfo, tree);

	col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_writable);
	return tvb_reported_length(tvb);
}

/* https://www.3gpp2.org/Public_html/X/VSA-VSE.cfm */
static const value_string diameter_3gpp2_exp_res_vals[]= {
	{ 5001,	"Diameter_Error_User_No_WLAN_Subscription"},
	{ 5002,	"Diameter_Error_Roaming_Not_Allowed(Obsoleted)"},
	{ 5003,	"Diameter_Error_User_No_FAP_Subscription"},
	{0,NULL}
};

static int
dissect_diameter_3gpp2_exp_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
	proto_item *pi;
	diam_sub_dis_t *diam_sub_dis;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	diam_sub_dis = (diam_sub_dis_t*)data;

	if (tree) {
		pi = proto_tree_add_item(tree, hf_diameter_3gpp2_exp_res, tvb, 0, 4, ENC_BIG_ENDIAN);
		diam_sub_dis->avp_str = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), diam_sub_dis->avp_str);
		diam_sub_dis->avp_str = strstr(diam_sub_dis->avp_str,": ")+2;
	}

	return 4;
}

static void
dissect_diameter_other_vendor_exp_res(tvbuff_t *tvb, proto_tree *tree, diam_sub_dis_t *diam_sub_dis)
{
	proto_item *pi;

	if (tree) {
		pi = proto_tree_add_item(tree, hf_diameter_other_vendor_exp_res, tvb, 0, 4, ENC_BIG_ENDIAN);
		diam_sub_dis->avp_str = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), diam_sub_dis->avp_str);
		diam_sub_dis->avp_str = strstr(diam_sub_dis->avp_str,": ")+2;
	}
}

/* From RFC 3162 section 2.3 */
static int
dissect_diameter_base_framed_ipv6_prefix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;
	guint32 prefix_len, prefix_len_bytes;
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
		tvb_memcpy(tvb, (guint8 *)&value.bytes, 2, prefix_len_bytes);
		value.bytes[prefix_len_bytes] = value.bytes[prefix_len_bytes] & (0xff<<(prefix_len % 8));
		proto_tree_add_ipv6(tree, hf_framed_ipv6_prefix_ipv6, tvb, 2, prefix_len_bytes, &value);
		set_address(&addr, AT_IPv6, 16, value.bytes);
		diam_sub_dis->avp_str = wmem_strdup_printf(wmem_packet_scope(), "%s/%u", address_to_str(wmem_packet_scope(), &addr), prefix_len);
	}

	return(prefix_len_bytes+2);
}

/* AVP Code: 1 User-Name */
/* Do special decoding of the User-Name depending on the interface */
static int
dissect_diameter_user_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;
	guint32 application_id = 0, str_len;

	if (diam_sub_dis) {
		application_id = diam_sub_dis->application_id;
	}

	switch (application_id) {
	case DIAM_APPID_3GPP_S6A_S6D:
	case DIAM_APPID_3GPP_SLH:
	case DIAM_APPID_3GPP_S7A:
		str_len = tvb_reported_length(tvb);
		dissect_e212_utf8_imsi(tvb, pinfo, tree, 0, str_len);
		return str_len;
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

	guint32 application_id = 0;
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
	guint32 str_len;
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	guint32 subscription_id_type = diam_sub_dis_inf->subscription_id_type;

	switch (subscription_id_type) {
	case SUBSCRIPTION_ID_TYPE_IMSI:
		str_len = tvb_reported_length(tvb);
		dissect_e212_utf8_imsi(tvb, pinfo, tree, 0, str_len);
		return str_len;
	case SUBSCRIPTION_ID_TYPE_E164:
		str_len = tvb_reported_length(tvb);
		dissect_e164_msisdn(tvb, tree, 0, str_len, E164_ENC_UTF8);
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
	guint32 len;
	diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;
	guint32 user_equipment_info_type = diam_sub_dis_inf->user_equipment_info_type;

	switch (user_equipment_info_type) {
	case USER_EQUIPMENT_INFO_TYPE_IMEISV:
		/* RFC 8506 section 8.53, 3GPP TS 23.003 */
		len = tvb_reported_length(tvb);
		/* IMEISV is 16 digits, but often transmitted BCD coded in 8 octets.
		   Some implementations use IMEI (15 digits) instead of IMEISV */
		if (len == 8) {
			proto_tree_add_item(tree, hf_diameter_user_equipment_info_imeisv, tvb, 0, len, ENC_BCD_DIGITS_0_9|ENC_NA);
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
call_avp_subdissector(guint32 vendorid, guint32 code, tvbuff_t *subtvb, packet_info *pinfo, proto_tree *avp_tree, diam_sub_dis_t *diam_sub_dis_inf)
{
	TRY {
		switch (vendorid) {
		case 0:
			dissector_try_uint_new(diameter_dissector_table, code, subtvb, pinfo, avp_tree, FALSE, diam_sub_dis_inf);
			break;
		case VENDOR_ERICSSON:
			dissector_try_uint_new(diameter_ericsson_avp_dissector_table, code, subtvb, pinfo, avp_tree, FALSE, diam_sub_dis_inf);
			break;
		case VENDOR_VERIZON:
			dissector_try_uint_new(diameter_verizon_avp_dissector_table, code, subtvb, pinfo, avp_tree, FALSE, diam_sub_dis_inf);
			break;
		case VENDOR_THE3GPP:
			dissector_try_uint_new(diameter_3gpp_avp_dissector_table, code, subtvb, pinfo, avp_tree, FALSE, diam_sub_dis_inf);
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
dissect_diameter_avp(diam_ctx_t *c, tvbuff_t *tvb, int offset, diam_sub_dis_t *diam_sub_dis_inf, gboolean update_col_info)
{
	guint32 code           = tvb_get_ntohl(tvb,offset);
	guint32 len            = tvb_get_ntohl(tvb,offset+4);
	guint32 vendor_flag    = len & 0x80000000;
	guint32 flags_bits_idx = (len & 0xE0000000) >> 29;
	guint32 flags_bits     = (len & 0xFF000000) >> 24;
	guint32 vendorid       = vendor_flag ? tvb_get_ntohl(tvb,offset+8) : 0 ;
	wmem_tree_key_t k[3];
	diam_avp_t *a;
	proto_item *pi, *avp_item;
	proto_tree *avp_tree, *save_tree;
	tvbuff_t *subtvb;
	diam_vnd_t *vendor;
	const char *code_str;
	const char *avp_str = NULL;
	guint8 pad_len;

	k[0].length = 1;
	k[0].key = &code;

	k[1].length = 1;
	k[1].key = &vendorid;

	k[2].length = 0;
	k[2].key = NULL;

	a = (diam_avp_t *)wmem_tree_lookup32_array(dictionary.avps,k);

	len &= 0x00ffffff;
	pad_len =  (len % 4) ? 4 - (len % 4) : 0 ;

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
		vendor->vs_avps_ext = value_string_ext_new(VND_AVP_VS(vendor),
							   VND_AVP_VS_LEN(vendor)+1,
							   wmem_strdup_printf(wmem_epan_scope(), "diameter_vendor_%s",
									   enterprises_lookup(vendorid, "Unknown")));
#if 0
		{ /* Debug code */
			value_string *vendor_avp_vs = VALUE_STRING_EXT_VS_P(vendor->vs_avps_ext);
			gint i = 0;
			while (vendor_avp_vs[i].strptr != NULL) {
				ws_warning("%u %s", vendor_avp_vs[i].value, vendor_avp_vs[i].strptr);
				i++;
			}
		}
#endif
	}
	/* Check if the length is sane */
	if (len > (guint32)tvb_reported_length_remaining(tvb, offset)) {
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
		pad_len = (guint32)tvb_reported_length_remaining(tvb, offset + len);
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

	proto_item_set_text(avp_item,"AVP: %s(%u) l=%u f=%s", code_str, code, len, avpflags_str[flags_bits_idx]);
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
	proto_tree_add_item(avp_tree,hf_diameter_avp_len,tvb,offset,3,ENC_BIG_ENDIAN);
	offset += 3;

	/* Vendor flag */
	if (vendor_flag) {
		proto_item_append_text(avp_item," vnd=%s", val_to_str(vendorid, vnd_short_vs, "%d"));
		pi = proto_tree_add_item(avp_tree,hf_diameter_avp_vendor_id,tvb,offset,4,ENC_BIG_ENDIAN);
		if (vendor == &unknown_vendor) {
			proto_tree *tu = proto_item_add_subtree(pi,ett_unknown);
			proto_tree_add_expert(tu, c->pinfo, &ei_diameter_avp_vendor_id, tvb, offset, 4);
		}
		offset += 4;
	}

	if ( len == (guint32)(vendor_flag ? 12 : 8) ) {
		/* Data is empty so return now */
		proto_tree_add_expert(avp_tree, c->pinfo, &ei_diameter_avp_no_data, tvb, offset, 0);
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
		if (!dissector_try_uint_new(diameter_expr_result_vnd_table, diam_sub_dis_inf->vendor_id,
					    subtvb, c->pinfo, avp_tree, FALSE, diam_sub_dis_inf)) {
			/* No subdissector for this vendor ID, use the generic one */
			dissect_diameter_other_vendor_exp_res(subtvb, avp_tree, diam_sub_dis_inf);
		}

		if (diam_sub_dis_inf->avp_str) {
			proto_item_append_text(avp_item," val=%s", diam_sub_dis_inf->avp_str);
		}
	} else {
		avp_str = a->dissector_rfc(c,a,subtvb, diam_sub_dis_inf);
	}
	c->tree = save_tree;

	diam_sub_dis_inf->avp_str = NULL;
	call_avp_subdissector(vendorid, code, subtvb, c->pinfo, avp_tree, diam_sub_dis_inf);

	/* Let the subdissector have precedence filling in the avp_item string */
	if (diam_sub_dis_inf->avp_str) {
		proto_item_append_text(avp_item," val=%s", diam_sub_dis_inf->avp_str);
	} else if (avp_str) {
		proto_item_append_text(avp_item," val=%s", avp_str);
	}


	if (pad_len) {
		guint8 i;

		pi = proto_tree_add_item(avp_tree, hf_diameter_avp_pad, tvb, offset, pad_len, ENC_NA);
		for (i=0; i < pad_len; i++) {
			if (tvb_get_guint8(tvb, offset++) != 0) {
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
	gint len = tvb_reported_length(tvb);
	proto_item *pi = proto_tree_add_item(c->tree, a->hf_value, tvb, 0, len, ENC_BIG_ENDIAN);
	proto_tree *pt = proto_item_add_subtree(pi,t->ett);
	guint32 addr_type;
	len = len-2;

	proto_tree_add_item_ret_uint(pt, t->hf_address_type, tvb, 0, 2, ENC_NA, &addr_type);
	/* See afn.h and https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml */
	switch (addr_type ) {
		case AFNUM_INET:
			if (len != 4) {
				proto_tree_add_expert_format(pt, c->pinfo, &ei_diameter_avp_len, tvb, 2, len, "Wrong length for IPv4 Address: %d instead of 4", len);
				return "[Malformed]";
			}
			pi = proto_tree_add_item(pt,t->hf_ipv4,tvb,2,4,ENC_BIG_ENDIAN);
			break;
		case AFNUM_INET6:
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
		label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label);
		label = strstr(label,": ")+2;
	}

	return label;
}

static const char *
proto_avp(diam_ctx_t *c, diam_avp_t *a, tvbuff_t *tvb, diam_sub_dis_t *diam_sub_dis_inf)
{
	proto_avp_t *t = (proto_avp_t *)a->type_data;

	col_set_writable(c->pinfo->cinfo, COL_PROTOCOL, FALSE);
	col_set_writable(c->pinfo->cinfo, COL_INFO, FALSE);

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
		label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		pi = proto_tree_add_item(c->tree, (a->hf_value), tvb, 0, 4, ENC_TIME_SECS_NTP|ENC_BIG_ENDIAN);
		proto_item_fill_label(PITEM_FINFO(pi), label);
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
	guint32 len = tvb_reported_length(tvb);

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
		label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label);
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
		label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label);
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
		label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
		proto_item_fill_label(PITEM_FINFO(pi), label);
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
	gint length = tvb_reported_length(tvb);
	if (length == 4) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label);
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
	gint length = tvb_reported_length(tvb);
	if (length == 8) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label);
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
	gint length = tvb_reported_length(tvb);
	if (length == 4) {
		if (c->tree) {
			diam_sub_dis_inf->item = pi = proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label);
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
	gint length = tvb_reported_length(tvb);
	if (length == 8) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label);
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
	gint length = tvb_reported_length(tvb);
	if (length == 4) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree,a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label);
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
	gint length = tvb_reported_length(tvb);
	if (length == 8) {
		if (c->tree) {
			pi= proto_tree_add_item(c->tree, a->hf_value, tvb, 0, length, ENC_BIG_ENDIAN);
			label = (char *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH+1);
			proto_item_fill_label(PITEM_FINFO(pi), label);
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
	proto_item *pi = proto_tree_add_item(c->tree, a->hf_value, tvb , 0 , -1, ENC_BIG_ENDIAN);
	proto_tree *pt = c->tree;

	c->tree = proto_item_add_subtree(pi,a->ett);

	/* Set the flag that we are dissecting a grouped AVP */
	diam_sub_dis_inf->dis_gouped = TRUE;
	while (offset < len) {
		offset += dissect_diameter_avp(c, tvb, offset, diam_sub_dis_inf, FALSE);
	}
	/* Clear info collected in grouped AVP */
	diam_sub_dis_inf->vendor_id  = 0;
	diam_sub_dis_inf->dis_gouped = FALSE;
	diam_sub_dis_inf->avp_str = NULL;

	c->tree = pt;

	return NULL;
}

static const char *msgflags_str[] = {
	"----", "---T", "--E-", "--ET",
	"-P--", "-P-T", "-PE-", "-PET",
	"R---", "R--T", "R-E-", "R-ET",
	"RP--", "RP-T", "RPE-", "RPET"
};

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
	guint32 version;
	guint64 flags_bits;
	int packet_len;
	proto_item *pi, *cmd_item, *app_item, *version_item;
	proto_tree *diam_tree;
	diam_ctx_t *c = wmem_new0(wmem_packet_scope(), diam_ctx_t);
	int offset;
	const char *cmd_str;
	guint32 cmd;
	guint32 hop_by_hop_id, end_to_end_id;
	conversation_t *conversation;
	diameter_conv_info_t *diameter_conv_info;
	diameter_req_ans_pair_t *diameter_pair = NULL;
	wmem_tree_t *pdus_tree;
	proto_item *it;
	nstime_t ns;
	diam_sub_dis_t *diam_sub_dis_inf = wmem_new0(wmem_packet_scope(), diam_sub_dis_t);

	/* Set default value Subscription-Id-Type and User-Equipment-Info-Type as XXX_UNKNOWN */
	diam_sub_dis_inf->subscription_id_type = SUBSCRIPTION_ID_TYPE_UNKNOWN;
	diam_sub_dis_inf->user_equipment_info_type = USER_EQUIPMENT_INFO_TYPE_UNKNOWN;

	/* Load header fields if not already done */
	if (hf_diameter_code == -1)
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

	col_add_fstr(pinfo->cinfo, COL_INFO,
			 "cmd=%s%s(%d) flags=%s %s=%s(%d) h2h=%x e2e=%x",
			 cmd_str,
			 ((flags_bits>>4)&0x08) ? " Request" : " Answer",
			 cmd,
			 msgflags_str[((flags_bits>>4)&0x0f)],
			 "appl",
			 val_to_str_ext_const(diam_sub_dis_inf->application_id, dictionary.applications, "Unknown"),
			 diam_sub_dis_inf->application_id,
			 hop_by_hop_id,
			 end_to_end_id);

	col_append_str(pinfo->cinfo, COL_INFO, " | ");
	col_set_fence(pinfo->cinfo, COL_INFO);


	/* Conversation tracking stuff */
	/*
	 * FIXME: Looking at epan/conversation.c it seems unlikely that this will work properly in
	 * multi-homed SCTP connections. This will probably need to be fixed at some point.
	 */

	conversation = find_or_create_conversation(pinfo);

	diameter_conv_info = (diameter_conv_info_t *)conversation_get_proto_data(conversation, proto_diameter);
	if (!diameter_conv_info) {
		diameter_conv_info = wmem_new(wmem_file_scope(), diameter_conv_info_t);
		diameter_conv_info->pdu_trees = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

		conversation_add_proto_data(conversation, proto_diameter, diameter_conv_info);
	}

	/* pdus_tree is an wmem_tree keyed by frame number (in order to handle hop-by-hop collisions */
	pdus_tree = (wmem_tree_t *)wmem_map_lookup(diameter_conv_info->pdu_trees, GUINT_TO_POINTER(hop_by_hop_id));

	if (pdus_tree == NULL && (flags_bits & DIAM_FLAGS_R)) {
		/* This is the first request we've seen with this hop-by-hop id */
		pdus_tree = wmem_tree_new(wmem_file_scope());
		wmem_map_insert(diameter_conv_info->pdu_trees, GUINT_TO_POINTER(hop_by_hop_id), pdus_tree);
	}

	if (pdus_tree) {
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
				wmem_tree_insert32(pdus_tree, pinfo->num, (void *)diameter_pair);
			} else {
				/* Look for a request which occurs earlier in the trace than this answer. */
				diameter_pair = (diameter_req_ans_pair_t *)wmem_tree_lookup32_le(pdus_tree, pinfo->num);

				/* Verify the end-to-end-id matches before declaring a match */
				if (diameter_pair && diameter_pair->end_to_end_id == end_to_end_id) {
					diameter_pair->ans_frame = pinfo->num;
				}
			}
		} else {
			/* Look for a request which occurs earlier in the trace than this answer. */
			diameter_pair = (diameter_req_ans_pair_t *)wmem_tree_lookup32_le(pdus_tree, pinfo->num);

			/* If the end-to-end ID doesn't match then this is not the request we were
			 * looking for.
			 */
			if (diameter_pair && diameter_pair->end_to_end_id != end_to_end_id)
				diameter_pair = NULL;
		}
	}

	if (!diameter_pair) {
		/* create a "fake" diameter_pair structure */
		diameter_pair = wmem_new(wmem_packet_scope(), diameter_req_ans_pair_t);
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
	while (offset < packet_len) {
		offset += dissect_diameter_avp(c, tvb, offset, diam_sub_dis_inf, FALSE);
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

static guint
get_diameter_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
	/* Get the length of the Diameter packet. */
	return tvb_get_ntoh24(tvb, offset + 1);
}

#define NOT_DIAMETER	0
#define IS_DIAMETER	1
#define NOT_ENOUGH_DATA 2
static gint
check_diameter(tvbuff_t *tvb)
{
	guint8 flags;
	guint32 msg_len;

	/* Ensure we don't throw an exception trying to do these heuristics */
	if (tvb_captured_length(tvb) < 5)
		return NOT_ENOUGH_DATA;

	/* Check if the Diameter version is 1 */
	if (tvb_get_guint8(tvb, 0) != 1)
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

	flags = tvb_get_guint8(tvb, 4);

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
	gint is_diam = check_diameter(tvb);

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

static gboolean
dissect_diameter_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (check_diameter(tvb) != IS_DIAMETER) {
		return FALSE;
	}

	conversation_set_dissector(find_or_create_conversation(pinfo), diameter_tcp_handle);

	tcp_dissect_pdus(tvb, pinfo, tree, gbl_diameter_desegment, 4,
			 get_diameter_pdu_len, dissect_diameter_common, data);

	return TRUE;
}

static int
dissect_diameter_avps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *pi;
	proto_tree *diam_tree;
	int offset = 0;
	diam_ctx_t *c = wmem_new0(wmem_packet_scope(), diam_ctx_t);
	diam_sub_dis_t *diam_sub_dis_inf = wmem_new0(wmem_packet_scope(), diam_sub_dis_t);

	/* Load header fields if not already done */
	if (hf_diameter_code == -1)
		proto_registrar_get_byname("diameter.code");

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DIAMETER");
	col_set_str(pinfo->cinfo, COL_INFO, "AVPs:");

	pi = proto_tree_add_item(tree, proto_diameter, tvb, 0, -1, ENC_NA);
	diam_tree = proto_item_add_subtree(pi, ett_diameter);
	c->tree = diam_tree;
	c->pinfo = pinfo;

	/* Dissect AVPs until the end of the packet is reached */
	while (tvb_reported_length_remaining(tvb, offset)) {
		offset += dissect_diameter_avp(c, tvb, offset, diam_sub_dis_inf, TRUE);
	}
	return tvb_reported_length(tvb);
}

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


static guint
reginfo(int *hf_ptr, const char *name, const char *abbr, const char *desc,
	enum ftenum ft, field_display_e base, value_string_ext *vs_ext,
	guint32 mask)
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

	wmem_array_append_one(build_dict.hf,hf);
	return wmem_array_get_count(build_dict.hf);
}

static void
basic_avp_reginfo(diam_avp_t *a, const char *name, enum ftenum ft,
		  field_display_e base, value_string_ext *vs_ext)
{
	hf_register_info hf;
	gint *ettp = &(a->ett);

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

	wmem_array_append(build_dict.hf,&hf,1);
	g_ptr_array_add(build_dict.ett,ettp);
}

static diam_avp_t *
build_address_avp(const avp_type_t *type _U_, guint32 code,
		  diam_vnd_t *vendor, const char *name,
		  const value_string *vs _U_, void *data _U_)
{
	diam_avp_t *a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	address_avp_t *t = wmem_new(wmem_epan_scope(), address_avp_t);
	gint *ettp = &(t->ett);

	a->code = code;
	a->vendor = vendor;
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
	if (code<256) {
		a->dissector_rfc = address_radius_avp;
	} else {
		a->dissector_rfc = address_rfc_avp;
	}
	a->ett = -1;
	a->hf_value = -1;
	a->type_data = t;

	t->ett = -1;
	t->hf_address_type = -1;
	t->hf_ipv4 = -1;
	t->hf_ipv6 = -1;
	t->hf_e164_str = -1;
	t->hf_other = -1;

	basic_avp_reginfo(a, name, FT_BYTES, BASE_NONE, NULL);

	reginfo(&(t->hf_address_type), wmem_strconcat(wmem_epan_scope(), name, " Address Family", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".addr_family", NULL)),
		NULL, FT_UINT16, (field_display_e)(BASE_DEC|BASE_EXT_STRING), &diameter_avp_data_addrfamily_vals_ext, 0);

	reginfo(&(t->hf_ipv4), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".IPv4", NULL)),
		NULL, FT_IPv4, BASE_NONE, NULL, 0);

	reginfo(&(t->hf_ipv6), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".IPv6", NULL)),
		NULL, FT_IPv6, BASE_NONE, NULL, 0);

	reginfo(&(t->hf_e164_str), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".E164", NULL)),
		NULL, FT_STRING, BASE_NONE, NULL, 0);

	reginfo(&(t->hf_other), wmem_strconcat(wmem_epan_scope(), name, " Address", NULL),
		alnumerize(wmem_strconcat(wmem_epan_scope(), "diameter.", name, ".Bytes", NULL)),
		NULL, FT_BYTES, BASE_NONE, NULL, 0);

	g_ptr_array_add(build_dict.ett,ettp);

	return a;
}

static diam_avp_t *
build_proto_avp(const avp_type_t *type _U_, guint32 code,
		diam_vnd_t *vendor, const char *name _U_,
		const value_string *vs _U_, void *data)
{
	diam_avp_t *a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	proto_avp_t *t = wmem_new0(wmem_epan_scope(), proto_avp_t);
	gint *ettp = &(a->ett);

	a->code = code;
	a->vendor = vendor;
	a->dissector_rfc = proto_avp;
	a->ett = -1;
	a->hf_value = -2;
	a->type_data = t;

	t->name = (char *)data;
	t->handle = NULL;
	t->reassemble_mode = REASEMBLE_NEVER;

	g_ptr_array_add(build_dict.ett,ettp);

	return a;
}

static diam_avp_t *
build_simple_avp(const avp_type_t *type, guint32 code, diam_vnd_t *vendor,
		 const char *name, const value_string *vs, void *data _U_)
{
	diam_avp_t *a;
	value_string_ext *vs_ext = NULL;
	field_display_e base;
	guint i = 0;

	/*
	 * Only 32-bit or shorter integral types can have a list of values.
	 */
	base = (field_display_e)type->base;
	if (vs != NULL) {
		switch (type->ft) {

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT32:
			break;

		default:
			report_failure("Diameter Dictionary: AVP '%s' has a list of values but isn't of a 32-bit or shorter integral type (%s)\n",
				name, ftype_name(type->ft));
			return NULL;
		}
		while (vs[i].strptr) {
		  i++;
		}
		vs_ext = value_string_ext_new(vs, i+1, wmem_strconcat(wmem_epan_scope(), name, "_vals_ext", NULL));
		base = (field_display_e)(base|BASE_EXT_STRING);
	}

	a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	a->code = code;
	a->vendor = vendor;
	a->dissector_rfc = type->rfc;
	a->ett = -1;
	a->hf_value = -1;

	basic_avp_reginfo(a, name, type->ft, base, vs_ext);

	return a;
}

static diam_avp_t *
build_appid_avp(const avp_type_t *type, guint32 code, diam_vnd_t *vendor,
		const char *name, const value_string *vs, void *data _U_)
{
	diam_avp_t *a;
	field_display_e base;

	a = wmem_new0(wmem_epan_scope(), diam_avp_t);
	a->code = code;
	a->vendor = vendor;
	a->dissector_rfc = type->rfc;
	a->ett = -1;
	a->hf_value = -1;

	if (vs != NULL) {
		report_failure("Diameter Dictionary: AVP '%s' (of type AppId) has a list of values but the list won't be used\n",
				name);
	}

	base = (field_display_e)(type->base|BASE_EXT_STRING);

	basic_avp_reginfo(a, name, type->ft, base, dictionary.applications);
	return a;
}

static const avp_type_t basic_types[] = {
	{"octetstring"			, simple_avp		, FT_BYTES			, BASE_NONE			, build_simple_avp  },
	{"octetstringorutf8"	, simple_avp		, FT_BYTES			, BASE_SHOW_ASCII_PRINTABLE	, build_simple_avp  },
	{"utf8string"			, utf8_avp			, FT_STRING			, BASE_NONE			, build_simple_avp  },
	{"grouped"				, grouped_avp		, FT_BYTES			, BASE_NONE			, build_simple_avp  },
	{"integer32"			, integer32_avp		, FT_INT32			, BASE_DEC			, build_simple_avp  },
	{"unsigned32"			, unsigned32_avp	, FT_UINT32			, BASE_DEC			, build_simple_avp  },
	{"integer64"			, integer64_avp		, FT_INT64			, BASE_DEC			, build_simple_avp  },
	{"unsigned64"			, unsigned64_avp	, FT_UINT64			, BASE_DEC			, build_simple_avp  },
	{"float32"				, float32_avp		, FT_FLOAT			, BASE_NONE			, build_simple_avp  },
	{"float64"				, float64_avp		, FT_DOUBLE			, BASE_NONE			, build_simple_avp  },
	{"ipaddress"			, NULL				, FT_NONE			, BASE_NONE			, build_address_avp },
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
static guint
strcase_hash(gconstpointer key)
{
	const char *p = (const char *)key;
	guint h = *p;
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
strcase_equal(gconstpointer ka, gconstpointer kb)
{
	const char *a = (const char *)ka;
	const char *b = (const char *)kb;
	return g_ascii_strcasecmp(a,b) == 0;
}

static gboolean
ddict_cleanup_cb(wmem_allocator_t* allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
	ddict_t *d = (ddict_t *)user_data;
	ddict_free(d);
	return FALSE;
}


/* Note: Dynamic "value string arrays" (e.g., vs_avps, ...) are constructed using */
/*       "zero-terminated" GArrays so that they will have the same form as standard        */
/*       value_string arrays created at compile time. Since the last entry in a            */
/*       value_string array must be {0, NULL}, we are assuming that NULL == 0 (hackish).   */

static int
dictionary_load(void)
{
	ddict_t *d;
	ddict_application_t *p;
	ddict_vendor_t *v;
	ddict_cmd_t *c;
	ddict_typedefn_t *t;
	ddict_avp_t *a;
	gboolean do_debug_parser = getenv("WIRESHARK_DEBUG_DIAM_DICT_PARSER") ? TRUE : FALSE;
	gboolean do_dump_dict = getenv("WIRESHARK_DUMP_DIAM_DICT") ? TRUE : FALSE;
	char *dir;
	const avp_type_t *type;
	const avp_type_t *octetstring = &basic_types[0];
	diam_avp_t *avp;
	GHashTable *vendors = g_hash_table_new(strcase_hash,strcase_equal);
	diam_vnd_t *vnd;
	GArray *vnd_shrt_arr = g_array_new(TRUE,TRUE,sizeof(value_string));
	GArray *all_cmds = g_array_new(TRUE,TRUE,sizeof(value_string));

	/* Pre allocate the arrays big enough to hold the hf:s and etts:s*/
	build_dict.hf = wmem_array_sized_new(wmem_epan_scope(), sizeof(hf_register_info), 4096);
	build_dict.ett = g_ptr_array_sized_new(4096);
	build_dict.types = g_hash_table_new(strcase_hash,strcase_equal);
	build_dict.avps = g_hash_table_new(strcase_hash,strcase_equal);

	dictionary.vnds = wmem_tree_new(wmem_epan_scope());
	dictionary.avps = wmem_tree_new(wmem_epan_scope());

	unknown_vendor.vs_avps = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
	wmem_array_set_null_terminator(unknown_vendor.vs_avps);
	wmem_array_bzero(unknown_vendor.vs_avps);
	no_vnd.vs_avps = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
	wmem_array_set_null_terminator(no_vnd.vs_avps);
	wmem_array_bzero(no_vnd.vs_avps);

	wmem_tree_insert32(dictionary.vnds,0,&no_vnd);
	g_hash_table_insert(vendors,"None",&no_vnd);

	/* initialize the types hash with the known basic types */
	for (type = basic_types; type->name; type++) {
		g_hash_table_insert(build_dict.types,(gchar *)type->name,(void *)type);
	}

	/* load the dictionary */
	dir = wmem_strdup_printf(NULL, "%s" G_DIR_SEPARATOR_S "diameter" G_DIR_SEPARATOR_S, get_datafile_dir());
	d = ddict_scan(dir,"dictionary.xml",do_debug_parser);
	wmem_free(NULL, dir);
	if (d == NULL) {
		g_hash_table_destroy(vendors);
		g_array_free(vnd_shrt_arr, TRUE);
		return 0;
	}
	wmem_register_callback(wmem_epan_scope(), ddict_cleanup_cb, d);

	if (do_dump_dict) ddict_print(stdout, d);

	/* populate the types */
	for (t = d->typedefns; t; t = t->next) {
		const avp_type_t *parent = NULL;
		/* try to get the parent type */

		if (t->name == NULL) {
			report_failure("Diameter Dictionary: Invalid Type (empty name): parent==%s\n",
				t->parent ? t->parent : "(null)");
			continue;
		}


		if (g_hash_table_lookup(build_dict.types,t->name))
			continue;

		if (t->parent) {
			parent = (avp_type_t *)g_hash_table_lookup(build_dict.types,t->parent);
		}

		if (!parent) parent = octetstring;

		/* insert the parent type for this type */
		g_hash_table_insert(build_dict.types,t->name,(void *)parent);
	}

	/* populate the applications */
	if ((p = d->applications)) {
		wmem_array_t *arr = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
		value_string term[1];

		term[0].value =  0;
		term[0].strptr = NULL;

		for (; p; p = p->next) {
			value_string item[1];

			item[0].value = p->code;
			item[0].strptr = p->name;
			if (!p->name) {
				report_failure("Diameter Dictionary: Invalid Application (empty name): id=%d\n", p->code);
				continue;
			}

			wmem_array_append_one(arr,item);
		}

		wmem_array_sort(arr, compare_avps);
		wmem_array_append_one(arr,term);

		/* TODO: Remove duplicates */

		dictionary.applications = value_string_ext_new((value_string *)wmem_array_get_raw(arr),
								wmem_array_get_count(arr),
								wmem_strdup(wmem_epan_scope(), "applications_vals_ext"));
	}

	if ((v = d->vendors)) {
		for ( ; v; v = v->next) {
			value_string item[1];

			item[0].value = v->code;
			item[0].strptr = v->name;

			if (v->name == NULL) {
				report_failure("Diameter Dictionary: Invalid Vendor (empty name): code==%d\n", v->code);
				continue;
			}

			if (g_hash_table_lookup(vendors,v->name))
				continue;

			g_array_append_val(vnd_shrt_arr,item);

			vnd = wmem_new(wmem_epan_scope(), diam_vnd_t);
			vnd->code = v->code;
			vnd->vs_avps = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
			wmem_array_set_null_terminator(vnd->vs_avps);
			wmem_array_bzero(vnd->vs_avps);
			vnd->vs_avps_ext = NULL;
			wmem_tree_insert32(dictionary.vnds,vnd->code,vnd);
			g_hash_table_insert(vendors,v->name,vnd);
		}
	}

	vnd_short_vs = (value_string *)g_array_free(vnd_shrt_arr, FALSE);

	if ((c = d->cmds)) {
		for (; c; c = c->next) {
			if (c->vendor == NULL) {
				report_failure("Diameter Dictionary: Invalid Vendor (empty name) for command %s\n",
					c->name ? c->name : "(null)");
				continue;
			}

			if ((vnd = (diam_vnd_t *)g_hash_table_lookup(vendors,c->vendor))) {
				value_string item[1];

				item[0].value =  c->code;
				item[0].strptr = c->name;

				g_array_append_val(all_cmds,item);
			} else {
				report_failure("Diameter Dictionary: No Vendor: %s\n",c->vendor);
			}
		}
	}


	for (a = d->avps; a; a = a->next) {
		ddict_enum_t *e;
		value_string *vs = NULL;
		const char *vend = a->vendor ? a->vendor : "None";
		ddict_xmlpi_t *x;
		void *avp_data = NULL;

		if (a->name == NULL) {
			report_failure("Diameter Dictionary: Invalid AVP (empty name)\n");
			continue;
		}

		if ((vnd = (diam_vnd_t *)g_hash_table_lookup(vendors,vend))) {
			value_string vndvs[1];

			vndvs[0].value =  a->code;
			vndvs[0].strptr = a->name;


			wmem_array_append_one(vnd->vs_avps,vndvs);
		} else {
			report_failure("Diameter Dictionary: No Vendor: %s\n",vend);
			vnd = &unknown_vendor;
		}

		if ((e = a->enums)) {
			wmem_array_t *arr = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
			value_string term[1];

			term[0].value =  0;
			term[0].strptr = NULL;

			for (; e; e = e->next) {
				value_string item[1];

				item[0].value =  e->code;
				item[0].strptr = e->name;
				wmem_array_append_one(arr,item);
			}
			wmem_array_sort(arr, compare_avps);
			wmem_array_append_one(arr,term);
			vs = (value_string *)wmem_array_get_raw(arr);
		}

		type = NULL;

		for( x = d->xmlpis; x; x = x->next ) {
			if ( (strcase_equal(x->name,"avp-proto") && strcase_equal(x->key,a->name))
				 || (a->type && strcase_equal(x->name,"type-proto") && strcase_equal(x->key,a->type))
				 ) {
				static avp_type_t proto_type = {"proto", proto_avp, FT_UINT32, BASE_HEX, build_proto_avp};
				type =  &proto_type;

				avp_data = x->value;
				break;
			}
		}

		if ( (!type) && a->type )
			type = (avp_type_t *)g_hash_table_lookup(build_dict.types,a->type);

		if (!type) type = octetstring;

		avp = type->build( type, a->code, vnd, a->name, vs, avp_data);
		if (avp != NULL) {
			g_hash_table_insert(build_dict.avps, a->name, avp);

			{
				wmem_tree_key_t k[3];

				k[0].length = 1;
				k[0].key	= &(a->code);
				k[1].length = 1;
				k[1].key	= &(vnd->code);
				k[2].length = 0;
				k[2].key	= NULL;

				wmem_tree_insert32_array(dictionary.avps,k,avp);
			}
		}
	}
	g_hash_table_destroy(build_dict.types);
	g_hash_table_destroy(build_dict.avps);
	g_hash_table_destroy(vendors);

	cmd_vs = (const value_string *)(void *)all_cmds->data;

	return 1;
}

/*
 * This does most of the registration work; see register_diameter_fields()
 * for the reason why we split it off.
 */
static void
real_register_diameter_fields(void)
{
	expert_module_t* expert_diameter;
	guint i, ett_length;

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
		{ "Modified EUI64","diameter.user_equipment_info.modified_eui64", FT_EUI64, BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	gint *ett_base[] = {
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

	wmem_array_append(build_dict.hf, hf_base, array_length(hf_base));
	ett_length = array_length(ett_base);
	for (i = 0; i < ett_length; i++) {
		g_ptr_array_add(build_dict.ett, ett_base[i]);
	}

	proto_register_field_array(proto_diameter, (hf_register_info *)wmem_array_get_raw(build_dict.hf), wmem_array_get_count(build_dict.hf));
	proto_register_subtree_array((gint **)build_dict.ett->pdata, build_dict.ett->len);
	expert_diameter = expert_register_protocol(proto_diameter);
	expert_register_field_array(expert_diameter, ei, array_length(ei));

	g_ptr_array_free(build_dict.ett,TRUE);

}

static void
register_diameter_fields(const char *unused _U_)
{
	/*
	 * The hf_base[] array for Diameter refers to a variable
	 * that is set by dictionary_load(), so we need to call
	 * dictionary_load() before hf_base[] is initialized.
	 *
	 * To ensure that, we call dictionary_load() and then
	 * call a routine that defines hf_base[] and does all
	 * the registration work.
	 */
	dictionary_load();
	real_register_diameter_fields();
}

void
proto_register_diameter(void)
{
	module_t *diameter_module;

	proto_diameter = proto_register_protocol ("Diameter Protocol", "Diameter", "diameter");

	/* Allow dissector to find be found by name. */
	diameter_sctp_handle = register_dissector("diameter", dissect_diameter, proto_diameter);
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

	/* Set default TCP ports */
	range_convert_str(wmem_epan_scope(), &global_diameter_sctp_port_range, DEFAULT_DIAMETER_PORT_RANGE, MAX_SCTP_PORT);

	/* Register configuration options for ports */
	diameter_module = prefs_register_protocol(proto_diameter, proto_reg_handoff_diameter);
	/* For reading older preference files with "Diameter." preferences */
	prefs_register_module_alias("Diameter", diameter_module);

	prefs_register_range_preference(diameter_module, "sctp.ports",
					"Diameter SCTP Ports",
					"SCTP ports to be decoded as Diameter (default: "
					DEFAULT_DIAMETER_PORT_RANGE ")",
					&global_diameter_sctp_port_range, MAX_SCTP_PORT);

	/* Desegmentation */
	prefs_register_bool_preference(diameter_module, "desegment",
				       "Reassemble Diameter messages spanning multiple TCP segments",
				       "Whether the Diameter dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &gbl_diameter_desegment);

	/*  Register some preferences we no longer support, so we can report
	 *  them as obsolete rather than just illegal.
	 */
	prefs_register_obsolete_preference(diameter_module, "version");
	prefs_register_obsolete_preference(diameter_module, "sctp.port");
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
	static gboolean Initialized=FALSE;
	static range_t *diameter_sctp_port_range;

	if (!Initialized) {
		diameter_udp_handle = create_dissector_handle(dissect_diameter, proto_diameter);
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

		/* AVP Code: 265 Supported-Vendor-Id */
		dissector_add_uint("diameter.base", 265, create_dissector_handle(dissect_diameter_vendor_id, proto_diameter));

		/* AVP Code: 266 Vendor-Id */
		dissector_add_uint("diameter.base", 266, create_dissector_handle(dissect_diameter_vendor_id, proto_diameter));

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

		dissector_add_uint_range_with_preference("tcp.port", DEFAULT_DIAMETER_PORT_RANGE, diameter_tcp_handle);
		dissector_add_uint_range_with_preference("udp.port", "", diameter_udp_handle);

		Initialized=TRUE;
	} else {
		dissector_delete_uint_range("sctp.port", diameter_sctp_port_range, diameter_sctp_handle);
		wmem_free(wmem_epan_scope(), diameter_sctp_port_range);
	}

	/* set port for future deletes */
	diameter_sctp_port_range = range_copy(wmem_epan_scope(), global_diameter_sctp_port_range);
	dissector_add_uint_range("sctp.port", diameter_sctp_port_range, diameter_sctp_handle);

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
