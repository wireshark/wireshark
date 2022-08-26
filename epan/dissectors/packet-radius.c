/* packet-radius.c
 *
 * Routines for RADIUS packet disassembly
 * Copyright 1999 Johan Feyaerts
 * Changed 03/12/2003 Rui Carmo (http://the.taoofmac.com - added all 3GPP VSAs, some parsing)
 * Changed 07/2005 Luis Ontanon <luis@ontanon.org> - use FreeRADIUS' dictionary
 * Changed 10/2006 Alejandro Vaquero <alejandrovaquero@yahoo.com> - add Conversations support
 * Changed 08/2015 Didier Arenzana <darenzana@yahoo.fr> - add response authenticator validation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 *
 * RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
 * RFC 2866 - RADIUS Accounting
 * RFC 2867 - RADIUS Accounting Modifications for Tunnel Protocol Support
 * RFC 2868 - RADIUS Attributes for Tunnel Protocol Support
 * RFC 2869 - RADIUS Extensions
 * RFC 3162 - RADIUS and IPv6
 * RFC 3576 - Dynamic Authorization Extensions to RADIUS
 * RFC 6929 - Remote Authentication Dial-In User Service (RADIUS) Protocol Extensions
 *
 * See also
 *
 *	http://www.iana.org/assignments/radius-types
 *
 * and see
 *
 *	http://freeradius.org/radiusd/man/dictionary.html
 *
 * for the dictionary file syntax.
 */


/*
  TO (re)DO: (see svn rev 14786)
    - dissect_3gpp_ipv6_dns_servers()
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/rtd_table.h>
#include <epan/addr_resolv.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>


#include "packet-radius.h"
#include "packet-e212.h"

void proto_register_radius(void);
void proto_reg_handoff_radius(void);

typedef struct _e_radiushdr {
	guint8 rh_code;
	guint8 rh_ident;
	guint16 rh_pktlength;
} e_radiushdr;

typedef struct {
	wmem_array_t *hf;
	wmem_array_t *ett;
	wmem_array_t *vend_vs;
} hfett_t;

#define AUTHENTICATOR_LENGTH	16
#define RD_HDR_LENGTH		4
#define HDR_LENGTH		(RD_HDR_LENGTH + AUTHENTICATOR_LENGTH)

/* Item of request list */
typedef struct _radius_call_t
{
	guint code;
	guint ident;
	guint8 req_authenticator[AUTHENTICATOR_LENGTH];

	guint32 req_num; /* frame number request seen */
	guint32 rsp_num; /* frame number response seen */
	guint32 rspcode;
	nstime_t req_time;
	gboolean responded;
} radius_call_t;

/* Container for tapping relevant data */
typedef struct _radius_info_t
{
	guint code;
	guint ident;
	nstime_t req_time;
	gboolean is_duplicate;
	gboolean request_available;
	guint32 req_num; /* frame number request seen */
	guint32 rspcode;
} radius_info_t;


/*
 * Default RADIUS ports:
 * 1645 (Authentication, pre RFC 2865)
 * 1646 (Accounting, pre RFC 2866)
 * 1812 (Authentication, RFC 2865)
 * 1813 (Accounting, RFC 2866)
 * 1700 (Dynamic Authorization Extensions, pre RFC 3576)
 * 3799 (Dynamic Authorization Extensions, RFC 3576)
*/
#define DEFAULT_RADIUS_PORT_RANGE "1645,1646,1700,1812,1813,3799"

static radius_dictionary_t *dict = NULL;

static int proto_radius = -1;

static int hf_radius_req = -1;
static int hf_radius_rsp = -1;
static int hf_radius_req_frame = -1;
static int hf_radius_rsp_frame = -1;
static int hf_radius_time = -1;

static int hf_radius_dup = -1;
static int hf_radius_req_dup = -1;
static int hf_radius_rsp_dup = -1;

static int hf_radius_id = -1;
static int hf_radius_code = -1;
static int hf_radius_length = -1;
static int hf_radius_authenticator = -1;
static int hf_radius_authenticator_valid = -1;
static int hf_radius_authenticator_invalid = -1;

static int hf_radius_chap_password = -1;
static int hf_radius_chap_ident = -1;
static int hf_radius_chap_string = -1;
static int hf_radius_framed_ip_address = -1;

static int hf_radius_login_ip_host = -1;
static int hf_radius_framed_ipx_network = -1;

static int hf_radius_cosine_vpi = -1;
static int hf_radius_cosine_vci = -1;

static int hf_radius_ascend_data_filter = -1;
static int hf_radius_ascend_data_filter_type = -1;
static int hf_radius_ascend_data_filter_filteror = -1;
static int hf_radius_ascend_data_filter_inout = -1;
static int hf_radius_ascend_data_filter_spare = -1;
static int hf_radius_ascend_data_filter_src_ipv4 = -1;
static int hf_radius_ascend_data_filter_dst_ipv4 = -1;
static int hf_radius_ascend_data_filter_src_ipv6 = -1;
static int hf_radius_ascend_data_filter_dst_ipv6 = -1;
static int hf_radius_ascend_data_filter_src_ip_prefix = -1;
static int hf_radius_ascend_data_filter_dst_ip_prefix = -1;
static int hf_radius_ascend_data_filter_protocol = -1;
static int hf_radius_ascend_data_filter_established = -1;
static int hf_radius_ascend_data_filter_src_port = -1;
static int hf_radius_ascend_data_filter_dst_port = -1;
static int hf_radius_ascend_data_filter_src_port_qualifier = -1;
static int hf_radius_ascend_data_filter_dst_port_qualifier = -1;
static int hf_radius_ascend_data_filter_reserved = -1;

static int hf_radius_vsa_fragment = -1;
static int hf_radius_eap_fragment = -1;
static int hf_radius_avp = -1;
static int hf_radius_avp_length = -1;
static int hf_radius_avp_type = -1;
static int hf_radius_avp_vendor_id = -1;
static int hf_radius_avp_vendor_type = -1;
static int hf_radius_avp_vendor_len = -1;
static int hf_radius_avp_extended_type = -1;
static int hf_radius_avp_extended_more = -1;
static int hf_radius_3gpp_ms_tmime_zone = -1;

static int hf_radius_egress_vlanid_tag = -1;
static int hf_radius_egress_vlanid_pad = -1;
static int hf_radius_egress_vlanid = -1;

static int hf_radius_egress_vlan_name_tag = -1;
static int hf_radius_egress_vlan_name = -1;


static gint ett_radius = -1;
static gint ett_radius_avp = -1;

static gint ett_radius_authenticator = -1;
static gint ett_radius_ascend = -1;

static gint ett_eap = -1;
static gint ett_chap = -1;

static expert_field ei_radius_invalid_length = EI_INIT;

/*
 * Define the tap for radius
 */
static int radius_tap = -1;

static radius_vendor_info_t no_vendor = {"Unknown Vendor", 0, NULL, -1, 1, 1, FALSE};

static radius_attr_info_t no_dictionary_entry = {"Unknown-Attribute", { { 0, 0 } }, FALSE, FALSE, radius_octets, NULL, NULL, -1, -1, -1, -1, -1, NULL };

static dissector_handle_t eap_handle;
static dissector_handle_t radius_handle;


static const gchar *shared_secret = "";
static gboolean validate_authenticator = FALSE;
static gboolean show_length = FALSE;
static gboolean disable_extended_attributes = FALSE;

static guint8 authenticator[AUTHENTICATOR_LENGTH];

/* http://www.iana.org/assignments/radius-types */
static const value_string radius_pkt_type_codes[] =
{
	{RADIUS_PKT_TYPE_ACCESS_REQUEST,			"Access-Request"},			/*  1 RFC2865 */
	{RADIUS_PKT_TYPE_ACCESS_ACCEPT,				"Access-Accept"},			/*  2 RFC2865 */
	{RADIUS_PKT_TYPE_ACCESS_REJECT,				"Access-Reject"},			/*  3 RFC2865 */
	{RADIUS_PKT_TYPE_ACCOUNTING_REQUEST,			"Accounting-Request"},			/*  4 RFC2865 */
	{RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE,			"Accounting-Response"},			/*  5 RFC2865 */
	{RADIUS_PKT_TYPE_ACCOUNTING_STATUS,			"Accounting-Status"},			/*  6 RFC3575 */
	{RADIUS_PKT_TYPE_PASSWORD_REQUEST,			"Password-Request"},			/*  7 RFC3575 */
	{RADIUS_PKT_TYPE_PASSWORD_ACK,				"Password-Ack"},			/*  8 RFC3575 */
	{RADIUS_PKT_TYPE_PASSWORD_REJECT,			"Password-Reject"},			/*  9 RFC3575 */
	{RADIUS_PKT_TYPE_ACCOUNTING_MESSAGE,			"Accounting-Message"},			/* 10 RFC3575 */
	{RADIUS_PKT_TYPE_ACCESS_CHALLENGE,			"Access-Challenge"},			/* 11 RFC2865 */
	{RADIUS_PKT_TYPE_STATUS_SERVER,				"Status-Server"},			/* 12 RFC2865 */
	{RADIUS_PKT_TYPE_STATUS_CLIENT,				"Status-Client"},			/* 13 RFC2865 */

	{RADIUS_PKT_TYPE_RESOURCE_FREE_REQUEST,			"Resource-Free-Request"},		/* 21 RFC3575 */
	{RADIUS_PKT_TYPE_RESOURCE_FREE_RESPONSE,		"Resource-Free-Response"},		/* 22 RFC3575 */
	{RADIUS_PKT_TYPE_RESOURCE_QUERY_REQUEST,		"Resource-Query-Request"},		/* 23 RFC3575 */
	{RADIUS_PKT_TYPE_RESOURCE_QUERY_RESPONSE,		"Query_Response"},			/* 24 RFC3575 */
	{RADIUS_PKT_TYPE_ALTERNATE_RESOURCE_RECLAIM_REQUEST,	"Alternate-Resource-Reclaim-Request"},	/* 25 RFC3575 */
	{RADIUS_PKT_TYPE_NAS_REBOOT_REQUEST,			"NAS-Reboot-Request"},			/* 26 RFC3575 */
	{RADIUS_PKT_TYPE_NAS_REBOOT_RESPONSE,			"NAS-Reboot-Response"},			/* 27 RFC3575 */

	{RADIUS_PKT_TYPE_NEXT_PASSCODE,				"Next-Passcode"},			/* 29 RFC3575 */
	{RADIUS_PKT_TYPE_NEW_PIN,				"New-Pin"},				/* 30 RFC3575 */
	{RADIUS_PKT_TYPE_TERMINATE_SESSION,			"Terminate-Session"},			/* 31 RFC3575 */
	{RADIUS_PKT_TYPE_PASSWORD_EXPIRED,			"Password-Expired"},			/* 32 RFC3575 */
	{RADIUS_PKT_TYPE_EVENT_REQUEST,				"Event-Request"},			/* 33 RFC3575 */
	{RADIUS_PKT_TYPE_EVENT_RESPONSE,			"Event-Response"},			/* 34 RFC3575|RFC5176 */

	{RADIUS_PKT_TYPE_DISCONNECT_REQUEST,			"Disconnect-Request"},			/* 40 RFC3575|RFC5176 */
	{RADIUS_PKT_TYPE_DISCONNECT_ACK,			"Disconnect-ACK"},			/* 41 RFC3575|RFC5176 */
	{RADIUS_PKT_TYPE_DISCONNECT_NAK,			"Disconnect-NAK"},			/* 42 RFC3575|RFC5176 */
	{RADIUS_PKT_TYPE_COA_REQUEST,				"CoA-Request"},				/* 43 RFC3575|RFC5176 */
	{RADIUS_PKT_TYPE_COA_ACK,				"CoA-ACK"},				/* 44 RFC3575|RFC5176 */
	{RADIUS_PKT_TYPE_COA_NAK,				"CoA-NAK"},				/* 45 RFC3575|RFC5176 */

	{RADIUS_PKT_TYPE_IP_ADDRESS_ALLOCATE,			"IP-Address-Allocate"},			/* 50 RFC3575 */
	{RADIUS_PKT_TYPE_IP_ADDRESS_RELEASE,			"IP-Address-Release"},			/* 51 RFC3575 */

	{RADIUS_PKT_TYPE_ALU_STATE_REQUEST,			"ALU-State-Request"},			/* 129 ALU AAA */
	{RADIUS_PKT_TYPE_ALU_STATE_ACCEPT,			"ALU-State-Accept"},			/* 130 ALU AAA */
	{RADIUS_PKT_TYPE_ALU_STATE_REJECT,			"ALU-State-Reject"},			/* 131 ALU AAA */
	{RADIUS_PKT_TYPE_ALU_STATE_ERROR,			"ALU-State-Error"},				/* 132 ALU AAA */
/*
250-253  Experimental Use	[RFC3575]
254-255  Reserved		[RFC3575]
*/
	{0, NULL}
};
static value_string_ext radius_pkt_type_codes_ext = VALUE_STRING_EXT_INIT(radius_pkt_type_codes);

typedef enum _radius_category {
	RADIUS_CAT_OVERALL = 0,
	RADIUS_CAT_ACCESS,
	RADIUS_CAT_ACCOUNTING,
	RADIUS_CAT_PASSWORD,
	RADIUS_CAT_RESOURCE_FREE,
	RADIUS_CAT_RESOURCE_QUERY,
	RADIUS_CAT_NAS_REBOOT,
	RADIUS_CAT_EVENT,
	RADIUS_CAT_DISCONNECT,
	RADIUS_CAT_COA,
	RADIUS_CAT_OTHERS,
	RADIUS_CAT_NUM_TIMESTATS
} radius_category;

static const value_string radius_message_code[] = {
	{  RADIUS_CAT_OVERALL,		"Overall"},
	{  RADIUS_CAT_ACCESS,		"Access"},
	{  RADIUS_CAT_ACCOUNTING,	"Accounting"},
	{  RADIUS_CAT_PASSWORD,		"Password"},
	{  RADIUS_CAT_RESOURCE_FREE,	"Resource Free"},
	{  RADIUS_CAT_RESOURCE_QUERY,	"Resource Query"},
	{  RADIUS_CAT_NAS_REBOOT,	"NAS Reboot"},
	{  RADIUS_CAT_EVENT,		"Event"},
	{  RADIUS_CAT_DISCONNECT,	"Disconnect"},
	{  RADIUS_CAT_COA,		"CoA"},
	{  RADIUS_CAT_OTHERS,		"Other"},
	{  0, NULL}
};

static tap_packet_status
radiusstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pri, tap_flags_t flags _U_)
{
	rtd_data_t *rtd_data = (rtd_data_t *)prs;
	rtd_stat_table *rs = &rtd_data->stat_table;
	const radius_info_t *ri = (const radius_info_t *)pri;
	nstime_t delta;
	radius_category radius_cat = RADIUS_CAT_OTHERS;
	tap_packet_status ret = TAP_PACKET_DONT_REDRAW;

	switch (ri->code) {
		case RADIUS_PKT_TYPE_ACCESS_REQUEST:
		case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
		case RADIUS_PKT_TYPE_ACCESS_REJECT:
			radius_cat = RADIUS_CAT_ACCESS;
			break;
		case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
		case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
			radius_cat = RADIUS_CAT_ACCOUNTING;
			break;
		case RADIUS_PKT_TYPE_PASSWORD_REQUEST:
		case RADIUS_PKT_TYPE_PASSWORD_ACK:
		case RADIUS_PKT_TYPE_PASSWORD_REJECT:
			radius_cat = RADIUS_CAT_PASSWORD;
			break;
		case RADIUS_PKT_TYPE_RESOURCE_FREE_REQUEST:
		case RADIUS_PKT_TYPE_RESOURCE_FREE_RESPONSE:
			radius_cat = RADIUS_CAT_RESOURCE_FREE;
			break;
		case RADIUS_PKT_TYPE_RESOURCE_QUERY_REQUEST:
		case RADIUS_PKT_TYPE_RESOURCE_QUERY_RESPONSE:
			radius_cat = RADIUS_CAT_RESOURCE_QUERY;
			break;
		case RADIUS_PKT_TYPE_NAS_REBOOT_REQUEST:
		case RADIUS_PKT_TYPE_NAS_REBOOT_RESPONSE:
			radius_cat = RADIUS_CAT_NAS_REBOOT;
			break;
		case RADIUS_PKT_TYPE_EVENT_REQUEST:
		case RADIUS_PKT_TYPE_EVENT_RESPONSE:
			radius_cat = RADIUS_CAT_EVENT;
			break;
		case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
		case RADIUS_PKT_TYPE_DISCONNECT_ACK:
		case RADIUS_PKT_TYPE_DISCONNECT_NAK:
			radius_cat = RADIUS_CAT_DISCONNECT;
			break;
		case RADIUS_PKT_TYPE_COA_REQUEST:
		case RADIUS_PKT_TYPE_COA_ACK:
		case RADIUS_PKT_TYPE_COA_NAK:
			radius_cat = RADIUS_CAT_COA;
			break;
	}

	switch (ri->code) {

	case RADIUS_PKT_TYPE_ACCESS_REQUEST:
	case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
	case RADIUS_PKT_TYPE_PASSWORD_REQUEST:
	case RADIUS_PKT_TYPE_EVENT_REQUEST:
	case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
	case RADIUS_PKT_TYPE_COA_REQUEST:
		if (ri->is_duplicate) {
			/* Duplicate is ignored */
			rs->time_stats[RADIUS_CAT_OVERALL].req_dup_num++;
			rs->time_stats[radius_cat].req_dup_num++;
		} else {
			rs->time_stats[RADIUS_CAT_OVERALL].open_req_num++;
			rs->time_stats[radius_cat].open_req_num++;
		}
		break;

	case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
	case RADIUS_PKT_TYPE_ACCESS_REJECT:
	case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
	case RADIUS_PKT_TYPE_PASSWORD_ACK:
	case RADIUS_PKT_TYPE_PASSWORD_REJECT:
	case RADIUS_PKT_TYPE_EVENT_RESPONSE:
	case RADIUS_PKT_TYPE_DISCONNECT_ACK:
	case RADIUS_PKT_TYPE_DISCONNECT_NAK:
	case RADIUS_PKT_TYPE_COA_ACK:
	case RADIUS_PKT_TYPE_COA_NAK:
		if (ri->is_duplicate) {
			/* Duplicate is ignored */
			rs->time_stats[RADIUS_CAT_OVERALL].rsp_dup_num++;
			rs->time_stats[radius_cat].rsp_dup_num++;
		} else if (!ri->request_available) {
			/* no request was seen */
			rs->time_stats[RADIUS_CAT_OVERALL].disc_rsp_num++;
			rs->time_stats[radius_cat].disc_rsp_num++;
		} else {
			rs->time_stats[RADIUS_CAT_OVERALL].open_req_num--;
			rs->time_stats[radius_cat].open_req_num--;
			/* calculate time delta between request and response */
			nstime_delta(&delta, &pinfo->abs_ts, &ri->req_time);

			time_stat_update(&(rs->time_stats[RADIUS_CAT_OVERALL].rtd[0]),&delta, pinfo);
			time_stat_update(&(rs->time_stats[radius_cat].rtd[0]),&delta, pinfo);

			ret = TAP_PACKET_REDRAW;
		}
		break;

	default:
		break;
	}

	return ret;
}



/*
 * Init Hash table stuff for conversation
 */

typedef struct _radius_call_info_key
{
	guint code;
	guint ident;
	conversation_t *conversation;
	nstime_t req_time;
} radius_call_info_key;

static wmem_map_t *radius_calls;

typedef struct _radius_vsa_buffer_key
{
	guint32 vendor_id;
	guint32 vsa_type;
} radius_vsa_buffer_key;

typedef struct _radius_vsa_buffer
{
	radius_vsa_buffer_key key;
	guint8 *data;
	guint seg_num;
	guint len;
} radius_vsa_buffer;

static gint
radius_vsa_equal(gconstpointer k1, gconstpointer k2)
{
	const radius_vsa_buffer_key *key1 = (const radius_vsa_buffer_key *) k1;
	const radius_vsa_buffer_key *key2 = (const radius_vsa_buffer_key *) k2;

	return (((key1->vendor_id == key2->vendor_id) &&
		(key1->vsa_type == key2->vsa_type)
		) ? TRUE : FALSE);
}

static guint
radius_vsa_hash(gconstpointer k)
{
	const radius_vsa_buffer_key *key = (const radius_vsa_buffer_key *) k;

	return key->vendor_id + key->vsa_type;
}

/* Compare 2 keys */
static gboolean
radius_call_equal(gconstpointer k1, gconstpointer k2)
{
	const radius_call_info_key *key1 = (const radius_call_info_key *) k1;
	const radius_call_info_key *key2 = (const radius_call_info_key *) k2;

	if (key1->ident == key2->ident && key1->conversation == key2->conversation) {
		if (key1->code == key2->code)
			return TRUE;

		/* check the request and response are of the same code type */
		if ((key1->code == RADIUS_PKT_TYPE_ACCESS_REQUEST) &&
		    ((key2->code == RADIUS_PKT_TYPE_ACCESS_ACCEPT) ||
		     (key2->code == RADIUS_PKT_TYPE_ACCESS_REJECT) ||
		     (key2->code == RADIUS_PKT_TYPE_ACCESS_CHALLENGE)))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_ACCESS_REQUEST) &&
		    ((key1->code == RADIUS_PKT_TYPE_ACCESS_ACCEPT) ||
		     (key1->code == RADIUS_PKT_TYPE_ACCESS_REJECT) ||
		     (key1->code == RADIUS_PKT_TYPE_ACCESS_CHALLENGE)))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_ACCOUNTING_REQUEST) &&
		    (key2->code == RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_ACCOUNTING_REQUEST) &&
		    (key1->code == RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_PASSWORD_REQUEST) &&
		    ((key2->code == RADIUS_PKT_TYPE_PASSWORD_ACK) ||
		     (key2->code == RADIUS_PKT_TYPE_PASSWORD_REJECT)))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_PASSWORD_REQUEST) &&
		    ((key1->code == RADIUS_PKT_TYPE_PASSWORD_ACK) ||
		     (key1->code == RADIUS_PKT_TYPE_PASSWORD_REJECT)))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_RESOURCE_FREE_REQUEST) &&
		    (key2->code == RADIUS_PKT_TYPE_RESOURCE_FREE_RESPONSE))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_RESOURCE_FREE_REQUEST) &&
		    (key1->code == RADIUS_PKT_TYPE_RESOURCE_FREE_RESPONSE))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_RESOURCE_QUERY_REQUEST) &&
		    (key2->code == RADIUS_PKT_TYPE_RESOURCE_QUERY_RESPONSE))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_RESOURCE_QUERY_REQUEST) &&
		    (key1->code == RADIUS_PKT_TYPE_RESOURCE_QUERY_RESPONSE))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_NAS_REBOOT_REQUEST) &&
		    (key2->code == RADIUS_PKT_TYPE_NAS_REBOOT_RESPONSE))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_NAS_REBOOT_REQUEST) &&
		    (key1->code == RADIUS_PKT_TYPE_NAS_REBOOT_RESPONSE))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_EVENT_REQUEST) &&
		    (key2->code == RADIUS_PKT_TYPE_EVENT_RESPONSE))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_EVENT_REQUEST) &&
		    (key1->code == RADIUS_PKT_TYPE_EVENT_RESPONSE))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_DISCONNECT_REQUEST) &&
		    ((key2->code == RADIUS_PKT_TYPE_DISCONNECT_ACK) ||
		     (key2->code == RADIUS_PKT_TYPE_DISCONNECT_NAK)))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_DISCONNECT_REQUEST) &&
		    ((key1->code == RADIUS_PKT_TYPE_DISCONNECT_ACK) ||
		     (key1->code == RADIUS_PKT_TYPE_DISCONNECT_NAK)))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_COA_REQUEST) &&
		    ((key2->code == RADIUS_PKT_TYPE_COA_ACK) ||
		     (key2->code == RADIUS_PKT_TYPE_COA_NAK)))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_COA_REQUEST) &&
		    ((key1->code == RADIUS_PKT_TYPE_COA_ACK) ||
		     (key1->code == RADIUS_PKT_TYPE_COA_NAK)))
			return TRUE;

		if ((key1->code == RADIUS_PKT_TYPE_ALU_STATE_REQUEST) &&
		    ((key2->code == RADIUS_PKT_TYPE_ALU_STATE_ACCEPT) ||
		     (key2->code == RADIUS_PKT_TYPE_ALU_STATE_REJECT) ||
		     (key2->code == RADIUS_PKT_TYPE_ALU_STATE_ERROR)))
			return TRUE;
		if ((key2->code == RADIUS_PKT_TYPE_ALU_STATE_REQUEST) &&
		    ((key1->code == RADIUS_PKT_TYPE_ALU_STATE_ACCEPT) ||
		     (key1->code == RADIUS_PKT_TYPE_ALU_STATE_REJECT) ||
		     (key1->code == RADIUS_PKT_TYPE_ALU_STATE_ERROR)))
			return TRUE;
	}
	return FALSE;
}

/* Calculate a hash key */
static guint
radius_call_hash(gconstpointer k)
{
	const radius_call_info_key *key = (const radius_call_info_key *) k;

	return key->ident + key->conversation->conv_index;
}


static const gchar *
dissect_chap_password(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int len;
	proto_item *ti;
	proto_tree *chap_tree;

	len = tvb_reported_length(tvb);
	if (len != 17)
		return "[wrong length for CHAP-Password]";

	ti = proto_tree_add_item(tree, hf_radius_chap_password, tvb, 0, len, ENC_NA);
		chap_tree = proto_item_add_subtree(ti, ett_chap);
		proto_tree_add_item(chap_tree, hf_radius_chap_ident, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(chap_tree, hf_radius_chap_string, tvb, 1, 16, ENC_NA);
	return (tvb_bytes_to_str(wmem_packet_scope(), tvb, 0, len));
}

static const gchar *
dissect_framed_ip_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int len;
	guint32 ip;
	guint32 ip_h;
	const gchar *str;

	len = tvb_reported_length(tvb);
	if (len != 4)
		return "[wrong length for IP address]";

	ip = tvb_get_ipv4(tvb, 0);
	ip_h = g_ntohl(ip);

	if (ip_h == 0xFFFFFFFF) {
		str = "Negotiated";
		proto_tree_add_ipv4_format_value(tree, hf_radius_framed_ip_address,
					   tvb, 0, len, ip, "%s", str);
	} else if (ip_h == 0xFFFFFFFE) {
		str = "Assigned";
		proto_tree_add_ipv4_format_value(tree, hf_radius_framed_ip_address,
					   tvb, 0, len, ip, "%s", str);
	} else {
		str = tvb_ip_to_str(pinfo->pool, tvb, 0);
		proto_tree_add_item(tree, hf_radius_framed_ip_address,
					   tvb, 0, len, ENC_BIG_ENDIAN);
	}

	return str;
}

static const gchar *
dissect_login_ip_host(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int len;
	guint32 ip;
	guint32 ip_h;
	const gchar *str;

	len = tvb_reported_length(tvb);
	if (len != 4)
		return "[wrong length for IP address]";

	ip = tvb_get_ipv4(tvb, 0);
	ip_h = g_ntohl(ip);

	if (ip_h == 0xFFFFFFFF) {
		str = "User-selected";
		proto_tree_add_ipv4_format_value(tree, hf_radius_login_ip_host,
					   tvb, 0, len, ip, "%s", str);
	} else if (ip_h == 0) {
		str = "NAS-selected";
		proto_tree_add_ipv4_format_value(tree, hf_radius_login_ip_host,
					   tvb, 0, len, ip, "%s", str);
	} else {
		str = tvb_ip_to_str(pinfo->pool, tvb, 0);
		proto_tree_add_item(tree, hf_radius_login_ip_host,
					   tvb, 0, len, ENC_BIG_ENDIAN);
	}

	return str;
}

static const value_string ascenddf_filtertype[] = { {0, "generic"}, {1, "ipv4"}, {3, "ipv6"}, {0, NULL} };
static const value_string ascenddf_filteror[]   = { {0, "drop"}, {1, "forward"}, {0, NULL} };
static const value_string ascenddf_inout[]      = { {0, "out"}, {1, "in"}, {0, NULL} };
static const value_string ascenddf_proto[]      = { {1, "icmp"}, {6, "tcp"}, {17, "udp"}, {0, NULL} };
static const value_string ascenddf_portq[]      = { {1, "lt"}, {2, "eq"}, {3, "gt"}, {4, "ne"}, {0, NULL} };

static const gchar *
dissect_ascend_data_filter(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	wmem_strbuf_t *filterstr;
	proto_item *ti;
	proto_tree *ascend_tree;
	int len;
	guint8 type, proto, srclen, dstlen;
	address srcip, dstip;
	guint16 srcport, dstport;
	guint8 srcportq, dstportq;
	guint8 iplen = 4;
	guint offset = 0;
	len=tvb_reported_length(tvb);

	if (len != 24 && len != 48) {
		return wmem_strdup_printf(wmem_packet_scope(), "Wrong attribute length %d", len);
	}

	filterstr = wmem_strbuf_sized_new(wmem_packet_scope(), 128, 128);

	ti = proto_tree_add_item(tree, hf_radius_ascend_data_filter, tvb, 0, -1, ENC_NA);
	ascend_tree = proto_item_add_subtree(ti, ett_radius_ascend);

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	type = tvb_get_guint8(tvb, 0);
	offset += 1;
	if (type == 3) { /* IPv6 */
		iplen = 16;
	}

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_filteror, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_inout, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (type == 3) { /* IPv6 */
		proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_src_ipv6, tvb, offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_dst_ipv6, tvb, offset, 16, ENC_NA);
		offset += 16;
	} else { /* IPv4 */
		proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_src_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_dst_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_src_ip_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_dst_ip_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_established, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_src_port_qualifier, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_dst_port_qualifier, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(ascend_tree, hf_radius_ascend_data_filter_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);

	wmem_strbuf_append_printf(filterstr, "%s %s %s",
		val_to_str(type, ascenddf_filtertype, "%u"),
		val_to_str(tvb_get_guint8(tvb, 2), ascenddf_inout, "%u"),
		val_to_str(tvb_get_guint8(tvb, 1), ascenddf_filteror, "%u"));


	proto = tvb_get_guint8(tvb, 6+iplen*2);
	if (proto) {
		wmem_strbuf_append_printf(filterstr, " %s",
				val_to_str(proto, ascenddf_proto, "%u"));
	}

	if (type == 3) { /* IPv6 */
		set_address_tvb(&srcip, AT_IPv6, 16, tvb, 4);
	} else {
		set_address_tvb(&srcip, AT_IPv4, 4, tvb, 4);
	}
	srclen = tvb_get_guint8(tvb, 4+iplen*2);
	srcport = tvb_get_ntohs(tvb, 9+iplen*2);
	srcportq = tvb_get_guint8(tvb, 12+iplen*2);

	if (srclen || srcportq) {
		wmem_strbuf_append_printf(filterstr, " srcip %s/%d", address_to_display(wmem_packet_scope(), &srcip), srclen);
		if (srcportq)
			wmem_strbuf_append_printf(filterstr, " srcport %s %d",
				val_to_str(srcportq, ascenddf_portq, "%u"), srcport);
	}

	if (type == 3) { /* IPv6-*/
		set_address_tvb(&dstip, AT_IPv6, 16, tvb, 4+iplen);
	} else {
		set_address_tvb(&dstip, AT_IPv4, 4, tvb, 4+iplen);
	}
	dstlen = tvb_get_guint8(tvb, 5+iplen*2);
	dstport = tvb_get_ntohs(tvb, 10+iplen*2);
	dstportq = tvb_get_guint8(tvb, 13+iplen*2);

	if (dstlen || dstportq) {
		wmem_strbuf_append_printf(filterstr, " dstip %s/%d", address_to_display(wmem_packet_scope(), &dstip), dstlen);
		if (dstportq)
			wmem_strbuf_append_printf(filterstr, " dstport %s %d",
				val_to_str(dstportq, ascenddf_portq, "%u"), dstport);
	}

	return wmem_strbuf_get_str(filterstr);
}

static const gchar *
dissect_framed_ipx_network(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int len;
	guint32 net;
	const gchar *str;

	len = tvb_reported_length(tvb);
	if (len != 4)
		return "[wrong length for IPX network]";

	net = tvb_get_ntohl(tvb, 0);

	if (net == 0xFFFFFFFE)
		str = "NAS-selected";
	else
		str = wmem_strdup_printf(wmem_packet_scope(), "0x%08X", net);
	proto_tree_add_ipxnet_format_value(tree, hf_radius_framed_ipx_network, tvb, 0,
				     len, net, "Framed-IPX-Network: %s", str);

	return str;
}

static const gchar *
dissect_cosine_vpvc(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	guint vpi, vci;

	if (tvb_reported_length(tvb) != 4)
		return "[Wrong Length for VP/VC AVP]";

	vpi = tvb_get_ntohs(tvb, 0);
	vci = tvb_get_ntohs(tvb, 2);

	proto_tree_add_uint(tree, hf_radius_cosine_vpi, tvb, 0, 2, vpi);
	proto_tree_add_uint(tree, hf_radius_cosine_vci, tvb, 2, 2, vci);

	return wmem_strdup_printf(wmem_packet_scope(), "%u/%u", vpi, vci);
}

static const value_string daylight_saving_time_vals[] = {
	{0, "No adjustment"},
	{1, "+1 hour adjustment for Daylight Saving Time"},
	{2, "+2 hours adjustment for Daylight Saving Time"},
	{3, "Reserved"},
	{0, NULL}
};

static const gchar *
dissect_radius_3gpp_imsi(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
{
	return dissect_e212_utf8_imsi(tvb, pinfo, tree, 0, tvb_reported_length(tvb));
}

static const gchar *
dissect_radius_3gpp_ms_tmime_zone(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{

	int offset = 0;
	guint8 oct, daylight_saving_time;
	char sign;

	/* 3GPP TS 23.040 version 6.6.0 Release 6
	 * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
	 * :
	 * The Time Zone indicates the difference, expressed in quarters of an hour,
	 * between the local time and GMT. In the first of the two semi-octets,
	 * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
	 * represents the algebraic sign of this difference (0: positive, 1: negative).
	 */

	oct = tvb_get_guint8(tvb, offset);
	sign = (oct & 0x08) ? '-' : '+';
	oct = (oct >> 4) + (oct & 0x07) * 10;
	daylight_saving_time = tvb_get_guint8(tvb, offset+1) & 0x3;

	proto_tree_add_bytes_format_value(tree, hf_radius_3gpp_ms_tmime_zone, tvb, offset, 2, NULL,
						"GMT %c%d hours %d minutes %s", sign, oct / 4, oct % 4 * 15,
						val_to_str_const(daylight_saving_time, daylight_saving_time_vals, "Unknown"));

	return wmem_strdup_printf(wmem_packet_scope(), "Timezone: GMT %c%d hours %d minutes %s ",
				  sign, oct / 4, oct % 4 * 15, val_to_str_const(daylight_saving_time, daylight_saving_time_vals, "Unknown"));

}

static const value_string egress_vlan_tag_vals[] = {
	{ 0x31, "Tagged"},
	{ 0x32, "Untagged"},
	{  0, NULL}
};
static const gchar *
dissect_rfc4675_egress_vlanid(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int len;
	guint32 vlanid;

	len = tvb_reported_length(tvb);
	if (len != 4)
		return "[wrong length for Egress-VLANID ]";

	proto_tree_add_item(tree, hf_radius_egress_vlanid_tag, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_radius_egress_vlanid_pad, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_radius_egress_vlanid, tvb, 0, 4, ENC_BIG_ENDIAN);
	vlanid = tvb_get_ntohl(tvb, 0);

	return wmem_strdup_printf(wmem_packet_scope(), "%s, Vlan ID: %u",
				   val_to_str_const(((vlanid&0xFF000000)>>24), egress_vlan_tag_vals, "Unknown"), vlanid&0xFFF);
}

static const gchar *
dissect_rfc4675_egress_vlan_name(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_)
{
	int len;
	guint8 tag;
	const guint8 *name;

	len = tvb_reported_length(tvb);
	if (len < 2)
		return "[wrong length for Egress-VLAN-Name ]";

	proto_tree_add_item(tree, hf_radius_egress_vlan_name_tag, tvb, 0, 1, ENC_BIG_ENDIAN);
	tag = tvb_get_guint8(tvb, 0);
	len -= 1;
	proto_tree_add_item_ret_string(tree, hf_radius_egress_vlan_name, tvb, 1, len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &name);

	return wmem_strdup_printf(wmem_packet_scope(), "%s, Vlan Name: %s",
				   val_to_str_const(tag, egress_vlan_tag_vals, "Unknown"), name);
}

static void
radius_decrypt_avp(gchar *dest, int dest_len, tvbuff_t *tvb, int offset, int length)
{
	gcry_md_hd_t md5_handle;
	guint8 digest[HASH_MD5_LENGTH];
	int i, j;
	gint totlen = 0, returned_length, padded_length;
	guint8 *pd;
	guchar c;

	DISSECTOR_ASSERT(dest_len > 0);
	dest[0] = '\0';
	if (length <= 0)
		return;

	/* The max avp length is 253 (255 - 2 for type & length), but only the
	 * User-Password is marked with encrypt=1 in dictionary.rfc2865, and the
	 * User-Password max length is only 128 (130 - 2 for type & length) per
	 * tools.ietf.org/html/rfc2865#section-5.2, so enforce that limit here.
	 */
	if (length > 128)
		length = 128;

	if (gcry_md_open(&md5_handle, GCRY_MD_MD5, 0)) {
		return;
	}
	gcry_md_write(md5_handle, (const guint8 *)shared_secret, (int)strlen(shared_secret));
	gcry_md_write(md5_handle, authenticator, AUTHENTICATOR_LENGTH);
	memcpy(digest, gcry_md_read(md5_handle, 0), HASH_MD5_LENGTH);

	padded_length = length + ((length % AUTHENTICATOR_LENGTH) ?
		(AUTHENTICATOR_LENGTH - (length % AUTHENTICATOR_LENGTH)) : 0);
	pd = (guint8 *)wmem_alloc0(wmem_packet_scope(), padded_length);
	tvb_memcpy(tvb, pd, offset, length);

	for (i = 0; i < padded_length; i += AUTHENTICATOR_LENGTH) {
		for (j = 0; j < AUTHENTICATOR_LENGTH; j++) {
			c = pd[i + j] ^ digest[j];
			if (g_ascii_isprint(c)) {
				returned_length = snprintf(&dest[totlen], dest_len - totlen,
					"%c", c);
				totlen += MIN(returned_length, dest_len - totlen - 1);
			}
			else if (c) {
				returned_length = snprintf(&dest[totlen], dest_len - totlen,
					"\\%03o", c);
				totlen += MIN(returned_length, dest_len - totlen - 1);
			}
		}

		gcry_md_reset(md5_handle);
		gcry_md_write(md5_handle, (const guint8 *)shared_secret, (int)strlen(shared_secret));
		gcry_md_write(md5_handle, &pd[i], AUTHENTICATOR_LENGTH);
		memcpy(digest, gcry_md_read(md5_handle, 0), HASH_MD5_LENGTH);
	}

	gcry_md_close(md5_handle);
}

static void
add_avp_to_tree_with_dissector(proto_tree *avp_tree, proto_item *avp_item, packet_info *pinfo, tvbuff_t *tvb, radius_avp_dissector_t *avp_dissector, guint32 avp_length, guint32 offset);


void
radius_integer(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	guint32 uintv;

	switch (len) {
		case 1:
			uintv = tvb_get_guint8(tvb, offset);
			break;
		case 2:
			uintv = tvb_get_ntohs(tvb, offset);
			break;
		case 3:
			uintv = tvb_get_ntoh24(tvb, offset);
			break;
		case 4:
			uintv = tvb_get_ntohl(tvb, offset);
			break;
		case 8: {
			guint64 uintv64 = tvb_get_ntoh64(tvb, offset);
			proto_tree_add_uint64(tree, a->hf_alt, tvb, offset, len, uintv64);
			proto_item_append_text(avp_item, "%" PRIu64, uintv64);
			return;
		}
		default:
			proto_item_append_text(avp_item, "[unhandled integer length(%u)]", len);
			return;
	}
	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_BIG_ENDIAN);

	if (a->vs) {
		proto_item_append_text(avp_item, "%s(%u)", val_to_str_const(uintv, a->vs, "Unknown"), uintv);
	} else {
		proto_item_append_text(avp_item, "%u", uintv);
	}
}

void
radius_signed(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	guint32 uintv;

	switch (len) {
		case 1:
			uintv = tvb_get_guint8(tvb, offset);
			break;
		case 2:
			uintv = tvb_get_ntohs(tvb, offset);
			break;
		case 3:
			uintv = tvb_get_ntoh24(tvb, offset);
			break;
		case 4:
			uintv = tvb_get_ntohl(tvb, offset);
			break;
		case 8: {
			guint64 uintv64 = tvb_get_ntoh64(tvb, offset);
			proto_tree_add_int64(tree, a->hf_alt, tvb, offset, len, uintv64);
			proto_item_append_text(avp_item, "%" PRIu64, uintv64);
			return;
		}
		default:
			proto_item_append_text(avp_item, "[unhandled signed integer length(%u)]", len);
			return;
	}

	proto_tree_add_int(tree, a->hf, tvb, offset, len, uintv);

	if (a->vs) {
		proto_item_append_text(avp_item, "%s(%d)", val_to_str_const(uintv, a->vs, "Unknown"), uintv);
	} else {
		proto_item_append_text(avp_item, "%d", uintv);
	}
}

void
radius_string(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	switch (a->encrypt) {

	case 0: /* not encrypted */
		proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_UTF_8|ENC_NA);
		proto_item_append_text(avp_item, "%s", tvb_format_text(pinfo->pool, tvb, offset, len));
		break;

	case 1: /* encrypted like User-Password as defined in RFC 2865 */
		if (*shared_secret == '\0') {
			proto_item_append_text(avp_item, "Encrypted");
			proto_tree_add_item(tree, a->hf_alt, tvb, offset, len, ENC_NA);
		} else {
			gchar *buffer;
			buffer = (gchar *)wmem_alloc(wmem_packet_scope(), 1024); /* an AVP value can be at most 253 bytes */
			radius_decrypt_avp(buffer, 1024, tvb, offset, len);
			proto_item_append_text(avp_item, "Decrypted: %s", buffer);
			proto_tree_add_string(tree, a->hf, tvb, offset, len, buffer);
		}
		break;

	case 2: /* encrypted like Tunnel-Password as defined in RFC 2868 */
		proto_item_append_text(avp_item, "Encrypted");
		proto_tree_add_item(tree, a->hf_alt, tvb, offset, len, ENC_NA);
		break;

	case 3: /* encrypted like Ascend-Send-Secret as defined by Ascend^WLucent^WAlcatel-Lucent */
		proto_item_append_text(avp_item, "Encrypted");
		proto_tree_add_item(tree, a->hf_alt, tvb, offset, len, ENC_NA);
		break;
	}
}

void
radius_octets(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	if (len == 0) {
		proto_item_append_text(avp_item, "[wrong length]");
		return;
	}

	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);
	proto_item_append_text(avp_item, "%s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, len));
}

void
radius_ipaddr(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{

	if (len != 4) {
		proto_item_append_text(avp_item, "[wrong length for IP address]");
		return;
	}

	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_BIG_ENDIAN);

	proto_item_append_text(avp_item, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
}

void
radius_ipv6addr(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{

	if (len != 16) {
		proto_item_append_text(avp_item, "[wrong length for IPv6 address]");
		return;
	}

	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);

	proto_item_append_text(avp_item, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
}

void
radius_ipv6prefix(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	ws_in6_addr ipv6_buff;
	gchar txtbuf[256];
	guint8 n;

	if ((len < 2) || (len > 18)) {
		proto_item_append_text(avp_item, "[wrong length for IPv6 prefix]");
		return;
	}

	/* first byte is reserved == 0x00 */
	if (tvb_get_guint8(tvb, offset)) {
		proto_item_append_text(avp_item, "[invalid reserved byte for IPv6 prefix]");
		return;
	}

	/* this is the prefix length */
	n = tvb_get_guint8(tvb, offset + 1);
	if (n > 128) {
		proto_item_append_text(avp_item, "[invalid IPv6 prefix length]");
		return;
	}

	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);

	/* cannot use tvb_get_ipv6() here, since the prefix most likely is truncated */
	memset(&ipv6_buff, 0, sizeof ipv6_buff);
	tvb_memcpy(tvb, &ipv6_buff, offset + 2,  len - 2);
	ip6_to_str_buf(&ipv6_buff, txtbuf, sizeof(txtbuf));
	proto_item_append_text(avp_item, "%s/%u", txtbuf, n);
}


void
radius_combo_ip(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{

	if (len == 4) {
		proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_BIG_ENDIAN);
		proto_item_append_text(avp_item, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
	} else if (len == 16) {
		proto_tree_add_item(tree, a->hf_alt, tvb, offset, len, ENC_NA);
		proto_item_append_text(avp_item, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
	} else {
		proto_item_append_text(avp_item, "[wrong length for both of IPv4 and IPv6 address]");
		return;
	}
}

void
radius_ipxnet(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	guint32 net;

	if (len != 4) {
		proto_item_append_text(avp_item, "[wrong length for IPX network]");
		return;
	}

	net = tvb_get_ntohl(tvb, offset);

	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);

	proto_item_append_text(avp_item, "0x%08X", net);
}

void
radius_date(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	nstime_t time_ptr;

	if (len != 4) {
		proto_item_append_text(avp_item, "[wrong length for timestamp]");
		return;
	}

	time_ptr.secs = tvb_get_ntohl(tvb, offset);
	time_ptr.nsecs = 0;

	proto_tree_add_time(tree, a->hf, tvb, offset, len, &time_ptr);
	proto_item_append_text(avp_item, "%s", abs_time_to_str(wmem_packet_scope(), &time_ptr, ABSOLUTE_TIME_LOCAL, TRUE));
}

/*
 * "abinary" is Ascend's binary format for filters.  See dissect_ascend_data_filter().
 */
void
radius_abinary(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	if (a->code.u8_code[0] == 242) {
		add_avp_to_tree_with_dissector(tree, avp_item, pinfo, tvb, dissect_ascend_data_filter, len, offset);
		return;
	}
	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);
	proto_item_append_text(avp_item, "%s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, len));
}

void
radius_ether(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	if (len != 6) {
		proto_item_append_text(avp_item, "[wrong length for ethernet address]");
		return;
	}

	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);
	proto_item_append_text(avp_item, "%s", tvb_ether_to_str(pinfo->pool, tvb, offset));
}

void
radius_ifid(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	proto_tree_add_item(tree, a->hf, tvb, offset, len, ENC_NA);
	proto_item_append_text(avp_item, "%s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, len));
}

static void
add_tlv_to_tree(proto_tree *tlv_tree, proto_item *tlv_item, packet_info *pinfo, tvbuff_t *tvb, radius_attr_info_t *dictionary_entry, guint32 tlv_length, guint32 offset)
{
	proto_item_append_text(tlv_item, ": ");
	dictionary_entry->type(dictionary_entry, tlv_tree, pinfo, tvb, offset, tlv_length, tlv_item);
}

void
radius_tlv(radius_attr_info_t *a, proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, int offset, int len, proto_item *avp_item)
{
	gint tlv_num = 0;

	while (len > 0) {
		radius_attr_info_t *dictionary_entry = NULL;
		guint32 tlv_type;
		guint32 tlv_length;

		proto_item *tlv_item;
		proto_item *tlv_len_item;
		proto_tree *tlv_tree;

		if (len < 2) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "Not enough room in packet for TLV header");
			return;
		}
		tlv_type = tvb_get_guint8(tvb, offset);
		tlv_length = tvb_get_guint8(tvb, offset+1);

		if (tlv_length < 2) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "TLV too short: length %u < 2", tlv_length);
			return;
		}

		if (len < (gint)tlv_length) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "Not enough room in packet for TLV");
			return;
		}

		len -= tlv_length;

		dictionary_entry = (radius_attr_info_t *)g_hash_table_lookup(a->tlvs_by_id, GUINT_TO_POINTER(tlv_type));

		if (!dictionary_entry) {
			dictionary_entry = &no_dictionary_entry;
		}

		tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, tlv_length,
					       dictionary_entry->ett, &tlv_item, "TLV: t=%s(%u) l=%u ", dictionary_entry->name, tlv_type,
					       tlv_length);

		tlv_length -= 2;
		offset += 2;

		if (show_length) {
			tlv_len_item = proto_tree_add_uint(tlv_tree,
							   dictionary_entry->hf_len,
							   tvb, 0, 0, tlv_length);
			proto_item_set_generated(tlv_len_item);
		}

		add_tlv_to_tree(tlv_tree, tlv_item, pinfo, tvb, dictionary_entry,
				tlv_length, offset);
		offset += tlv_length;
		tlv_num++;
	}

	proto_item_append_text(avp_item, "%d TLV(s) inside", tlv_num);
}

static void
add_avp_to_tree_with_dissector(proto_tree *avp_tree, proto_item *avp_item, packet_info *pinfo, tvbuff_t *tvb, radius_avp_dissector_t *avp_dissector, guint32 avp_length, guint32 offset)
{
	tvbuff_t *tvb_value;
	const gchar *str;

	tvb_value = tvb_new_subset_length(tvb, offset, avp_length);
	str = avp_dissector(avp_tree, tvb_value, pinfo);
	proto_item_append_text(avp_item, "%s", str);
}

static void
add_avp_to_tree(proto_tree *avp_tree, proto_item *avp_item, packet_info *pinfo, tvbuff_t *tvb, radius_attr_info_t *dictionary_entry, guint32 avp_length, guint32 offset)
{

	if (dictionary_entry->tagged) {
		guint tag;

		if (avp_length == 0) {
			proto_tree_add_expert_format(avp_tree, pinfo, &ei_radius_invalid_length, tvb, offset,
						 0, "AVP too short for tag");
			return;
		}

		tag = tvb_get_guint8(tvb, offset);

		if (tag <=  0x1f) {
			proto_tree_add_uint(avp_tree,
					    dictionary_entry->hf_tag,
					    tvb, offset, 1, tag);

			proto_item_append_text(avp_item,
					       " Tag=0x%.2x", tag);

			offset++;
			avp_length--;
		}
	}

	proto_item_append_text(avp_item, " val=");

	if (dictionary_entry->dissector) {
		add_avp_to_tree_with_dissector(avp_tree, avp_item, pinfo, tvb, dictionary_entry->dissector, avp_length, offset);
		return;
	}

	dictionary_entry->type(dictionary_entry, avp_tree, pinfo, tvb, offset, avp_length, avp_item);
}

static gboolean
vsa_buffer_destroy(gpointer k _U_, gpointer v, gpointer p _U_)
{
	radius_vsa_buffer *vsa_buffer = (radius_vsa_buffer *)v;
	g_free((gpointer)vsa_buffer->data);
	g_free(v);
	return TRUE;
}

static void
eap_buffer_free_indirect(void *context)
{
	guint8 *eap_buffer = *(guint8 **)context;
	g_free(eap_buffer);
}

static void
vsa_buffer_table_destroy_indirect(void *context)
{
	GHashTable *vsa_buffer_table = *(GHashTable **)context;
	if (vsa_buffer_table) {
		g_hash_table_foreach_remove(vsa_buffer_table, vsa_buffer_destroy, NULL);
		g_hash_table_destroy(vsa_buffer_table);
	}
}

void
dissect_attribute_value_pairs(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, guint length)
{
	gboolean last_eap = FALSE;
	guint8 *eap_buffer = NULL;
	guint eap_seg_num = 0;
	guint eap_tot_len_captured = 0;
	guint eap_tot_len = 0;
	proto_tree *eap_tree = NULL;
	tvbuff_t *eap_tvb = NULL;

	GHashTable *vsa_buffer_table = NULL;

	if (hf_radius_code == -1)
		proto_registrar_get_byname("radius.code");

	/*
	 * In case we throw an exception, clean up whatever stuff we've
	 * allocated (if any).
	 */
	CLEANUP_PUSH_PFX(la, eap_buffer_free_indirect, &eap_buffer);
	CLEANUP_PUSH_PFX(lb, vsa_buffer_table_destroy_indirect, &vsa_buffer_table);

	while (length > 0) {
		radius_attr_info_t *dictionary_entry = NULL;
		guint32 avp_type0 = 0, avp_type1 = 0;
		radius_attr_type_t avp_type;
		guint32 avp_length;
		guint32 vendor_id;
		gboolean avp_is_extended = FALSE;
		int avp_offset_start = offset;

		proto_item *avp_item;
		proto_item *avp_len_item;
		proto_tree *avp_tree;

		if (length < 2) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "Not enough room in packet for AVP header");
			break;  /* exit outer loop, then cleanup & return */
		}

		avp_type0 = tvb_get_guint8(tvb, offset);
		avp_length = tvb_get_guint8(tvb, offset+1);
		avp_is_extended = RADIUS_ATTR_TYPE_IS_EXTENDED(avp_type0);
		if (avp_is_extended) {
			avp_type1 = tvb_get_guint8(tvb, offset+2);
		}
		memset(&avp_type, 0, sizeof(avp_type));
		avp_type.u8_code[0] = avp_type0;
		avp_type.u8_code[1] = avp_type1;

		if (disable_extended_attributes) {
			avp_is_extended = FALSE;
			avp_type.u8_code[1] = 0;
		}

		if (avp_length < 2) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "AVP too short: length %u < 2", avp_length);
			break;  /* exit outer loop, then cleanup & return */
		}

		if (avp_is_extended && avp_length < 3) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "Extended AVP too short: length %u < 3", avp_length);
			break;  /* exit outer loop, then cleanup & return */
		}

		if (length < avp_length) {
			proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset, 0,
						   "Not enough room in packet for AVP");
			break;  /* exit outer loop, then cleanup & return */
		}

		length -= avp_length;

		dictionary_entry = (radius_attr_info_t *)g_hash_table_lookup(dict->attrs_by_id, GUINT_TO_POINTER(avp_type.value));

		if (!dictionary_entry) {
			dictionary_entry = &no_dictionary_entry;
		}

		avp_item = proto_tree_add_bytes_format_value(tree, hf_radius_avp, tvb, offset, avp_length,
					       NULL, "t=%s", dictionary_entry->name);
		if (avp_is_extended)
			proto_item_append_text(avp_item, "(%u.%u)", avp_type0, avp_type1);
		else
			proto_item_append_text(avp_item, "(%u)", avp_type0);

		proto_item_append_text(avp_item, " l=%u", avp_length);

		avp_length -= 2;
		offset += 2;
		if (avp_is_extended) {
			avp_length -= 1;
			offset += 1;
			if (RADIUS_ATTR_TYPE_IS_EXTENDED_LONG(avp_type0)) {
				avp_length -= 1;
				offset += 1;
			}
		}

		if (avp_type0 == RADIUS_ATTR_TYPE_VENDOR_SPECIFIC || (avp_is_extended && avp_type1 == RADIUS_ATTR_TYPE_VENDOR_SPECIFIC)) {
			radius_vendor_info_t *vendor;
			proto_tree *vendor_tree;
			gint max_offset = offset + avp_length;
			const gchar *vendor_str;
			int vendor_offset;

			/* XXX TODO: handle 2 byte codes for USR */

			if (avp_length < 4) {
				expert_add_info_format(pinfo, avp_item, &ei_radius_invalid_length, "AVP too short; no room for vendor ID");
				offset += avp_length;
				continue; /* while (length > 0) */
			}
			vendor_id = tvb_get_ntohl(tvb, offset);

			avp_length -= 4;
			offset += 4;

			vendor = (radius_vendor_info_t *)g_hash_table_lookup(dict->vendors_by_id, GUINT_TO_POINTER(vendor_id));
			vendor_str = enterprises_lookup(vendor_id, "Unknown");
			if (!vendor) {
				vendor = &no_vendor;
			}
			proto_item_append_text(avp_item, " vnd=%s(%u)", vendor_str,
					       vendor_id);

			vendor_tree = proto_item_add_subtree(avp_item, vendor->ett);

			vendor_offset = avp_offset_start;
			proto_tree_add_item(vendor_tree, hf_radius_avp_type, tvb, vendor_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(vendor_tree, hf_radius_avp_length, tvb, vendor_offset+1, 1, ENC_BIG_ENDIAN);
			vendor_offset += 2;
			if (avp_is_extended) {
				proto_tree_add_item(vendor_tree, hf_radius_avp_extended_type, tvb, vendor_offset, 1, ENC_BIG_ENDIAN);
				vendor_offset += 1;
				if (RADIUS_ATTR_TYPE_IS_EXTENDED_LONG(avp_type0)) {
					proto_tree_add_item(vendor_tree, hf_radius_avp_extended_more, tvb, vendor_offset, 1, ENC_BIG_ENDIAN);
					vendor_offset += 1;
				}
			}
			proto_tree_add_uint_format_value(vendor_tree, hf_radius_avp_vendor_id, tvb, vendor_offset, 4, vendor_id, "%s (%u)", vendor_str, vendor_id);
			vendor_offset += 4;

			while (offset < max_offset) {
				radius_attr_type_t vendor_type;
				guint32 avp_vsa_type;
				guint32 avp_vsa_len;
				guint8 avp_vsa_flags = 0;
				guint32 avp_vsa_header_len;
				guint32 vendor_attribute_len;

				switch (vendor->type_octets) {
					case 1:
						avp_vsa_type = tvb_get_guint8(tvb, offset++);
						break;
					case 2:
						avp_vsa_type = tvb_get_ntohs(tvb, offset);
						offset += 2;
						break;
					case 4:
						avp_vsa_type = tvb_get_ntohl(tvb, offset);
						offset += 4;
						break;
					default:
						/* vendor->type_octets = 1; */
						DISSECTOR_ASSERT_NOT_REACHED();
						break;
				}

				if (!avp_is_extended) {
					switch (vendor->length_octets) {
						case 1:
							avp_vsa_len = tvb_get_guint8(tvb, offset++);
							break;
						case 0:
							avp_vsa_len = avp_length;
							break;
						case 2:
							avp_vsa_len = tvb_get_ntohs(tvb, offset);
							offset += 2;
							break;
						default:
							/* vendor->length_octets = 1; */
							DISSECTOR_ASSERT_NOT_REACHED();
							break;
					}
					avp_vsa_header_len = vendor->type_octets + vendor->length_octets + (vendor->has_flags ? 1 : 0);
				} else {
					avp_vsa_len = avp_length;
					avp_vsa_header_len = vendor->type_octets + (vendor->has_flags ? 1 : 0);
				}

				if (vendor->has_flags) {
					avp_vsa_flags = tvb_get_guint8(tvb, offset++);
				}

				if (avp_vsa_len < avp_vsa_header_len) {
					proto_tree_add_expert_format(tree, pinfo, &ei_radius_invalid_length, tvb, offset+1, 1,
							    "VSA too short");
					break; /* exit while (offset < max_offset) loop */
				}

				avp_vsa_len -= avp_vsa_header_len;

				memset(&vendor_type, 0, sizeof(vendor_type));
				if (avp_is_extended) {
					vendor_type.u8_code[0] = avp_type.u8_code[0];
					vendor_type.u8_code[1] = avp_vsa_type;
				} else {
					vendor_type.u8_code[0] = avp_vsa_type;
					vendor_type.u8_code[1] = 0;
				}
				if (vendor->attrs_by_id) {
					dictionary_entry = (radius_attr_info_t *)g_hash_table_lookup(vendor->attrs_by_id, GUINT_TO_POINTER(vendor_type.value));
				} else {
					dictionary_entry = NULL;
				}

				if (!dictionary_entry) {
					dictionary_entry = &no_dictionary_entry;
				}

				if (vendor->has_flags) {
					avp_tree = proto_tree_add_subtree_format(vendor_tree, tvb, offset-avp_vsa_header_len, avp_vsa_len+avp_vsa_header_len,
								       dictionary_entry->ett, &avp_item, "VSA: t=%s(%u) l=%u C=0x%02x",
								       dictionary_entry->name, avp_vsa_type, avp_vsa_len+avp_vsa_header_len, avp_vsa_flags);
				} else if (avp_is_extended) {
					avp_tree = proto_tree_add_subtree_format(vendor_tree, tvb, offset-avp_vsa_header_len, avp_vsa_len+avp_vsa_header_len,
								       dictionary_entry->ett, &avp_item, "EVS: t=%s(%u) l=%u",
								        dictionary_entry->name, avp_vsa_type, avp_vsa_len+avp_vsa_header_len);
				} else {
					avp_tree = proto_tree_add_subtree_format(vendor_tree, tvb, offset-avp_vsa_header_len, avp_vsa_len+avp_vsa_header_len,
								       dictionary_entry->ett, &avp_item, "VSA: t=%s(%u) l=%u",
								       dictionary_entry->name, avp_vsa_type, avp_vsa_len+avp_vsa_header_len);
				}

				proto_tree_add_item(avp_tree, hf_radius_avp_vendor_type, tvb, vendor_offset, vendor->type_octets, ENC_BIG_ENDIAN);
				vendor_offset += vendor->type_octets;
				if (!avp_is_extended && vendor->length_octets) {
					proto_tree_add_item_ret_uint(avp_tree, hf_radius_avp_vendor_len, tvb, vendor_offset, vendor->length_octets, ENC_BIG_ENDIAN, &vendor_attribute_len);
					vendor_offset += (vendor_attribute_len - vendor->type_octets);
				}

				if (show_length) {
					avp_len_item = proto_tree_add_uint(avp_tree,
									   dictionary_entry->hf_len,
									   tvb, 0, 0, avp_length);
					proto_item_set_generated(avp_len_item);
				}

				if (vendor->has_flags) {
					/*
					 *       WiMAX VSA's have a non-standard format:
					 *
					 *               type            1 octet
					 *               length          1 octet
					 *               continuation    1 octet      0bcrrrrrrr
					 *               value           1+ octets
					 *
					 *       If the high bit of the "continuation" field is set, then
					 *       the next attribute of the same WiMAX type should have it's
					 *       value concatenated to this one.
					 *
					 *       See "dictionary.wimax" from FreeRADIUS for details and references.
					 */
					radius_vsa_buffer_key key;
					radius_vsa_buffer *vsa_buffer = NULL;
					key.vendor_id = vendor_id;
					key.vsa_type = avp_vsa_type;

					if (!vsa_buffer_table) {
						vsa_buffer_table = g_hash_table_new(radius_vsa_hash, radius_vsa_equal);
					}

					vsa_buffer = (radius_vsa_buffer *)g_hash_table_lookup(vsa_buffer_table, &key);
					if (vsa_buffer) {
						vsa_buffer->data = (guint8 *)g_realloc(vsa_buffer->data, vsa_buffer->len + avp_vsa_len);
						tvb_memcpy(tvb, vsa_buffer->data + vsa_buffer->len, offset, avp_vsa_len);
						vsa_buffer->len += avp_vsa_len;
						vsa_buffer->seg_num++;
					}

					if (avp_vsa_flags & 0x80) {
						if (!vsa_buffer) {
							vsa_buffer = g_new(radius_vsa_buffer, 1);
							vsa_buffer->key.vendor_id = vendor_id;
							vsa_buffer->key.vsa_type = avp_vsa_type;
							vsa_buffer->len = avp_vsa_len;
							vsa_buffer->seg_num = 1;
							vsa_buffer->data = (guint8 *)g_malloc(avp_vsa_len);
							tvb_memcpy(tvb, vsa_buffer->data, offset, avp_vsa_len);
							g_hash_table_insert(vsa_buffer_table, &(vsa_buffer->key), vsa_buffer);
						}
						proto_tree_add_item(avp_tree, hf_radius_vsa_fragment, tvb, offset, avp_vsa_len, ENC_NA);
						proto_item_append_text(avp_item, ": VSA fragment[%u]", vsa_buffer->seg_num);
					} else {
						if (vsa_buffer) {
							tvbuff_t *vsa_tvb = NULL;
							proto_tree_add_item(avp_tree, hf_radius_vsa_fragment, tvb, offset, avp_vsa_len, ENC_NA);
							proto_item_append_text(avp_item, ": Last VSA fragment[%u]", vsa_buffer->seg_num);
							vsa_tvb = tvb_new_child_real_data(tvb, vsa_buffer->data, vsa_buffer->len, vsa_buffer->len);
							tvb_set_free_cb(vsa_tvb, g_free);
							add_new_data_source(pinfo, vsa_tvb, "Reassembled VSA");
							add_avp_to_tree(avp_tree, avp_item, pinfo, vsa_tvb, dictionary_entry, vsa_buffer->len, 0);
							g_hash_table_remove(vsa_buffer_table, &(vsa_buffer->key));
							g_free(vsa_buffer);

						} else {
							add_avp_to_tree(avp_tree, avp_item, pinfo, tvb, dictionary_entry, avp_vsa_len, offset);
						}
					}
				} else {
					add_avp_to_tree(avp_tree, avp_item, pinfo, tvb, dictionary_entry, avp_vsa_len, offset);
				}

				offset += avp_vsa_len;
			} /* while (offset < max_offset) */
			continue;  /* while (length > 0) */
		}

		avp_tree = proto_item_add_subtree(avp_item, dictionary_entry->ett);

		proto_tree_add_item(avp_tree, hf_radius_avp_type, tvb, avp_offset_start, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(avp_tree, hf_radius_avp_length, tvb, avp_offset_start+1, 1, ENC_BIG_ENDIAN);

		if (show_length) {
			avp_len_item = proto_tree_add_uint(avp_tree,
							   dictionary_entry->hf_len,
							   tvb, 0, 0, avp_length);
			proto_item_set_generated(avp_len_item);
		}

		if (avp_is_extended) {
			proto_tree_add_item(avp_tree, hf_radius_avp_extended_type, tvb, avp_offset_start+2, 1, ENC_BIG_ENDIAN);
			if (RADIUS_ATTR_TYPE_IS_EXTENDED_LONG(avp_type0)) {
				proto_tree_add_item(avp_tree, hf_radius_avp_extended_more, tvb, avp_offset_start+3, 1, ENC_BIG_ENDIAN);
			}
		}

		if (avp_type0 == RADIUS_ATTR_TYPE_EAP_MESSAGE) {
			gint tvb_len;

			eap_seg_num++;

			tvb_len = tvb_captured_length_remaining(tvb, offset);

			if ((gint)avp_length < tvb_len)
				tvb_len = avp_length;

			/* Show this as an EAP fragment. */
			proto_tree_add_item(avp_tree, hf_radius_eap_fragment, tvb, offset, tvb_len, ENC_NA);

			if (eap_tvb != NULL) {
				/*
				 * Oops, a non-consecutive EAP-Message
				 * attribute.
				 */
				proto_item_append_text(avp_item, " (non-consecutive)");
			} else {
				/*
				 * RFC 2869 says, in section 5.13, describing
				 * the EAP-Message attribute:
				 *
				 *    The NAS places EAP messages received
				 *    from the authenticating peer into one
				 *    or more EAP-Message attributes and
				 *    forwards them to the RADIUS Server
				 *    within an Access-Request message.
				 *    If multiple EAP-Messages are
				 *    contained within an Access-Request or
				 *    Access-Challenge packet, they MUST be
				 *    in order and they MUST be consecutive
				 *    attributes in the Access-Request or
				 *    Access-Challenge packet.
				 *
				 *	...
				 *
				 *    The String field contains EAP packets,
				 *    as defined in [3].  If multiple
				 *    EAP-Message attributes are present
				 *    in a packet their values should be
				 *    concatenated; this allows EAP packets
				 *    longer than 253 octets to be passed
				 *    by RADIUS.
				 *
				 * Do reassembly of EAP-Message attributes.
				 * We just concatenate all the attributes,
				 * and when we see either the end of the
				 * attribute list or a non-EAP-Message
				 * attribute, we know we're done.
				 */

				if (eap_buffer == NULL)
					eap_buffer = (guint8 *)g_malloc(eap_tot_len_captured + tvb_len);
				else
					eap_buffer = (guint8 *)g_realloc(eap_buffer,
							       eap_tot_len_captured + tvb_len);
				tvb_memcpy(tvb, eap_buffer + eap_tot_len_captured, offset,
					   tvb_len);
				eap_tot_len_captured += tvb_len;
				eap_tot_len += avp_length;

				if (tvb_bytes_exist(tvb, offset + avp_length + 1, 1)) {
					guint8 next_type = tvb_get_guint8(tvb, offset + avp_length);

					if (next_type != RADIUS_ATTR_TYPE_EAP_MESSAGE) {
						/* Non-EAP-Message attribute */
						last_eap = TRUE;
					}
				} else {
					/*
					 * No more attributes, either because
					 * we're at the end of the packet or
					 * because we're at the end of the
					 * captured packet data.
					 */
					last_eap = TRUE;
				}

				if (last_eap && eap_buffer) {
					gboolean save_writable;

					proto_item_append_text(avp_item, " Last Segment[%u]",
							       eap_seg_num);

					eap_tree = proto_item_add_subtree(avp_item, ett_eap);

					eap_tvb = tvb_new_child_real_data(tvb, eap_buffer,
									  eap_tot_len_captured,
									  eap_tot_len);
					tvb_set_free_cb(eap_tvb, g_free);
					add_new_data_source(pinfo, eap_tvb, "Reassembled EAP");

					/*
					 * Don't free this when we're done -
					 * it's associated with a tvbuff.
					 */
					eap_buffer = NULL;

					/*
					 * Set the columns non-writable,
					 * so that the packet list shows
					 * this as an RADIUS packet, not
					 * as an EAP packet.
					 */
					save_writable = col_get_writable(pinfo->cinfo, -1);
					col_set_writable(pinfo->cinfo, -1, FALSE);

					call_dissector(eap_handle, eap_tvb, pinfo, eap_tree);

					col_set_writable(pinfo->cinfo, -1, save_writable);
				} else {
					proto_item_append_text(avp_item, " Segment[%u]",
							       eap_seg_num);
				}
			}

			offset += avp_length;
			continue;
		}

		add_avp_to_tree(avp_tree, avp_item, pinfo, tvb, dictionary_entry,
				avp_length, offset);
		offset += avp_length;

	}  /* while (length > 0) */

	CLEANUP_CALL_AND_POP_PFX(lb); /* vsa_buffer_table_destroy_indirect(&vsa_buffer_table) */

	/*
	 * Call the cleanup handler to free any reassembled data we haven't
	 * attached to a tvbuff, and pop the handler.
	 */
	CLEANUP_CALL_AND_POP_PFX(la); /* eap_buffer_free_indirect(&eap_buffer); */
}

/* This function tries to determine whether a packet is radius or not */
static gboolean
is_radius(tvbuff_t *tvb)
{
	guint8 code;
	guint16 length;

	code = tvb_get_guint8(tvb, 0);
	if (try_val_to_str_ext(code, &radius_pkt_type_codes_ext) == NULL) {
		return FALSE;
	}

	/* Check for valid length value:
	 * Length
	 *
	 *  The Length field is two octets.  It indicates the length of the
	 *  packet including the Code, Identifier, Length, Authenticator and
	 *  Attribute fields.  Octets outside the range of the Length field
	 *  MUST be treated as padding and ignored on reception.  If the
	 *  packet is shorter than the Length field indicates, it MUST be
	 *  silently discarded.  The minimum length is 20 and maximum length
	 *  is 4096.
	 */
	length = tvb_get_ntohs(tvb, 2);
	if ((length < 20) || (length > 4096)) {
		return FALSE;
	}

	return TRUE;
}

/*
 * returns true if the response or accounting request authenticator is valid
 * input: tvb of the response, corresponding request authenticator (not used for request),
 * uses the shared secret to calculate the authenticator
 * and checks with the current.
 * see RFC 2865, packet format page 16
 * see RFC 2866, Request Authenticator page 7
 */
static gboolean
valid_authenticator(tvbuff_t *tvb, guint8 request_authenticator[], int request)
{
	gcry_md_hd_t md5_handle;
	guint8 *digest;
	gboolean result;
	guint tvb_length;
	guint8 *payload;

	tvb_length = tvb_captured_length(tvb); /* should it be tvb_reported_length ? */

	/* copy response into payload */
	payload = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, 0, tvb_length);

	if (request) {
		/* reset authenticator field */
		memset(payload+4, 0, AUTHENTICATOR_LENGTH);
	} else {
		/* replace authenticator in reply with the one in request */
		memcpy(payload+4, request_authenticator, AUTHENTICATOR_LENGTH);
	}

	/* calculate MD5 hash (payload+shared_secret) */
	if (gcry_md_open(&md5_handle, GCRY_MD_MD5, 0)) {
		return FALSE;
	}
	gcry_md_write(md5_handle, payload, tvb_length);
	gcry_md_write(md5_handle, shared_secret, strlen(shared_secret));
	digest = gcry_md_read(md5_handle, 0);

	result = !memcmp(digest, authenticator, AUTHENTICATOR_LENGTH);
	gcry_md_close(md5_handle);
	return result;
}

static int
dissect_radius(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree *radius_tree = NULL;
	proto_tree *avptree = NULL;
	proto_item *ti, *hidden_item, *authenticator_item = NULL;
	guint avplength;
	e_radiushdr rh;
	radius_info_t *rad_info;

	conversation_t *conversation;
	radius_call_info_key radius_call_key;
	radius_call_info_key *new_radius_call_key;
	wmem_tree_t *radius_call_tree;
	radius_call_t *radius_call = NULL;
	static address null_address = ADDRESS_INIT_NONE;

	/* does this look like radius ? */
	if (!is_radius(tvb)) {
		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RADIUS");
	col_clear(pinfo->cinfo, COL_INFO);

	rh.rh_code = tvb_get_guint8(tvb, 0);
	rh.rh_ident = tvb_get_guint8(tvb, 1);
	rh.rh_pktlength = tvb_get_ntohs(tvb, 2);


	/* Initialise stat info for passing to tap */
	rad_info = wmem_new(wmem_packet_scope(), radius_info_t);
	rad_info->req_time.secs = 0;
	rad_info->req_time.nsecs = 0;
	rad_info->is_duplicate = FALSE;
	rad_info->request_available = FALSE;
	rad_info->req_num = 0; /* frame number request seen */
	rad_info->rspcode = 0;
	/* tap stat info */
	rad_info->code = rh.rh_code;
	rad_info->ident = rh.rh_ident;
	tap_queue_packet(radius_tap, pinfo, rad_info);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s id=%d",
			val_to_str_ext_const(rh.rh_code, &radius_pkt_type_codes_ext, "Unknown Packet"),
			rh.rh_ident);

	/* Load header fields if not already done */
	if (hf_radius_code == -1)
		proto_registrar_get_byname("radius.code");

	ti = proto_tree_add_item(tree, proto_radius, tvb, 0, rh.rh_pktlength, ENC_NA);
	radius_tree = proto_item_add_subtree(ti, ett_radius);
	proto_tree_add_uint(radius_tree, hf_radius_code, tvb, 0, 1, rh.rh_code);
	proto_tree_add_uint_format(radius_tree, hf_radius_id, tvb, 1, 1, rh.rh_ident,
		"Packet identifier: 0x%01x (%d)", rh.rh_ident, rh.rh_ident);

	/*
	 * Make sure the length is sane.
	 */
	if (rh.rh_pktlength < HDR_LENGTH) {
		proto_tree_add_uint_format_value(radius_tree, hf_radius_length,
			tvb, 2, 2, rh.rh_pktlength, "%u (bogus, < %u)",
			rh.rh_pktlength, HDR_LENGTH);
		return tvb_captured_length(tvb);
	}

	avplength = rh.rh_pktlength - HDR_LENGTH;
	proto_tree_add_uint(radius_tree, hf_radius_length, tvb, 2, 2, rh.rh_pktlength);
	authenticator_item = proto_tree_add_item(radius_tree, hf_radius_authenticator, tvb, 4, AUTHENTICATOR_LENGTH, ENC_NA);
	tvb_memcpy(tvb, authenticator, 4, AUTHENTICATOR_LENGTH);

	/* Conversation support REQUEST/RESPONSES */
	switch (rh.rh_code)
	{
		case RADIUS_PKT_TYPE_ACCESS_REQUEST:
		case RADIUS_PKT_TYPE_ACCOUNTING_REQUEST:
		case RADIUS_PKT_TYPE_PASSWORD_REQUEST:
		case RADIUS_PKT_TYPE_RESOURCE_FREE_REQUEST:
		case RADIUS_PKT_TYPE_RESOURCE_QUERY_REQUEST:
		case RADIUS_PKT_TYPE_NAS_REBOOT_REQUEST:
		case RADIUS_PKT_TYPE_EVENT_REQUEST:
		case RADIUS_PKT_TYPE_DISCONNECT_REQUEST:
		case RADIUS_PKT_TYPE_COA_REQUEST:
		case RADIUS_PKT_TYPE_ALU_STATE_REQUEST:
			/* Don't bother creating conversations if we're encapsulated within
			 * an error packet, such as an ICMP destination unreachable */
			if (pinfo->flags.in_error_pkt)
				break;

			hidden_item = proto_tree_add_boolean(radius_tree, hf_radius_req, tvb, 0, 0, TRUE);
			proto_item_set_hidden(hidden_item);

			/* Keep track of the address and port whence the call came
			 *  so that we can match up requests with replies.
			 *
			 * Because it is UDP and the reply can come from any IP
			 * and port (not necessarily the request dest), we only
			 * track the source IP and port of the request to match
			 * the reply.
			 */

			/*
			 * XXX - can we just use NO_ADDR_B?  Unfortunately,
			 * you currently still have to pass a non-null
			 * pointer for the second address argument even
			 * if you do that.
			 */
			conversation = find_conversation(pinfo->num, &pinfo->src,
				&null_address, conversation_pt_to_conversation_type(pinfo->ptype), pinfo->srcport,
				pinfo->destport, 0);
			if (conversation == NULL)
			{
				/* It's not part of any conversation - create a new one. */
				conversation = conversation_new(pinfo->num, &pinfo->src,
					&null_address, conversation_pt_to_conversation_type(pinfo->ptype), pinfo->srcport,
					pinfo->destport, 0);
			}

			/* Prepare the key data */
			radius_call_key.code = rh.rh_code;
			radius_call_key.ident = rh.rh_ident;
			radius_call_key.conversation = conversation;
			radius_call_key.req_time = pinfo->abs_ts;

			/* Look up the tree of calls with this ident */
			radius_call_tree = (wmem_tree_t *)wmem_map_lookup(radius_calls, &radius_call_key);

			if (!radius_call_tree) {
				radius_call_tree = wmem_tree_new(wmem_file_scope());
				new_radius_call_key = wmem_new(wmem_file_scope(), radius_call_info_key);
				*new_radius_call_key = radius_call_key;
				wmem_map_insert(radius_calls, new_radius_call_key, radius_call_tree);
			}

			/* Find the last call we've seen (for this ident in this conversation) */
			radius_call = (radius_call_t *)wmem_tree_lookup32_le(radius_call_tree, pinfo->num);
			if (radius_call != NULL) {
				/* We found a request with the same ident (in this conversation).
				 * Is it really a duplicate?
				 */
				if (pinfo->num != radius_call->req_num &&
				    !memcmp(radius_call->req_authenticator, authenticator, AUTHENTICATOR_LENGTH)) {
					/* Yes, mark it as such */
					rad_info->is_duplicate = TRUE;
					rad_info->req_num = radius_call->req_num;
					col_append_fstr(pinfo->cinfo, COL_INFO, ", Duplicate Request");

					if (tree) {
						proto_item *item;
						hidden_item = proto_tree_add_uint(radius_tree, hf_radius_dup, tvb, 0, 0, rh.rh_ident);
						proto_item_set_hidden(hidden_item);
						item = proto_tree_add_uint(radius_tree, hf_radius_req_dup, tvb, 0, 0, radius_call->req_num);
						proto_item_set_generated(item);
					}
				}

				/* Accounting Request Authenticator Validation */
				if (rh.rh_code == RADIUS_PKT_TYPE_ACCOUNTING_REQUEST && validate_authenticator && *shared_secret != '\0') {
					proto_item *authenticator_tree, *item;
					int valid;
					valid = valid_authenticator(tvb, radius_call->req_authenticator, 1);

					proto_item_append_text(authenticator_item, " [%s]", valid? "correct" : "incorrect");
					authenticator_tree = proto_item_add_subtree(authenticator_item, ett_radius_authenticator);
					item = proto_tree_add_boolean(authenticator_tree, hf_radius_authenticator_valid, tvb, 4, AUTHENTICATOR_LENGTH, valid ? TRUE : FALSE);
					proto_item_set_generated(item);
					item = proto_tree_add_boolean(authenticator_tree, hf_radius_authenticator_invalid, tvb, 4, AUTHENTICATOR_LENGTH, valid ? FALSE : TRUE);
					proto_item_set_generated(item);

					if (!valid) {
						col_append_fstr(pinfo->cinfo, COL_INFO, " [incorrect authenticator]");
					}
				}
			}

			if (!PINFO_FD_VISITED(pinfo) && (radius_call == NULL || !rad_info->is_duplicate)) {
				/* Prepare the value data.
				 * "req_num" and "rsp_num" are frame numbers;
				 * frame numbers are 1-origin, so we use 0
				 * to mean "we don't yet know in which frame
				 * the reply for this call appears".
				 */
				radius_call = wmem_new(wmem_file_scope(), radius_call_t);
				radius_call->req_num = pinfo->num;
				radius_call->rsp_num = 0;
				radius_call->ident = rh.rh_ident;
				radius_call->code = rh.rh_code;
				memcpy(radius_call->req_authenticator, authenticator, AUTHENTICATOR_LENGTH);
				radius_call->responded = FALSE;
				radius_call->req_time = pinfo->abs_ts;
				radius_call->rspcode = 0;

				/* Store it */
				wmem_tree_insert32(radius_call_tree, pinfo->num, radius_call);
			}

			if (radius_call && radius_call->rsp_num) {
				proto_item *item;
				item = proto_tree_add_uint_format(radius_tree,
					hf_radius_rsp_frame, tvb, 0, 0, radius_call->rsp_num,
					"The response to this request is in frame %u",
					radius_call->rsp_num);
				proto_item_set_generated(item);
			}
			break;
		case RADIUS_PKT_TYPE_ACCESS_ACCEPT:
		case RADIUS_PKT_TYPE_ACCESS_REJECT:
		case RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE:
		case RADIUS_PKT_TYPE_PASSWORD_ACK:
		case RADIUS_PKT_TYPE_PASSWORD_REJECT:
		case RADIUS_PKT_TYPE_RESOURCE_FREE_RESPONSE:
		case RADIUS_PKT_TYPE_RESOURCE_QUERY_RESPONSE:
		case RADIUS_PKT_TYPE_NAS_REBOOT_RESPONSE:
		case RADIUS_PKT_TYPE_EVENT_RESPONSE:
		case RADIUS_PKT_TYPE_DISCONNECT_ACK:
		case RADIUS_PKT_TYPE_DISCONNECT_NAK:
		case RADIUS_PKT_TYPE_COA_ACK:
		case RADIUS_PKT_TYPE_COA_NAK:
		case RADIUS_PKT_TYPE_ACCESS_CHALLENGE:
		case RADIUS_PKT_TYPE_ALU_STATE_ACCEPT:
		case RADIUS_PKT_TYPE_ALU_STATE_REJECT:
		case RADIUS_PKT_TYPE_ALU_STATE_ERROR:
			/* Don't bother finding conversations if we're encapsulated within
			 * an error packet, such as an ICMP destination unreachable */
			if (pinfo->flags.in_error_pkt)
				break;

			hidden_item = proto_tree_add_boolean(radius_tree, hf_radius_rsp, tvb, 0, 0, TRUE);
			proto_item_set_hidden(hidden_item);

			/* Check for RADIUS response.  A response must match a call that
			 * we've seen, and the response must be sent to the same
			 * port and address that the call came from.
			 *
			 * Because it is UDP and the reply can come from any IP
			 * and port (not necessarily the request dest), we only
			 * track the source IP and port of the request to match
			 * the reply.
			 */

			/* XXX - can we just use NO_ADDR_B?  Unfortunately,
			 * you currently still have to pass a non-null
			 * pointer for the second address argument even
			 * if you do that.
			 */
			conversation = find_conversation(pinfo->num, &null_address,
				&pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype), pinfo->srcport, pinfo->destport, 0);
			if (conversation == NULL) {
				/* Nothing more to do here */
				break;
			}

			/* Prepare the key data */
			radius_call_key.code = rh.rh_code;
			radius_call_key.ident = rh.rh_ident;
			radius_call_key.conversation = conversation;
			radius_call_key.req_time = pinfo->abs_ts;

			/* Look up the tree of calls with this ident */
			radius_call_tree = (wmem_tree_t *)wmem_map_lookup(radius_calls, &radius_call_key);
			if (radius_call_tree == NULL) {
				/* Nothing more to do here */
				break;
			}

			/* Find the last call we've seen (for this ident in this conversation) */
			radius_call = (radius_call_t *)wmem_tree_lookup32_le(radius_call_tree, pinfo->num);
			if (radius_call == NULL) {
				/* Nothing more to do here */
				break;
			}

			/* Indicate the frame to which this is a reply. */
			if (radius_call->req_num) {
				nstime_t delta;
				proto_item *item;

				rad_info->request_available = TRUE;
				rad_info->req_num = radius_call->req_num;
				radius_call->responded = TRUE;

				item = proto_tree_add_uint_format(radius_tree,
					hf_radius_req_frame, tvb, 0, 0,
					radius_call->req_num,
					"This is a response to a request in frame %u",
					radius_call->req_num);
				proto_item_set_generated(item);
				nstime_delta(&delta, &pinfo->abs_ts, &radius_call->req_time);
				item = proto_tree_add_time(radius_tree, hf_radius_time, tvb, 0, 0, &delta);
				proto_item_set_generated(item);
				/* Response Authenticator Validation */
				if (validate_authenticator && *shared_secret != '\0') {
					proto_item *authenticator_tree;
					int valid;
					valid = valid_authenticator(tvb, radius_call->req_authenticator, 0);

					proto_item_append_text(authenticator_item, " [%s]", valid? "correct" : "incorrect");
					authenticator_tree = proto_item_add_subtree(authenticator_item, ett_radius_authenticator);
					item = proto_tree_add_boolean(authenticator_tree, hf_radius_authenticator_valid, tvb, 4, AUTHENTICATOR_LENGTH, valid ? TRUE : FALSE);
					proto_item_set_generated(item);
					item = proto_tree_add_boolean(authenticator_tree, hf_radius_authenticator_invalid, tvb, 4, AUTHENTICATOR_LENGTH, valid ? FALSE : TRUE);
					proto_item_set_generated(item);

					if (!valid) {
						col_append_fstr(pinfo->cinfo, COL_INFO, " [incorrect authenticator]");
					}
				}
			}

			if (radius_call->rsp_num == 0) {
				/* We have not yet seen a response to that call, so
				   this must be the first response; remember its
				   frame number. */
				radius_call->rsp_num = pinfo->num;
			} else {
				/* We have seen a response to this call - but was it
				   *this* response? (disregard provisional responses) */
				if ((radius_call->rsp_num != pinfo->num) && (radius_call->rspcode == rh.rh_code)) {
					/* No, so it's a duplicate response. Mark it as such. */
					rad_info->is_duplicate = TRUE;
					col_append_fstr(pinfo->cinfo, COL_INFO, ", Duplicate Response");

					if (tree) {
						proto_item *item;
						hidden_item = proto_tree_add_uint(radius_tree,
							hf_radius_dup, tvb, 0, 0, rh.rh_ident);
						proto_item_set_hidden(hidden_item);
						item = proto_tree_add_uint(radius_tree,
							hf_radius_rsp_dup, tvb, 0, 0, radius_call->rsp_num);
						proto_item_set_generated(item);
					}
				}
			}
			/* Now store the response code (after comparison above) */
			radius_call->rspcode = rh.rh_code;
			rad_info->rspcode = rh.rh_code;
			break;
		default:
			break;
	}

	if (radius_call) {
		rad_info->req_time = radius_call->req_time;
	}

	if (avplength > 0) {
		/* list the attribute value pairs */
		avptree = proto_tree_add_subtree(radius_tree, tvb, HDR_LENGTH,
			avplength, ett_radius_avp, NULL, "Attribute Value Pairs");
		dissect_attribute_value_pairs(avptree, pinfo, tvb, HDR_LENGTH,
			avplength);
	}

	return tvb_captured_length(tvb);
}

void
free_radius_attr_info(gpointer data)
{
	radius_attr_info_t* attr = (radius_attr_info_t*)data;
	value_string *vs = (value_string *)attr->vs;

	g_free(attr->name);
	if (attr->tlvs_by_id) {
		g_hash_table_destroy(attr->tlvs_by_id);
	}
	if (vs) {
		for (; vs->strptr; vs++) {
			g_free((gpointer)vs->strptr);
		}
		g_free((gpointer)attr->vs);
	}

	g_free(attr);
}

static void
free_radius_vendor_info(gpointer data)
{
	radius_vendor_info_t* vendor = (radius_vendor_info_t*)data;

	g_free(vendor->name);
	if (vendor->attrs_by_id)
		g_hash_table_destroy(vendor->attrs_by_id);

	g_free(vendor);
}

static void
register_attrs(gpointer k _U_, gpointer v, gpointer p)
{
	radius_attr_info_t *a = (radius_attr_info_t *)v;
	int i;
	gint *ett = &(a->ett);
	gchar *abbrev = wmem_strdup_printf(wmem_epan_scope(), "radius.%s", a->name);
	hf_register_info hfri[] = {
		{ NULL, { NULL, NULL, FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ NULL, { NULL, NULL, FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ NULL, { NULL, NULL, FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ NULL, { NULL, NULL, FT_NONE,  BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};
	guint len_hf = 2;
	hfett_t *ri = (hfett_t *)p;

	for(i=0; abbrev[i]; i++) {
		if (abbrev[i] == '-') abbrev[i] = '_';
		if (abbrev[i] == '/') abbrev[i] = '_';
	}

	hfri[0].p_id = &(a->hf);
	hfri[1].p_id = &(a->hf_len);

	hfri[0].hfinfo.name = a->name;
	hfri[0].hfinfo.abbrev = abbrev;

	hfri[1].hfinfo.name = "Length";
	hfri[1].hfinfo.abbrev = wmem_strdup_printf(wmem_epan_scope(), "%s.len", abbrev);
	hfri[1].hfinfo.blurb = wmem_strdup_printf(wmem_epan_scope(), "%s Length", a->name);

	if (a->type == radius_integer) {
		hfri[0].hfinfo.type = FT_UINT32;
		hfri[0].hfinfo.display = BASE_DEC;

		hfri[2].p_id = &(a->hf_alt);
		hfri[2].hfinfo.name = wmem_strdup(wmem_epan_scope(), a->name);
		hfri[2].hfinfo.abbrev = abbrev;
		hfri[2].hfinfo.type = FT_UINT64;
		hfri[2].hfinfo.display = BASE_DEC;

		if (a->vs) {
			hfri[0].hfinfo.strings = VALS(a->vs);
		}

		len_hf++;
	} else if (a->type == radius_signed) {
		hfri[0].hfinfo.type = FT_INT32;
		hfri[0].hfinfo.display = BASE_DEC;

		hfri[2].p_id = &(a->hf_alt);
		hfri[2].hfinfo.name = wmem_strdup(wmem_epan_scope(), a->name);
		hfri[2].hfinfo.abbrev = abbrev;
		hfri[2].hfinfo.type = FT_INT64;
		hfri[2].hfinfo.display = BASE_DEC;

		if (a->vs) {
			hfri[0].hfinfo.strings = VALS(a->vs);
		}

		len_hf++;
	} else if (a->type == radius_string) {
		hfri[0].hfinfo.type = FT_STRING;
		hfri[0].hfinfo.display = BASE_NONE;

		if (a->encrypt != 0) {
			/*
			 * This attribute is encrypted, so create an
			 * alternative field for the encrypted value.
			 */
			hfri[2].p_id = &(a->hf_alt);
			hfri[2].hfinfo.name = wmem_strdup_printf(wmem_epan_scope(), "%s (encrypted)", a->name);
			hfri[2].hfinfo.abbrev = wmem_strdup_printf(wmem_epan_scope(), "%s_encrypted", abbrev);
			hfri[2].hfinfo.type = FT_BYTES;
			hfri[2].hfinfo.display = BASE_NONE;

			len_hf++;
		}
	} else if (a->type == radius_octets) {
		hfri[0].hfinfo.type = FT_BYTES;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_ipaddr) {
		hfri[0].hfinfo.type = FT_IPv4;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_ipv6addr) {
		hfri[0].hfinfo.type = FT_IPv6;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_ipv6prefix) {
		hfri[0].hfinfo.type = FT_BYTES;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_ipxnet) {
		hfri[0].hfinfo.type = FT_IPXNET;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_date) {
		hfri[0].hfinfo.type = FT_ABSOLUTE_TIME;
		hfri[0].hfinfo.display = ABSOLUTE_TIME_LOCAL;
	} else if (a->type == radius_abinary) {
		hfri[0].hfinfo.type = FT_BYTES;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_ifid) {
		hfri[0].hfinfo.type = FT_BYTES;
		hfri[0].hfinfo.display = BASE_NONE;
	} else if (a->type == radius_combo_ip) {
		hfri[0].hfinfo.type = FT_IPv4;
		hfri[0].hfinfo.display = BASE_NONE;

		hfri[2].p_id = &(a->hf_alt);
		hfri[2].hfinfo.name = wmem_strdup(wmem_epan_scope(), a->name);
		hfri[2].hfinfo.abbrev = wmem_strdup(wmem_epan_scope(), abbrev);
		hfri[2].hfinfo.type = FT_IPv6;
		hfri[2].hfinfo.display = BASE_NONE;

		len_hf++;
#if 0 /* Fix -Wduplicated-branches */
	} else if (a->type == radius_tlv) {
		hfri[0].hfinfo.type = FT_BYTES;
		hfri[0].hfinfo.display = BASE_NONE;
#endif
	} else {
		hfri[0].hfinfo.type = FT_BYTES;
		hfri[0].hfinfo.display = BASE_NONE;
	}

	if (a->tagged) {
		hfri[len_hf].p_id = &(a->hf_tag);
		hfri[len_hf].hfinfo.name = "Tag";
		hfri[len_hf].hfinfo.abbrev = wmem_strdup_printf(wmem_epan_scope(), "%s.tag", abbrev);
		hfri[len_hf].hfinfo.blurb = wmem_strdup_printf(wmem_epan_scope(), "%s Tag", a->name);
		hfri[len_hf].hfinfo.type = FT_UINT8;
		hfri[len_hf].hfinfo.display = BASE_HEX;
		len_hf++;
	}

	wmem_array_append(ri->hf, hfri, len_hf);
	wmem_array_append_one(ri->ett, ett);

	if (a->tlvs_by_id) {
		g_hash_table_foreach(a->tlvs_by_id, register_attrs, ri);
	}
}

static void
register_vendors(gpointer k _U_, gpointer v, gpointer p)
{
	radius_vendor_info_t *vnd = (radius_vendor_info_t *)v;
	hfett_t *ri = (hfett_t *)p;
	value_string vnd_vs;
	gint *ett_p = &(vnd->ett);

	vnd_vs.value = vnd->code;
	vnd_vs.strptr = vnd->name;

	wmem_array_append_one(ri->vend_vs, vnd_vs);
	wmem_array_append_one(ri->ett, ett_p);

	g_hash_table_foreach(vnd->attrs_by_id, register_attrs, ri);
}

extern void
radius_register_avp_dissector(guint32 vendor_id, guint32 _attribute_id, radius_avp_dissector_t radius_avp_dissector)
{
	radius_vendor_info_t *vendor;
	radius_attr_info_t *dictionary_entry;
	GHashTable *by_id;
	radius_attr_type_t attribute_id;

	DISSECTOR_ASSERT(radius_avp_dissector != NULL);
	memset(&attribute_id, 0, sizeof(attribute_id));
	attribute_id.u8_code[0] = _attribute_id;

	if (vendor_id) {
		vendor = (radius_vendor_info_t *)g_hash_table_lookup(dict->vendors_by_id, GUINT_TO_POINTER(vendor_id));

		if (!vendor) {
			vendor = g_new(radius_vendor_info_t, 1);

			vendor->name = ws_strdup_printf("%s-%u",
						       enterprises_lookup(vendor_id, "Unknown"),
						       vendor_id);
			vendor->code = vendor_id;
			vendor->attrs_by_id = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_radius_attr_info);
			vendor->ett = no_vendor.ett;

			/* XXX: Default "standard" values: Should be parameters ?  */
			vendor->type_octets   = 1;
			vendor->length_octets = 1;
			vendor->has_flags     = FALSE;

			g_hash_table_insert(dict->vendors_by_id, GUINT_TO_POINTER(vendor->code), vendor);
			g_hash_table_insert(dict->vendors_by_name, (gpointer)(vendor->name), vendor);
		}

		dictionary_entry = (radius_attr_info_t *)g_hash_table_lookup(vendor->attrs_by_id, GUINT_TO_POINTER(attribute_id.value));
		by_id = vendor->attrs_by_id;
	} else {
		dictionary_entry = (radius_attr_info_t *)g_hash_table_lookup(dict->attrs_by_id, GUINT_TO_POINTER(attribute_id.value));
		by_id = dict->attrs_by_id;
	}

	if (!dictionary_entry) {
		dictionary_entry = g_new(radius_attr_info_t, 1);

		dictionary_entry->name = ws_strdup_printf("Unknown-Attribute-%u", attribute_id.value);
		dictionary_entry->code = attribute_id;
		dictionary_entry->encrypt = 0;
		dictionary_entry->type = NULL;
		dictionary_entry->vs = NULL;
		dictionary_entry->hf = no_dictionary_entry.hf;
		dictionary_entry->tagged = 0;
		dictionary_entry->hf_tag = -1;
		dictionary_entry->hf_len = no_dictionary_entry.hf_len;
		dictionary_entry->ett = no_dictionary_entry.ett;
		dictionary_entry->tlvs_by_id = NULL;

		g_hash_table_insert(by_id, GUINT_TO_POINTER(dictionary_entry->code.value), dictionary_entry);
	}

	dictionary_entry->dissector = radius_avp_dissector;

}

/* Discard and init any state we've saved */
static void
radius_init_protocol(void)
{
	module_t *radius_module = prefs_find_module("radius");
	pref_t *alternate_port;

	if (radius_module) {
		/* Find alternate_port preference and mark it obsolete (thus hiding it from a user) */
		alternate_port = prefs_find_preference(radius_module, "alternate_port");
		if (! prefs_get_preference_obsolete(alternate_port))
			prefs_set_preference_obsolete(alternate_port);
	}
}

static void
radius_shutdown(void)
{
	if (dict != NULL) {
		g_hash_table_destroy(dict->attrs_by_id);
		g_hash_table_destroy(dict->attrs_by_name);
		g_hash_table_destroy(dict->vendors_by_id);
		g_hash_table_destroy(dict->vendors_by_name);
		g_hash_table_destroy(dict->tlvs_by_name);
		g_free(dict);
	}
}

static void
_radius_load_dictionary(gchar* dir)
{
	gchar *dict_err_str = NULL;

	if (!dir || test_for_directory(dir) != EISDIR) {
		return;
	}

	radius_load_dictionary(dict, dir, "dictionary", &dict_err_str);

	if (dict_err_str) {
		report_failure("radius: %s", dict_err_str);
		g_free(dict_err_str);
	}
}

static void
register_radius_fields(const char *unused _U_)
{
	hf_register_info base_hf[] = {
		{ &hf_radius_req,
		{ "Request", "radius.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"TRUE if RADIUS request", HFILL }},
		{ &hf_radius_rsp,
		{ "Response", "radius.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"TRUE if RADIUS response", HFILL }},
		{ &hf_radius_req_frame,
		{ "Request Frame", "radius.reqframe", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
			NULL, HFILL }},
		{ &hf_radius_rsp_frame,
		{ "Response Frame", "radius.rspframe", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
			NULL, HFILL }},
		{ &hf_radius_time,
		{ "Time from request", "radius.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
			"Timedelta between Request and Response", HFILL }},
		{ &hf_radius_code,
		{ "Code", "radius.code", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &radius_pkt_type_codes_ext, 0x0,
			NULL, HFILL }},
		{ &hf_radius_id,
		{ "Identifier",	"radius.id", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_authenticator,
		{ "Authenticator",	"radius.authenticator", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_authenticator_valid,
		{ "Valid Authenticator", "radius.authenticator.valid", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"TRUE if Authenticator is valid", HFILL }},
		{ &hf_radius_authenticator_invalid,
		{ "Invalid Authenticator", "radius.authenticator.invalid", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"TRUE if Authenticator is invalid", HFILL }},
		{ &hf_radius_length,
		{ "Length", "radius.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &(no_dictionary_entry.hf),
		{ "Unknown-Attribute", "radius.Unknown_Attribute", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &(no_dictionary_entry.hf_len),
		{ "Unknown-Attribute Length", "radius.Unknown_Attribute.length", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_chap_password,
		{ "CHAP-Password", "radius.CHAP_Password", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_chap_ident,
		{ "CHAP Ident", "radius.CHAP_Ident", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_chap_string,
		{ "CHAP String", "radius.CHAP_String", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_framed_ip_address,
		{ "Framed-IP-Address", "radius.Framed-IP-Address", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_login_ip_host,
		{ "Login-IP-Host", "radius.Login-IP-Host", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_framed_ipx_network,
		{ "Framed-IPX-Network", "radius.Framed-IPX-Network", FT_IPXNET, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_cosine_vpi,
		{ "Cosine-VPI", "radius.Cosine-Vpi", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_cosine_vci,
		{ "Cosine-VCI", "radius.Cosine-Vci", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_dup,
		{ "Duplicate Message ID", "radius.dup", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_req_dup,
		{ "Duplicate Request Frame Number", "radius.req.dup", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_rsp_dup,
		{ "Duplicate Response Frame Number", "radius.rsp.dup", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter,
		{ "Ascend Data Filter", "radius.ascenddatafilter", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_type,
		{ "Type", "radius.ascenddatafilter.type", FT_UINT8, BASE_DEC, VALS(ascenddf_filtertype), 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_filteror,
		{ "Filter or forward", "radius.ascenddatafilter.filteror", FT_UINT8, BASE_DEC, VALS(ascenddf_filteror), 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_inout,
		{ "Indirection", "radius.ascenddatafilter.inout", FT_UINT8, BASE_DEC, VALS(ascenddf_inout), 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_spare,
		{ "Spare", "radius.ascenddatafilter.spare", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_src_ipv4,
		{ "Source IPv4 address", "radius.ascenddatafilter.src_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_dst_ipv4,
		{ "Destination IPv4 address", "radius.ascenddatafilter.dst_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_src_ipv6,
		{ "Source IPv6 address", "radius.ascenddatafilter.src_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_dst_ipv6,
		{ "Destination IPv6 address", "radius.ascenddatafilter.dst_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_src_ip_prefix,
		{ "Source IP prefix", "radius.ascenddatafilter.src_prefix_ip", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_dst_ip_prefix,
		{ "Destination IP prefix", "radius.ascenddatafilter.dst_prefix_ip", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_protocol,
		{ "Protocol", "radius.ascenddatafilter.protocol", FT_UINT8, BASE_DEC, VALS(ascenddf_proto), 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_established,
		{ "Established", "radius.ascenddatafilter.established", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_src_port,
		{ "Source Port", "radius.ascenddatafilter.src_port", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_dst_port,
		{ "Destination Port", "radius.ascenddatafilter.dst_port", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_src_port_qualifier,
		{ "Source Port Qualifier", "radius.ascenddatafilter.src_port_qualifier", FT_UINT8, BASE_DEC, VALS(ascenddf_portq), 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_dst_port_qualifier,
		{ "Destination Port Qualifier", "radius.ascenddatafilter.dst_port_qualifier", FT_UINT8, BASE_DEC, VALS(ascenddf_portq), 0x0,
			NULL, HFILL }},
		{ &hf_radius_ascend_data_filter_reserved,
		{ "Reserved", "radius.ascenddatafilter.reserved", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_vsa_fragment,
		{ "VSA fragment", "radius.vsa_fragment", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_eap_fragment,
		{ "EAP fragment", "radius.eap_fragment", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp,
		{ "AVP", "radius.avp", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_length,
		{ "Length", "radius.avp.length", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_type,
		{ "Type", "radius.avp.type", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_vendor_id,
		{ "Vendor ID", "radius.avp.vendor_id", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_vendor_type,
		{ "Type", "radius.avp.vendor_type", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_vendor_len,
		{ "Length", "radius.avp.vendor_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_extended_type,
		{ "Extended Type", "radius.avp.extended_type", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_avp_extended_more,
		{ "Extended More", "radius.avp.extended_more", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x80,
			NULL, HFILL }},
		{ &hf_radius_egress_vlanid_tag,
		{ "Tag", "radius.egress_vlanid_tag", FT_UINT32, BASE_HEX, VALS(egress_vlan_tag_vals), 0xFF000000,
			NULL, HFILL }},
		{ &hf_radius_egress_vlanid_pad,
		{ "Pad", "radius.egress_vlanid_pad", FT_UINT32, BASE_HEX, NULL, 0x00FFF000,
			NULL, HFILL }},
		{ &hf_radius_egress_vlanid,
		{ "Vlan ID", "radius.egress_vlanid", FT_UINT32, BASE_DEC, NULL, 0x00000FFF,
			NULL, HFILL }},
		{ &hf_radius_egress_vlan_name_tag,
		{ "Tag", "radius.egress_vlan_name_tag", FT_UINT8, BASE_HEX, VALS(egress_vlan_tag_vals), 0x0,
			NULL, HFILL }},
		{ &hf_radius_egress_vlan_name,
		{ "Vlan Name", "radius.egress_vlan_name", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_radius_3gpp_ms_tmime_zone,
		{ "Timezone", "radius.3gpp_ms_tmime_zone", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	};

	gint *base_ett[] = {
		&ett_radius,
		&ett_radius_avp,
		&ett_radius_authenticator,
		&ett_radius_ascend,
		&ett_eap,
		&ett_chap,
		&(no_dictionary_entry.ett),
		&(no_vendor.ett),
	};

	static ei_register_info ei[] = {
	{
		 &ei_radius_invalid_length, { "radius.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
	};

	expert_module_t *expert_radius;
	hfett_t ri;
	char *dir = NULL;

	ri.hf = wmem_array_new(wmem_epan_scope(), sizeof(hf_register_info));
	ri.ett = wmem_array_new(wmem_epan_scope(), sizeof(gint *));
	ri.vend_vs = wmem_array_new(wmem_epan_scope(), sizeof(value_string));

	wmem_array_append(ri.hf, base_hf, array_length(base_hf));
	wmem_array_append(ri.ett, base_ett, array_length(base_ett));


	dir = get_datafile_path("radius");
	_radius_load_dictionary(dir);
	g_free(dir);
	dir = get_persconffile_path("radius", FALSE);
	_radius_load_dictionary(dir);
	g_free(dir);

	g_hash_table_foreach(dict->attrs_by_id, register_attrs, &ri);
	g_hash_table_foreach(dict->vendors_by_id, register_vendors, &ri);

	proto_register_field_array(proto_radius, (hf_register_info *)wmem_array_get_raw(ri.hf), wmem_array_get_count(ri.hf));
	proto_register_subtree_array((gint **)wmem_array_get_raw(ri.ett), wmem_array_get_count(ri.ett));
	expert_radius = expert_register_protocol(proto_radius);
	expert_register_field_array(expert_radius, ei, array_length(ei));

	/*
	 * Handle attributes that have a special format.
	 */
	radius_register_avp_dissector(0, 3, dissect_chap_password);
	radius_register_avp_dissector(0, 8, dissect_framed_ip_address);
	radius_register_avp_dissector(0, 14, dissect_login_ip_host);
	radius_register_avp_dissector(0, 23, dissect_framed_ipx_network);
	radius_register_avp_dissector(0, 56, dissect_rfc4675_egress_vlanid);
	radius_register_avp_dissector(0, 58, dissect_rfc4675_egress_vlan_name);

	radius_register_avp_dissector(VENDOR_COSINE, 5, dissect_cosine_vpvc);

	/*
	 * XXX - we should special-case Cisco attribute 252; see the comment in
	 * dictionary.cisco.
	 */
	radius_register_avp_dissector(VENDOR_THE3GPP, 1, dissect_radius_3gpp_imsi);
	radius_register_avp_dissector(VENDOR_THE3GPP, 23, dissect_radius_3gpp_ms_tmime_zone);
}


void
proto_register_radius(void)
{
	module_t *radius_module;

	proto_radius = proto_register_protocol("RADIUS Protocol", "RADIUS", "radius");
	radius_handle = register_dissector("radius", dissect_radius, proto_radius);
	register_init_routine(&radius_init_protocol);
	register_shutdown_routine(radius_shutdown);
	radius_module = prefs_register_protocol(proto_radius, NULL);
	prefs_register_string_preference(radius_module, "shared_secret", "Shared Secret",
					 "Shared secret used to decode User Passwords and validate Accounting Request and Response Authenticators",
					 &shared_secret);
	prefs_register_bool_preference(radius_module, "validate_authenticator", "Validate Accounting Request and Response Authenticator",
				       "Whether to check or not if Accounting Request and Response Authenticator are correct. You need to define shared secret for this to work.",
				       &validate_authenticator);
	prefs_register_bool_preference(radius_module, "show_length", "Show AVP Lengths",
				       "Whether to add or not to the tree the AVP's payload length",
				       &show_length);
	/*
	 * For now this preference allows supporting legacy Ascend AVPs and others
	 * who might use these attribute types (not complying with IANA allocation).
	 */
	prefs_register_bool_preference(radius_module, "disable_extended_attributes", "Disable extended attribute space (RFC 6929)",
				       "Whether to interpret 241-246 as extended attributes according to RFC 6929",
				       &disable_extended_attributes);
	prefs_register_obsolete_preference(radius_module, "request_ttl");

	radius_tap = register_tap("radius");
	proto_register_prefix("radius", register_radius_fields);

	dict = g_new(radius_dictionary_t, 1);
	/*
	 * IDs map to names and vice versa. The attribute and vendor is stored
	 * only once, but referenced by both name and ID mappings.
	 * See also radius_dictionary_t in packet-radius.h
	 */
	dict->attrs_by_id     = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_radius_attr_info);
	dict->attrs_by_name   = g_hash_table_new(g_str_hash, g_str_equal);
	dict->vendors_by_id   = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_radius_vendor_info);
	dict->vendors_by_name = g_hash_table_new(g_str_hash, g_str_equal);
	dict->tlvs_by_name    = g_hash_table_new(g_str_hash, g_str_equal);

	radius_calls = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), radius_call_hash, radius_call_equal);

	register_rtd_table(proto_radius, NULL, RADIUS_CAT_NUM_TIMESTATS, 1, radius_message_code, radiusstat_packet, NULL);
}

void
proto_reg_handoff_radius(void)
{
	eap_handle = find_dissector_add_dependency("eap", proto_radius);
	dissector_add_uint_range_with_preference("udp.port", DEFAULT_RADIUS_PORT_RANGE, radius_handle);
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
