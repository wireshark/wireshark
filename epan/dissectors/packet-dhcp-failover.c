/* packet-dhcpfo.c
 * Routines for ISC DHCP Server failover protocol dissection
 * Copyright 2004, M. Ortega y Strupp <moys@loplof.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This implementation is loosely based on draft-ietf-dhc-failover-07.txt.
 * As this document does not represent the actual implementation, the
 * source code of ISC DHCPD 3.0 was used too.
 *
 * See also
 *
 *	https://tools.ietf.org/html/draft-ietf-dhc-failover-10
 *
 * upon which the handling of the message-digest option is based.
 *
 * Updated to https://tools.ietf.org/html/draft-ietf-dhc-failover-12, July 2020
 *
 * Updated with Microsoft DHCP Failover Protocol Extension in August 2023:
 *   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpf/380744f9-17ed-4aef-8810-ef08d1e70932
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>

#include "packet-arp.h"
#include "packet-tcp.h"

#define TCP_PORT_DHCPFO 647 /* Not IANA registered */

void proto_register_dhcpfo(void);
void proto_reg_handoff_dhcpfo(void);

static dissector_handle_t dhcpfo_handle;

/* desegmentation of DHCP failover over TCP */
static bool dhcpfo_desegment = true;

/* enum preference to interpret Microsoft-formatted fields correctly */
#define AUTODETECT_MS_DHCP	0
#define DISSECT_IEFT_DRAFT	1
#define DISSECT_MS_DHCP		2
static const enum_val_t microsoft_compatibility[] = {
	{ "autodetect_ms_dhcp", "Autodetect Microsoft Windows DHCP server", AUTODETECT_MS_DHCP },
	{ "dissect_ietf_draft", "Dissect using IETF draft 12 specifications", DISSECT_IEFT_DRAFT },
	{ "dissect_ms_dhcp", "Dissect using Microsoft-style formatting", DISSECT_MS_DHCP },
	{ NULL, NULL, 0 }
};
static int dhcpfo_microsoft_compatibility = AUTODETECT_MS_DHCP;

/* Initialize the protocol and registered fields */
static int proto_dhcpfo;
static int hf_dhcpfo_length;
static int hf_dhcpfo_type;
static int hf_dhcpfo_poffset;
static int hf_dhcpfo_time;
static int hf_dhcpfo_xid;
static int hf_dhcpfo_additional_HB;
static int hf_dhcpfo_payload_data;
static int hf_dhcpfo_option_code;
static int hf_dhcpfo_dhcp_style_option;
static int hf_dhcpfo_option_length;
static int hf_dhcpfo_binding_status;
static int hf_dhcpfo_server_state;
static int hf_dhcpfo_assigned_ip_address;
static int hf_dhcpfo_delayed_service_parameter;
static int hf_dhcpfo_addresses_transferred;
static int hf_dhcpfo_client_identifier;
static int hf_dhcpfo_client_hw_type;
static int hf_dhcpfo_client_hardware_address;
static int hf_dhcpfo_ftddns;
static int hf_dhcpfo_reject_reason;
static int hf_dhcpfo_relationship_name;
static int hf_dhcpfo_message;
static int hf_dhcpfo_mclt;
static int hf_dhcpfo_vendor_class;
static int hf_dhcpfo_lease_expiration_time;
static int hf_dhcpfo_potential_expiration_time;
static int hf_dhcpfo_client_last_transaction_time;
static int hf_dhcpfo_start_time_of_state;
static int hf_dhcpfo_vendor_option;
static int hf_dhcpfo_max_unacked_bndupd;
static int hf_dhcpfo_protocol_version;
static int hf_dhcpfo_receive_timer;
static int hf_dhcpfo_message_digest;
static int hf_dhcpfo_ipflags;
static int hf_dhcpfo_ipflags_reserved;
static int hf_dhcpfo_ipflags_bootp;
static int hf_dhcpfo_ipflags_mbz;
static int hf_dhcpfo_hash_bucket_assignment;
static int hf_dhcpfo_message_digest_type;
static int hf_dhcpfo_tls_request;
static int hf_dhcpfo_tls_reply;
static int hf_dhcpfo_serverflag;
static int hf_dhcpfo_options;
static int hf_dhcpfo_ms_client_name;
static int hf_dhcpfo_ms_client_description;
static int hf_dhcpfo_ms_client_type;
static int hf_dhcpfo_ms_client_nap_status;
static int hf_dhcpfo_ms_client_nap_capable;
static int hf_dhcpfo_ms_client_nap_probation;
static int hf_dhcpfo_ms_client_matched_policy;
static int hf_dhcpfo_ms_server_name;
static int hf_dhcpfo_ms_server_ip;
static int hf_dhcpfo_ms_client_scope;
static int hf_dhcpfo_ms_client_subnet_mask;
static int hf_dhcpfo_ms_scope_id;
static int hf_dhcpfo_ms_ipflags;
static int hf_dhcpfo_ms_extended_address_state;
static int hf_dhcpfo_infoblox_client_hostname;
static int hf_dhcpfo_unknown_data;

/* Initialize the subtree pointers */
static int ett_dhcpfo;
static int ett_fo_payload;
static int ett_fo_option;
static int ett_fo_payload_data;

static expert_field ei_dhcpfo_bad_length;
static expert_field ei_dhcpfo_message_digest_type_not_allowed;


/* Length of fixed-length portion of header */
#define DHCPFO_FL_HDR_LEN	12

/* message-types of failover */

static const value_string failover_vals[] =
{
	{1,	"Pool request"},
	{2,	"Pool response"},
	{3,	"Binding update"},
	{4,	"Binding acknowledge"},
	{5,	"Connect"},
	{6,	"Connect acknowledge"},
	{7,	"Update request"},
	{8,	"Update done"},
	{9,	"Update request all"},
	{10,	"State"},
	{11,	"Contact"},
	{12,	"Disconnect"},
	{0, NULL}
};

/*options of payload-data*/
#define DHCP_FO_PD_ADDRESSES_TRANSFERRED         1
#define DHCP_FO_PD_ASSIGNED_IP_ADDRESS           2
#define DHCP_FO_PD_BINDING_STATUS                3
#define DHCP_FO_PD_CLIENT_IDENTIFIER             4
#define DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS       5
#define DHCP_FO_PD_CLIENT_LAST_TRANSACTION_TIME  6
#define DHCP_FO_PD_REPLY_OPTION                  7
#define DHCP_FO_PD_REQUEST_OPTION                8
#define DHCP_FO_PD_FTDDNS                        9
#define DHCP_FO_PD_DELAYED_SERVICE_PARAMETER    10
#define DHCP_FO_PD_HASH_BUCKET_ASSIGNMENT       11
#define DHCP_FO_PD_IP_FLAGS                     12
#define DHCP_FO_PD_LEASE_EXPIRATION_TIME        13
#define DHCP_FO_PD_MAX_UNACKED_BNDUPD           14
#define DHCP_FO_PD_MCLT                         15
#define DHCP_FO_PD_MESSAGE                      16
#define DHCP_FO_PD_MESSAGE_DIGEST               17
#define DHCP_FO_PD_POTENTIAL_EXPIRATION_TIME    18
#define DHCP_FO_PD_RECEIVE_TIMER                19
#define DHCP_FO_PD_PROTOCOL_VERSION             20
#define DHCP_FO_PD_REJECT_REASON                21
#define DHCP_FO_PD_RELATIONSHIP_NAME            22
#define DHCP_FO_PD_SERVERFLAG                   23
#define DHCP_FO_PD_SERVERSTATE                  24
#define DHCP_FO_PD_START_TIME_OF_STATE          25
#define DHCP_FO_PD_TLS_REPLY                    26
#define DHCP_FO_PD_TLS_REQUEST                  27
#define DHCP_FO_PD_VENDOR_CLASS                 28
#define DHCP_FO_PD_VENDOR_OPTION                29
/* Options not defined in the draft */
#define DHCP_FO_PD_OPTION_30                    30
#define DHCP_FO_PD_OPTION_31                    31
#define DHCP_FO_PD_OPTION_32                    32
#define DHCP_FO_PD_OPTION_33                    33
#define DHCP_FO_PD_OPTION_34                    34
#define DHCP_FO_PD_OPTION_35                    35
#define DHCP_FO_PD_OPTION_36                    36
#define DHCP_FO_PD_OPTION_37                    37
#define DHCP_FO_PD_OPTION_38                    38
#define DHCP_FO_PD_OPTION_39                    39
#define DHCP_FO_PD_OPTION_40                    40
#define DHCP_FO_PD_OPTION_41                    41


static const char VENDOR_SPECIFIC[] = "(vendor-specific)";
static const char UNKNOWN_OPTION[] = "Unknown Option";

static const value_string option_code_vals[] =
{
	{DHCP_FO_PD_ADDRESSES_TRANSFERRED,		"addresses-transferred"},
	{DHCP_FO_PD_ASSIGNED_IP_ADDRESS,		"assigned-IP-address"},
	{DHCP_FO_PD_BINDING_STATUS,			"binding-status"},
	{DHCP_FO_PD_CLIENT_IDENTIFIER,			"client-identifier"},
	{DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS,		"client-hardware-address"},
	{DHCP_FO_PD_CLIENT_LAST_TRANSACTION_TIME,	"client-last-transaction-time"},
	{DHCP_FO_PD_REPLY_OPTION,			"reply-option"},
	{DHCP_FO_PD_REQUEST_OPTION,			"request-option"},
	{DHCP_FO_PD_FTDDNS,				"FTDDNS"},
	{DHCP_FO_PD_DELAYED_SERVICE_PARAMETER,		"delayed-service-parameter"},
	{DHCP_FO_PD_HASH_BUCKET_ASSIGNMENT,		"hash-bucket-assignment"},
	{DHCP_FO_PD_IP_FLAGS,				"IP-flags"},
	{DHCP_FO_PD_LEASE_EXPIRATION_TIME,		"lease-expiration-time"},
	{DHCP_FO_PD_MAX_UNACKED_BNDUPD,			"max-unacked-BNDUPD"},
	{DHCP_FO_PD_MCLT,				"MCLT"},
	{DHCP_FO_PD_MESSAGE,				"message"},
	{DHCP_FO_PD_MESSAGE_DIGEST,			"message-digest"},
	{DHCP_FO_PD_POTENTIAL_EXPIRATION_TIME,		"potential-expiration-time"},
	{DHCP_FO_PD_RECEIVE_TIMER,			"receive-timer"},
	{DHCP_FO_PD_PROTOCOL_VERSION,			"protocol-version"},
	{DHCP_FO_PD_REJECT_REASON,			"reject-reason"},
	{DHCP_FO_PD_RELATIONSHIP_NAME,			"relationship-name"},
	{DHCP_FO_PD_SERVERFLAG,				"server-flag"},
	{DHCP_FO_PD_SERVERSTATE,			"server-state"},
	{DHCP_FO_PD_START_TIME_OF_STATE,		"start-time-of-state"},
	{DHCP_FO_PD_TLS_REPLY,				"TLS-reply"},
	{DHCP_FO_PD_TLS_REQUEST,			"TLS-request"},
	{DHCP_FO_PD_VENDOR_CLASS,			"vendor-class"},
	{DHCP_FO_PD_VENDOR_OPTION,			"vendor-option"},
	/* Not specified in the draft, further defined in the following arrays: */
	{DHCP_FO_PD_OPTION_30,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_31,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_32,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_33,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_34,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_35,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_36,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_37,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_38,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_39,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_40,				VENDOR_SPECIFIC},
	{DHCP_FO_PD_OPTION_41,				VENDOR_SPECIFIC},
	{0, NULL}
};

/* Used when Microsoft-compatibility is detected/enabled */
static const value_string microsoft_option_code_vals[] =
{
	{DHCP_FO_PD_OPTION_30,		"microsoft-scope-ID-list"},
	{DHCP_FO_PD_OPTION_31,		"microsoft-client-name"},
	{DHCP_FO_PD_OPTION_32,		"microsoft-client-description"},
	{DHCP_FO_PD_OPTION_33,		"microsoft-client-subnet-mask"},
	{DHCP_FO_PD_OPTION_34,		"microsoft-server-IP"},
	{DHCP_FO_PD_OPTION_35,		"microsoft-server-name"},
	{DHCP_FO_PD_OPTION_36,		"microsoft-client-type"},
	{DHCP_FO_PD_OPTION_37,		"microsoft-client-NAP-status"},
	{DHCP_FO_PD_OPTION_38,		"microsoft-client-NAP-probation"},
	{DHCP_FO_PD_OPTION_39,		"microsoft-client-NAP-capable"},
	{DHCP_FO_PD_OPTION_40,		"microsoft-client-matched-policy"},
	{DHCP_FO_PD_OPTION_41,		"microsoft-extended-address-state"},
	{0, NULL}
};

/* Used when Microsoft-compatibility is NOT detected/enabled */
static const value_string others_option_code_vals[] =
{
	{DHCP_FO_PD_OPTION_30,		"infoblox-client-hostname"},
	{0, NULL}
};

/* Microsoft client types (option 36) */

static const value_string ms_client_type_vals[] =
{
	{0x00,	"CLIENT_TYPE_UNSPECIFIED"},
	{0x01,	"CLIENT_TYPE_DHCP"},
	{0x02,	"CLIENT_TYPE_BOOTP"},
	{0x03,	"CLIENT_TYPE_BOTH"},
	{0x04,	"CLIENT_TYPE_RESERVATION_FLAG"},
	{0x64,	"CLIENT_TYPE_NONE"},
	{0, NULL}
};

/* Microsoft client NAP status codes (option 37) */

static const value_string ms_client_nap_status_vals[] =
{
	{0x00,	"NOQUARANTINE"},
	{0x01,	"RESTRICTEDACCESS"},
	{0x02,	"DROPPACKET"},
	{0x03,	"PROBATION"},
	{0, NULL}
};

/* Binding-status */

static const value_string binding_status_vals[] =
{
	{1,	"FREE"},
	{2,	"ACTIVE"},
	{3,	"EXPIRED"},
	{4,	"RELEASED"},
	{5,	"ABANDONED"},
	{6,	"RESET"},
	{7,	"BACKUP"},
	{0, NULL}

};

/* Server-status */

static const value_string server_state_vals[] =
{
	{1,	"startup"},
	{2,	"normal"},
	{3,	"communication interrupted"},
	{4,	"partner down"},
	{5,	"potential conflict"},
	{6,	"recover"},
	{7,	"paused"},
	{8,	"shutdown"},
	{9,	"recover done"},
	{10,	"resolution interrupted"},
	{11,	"conflict done"},
	{0, NULL}
};

/* reject reasons */
static const value_string reject_reason_vals[] =
{
	{0,   "Reserved"},
	{1,   "Illegal IP address (not part of any address pool)"},
	{2,   "Fatal conflict exists: address in use by other client"},
	{3,   "Missing binding information"},
	{4,   "Connection rejected, time mismatch too great"},
	{5,   "Connection rejected, invalid MCLT"},
	{6,   "Connection rejected, unknown reason"},
	{7,   "Connection rejected, duplicate connection"},
	{8,   "Connection rejected, invalid failover partner"},
	{9,   "TLS not supported"},
	{10,  "TLS supported but not configured"},
	{11,  "TLS required but not supported by partner"},
	{12,  "Message digest not supported"},
	{13,  "Message digest not configured"},
	{14,  "Protocol version mismatch"},
	{15,  "Outdated binding information"},
	{16,  "Less critical binding information"},
	{17,  "No traffic within sufficient time"},
	{18,  "Hash bucket assignment conflict"},
	{19,  "IP not reserved on this server"},
	{20,  "Message digest failed to compare"},
	{21,  "Missing message digest."},
	{254, "Unknown: Error occurred but does not match any reason"},
	{0, NULL}
};

static const value_string tls_request_vals[] =
{
	{0, "No TLS operation"},
	{1, "TLS operation desired but not required"},
	{2, "TLS operation is required"},
	{0, NULL}
};

static const value_string tls_reply_vals[] =
{
	{0, "No TLS operation"},
	{1, "TLS operation is required"},
	{0, NULL}
};

static const value_string message_digest_type_vals[] =
{
	{1, "HMAC-MD5"},
	{2, "Microsoft-specific"},
	{0, NULL}
};

static const value_string serverflag_vals[] =
{
	{0, "NONE"},
	{1, "STARTUP"},
	{0, NULL}
};

/* Code to actually dissect the packets */
static unsigned
get_dhcpfo_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/*
	 * Return the length of the DHCP failover packet.
	 */
	return tvb_get_ntohs(tvb, offset);
}

static int
dissect_dhcpfo_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	proto_item *ti, *pi, *oi;
	proto_tree *dhcpfo_tree = NULL, *payload_tree, *option_tree;
	uint8_t tls_request, tls_reply;
	uint16_t length;
	unsigned type, serverflag;
	int poffset;
	uint32_t xid;
	nstime_t timex;
	uint32_t lease_expiration_time,
			potential_expiration_time, client_last_transaction_time,
			start_time_of_state;
	bool bogus_poffset, microsoft_style;
	uint16_t opcode, option_length;
	uint8_t htype, reject_reason, message_digest_type, binding_status;
	const uint8_t *vendor_class_str, *relationship_name_str;
	const char *htype_str, *option_name;
	char *lease_expiration_time_str, *potential_expiration_time_str,
		  *client_last_transaction_time_str, *start_time_of_state_str;
	uint32_t mclt;
	uint8_t server_state, ms_client_type, ms_client_nap_status, ms_client_nap_capable;
	uint32_t max_unacked_bndupd, receive_timer,
			ms_client_nap_probation, ms_extended_address_state;
	const uint8_t *client_hostname_str, *ms_server_name_str, *ms_client_description_str,
				 *ms_client_matched_policy_str;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPFO");
	col_clear(pinfo->cinfo, COL_INFO);

	length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_dhcpfo, tvb, 0, -1, ENC_NA);

		dhcpfo_tree = proto_item_add_subtree(ti, ett_dhcpfo);

		if (length >= DHCPFO_FL_HDR_LEN) {
			proto_tree_add_uint(dhcpfo_tree,
			    hf_dhcpfo_length, tvb, offset, 2, length);
		} else {
			proto_tree_add_uint_format_value(dhcpfo_tree,
			    hf_dhcpfo_length, tvb, offset, 2, length,
			    "%u (bogus, must be >= %u)",
			    length, DHCPFO_FL_HDR_LEN);
		}
	}
	offset += 2;

	type = tvb_get_uint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(dhcpfo_tree,
		    hf_dhcpfo_type, tvb, offset, 1, type);
	}
	col_set_str(pinfo->cinfo, COL_INFO,
	    val_to_str_const(type, failover_vals, "Unknown Packet"));
	offset += 1;

	if (dhcpfo_microsoft_compatibility == DISSECT_MS_DHCP) {
		microsoft_style = true;
	} else {
		/* Set to false, changed to true later if autodetected */
		microsoft_style = false;
	}
	poffset = tvb_get_uint8(tvb, offset);
	if (poffset == 8) {
		if (dhcpfo_microsoft_compatibility == AUTODETECT_MS_DHCP) {
			microsoft_style = true;
		}
		bogus_poffset = false;
		proto_tree_add_uint_format_value(dhcpfo_tree,
			hf_dhcpfo_poffset, tvb, offset, 1, poffset,
			"%u (as per Draft, now treated as being %u)",
			poffset, DHCPFO_FL_HDR_LEN);
		poffset = DHCPFO_FL_HDR_LEN;
	} else if (poffset < DHCPFO_FL_HDR_LEN) {
		bogus_poffset = true;
		if (tree) {
			proto_tree_add_uint_format_value(dhcpfo_tree,
			    hf_dhcpfo_poffset, tvb, offset, 1, poffset,
			    "%u (bogus, must be >= %u)",
			    poffset, DHCPFO_FL_HDR_LEN);
		}
	} else if (poffset > length) {
		bogus_poffset = true;
		if (tree) {
			proto_tree_add_uint_format_value(dhcpfo_tree,
			    hf_dhcpfo_poffset, tvb, offset, 1, poffset,
			    "%u (bogus, must be <= length of message)",
			    poffset);
		}
	} else {
		bogus_poffset = false;
		if (tree) {
			proto_tree_add_uint(dhcpfo_tree,
			    hf_dhcpfo_poffset, tvb, offset, 1, poffset);
		}
	}
	offset += 1;

	if (tree) {
		/*
		 * XXX - this is *almost* like a time_t, but it's unsigned.
		 * Also, we need a way to keep from displaying nanoseconds,
		 * so as not to make it look as if it has higher
		 */
		timex.secs = tvb_get_ntohl(tvb, offset);
		timex.nsecs = 0;
		proto_tree_add_time_format_value(dhcpfo_tree, hf_dhcpfo_time, tvb,
		    offset, 4, &timex, "%s",
		    abs_time_secs_to_str(pinfo->pool, timex.secs, ABSOLUTE_TIME_LOCAL, true));
	}
	offset += 4;

	xid = tvb_get_ntohl(tvb, offset);
	if (tree) {
		proto_tree_add_item(dhcpfo_tree,
		    hf_dhcpfo_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
	}
	col_append_fstr(pinfo->cinfo, COL_INFO," xid: %x", xid);
	offset += 4;

	if (bogus_poffset)
		return offset;	/* payload offset was bogus */

	/* if there are any additional header bytes */
	if (poffset != offset) {
		proto_tree_add_item(dhcpfo_tree, hf_dhcpfo_additional_HB, tvb,
		    offset, poffset-offset, ENC_NA);
		offset = poffset;
	}

	/* payload-data */
	if (poffset == length)
		return length;	/* no payload */
	/* create display subtree for the payload */
	pi = proto_tree_add_item(dhcpfo_tree, hf_dhcpfo_payload_data,
	    tvb, poffset, length-poffset, ENC_NA);
	payload_tree = proto_item_add_subtree(pi, ett_fo_payload);
	while (offset < length) {
		opcode = tvb_get_ntohs(tvb, offset);
		option_length = tvb_get_ntohs(tvb, offset+2);

		oi = proto_tree_add_item(payload_tree,
		    hf_dhcpfo_dhcp_style_option, tvb, offset,
		    option_length+4, ENC_NA);
		option_tree = proto_item_add_subtree(oi, ett_fo_option);

		/*** DHCP-Style-Options ****/

		option_name = val_to_str_const(opcode, option_code_vals, UNKNOWN_OPTION);
		if (strcmp(option_name, VENDOR_SPECIFIC) == 0) {
			/* Get the option name based on current setting */
			if (microsoft_style) {
				option_name = val_to_str_const(opcode, microsoft_option_code_vals, UNKNOWN_OPTION);
			} else {
				option_name = val_to_str_const(opcode, others_option_code_vals, UNKNOWN_OPTION);
			}
		}
		proto_item_append_text(oi, ", %s (%u)", option_name, opcode);

		proto_tree_add_uint(option_tree, hf_dhcpfo_option_code, tvb,
		    offset, 2, opcode);

		proto_tree_add_uint(option_tree, hf_dhcpfo_option_length, tvb,
		    offset+2, 2, option_length);

		offset += 4;

		/** opcode dependent format **/

		switch (opcode) {

		case DHCP_FO_PD_BINDING_STATUS:
			binding_status = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s (%d)",
			    val_to_str_const(binding_status,
				binding_status_vals,
				"Unknown Packet"),
			    binding_status);

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_binding_status, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_ASSIGNED_IP_ADDRESS:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "assigned ip address is not 4 bytes long");
				break;
			}
			proto_item_append_text(oi, ", %s ", tvb_ip_to_str(pinfo->pool, tvb, offset));

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_assigned_ip_address, tvb,	offset,
			    option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_DELAYED_SERVICE_PARAMETER:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "delayed service parameter is not 1 bytes long");
				break;
			}

			proto_item_append_text(oi, ", %d ", tvb_get_uint8(tvb, offset));

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_delayed_service_parameter, tvb,
			    offset, option_length, ENC_NA);
			break;

		case DHCP_FO_PD_ADDRESSES_TRANSFERRED:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "addresses transferred is not 4 bytes long");
				break;
			}

			proto_item_append_text(oi,", %u", tvb_get_ntohl(tvb, offset));

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_addresses_transferred, tvb, offset,
			    option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_CLIENT_IDENTIFIER:
			{
			const uint8_t* identifier;
			/*
			 * XXX - if this is truly like DHCP option 81,
			 * we need to dissect it as such.
			 */
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_client_identifier, tvb, offset,
			    option_length, ENC_ASCII|ENC_NA, pinfo->pool, &identifier);

			proto_item_append_text(oi,", \"%s\"", identifier);
			}
			break;

		case DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS:
			if (microsoft_style == false) {
				/* As specified in the draft: hardware type + hardware address */
				if (option_length < 2) {
					expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "hardware address is too short");
					break;
				}
				htype = tvb_get_uint8(tvb, offset);
				htype_str = tvb_arphrdaddr_to_str(pinfo->pool, tvb, offset+1, option_length-1,
					htype);
				proto_item_append_text(oi, ", %s", htype_str);

				proto_tree_add_item(option_tree, hf_dhcpfo_client_hw_type, tvb,
					offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_string(option_tree, hf_dhcpfo_client_hardware_address, tvb,
					offset+1, option_length-1, htype_str);
			} else {
				/* Microsoft-style: DHCP scope (reversed) + hardware type + hardware address */
				if (option_length < 6) {
					expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "hardware address is too short");
					break;
				}
				proto_tree_add_item(option_tree,
					hf_dhcpfo_ms_client_scope, tvb,	offset, 4, ENC_LITTLE_ENDIAN);
				uint32_t scope = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
				htype = tvb_get_uint8(tvb, offset+4);
				htype_str = tvb_arphrdaddr_to_str(pinfo->pool, tvb, offset+1+4, option_length-1-4,
					htype);
				proto_item_append_text(oi, ", %s, client DHCP scope: %s",
					htype_str, ip_num_to_str(pinfo->pool, scope));

				proto_tree_add_item(option_tree, hf_dhcpfo_client_hw_type, tvb,
					offset+4, 1, ENC_BIG_ENDIAN);
				proto_tree_add_string(option_tree, hf_dhcpfo_client_hardware_address, tvb,
					offset+1+4, option_length-1-4, htype_str);
			}
			break;

		case DHCP_FO_PD_FTDDNS:
			proto_tree_add_item(option_tree, hf_dhcpfo_ftddns, tvb,
			    offset, option_length, ENC_ASCII);
			break;

		case DHCP_FO_PD_REJECT_REASON:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Reject reason is not 1 byte long");
				break;
			}
			reject_reason = tvb_get_uint8(tvb, offset);

			proto_item_append_text(oi, ", %s (%d)",
			    val_to_str_const(reject_reason, reject_reason_vals,
			      "Unknown Packet"),
			    reject_reason);

			proto_tree_add_uint(option_tree,
			    hf_dhcpfo_reject_reason, tvb, offset,
			    option_length, reject_reason);
			break;

		case DHCP_FO_PD_RELATIONSHIP_NAME:
			if (microsoft_style == false) {
				/* Parse as ASCII */
				proto_tree_add_item_ret_string(option_tree,
					hf_dhcpfo_relationship_name, tvb, offset,
					option_length, ENC_ASCII, pinfo->pool, &relationship_name_str);
				proto_item_append_text(oi,", \"%s\"",
					format_text(pinfo->pool, relationship_name_str, option_length));
			} else {
				/* Microsoft-style: Parse as UTF-16-LE */
				proto_tree_add_item_ret_string(option_tree,
					hf_dhcpfo_relationship_name, tvb, offset,
					option_length, ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &relationship_name_str);
				/* String length is half the data length */
				proto_item_append_text(oi,", \"%s\"",
					format_text(pinfo->pool, relationship_name_str, option_length/2));
			}
			break;

		case DHCP_FO_PD_MESSAGE:
			proto_tree_add_item(option_tree, hf_dhcpfo_message, tvb,
			    offset, option_length, ENC_ASCII);
			break;

		case DHCP_FO_PD_MCLT:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "MCLT is not 4 bytes long");
				break;
			}
			mclt = tvb_get_ntohl(tvb, offset);
			proto_item_append_text(oi,", %u seconds", mclt);
			proto_tree_add_uint(option_tree, hf_dhcpfo_mclt, tvb,
			    offset, option_length, mclt);
			break;

		case DHCP_FO_PD_VENDOR_CLASS:
			if (microsoft_style == false) {
				/* Parse as ASCII */
				proto_tree_add_item_ret_string(option_tree,
					hf_dhcpfo_vendor_class, tvb, offset,
					option_length, ENC_ASCII, pinfo->pool, &vendor_class_str);
				proto_item_append_text(oi,", \"%s\"",
					format_text(pinfo->pool, vendor_class_str, option_length));
			} else {
				/* Microsoft-style: Parse as UTF-16-LE */
				proto_tree_add_item_ret_string(option_tree,
					hf_dhcpfo_vendor_class, tvb, offset,
					option_length, ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &vendor_class_str);
				/* String length is half the data length */
				proto_item_append_text(oi,", \"%s\"",
					format_text(pinfo->pool, vendor_class_str, option_length/2));
			}
			break;

		case DHCP_FO_PD_LEASE_EXPIRATION_TIME:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Lease expiration time is not 4 bytes long");
				break;
			}
			lease_expiration_time =
			    tvb_get_ntohl(tvb, offset);
			lease_expiration_time_str =
			    abs_time_secs_to_str(pinfo->pool, lease_expiration_time, ABSOLUTE_TIME_LOCAL, true);

			proto_item_append_text(oi, ", %s",
			    lease_expiration_time_str);

			proto_tree_add_uint_format_value(option_tree,
			    hf_dhcpfo_lease_expiration_time, tvb,
			    offset, option_length,
			    lease_expiration_time,
			    "%s",
			    lease_expiration_time_str);
			break;

		case DHCP_FO_PD_POTENTIAL_EXPIRATION_TIME:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Potential expiration time is not 4 bytes long");
				break;
			}
			potential_expiration_time =
			    tvb_get_ntohl(tvb, offset);

			potential_expiration_time_str =
			    abs_time_secs_to_str(pinfo->pool, potential_expiration_time, ABSOLUTE_TIME_LOCAL, true);

			proto_item_append_text(oi, ", %s",
			    potential_expiration_time_str);

			proto_tree_add_uint_format_value(option_tree,
			    hf_dhcpfo_potential_expiration_time, tvb,
			    offset, option_length,
			    potential_expiration_time,
			    "%s",
			    potential_expiration_time_str);
			break;

		case DHCP_FO_PD_CLIENT_LAST_TRANSACTION_TIME:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Last transaction time is not 4 bytes long");
				break;
			}
			client_last_transaction_time =
			    tvb_get_ntohl(tvb, offset);
			client_last_transaction_time_str =
			    abs_time_secs_to_str(pinfo->pool, client_last_transaction_time, ABSOLUTE_TIME_LOCAL, true);

			proto_item_append_text(oi, ", %s",
			    client_last_transaction_time_str);

			proto_tree_add_uint_format_value(option_tree,
			    hf_dhcpfo_client_last_transaction_time, tvb,
			    offset, option_length,
			    client_last_transaction_time,
			    "%s",
			    abs_time_secs_to_str(pinfo->pool, client_last_transaction_time, ABSOLUTE_TIME_LOCAL, true));
			break;

		case DHCP_FO_PD_START_TIME_OF_STATE:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Start time of state is not 4 bytes long");
				break;
			}
			start_time_of_state =
			    tvb_get_ntohl(tvb, offset);
			start_time_of_state_str =
			    abs_time_secs_to_str(pinfo->pool, start_time_of_state, ABSOLUTE_TIME_LOCAL, true);

			proto_item_append_text(oi, ", %s",
			    start_time_of_state_str);

			proto_tree_add_uint_format_value(option_tree,
			    hf_dhcpfo_start_time_of_state, tvb,
			    offset, option_length,
			    start_time_of_state,
			    "%s",
			    abs_time_secs_to_str(pinfo->pool, start_time_of_state, ABSOLUTE_TIME_LOCAL, true));
			break;

		case DHCP_FO_PD_SERVERSTATE:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "server status is not 1 byte long");
				break;
			}
			server_state = tvb_get_uint8(tvb, offset);

			proto_item_append_text(oi, ", %s (%u)",
			    val_to_str_const(server_state, server_state_vals,
			        "Unknown"),
			    server_state);

			proto_tree_add_uint(option_tree,
			    hf_dhcpfo_server_state, tvb, offset, 1,
			    server_state);
			break;

		case DHCP_FO_PD_SERVERFLAG:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Serverflag is not 1 byte long");
				break;
			}
			serverflag = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s (%d)",
				val_to_str_const(serverflag, serverflag_vals, "UNKNOWN FLAGS"),
				serverflag);
			proto_tree_add_item(option_tree, hf_dhcpfo_serverflag, tvb, offset, option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_VENDOR_OPTION:
			proto_tree_add_item(option_tree,
			    hf_dhcpfo_vendor_option, tvb, offset,
			    option_length, ENC_NA);
			break;

		case DHCP_FO_PD_MAX_UNACKED_BNDUPD:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Max unacked BNDUPD is not 4 bytes long");
				break;
			}
			max_unacked_bndupd = tvb_get_ntohl(tvb, offset);
			proto_item_append_text(oi, ", %u", max_unacked_bndupd);

			proto_tree_add_uint(option_tree,
			    hf_dhcpfo_max_unacked_bndupd, tvb, offset,
			    option_length, max_unacked_bndupd);
			break;

		case DHCP_FO_PD_RECEIVE_TIMER:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Receive timer is not 4 bytes long");
				break;
			}
			receive_timer = tvb_get_ntohl(tvb, offset);
			proto_item_append_text(oi,", %u seconds",
			    receive_timer);

			proto_tree_add_uint(option_tree,
			    hf_dhcpfo_receive_timer, tvb, offset,
			    option_length, receive_timer);
			break;

		case DHCP_FO_PD_HASH_BUCKET_ASSIGNMENT:
			proto_tree_add_item(option_tree,
			    hf_dhcpfo_hash_bucket_assignment, tvb,
			    offset, option_length, ENC_NA);
			break;

		case DHCP_FO_PD_IP_FLAGS: {
			if (microsoft_style == false) {
				/* As specified in the draft: 16-bit flags */
				static int * const ipflags[] = {
					&hf_dhcpfo_ipflags_reserved,
					&hf_dhcpfo_ipflags_bootp,
					&hf_dhcpfo_ipflags_mbz,
					NULL
				};
				if (option_length != 2) {
					/* Draft-12 shows Len=1 with 16-bit field though */
					expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "IP flags is not 2 bytes long");
					break;
				}
				proto_tree_add_bitmask(option_tree, tvb, offset, hf_dhcpfo_ipflags,
					ett_fo_payload_data, ipflags, ENC_BIG_ENDIAN);
			} else {
				/* Microsoft-style: one byte only, usage unknown */
				if (option_length != 1) {
					expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "IP flags is not 1 bytes long");
					break;
				}
				proto_item_append_text(oi, ", flags (Microsoft-specific): 0x%02x", tvb_get_uint8(tvb, offset));
				proto_tree_add_item(option_tree, hf_dhcpfo_ms_ipflags, tvb, offset, option_length, ENC_BIG_ENDIAN);
			}
			break;
			}

		case DHCP_FO_PD_MESSAGE_DIGEST:
			if (option_length < 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Message digest option is too short");
				break;
			}

			message_digest_type = tvb_get_uint8(tvb, offset);
			ti = proto_tree_add_item(option_tree, hf_dhcpfo_message_digest_type, tvb, offset, 1, ENC_BIG_ENDIAN);

			if (message_digest_type >= 1 && message_digest_type <= 2) {
				proto_item_append_text(oi, ", %s", val_to_str_const(message_digest_type, message_digest_type_vals, "Unknown value"));
			} else {
				proto_item_append_text(oi, ", type not allowed");
				expert_add_info_format(pinfo, ti, &ei_dhcpfo_message_digest_type_not_allowed, "Message digest type: %u, not allowed", message_digest_type);
			}

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_message_digest, tvb, offset+1,
			    option_length-1, ENC_ASCII);
			break;

		case DHCP_FO_PD_PROTOCOL_VERSION:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Protocol version is not 1 byte long");
				break;
			}
			proto_item_append_text(oi, ", version: %u", tvb_get_uint8(tvb, offset));
			proto_tree_add_item(option_tree, hf_dhcpfo_protocol_version, tvb, offset, option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_TLS_REQUEST:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "TLS request is not 1 bytes long");
				break;
			}
			tls_request = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s", val_to_str(tls_request, tls_request_vals, "Unknown (%u)"));
			proto_tree_add_item(option_tree, hf_dhcpfo_tls_request, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_TLS_REPLY:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "TLS reply is not 1 bytes long");
				break;
			}
			tls_reply = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s", val_to_str(tls_reply, tls_reply_vals, "Unknown (%u)"));
			proto_tree_add_item(option_tree, hf_dhcpfo_tls_reply, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_REQUEST_OPTION:
		case DHCP_FO_PD_REPLY_OPTION:
			proto_tree_add_item(option_tree, hf_dhcpfo_options, tvb, offset, option_length, ENC_NA);
			break;

		case DHCP_FO_PD_OPTION_30:
			if (microsoft_style) {
				/* Microsoft: Scope ID List */
				uint16_t local_offset = 0;
				while (local_offset < option_length) {
					proto_tree_add_item(option_tree,
						hf_dhcpfo_ms_scope_id, tvb, offset+local_offset, 4, ENC_LITTLE_ENDIAN);
					local_offset += 4;
				}
			} else {
				/* In Infoblox this is client hostname */
				proto_tree_add_item_ret_string(option_tree,
					hf_dhcpfo_infoblox_client_hostname, tvb, offset,
					option_length, ENC_UTF_8, pinfo->pool, &client_hostname_str);
				proto_item_append_text(oi,", \"%s\"",
					format_text(pinfo->pool, client_hostname_str, option_length));
			}
			break;

		case DHCP_FO_PD_OPTION_31:
			/* Microsoft: Client Name */
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_ms_client_name, tvb, offset,
			    option_length, ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &client_hostname_str);
			/* With UTF-16 the string length is half the data length, minus the zero-termination */
			proto_item_append_text(oi,", \"%s\"",
			    format_text(pinfo->pool, client_hostname_str, option_length/2-1));
			break;

		case DHCP_FO_PD_OPTION_32:
			/* Microsoft: Client Description */
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_ms_client_description, tvb, offset,
			    option_length, ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &ms_client_description_str);
			/* With UTF-16 the string length is half the data length, minus the zero-termination */
			proto_item_append_text(oi,", \"%s\"",
			    format_text(pinfo->pool, ms_client_description_str, option_length/2-1));
			break;

		case DHCP_FO_PD_OPTION_33:
			/* Microsoft: Client Subnet Mask */
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "netmask is not 4 bytes long");
				break;
			}
			proto_item_append_text(oi, ", %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
			proto_tree_add_item(option_tree,
				hf_dhcpfo_ms_client_subnet_mask, tvb, offset,
				option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_OPTION_34:
			/* Microsoft: Server IP */
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "server IP address is not 4 bytes long");
				break;
			}
			proto_item_append_text(oi, ", %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
			proto_tree_add_item(option_tree,
				hf_dhcpfo_ms_server_ip, tvb, offset,
				option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_OPTION_35:
			/* Microsoft: Server Name */
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_ms_server_name, tvb, offset,
			    option_length, ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &ms_server_name_str);
			/* With UTF-16 the string length is half the data length, minus the zero-termination */
			proto_item_append_text(oi,", \"%s\"",
			    format_text(pinfo->pool, ms_server_name_str, option_length/2-1));
			break;

		case DHCP_FO_PD_OPTION_36:
			/* Microsoft: Client Type */
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "client type is not 1 byte long");
				break;
			}
			ms_client_type = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s (%d)",
				val_to_str_const(ms_client_type, ms_client_type_vals, "(undefined)"),
				ms_client_type);
			proto_tree_add_item(option_tree, hf_dhcpfo_ms_client_type, tvb, offset, option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_OPTION_37:
			/* Microsoft: Client NAP Status */
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "client NAP status is not 1 byte long");
				break;
			}
			ms_client_nap_status = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s (%d)",
				val_to_str_const(ms_client_nap_status, ms_client_nap_status_vals, "(undefined)"),
				ms_client_nap_status);
			proto_tree_add_item(option_tree, hf_dhcpfo_ms_client_nap_status, tvb, offset, option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_OPTION_38:
			/* Microsoft: Client NAP Probation */
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "client NAP probation is not 4 bytes long");
				break;
			}
			ms_client_nap_probation = tvb_get_ntohl(tvb, offset);
			/* The option value is specified:
			 * "The value is specified as an absolute time and represents the
			 * number of 100-nanosecond intervals since January 1, 1601 (UTC)"
			 * But obviously that large values won't fit into a 4-byte variable.
			 * So showing as uint32 for now.
			 */
			proto_item_append_text(oi,", %u", ms_client_nap_probation);
			proto_tree_add_uint(option_tree,
				hf_dhcpfo_ms_client_nap_probation, tvb, offset,
				option_length, ms_client_nap_probation);
			break;

		case DHCP_FO_PD_OPTION_39:
			/* Microsoft: Client NAP Capable */
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "client NAP capable option is not 1 byte long");
				break;
			}
			ms_client_nap_capable = tvb_get_uint8(tvb, offset);
			proto_item_append_text(oi, ", %s (%d)",
				tfs_get_true_false(ms_client_nap_capable),
				ms_client_nap_capable);
			proto_tree_add_item(option_tree, hf_dhcpfo_ms_client_nap_capable, tvb, offset, option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_OPTION_40:
			/* Microsoft: Client Matched Policy */
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_ms_client_matched_policy, tvb, offset,
			    option_length, ENC_UTF_16|ENC_LITTLE_ENDIAN, pinfo->pool, &ms_client_matched_policy_str);
			/* With UTF-16 the string length is half the data length, minus the zero-termination */
			proto_item_append_text(oi,", \"%s\"",
			    format_text(pinfo->pool, ms_client_matched_policy_str, option_length/2-1));
			break;

		case DHCP_FO_PD_OPTION_41:
			/* Microsoft: Extended Address State */
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Extended address state is not 4 bytes long");
				break;
			}
			ms_extended_address_state = tvb_get_ntohl(tvb, offset);
			proto_item_append_text(oi,", 0x%08x", ms_extended_address_state);

			proto_tree_add_uint(option_tree,
			    hf_dhcpfo_ms_extended_address_state, tvb, offset,
			    option_length, ms_extended_address_state);
			break;

		default:
			proto_tree_add_item(option_tree,
				hf_dhcpfo_unknown_data, tvb, offset,
				option_length, ENC_ASCII);
			break;
		}

		offset += option_length;
	}

	return tvb_reported_length(tvb);
}

static int
dissect_dhcpfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, dhcpfo_desegment, 2,
	    get_dhcpfo_pdu_len, dissect_dhcpfo_pdu, data);
	return tvb_reported_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_dhcpfo(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_dhcpfo_length,
			{ "Message length",	   "dhcpfo.length",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_type,
			{ "Message Type",	   "dhcpfo.type",
			FT_UINT8, BASE_DEC, VALS(failover_vals), 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_poffset,
			{ "Payload Offset",	   "dhcpfo.poffset",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_time,
			{ "Time",	   "dhcpfo.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_xid,
			{ "Xid",	   "dhcpfo.xid",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_additional_HB,
			{"Additional Header Bytes",	"dhcpfo.additionalheaderbytes",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_payload_data,
			{"Payload Data",	"dhcpfo.payloaddata",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_dhcp_style_option,
			{"DHCP Style Option",	"dhcpfo.dhcpstyleoption",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dhcpfo_option_code,
			{"Option Code",		"dhcpfo.optioncode",
			FT_UINT16, BASE_DEC, VALS(option_code_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_option_length,
			{"Length",		"dhcpfo.optionlength",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_binding_status,
			{"Status", "dhcpfo.bindingstatus",
			FT_UINT32, BASE_DEC, VALS(binding_status_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_server_state,
			{"server status", "dhcpfo.serverstatus",
			FT_UINT8, BASE_DEC, VALS(server_state_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_assigned_ip_address,
			{"assigned ip address", "dhcpfo.assignedipaddress",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_delayed_service_parameter,
			{"delayed service parameter", "dhcpfo.delayedserviceparameter",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_addresses_transferred,
			{"addresses transferred", "dhcpfo.addressestransferred",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_client_identifier,
			{"Client Identifier", "dhcpfo.clientidentifier",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_client_hw_type,
			{"Client Hardware Type", "dhcpfo.clienthardwaretype",
			FT_UINT8, BASE_HEX, VALS(arp_hrd_vals), 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_client_hardware_address,
			{"Client Hardware Address", "dhcpfo.clienthardwareaddress",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ftddns,
			{"FTDDNS", "dhcpfo.ftddns",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_reject_reason,
			{"Reject reason", "dhcpfo.rejectreason",
			FT_UINT8, BASE_DEC, VALS(reject_reason_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_relationship_name,
			{"Relationship name", "dhcpfo.relationshipname",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_message,
			{"Message", "dhcpfo.message",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_mclt,
			{"MCLT", "dhcpfo.mclt",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_vendor_class,
			{"Vendor class", "dhcpfo.vendorclass",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_lease_expiration_time,
			{"Lease expiration time", "dhcpfo.leaseexpirationtime",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_potential_expiration_time,
			{"Potential expiration time", "dhcpfo.potentialexpirationtime",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_client_last_transaction_time,
			{"Client last transaction time", "dhcpfo.clientlasttransactiontime",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_start_time_of_state,
			{"Start time of state", "dhcpfo.starttimeofstate",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_vendor_option,
			{"Vendor option", "dhcpfo.vendoroption",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_max_unacked_bndupd,
			{"Max unacked BNDUPD", "dhcpfo.maxunackedbndupd",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_protocol_version,
			{"Protocol version", "dhcpfo.protocolversion",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_receive_timer,
			{"Receive timer", "dhcpfo.receivetimer",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_second_seconds, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_message_digest,
			{"Message digest", "dhcpfo.messagedigest",
			FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_hash_bucket_assignment,
			{"Hash bucket assignment", "dhcpfo.hashbucketassignment",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ipflags,
			{"IP Flags", "dhcpfo.ipflags",
			FT_UINT16, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ipflags_reserved,
			{"Reserved", "dhcpfo.ipflags.reserved",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ipflags_bootp,
			{"BOOTP", "dhcpfo.ipflags.bootp",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ipflags_mbz,
			{"MBZ", "dhcpfo.ipflags.mbz",
			FT_UINT8, BASE_HEX, NULL, 0x3F,
			NULL, HFILL }
		},
		{&hf_dhcpfo_message_digest_type,
			{"Message digest type", "dhcpfo.message_digest_type",
			FT_UINT8, BASE_DEC, VALS(message_digest_type_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_tls_request,
			{"TLS Request", "dhcpfo.tls_request",
			FT_UINT8, BASE_DEC, VALS(tls_request_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_tls_reply,
			{"TLS Reply", "dhcpfo.tls_reply",
			FT_UINT8, BASE_DEC, VALS(tls_reply_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_serverflag,
			{"Serverflag", "dhcpfo.serverflag",
			FT_UINT8, BASE_DEC, VALS(serverflag_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_options,
			{"Options", "dhcpfo.options",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_name,
			{"Client name (Microsoft-specific)", "dhcpfo.microsoft.clientname",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_description,
			{"Client description (Microsoft-specific)", "dhcpfo.microsoft.clientdescription",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_type,
			{"Client type (Microsoft-specific)", "dhcpfo.microsoft.clienttype",
			FT_UINT8, BASE_NONE, VALS(ms_client_type_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_nap_status,
			{"Client NAP status (Microsoft-specific)", "dhcpfo.microsoft.clientnapstatus",
			FT_UINT8, BASE_NONE, VALS(ms_client_nap_status_vals), 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_nap_capable,
			{"Client NAP capable (Microsoft-specific)", "dhcpfo.microsoft.clientnapcapable",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_nap_probation,
			{"Client NAP probation (Microsoft-specific)", "dhcpfo.microsoft.clientnapprobation",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_matched_policy,
			{"Client matched policy (Microsoft-specific)", "dhcpfo.microsoft.clientmatchedpolicy",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_server_name,
			{"Server name (Microsoft-specific)", "dhcpfo.microsoft.servername",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_scope,
			{"Client DHCP scope (Microsoft-specific)", "dhcpfo.microsoft.clientscope",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_client_subnet_mask,
			{"Client subnet mask (Microsoft-specific)", "dhcpfo.microsoft.clientsubnetmask",
			FT_IPv4, BASE_NETMASK, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_scope_id,
			{"Scope ID (Microsoft-specific)", "dhcpfo.microsoft.scopeid",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_server_ip,
			{"Server IP (Microsoft-specific)", "dhcpfo.microsoft.serverip",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_ipflags,
			{"IP flags (Microsoft-specific)", "dhcpfo.microsoft.ipflags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_ms_extended_address_state,
			{"Extended address state (Microsoft-specific)", "dhcpfo.microsoft.extendedaddressstate",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_infoblox_client_hostname,
			{"Client hostname (Infoblox-specific)", "dhcpfo.infoblox.clienthostname",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{&hf_dhcpfo_unknown_data,
			{"Unknown data", "dhcpfo.unknowndata",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_dhcpfo,
		&ett_fo_payload,
		&ett_fo_option,
		&ett_fo_payload_data,
	};

	static ei_register_info ei[] = {
		{ &ei_dhcpfo_bad_length, { "dhcpfo.bad_length", PI_PROTOCOL, PI_WARN, "Bad length", EXPFILL }},
		{ &ei_dhcpfo_message_digest_type_not_allowed, { "dhcpfo.message_digest_type_not_allowed", PI_PROTOCOL, PI_WARN, "Message digest type not allowed", EXPFILL }},
	};

	module_t *dhcpfo_module;
	expert_module_t* expert_dhcpfo;

/* Register the protocol name and description */
	proto_dhcpfo = proto_register_protocol("DHCP Failover", "DHCPFO", "dhcpfo");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_dhcpfo, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dhcpfo = expert_register_protocol(proto_dhcpfo);
	expert_register_field_array(expert_dhcpfo, ei, array_length(ei));

	dhcpfo_module = prefs_register_protocol(proto_dhcpfo, NULL);

	prefs_register_bool_preference(dhcpfo_module, "desegment",
	    "Reassemble DHCP failover messages spanning multiple TCP segments",
	    "Whether the DHCP failover dissector should reassemble messages spanning multiple TCP segments."
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &dhcpfo_desegment);
	prefs_register_enum_preference(dhcpfo_module, "microsoft_compatibility",
		"Microsoft Windows DHCP server compatibility",
		"Enables the dissector to show Microsoft-formatted option fields correctly",
		&dhcpfo_microsoft_compatibility,
		microsoft_compatibility, false);

	dhcpfo_handle = register_dissector("dhcpfo", dissect_dhcpfo, proto_dhcpfo);
}

void
proto_reg_handoff_dhcpfo(void)
{
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_DHCPFO, dhcpfo_handle);
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
