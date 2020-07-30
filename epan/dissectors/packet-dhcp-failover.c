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

/* desegmentation of DHCP failover over TCP */
static gboolean dhcpfo_desegment = TRUE;

/* Initialize the protocol and registered fields */
static int proto_dhcpfo = -1;
static int hf_dhcpfo_length = -1;
static int hf_dhcpfo_type = -1;
static int hf_dhcpfo_poffset = -1;
static int hf_dhcpfo_time = -1;
static int hf_dhcpfo_xid = -1;
static int hf_dhcpfo_additional_HB = -1;
static int hf_dhcpfo_payload_data = -1;
static int hf_dhcpfo_option_code = -1;
static int hf_dhcpfo_dhcp_style_option = -1;
static int hf_dhcpfo_option_length = -1;
static int hf_dhcpfo_binding_status = -1;
static int hf_dhcpfo_server_state = -1;
static int hf_dhcpfo_assigned_ip_address = -1;
static int hf_dhcpfo_delayed_service_parameter = -1;
static int hf_dhcpfo_addresses_transferred = -1;
static int hf_dhcpfo_client_identifier = -1;
static int hf_dhcpfo_client_hw_type = -1;
static int hf_dhcpfo_client_hardware_address = -1;
static int hf_dhcpfo_ftddns = -1;
static int hf_dhcpfo_reject_reason = -1;
static int hf_dhcpfo_relationship_name = -1;
static int hf_dhcpfo_message = -1;
static int hf_dhcpfo_mclt = -1;
static int hf_dhcpfo_vendor_class = -1;
static int hf_dhcpfo_lease_expiration_time = -1;
static int hf_dhcpfo_potential_expiration_time = -1;
static int hf_dhcpfo_client_last_transaction_time = -1;
static int hf_dhcpfo_start_time_of_state = -1;
static int hf_dhcpfo_vendor_option = -1;
static int hf_dhcpfo_max_unacked_bndupd = -1;
static int hf_dhcpfo_protocol_version = -1;
static int hf_dhcpfo_receive_timer = -1;
static int hf_dhcpfo_message_digest = -1;
static int hf_dhcpfo_ipflags = -1;
static int hf_dhcpfo_ipflags_reserved = -1;
static int hf_dhcpfo_ipflags_bootp = -1;
static int hf_dhcpfo_ipflags_mbz = -1;
static int hf_dhcpfo_hash_bucket_assignment = -1;
static int hf_dhcpfo_message_digest_type = -1;
static int hf_dhcpfo_tls_request = -1;
static int hf_dhcpfo_tls_reply = -1;
static int hf_dhcpfo_serverflag = -1;
static int hf_dhcpfo_options = -1;

/* Initialize the subtree pointers */
static gint ett_dhcpfo = -1;
static gint ett_fo_payload = -1;
static gint ett_fo_option = -1;
static gint ett_fo_payload_data = -1;

static expert_field ei_dhcpfo_bad_length = EI_INIT;
static expert_field ei_dhcpfo_message_digest_type_not_allowed = EI_INIT;


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
	{0, NULL}
};

static const value_string serverflag_vals[] =
{
	{0, "NONE"},
	{1, "STARTUP"},
	{0, NULL}
};

/* Code to actually dissect the packets */
static guint
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
	guint8 tls_request, tls_reply;
	guint16 length;
	guint type, serverflag;
	int poffset;
	guint32 xid;
	nstime_t timex;
	guint32 lease_expiration_time,
			potential_expiration_time, client_last_transaction_time,
			start_time_of_state;
	gboolean bogus_poffset;
	guint16 opcode, option_length;
	guint8 htype, reject_reason, message_digest_type, binding_status;
	const guint8 *vendor_class_str;
	const gchar *htype_str;
	gchar *lease_expiration_time_str, *potential_expiration_time_str,
		  *client_last_transaction_time_str, *start_time_of_state_str;
	guint32 mclt;
	guint8 server_state;
	guint32 max_unacked_bndupd, receive_timer;

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

	type = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_uint(dhcpfo_tree,
		    hf_dhcpfo_type, tvb, offset, 1, type);
	}
	col_set_str(pinfo->cinfo, COL_INFO,
	    val_to_str_const(type, failover_vals, "Unknown Packet"));
	offset += 1;

	poffset = tvb_get_guint8(tvb, offset);
	if (poffset < DHCPFO_FL_HDR_LEN) {
		bogus_poffset = TRUE;
		if (tree) {
			proto_tree_add_uint_format_value(dhcpfo_tree,
			    hf_dhcpfo_poffset, tvb, offset, 1, poffset,
			    "%u (bogus, must be >= %u)",
			    poffset, DHCPFO_FL_HDR_LEN);
		}
	} else if (poffset > length) {
		bogus_poffset = TRUE;
		if (tree) {
			proto_tree_add_uint_format_value(dhcpfo_tree,
			    hf_dhcpfo_poffset, tvb, offset, 1, poffset,
			    "%u (bogus, must be <= length of message)",
			    poffset);
		}
	} else {
		bogus_poffset = FALSE;
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
		    abs_time_secs_to_str(wmem_packet_scope(), timex.secs, ABSOLUTE_TIME_LOCAL, TRUE));
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

	if (!tree)
		return tvb_reported_length(tvb);

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

		proto_item_append_text(oi, ", %s (%u)",
		    val_to_str_const(opcode, option_code_vals, "Unknown Option"),
		    opcode);

		proto_tree_add_uint(option_tree, hf_dhcpfo_option_code, tvb,
		    offset, 2, opcode);

		proto_tree_add_uint(option_tree, hf_dhcpfo_option_length, tvb,
		    offset+2, 2, option_length);

		offset += 4;

		/** opcode dependent format **/

		switch (opcode) {

		case DHCP_FO_PD_BINDING_STATUS:
			binding_status = tvb_get_guint8(tvb, offset);
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
			proto_item_append_text(oi, ", %s ", tvb_ip_to_str(tvb, offset));

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_assigned_ip_address, tvb,	offset,
			    option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_DELAYED_SERVICE_PARAMETER:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "delayed service parameter is not 1 bytes long");
				break;
			}

			proto_item_append_text(oi, ", %d ", tvb_get_guint8(tvb, offset));

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
			const guint8* identifier;
			/*
			 * XXX - if this is truly like DHCP option 81,
			 * we need to dissect it as such.
			 */
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_client_identifier, tvb, offset,
			    option_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &identifier);

			proto_item_append_text(oi,", \"%s\"", identifier);
			}
			break;

		case DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS:
			if (option_length < 2) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "hardware address is too short");
				break;
			}
			htype = tvb_get_guint8(tvb, offset);
			htype_str = tvb_arphrdaddr_to_str(tvb, offset+1, option_length-1,
			    htype);

			proto_item_append_text(oi, ", %s, %s", htype_str,
			    htype_str);

			proto_tree_add_item(option_tree, hf_dhcpfo_client_hw_type, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_string(option_tree, hf_dhcpfo_client_hardware_address, tvb,
				offset+1, option_length-1, htype_str);
			break;

		case DHCP_FO_PD_FTDDNS:
			proto_tree_add_item(option_tree, hf_dhcpfo_ftddns, tvb,
			    offset, option_length, ENC_ASCII|ENC_NA);
			break;

		case DHCP_FO_PD_REJECT_REASON:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Reject reason is not 1 byte long");
				break;
			}
			reject_reason = tvb_get_guint8(tvb, offset);

			proto_item_append_text(oi, ", %s (%d)",
			    val_to_str_const(reject_reason, reject_reason_vals,
			      "Unknown Packet"),
			    reject_reason);

			proto_tree_add_uint(option_tree,
			    hf_dhcpfo_reject_reason, tvb, offset,
			    option_length, reject_reason);
			break;

		case DHCP_FO_PD_RELATIONSHIP_NAME:
			proto_tree_add_item(option_tree, hf_dhcpfo_relationship_name, tvb,
			    offset, option_length, ENC_ASCII|ENC_NA);
			break;

		case DHCP_FO_PD_MESSAGE:
			proto_tree_add_item(option_tree, hf_dhcpfo_message, tvb,
			    offset, option_length, ENC_ASCII|ENC_NA);
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
			proto_tree_add_item_ret_string(option_tree,
			    hf_dhcpfo_vendor_class, tvb, offset,
			    option_length, ENC_ASCII, wmem_packet_scope(), &vendor_class_str);
			proto_item_append_text(oi,", \"%s\"",
			    format_text(wmem_packet_scope(), vendor_class_str, option_length));
			break;

		case DHCP_FO_PD_LEASE_EXPIRATION_TIME:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Lease expiration time is not 4 bytes long");
				break;
			}
			lease_expiration_time =
			    tvb_get_ntohl(tvb, offset);
			lease_expiration_time_str =
			    abs_time_secs_to_str(wmem_packet_scope(), lease_expiration_time, ABSOLUTE_TIME_LOCAL, TRUE);

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
			    abs_time_secs_to_str(wmem_packet_scope(), potential_expiration_time, ABSOLUTE_TIME_LOCAL, TRUE);

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
			    abs_time_secs_to_str(wmem_packet_scope(), client_last_transaction_time, ABSOLUTE_TIME_LOCAL, TRUE);

			proto_item_append_text(oi, ", %s",
			    client_last_transaction_time_str);

			proto_tree_add_uint_format_value(option_tree,
			    hf_dhcpfo_client_last_transaction_time, tvb,
			    offset, option_length,
			    client_last_transaction_time,
			    "%s",
			    abs_time_secs_to_str(wmem_packet_scope(), client_last_transaction_time, ABSOLUTE_TIME_LOCAL, TRUE));
			break;

		case DHCP_FO_PD_START_TIME_OF_STATE:
			if (option_length != 4) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Start time of state is not 4 bytes long");
				break;
			}
			start_time_of_state =
			    tvb_get_ntohl(tvb, offset);
			start_time_of_state_str =
			    abs_time_secs_to_str(wmem_packet_scope(), start_time_of_state, ABSOLUTE_TIME_LOCAL, TRUE);

			proto_item_append_text(oi, ", %s",
			    start_time_of_state_str);

			proto_tree_add_uint_format_value(option_tree,
			    hf_dhcpfo_start_time_of_state, tvb,
			    offset, option_length,
			    start_time_of_state,
			    "%s",
			    abs_time_secs_to_str(wmem_packet_scope(), start_time_of_state, ABSOLUTE_TIME_LOCAL, TRUE));
			break;

		case DHCP_FO_PD_SERVERSTATE:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "server status is not 1 byte long");
				break;
			}
			server_state = tvb_get_guint8(tvb, offset);

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
			serverflag = tvb_get_guint8(tvb, offset);
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
			static int * const ipflags[] = {
				&hf_dhcpfo_ipflags_reserved,
				&hf_dhcpfo_ipflags_bootp,
				&hf_dhcpfo_ipflags_mbz,
				NULL
			};
			if (option_length != 2) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "IP flags is not 2 bytes long");
				break;
			}
			proto_tree_add_bitmask(option_tree, tvb, offset, hf_dhcpfo_ipflags,
			    ett_fo_payload_data, ipflags, ENC_BIG_ENDIAN);
			break;
			}

		case DHCP_FO_PD_MESSAGE_DIGEST:
			if (option_length < 2) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Message digest is too short");
				break;
			}

			message_digest_type = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_item(option_tree, hf_dhcpfo_message_digest_type, tvb, offset, 1, ENC_BIG_ENDIAN);

			if (message_digest_type == 1) {
				proto_item_append_text(oi, ", HMAC-MD5");
			} else {
				proto_item_append_text(oi, ", type not allowed");
				expert_add_info_format(pinfo, ti, &ei_dhcpfo_message_digest_type_not_allowed, "Message digest type: %u, not allowed", message_digest_type);
			}

			proto_tree_add_item(option_tree,
			    hf_dhcpfo_message_digest, tvb, offset+1,
			    option_length-1, ENC_ASCII|ENC_NA);
			break;

		case DHCP_FO_PD_PROTOCOL_VERSION:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "Protocol version is not 1 byte long");
				break;
			}
			proto_item_append_text(oi, ", version: %u", tvb_get_guint8(tvb, offset));
			proto_tree_add_item(option_tree, hf_dhcpfo_protocol_version, tvb, offset, option_length, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_TLS_REQUEST:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "TLS request is not 1 bytes long");
				break;
			}
			tls_request = tvb_get_guint8(tvb, offset);
			proto_item_append_text(oi, ", %s", val_to_str(tls_request, tls_request_vals, "Unknown (%u)"));
			proto_tree_add_item(option_tree, hf_dhcpfo_tls_request, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_TLS_REPLY:
			if (option_length != 1) {
				expert_add_info_format(pinfo, oi, &ei_dhcpfo_bad_length, "TLS reply is not 1 bytes long");
				break;
			}
			tls_reply = tvb_get_guint8(tvb, offset);
			proto_item_append_text(oi, ", %s", val_to_str(tls_reply, tls_reply_vals, "Unknown (%u)"));
			proto_tree_add_item(option_tree, hf_dhcpfo_tls_reply, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;

		case DHCP_FO_PD_REQUEST_OPTION:
		case DHCP_FO_PD_REPLY_OPTION:
			proto_tree_add_item(option_tree, hf_dhcpfo_options, tvb, offset, option_length, ENC_NA);
			break;
		default:
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
			{"Type", "dhcpfo.bindingstatus",
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
			NULL, HFILL }},

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
			FT_STRING, BASE_NONE, NULL, 0,
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

	};

/* Setup protocol subtree array */
	static gint *ett[] = {
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
}

void
proto_reg_handoff_dhcpfo(void)
{
	dissector_handle_t dhcpfo_handle;

	dhcpfo_handle = create_dissector_handle(dissect_dhcpfo, proto_dhcpfo);
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
