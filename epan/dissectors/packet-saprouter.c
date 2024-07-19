/* packet-saprouter.c
 * Routines for SAP Router dissection
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is a dissector for the SAP Router protocol.
 *
 * Some details and example requests can be found in pysap's documentation: https://pysap.readthedocs.io/en/latest/protocols/SAPRouter.html.
 */

#include <config.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/wmem/wmem.h>
#include <epan/conversation.h>

#include <epan/tap.h>
#include <ui/tap-credentials.h>

#include "packet-sapni.h"
#include "packet-sapsnc.h"


/* Define default ports */
#define SAPROUTER_PORT_RANGE "3298-3299"

/*
 * Length of the frame header
 */
#define SAPROUTER_HEADER_LEN	8

/*
 * Offsets of header fields
 */
#define SAPROUTER_ROUTE_LENGTH_OFFSET	16
#define SAPROUTER_ROUTE_OFFSET_OFFSET	20

/* SAP Router Eye Catcher strings */
#define SAPROUTER_TYPE_NIPING_STRING "EYECATCHER"
#define SAPROUTER_TYPE_ROUTE_STRING	"NI_ROUTE"
#define SAPROUTER_TYPE_ROUTE_ACCEPT	"NI_PONG"
#define SAPROUTER_TYPE_ERR_STRING	"NI_RTERR"
#define SAPROUTER_TYPE_ADMIN_STRING	"ROUTER_ADM"

/* SAP Router Talk Modes */
static const value_string saprouter_talk_mode_vals[] = {
	{ 0, "NI_MSG_IO" },
	{ 1, "NI_RAW_IO" },
	{ 2, "NI_ROUT_IO" },
	/* NULL */
	{ 0, NULL},
};

/* SAP Router Operation values */
static const value_string saprouter_opcode_vals[] = {
	{ 0, "Error information" },
	{ 1, "Version Request" },
	{ 2, "Version Response" },
	{ 5, "Send Handle (5)" },		/* TODO: Check this opcodes */
	{ 6, "Send Handle (6)" },		/* TODO: Check this opcodes */
	{ 8, "Send Handle (8)" },		/* TODO: Check this opcodes */
	{ 70, "SNC request" },			/* TODO: Check this opcodes NiSncOpcode: NISNC_REQ */
	{ 71, "SNC handshake complete" },	/* TODO: Check this opcodes NiSncOpcode: NISNC_ACK */
	/* NULL */
	{ 0, NULL}
};

/* SAP Router Return Code values (as per SAP Note 63342 https://launchpad.support.sap.com/#/notes/63342) */
static const value_string saprouter_return_code_vals[] = {
	{ -1, "NI-internal error (NIEINTERN)" },
	{ -2, "Host name unknown (NIEHOST_UNKNOWN)" },
	{ -3, "Service unknown (NIESERV_UNKNOWN)" },
	{ -4, "Service already used (NIESERV_USED)" },
	{ -5, "Time limit reached (NIETIMEOUT)" },
	{ -6, "Connection to partner broken (NIECONN_BROKEN)" },
	{ -7, "Data range too small (NIETOO_SMALL)" },
	{ -8, "Invalid parameters (NIEINVAL)" },
	{ -9, "Wake-Up (without data) (NIEWAKEUP)" },
	{-10, "Connection setup failed (NIECONN_REFUSED)" },
	{-11, "PING/PONG signal received (NIEPING)" },
	{-12, "Connection to partner via NiRouter not yet set up (NIECONN_PENDING)" },
	{-13, "Invalid version (NIEVERSION)" },
	{-14, "Local hostname cannot be found (NIEMYHOSTNAME)" },
	{-15, "No free port in range (NIENOFREEPORT)" },
	{-16, "Local hostname invalid (NIEMYHOST_VERIFY)" },
	{-17, "Error in the SNC shift in the saprouter ==> (NIESNC_FAILURE)" },
	{-18, "Opcode received (NIEOPCODE)" },
	{-19, "queue limit reached, next package not accepted (NIEQUE_FULL)" },
	{-20, "Requested package too large (NIETOO_BIG)" },
	{-90, "Host name unknown (NIEROUT_HOST_UNKNOWN)" },
	{-91, "Service unknown (NIEROUT_SERV_UNKNOWN)" },
	{-92, "Connection setup failed (NIEROUT_CONN_REFUSED)" },
	{-93, "NI-internal errors (NIEROUT_INTERN)" },
	{-94, "Connect from source to destination not allowed (NIEROUT_PERM_DENIED)" },
	{-95, "Connection terminated (NIEROUT_CONN_BROKEN)" },
	{-96, "Invalid client version (NIEROUT_VERSION)" },
	{-97, "Connection cancelled by administrator (NIEROUT_CANCELED)" },
	{-98, "saprouter shutdown (NIEROUT_SHUTDOWN)" },
	{-99, "Information request refused (NIEROUT_INFO_DENIED)" },
	{-100, "Max. number of clients reached (NIEROUT_OVERFLOW)" },
	{-101, "Talkmode not allowed (NIEROUT_MODE_DENIED)" },
	{-102, "Client not available (NIEROUT_NOCLIENT)" },
	{-103, "Error in external library (NIEROUT_EXTERN)" },
	{-104, "Error in the SNC shift (NIEROUT_SNC_FAILURE)" },
	/* NULL */
	{ 0, NULL}
};


/* SAP Router Admin Command values */
static const value_string saprouter_admin_command_vals[] = {
	{ 2, "Information Request" },
	{ 3, "New Route Table Request" },
	{ 4, "Toggle Trace Request" },
	{ 5, "Stop Request" },
	{ 6, "Cancel Route Request" },
	{ 7, "Dump Buffers Request" },
	{ 8, "Flush Buffers Request" },
	{ 9, "Soft Shutdown Request" },
	{ 10, "Set Trace Peer" },
	{ 11, "Clear Trace Peer" },
	{ 12, "Trace Connection" },
	{ 13, "Trace Connection" },
	{ 14, "Hide Error Information Request" },
	/* NULL */
	{ 0, NULL}
};

static int credentials_tap;

static int proto_saprouter;

/* General fields */
static int hf_saprouter_type;
static int hf_saprouter_ni_version;

/* Niping messages */
static int hf_saprouter_niping_message;

/* Route information */
static int hf_saprouter_route_version;
static int hf_saprouter_entries;
static int hf_saprouter_talk_mode;
static int hf_saprouter_rest_nodes;
static int hf_saprouter_route_length;
static int hf_saprouter_route_offset;
static int hf_saprouter_route;
static int hf_saprouter_route_string;

static int hf_saprouter_route_requested_in;
static int hf_saprouter_route_accepted_in;

/* Route strings */
static int hf_saprouter_route_string_hostname;
static int hf_saprouter_route_string_service;
static int hf_saprouter_route_string_password;


/* Error Information/Control Messages */
static int hf_saprouter_opcode;
static int hf_saprouter_return_code;
static int hf_saprouter_unknown;

/* Error Information Messages */
static int hf_saprouter_error_length;
static int hf_saprouter_error_string;
static int hf_saprouter_error_eyecatcher;
static int hf_saprouter_error_counter;
static int hf_saprouter_error_error;
static int hf_saprouter_error_return_code;
static int hf_saprouter_error_component;
static int hf_saprouter_error_release;
static int hf_saprouter_error_version;
static int hf_saprouter_error_module;
static int hf_saprouter_error_line;
static int hf_saprouter_error_detail;
static int hf_saprouter_error_time;
static int hf_saprouter_error_system_call;
static int hf_saprouter_error_errorno;
static int hf_saprouter_error_errorno_text;
static int hf_saprouter_error_error_count;
static int hf_saprouter_error_location;
static int hf_saprouter_error_unknown;  /* TODO: Unknown fields */

/* Control Messages */
static int hf_saprouter_control_length;
static int hf_saprouter_control_string;
static int hf_saprouter_control_unknown;

/* Admin Messages */
static int hf_saprouter_admin_command;
static int hf_saprouter_admin_password;
static int hf_saprouter_admin_client_count_short;
static int hf_saprouter_admin_client_count_int;
static int hf_saprouter_admin_client_ids;
static int hf_saprouter_admin_client_id;
static int hf_saprouter_admin_address_mask;

static int ett_saprouter;

/* Expert info */
static expert_field ei_saprouter_route_password_found;
static expert_field ei_saprouter_route_invalid_length;
static expert_field ei_saprouter_info_password_found;
static expert_field ei_saprouter_invalid_client_ids;

/* Global port preference */
static range_t *global_saprouter_port_range;


/* Global SNC dissection preference */
static bool global_saprouter_snc_dissection = true;

/* Protocol handle */
static dissector_handle_t saprouter_handle;

/* Session state information being tracked in a SAP Router conversation */
typedef struct saprouter_session_state {
	bool route_information;
	unsigned	 route_requested_in;
	bool route_accepted;
	unsigned	 route_accepted_in;
	bool route_snc_protected;
	char 	*src_hostname;			/* Source hostname (first entry in the route string) */
	uint32_t src_port;				/* Source port number */
	char 	*src_password;			/* Source password XXX: Check if possible */
	char 	*dest_hostname;			/* Destination hostname (last entry in the route string) */
	uint32_t dest_port;				/* Destination port number */
	char 	*dest_password;			/* Destination password */
} saprouter_session_state;

/*
 *
 */
void proto_reg_handoff_saprouter(void);
void proto_register_saprouter(void);


static uint32_t
dissect_serviceport(char *port){
	uint32_t portnumber = 0;

	if (g_ascii_isdigit(port[0])){
		portnumber = (uint32_t)strtoul(port, NULL, 10);
	} else if ((strlen(port)>5) && g_str_has_prefix(port, "sapdp")){
		portnumber = 3200 + (uint32_t)strtoul(port+5, NULL, 10);
	} else if ((strlen(port)>5) && g_str_has_prefix(port, "sapgw")){
		portnumber = 3300 + (uint32_t)strtoul(port+5, NULL, 10);
	} else if ((strlen(port)>5) && g_str_has_prefix(port, "sapms")){
		portnumber = 3600 + (uint32_t)strtoul(port+5, NULL, 10);
	}
	return (portnumber);
}

static void
dissect_routestring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, saprouter_session_state *session_state){
	int hop = 1;
	uint32_t len, route_offset, int_port = 0;
	char *hostname = NULL, *port = NULL, *password = NULL;
	proto_item *route_hop = NULL, *route_password = NULL;
	proto_tree *route_hop_tree = NULL;

	while (tvb_offset_exists(tvb, offset)){
		route_offset = offset; hostname = port = password = NULL;

		/* Create the subtree for this route hop */
		route_hop = proto_tree_add_item(tree, hf_saprouter_route_string, tvb, offset, 0, ENC_NA);
		route_hop_tree = proto_item_add_subtree(route_hop, ett_saprouter);
		proto_item_append_text(route_hop, ", nro %d", hop);

		/* Dissect the hostname string */
		len = tvb_strsize(tvb, offset);
		hostname = (char *)tvb_get_string_enc(wmem_file_scope(), tvb, offset, len - 1, ENC_ASCII);
		proto_tree_add_item(route_hop_tree, hf_saprouter_route_string_hostname, tvb, offset, len, ENC_ASCII|ENC_NA);
		offset += len;

		/* Dissect the port string */
		len = tvb_strsize(tvb, offset);
		port = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, len - 1, ENC_ASCII);
		proto_tree_add_item(route_hop_tree, hf_saprouter_route_string_service, tvb, offset, len, ENC_ASCII|ENC_NA);
		offset += len;

		/* Dissect the password string */
		len = tvb_strsize(tvb, offset);
		password = (char *)tvb_get_string_enc(wmem_file_scope(), tvb, offset, len - 1, ENC_ASCII);
		route_password = proto_tree_add_item(route_hop_tree, hf_saprouter_route_string_password, tvb, offset, len, ENC_ASCII|ENC_NA);

		/* If a password was found, add a expert warning in the security category */
		if (len > 1){
			expert_add_info(pinfo, route_password, &ei_saprouter_route_password_found);

			/* Add the password to the credential tap */
			tap_credential_t *auth =  wmem_new0(pinfo->pool, tap_credential_t);
			auth->num = pinfo->num;
			auth->password_hf_id = hf_saprouter_route_string_password;
			auth->proto = "SAP Router Route String password";
			auth->username = wmem_strdup(pinfo->pool, TAP_CREDENTIALS_PLACEHOLDER);
			tap_queue_packet(credentials_tap, pinfo, auth);
		}
		offset += len;

		/* Adjust the size of the route hop item now that we know the size */
		proto_item_set_len(route_hop, offset - route_offset);

		/* Get the service port in numeric format */
		int_port = dissect_serviceport(port);

		/* Add the first hostname/port as source in the conversation state*/
		if ((hop==1) && !(pinfo->fd->visited)){
			session_state->src_hostname = hostname;
			session_state->src_port = int_port;
			session_state->src_password = password;
		}
		hop++;
	}

	if (!(pinfo->fd->visited)) {
		/* Add the last hostname/port as destination */
		if (hop!=1){
			session_state->dest_hostname = hostname;
			session_state->dest_port = int_port;
			session_state->dest_password = password;
		}
		/* Save the status of the conversation state */
		session_state->route_information = true;
		session_state->route_accepted = false;
	}

}

static void
dissect_errorstring(tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
	uint32_t len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_eyecatcher, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_counter, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_error, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_return_code, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_component, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_release, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_version, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_module, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_line, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_detail, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_time, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_system_call, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_errorno, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_errorno_text, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_error_count, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_location, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA);
	offset += len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_eyecatcher, tvb, offset, len, ENC_ASCII|ENC_NA);
}


static tvbuff_t*
dissect_saprouter_snc_frame(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, uint32_t offset _U_){

	/* Call the SNC dissector */
	if (global_saprouter_snc_dissection == true){
		return dissect_sapsnc_frame(tvb, pinfo, tree, offset);
	}

	return NULL;
}


static int
dissect_saprouter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	tvbuff_t *next_tvb = NULL;
	uint8_t opcode;
	uint32_t offset = 0, eyecatcher_length = 0;
	conversation_t *conversation = NULL;
	saprouter_session_state *session_state = NULL;
	proto_item *ti = NULL, *ri = NULL, *ei = NULL, *ci = NULL, *gi = NULL, *admin_password = NULL;
	proto_tree *saprouter_tree = NULL, *route_tree = NULL, *text_tree = NULL, *clients_tree = NULL;

	/* Search for a conversation */
	conversation = find_or_create_conversation(pinfo);
	session_state = (saprouter_session_state *)conversation_get_proto_data(conversation, proto_saprouter);
	if (!session_state){
		session_state = wmem_new(wmem_file_scope(), saprouter_session_state);
		if (session_state){
			session_state->route_information = false;
			session_state->route_requested_in = 0;
			session_state->route_accepted = false;
			session_state->route_accepted_in = 0;
			session_state->route_snc_protected = false;
			session_state->src_hostname = NULL;
			session_state->src_port = 0;
			session_state->src_password = NULL;
			session_state->dest_hostname = NULL;
			session_state->dest_port = 0;
			session_state->dest_password = NULL;
			conversation_add_proto_data(conversation, proto_saprouter, session_state);
		} else {
			/* Unable to establish a conversation, break dissection of the packet */
			return 0;
		}
	}

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPROUTER");

	/* Add the main SAP Router subtree */
	ti = proto_tree_add_item(tree, proto_saprouter, tvb, offset, -1, ENC_NA);
	saprouter_tree = proto_item_add_subtree(ti, ett_saprouter);

	/* Get the 'eye catcher' length */
	eyecatcher_length = tvb_strsize(tvb, offset);

	/* Niping message */
	if (tvb_reported_length_remaining(tvb, offset) >= 10 && tvb_strneql(tvb, offset, SAPROUTER_TYPE_NIPING_STRING, 10) == 0) {
		col_set_str(pinfo->cinfo, COL_INFO, "Niping message");

		proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, offset, 10, ENC_ASCII|ENC_NA);
		offset += 10;
		proto_item_append_text(ti, ", Niping message");

		if (tvb_reported_length_remaining(tvb, offset)) {
			proto_tree_add_item(saprouter_tree, hf_saprouter_niping_message, tvb, offset, -1, ENC_NA);
		}

	}
	/* Admin Message Type */
	else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ADMIN_STRING, eyecatcher_length) == 0) {
		col_set_str(pinfo->cinfo, COL_INFO, "Admin message");

		proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, offset, eyecatcher_length, ENC_ASCII|ENC_NA);
		offset += eyecatcher_length;
		proto_item_append_text(ti, ", Admin message");

		proto_tree_add_item(saprouter_tree, hf_saprouter_ni_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		opcode = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(saprouter_tree, hf_saprouter_admin_command, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		switch (opcode){
			case 2:{  /* Info request */
				offset+=2; /* Skip 2 bytes */
				/* Check if a password was supplied */
				if (tvb_offset_exists(tvb, offset) && (tvb_strsize(tvb, offset) > 0)){
					admin_password = proto_tree_add_item(saprouter_tree, hf_saprouter_admin_password, tvb, offset, tvb_strsize(tvb, offset), ENC_ASCII|ENC_NA);
					expert_add_info(pinfo, admin_password, &ei_saprouter_info_password_found);

					/* Add the password to the credential tap */
					tap_credential_t *auth =  wmem_new0(pinfo->pool, tap_credential_t);
					auth->num = pinfo->num;
					auth->password_hf_id = hf_saprouter_admin_password;
					auth->proto = "SAP Router Info Request password";
					auth->username = wmem_strdup(pinfo->pool, TAP_CREDENTIALS_PLACEHOLDER);
					tap_queue_packet(credentials_tap, pinfo, auth);
				}
				break;
			}
			case 10:  /* Set Peer Trace */
			case 11:{ /* Clear Peer Trace */
				proto_tree_add_item(saprouter_tree, hf_saprouter_admin_address_mask, tvb, offset, 32, ENC_ASCII|ENC_NA);
				break;
			}
			case 6:  /* Cancel Route request */
			case 12: /* Trace Connection */
			case 13: /* Trace Connection */
			{
				uint16_t client_count = 0, client_count_actual = 0;

				/* Retrieve the client count first */
				if (opcode == 6){
					offset+=2; /* Skip 2 bytes for Cancel Route request*/
					client_count = tvb_get_ntohs(tvb, offset);
					proto_tree_add_item(saprouter_tree, hf_saprouter_admin_client_count_short, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset+=2;
				} else {
					client_count = tvb_get_ntohl(tvb, offset);
					proto_tree_add_item(saprouter_tree, hf_saprouter_admin_client_count_int, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset+=4;
				}

				/* Parse the list of client IDs */
				ci = proto_tree_add_item(saprouter_tree, hf_saprouter_admin_client_ids, tvb, offset, 4*client_count, ENC_NA);
				clients_tree = proto_item_add_subtree(ci, ett_saprouter);
				while (tvb_offset_exists(tvb, offset) && tvb_reported_length_remaining(tvb, offset)>=4){
					proto_tree_add_item(clients_tree, hf_saprouter_admin_client_id, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset+=4;
					client_count_actual+=1;
				}

				/* Check if the actual count of IDs differes from the reported number */
				if ((client_count_actual != client_count) || tvb_reported_length_remaining(tvb, offset)>0){
					expert_add_info(pinfo, clients_tree, &ei_saprouter_invalid_client_ids);
				}

				break;
			}
			default: {
				/* Skip 2 bytes */
				break;
			}
		}

	/* Route Message Type */
	} else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ROUTE_STRING, eyecatcher_length) == 0){
		uint32_t route_length = 0, route_offset = 0;

		col_set_str(pinfo->cinfo, COL_INFO, "Route message");

		/* Get the route length/offset */
		route_length = tvb_get_ntohl(tvb, offset + SAPROUTER_ROUTE_LENGTH_OFFSET);
		route_offset = offset + SAPROUTER_ROUTE_OFFSET_OFFSET + 4;

		proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, 0, eyecatcher_length, ENC_ASCII|ENC_NA);
		offset += eyecatcher_length;
		proto_item_append_text(ti, ", Route message");
		/* Add the fields */
		proto_tree_add_item(saprouter_tree, hf_saprouter_route_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(saprouter_tree, hf_saprouter_ni_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(saprouter_tree, hf_saprouter_entries, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(saprouter_tree, hf_saprouter_talk_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=3; /* There're two unused bytes there */
		proto_tree_add_item(saprouter_tree, hf_saprouter_rest_nodes, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(saprouter_tree, hf_saprouter_route_length, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
		proto_tree_add_item(saprouter_tree, hf_saprouter_route_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
		/* Add the route tree */
		if ((uint32_t)tvb_reported_length_remaining(tvb, offset) != route_length){
			expert_add_info_format(pinfo, saprouter_tree, &ei_saprouter_route_invalid_length, "Route string length is invalid (remaining=%d, route_length=%d)", tvb_reported_length_remaining(tvb, offset), route_length);
			route_length = (uint32_t)tvb_reported_length_remaining(tvb, offset);
		}
		ri = proto_tree_add_item(saprouter_tree, hf_saprouter_route, tvb, offset, route_length, ENC_NA);
		route_tree = proto_item_add_subtree(ri, ett_saprouter);

		/* Dissect the route string */
		dissect_routestring(tvb, pinfo, route_tree, route_offset, session_state);

		/* If this is the first time we're seeing this packet, mark it as the one where the route was requested */
		if (!pinfo->fd->visited) {
			session_state->route_requested_in = pinfo->num;
		}

		/* Add the route to the colinfo*/
		if (session_state->src_hostname){
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Source: Hostname=%s Service Port=%d", session_state->src_hostname, session_state->src_port);
			if (strlen(session_state->src_password)>0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " Password=%s", session_state->src_password);
		}
		if (session_state->dest_hostname){
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Destination: Hostname=%s Service Port=%d", session_state->dest_hostname, session_state->dest_port);
			if (strlen(session_state->dest_password)>0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " Password=%s", session_state->dest_password);
		}

		if (session_state->route_accepted && session_state->route_accepted_in) {
			gi = proto_tree_add_uint(saprouter_tree, hf_saprouter_route_accepted_in, tvb, 0, 0, session_state->route_accepted_in);
			proto_item_set_generated(gi);
		}

	/* Error Information/Control Message Type */
	} else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ERR_STRING, eyecatcher_length) == 0){

		/* Extract the opcode if possible to determine the type of message */
		if (tvb_offset_exists(tvb, offset + 10)) {
			opcode = tvb_get_uint8(tvb, offset + 10);
		} else {
			opcode = 0;
		}

		col_set_str(pinfo->cinfo, COL_INFO, (opcode==0)? "Error information" : "Control message");

		uint32_t text_length = 0;

		proto_item_append_text(ti, (opcode==0)? ", Error information" : ", Control message");
		/* Add the fields */
		proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, offset, eyecatcher_length, ENC_ASCII|ENC_NA);
		offset += eyecatcher_length;
		proto_tree_add_item(saprouter_tree, hf_saprouter_ni_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(saprouter_tree, hf_saprouter_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=2; /* There's a unused byte there */
		proto_tree_add_item(saprouter_tree, hf_saprouter_return_code, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		text_length = tvb_get_ntohl(tvb, offset);
		/* Error Information Message */
		if (opcode == 0){
			proto_tree_add_item(saprouter_tree, hf_saprouter_error_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			if ((text_length > 0) && tvb_offset_exists(tvb, offset+text_length)){
				/* Add the error string tree */
				ei = proto_tree_add_item(saprouter_tree, hf_saprouter_error_string, tvb, offset, text_length, ENC_NA);
				text_tree = proto_item_add_subtree(ei, ett_saprouter);
				dissect_errorstring(tvb, text_tree, offset);
				offset += text_length;
			}

			/* Add an unknown int field */
			proto_tree_add_item(saprouter_tree, hf_saprouter_unknown, tvb, offset, 4, ENC_BIG_ENDIAN);

		/* Control Message */
		} else {
			/* Add the opcode name */
		        proto_item_append_text(ti, ", opcode=%s", val_to_str_const(opcode, saprouter_opcode_vals, "Unknown"));
			col_append_fstr(pinfo->cinfo, COL_INFO, ", opcode=%s", val_to_str_const(opcode, saprouter_opcode_vals, "Unknown"));

			proto_tree_add_item(saprouter_tree, hf_saprouter_control_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			if ((text_length >0) && tvb_offset_exists(tvb, offset+text_length)){
				/* Add the control string tree */
				proto_tree_add_item(saprouter_tree, hf_saprouter_control_string, tvb, offset, text_length, ENC_ASCII|ENC_NA);
				offset += text_length;
			}

			/* SNC request, mark the conversation as SNC protected and dissect the SNC frame */
			if (opcode == 70 || opcode == 71){
				session_state->route_snc_protected = true;
				dissect_saprouter_snc_frame(tvb, pinfo, tree, offset);

			/* Other opcodes */
			} else {
				proto_tree_add_item(saprouter_tree, hf_saprouter_control_unknown, tvb, offset, 4, ENC_ASCII|ENC_NA);
			}

		}

	/* Route Acceptance (NI_PONG) Message Type */
	} else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ROUTE_ACCEPT, eyecatcher_length) == 0){
		/* Route information available */
		if (session_state->route_information){
			/* If this is the first time we're seen the packet, mark is as the one where the route was accepted */
			if (!pinfo->fd->visited) {
				session_state->route_accepted = true;
				session_state->route_accepted_in = pinfo->num;
			}

			col_append_fstr(pinfo->cinfo, COL_INFO, ", from %s:%d to %s:%d", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);
			proto_item_append_text(ti, ", from %s:%d to %s:%d", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);

			if (session_state->route_requested_in) {
				gi = proto_tree_add_uint(saprouter_tree, hf_saprouter_route_requested_in, tvb, 0, 0, session_state->route_requested_in);
				proto_item_set_generated(gi);
			}
		}

	/* Unknown Message Type */
	} else {

		col_add_fstr(pinfo->cinfo, COL_INFO, "Routed message");
		proto_item_append_text(ti, ", Routed message");

		/* If the session is protected with SNC, first dissect the SNC frame
		 * and save the content for further dissection.
		 */
		if (session_state->route_snc_protected) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", SNC protected");
			proto_item_append_text(ti, ", SNC protected");
			next_tvb = dissect_saprouter_snc_frame(tvb, pinfo, tree, offset);

		/* If the session is not protected dissect the entire payload */
		} else {
			next_tvb = tvb;
		}

		/* If the session has information about the route requested */
		if (session_state->route_information){

			/* Route accepted */
			if (session_state->route_accepted){

				col_append_fstr(pinfo->cinfo, COL_INFO, ", from %s:%d to %s:%d ", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);
				proto_item_append_text(ti, ", from %s:%d to %s:%d ", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);

				if (session_state->route_requested_in) {
					gi = proto_tree_add_uint(saprouter_tree, hf_saprouter_route_requested_in, tvb, 0, 0, session_state->route_requested_in);
					proto_item_set_generated(gi);
				}
				if (session_state->route_accepted_in) {
					gi = proto_tree_add_uint(saprouter_tree, hf_saprouter_route_accepted_in, tvb, 0, 0, session_state->route_accepted_in);
					proto_item_set_generated(gi);
				}

			/* Route not accepted but some information available */
			} else {
				col_append_fstr(pinfo->cinfo, COL_INFO, ", to unknown destination");
				proto_item_append_text(ti, ", to unknown destination");
			}

			/* Call the dissector in the NI protocol sub-dissectors table
			 * according to the route destination port number. */
			if (next_tvb) {
				dissect_sap_protocol_payload(next_tvb, offset, pinfo, tree, 0, session_state->dest_port);
			}

		} else {
			/* No route information available */
			col_append_fstr(pinfo->cinfo, COL_INFO, ", to unknown destination");
			proto_item_append_text(ti, ", to unknown destination");
		}
	}

	return tvb_reported_length(tvb);
}

void
proto_register_saprouter(void)
{
	static hf_register_info hf[] = {
		{ &hf_saprouter_type,
			{ "Type", "saprouter.type", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Niping message */
		{ &hf_saprouter_niping_message,
			{ "Niping message", "saprouter.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* NI Route messages */
		{ &hf_saprouter_route_version,
			{ "Route version", "saprouter.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_ni_version,
			{ "NI version", "saprouter.niversion", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_entries,
			{ "Entries", "saprouter.entries", FT_UINT8, BASE_DEC, NULL, 0x0, "Total number of entries", HFILL }},
		{ &hf_saprouter_talk_mode,
			{ "Talk Mode", "saprouter.talkmode", FT_UINT8, BASE_DEC, VALS(saprouter_talk_mode_vals), 0x0, NULL, HFILL }},
		{ &hf_saprouter_rest_nodes,
			{ "Remaining Hops", "saprouter.restnodes", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route_length,
			{ "Route String Length", "saprouter.routelength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route_offset,
			{ "Route String Offset", "saprouter.routeoffset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route,
			{ "Route String", "saprouter.routestring", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route_string,
			{ "Route Hop", "saprouter.routestring", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route_string_hostname,
			{ "Hostname", "saprouter.routestring.hostname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route_string_service,
			{ "Service", "saprouter.routestring.service", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_route_string_password,
			{ "Password", "saprouter.routestring.password", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_saprouter_route_requested_in,
			{ "Route Requested in", "saprouter.requested_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "The route request for this packet is in this packet", HFILL }},
		{ &hf_saprouter_route_accepted_in,
			{ "Route Accepted in", "saprouter.accepted_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "The route for this packet was accepted in this packet", HFILL }},

		/* NI error information / Control messages */
		{ &hf_saprouter_opcode,
			{ "Operation Code", "saprouter.opcode", FT_UINT8, BASE_DEC, VALS(saprouter_opcode_vals), 0x0, NULL, HFILL }},
		{ &hf_saprouter_return_code,
			{ "Return Code", "saprouter.returncode", FT_INT32, BASE_DEC, VALS(saprouter_return_code_vals), 0x0, NULL, HFILL }},
		{ &hf_saprouter_unknown,
			{ "Unknown field", "saprouter.unknown", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		/* NI Error Information messages */
		{ &hf_saprouter_error_length,
			{ "Error Information Text Length", "saprouter.errorlength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_string,
			{ "Error Information Text", "saprouter.errortext", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_eyecatcher,
			{ "Eyecatcher", "saprouter.errortext.eyecatcher", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_counter,
			{ "Counter", "saprouter.errortext.counter", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_error,
			{ "Error", "saprouter.errortext.error", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_return_code,
			{ "Return code", "saprouter.errortext.returncode", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_component,
			{ "Component", "saprouter.errortext.component", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_release,
			{ "Release", "saprouter.errortext.release", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_version,
			{ "Version", "saprouter.errortext.version", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_module,
			{ "Module", "saprouter.errortext.module", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_line,
			{ "Line", "saprouter.errortext.line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_detail,
			{ "Detail", "saprouter.errortext.detail", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_time,
			{ "Time", "saprouter.errortext.time", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_system_call,
			{ "System Call", "saprouter.errortext.system_call", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_errorno,
			{ "Error Number", "saprouter.errortext.errorno", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_errorno_text,
			{ "Error Number Text", "saprouter.errortext.errorno_text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_location,
			{ "Location", "saprouter.errortext.location", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_error_count,
			{ "Error Count", "saprouter.errortext.error_count", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_error_unknown,
			{ "Unknown field", "saprouter.errortext.unknown", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Control messages */
		{ &hf_saprouter_control_length,
			{ "Control Text Length", "saprouter.controllength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_control_string,
			{ "Control Text", "saprouter.controltext", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_control_unknown,
			{ "Control Unknown field", "saprouter.controlunknown", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Router Admin messages */
		{ &hf_saprouter_admin_command,
			{ "Admin Command", "saprouter.command", FT_UINT8, BASE_DEC, VALS(saprouter_admin_command_vals), 0x0, NULL, HFILL }},
		{ &hf_saprouter_admin_password,
			{ "Admin Command Info Password", "saprouter.password", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_admin_client_count_short,
			{ "Admin Command Client Count", "saprouter.client_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_admin_client_count_int,
			{ "Admin Command Client Count", "saprouter.client_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_admin_client_ids,
			{ "Admin Command Client IDs", "saprouter.client_ids", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_admin_client_id,
			{ "Admin Command Client ID", "saprouter.client_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_saprouter_admin_address_mask,
			{ "Admin Command Address Mask", "saprouter.address_mask", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_saprouter
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_saprouter_route_password_found, { "saprouter.routestring.password.found", PI_SECURITY, PI_WARN, "Route password found", EXPFILL }},
		{ &ei_saprouter_info_password_found, { "saprouter.password.found", PI_SECURITY, PI_WARN, "Info password found", EXPFILL }},
		{ &ei_saprouter_route_invalid_length, { "saprouter.routestring.routelength.invalid", PI_MALFORMED, PI_WARN, "The route string length is invalid", EXPFILL }},
		{ &ei_saprouter_invalid_client_ids, { "saprouter.client_ids.invalid", PI_MALFORMED, PI_WARN, "Client IDs list is malformed", EXPFILL }},
	};

	module_t *saprouter_module;
	expert_module_t* saprouter_expert;

	/* Register the protocol */
	proto_saprouter = proto_register_protocol("SAP Router Protocol", "SAPROUTER", "saprouter");

	proto_register_field_array(proto_saprouter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	saprouter_expert = expert_register_protocol(proto_saprouter);
	expert_register_field_array(saprouter_expert, ei, array_length(ei));

	register_dissector("saprouter", dissect_saprouter, proto_saprouter);

	/* Register the preferences */
	saprouter_module = prefs_register_protocol(proto_saprouter, proto_reg_handoff_saprouter);

	range_convert_str(wmem_epan_scope(), &global_saprouter_port_range, SAPROUTER_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(saprouter_module, "tcp_ports", "SAP Router Protocol TCP port numbers", "Port numbers used for SAP Router Protocol (default " SAPROUTER_PORT_RANGE ")", &global_saprouter_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(saprouter_module, "snc_dissection", "Dissect SAP SNC frames", "Whether the SAP Router Protocol dissector should call the SAP SNC dissector for SNC frames", &global_saprouter_snc_dissection);

	/* Register the tap*/
	credentials_tap = register_tap("credentials");

}


/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (uint32_t port, void *ptr _U_)
{
	dissector_delete_uint("sapni.port", port, saprouter_handle);
}

static void range_add_callback (uint32_t port, void *ptr _U_)
{
	dissector_add_uint("sapni.port", port, saprouter_handle);
}


/**
 * Register Hand off for the SAP Router Protocol
 */
void
proto_reg_handoff_saprouter(void)
{
	static bool initialized = false;
	static range_t *saprouter_port_range;

	if (!initialized) {
		saprouter_handle = create_dissector_handle(dissect_saprouter, proto_saprouter);
		initialized = true;
	} else {
		range_foreach(saprouter_port_range, range_delete_callback, NULL);
		wmem_free(wmem_epan_scope(), saprouter_port_range);
	}

	saprouter_port_range = range_copy(wmem_epan_scope(), global_saprouter_port_range);
	range_foreach(saprouter_port_range, range_add_callback, NULL);

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
