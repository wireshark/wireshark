/* packet-lat.c
 * Routines for the disassembly of DEC's LAT protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include "etypes.h"

void proto_register_lat(void);
void proto_reg_handoff_lat(void);

/*
 * Information on LAT taken from the LAT specification at
 *
 *	http://www.bitsavers.org/pdf/dec/ethernet/lat/AA-NL26A-TE_LAT_Specification_Jun89.pdf
 */

static dissector_handle_t lat_handle;

static int proto_lat = -1;
static int hf_lat_rrf = -1;
static int hf_lat_master = -1;
static int hf_lat_msg_typ = -1;
static int hf_lat_nbr_slots = -1;
static int hf_lat_dst_cir_id = -1;
static int hf_lat_src_cir_id = -1;
static int hf_lat_msg_seq_nbr = -1;
static int hf_lat_msg_ack_nbr = -1;
static int hf_lat_min_rcv_datagram_size = -1;
static int hf_lat_prtcl_ver = -1;
static int hf_lat_prtcl_eco = -1;
static int hf_lat_max_sim_slots = -1;
static int hf_lat_nbr_dl_bufs = -1;
static int hf_lat_server_circuit_timer = -1;
static int hf_lat_keep_alive_timer = -1;
static int hf_lat_facility_number = -1;
static int hf_lat_prod_type_code = -1;
static const value_string prod_type_code_vals[] = {
	{ 1, "Ethernet terminal server" },
	{ 2, "DECserver 100" },
	{ 3, "VAX/VMS" },
	{ 4, "RSX11-M" },
	{ 5, "RSX11-M+" },
	{ 6, "TOPS-20" },
	{ 7, "TOPS-10" },
	{ 8, "Ultrix-11" },
	{ 9, "LAT-11" },
	{ 10, "RSTS/E" },
	{ 11, "Ultrix-32" },
	{ 12, "ELN" },
	{ 13, "MS/DOS" },
	{ 14, "P/OS" },
	{ 15, "PCSG-LAT" },
	{ 16, "DELIX" },
	{ 17, "DECserver 200" },
	{ 18, "DECserver 500" },
	{ 19, "Actor" },
	{ 0, NULL }
};
static int hf_lat_prod_vers_numb = -1;
static int hf_lat_slave_node_name = -1;
static int hf_lat_master_node_name = -1;
static int hf_lat_location_text = -1;
static int hf_lat_param_code = -1;
static int hf_lat_param_len = -1;
static int hf_lat_param_data = -1;
static int hf_lat_slot_dst_slot_id = -1;
static int hf_lat_slot_src_slot_id = -1;
static int hf_lat_slot_byte_count = -1;
static int hf_lat_slot_credits = -1;
static int hf_lat_slot_type = -1;
static int hf_lat_start_slot_service_class = -1;
static int hf_lat_start_slot_minimum_attention_slot_size = -1;
static int hf_lat_start_slot_minimum_data_slot_size = -1;
static int hf_lat_start_slot_obj_srvc = -1;
static int hf_lat_start_slot_subj_dscr = -1;
static int hf_lat_start_slot_class_1_param_code = -1;
static int hf_lat_status_remaining = -1;
static int hf_lat_slot_data = -1;
static int hf_lat_data_b_slot_control_flags = -1;
static int hf_lat_data_b_slot_control_flags_enable_input_flow_control = -1;
static int hf_lat_data_b_slot_control_flags_disable_input_flow_control = -1;
static int hf_lat_data_b_slot_control_flags_enable_output_flow_control = -1;
static int hf_lat_data_b_slot_control_flags_disable_output_flow_control = -1;
static int hf_lat_data_b_slot_control_flags_break_detected = -1;
static int hf_lat_data_b_slot_control_flags_set_port_char = -1;
static int hf_lat_data_b_slot_control_flags_report_port_char = -1;
static int * const data_b_slot_control_flags_fields[] = {
	&hf_lat_data_b_slot_control_flags_enable_input_flow_control,
	&hf_lat_data_b_slot_control_flags_disable_input_flow_control,
	&hf_lat_data_b_slot_control_flags_enable_output_flow_control,
	&hf_lat_data_b_slot_control_flags_disable_output_flow_control,
	&hf_lat_data_b_slot_control_flags_break_detected,
	&hf_lat_data_b_slot_control_flags_set_port_char,
	&hf_lat_data_b_slot_control_flags_report_port_char,
	NULL
};
static int hf_lat_data_b_slot_stop_output_channel_char = -1;
static int hf_lat_data_b_slot_start_output_channel_char = -1;
static int hf_lat_data_b_slot_stop_input_channel_char = -1;
static int hf_lat_data_b_slot_start_input_channel_char = -1;
static int hf_lat_data_b_slot_param_code = -1;
static const value_string data_b_slot_param_code_vals[] = {
	{ 0, "End of parameters" },
	{ 1, "Parity and frame size" },
	{ 2, "Input speed" },
	{ 3, "Output speed" },
	{ 4, "Bell-on-discard preference" },
	{ 5, "Transparency mode" },
	{ 6, "Status" },
	{ 0, NULL }
};
static int hf_lat_slot_data_remaining = -1;
static int hf_lat_attention_slot_control_flags = -1;
static int hf_lat_attention_slot_control_flags_abort = -1;
static int * const attention_slot_control_flags_fields[] = {
	&hf_lat_attention_slot_control_flags_abort,
	NULL
};
static int hf_lat_mbz = -1;
static int hf_lat_reason = -1;
static int hf_lat_circuit_disconnect_reason = -1;
static int hf_lat_reason_text = -1;
static int hf_lat_high_prtcl_ver = -1;
static int hf_lat_low_prtcl_ver = -1;
static int hf_lat_cur_prtcl_ver = -1;
static int hf_lat_cur_prtcl_eco = -1;
static int hf_lat_msg_inc = -1;
static int hf_lat_change_flags = -1;
static int hf_lat_data_link_rcv_frame_size = -1;
static int hf_lat_node_multicast_timer = -1;
static int hf_lat_node_status = -1;
static int hf_lat_node_group_len = -1;
static int hf_lat_node_groups = -1;
static int hf_lat_node_name = -1;
static int hf_lat_node_description = -1;
static int hf_lat_service_name_count = -1;
static int hf_lat_service_rating = -1;
static int hf_lat_node_service_len = -1;
static int hf_lat_node_service_class = -1;

static int hf_lat_prtcl_format = -1;
static int hf_lat_request_identifier = -1;
static int hf_lat_entry_identifier = -1;
static int hf_lat_command_type = -1;
static const value_string command_type_vals[] = {
	{ 1, "Solicit non-queued access to the service" },
	{ 2, "Solicit queued access to the service" },
	{ 3, "Cancel entry in the queue" },
	{ 4, "Send status of the entry" },
	{ 5, "Send status of the queue" },
	{ 6, "Send status of multiple entries" },
	{ 0, NULL }
};
static int hf_lat_command_modifier = -1;
static int hf_lat_command_modifier_send_status_periodically = -1;
static int hf_lat_command_modifier_send_status_on_queue_depth_change = -1;
static int * const lat_command_modifier_fields[] = {
	&hf_lat_command_modifier_send_status_periodically,
	&hf_lat_command_modifier_send_status_on_queue_depth_change,
	NULL
};
static int hf_lat_obj_node_name = -1;
static int hf_lat_subj_group_len = -1;
static int hf_lat_subj_group = -1;
static int hf_lat_subj_node_name = -1;
static int hf_lat_subj_port_name = -1;
static int hf_lat_status_retransmit_timer = -1;
static int hf_lat_entries_counter = -1;
static int hf_lat_entry_length = -1;
static int hf_lat_entry_status = -1;
static int hf_lat_entry_status_rejected = -1;
static int hf_lat_entry_status_additional_information = -1;
static int * const lat_entry_status_fields[] = {
	&hf_lat_entry_status_rejected,
	&hf_lat_entry_status_additional_information,
	NULL
};
#define ENTRY_STATUS_REJECTED			0x80
#define ENTRY_STATUS_ADDITIONAL_INFORMATION	0x7F
static const value_string additional_information_vals[] = {
	{ 0, "No additional information is provided" },
	{ 1, "Request is already queued" },
	{ 2, "Entry is accepted for processing" },
	{ 3, "Periodic status return is not supported" },
	{ 4, "Queue-depth status report is not supported" },
	{ 0, NULL }
};
static int hf_lat_entry_error = -1;
static const value_string entry_error_vals[] = {
	{ 1, "reason is unknown" },
	{ 2, "user requested disconnect" },
	{ 3, "system shutdown in progress" },
	{ 4, "invalid slot received" },
	{ 5, "invalid service class" },
	{ 6, "insufficient resources to satisfy request" },
	{ 7, "service in use" },
	{ 8, "no such service" },
	{ 9, "service is disabled" },
	{ 10, "service is not offered by the requested port" },
	{ 11, "port name is unknown" },
	{ 12, "invalid password" },
	{ 13, "entry is not in the queue" },
	{ 14, "immediate access rejected" },
	{ 15, "access denied" },
	{ 16, "COMMAND_TYPE code is illegal/not supported" },
	{ 17, "Start slot can't be set" },
	{ 18, "Queue entry deleted by local node" },
	{ 19, "Inconsistent or illegal request parameters" },
	{ 0, NULL }
};
static int hf_lat_elapsed_queue_time = -1;
static int hf_lat_min_queue_position = -1;
static int hf_lat_max_queue_position = -1;
static int hf_lat_obj_srvc_name = -1;
static int hf_lat_obj_port_name = -1;
static int hf_lat_subj_description = -1;

static int hf_lat_solicit_identifier = -1;
static int hf_lat_response_timer = -1;
static int hf_lat_dst_node_name = -1;
static int hf_lat_src_node_group_len = -1;
static int hf_lat_src_node_groups = -1;
static int hf_lat_src_node_name = -1;
static int hf_lat_dst_srvc_name = -1;

static int hf_lat_response_status = -1;
static int hf_lat_response_status_node_does_not_offer_requested_service = -1;
static int * const lat_response_status_fields[] = {
	&hf_lat_response_status_node_does_not_offer_requested_service,
	NULL
};
static int hf_lat_src_node_status = -1;
static int hf_lat_src_node_status_node_is_disabled = -1;
static int hf_lat_src_node_status_start_message_can_be_sent = -1;
static int hf_lat_src_node_status_command_message_can_be_sent = -1;
static int * const lat_src_node_status_fields[] = {
	&hf_lat_src_node_status_node_is_disabled,
	&hf_lat_src_node_status_start_message_can_be_sent,
	&hf_lat_src_node_status_command_message_can_be_sent,
	NULL
};
static int hf_lat_source_node_addr = -1;
static int hf_lat_src_node_mc_timer = -1;
static int hf_lat_src_node_desc = -1;
static int hf_lat_srvc_count = -1;
static int hf_lat_srvc_entry_len = -1;
static int hf_lat_srvc_class_len = -1;
static int hf_lat_srvc_class = -1;
static int hf_lat_srvc_status = -1;
static int hf_lat_srvc_status_enabled = -1;
static int hf_lat_srvc_status_supports_queueing = -1;
static int * const lat_srvc_status_fields[] = {
	&hf_lat_srvc_status_enabled,
	&hf_lat_srvc_status_supports_queueing,
	NULL
};
static int hf_lat_srvc_rating = -1;
static int hf_lat_srvc_group_len = -1;
static int hf_lat_srvc_groups = -1;
static int hf_lat_srvc_name = -1;
static int hf_lat_srvc_desc = -1;

static int hf_lat_service_name = -1;
static int hf_lat_service_description = -1;
static int hf_lat_unknown_command_data = -1;

static gint ett_lat = -1;
static gint ett_data_b_slot_control_flags = -1;
static gint ett_lat_attention_slot_control_flags = -1;
static gint ett_lat_command_modifier = -1;
static gint ett_lat_entry_status = -1;
static gint ett_lat_response_status = -1;
static gint ett_lat_src_node_status = -1;
static gint ett_lat_srvc_status = -1;

static expert_field ei_slot_data_len_invalid = EI_INIT;
static expert_field ei_entry_length_too_short = EI_INIT;
static expert_field ei_srvc_entry_len_too_short = EI_INIT;
static expert_field ei_mbz_data_nonzero = EI_INIT;

/* LAT message types. */
#define LAT_MSG_TYP_RUN				0
#define LAT_MSG_TYP_START			1
#define LAT_MSG_TYP_STOP			2
#define LAT_MSG_TYP_SERVICE_ANNOUNCEMENT	10
#define LAT_MSG_TYP_COMMAND			12
#define LAT_MSG_TYP_STATUS			13
#define LAT_MSG_TYP_SOLICIT_INFORMATION		14
#define LAT_MSG_TYP_RESPONSE_INFORMATION	15

static const value_string msg_typ_vals[] = {
	{ LAT_MSG_TYP_RUN,                  "Run" },
	{ LAT_MSG_TYP_START,                "Start" },
	{ LAT_MSG_TYP_STOP,                 "Stop" },
	{ LAT_MSG_TYP_SERVICE_ANNOUNCEMENT, "Service announcement" },
	{ LAT_MSG_TYP_COMMAND,              "Command" },
	{ LAT_MSG_TYP_STATUS,               "Status" },
	{ LAT_MSG_TYP_SOLICIT_INFORMATION,  "Solicit information" },
	{ LAT_MSG_TYP_RESPONSE_INFORMATION, "Response information" },
	{ 0,                                NULL },
};

static void dissect_lat_run(tvbuff_t *tvb, int offset, proto_tree *tree,
    packet_info *pinfo);
static void dissect_lat_start(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_stop(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_service_announcement(tvbuff_t *tvb, int offset,
    proto_tree *tree);
static void dissect_lat_command(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_status(tvbuff_t *tvb, int offset, proto_tree *tree,
    packet_info *pinfo);
static void dissect_lat_solicit_information(tvbuff_t *tvb, int offset,
    proto_tree *tree);
static void dissect_lat_response_information(tvbuff_t *tvb, int offset,
    proto_tree *tree, packet_info *pinfo);

static int dissect_lat_string(tvbuff_t *tvb, int offset, int hf,
    proto_tree *tree);

static guint dissect_lat_header(tvbuff_t *tvb, int offset, proto_tree *tree);

static void dissect_lat_slots(tvbuff_t *tvb, int offset, guint nbr_slots,
    proto_tree *tree, packet_info *pinfo);

static int
dissect_lat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	proto_item *ti;
	proto_tree *lat_tree = NULL;
	guint8 command;

	col_add_str(pinfo->cinfo, COL_PROTOCOL, "LAT");
	col_clear(pinfo->cinfo, COL_INFO);

	command = tvb_get_guint8(tvb, offset) >> 2;

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
	    val_to_str(command, msg_typ_vals, "Unknown command (%u)"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_lat, tvb, offset, -1,
		    ENC_NA);
		lat_tree = proto_item_add_subtree(ti, ett_lat);

		/* First byte of LAT header */
		proto_tree_add_item(lat_tree, hf_lat_rrf, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN);
		proto_tree_add_item(lat_tree, hf_lat_master, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN);
		proto_tree_add_item(lat_tree, hf_lat_msg_typ, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN);
		offset += 1;

		switch (command) {

		case LAT_MSG_TYP_RUN:
			dissect_lat_run(tvb, offset, lat_tree, pinfo);
			break;

		case LAT_MSG_TYP_START:
			dissect_lat_start(tvb, offset, lat_tree);
			break;

		case LAT_MSG_TYP_STOP:
			dissect_lat_stop(tvb, offset, lat_tree);
			break;

		case LAT_MSG_TYP_SERVICE_ANNOUNCEMENT:
			dissect_lat_service_announcement(tvb, offset, lat_tree);
			break;

		case LAT_MSG_TYP_COMMAND:
			dissect_lat_command(tvb, offset, lat_tree);
			break;

		case LAT_MSG_TYP_STATUS:
			dissect_lat_status(tvb, offset, lat_tree, pinfo);
			break;

		case LAT_MSG_TYP_SOLICIT_INFORMATION:
			dissect_lat_solicit_information(tvb, offset, lat_tree);
			break;

		case LAT_MSG_TYP_RESPONSE_INFORMATION:
			dissect_lat_response_information(tvb, offset, lat_tree,
			    pinfo);
			break;

		default:
			proto_tree_add_item(lat_tree, hf_lat_unknown_command_data,
			    tvb, offset, -1, ENC_NA);
			break;
		}

	}
	return tvb_captured_length(tvb);
}

/*
 * Virtual circuit message header.
 */
static guint
dissect_lat_header(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32 nbr_slots;

	proto_tree_add_item_ret_uint(tree, hf_lat_nbr_slots, tvb, offset, 1,
	    ENC_LITTLE_ENDIAN, &nbr_slots);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_dst_cir_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_src_cir_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_msg_seq_nbr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_msg_ack_nbr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	/*offset += 1;*/

	return nbr_slots;
}

static void
dissect_lat_start(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 timer;
	guint32 param_code;
	guint32 param_len;

	dissect_lat_header(tvb, offset, tree);
	offset += 1 + 2 + 2 + 1 + 1;
	proto_tree_add_item(tree, hf_lat_min_rcv_datagram_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_lat_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_max_sim_slots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_nbr_dl_bufs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_lat_server_circuit_timer, tvb,
	    offset, 1, timer, "%u milliseconds", timer*10);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_keep_alive_timer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_facility_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(tree, hf_lat_prod_type_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_prod_vers_numb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	offset = dissect_lat_string(tvb, offset, hf_lat_slave_node_name, tree);
	offset = dissect_lat_string(tvb, offset, hf_lat_master_node_name, tree);
	offset = dissect_lat_string(tvb, offset, hf_lat_location_text, tree);
	for (;;) {
		proto_tree_add_item_ret_uint(tree, hf_lat_param_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
		offset += 1;
		if (param_code == 0)
			break;
		proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
		offset += 1;
		proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
		offset += param_len;
	}
}

static void
dissect_lat_run(tvbuff_t *tvb, int offset, proto_tree *tree,
    packet_info *pinfo)
{
	guint8 nbr_slots;

	nbr_slots = dissect_lat_header(tvb, offset, tree);
	offset += 1 + 2 + 2 + 1 + 1;
	dissect_lat_slots(tvb, offset, nbr_slots, tree, pinfo);
}

/*
 * Slot types.
 */
#define START_SLOT	9
#define DATA_A_SLOT	0
#define DATA_B_SLOT	10
#define ATTENTION_SLOT	11
#define REJECT_SLOT	12
#define STOP_SLOT	13

static const value_string slot_type_vals[] = {
	{ START_SLOT,     "Start" },
	{ DATA_A_SLOT,    "Data_a" },
	{ DATA_B_SLOT,    "Data_b" },
	{ ATTENTION_SLOT, "Attention" },
	{ REJECT_SLOT,    "Reject" },
	{ STOP_SLOT,      "Stop" },
	{ 0, NULL }
};

static const value_string reason_code_vals[] = {
	{ 1, "reason is unknown" },
	{ 2, "user requested disconnect" },
	{ 3, "system shutdown in progress" },
	{ 4, "invalid slot received" },
	{ 5, "invalid service class" },
	{ 6, "insufficient resources to satisfy request" },
	{ 7, "service in use" },
	{ 8, "no such service" },
	{ 9, "service is disabled" },
	{ 10, "service is not offered by the requested port" },
	{ 11, "port name is unknown" },
	{ 12, "invalid password" },
	{ 13, "entry is not in the queue" },
	{ 14, "immediate access rejected" },
	{ 15, "access denied" },
	{ 16, "corrupted solicit request" },
	{ 0, NULL }
};

static int
dissect_lat_channel_char(proto_tree *tree, int hf, tvbuff_t *tvb, int offset)
{
	guint8 character;

	character = tvb_get_guint8(tvb, offset);
	if (g_ascii_isprint(character)) {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 1,
		    character, "'%c'", character);
	} else if (character < 0x20) {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 1,
		    character, "^%c", character + 0x40);
	} else {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 1,
		    character, "0x%02x", character);
	}
	offset++;
	return offset;
}

#define CHECK_SLOT_DATA_BOUNDS(len) \
	if (slot_byte_count < (len)) { \
		expert_add_info(pinfo, length_ti, &ei_slot_data_len_invalid); \
		goto end_slot; \
	}

#define SERVICE_CLASS_TERMINAL	1

static const value_string service_class_vals[] = {
	{ 0, "Reserved" },
	{ SERVICE_CLASS_TERMINAL, "Application and interactive terminals" },
	{ 0, NULL }
};

static const value_string start_slot_class_1_param_code_vals[] = {
	{ 0, "End of parameters" },
	{ 1, "Flag word" },
	{ 2, "Identifier of the particular entry in the queue" },
	{ 3, "Reserved" },
	{ 4, "Destination node port name" },
	{ 5, "Source node port name" },
	{ 6, "Source service group codes" },
	{ 7, "Service password" },
	{ 0, NULL }
};

static int
dissect_lat_terminal_parameters(tvbuff_t *tvb, int offset,
    guint32 slot_byte_count, proto_item *length_ti, proto_tree *tree,
    packet_info *pinfo)
{
	guint32 param_code;
	guint32 param_len;
	int length_dissected = 0;

	for (;;) {
		CHECK_SLOT_DATA_BOUNDS(1);
		proto_tree_add_item_ret_uint(tree, hf_lat_start_slot_class_1_param_code,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
		offset += 1;
		slot_byte_count -= 1;
		length_dissected += 1;
		if (param_code == 0)
			break;

		CHECK_SLOT_DATA_BOUNDS(1);
		proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
		offset += 1;
		slot_byte_count -= 1;
		length_dissected += 1;

		/*
		 * XXX - dissect specific parameters as per A.6.1
		 * Start Slot Status Field
		 */
		CHECK_SLOT_DATA_BOUNDS(param_len);
		proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
		offset += param_len;
		slot_byte_count -= param_len;
		length_dissected += param_len;
	}

end_slot:
	return length_dissected;
}

static void
dissect_lat_slots(tvbuff_t *tvb, int offset, guint nbr_slots, proto_tree *tree,
    packet_info *pinfo)
{
	guint i;
	proto_item *length_ti;
	guint32 slot_byte_count;
	guint32 slot_type_byte;
	int slot_padding;
	guint32 start_slot_service_class;
	guint32 name_len;
	int length_dissected;
	guint32 param_code;
	guint32 param_len;
	guint32 mbz;
	proto_item *mbz_ti;

	for (i = 0; i < nbr_slots; i++) {
		proto_tree_add_item(tree, hf_lat_slot_dst_slot_id,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(tree, hf_lat_slot_src_slot_id,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		length_ti = proto_tree_add_item_ret_uint(tree, hf_lat_slot_byte_count, tvb,
		    offset, 1, ENC_LITTLE_ENDIAN, &slot_byte_count);
		offset += 1;
		slot_padding = slot_byte_count & 1;

		slot_type_byte = tvb_get_guint8(tvb, offset);
		switch (slot_type_byte >> 4) {

		case START_SLOT:
			proto_tree_add_item(tree, hf_lat_slot_credits, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tree, hf_lat_slot_type, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			proto_tree_add_item_ret_uint(tree, hf_lat_start_slot_service_class,
			    tvb, offset, 1, ENC_LITTLE_ENDIAN,
			    &start_slot_service_class);
			offset += 1;
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			proto_tree_add_item(tree, hf_lat_start_slot_minimum_attention_slot_size,
			    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			proto_tree_add_item(tree, hf_lat_start_slot_minimum_data_slot_size,
			    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			name_len = tvb_get_guint8(tvb, offset);
			CHECK_SLOT_DATA_BOUNDS(1 + name_len);
			proto_tree_add_item(tree, hf_lat_start_slot_obj_srvc,
			    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
			offset += 1 + name_len;
			slot_byte_count -= 1 + name_len;

			CHECK_SLOT_DATA_BOUNDS(1);
			name_len = tvb_get_guint8(tvb, offset);
			CHECK_SLOT_DATA_BOUNDS(1 + name_len);
			proto_tree_add_item(tree, hf_lat_start_slot_subj_dscr,
			    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
			offset += 1 + name_len;
			slot_byte_count -= 1 + name_len;

			if (slot_byte_count != 0) {
				switch (start_slot_service_class) {

				case SERVICE_CLASS_TERMINAL:
					length_dissected =
					    dissect_lat_terminal_parameters(tvb,
					        offset, slot_byte_count,
						length_ti, tree, pinfo);
					offset += length_dissected;
					slot_byte_count -= length_dissected;
					break;

				default:
					break;
				}

				if (slot_byte_count != 0) {
					proto_tree_add_item(tree, hf_lat_status_remaining,
					    tvb, offset, slot_byte_count, ENC_NA);
					offset += slot_byte_count;
				}
			}
			break;

		case DATA_A_SLOT:
			proto_tree_add_item(tree, hf_lat_slot_credits, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tree, hf_lat_slot_type, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			if (slot_byte_count != 0) {
				proto_tree_add_item(tree, hf_lat_slot_data,
				    tvb, offset, slot_byte_count, ENC_NA);
				offset += slot_byte_count;
			}
			break;

		case DATA_B_SLOT:
			proto_tree_add_item(tree, hf_lat_slot_credits, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tree, hf_lat_slot_type, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			if (slot_byte_count == 0)
				break;

			/*
			 * XXX - this is only for service class 1, and
			 * we don't know the service class here, but
			 * are there any other service classes used
			 * in practice?
			 */
			proto_tree_add_bitmask(tree, tvb, offset,
			    hf_lat_data_b_slot_control_flags,
			    ett_data_b_slot_control_flags,
			    data_b_slot_control_flags_fields,
			    ENC_LITTLE_ENDIAN);
			offset += 1;
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			offset = dissect_lat_channel_char(tree,
			    hf_lat_data_b_slot_stop_output_channel_char,
			    tvb, offset);
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			offset = dissect_lat_channel_char(tree,
			    hf_lat_data_b_slot_start_output_channel_char,
			    tvb, offset);
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			offset = dissect_lat_channel_char(tree,
			    hf_lat_data_b_slot_stop_input_channel_char,
			    tvb, offset);
			slot_byte_count -= 1;

			CHECK_SLOT_DATA_BOUNDS(1);
			offset = dissect_lat_channel_char(tree,
			    hf_lat_data_b_slot_start_input_channel_char,
			    tvb, offset);
			slot_byte_count -= 1;

			for (;;) {
				CHECK_SLOT_DATA_BOUNDS(1);
				proto_tree_add_item_ret_uint(tree,
				    hf_lat_data_b_slot_param_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
				offset += 1;
				slot_byte_count -= 1;
				if (param_code == 0)
					break;

				CHECK_SLOT_DATA_BOUNDS(1);
				proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
				offset += 1;
				slot_byte_count -= 1;

				CHECK_SLOT_DATA_BOUNDS(param_len);
				proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
				offset += param_len;
				slot_byte_count -= param_len;
			}

			if (slot_byte_count != 0) {
				proto_tree_add_item(tree, hf_lat_slot_data_remaining,
				    tvb, offset, slot_byte_count, ENC_NA);
				offset += slot_byte_count;
			}
			break;

		case ATTENTION_SLOT:
			mbz_ti = proto_tree_add_item_ret_uint(tree, hf_lat_mbz, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN, &mbz);
			if (mbz != 0) {
				expert_add_info(pinfo, mbz_ti,
				    &ei_mbz_data_nonzero);
			}
			proto_tree_add_item(tree, hf_lat_slot_type, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			/*
			 * XXX - this is only for service class 1, and
			 * we don't know the service class here, but
			 * are there any other service classes used
			 * in practice?
			 */
			if (slot_byte_count >= 1) {
				proto_tree_add_bitmask(tree, tvb, offset,
				    hf_lat_attention_slot_control_flags,
				    ett_lat_attention_slot_control_flags,
				    attention_slot_control_flags_fields,
				    ENC_LITTLE_ENDIAN);
				offset += 1;
				slot_byte_count -= 1;
			}

			if (slot_byte_count != 0) {
				proto_tree_add_item(tree, hf_lat_slot_data_remaining,
				    tvb, offset, slot_byte_count, ENC_NA);
				offset += slot_byte_count;
			}
			break;

		case REJECT_SLOT:
		case STOP_SLOT:
			proto_tree_add_item(tree, hf_lat_reason, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tree, hf_lat_slot_type, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			if (slot_byte_count != 0) {
				proto_tree_add_item(tree, hf_lat_slot_data,
				    tvb, offset, slot_byte_count, ENC_NA);
				offset += slot_byte_count;
			}
			break;

		default:
			proto_tree_add_item(tree, hf_lat_slot_type, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			if (slot_byte_count != 0) {
				proto_tree_add_item(tree, hf_lat_slot_data,
				    tvb, offset, slot_byte_count, ENC_NA);
				offset += slot_byte_count;
			}
			break;
		}

	end_slot:
		/* Padding */
		offset += slot_padding;
	}
}

static const value_string circuit_disconnect_reason_code_vals[] = {
	{ 1, "reason is unknown" },
	{ 2, "No slots connected on virtual circuit" },
	{ 3, "Illegal message or slot format received" },
	{ 4, "VC_halt from user" },
	{ 5, "No progress is being made" },
	{ 6, "Time limit expired" },
	{ 7, "LAT_MESSAGE_RETRANSMIT_LIMIT reached" },
	{ 8, "Insufficient resources to satisfy request" },
	{ 9, "SERVER_CIRCUIT_TIMER out of desired range" },
	{ 10, "Number of virtual circuits is exceeded" },
	{ 0, NULL }
};

static void
dissect_lat_stop(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	dissect_lat_header(tvb, offset, tree);
	offset += 1 + 2 + 2 + 1 + 1;

	proto_tree_add_item(tree, hf_lat_circuit_disconnect_reason, tvb,
	    offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_lat_reason_text, tvb, offset, 1,
	    ENC_ASCII|ENC_LITTLE_ENDIAN);
}

static const value_string node_status_vals[] = {
	{ 2, "Accepting connections" },
	{ 3, "Not accepting connections" },
	{ 0, NULL },
};

static void
dissect_lat_service_announcement(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 timer;
	guint32 node_group_len;
	guint32 service_name_count;
	guint32 node_service_len;
	guint i;

	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_lat_server_circuit_timer, tvb,
	    offset, 1, timer, "%u milliseconds", timer*10);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_high_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_low_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_msg_inc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_change_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_data_link_rcv_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(tree, hf_lat_node_multicast_timer, tvb,
	    offset, 1, timer, "Multicast timer: %u seconds", timer);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_node_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item_ret_uint(tree, hf_lat_node_group_len,
	    tvb, offset, 1, ENC_LITTLE_ENDIAN, &node_group_len);
	offset += 1;

	/* This is a bitmask */
	proto_tree_add_item(tree, hf_lat_node_groups, tvb, offset, node_group_len, ENC_NA);
	offset += node_group_len;

	offset = dissect_lat_string(tvb, offset, hf_lat_node_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_node_description, tree);

	proto_tree_add_item_ret_uint(tree, hf_lat_service_name_count,
	    tvb, offset, 1, ENC_LITTLE_ENDIAN, &service_name_count);
	offset += 1;

	for (i = 0; i < service_name_count; i++) {
		proto_tree_add_item(tree, hf_lat_service_rating, tvb,
		    offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		offset = dissect_lat_string(tvb, offset, hf_lat_service_name,
		    tree);
		offset = dissect_lat_string(tvb, offset, hf_lat_service_description,
		    tree);
	}

	proto_tree_add_item_ret_uint(tree, hf_lat_node_service_len,
	    tvb, offset, 1, ENC_LITTLE_ENDIAN, &node_service_len);
	offset += 1;

	for (i = 0; i < node_service_len; i++) {
		proto_tree_add_item(tree, hf_lat_node_service_class,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
}

static void
dissect_lat_command(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32 subj_group_len;
	guint32 param_code;
	guint32 param_len;

	proto_tree_add_item(tree, hf_lat_prtcl_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_high_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_low_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_data_link_rcv_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_request_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_entry_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_command_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lat_command_modifier,
	    ett_lat_command_modifier, lat_command_modifier_fields,
	    ENC_LITTLE_ENDIAN);
	offset += 1;

	offset = dissect_lat_string(tvb, offset, hf_lat_obj_node_name, tree);

	proto_tree_add_item_ret_uint(tree, hf_lat_subj_group_len,
	    tvb, offset, 1, ENC_LITTLE_ENDIAN, &subj_group_len);
	offset += 1;

	/* This is a bitmask */
	proto_tree_add_item(tree, hf_lat_subj_group, tvb, offset, subj_group_len, ENC_NA);
	offset += subj_group_len;

	offset = dissect_lat_string(tvb, offset, hf_lat_subj_node_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_subj_port_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_subj_description, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_obj_srvc_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_obj_port_name, tree);

	for (;;) {
		proto_tree_add_item_ret_uint(tree, hf_lat_param_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
		offset += 1;
		if (param_code == 0)
			break;
		proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
		offset += 1;
		proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
		offset += param_len;
	}
}

static void
dissect_lat_status(tvbuff_t *tvb, int offset, proto_tree *tree,
    packet_info *pinfo)
{
	guint32 entries_counter;
	guint32 subj_node_name_len;
	guint i;

	proto_tree_add_item(tree, hf_lat_prtcl_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_high_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_low_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_data_link_rcv_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_status_retransmit_timer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item_ret_uint(tree, hf_lat_entries_counter, tvb, offset, 1,
	    ENC_LITTLE_ENDIAN, &entries_counter);
	offset += 1;

	proto_tree_add_item_ret_length(tree, hf_lat_subj_node_name, tvb, offset, 1,
	    ENC_LITTLE_ENDIAN, &subj_node_name_len);
	offset += subj_node_name_len;
	if (!(subj_node_name_len & 0x01)) {
		/*
		 * This length includes the length of the length field,
		 * which is 1 byte; if it's *even*, we need to pad.
		 */
		offset++;
	}

	for (i = 0; i < entries_counter; i++) {
		proto_item *entry_length_ti;
		guint32 entry_length;
		guint entry_padding;
		guint64 entry_status;
		proto_item *mbz_ti;
		guint32 mbz;
		guint name_len;

		entry_length_ti = proto_tree_add_item_ret_uint(tree, hf_lat_entry_length, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN, &entry_length);
		offset += 1;
		entry_padding = (entry_length + 1) & 1;

		if (entry_length == 0) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_lat_entry_status,
		    ett_lat_entry_status, lat_entry_status_fields,
		    ENC_LITTLE_ENDIAN, &entry_status);
		offset += 1;
		entry_length -= 1;

		if (entry_length == 0) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		if (entry_status & ENTRY_STATUS_REJECTED) {
			proto_tree_add_item(tree, hf_lat_entry_error, tvb, offset, 1,
			    ENC_LITTLE_ENDIAN);
		} else {
			/* No status, must be zero */
			mbz_ti = proto_tree_add_item_ret_uint(tree, hf_lat_mbz, tvb, offset, 1,
			    ENC_LITTLE_ENDIAN, &mbz);
			if (mbz != 0)
				expert_add_info(pinfo, mbz_ti, &ei_entry_length_too_short);
		}
		offset += 1;
		entry_length -= 1;

		if (entry_length == 0) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		/* Reserved, MBZ - do MBZ checks */
		offset += 1;
		entry_length -= 1;

		if (entry_length < 2) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_request_identifier, tvb, offset, 2,
		    ENC_LITTLE_ENDIAN);
		offset += 2;
		entry_length -= 2;

		if (entry_length < 2) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_entry_identifier, tvb, offset, 2,
		    ENC_LITTLE_ENDIAN);
		offset += 2;
		entry_length -= 2;

		if (entry_length < 2) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_elapsed_queue_time, tvb, offset, 2,
		    ENC_LITTLE_ENDIAN);
		offset += 2;
		entry_length -= 2;

		if (entry_length < 2) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_min_queue_position, tvb, offset, 2,
		    ENC_LITTLE_ENDIAN);
		offset += 2;
		entry_length -= 2;

		if (entry_length < 2) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_max_queue_position, tvb, offset, 2,
		    ENC_LITTLE_ENDIAN);
		offset += 2;
		entry_length -= 2;

		if (entry_length == 0) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		name_len = tvb_get_guint8(tvb, offset);
		if (entry_length < 1 + name_len) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			offset += entry_length;
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_obj_srvc_name,
		    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
		offset += 1 + name_len;
		entry_length -= 1 + name_len;

		if (entry_length == 0) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		name_len = tvb_get_guint8(tvb, offset);
		if (entry_length < 1 + name_len) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			offset += entry_length;
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_obj_port_name,
		    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
		offset += 1 + name_len;
		entry_length -= 1 + name_len;

		if (entry_length == 0) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			goto end_entry;
		}
		name_len = tvb_get_guint8(tvb, offset);
		if (entry_length < 1 + name_len) {
			expert_add_info(pinfo, entry_length_ti, &ei_entry_length_too_short);
			offset += entry_length;
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_subj_description,
		    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
		offset += 1 + name_len;
		entry_length -= 1 + name_len;

	end_entry:
		/* Padding */
		offset += entry_padding;
	}
	for (;;) {
		guint32 param_code;
		guint32 param_len;

		proto_tree_add_item_ret_uint(tree, hf_lat_param_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
		offset += 1;
		if (param_code == 0)
			break;
		proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
		offset += 1;
		proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
		offset += param_len;
	}
}

static void
dissect_lat_solicit_information(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32 src_node_group_len;

	proto_tree_add_item(tree, hf_lat_prtcl_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_high_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_low_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_data_link_rcv_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_solicit_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_response_timer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	offset = dissect_lat_string(tvb, offset, hf_lat_dst_node_name, tree);

	proto_tree_add_item_ret_uint(tree, hf_lat_src_node_group_len, tvb, offset, 1,
	    ENC_LITTLE_ENDIAN, &src_node_group_len);
	offset += 1;

	/* This is a bitmask */
	proto_tree_add_item(tree, hf_lat_src_node_groups, tvb, offset, src_node_group_len, ENC_NA);
	offset += src_node_group_len;

	offset = dissect_lat_string(tvb, offset, hf_lat_src_node_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_dst_srvc_name, tree);

	for (;;) {
		guint32 param_code;
		guint32 param_len;

		proto_tree_add_item_ret_uint(tree, hf_lat_param_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
		offset += 1;
		if (param_code == 0)
			break;
		proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
		offset += 1;
		proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
		offset += param_len;
	}
}

static void
dissect_lat_response_information(tvbuff_t *tvb, int offset, proto_tree *tree,
    packet_info *pinfo)
{
	guint32 srvc_count;
	guint32 src_node_group_len;
	guint i;

	proto_tree_add_item(tree, hf_lat_prtcl_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_high_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_low_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_data_link_rcv_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_solicit_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lat_response_status,
	    ett_lat_response_status, lat_response_status_fields,
	    ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lat_src_node_status,
	    ett_lat_src_node_status, lat_src_node_status_fields,
	    ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_source_node_addr, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(tree, hf_lat_src_node_mc_timer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	offset = dissect_lat_string(tvb, offset, hf_lat_dst_node_name, tree);

	proto_tree_add_item_ret_uint(tree, hf_lat_src_node_group_len, tvb, offset, 1,
	    ENC_LITTLE_ENDIAN, &src_node_group_len);
	offset += 1;

	/* This is a bitmask */
	proto_tree_add_item(tree, hf_lat_src_node_groups, tvb, offset, src_node_group_len, ENC_NA);
	offset += src_node_group_len;

	offset = dissect_lat_string(tvb, offset, hf_lat_src_node_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_src_node_desc, tree);

	proto_tree_add_item_ret_uint(tree, hf_lat_srvc_count, tvb, offset, 1,
	    ENC_LITTLE_ENDIAN, &srvc_count);

	for (i = 0; i < srvc_count; i++) {
		proto_item *srvc_entry_len_ti;
		guint32 srvc_entry_len;
		guint32 srvc_class_len;
		guint j;
		guint32 srvc_group_len;
		guint string_len;

		srvc_entry_len_ti = proto_tree_add_item_ret_uint(tree, hf_lat_srvc_entry_len,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN, &srvc_entry_len);
		offset += 1;

		if (srvc_entry_len == 0) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		proto_tree_add_item_ret_uint(tree, hf_lat_srvc_class_len,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN, &srvc_class_len);
		offset += 1;
		srvc_entry_len -= 1;

		for (j = 0; j < srvc_class_len; j++) {
			if (srvc_entry_len == 0) {
				expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
				goto end_entry;
			}
			proto_tree_add_item(tree, hf_lat_srvc_class,
			    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
			srvc_entry_len -= 1;
		}

		if (srvc_entry_len == 0) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		proto_tree_add_bitmask(tree, tvb, offset, hf_lat_srvc_status,
		    ett_lat_srvc_status, lat_srvc_status_fields,
		    ENC_LITTLE_ENDIAN);
		offset += 1;
		srvc_entry_len -= 1;

		if (srvc_entry_len == 0) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_srvc_rating,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		srvc_entry_len -= 1;

		if (srvc_entry_len == 0) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		proto_tree_add_item_ret_uint(tree, hf_lat_srvc_group_len,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN, &srvc_group_len);
		offset += 1;
		srvc_entry_len -= 1;

		/* This is a bitmask */
		if (srvc_entry_len < srvc_group_len) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_srvc_groups, tvb, offset, srvc_group_len, ENC_NA);
		offset += srvc_group_len;
		srvc_entry_len -= srvc_group_len;

		if (srvc_entry_len == 0) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		string_len = tvb_get_guint8(tvb, offset);
		if (srvc_entry_len < 1 + string_len) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			offset += srvc_entry_len;
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_srvc_name,
		    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
		offset += 1 + string_len;
		srvc_entry_len -= 1 + string_len;

		if (srvc_entry_len == 0) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			goto end_entry;
		}
		string_len = tvb_get_guint8(tvb, offset);
		if (srvc_entry_len < 1 + string_len) {
			expert_add_info(pinfo, srvc_entry_len_ti, &ei_srvc_entry_len_too_short);
			offset += srvc_entry_len;
			goto end_entry;
		}
		proto_tree_add_item(tree, hf_lat_srvc_desc,
		    tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN);
		offset += 1 + string_len;
		srvc_entry_len -= 1 + string_len;

	end_entry:
		/* There shouldn't be padding, but if there is... */
		offset += srvc_entry_len;
	}

	for (;;) {
		guint32 param_code;
		guint32 param_len;

		proto_tree_add_item_ret_uint(tree, hf_lat_param_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_code);
		offset += 1;
		if (param_code == 0)
			break;
		proto_tree_add_item_ret_uint(tree, hf_lat_param_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &param_len);
		offset += 1;
		proto_tree_add_item(tree, hf_lat_param_data, tvb, offset, param_len, ENC_NA);
		offset += param_len;
	}
}

static int
dissect_lat_string(tvbuff_t *tvb, int offset, int hf, proto_tree *tree)
{
	gint item_length;

	proto_tree_add_item_ret_length(tree, hf, tvb, offset, 1, ENC_ASCII|ENC_LITTLE_ENDIAN, &item_length);
	return offset + item_length;
}

void
proto_register_lat(void)
{
	static hf_register_info hf[] = {
	    { &hf_lat_rrf,
		{ "RRF", "lat.rrf", FT_BOOLEAN, 8,
		  NULL, 0x01, NULL, HFILL}},

	    { &hf_lat_master,
		{ "Master", "lat.master", FT_BOOLEAN, 8,
		  NULL, 0x02, NULL, HFILL}},

	    { &hf_lat_msg_typ,
		{ "Message type", "lat.msg_typ", FT_UINT8, BASE_DEC,
		  VALS(msg_typ_vals), 0xFC, NULL, HFILL}},

	    { &hf_lat_nbr_slots,
		{ "Number of slots", "lat.nbr_slots", FT_UINT8, BASE_DEC,
		  NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_dst_cir_id,
		{ "Destination circuit ID", "lat.dst_cir_id", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_cir_id,
		{ "Source circuit ID", "lat.src_cir_id", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_msg_seq_nbr,
		{ "Message sequence number", "lat.msg_seq_nbr", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_msg_ack_nbr,
		{ "Message acknowledgment number", "lat.msg_ack_nbr", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    /*
	     * Yes, the DEC spec says "MIN" in the field name and "maximum"
	     * in the field description.  Go figure.
	     */
	    { &hf_lat_min_rcv_datagram_size,
		{ "Maximum LAT message size", "lat.min_rcv_datagram_size", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_prtcl_ver,
		{ "Protocol version of this session", "lat.prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_prtcl_eco,
		{ "ECO level of protocol version of this session", "lat.prtcl_eco", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_max_sim_slots,
		{ "Maximum simultaneous sessions on this circuit", "lat.max_sim_slots", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_nbr_dl_bufs,
		{ "Number of extra data link buffers queued", "lat.nbr_dl_bufs", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_server_circuit_timer,
		{ "Server circuit timer", "lat.server_circuit_timer", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_keep_alive_timer,
		{ "Keep-alive timer", "lat.keep_alive_timer", FT_UINT8,
		  BASE_DEC|BASE_UNIT_STRING, &units_second_seconds, 0x0, NULL, HFILL}},

	    { &hf_lat_facility_number,
		{ "Facility number", "lat.facility_number", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_prod_type_code,
		{ "Product type code", "lat.prod_type_code", FT_UINT8,
		  BASE_DEC, VALS(prod_type_code_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_prod_vers_numb,
		{ "Product version number", "lat.prod_vers_numb", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slave_node_name,
		{ "Slave node name", "lat.slave_node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_master_node_name,
		{ "Master node name", "lat.master_node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_location_text,
		{ "Location", "lat.location_text", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_param_code,
		{ "Parameter code", "lat.param_code", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_param_len,
		{ "Parameter length", "lat.param_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_param_data,
		{ "Parameter data", "lat.param_data", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slot_dst_slot_id,
		{ "Destination slot ID", "lat.slot.dst_slot_id", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slot_src_slot_id,
		{ "Source slot ID", "lat.slot.src_slot_id", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slot_byte_count,
		{ "Slot data byte count", "lat.slot.byte_count", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slot_credits,
		{ "Credits", "lat.slot.credits", FT_UINT8,
		  BASE_DEC, NULL, 0x0F, NULL, HFILL}},

	    { &hf_lat_slot_type,
		{ "Slot type", "lat.slot.type", FT_UINT8,
		  BASE_HEX, VALS(slot_type_vals), 0xF0, NULL, HFILL}},

	    { &hf_lat_start_slot_service_class,
		{ "Service class", "lat.start_slot.service_class", FT_UINT8,
		  BASE_DEC, VALS(service_class_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_start_slot_minimum_attention_slot_size,
		{ "Minimum attention slot size", "lat.start_slot.minimum_attention_slot_size", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_start_slot_minimum_data_slot_size,
		{ "Minimum data slot size", "lat.start_slot.minimum_data_slot_size", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_start_slot_obj_srvc,
		{ "Name of the destination service", "lat.start_slot.obj_srvc", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_start_slot_subj_dscr,
		{ "Description of the source service", "lat.start_slot.subj_dscr", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_start_slot_class_1_param_code,
	        { "Parameter code", "lat.start_slot.class_1.param_code", FT_UINT8,
	          BASE_DEC, VALS(start_slot_class_1_param_code_vals),
	          0x0, NULL, HFILL }},

	    { &hf_lat_status_remaining,
		{ "Remainder of status", "lat.slot.status_remaining", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slot_data,
		{ "Slot data", "lat.slot.slot_data", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_data_b_slot_control_flags,
	        { "Control flags", "lat.data_b_slot.control_flags", FT_UINT8,
	          BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_enable_input_flow_control,
	        { "Enable usage of input flow control characters",
	          "lat.data_b_slot.control_flags.enable_input_flow_control",
	          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_disable_input_flow_control,
	        { "Disable recognition of input flow control characters",
	          "lat.data_b_slot.control_flags.disable_input_flow_control",
	          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_enable_output_flow_control,
	        { "Enable usage of output flow control characters",
	          "lat.data_b_slot.control_flags.enable_output_flow_control",
	          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_disable_output_flow_control,
	        { "Disable recognition of output flow control characters",
	          "lat.data_b_slot.control_flags.disable_output_flow_control",
	          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_break_detected,
	        { "Break condition detected",
	          "lat.data_b_slot.control_flags.break_detected",
	          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_set_port_char,
	        { "Set port characteristics",
	          "lat.data_b_slot.control_flags.set_port_characteristics",
	          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

	    { &hf_lat_data_b_slot_control_flags_report_port_char,
	        { "Report port characteristics",
	          "lat.data_b_slot.control_flags.report_port_characteristics",
	          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

	    { &hf_lat_data_b_slot_stop_output_channel_char,
	        { "Output channel stop character",
	          "lat.data_b_slot.stop_output_channel_char", FT_UINT8,
	          BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_lat_data_b_slot_start_output_channel_char,
	        { "Output channel start character",
	          "lat.data_b_slot.start_output_channel_char", FT_UINT8,
	          BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_lat_data_b_slot_stop_input_channel_char,
	        { "Input channel stop character",
	          "lat.data_b_slot.stop_input_channel_char", FT_UINT8,
	          BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_lat_data_b_slot_start_input_channel_char,
	        { "Input channel start character",
	          "lat.data_b_slot.start_input_channel_char", FT_UINT8,
	          BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_lat_data_b_slot_param_code,
	        { "Parameter code", "lat.data_b_slot.param_code", FT_UINT8,
	          BASE_DEC, VALS(data_b_slot_param_code_vals),
	          0x0, NULL, HFILL }},

	    { &hf_lat_slot_data_remaining,
		{ "Slot data remaining", "lat.slot.slot_data_remaining", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_attention_slot_control_flags,
	        { "Control flags", "lat.attention_slot.control_flags", FT_UINT8,
	          BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_lat_attention_slot_control_flags_abort,
	        { "Abort", "lat.attention_slot.control_flags.abort", FT_BOOLEAN,
	          8, NULL, 0x20, NULL, HFILL }},

	    { &hf_lat_mbz,
		{ "MBZ", "lat.slot.mbz", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_reason,
		{ "Reason", "lat.slot.reason", FT_UINT8,
		  BASE_DEC, VALS(reason_code_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_circuit_disconnect_reason,
		{ "Circuit disconnect reason", "lat.circuit_disconnect_reason", FT_UINT8,
		  BASE_DEC, VALS(circuit_disconnect_reason_code_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_reason_text,
		{ "Reason", "lat.reason_text", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_high_prtcl_ver,
		{ "Highest protocol version supported", "lat.high_prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_low_prtcl_ver,
		{ "Lowest protocol version supported", "lat.low_prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_cur_prtcl_ver,
		{ "Protocol version of this message", "lat.cur_prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_cur_prtcl_eco,
		{ "ECO level of current protocol version", "lat.cur_prtcl_eco", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_msg_inc,
		{ "Message incarnation", "lat.msg_inc", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_change_flags,
		{ "Change flags", "lat.change_flags", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_data_link_rcv_frame_size,
		{ "Maximum LAT message size", "lat.data_link_rcv_frame_size", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_multicast_timer,
		{ "Node multicast timer", "lat.node_multicast_timer", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_status,
		{ "Node status", "lat.node_status", FT_UINT8,
		  BASE_DEC, VALS(node_status_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_node_group_len,
		{ "Node group length", "lat.node_group_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_groups,
		{ "Node groups", "lat.node_groups", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_name,
		{ "Node name", "lat.node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_description,
		{ "Node description", "lat.node_description", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_name_count,
		{ "Number of service names", "lat.service_name_count", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_rating,
		{ "Service rating", "lat.service.rating", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_service_len,
		{ "Node service classes length", "lat.node_service_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_service_class,
		{ "Node service classes", "lat.node_service_class", FT_UINT8,
		  BASE_DEC, VALS(service_class_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_prtcl_format,
		{ "Protocol format", "lat.prtcl_format", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_request_identifier,
		{ "Request identifier", "lat.request_identifier", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_entry_identifier,
		{ "Entry identifier", "lat.entry_identifier", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_command_type,
		{ "Command type", "lat.command_type", FT_UINT8,
		  BASE_DEC, VALS(command_type_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_command_modifier,
		{ "Command modifier", "lat.command_modifier", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_command_modifier_send_status_periodically,
		{ "Send status of the entries periodically",
		  "lat.command_modifier.send_status_periodically", FT_BOOLEAN,
		  8, NULL, 0x01, NULL, HFILL}},

	    { &hf_lat_command_modifier_send_status_on_queue_depth_change,
		{ "Send status of the entries every time the queue depth changes",
		  "lat.command_modifier.send_status_on_queue_depth_change", FT_BOOLEAN,
		  8, NULL, 0x02, NULL, HFILL}},

	    { &hf_lat_obj_node_name,
		{ "Destination node name", "lat.obj_node.name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_subj_group_len,
		{ "Subject group code length", "lat.subj_group_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_subj_group,
		{ "Subject group code mask", "lat.subj_group", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_subj_node_name,
		{ "Subject node name", "lat.subj_node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_subj_port_name,
		{ "Subject port name", "lat.subj_port_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_status_retransmit_timer,
		{ "Status retransmit timer", "lat.status_retransmit_timer", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_entries_counter,
		{ "Entries counter", "lat.entries_counter", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  "Number of entries whose status is reported in the message",
		  HFILL}},

	    { &hf_lat_entry_length,
		{ "Entry length", "lat.entry_length", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "Length of status entry, in bytes",
		  HFILL}},

	    { &hf_lat_entry_status,
		{ "Entry status", "lat.entry_status", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_entry_status_rejected,
		{ "Rejected", "lat.entry_status.rejected", FT_BOOLEAN,
		  8, NULL, ENTRY_STATUS_REJECTED, "Solicitation request was rejected",
		  HFILL}},

	    { &hf_lat_entry_status_additional_information,
		{ "Additional information", "lat.entry_status.additional_information", FT_UINT8,
		  BASE_DEC, VALS(additional_information_vals),
		  ENTRY_STATUS_ADDITIONAL_INFORMATION, NULL, HFILL}},

	    { &hf_lat_entry_error,
		{ "Entry error", "lat.entry_error", FT_UINT8,
		  BASE_DEC, VALS(entry_error_vals), 0x0,
		  "Solicitation rejection reason", HFILL}},

	    { &hf_lat_elapsed_queue_time,
		{ "Elapsed queue time", "lat.elapsed_queue_time", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_min_queue_position,
		{ "Minimum queue position", "lat.min_queue_position", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_max_queue_position,
		{ "Maximum queue position", "lat.max_queue_position", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_obj_srvc_name,
		{ "Service name", "lat.obj_service_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_obj_port_name,
		{ "Port name", "lat.obj_port_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_subj_description,
		{ "Source service description", "lat.subj_description", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_solicit_identifier,
		{ "Solicit identifier", "lat.solicit_identifier", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_response_timer,
		{ "Response timer", "lat.response_timer", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_dst_node_name,
		{ "Destination node name", "lat.dst_node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_node_group_len,
		{ "Source node group length", "lat.src_node_group_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_node_groups,
		{ "Source node groups", "lat.src_node_groups", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_node_name,
		{ "Source node name", "lat.src_node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_dst_srvc_name,
		{ "Destination service name", "lat.dst_srvc_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_response_status,
		{ "Response status", "lat.response_status", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_response_status_node_does_not_offer_requested_service,
		{ "Node does not offer requested service",
		  "lat.response_status.node_does_not_offer_requested_service",
		  FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL}},

	    { &hf_lat_src_node_status,
		{ "Source node status", "lat.src_node_status", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_node_status_node_is_disabled,
		{ "Node is disabled",
		  "lat.src_node_status.node_is_disabled",
		  FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL}},

	    { &hf_lat_src_node_status_start_message_can_be_sent,
		{ "Start message can be sent",
		  "lat.src_node_status.start_message_can_be_sent",
		  FT_BOOLEAN, 16, NULL, 0x0002,
		  "Start message can be sent by the subject node to this node",
		  HFILL}},

	    { &hf_lat_src_node_status_command_message_can_be_sent,
		{ "Command message can be sent",
		  "lat.src_node_status.command_message_can_be_sent",
		  FT_BOOLEAN, 16, NULL, 0x0004,
		  "Command message can be sent by the subject node to this node",
		  HFILL}},

	    { &hf_lat_source_node_addr,
		{ "Source node address", "lat.source_node_addr", FT_ETHER,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_node_mc_timer,
		{ "Multicast timer", "lat.mc_timer", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_src_node_desc,
		{ "Source node description", "lat.src_node_desc", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_count,
		{ "Service count", "lat.srvc_status", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "Total number of service entries in the message", HFILL}},

	    { &hf_lat_srvc_entry_len,
		{ "Service entry length", "lat.srvc_entry_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "Length of service entry, in bytes", HFILL}},

	    { &hf_lat_srvc_class_len,
		{ "Service class length", "lat.srvc_class_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "Length of service class list", HFILL}},

	    { &hf_lat_srvc_class,
		{ "Service class", "lat.srvc_class", FT_UINT8,
		  BASE_DEC, VALS(service_class_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_status,
		{ "Service status", "lat.srvc_status", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_status_enabled,
		{ "Service is enabled", "lat.srvc_status.enabled", FT_BOOLEAN,
		  8, NULL, 0x01, NULL, HFILL}},

	    { &hf_lat_srvc_status_supports_queueing,
		{ "Service supports queueing", "lat.srvc_status.supports_queueing", FT_BOOLEAN,
		  8, NULL, 0x02, NULL, HFILL}},

	    { &hf_lat_srvc_rating,
		{ "Service rating", "lat.srvc_rating", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_group_len,
		{ "Service group code length", "lat.srvc_group_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_groups,
		{ "Service group code mask", "lat.srvc_groups", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_name,
		{ "Service name", "lat.srvc_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_srvc_desc,
		{ "Service description", "lat.srvc_desc", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_name,
		{ "Service name", "lat.service.name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_description,
		{ "Service description", "lat.service.description", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_unknown_command_data,
		{ "Unknown command data", "lat.unknown_command_data", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},
	};
	static gint *ett[] = {
		&ett_lat,
		&ett_data_b_slot_control_flags,
		&ett_lat_attention_slot_control_flags,
		&ett_lat_command_modifier,
		&ett_lat_entry_status,
		&ett_lat_response_status,
		&ett_lat_src_node_status,
		&ett_lat_srvc_status
	};
	static ei_register_info ei[] = {
		{ &ei_slot_data_len_invalid,
		  { "lat.slot.data_len_invalid", PI_PROTOCOL, PI_ERROR, "Slot data length is too short", EXPFILL }},
		{ &ei_entry_length_too_short,
		  { "lat.entry_length_too_short", PI_PROTOCOL, PI_ERROR, "Entry length in status message is too short", EXPFILL }},
		{ &ei_srvc_entry_len_too_short,
		  { "lat.srvc_entry_len_too_short", PI_PROTOCOL, PI_ERROR, "Entry length in response information message is too short", EXPFILL }},
		{ &ei_mbz_data_nonzero,
		  { "lat.mbz_data_nonzero", PI_PROTOCOL, PI_ERROR, "Must-be-zero data is nonzero", EXPFILL }},
	};
	expert_module_t* expert_lat;

	proto_lat = proto_register_protocol("Local Area Transport",
	    "LAT", "lat");
	lat_handle = register_dissector("lat", dissect_lat, proto_lat);
	proto_register_field_array(proto_lat, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_lat = expert_register_protocol(proto_lat);
	expert_register_field_array(expert_lat, ei, array_length(ei));
}

void
proto_reg_handoff_lat(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_LAT, lat_handle);
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
