/* packet-sapenqueue.c
 * Routines for SAP Enqueue (Enqueue Server) dissection
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
 * This is a dissector for the SAP Enqueue Server protocol.
 *
 * Some details and example requests can be found in pysap's documentation: https://pysap.readthedocs.io/en/latest/protocols/SAPEnqueue.html.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>


/* Enqueue Server Type values */
static const value_string sapenqueue_type_vals[] = {
	{  0, "SYNC_REQUEST" },
	{  1, "ASYNC_REQUEST" },
	{  2, "RESPONSE" },
	/* NULL */
	{  0, NULL }
};


/* Enqueue Server Destination values */
static const value_string sapenqueue_dest_vals[] = {
	{  1, "SYNC_ENQUEUE" },
	{  2, "ASYNC_ENQUEUE" },
	{  3, "SERVER_ADMIN" },
	{  5, "STAT_QUERY" },
	{  6, "CONNECTION_ADMIN" },
	{  7, "ENQ_TO_REP" },
	{  8, "REP_TO_ENQ" },
	/* NULL */
	{  0, NULL },
};


/* Enqueue Server Admin Opcode values */
static const value_string sapenqueue_server_admin_opcode_vals[] = {
	{  1, "EnAdmDummyRequest" },
	{  2, "EnAdmShutdownRequest" },
	{  4, "EnAdmGetReplInfoRequest" },
	{  6, "EnAdmTraceRequest" },
	/* NULL */
	{  0, NULL },
};

/* Enqueue Server Connection Admin Trace Action values */
static const value_string sapenqueue_server_admin_trace_action_vals[] = {
	{  1, "Raise level" },
	{  2, "Lower level" },
	{  3, "Get trace state" },
	{  4, "Set trace status" },
	{  5, "Reset trace files" },
	/* NULL */
	{  0, NULL }
};

/* Enqueue Server Connection Admin Trace Limit values */
static const value_string sapenqueue_server_admin_trace_limit_vals[] = {
	{  0, "Globally" },
	{  1, "Only in enserver" },
	{  2, "Only in repserver" },
	{  3, "Only in threads of type" },
	{  4, "Only in one thread of type" },
	/* NULL */
	{  0, NULL }
};

/* Enqueue Server Connection Admin Trace Thread values */
static const value_string sapenqueue_server_admin_trace_thread_vals[] = {
	{  0, "All threads" },
	{  1, "All I/O threads" },
	{  2, "Enqueue Worker thread" },
	{  3, "Replication thread" },
	{  4, "ADM thread" },
	{  5, "Signal thread" },
	{  6, "Listener thread" },
	/* NULL */
	{  0, NULL }
};

/* Enqueue Server Connection Admin Opcode values */
static const value_string sapenqueue_conn_admin_opcode_vals[] = {
	{  0, "Loopback packet" },
	{  1, "Parameter Request" },
	{  2, "Parameter Response" },
	{  3, "Shutdown Read" },
	{  4, "Shutdown Write" },
	{  5, "Shutdown Both" },
	{  6, "Keepalive" },
	/* NULL */
	{  0, NULL }
};

/* Enqueue Server Connection Admin Parameter values */
static const value_string sapenqueue_conn_admin_param_vals[] = {
	{  0, "ENCPARAM_RECV_LEN" },
	{  1, "ENCPARAM_SEND_LEN" },
	{  2, "ENCPARAM_MSG_TYPE" },
	{  3, "ENCPARAM_SET_NAME" },
	{  4, "ENCPARAM_SET_NOSUPP" },
	{  5, "ENCPARAM_SET_VERSION" },
	{  6, "ENCPARAM_SET_UCSUPPORT" },
	/* NULL */
	{  0, NULL }
};

static int proto_sapenqueue;

static int hf_sapenqueue_magic;
static int hf_sapenqueue_id;
static int hf_sapenqueue_length;
static int hf_sapenqueue_length_frag;
static int hf_sapenqueue_dest;
static int hf_sapenqueue_conn_admin_opcode;
static int hf_sapenqueue_more_frags;
static int hf_sapenqueue_type;

static int hf_sapenqueue_server_admin;
static int hf_sapenqueue_server_admin_eyecatcher;
static int hf_sapenqueue_server_admin_version;
static int hf_sapenqueue_server_admin_flag;
static int hf_sapenqueue_server_admin_length;
static int hf_sapenqueue_server_admin_opcode;
static int hf_sapenqueue_server_admin_flags;
static int hf_sapenqueue_server_admin_rc;
static int hf_sapenqueue_server_admin_value;

static int hf_sapenqueue_server_admin_trace_request;
static int hf_sapenqueue_server_admin_trace_protocol_version;
static int hf_sapenqueue_server_admin_trace_action;
static int hf_sapenqueue_server_admin_trace_limit;
static int hf_sapenqueue_server_admin_trace_thread;
static int hf_sapenqueue_server_admin_trace_level;
static int hf_sapenqueue_server_admin_trace_logging;
static int hf_sapenqueue_server_admin_trace_max_file_size;
static int hf_sapenqueue_server_admin_trace_nopatterns;
static int hf_sapenqueue_server_admin_trace_eyecatcher;
static int hf_sapenqueue_server_admin_trace_patterns;
static int hf_sapenqueue_server_admin_trace_unknown;

static int hf_sapenqueue_server_admin_trace_pattern;
static int hf_sapenqueue_server_admin_trace_pattern_len;
static int hf_sapenqueue_server_admin_trace_pattern_value;

static int hf_sapenqueue_conn_admin;
static int hf_sapenqueue_conn_admin_params_count;
static int hf_sapenqueue_conn_admin_params;
static int hf_sapenqueue_conn_admin_param;
static int hf_sapenqueue_conn_admin_param_id;
static int hf_sapenqueue_conn_admin_param_len;
static int hf_sapenqueue_conn_admin_param_value;
static int hf_sapenqueue_conn_admin_param_name;

static int ett_sapenqueue;

/* Expert info */
static expert_field ei_sapenqueue_pattern_invalid_length;
static expert_field ei_sapenqueue_support_invalid_offset;
static expert_field ei_sapenqueue_support_invalid_length;

/* Protocol handle */
static dissector_handle_t sapenqueue_handle;


/*
 *
 */
void proto_reg_handoff_sapenqueue(void);
void proto_register_sapenqueue(void);


static void
dissect_sapenqueue_server_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset){
	uint8_t opcode = 0;
	proto_item *server_admin = NULL;
	proto_tree *server_admin_tree = NULL;

	server_admin = proto_tree_add_item(tree, hf_sapenqueue_server_admin, tvb, offset, -1, ENC_NA);
	server_admin_tree = proto_item_add_subtree(server_admin, ett_sapenqueue);

	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_eyecatcher, tvb, offset, 4, ENC_ASCII|ENC_NA);
	offset += 4;
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	offset += 3;  /* Unknown bytes */
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_eyecatcher, tvb, offset, 4, ENC_ASCII|ENC_NA);
	offset += 4;
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_length, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	opcode = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_rc, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_eyecatcher, tvb, offset, 4, ENC_ASCII|ENC_NA);
	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) > 0){
		switch(opcode){
			case 0x06:{		/* EnAdmTraceRequest */
				uint8_t pattern_length = 0;
				uint32_t nopatterns = 0, total_length = 0;
				proto_item *trace_request = NULL, *trace_request_patterns = NULL, *trace_request_pattern = NULL;
				proto_tree *trace_request_tree = NULL, *trace_request_patterns_tree = NULL, *trace_request_pattern_tree = NULL;

				trace_request = proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_trace_request, tvb, offset, -1, ENC_NA);
				trace_request_tree = proto_item_add_subtree(trace_request, ett_sapenqueue);

				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_protocol_version, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_action, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_thread, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_unknown, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_level, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_unknown, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_logging, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_max_file_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				nopatterns = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_nopatterns, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_unknown, tvb, offset, 8, ENC_NA);
				offset += 8;
				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_eyecatcher, tvb, offset, 4, ENC_ASCII|ENC_NA);
				offset += 4;

				/* As we don't have the right size yet, start with 1 byte */
				trace_request_patterns = proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_patterns, tvb, offset, 1, ENC_NA);
				trace_request_patterns_tree = proto_item_add_subtree(trace_request_patterns, ett_sapenqueue);

				while (nopatterns > 0 && tvb_offset_exists(tvb, offset)){
					/* As we don't have the right size yet, start with 1 byte */
					trace_request_pattern = proto_tree_add_item(trace_request_patterns_tree, hf_sapenqueue_server_admin_trace_pattern, tvb, offset, 1, ENC_NA);
					trace_request_pattern_tree = proto_item_add_subtree(trace_request_pattern, ett_sapenqueue);

					pattern_length = tvb_get_uint8(tvb, offset) + 1; /* Pattern string is null terminated */
					proto_tree_add_item(trace_request_pattern_tree, hf_sapenqueue_server_admin_trace_pattern_len, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;

					/* Set the max length to the remaining of the packet, just in case a malformed packet arrives */
					if (!tvb_offset_exists(tvb, offset + pattern_length)) {
						pattern_length = (uint8_t)tvb_reported_length_remaining(tvb, offset);
						expert_add_info(pinfo, trace_request_pattern, &ei_sapenqueue_pattern_invalid_length);
					}
					proto_tree_add_item(trace_request_pattern_tree, hf_sapenqueue_server_admin_trace_pattern_value, tvb, offset, pattern_length, ENC_ASCII|ENC_NA);
					offset += pattern_length;

					/* Set the right size for the pattern tree */
					pattern_length += 1; /* Add also the length field */
					proto_item_set_len(trace_request_pattern, pattern_length);

					nopatterns -= 1;
					total_length += pattern_length;
				}
				proto_item_set_len(trace_request_patterns, total_length);

				proto_tree_add_item(trace_request_tree, hf_sapenqueue_server_admin_trace_eyecatcher, tvb, offset, 4, ENC_ASCII|ENC_NA);
				break;
			}
			default:{
				proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_value, tvb, offset, -1, ENC_NA);
				break;
			}
		}
	}

}


static void
dissect_sapenqueue_conn_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint8_t opcode){
	proto_item *conn_admin = NULL;
	proto_tree *conn_admin_tree = NULL;

	conn_admin = proto_tree_add_item(tree, hf_sapenqueue_conn_admin, tvb, offset, -1, ENC_NA);
	conn_admin_tree = proto_item_add_subtree(conn_admin, ett_sapenqueue);

	switch (opcode){
		case 0x01:		/* Parameter Request */
		case 0x02:{		/* Parameter Response */
			int name_length_remaining = 0;
			uint8_t length = 0, total_length = 0;
			uint32_t count = 0, id = 0, name_length = 0;
			proto_item *params = NULL, *param = NULL;
			proto_tree *params_tree = NULL, *param_tree = NULL;

			count = tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(conn_admin_tree, hf_sapenqueue_conn_admin_params_count, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			params = proto_tree_add_item(conn_admin_tree, hf_sapenqueue_conn_admin_params, tvb, offset, 1, ENC_NA);
			params_tree = proto_item_add_subtree(params, ett_sapenqueue);

			while (count > 0 && tvb_offset_exists(tvb, offset)){
				/* As we don't have the right size yet, start with 1 byte */
				param = proto_tree_add_item(params_tree, hf_sapenqueue_conn_admin_param, tvb, offset, 1, ENC_NA);
				param_tree = proto_item_add_subtree(param, ett_sapenqueue);

				id = tvb_get_ntohl(tvb, offset);
				proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_id, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				length = 4;

				switch(id){
					case 0x03:{	/* Set Name parameter */
						name_length = tvb_strsize(tvb, offset);
						if (name_length > 0) {
							proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_name, tvb, offset, name_length, ENC_ASCII|ENC_NA);
							offset += name_length;
							length += name_length;
						}
						break;

					} case 0x04:{  /* No support parameter */
						/* This parameter appears to have more fields only for responses */
						if (opcode == 0x02) {
							proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_value, tvb, offset, 4, ENC_BIG_ENDIAN);
							offset += 4;
							length += 4;
						}
						break;

					} case 0x06:{  /* Set Unicode Support Parameter */
						name_length = tvb_get_ntohl(tvb, offset);
						proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_len, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;

						/* If the reported length is not correct, use the remaining of the packet as length */
						name_length_remaining = tvb_reported_length_remaining(tvb, offset);
						if (name_length_remaining < 0){
							expert_add_info(pinfo, param, &ei_sapenqueue_support_invalid_offset);
							break;
						}
						if ((uint32_t)name_length_remaining < name_length) {
							name_length = (uint32_t)name_length_remaining;
							expert_add_info(pinfo, param, &ei_sapenqueue_support_invalid_length);
						}

						proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_value, tvb, offset, name_length, ENC_BIG_ENDIAN);
						offset += name_length;
						length += 4 + name_length;
						break;

					} default: {
						/* The rest of the parameters have an integer value field */
						proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_value, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
						length += 4;
					}
				}

				/* Set the right size for the parameter tree */
				proto_item_set_len(param, length);

				count -= 1;
				total_length += length;
			}

			proto_item_set_len(params, total_length);
			break;
		}
	}

}


static int
dissect_sapenqueue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint8_t dest = 0, type = 0, opcode = 0;
	uint32_t offset = 4;
	proto_item *ti = NULL;
	proto_tree *sapenqueue_tree = NULL;

	/* If the packet has less than 20 bytes we can be sure that is not an
	 * Enqueue server packet.
	 */
	if (tvb_reported_length(tvb) < 20){
		return 0;
	}

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPENQUEUE");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	dest = tvb_get_uint8(tvb, offset + 16);
	col_append_fstr(pinfo->cinfo, COL_INFO, "Dest=%s", val_to_str_const(dest, sapenqueue_dest_vals, "Unknown"));

	opcode = tvb_get_uint8(tvb, offset + 17);
	type = tvb_get_uint8(tvb, offset + 19);
	col_append_fstr(pinfo->cinfo, COL_INFO, ",Type=%s", val_to_str_const(type, sapenqueue_type_vals, "Unknown"));

	if (dest == 0x06){
		col_append_fstr(pinfo->cinfo, COL_INFO, ",Opcode=%s", val_to_str_const(opcode, sapenqueue_conn_admin_opcode_vals, "Unknown"));
	}

	/* Add the main sapenqueue subtree */
	ti = proto_tree_add_item(tree, proto_sapenqueue, tvb, 0, -1, ENC_NA);
	sapenqueue_tree = proto_item_add_subtree(ti, ett_sapenqueue);

	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_magic, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_length, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_length_frag, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_dest, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	if (dest == 0x06){  /* This field is only relevant if the destination is Connection Admin */
		proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_conn_admin_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;
	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_more_frags, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	switch (dest){
		case 0x03:{		/* Server Admin */
			dissect_sapenqueue_server_admin(tvb, pinfo, sapenqueue_tree, offset);
			break;
		}
		case 0x06:{		/* Connection Admin */
			dissect_sapenqueue_conn_admin(tvb, pinfo, sapenqueue_tree, offset, opcode);
			break;
		}
	}

	return tvb_reported_length(tvb);
}


static bool
dissect_sapenqueue_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_){
	conversation_t *conversation = NULL;

	/* If the first 4 bytes are the magic bytes, we can guess that the
	 * packet is a Enqueue server packet.
	 */
	if (tvb_get_ntohl(tvb, 0) != 0xabcde123){
		return false;
	}

	/* From now on this conversation is dissected as SAP Enqueue traffic */
	conversation = find_or_create_conversation(pinfo);
	conversation_set_dissector(conversation, sapenqueue_handle);

	/* Now dissect the packet */
	dissect_sapenqueue(tvb, pinfo, tree, data);

	return true;
}


void
proto_register_sapenqueue(void)
{
	static hf_register_info hf[] = {
		/* General Header fields */
		{ &hf_sapenqueue_magic,
			{ "Magic Bytes", "sapenqueue.magic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_id,
			{ "ID", "sapenqueue.id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_length,
			{ "Length", "sapenqueue.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_length_frag,
			{ "Fragment Length", "sapenqueue.fragment_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_dest,
			{ "Destination", "sapenqueue.destination", FT_UINT8, BASE_DEC, VALS(sapenqueue_dest_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_opcode,
			{ "Opcode", "sapenqueue.opcode", FT_UINT8, BASE_DEC, VALS(sapenqueue_conn_admin_opcode_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_more_frags,
			{ "More Fragments", "sapenqueue.more_frags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_type,
			{ "Type", "sapenqueue.type", FT_UINT8, BASE_DEC, VALS(sapenqueue_type_vals), 0x0, NULL, HFILL }},

		/* Server Admin fields */
		{ &hf_sapenqueue_server_admin,
			{ "Server Admin", "sapenqueue.server_admin", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_eyecatcher,
			{ "Eye Catcher", "sapenqueue.server_admin.eyecatcher", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_version,
			{ "Version", "sapenqueue.server_admin.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_flag,
			{ "Flag", "sapenqueue.server_admin.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_length,
			{ "Length", "sapenqueue.server_admin.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_opcode,
			{ "Opcode", "sapenqueue.server_admin.opcode", FT_UINT8, BASE_DEC, VALS(sapenqueue_server_admin_opcode_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_flags,
			{ "Flags", "sapenqueue.server_admin.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_rc,
			{ "Return Code", "sapenqueue.server_admin.rc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_value,
			{ "Value", "sapenqueue.server_admin.value", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Trace Request fields */
		{ &hf_sapenqueue_server_admin_trace_request,
			{ "Trace Request", "sapenqueue.server_admin.trace", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_protocol_version,
			{ "Trace Protocol Version", "sapenqueue.server_admin.trace.protocol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_action,
			{ "Trace Action", "sapenqueue.server_admin.trace.action", FT_UINT8, BASE_DEC, VALS(sapenqueue_server_admin_trace_action_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_limit,
			{ "Trace Limit", "sapenqueue.server_admin.trace.limit", FT_UINT8, BASE_DEC, VALS(sapenqueue_server_admin_trace_limit_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_thread,
			{ "Trace Thread", "sapenqueue.server_admin.trace.thread", FT_UINT8, BASE_DEC, VALS(sapenqueue_server_admin_trace_thread_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_level,
			{ "Trace Level", "sapenqueue.server_admin.trace.level", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_logging,
			{ "Trace Logging", "sapenqueue.server_admin.trace.logging", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_max_file_size,
			{ "Trace Max File Size", "sapenqueue.server_admin.trace.max_file_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_nopatterns,
			{ "Trace No Patterns", "sapenqueue.server_admin.trace.nopatterns", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_eyecatcher,
			{ "Trace Eye Catcher", "sapenqueue.server_admin.trace.eyecatcher", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_patterns,
			{ "Trace Patterns", "sapenqueue.server_admin.trace.patterns", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_unknown,
			{ "Unknown field", "sapenqueue.server_admin.trace.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Trace Request Pattern fields */
		{ &hf_sapenqueue_server_admin_trace_pattern,
			{ "Trace Pattern", "sapenqueue.server_admin.trace.pattern", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_pattern_len,
			{ "Trace Pattern Length", "sapenqueue.server_admin.trace.pattern.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_server_admin_trace_pattern_value,
			{ "Trace Pattern Value", "sapenqueue.server_admin.trace.pattern.value", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Connection Admin fields */
		{ &hf_sapenqueue_conn_admin,
			{ "Connection Admin", "sapenqueue.conn_admin", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_params_count,
			{ "Parameters Count", "sapenqueue.conn_admin.params.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_params,
			{ "Parameters", "sapenqueue.conn_admin.params", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_param,
			{ "Parameter", "sapenqueue.conn_admin.params.param", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_param_id,
			{ "Parameter ID", "sapenqueue.conn_admin.params.param.id", FT_UINT32, BASE_DEC, VALS(sapenqueue_conn_admin_param_vals), 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_param_len,
			{ "Parameter Length", "sapenqueue.conn_admin.params.param.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_param_value,
			{ "Parameter Value", "sapenqueue.conn_admin.params.param.value", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_sapenqueue_conn_admin_param_name,
			{ "Parameter Name", "sapenqueue.conn_admin.params.param.name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_sapenqueue
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_sapenqueue_pattern_invalid_length, { "sapenqueue.server_admin.trace.pattern.length.invalid", PI_MALFORMED, PI_WARN, "The reported length is incorrect", EXPFILL }},
		{ &ei_sapenqueue_support_invalid_offset, { "sapenqueue.conn_admin.params.param.offset.invalid", PI_MALFORMED, PI_ERROR, "Invalid offset", EXPFILL }},
		{ &ei_sapenqueue_support_invalid_length, { "sapenqueue.conn_admin.params.param.length.invalid", PI_MALFORMED, PI_WARN, "The reported length is incorrect", EXPFILL }},
	};

	expert_module_t* sapenqueue_expert;

	/* Register the protocol */
	proto_sapenqueue = proto_register_protocol("SAP Enqueue Protocol", "SAPENQUEUE", "sapenqueue");

	proto_register_field_array(proto_sapenqueue, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	sapenqueue_expert = expert_register_protocol(proto_sapenqueue);
	expert_register_field_array(sapenqueue_expert, ei, array_length(ei));

	register_dissector("sapenqueue", dissect_sapenqueue, proto_sapenqueue);

}


void
proto_reg_handoff_sapenqueue(void)
{
	sapenqueue_handle = create_dissector_handle(dissect_sapenqueue, proto_sapenqueue);

	/* Register the heuristic dissector. We need to use a heuristic dissector
	 * here as the Enqueue Server uses the same port number that the Dispatcher
	 * Service (32NN/tcp). */
	heur_dissector_add("sapni", dissect_sapenqueue_heur, "SAP Enqueue Protocol", "sapenqueue", proto_sapenqueue, HEURISTIC_ENABLE);
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
