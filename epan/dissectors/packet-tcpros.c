/* packet-tcpros.c
 * Routines for Robot Operating System TCP protocol (TCPROS)
 * Copyright 2015, Guillaume Autran  (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>

#include "packet-tcp.h"


#define SIZE_OF_LENGTH_FIELD 4
#define SIZE_OF_LENGTH_STAMP (4 + 4)

void proto_register_tcpros(void);
void proto_reg_handoff_tcpros(void);


static int proto_tcpros;
static dissector_handle_t tcpros_handle;

/** desegmentation of TCPROS over TCP */
static bool tcpros_desegment = true;


static int hf_tcpros_connection_header;
static int hf_tcpros_connection_header_length;
static int hf_tcpros_connection_header_content;
static int hf_tcpros_connection_header_field;
static int hf_tcpros_connection_header_field_length;
static int hf_tcpros_connection_header_field_data;
static int hf_tcpros_connection_header_field_name;
static int hf_tcpros_connection_header_field_value;
static int hf_tcpros_clock;
static int hf_tcpros_clock_length;
static int hf_tcpros_message;
static int hf_tcpros_message_length;
static int hf_tcpros_message_body;
static int hf_tcpros_message_header;
static int hf_tcpros_message_header_seq;
static int hf_tcpros_message_header_stamp;
static int hf_tcpros_message_header_stamp_sec;
static int hf_tcpros_message_header_stamp_nsec;
static int hf_tcpros_message_header_frame;
static int hf_tcpros_message_header_frame_length;
static int hf_tcpros_message_header_frame_value;
static int hf_tcpros_message_payload;

static int ett_tcpros;

/**
 * This is the ROS connection header dissector. The general packet format is described
 * here: http://wiki.ros.org/ROS/TCPROS
 * In short, a connection header looks like such: '4-byte length + [4-byte field length + "field=value" ]*'
 */
static int
dissect_ros_connection_header_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	proto_item *ti;
	proto_tree *field_tree;

	uint32_t fLen = 0;
	int   sep, ret = 0;

	/** Do we have enough for a length field? (ie: 4 bytes) */
	if( tvb_reported_length_remaining(tvb, offset) > SIZE_OF_LENGTH_FIELD ) {
		/** Get the length of the next field */
		fLen = tvb_get_letohl(tvb, offset);

		/** Display the field as a utf-8 string */
		ti = proto_tree_add_item(tree, hf_tcpros_connection_header_field, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_UTF_8|ENC_LITTLE_ENDIAN);
		field_tree = proto_item_add_subtree(ti, ett_tcpros);


		proto_tree_add_item(field_tree, hf_tcpros_connection_header_field_length, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
		offset += SIZE_OF_LENGTH_FIELD;
		ti = proto_tree_add_item(field_tree, hf_tcpros_connection_header_field_data, tvb, offset, fLen, ENC_UTF_8);

		/** Look for the '=' separator */
		sep = (tvb_find_guint8(tvb, offset, fLen, '=') - offset);

		/** If we find a separator, then split field name and value */
		if( sep > 0 ) {
			const uint8_t* field;
			field_tree = proto_item_add_subtree(ti, ett_tcpros);
			proto_tree_add_item_ret_string(field_tree, hf_tcpros_connection_header_field_name, tvb, offset, sep, ENC_UTF_8|ENC_NA, pinfo->pool, &field);
			proto_tree_add_item(field_tree, hf_tcpros_connection_header_field_value, tvb, offset+sep+1, fLen - sep - 1, ENC_UTF_8);

			col_append_str(pinfo->cinfo, COL_INFO, field);
		}
		ret = fLen + SIZE_OF_LENGTH_FIELD;
	}

	return ret;
}

static int
dissect_ros_connection_header(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, int offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	int consumed_len = 0;
	uint32_t header_len = tvb_get_letohl(tvb, offset);

	col_append_str(pinfo->cinfo, COL_INFO, "[ROS Conn] Metadata: [");

	/** We got a connection header */
	ti = proto_tree_add_item(root_tree, hf_tcpros_connection_header, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_NA|ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	proto_tree_add_item(sub_tree, hf_tcpros_connection_header_length, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	ti = proto_tree_add_item(sub_tree, hf_tcpros_connection_header_content, tvb, offset + consumed_len, header_len, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	header_len += SIZE_OF_LENGTH_FIELD;

	while( consumed_len < (int)header_len ) {
		int len = dissect_ros_connection_header_field(tvb, sub_tree, pinfo, offset + consumed_len);
		consumed_len += len;
		if( len == 0 ) {
			break;
		}
		if( consumed_len < (int)header_len ) {
			col_append_str(pinfo->cinfo, COL_INFO, ",");
		}
	}
	col_append_str(pinfo->cinfo, COL_INFO, "]");

	return consumed_len;
}


static int
dissect_ros_message_header_stamp(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, int offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	int consumed_len = 0;
	uint32_t sec, nsec;

	ti = proto_tree_add_item(root_tree, hf_tcpros_message_header_stamp, tvb, offset + consumed_len, SIZE_OF_LENGTH_STAMP, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	/** Seconds */
	proto_tree_add_item(sub_tree, hf_tcpros_message_header_stamp_sec, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	sec = tvb_get_letohl(tvb, offset + consumed_len);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	/** Nano seconds */
	proto_tree_add_item(sub_tree, hf_tcpros_message_header_stamp_nsec, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	nsec = tvb_get_letohl(tvb, offset + consumed_len);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	/** Info */
	col_append_fstr(pinfo->cinfo, COL_INFO, "Timestamp: %d.%09d ", sec, nsec);

	return consumed_len;
}

static int
dissect_ros_clock(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, int offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	int consumed_len = 0;

	col_append_str(pinfo->cinfo, COL_INFO, "[ROS Clock] ");

	/** We got a ROS Clock msg */
	ti = proto_tree_add_item(root_tree, hf_tcpros_clock, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	proto_tree_add_item(sub_tree, hf_tcpros_clock_length, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	consumed_len += dissect_ros_message_header_stamp(tvb, sub_tree, pinfo, offset + consumed_len);

	return consumed_len;
}

static int
dissect_ros_message_header(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, int offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	int consumed_len = 0;
	uint32_t frame_id_len;
	uint32_t seq;
	unsigned header_len;
	const uint8_t* frame_str;


	frame_id_len = tvb_get_letohl(tvb, offset + consumed_len + SIZE_OF_LENGTH_FIELD + SIZE_OF_LENGTH_STAMP);
	header_len = SIZE_OF_LENGTH_FIELD + SIZE_OF_LENGTH_STAMP + SIZE_OF_LENGTH_FIELD + frame_id_len;

	/** Header */
	ti = proto_tree_add_item(root_tree, hf_tcpros_message_header, tvb, offset + consumed_len, header_len, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	/** Sequence number */
	proto_tree_add_item(sub_tree, hf_tcpros_message_header_seq, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	seq = tvb_get_letohl(tvb, offset + consumed_len);
	consumed_len += SIZE_OF_LENGTH_FIELD;
	col_append_fstr(pinfo->cinfo, COL_INFO, "Seq: %d ", seq);

	/** Timestamp */
	consumed_len += dissect_ros_message_header_stamp(tvb, sub_tree, pinfo, offset + consumed_len);

	/** Frame ID */
	ti = proto_tree_add_item(sub_tree, hf_tcpros_message_header_frame, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_UTF_8|ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	proto_tree_add_item(sub_tree, hf_tcpros_message_header_frame_length, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	proto_tree_add_item_ret_string(sub_tree, hf_tcpros_message_header_frame_value, tvb, offset + consumed_len, frame_id_len, ENC_UTF_8|ENC_NA, pinfo->pool, &frame_str);
	col_append_fstr(pinfo->cinfo, COL_INFO, "Frame ID: '%s' ", frame_str);
	consumed_len += frame_id_len;

	return consumed_len;
}


/**
 * This is the ROS message dissector. A ROS message contains two parts: a msg header; a msg payload.
 * Because the packet is all in binary format, we don't really know the payload format (we don't know the payload type either).
 * However, every packet has the same header as defined here: http://docs.ros.org/api/std_msgs/html/msg/Header.html
 * So, we can break this one down and display it.
 */
static int
dissect_ros_message(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, int offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	int consumed_len = 0;
	uint32_t total_len = tvb_get_letohl(tvb, offset);
	unsigned payload_len;

	col_append_str(pinfo->cinfo, COL_INFO, "[ROS Msg] ");

	/** We got a ROS msg */
	ti = proto_tree_add_item(root_tree, hf_tcpros_message, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_NA | ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	proto_tree_add_item(sub_tree, hf_tcpros_message_length, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	/** Body */
	ti = proto_tree_add_item(sub_tree, hf_tcpros_message_body, tvb, offset + consumed_len, total_len, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	/** Body.Header */
	consumed_len += dissect_ros_message_header(tvb, sub_tree, pinfo, offset + consumed_len);

	/** Body.Payload */
	payload_len = (total_len + SIZE_OF_LENGTH_FIELD) - consumed_len;
	proto_tree_add_item(sub_tree, hf_tcpros_message_payload, tvb, offset + consumed_len, payload_len, ENC_NA);
	consumed_len += payload_len;


	return consumed_len;
}


/**
 * This is the poor man's way to differentiate between a connection header packet and a message packet.
 */
static bool
is_connection_header(tvbuff_t *tvb, packet_info *pinfo _U_ , unsigned offset)
{
	bool is_con_header = false;
	uint32_t len1 = tvb_get_letohl(tvb, offset);
	uint32_t len2 = tvb_get_letohl(tvb, offset + SIZE_OF_LENGTH_FIELD);


	if( len1 > len2 ) {
		is_con_header = true;
	}


	return is_con_header;
}

static bool
is_rosheaderfield(tvbuff_t *tvb, packet_info *pinfo _U_ , unsigned offset)
{
	/** ROS Header Field:
	    4-byte len + string */
	int available = tvb_reported_length_remaining(tvb, offset);
	uint32_t string_len = 0;
	uint32_t i;

	if( available < 4 )
		return false;

	string_len = tvb_get_letohl(tvb, offset);

	/** If we don't have enough data for the whole string, assume its not */
	if( (unsigned)available < (string_len + 4) )
		return false;
	/** Check for a valid ascii character and not nil */
	for( i = 0; i < string_len; i++ ) {
		int8_t ch = tvb_get_uint8(tvb, offset + 4 + i);
		if( !g_ascii_isalnum(ch) || 0x00 == ch )
			return false;
	}

	/** Assume it is */
	return true;
}

static bool
is_rosconnection_header(tvbuff_t *tvb, packet_info *pinfo _U_ , unsigned offset)
{
	/** ROS Connection Headers: http://wiki.ros.org/ROS/Connection%20Header
	    4-byte length + [4-byte length + string] */
	int available = tvb_reported_length_remaining(tvb, offset);
	uint32_t msg_len = 0;

	if( available < 8+1 )
		return false;

	msg_len = tvb_get_letohl(tvb, offset);
	if( msg_len < 4+1 )
		return false;

	/** Check first header field */
	if( !is_rosheaderfield(tvb, pinfo, offset + 4) )
		return false;


	return true;
}

static bool
is_rosclock(tvbuff_t *tvb, packet_info *pinfo _U_ , unsigned offset)
{
	/** ROS Clock message: http://docs.ros.org/api/rosgraph_msgs/html/msg/Clock.html
	    4-byte length + 8-byte timestamp == 12 bytes exactly */
	int available = tvb_reported_length_remaining(tvb, offset);
	if( available != 12 )
		return false;

	if( tvb_get_letohl(tvb, offset) != 8 )
		return false;

	/** This is highly likely a clock message. */
	return true;
}

static bool
is_rosmsg(tvbuff_t *tvb, packet_info *pinfo _U_ , unsigned offset)
{
	/** Most ROS messages start with a header: http://docs.ros.org/jade/api/std_msgs/html/msg/Header.html
	    4-byte size + 4-byte sequence id + 8-byte timestamp + 4-byte frame id length + frame id */
	int available = tvb_reported_length_remaining(tvb, offset);
	uint32_t string_len = 0;
	uint32_t msg_len = 0;

	if( available < 20 )
		return false;

	msg_len = tvb_get_letohl(tvb, offset);
	if( msg_len < 16 )
		return false;

	/** Check to see if the frame id length is reasonable */
	string_len = tvb_get_letohl(tvb, offset + 4 + 4 + 8);
	if( string_len > (msg_len - (4 + 8 + 4)) )
		return false;

	/** If we don't have enough data for the whole string, assume its not */
	if( (unsigned)available < (string_len + 4) )
		return false;

	/** This is highly likely a ROS message. */
	return true;
}

static void
dissect_ros_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool is_tcp _U_ )
{
	proto_item *ti;
	proto_tree *root_tree;

	unsigned offset;


	/** Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_tcpros, tvb, 0, -1, ENC_NA);
	root_tree = proto_item_add_subtree(ti, ett_tcpros);

	offset = 0;

	while(offset < tvb_reported_length(tvb)) {
		int available = tvb_reported_length_remaining(tvb, offset);

		if( (available < SIZE_OF_LENGTH_FIELD) || ((unsigned)available < tvb_get_letohl(tvb, offset)) ) {
			/** we ran out of data: ask for more */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return;
		}
		/** There are two types of packet: Connection Headers and ROS Message. Which one is it? */
		if( is_rosclock(tvb, pinfo, offset) ) {
			/** This is a ROS Clock message. */
			offset += dissect_ros_clock(tvb, root_tree, pinfo, offset);
		} else if( is_rosmsg(tvb, pinfo, offset) ) {
			/** We have a ROS message. */
			offset += dissect_ros_message(tvb, root_tree, pinfo, offset);
		} else if( is_rosconnection_header(tvb, pinfo, offset) ) {
			/** Check for a connection header */
			offset += dissect_ros_connection_header(tvb, root_tree, pinfo, offset);
		} else if( is_connection_header(tvb, pinfo, offset) ) {
			/** We have a ROS connection header. */
			offset += dissect_ros_connection_header(tvb, root_tree, pinfo, offset);
		} else {
			/** We have a ROS message. */
			offset += dissect_ros_message(tvb, root_tree, pinfo, offset);
		}

	}
}


static unsigned
get_tcpros_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t plen;

	/*
	 * Get the length of the TCPROS packet.
	 */
	plen = tvb_get_letohl(tvb, offset);

	/*
	 * That length doesn't include the length field itself; add that in.
	 */
	return plen + SIZE_OF_LENGTH_FIELD;
}


static int
dissect_tcpros_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCPROS");

	dissect_ros_common(tvb, pinfo, tree, true);
	return tvb_reported_length(tvb);
}

static int
dissect_tcpros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, tcpros_desegment, SIZE_OF_LENGTH_FIELD, get_tcpros_pdu_len,
			 dissect_tcpros_pdu, data);
	return tvb_reported_length(tvb);
}


void
proto_register_tcpros(void)
{
	static hf_register_info hf[] = {
		{ &hf_tcpros_connection_header,             { "ROS Connection", "tcpros.header",
							      FT_UINT_BYTES, BASE_NONE, NULL, 0,
							      "Message Header", HFILL } },
		{ &hf_tcpros_connection_header_length,      { "Header Length", "tcpros.header_length",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "Message Header Length", HFILL } },
		{ &hf_tcpros_connection_header_content,     { "Header Content", "tcpros.header_content",
							      FT_BYTES, BASE_NONE, NULL, 0,
							      "Message Header Content", HFILL } },

		{ &hf_tcpros_connection_header_field,       { "Field", "tcpros.header_field",
							      FT_UINT_STRING, BASE_NONE, NULL, 0,
							      "Message Header Field", HFILL } },
		{ &hf_tcpros_connection_header_field_length, { "Field Length", "tcpros.header_field_length",
							       FT_UINT32, BASE_DEC, NULL, 0,
							       "Message Header Field Length", HFILL } },
		{ &hf_tcpros_connection_header_field_data, { "Field Content", "tcpros.header_field_data",
							     FT_STRING, BASE_NONE, NULL, 0,
							     "Message Header Field Content", HFILL } },
		{ &hf_tcpros_connection_header_field_name,  { "Name", "tcpros.header_field_name",
							      FT_STRING, BASE_NONE, NULL, 0,
							      "Message Header Field Name", HFILL } },
		{ &hf_tcpros_connection_header_field_value, { "Value", "tcpros.header_field_value",
							      FT_STRING, BASE_NONE, NULL, 0,
							      "Message Header Field Value", HFILL } },

		{ &hf_tcpros_clock,                         { "ROS Clock", "tcpros.clock",
							      FT_UINT_BYTES, BASE_NONE, NULL, 0,
							      "ROS Clock Packet", HFILL } },
		{ &hf_tcpros_clock_length,                  { "Clock Length", "tcpros.clock.length",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "ROS Clock Packet length", HFILL } },

		{ &hf_tcpros_message,                       { "ROS Message", "tcpros.message",
							      FT_UINT_BYTES, BASE_NONE, NULL, 0,
							      "ROS Message Packet", HFILL } },
		{ &hf_tcpros_message_length,                { "Message Length", "tcpros.message.length",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "ROS Message Packet length", HFILL } },
		{ &hf_tcpros_message_body,                   { "Message Content", "tcpros.message.body",
							       FT_BYTES, BASE_NONE, NULL, 0,
							       "ROS Message Packet Body", HFILL } },

		{ &hf_tcpros_message_header,                { "Header", "tcpros.message.header",
							      FT_BYTES, BASE_NONE, NULL, 0,
							      "ROS Message Header", HFILL } },
		{ &hf_tcpros_message_header_seq,            { "Sequence ID", "tcpros.message.header.seq",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "ROS Message Header Sequence", HFILL } },
		{ &hf_tcpros_message_header_stamp,          { "Timestamp", "tcpros.message.header.stamp",
							      FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
							      "ROS Message Header Stamp", HFILL } },
		{ &hf_tcpros_message_header_stamp_sec,      { "Seconds", "tcpros.message.header.stamp.sec",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "ROS Message Header Stamp Sec", HFILL } },
		{ &hf_tcpros_message_header_stamp_nsec,     { "Nanoseconds", "tcpros.message.header.stamp.nsec",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "ROS Message Header Stamp NSec", HFILL } },

		{ &hf_tcpros_message_header_frame,          { "Frame ID", "tcpros.message.header.frame",
							      FT_UINT_STRING, BASE_NONE, NULL, 0,
							      "ROS Message Header Frame ID", HFILL } },
		{ &hf_tcpros_message_header_frame_length,   { "Length", "tcpros.message.header.frame.len",
							      FT_UINT32, BASE_DEC, NULL, 0,
							      "ROS Message Header Frame ID Length", HFILL } },
		{ &hf_tcpros_message_header_frame_value,     { "Value", "tcpros.message.header.frame.value",
							       FT_STRING, BASE_NONE, NULL, 0,
							       "ROS Message Header Frame ID Value", HFILL } },

		{ &hf_tcpros_message_payload,               { "Payload", "tcpros.message.payload",
							      FT_BYTES, BASE_NONE, NULL, 0,
							      "ROS Message Packet Payload", HFILL } },

	};

	static int *ett[] = {
		&ett_tcpros,
	};

	module_t *tcpros_module;

	proto_tcpros = proto_register_protocol("TCP based Robot Operating System protocol (TCPROS)", "TCPROS", "tcpros");

	proto_register_field_array(proto_tcpros, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	tcpros_handle = register_dissector("tcpros", dissect_tcpros, proto_tcpros);

	tcpros_module = prefs_register_protocol(proto_tcpros, NULL);

	prefs_register_bool_preference(tcpros_module, "desegment_tcpros_messages",
				       "Reassemble TCPROS messages spanning multiple TCP segments",
				       "Whether the TCPROS dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &tcpros_desegment);


}

/* Heuristics test */
static bool
test_tcpros(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
	if (tvb_captured_length(tvb) < 8)
		return false;

	if( is_rosclock(tvb, pinfo, offset) )
		return true;
	if( is_rosmsg(tvb, pinfo, offset) )
		return true;
	if( is_rosconnection_header(tvb, pinfo, offset) )
		return true;

	return false;
}

static bool
dissect_tcpros_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	conversation_t *conversation;

	if (!test_tcpros(pinfo, tvb, 0, data))
		return false;

	conversation = find_or_create_conversation(pinfo);
	conversation_set_dissector(conversation, tcpros_handle);

	dissect_tcpros(tvb, pinfo, tree, data);

	return true;
}



void
proto_reg_handoff_tcpros(void)
{
	dissector_add_for_decode_as_with_preference("tcp.port", tcpros_handle);   /* for "decode-as" */

	/* register as heuristic dissector */
	heur_dissector_add("tcp", dissect_tcpros_heur_tcp, "TCPROS over TCP",
				"tcpros_tcp", proto_tcpros, HEURISTIC_DISABLE);
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
