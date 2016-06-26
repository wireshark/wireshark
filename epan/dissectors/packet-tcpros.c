/* packet-tcpros.c
 * Routines for Robot Operating System TCP protocol (TCPROS)
 * Copyright 2015, Guillaume Autran  (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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


static int proto_tcpros = -1;

/** desegmentation of TCPROS over TCP */
static gboolean tcpros_desegment = TRUE;


static int hf_tcpros_connection_header = -1;
static int hf_tcpros_connection_header_length = -1;
static int hf_tcpros_connection_header_content = -1;
static int hf_tcpros_connection_header_field = -1;
static int hf_tcpros_connection_header_field_length = -1;
static int hf_tcpros_connection_header_field_data = -1;
static int hf_tcpros_connection_header_field_name = -1;
static int hf_tcpros_connection_header_field_value = -1;
static int hf_tcpros_message = -1;
static int hf_tcpros_message_length = -1;
static int hf_tcpros_message_body = -1;
static int hf_tcpros_message_header = -1;
static int hf_tcpros_message_header_seq = -1;
static int hf_tcpros_message_header_stamp = -1;
static int hf_tcpros_message_header_stamp_sec = -1;
static int hf_tcpros_message_header_stamp_nsec = -1;
static int hf_tcpros_message_header_frame = -1;
static int hf_tcpros_message_header_frame_length = -1;
static int hf_tcpros_message_header_frame_value = -1;
static int hf_tcpros_message_payload = -1;

static gint ett_tcpros = -1;

/**
 * This is the ROS connection header dissector. The general packet format is described
 * here: http://wiki.ros.org/ROS/TCPROS
 * In short, a connection header looks like such: '4-byte length + [4-byte field length + "field=value" ]*'
 */
static gint
dissect_ros_connection_header_field(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset)
{
	proto_item *ti;
	proto_tree *field_tree;

	guint32 fLen = 0;
	gint  sep, ret = 0;

	/** Do we have enough for a length field? (ie: 4 bytes) */
	if( tvb_reported_length_remaining(tvb, offset) > SIZE_OF_LENGTH_FIELD ) {
		/** Get the length of the next field */
		fLen = tvb_get_letohl(tvb, offset);

		/** Display the field as a utf-8 string */
		ti = proto_tree_add_item(tree, hf_tcpros_connection_header_field, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_UTF_8|ENC_LITTLE_ENDIAN);
		field_tree = proto_item_add_subtree(ti, ett_tcpros);


		proto_tree_add_item(field_tree, hf_tcpros_connection_header_field_length, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
		offset += SIZE_OF_LENGTH_FIELD;
		ti = proto_tree_add_item(field_tree, hf_tcpros_connection_header_field_data, tvb, offset, fLen, ENC_UTF_8|ENC_NA);

		/** Look for the '=' separator */
		sep = (tvb_find_guint8(tvb, offset, fLen, '=') - offset);

		/** If we find a separator, then split field name and value */
		if( sep > 0 ) {
			const guint8* field;
			field_tree = proto_item_add_subtree(ti, ett_tcpros);
			proto_tree_add_item_ret_string(field_tree, hf_tcpros_connection_header_field_name, tvb, offset, sep, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &field);
			proto_tree_add_item(field_tree, hf_tcpros_connection_header_field_value, tvb, offset+sep+1, fLen - sep - 1, ENC_UTF_8|ENC_NA);

			col_append_str(pinfo->cinfo, COL_INFO, field);
		}
		ret = fLen + SIZE_OF_LENGTH_FIELD;
	}

	return ret;
}

static gint
dissect_ros_connection_header(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, gint offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	gint consumed_len = 0;
	guint32 header_len = tvb_get_letohl(tvb, offset);

	col_append_str(pinfo->cinfo, COL_INFO, "[ROS Conn] Metadata: [");

	/** We got a connection header */
	ti = proto_tree_add_item(root_tree, hf_tcpros_connection_header, tvb, offset, SIZE_OF_LENGTH_FIELD, ENC_NA|ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	proto_tree_add_item(sub_tree, hf_tcpros_connection_header_length, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	consumed_len += SIZE_OF_LENGTH_FIELD;

	ti = proto_tree_add_item(sub_tree, hf_tcpros_connection_header_content, tvb, offset + consumed_len, header_len, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	header_len += SIZE_OF_LENGTH_FIELD;

	while( consumed_len < (gint)header_len ) {
		gint len = dissect_ros_connection_header_field(tvb, sub_tree, pinfo, offset + consumed_len);
		consumed_len += len;
		if( len == 0 ) {
			break;
		}
		if( consumed_len < (gint)header_len ) {
			col_append_str(pinfo->cinfo, COL_INFO, ",");
		}
	}
	col_append_str(pinfo->cinfo, COL_INFO, "]");

	return consumed_len;
}


static gint
dissect_ros_message_header_stamp(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, gint offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	gint consumed_len = 0;
	guint32 sec, nsec;


	ti = proto_tree_add_item(root_tree, hf_tcpros_message_header_stamp, tvb, offset + consumed_len, SIZE_OF_LENGTH_STAMP, ENC_LITTLE_ENDIAN);
	sub_tree = proto_item_add_subtree(ti, ett_tcpros);

	/** Seconds */
	proto_tree_add_item(sub_tree, hf_tcpros_message_header_stamp_sec, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	sec = tvb_get_letohl(tvb, offset + consumed_len);
	consumed_len += SIZE_OF_LENGTH_FIELD;
	col_append_fstr(pinfo->cinfo, COL_INFO, "Sec: %d ", sec);

	/** Nano seconds */
	proto_tree_add_item(sub_tree, hf_tcpros_message_header_stamp_nsec, tvb, offset + consumed_len, SIZE_OF_LENGTH_FIELD, ENC_LITTLE_ENDIAN);
	nsec = tvb_get_letohl(tvb, offset + consumed_len);
	consumed_len += SIZE_OF_LENGTH_FIELD;
	col_append_fstr(pinfo->cinfo, COL_INFO, "NSec: %d ", nsec);

	return consumed_len;
}

static gint
dissect_ros_message_header(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, gint offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	gint consumed_len = 0;
	guint32 frame_id_len;
	guint32 seq;
	guint header_len;
	const guint8* frame_str;


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

	proto_tree_add_item_ret_string(sub_tree, hf_tcpros_message_header_frame_value, tvb, offset + consumed_len, frame_id_len, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &frame_str);
	col_append_fstr(pinfo->cinfo, COL_INFO, "Frame: '%s' ",	frame_str);
	consumed_len += frame_id_len;

	return consumed_len;
}


/**
 * This is the ROS message dissector. A ROS message contains two parts: a msg header; a msg payload.
 * Because the packet is all in binary format, we don't really know the payload format (we don't know the payload type either).
 * However, every packet has the same header as defined here: http://docs.ros.org/api/std_msgs/html/msg/Header.html
 * So, we can break this one down and display it.
 */
static gint
dissect_ros_message(tvbuff_t *tvb, proto_tree *root_tree, packet_info *pinfo, gint offset)
{
	proto_item *ti;
	proto_tree *sub_tree;

	gint consumed_len = 0;
	guint32 total_len = tvb_get_letohl(tvb, offset);
	guint payload_len;

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
static gboolean
is_connection_header(tvbuff_t *tvb, packet_info *pinfo _U_ , guint offset)
{
	gboolean is_con_header = FALSE;
	guint32 len1 = tvb_get_letohl(tvb, offset);
	guint32 len2 = tvb_get_letohl(tvb, offset + SIZE_OF_LENGTH_FIELD);


	if( len1 > len2 ) {
		is_con_header = TRUE;
	}


	return is_con_header;
}

static void
dissect_ros_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_tcp _U_ )
{
	proto_item *ti;
	proto_tree *root_tree;

	guint offset;


	/** Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_tcpros, tvb, 0, -1, ENC_NA);
	root_tree = proto_item_add_subtree(ti, ett_tcpros);

	offset = 0;

	while(offset < tvb_reported_length(tvb)) {
		gint available = tvb_reported_length_remaining(tvb, offset);

		if( (available < SIZE_OF_LENGTH_FIELD) || ((guint)available < tvb_get_letohl(tvb, offset)) ) {
			/** we ran out of data: ask for more */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return;
		}
		/** There are two types of packet: Connection Headers and ROS Message. Which one is it? */
		if( is_connection_header(tvb, pinfo, offset) ) {
			/** We have a ROS connection header. */
			offset += dissect_ros_connection_header(tvb, root_tree, pinfo, offset);
		} else {
			/** We have a ROS message. */
			offset += dissect_ros_message(tvb, root_tree, pinfo, offset);
		}

	}
}


static guint
get_tcpros_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint32 plen;

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

	dissect_ros_common(tvb, pinfo, tree, TRUE);
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

	static gint *ett[] = {
		&ett_tcpros,
	};

	module_t *tcpros_module;

	proto_tcpros = proto_register_protocol("TCP based Robot Operating System protocol (TCPROS)", "TCPROS", "tcpros");

	proto_register_field_array(proto_tcpros, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	tcpros_module = prefs_register_protocol(proto_tcpros, proto_reg_handoff_tcpros);

	prefs_register_bool_preference(tcpros_module, "desegment_tcpros_messages",
				       "Reassemble TCPROS messages spanning multiple TCP segments",
				       "Whether the TCPROS dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &tcpros_desegment);


}


void
proto_reg_handoff_tcpros(void)
{
	static dissector_handle_t tcpros_handle;
	static gboolean Initialized = FALSE;

	if (!Initialized) {
		tcpros_handle = create_dissector_handle(dissect_tcpros, proto_tcpros);
		dissector_add_for_decode_as("tcp.port", tcpros_handle);   /* for "decode-as" */
		Initialized    = TRUE;
	}
}



/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
