/* packet-rtmpt.c
 * Routines for Real Time Messaging Protocol packet dissection
 *
 * metatech <metatech@flashmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*  This dissector is called RTMPT to avoid a conflict with 
*   the other RTMP protocol (Routing Table Maintenance Protocol) implemented in packet-atalk.c
*   (RTMPT normally stands for RTMP-Tunnel via http)
*
*   RTMP in a nutshell
*
*   The protocol has very little "magic words" to facilitate detection,
*   but rather has "magic lengths".
*   This protocol has plenty of special cases and few general rules,
*   especially regarding the lengths and the structures.
*
*   Documentation:
*	RTMP protocol description on Wiki of Red5 Open Source Flash Server
*   Default TCP port is 1935
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

static int proto_rtmpt = -1;
static int hf_rtmpt_header_objid = -1;
static int hf_rtmpt_header_timestamp = -1;
static int hf_rtmpt_header_body_size = -1;
static int hf_rtmpt_header_function = -1;
static int hf_rtmpt_header_source = -1;
static int hf_rtmpt_handshake_data = -1;
static int hf_rtmpt_amf_type = -1;
static int hf_rtmpt_amf_number = -1;
static int hf_rtmpt_amf_boolean = -1;
static int hf_rtmpt_amf_string = -1;

static gint ett_rtmpt = -1;
static gint ett_rtmpt_header = -1;
static gint ett_rtmpt_body = -1;
static gint ett_rtmpt_object = -1;
static gint ett_rtmpt_property = -1;

static dissector_handle_t rtmpt_tcp_handle;

static gboolean rtmpt_desegment = TRUE;

#define RTMPT_MAGIC    0x03
#define RTMPT_HANDSHAKE_OFFSET_1    1
#define RTMPT_HANDSHAKE_OFFSET_2    1538
#define RTMPT_HANDSHAKE_OFFSET_3    3074
#define RTMPT_HANDSHAKE_LENGTH_1    1537
#define RTMPT_HANDSHAKE_LENGTH_2    3073
#define RTMPT_HANDSHAKE_LENGTH_3    1536
#define RTMPT_INVOKE_CHUNK_SIZE   128
#define RTMPT_AUDIO_CHUNK_SIZE    128
#define RTMPT_VIDEO_CHUNK_SIZE    1024
#define RTMPT_MAX_PACKET_SIZE     16384

#define RTMPT_TYPE_NUMBER         0x00
#define RTMPT_TYPE_BOOLEAN        0x01
#define RTMPT_TYPE_STRING         0x02
#define RTMPT_TYPE_OBJECT         0x03
#define RTMPT_TYPE_MOVIECLIP      0x04
#define RTMPT_TYPE_NULL           0x05
#define RTMPT_TYPE_UNDEFINED      0x06
#define RTMPT_TYPE_REFERENCE      0x07
#define RTMPT_TYPE_MIXED_ARRAY    0x08
#define RTMPT_TYPE_END_OF_OBJECT  0x09
#define RTMPT_TYPE_ARRAY          0x0A
#define RTMPT_TYPE_DATE           0x0B
#define RTMPT_TYPE_LONG_STRING    0x0C
#define RTMPT_TYPE_UNSUPPORTED    0x0D
#define RTMPT_TYPE_RECORDSET      0x0E
#define RTMPT_TYPE_XML            0x0F
#define RTMPT_TYPE_CLASS_OBJECT   0x10
#define RTMPT_TYPE_AMF3_OBJECT    0x11

#define RTMPT_TEXT_RTMP_HEADER  "RTMP Header"
#define RTMPT_TEXT_RTMP_BODY    "RTMP Body"
#define RTMPT_TEXT_AMF_OBJECT   "AMF Object"
#define RTMPT_TEXT_AMF_PROPERTY "AMF Object Property"

#define RTMPT_TYPE_CHUNK_SIZE         0x01
#define RTMPT_TYPE_BYTES_READ         0x03
#define RTMPT_TYPE_PING               0x04
#define RTMPT_TYPE_SERVER_BANDWIDTH   0x05
#define RTMPT_TYPE_CLIENT_BANDWIDTH   0x06
#define RTMPT_TYPE_AUDIO_DATA         0x08
#define RTMPT_TYPE_VIDEO_DATA         0x09
#define RTMPT_TYPE_FLEX_STREAM_SEND   0x0F
#define RTMPT_TYPE_FLEX_SHARED_OBJECT 0x10
#define RTMPT_TYPE_FLEX_MESSAGE       0x11
#define RTMPT_TYPE_NOTIFY             0x12
#define RTMPT_TYPE_SHARED_OBJECT      0x13
#define RTMPT_TYPE_INVOKE             0x14

#define RTMPT_TYPE_HANDSHAKE_1        0xFA
#define RTMPT_TYPE_HANDSHAKE_2        0xFB
#define RTMPT_TYPE_HANDSHAKE_3        0xFC

static const value_string rtmpt_opcode_vals[] = {
  { RTMPT_TYPE_CHUNK_SIZE,         "Chunk size" },
  { RTMPT_TYPE_BYTES_READ,         "Bytes Read" },
  { RTMPT_TYPE_PING,               "Ping" },
  { RTMPT_TYPE_SERVER_BANDWIDTH,   "Server BW" },
  { RTMPT_TYPE_CLIENT_BANDWIDTH,   "Client BW" },
  { RTMPT_TYPE_AUDIO_DATA,         "Audio Data" },
  { RTMPT_TYPE_VIDEO_DATA,         "Video Data" },
  { RTMPT_TYPE_FLEX_STREAM_SEND,   "Flex Stream" },
  { RTMPT_TYPE_FLEX_SHARED_OBJECT, "Flex Shared Object" },
  { RTMPT_TYPE_FLEX_MESSAGE,       "Flex Message" },
  { RTMPT_TYPE_NOTIFY,             "Notify" },
  { RTMPT_TYPE_SHARED_OBJECT,      "Shared Object" },
  { RTMPT_TYPE_INVOKE,             "Invoke" },
  { RTMPT_TYPE_HANDSHAKE_1,        "Handshake part 1" },
  { RTMPT_TYPE_HANDSHAKE_2,        "Handshake part 2" },
  { RTMPT_TYPE_HANDSHAKE_3,        "Handshake part 3" },
  { 0,          NULL }
};

static const value_string rtmpt_type_vals[] = {
  { RTMPT_TYPE_NUMBER,        "Number" },
  { RTMPT_TYPE_BOOLEAN,       "Boolean" },
  { RTMPT_TYPE_STRING,        "String" },
  { RTMPT_TYPE_OBJECT,        "Object" },
  { RTMPT_TYPE_MOVIECLIP,     "Movie clip" },
  { RTMPT_TYPE_NULL,          "Null" },
  { RTMPT_TYPE_UNDEFINED,     "Undefined" },
  { RTMPT_TYPE_REFERENCE,     "Reference" },
  { RTMPT_TYPE_MIXED_ARRAY,   "Mixed array" },
  { RTMPT_TYPE_END_OF_OBJECT, "End of object" },
  { RTMPT_TYPE_ARRAY,         "Array" },
  { RTMPT_TYPE_LONG_STRING,   "Long string" },
  { RTMPT_TYPE_UNSUPPORTED,   "Unsupported" },
  { RTMPT_TYPE_RECORDSET,     "Record set" },
  { RTMPT_TYPE_XML,           "XML" },
  { RTMPT_TYPE_CLASS_OBJECT,  "Class object" },
  { RTMPT_TYPE_AMF3_OBJECT,   "AMF3 object" },
  { 0,          NULL }
};


static gint rtmpt_header_length_from_type(gint iHeaderType) 
{
	gint iHeaderLength = 0;
	switch (iHeaderType) {
		case 0: iHeaderLength = 12; break;
		case 1: iHeaderLength = 8;  break;
		case 2: iHeaderLength = 4;  break;
		case 3: iHeaderLength = 1;  break;
		case 4: iHeaderLength = 1;  break; /* Handshake */
	}
	return iHeaderLength;
}	
	

static void
dissect_rtmpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rtmpt_tree = NULL;
	proto_tree	*rtmptroot_tree = NULL;
	proto_item	*ti = NULL;
	gint offset = 0;
	struct tcpinfo* tcpinfo = pinfo->private_data;
	static gint iPreviousFrameNumber = -1;

	guint16 iCommand = G_MAXUINT16;
	guint16 iLength = 1;
	guint16 iHeaderType = 4; 
	guint16 iHeaderLength;
	guint8 iID;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		/* This is a trick to know whether this is the first PDU in this packet or not */
		if (iPreviousFrameNumber != (gint) pinfo->fd->num) 
			col_clear(pinfo->cinfo, COL_INFO);
		else
			col_append_str(pinfo->cinfo, COL_INFO, " | ");
	}
	iPreviousFrameNumber = pinfo->fd->num;
	if (tvb_length_remaining(tvb, offset) >= 12)
	{
		if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_1 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_1) iCommand =  RTMPT_TYPE_HANDSHAKE_1;
		else if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_2 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_1) iCommand =  RTMPT_TYPE_HANDSHAKE_2;
		else if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_3 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_2 
			&& tvb_length(tvb) == RTMPT_HANDSHAKE_LENGTH_3) iCommand = RTMPT_TYPE_HANDSHAKE_3;
		else 
		{
			iID = tvb_get_guint8(tvb, offset + 0);
			iHeaderType = iID >> 6;
			if (iHeaderType <= 2) iLength = tvb_get_ntoh24(tvb, offset + 4);
			if (iHeaderType <= 1) iCommand = tvb_get_guint8(tvb, offset + 7);
			if (iHeaderType >= 2) iCommand = RTMPT_TYPE_AUDIO_DATA;
		}

		iHeaderLength = rtmpt_header_length_from_type(iHeaderType);
		if (check_col(pinfo->cinfo, COL_INFO)) 
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(iCommand, rtmpt_opcode_vals, "Unknown (0x%01x)"));
		}

		if (tree)
		{
			gint iChunkSize = RTMPT_INVOKE_CHUNK_SIZE;
			ti = proto_tree_add_item(tree, proto_rtmpt, tvb, offset, -1, FALSE);
			proto_item_append_text(ti, " (%s)", val_to_str(iCommand, rtmpt_opcode_vals, "Unknown (0x%01x)"));
			rtmptroot_tree = proto_item_add_subtree(ti, ett_rtmpt);

			ti = proto_tree_add_text(rtmptroot_tree, tvb, offset, iHeaderLength, RTMPT_TEXT_RTMP_HEADER);
			proto_item_append_text(ti, " (%s)", val_to_str(iCommand, rtmpt_opcode_vals, "Unknown (0x%01x)"));
			rtmpt_tree = proto_item_add_subtree(ti, ett_rtmpt_header);

			if (iHeaderType <= 3) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_objid, tvb, offset + 0, 1, FALSE);
			if (iHeaderType <= 2) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_timestamp, tvb, offset + 1, 3, FALSE);
			if (iHeaderType <= 1) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_body_size, tvb, offset + 4, 3, FALSE);
			if (iHeaderType <= 1) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_function, tvb, offset + 7, 1, FALSE);
			if (iHeaderType <= 0) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_source, tvb, offset + 8, 4, TRUE);

			if (iCommand == RTMPT_TYPE_HANDSHAKE_1)
			{
				proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_data, tvb, 1, 1536, FALSE);				
			} 
			else if (iCommand == RTMPT_TYPE_HANDSHAKE_2)
			{
				proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_data, tvb, 1, 1536, FALSE);				
				proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_data, tvb, 1537, 1536, FALSE);								
			}
			else if (iCommand == RTMPT_TYPE_HANDSHAKE_3)
			{
				proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_data, tvb, 0, -1, FALSE);				
			} 

			switch (iCommand) {
				case RTMPT_TYPE_INVOKE:     iChunkSize = RTMPT_INVOKE_CHUNK_SIZE; break;
				case RTMPT_TYPE_AUDIO_DATA: iChunkSize = RTMPT_AUDIO_CHUNK_SIZE; break;
				case RTMPT_TYPE_VIDEO_DATA: iChunkSize = RTMPT_VIDEO_CHUNK_SIZE; break;
			}

			if (tvb_length_remaining(tvb, offset) > iChunkSize && (iCommand == RTMPT_TYPE_VIDEO_DATA || iCommand == RTMPT_TYPE_INVOKE)
				&& (tvb_get_guint8(tvb, offset + rtmpt_header_length_from_type(iHeaderType) + iChunkSize) >> 6) == 3)
			{ 
				gint iChunk;
				gint nbChunks; 
				tvbuff_t* dechunked_tvb = tvb_new_composite();
				offset = iHeaderLength;
				nbChunks = tvb_length_remaining(tvb, iHeaderLength) / iChunkSize;
							
				for (iChunk = 0; iChunk < nbChunks + 1; iChunk++) 
				{
					tvbuff_t* chunkBuffer;					
					if (tvb_length_remaining(tvb, offset) < iChunkSize) iChunkSize = tvb_length_remaining(tvb, offset);
					chunkBuffer = tvb_new_subset(tvb, offset, iChunkSize, iChunkSize);
					tvb_composite_append(dechunked_tvb, chunkBuffer);
					offset += iChunkSize + 1; /* Skip inter-chunk */
				}
				tvb_composite_finalize(dechunked_tvb);				
				add_new_data_source(pinfo, dechunked_tvb, "Unchunked RTMP");
			}

			offset = iHeaderLength;
			ti = proto_tree_add_text(rtmptroot_tree, tvb, offset, -1, RTMPT_TEXT_RTMP_BODY); 
			rtmpt_tree = proto_item_add_subtree(ti, ett_rtmpt_body);
			
			if (iCommand == RTMPT_TYPE_INVOKE || iCommand == RTMPT_TYPE_NOTIFY)
			{
				while (tvb_length_remaining(tvb, offset) > 0) 
				{
					guint8 iObjType = 0;
					guint16 iStringLength = 0;
					gint iObjectLength = 0;
					proto_tree	*rtmpt_tree_object = NULL;		
					proto_item	*ti_object = NULL;
					iObjType = tvb_get_guint8(tvb, offset + 0);
					proto_tree_add_item(rtmpt_tree, hf_rtmpt_amf_type, tvb, offset + 0, 1, FALSE);
					offset += 1;
	
					switch (iObjType) {
						case RTMPT_TYPE_NUMBER:  
							proto_tree_add_item(rtmpt_tree, hf_rtmpt_amf_number, tvb, offset + 0, 8, FALSE);
							offset += 8;
							break;
						case RTMPT_TYPE_BOOLEAN: 
							proto_tree_add_item(rtmpt_tree, hf_rtmpt_amf_boolean, tvb, offset + 0, 1, FALSE);
							offset += 1;
							break;
						case RTMPT_TYPE_STRING:  
							iStringLength = tvb_get_ntohs(tvb, offset + 0);
							proto_tree_add_item(rtmpt_tree, hf_rtmpt_amf_string, tvb, offset + 2, iStringLength, FALSE);
							offset += 2 + iStringLength;
							break;
						case RTMPT_TYPE_OBJECT:  
							ti_object = proto_tree_add_text(rtmpt_tree, tvb, offset, 1, RTMPT_TEXT_AMF_OBJECT); 
							rtmpt_tree_object = proto_item_add_subtree(ti_object, ett_rtmpt_object);
							for (;;) 
							{
								gint iPropertyLength = 0;
								proto_tree	*rtmpt_tree_prop = NULL;		
								if (tvb_length_remaining(tvb, offset) <= 0) break;
								iObjType = tvb_get_guint8(tvb, offset + 0);								
								if (iObjType != 0x00) break;
								if (tvb_get_guint8(tvb, offset + 1) == 0 && tvb_get_guint8(tvb, offset + 2) == RTMPT_TYPE_END_OF_OBJECT) 
								{
									/* End of objet marker */
									offset += 2;
									break;
								}
								ti = proto_tree_add_text(rtmpt_tree_object, tvb, offset, 1, RTMPT_TEXT_AMF_PROPERTY);
								rtmpt_tree_prop = proto_item_add_subtree(ti, ett_rtmpt_property);

								/* Property name */
								iStringLength = tvb_get_guint8(tvb, offset + 1);	
								proto_tree_add_item(rtmpt_tree_prop, hf_rtmpt_amf_string, tvb, offset + 2, iStringLength, FALSE);
								offset += 2 + iStringLength;
								iPropertyLength = 2 + iStringLength;
								
								/* Property value */
								iObjType = tvb_get_guint8(tvb, offset + 0);
								switch (iObjType) {
									case RTMPT_TYPE_NUMBER:  
										proto_tree_add_item(rtmpt_tree_prop, hf_rtmpt_amf_number, tvb, offset + 1, 8, FALSE);
										offset += 9;
										iPropertyLength += 9;
										break;
									case RTMPT_TYPE_BOOLEAN: 
										proto_tree_add_item(rtmpt_tree_prop, hf_rtmpt_amf_boolean, tvb, offset + 1, 1, FALSE);
										offset += 2;
										iPropertyLength += 2;
										break;
									case RTMPT_TYPE_STRING:  
										iStringLength = tvb_get_ntohs(tvb, offset + 1);
										proto_tree_add_item(rtmpt_tree_prop, hf_rtmpt_amf_string, tvb, offset + 3, iStringLength, FALSE);
										offset += 3 + iStringLength;
										iPropertyLength += 3 + iStringLength;
										break;
								}
								proto_item_set_len(ti, iPropertyLength);
								iObjectLength += 1 + iPropertyLength;	
							}
							proto_item_set_len(ti_object, iObjectLength);
							break;
	
					}
				}
			}			
		}
	}
}

static guint
get_rtmpt_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint returned = 0;
	struct tcpinfo *tcpinfo = pinfo->private_data;
	if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_1 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_1) returned =  RTMPT_HANDSHAKE_LENGTH_1;
	else if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_2 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_1) returned =  RTMPT_HANDSHAKE_LENGTH_2;
	else if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_3 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_2 
		&& tcpinfo->nxtseq - tcpinfo->seq - tvb_length(tvb) != RTMPT_HANDSHAKE_LENGTH_3) returned = RTMPT_HANDSHAKE_LENGTH_3;
	else 
	{
		guint16 iHeaderType;
		guint8 iID;
		guint16 iCommand = G_MAXUINT16;

		iID = tvb_get_guint8(tvb, offset + 0);
		iHeaderType = iID >> 6;
		if (iHeaderType <= 1 && tvb_length_remaining(tvb, offset) >= 8) iCommand = tvb_get_guint8(tvb, offset + 7);
		if (iHeaderType == 0 && tvb_length_remaining(tvb, offset) >= 7) returned = 12 + tvb_get_ntoh24(tvb, offset + 4);
		if (iHeaderType == 1 && tvb_length_remaining(tvb, offset) >= 7) returned =  8 + tvb_get_ntoh24(tvb, offset + 4);
		if (iCommand == RTMPT_TYPE_VIDEO_DATA) returned += returned / RTMPT_VIDEO_CHUNK_SIZE;
		if (iCommand == RTMPT_TYPE_INVOKE || iCommand == RTMPT_TYPE_NOTIFY) 
		{
			/* Educated guess whether the message is chunked or not */
			if (tvb_length_remaining(tvb, offset + rtmpt_header_length_from_type(iHeaderType)) >= RTMPT_INVOKE_CHUNK_SIZE
				&& (tvb_get_guint8(tvb, offset + rtmpt_header_length_from_type(iHeaderType) + RTMPT_INVOKE_CHUNK_SIZE) >> 6) == 3)
				returned += returned / RTMPT_INVOKE_CHUNK_SIZE;
		}
		if (iHeaderType == 2) returned = 5 + RTMPT_AUDIO_CHUNK_SIZE;  /* Most probably audio */
		if (iHeaderType == 3) returned = 2 + RTMPT_AUDIO_CHUNK_SIZE;  /* Most probably audio */
	}
	if (returned >= RTMPT_MAX_PACKET_SIZE) returned = 0;
	return returned;
}

static void
dissect_rtmpt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, rtmpt_desegment, 12, get_rtmpt_pdu_len, dissect_rtmpt);
}

static gboolean
dissect_rtmpt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	conversation_t * conversation;
	if (tvb_length(tvb) >= 12)
	{
		/* To avoid a too high rate of false positive, this heurisitics only matches the protocol 
		   from the first server response packet and not from the client request packets before.
		   Therefore it is necessary to a "Decode as" to properly decode the first packets */
		struct tcpinfo *tcpinfo = pinfo->private_data;
		if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_2 && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_1 && tvb_get_guint8(tvb, 0) == RTMPT_MAGIC)
		{
			/* Register this dissector for this conversation */
			conversation = NULL;
			conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			if (conversation == NULL)
			{
				conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			}
			conversation_set_dissector(conversation, rtmpt_tcp_handle);

			/* Dissect the packet */
			dissect_rtmpt(tvb, pinfo, tree);
			return TRUE;
		}
	}
	return FALSE;
}

void
proto_register_rtmpt(void)
{
  static hf_register_info hf[] = {
   { &hf_rtmpt_header_objid,
      { "ObjectID", "rtmpt.header.objid", FT_UINT8, BASE_DEC, NULL, 0x3F, "RTMPT Header object ID", HFILL }},

   { &hf_rtmpt_header_timestamp,
      { "Timestamp", "rtmpt.header.timestamp", FT_UINT24, BASE_DEC, NULL, 0x0, "RTMPT Header timestamp", HFILL }},

   { &hf_rtmpt_header_body_size,
      { "Body size", "rtmpt.header.bodysize", FT_UINT24, BASE_DEC, NULL, 0x0, "RTMPT Header body size", HFILL }},

   { &hf_rtmpt_header_function,
      { "Function call", "rtmpt.header.function", FT_UINT8, BASE_HEX, VALS(rtmpt_opcode_vals), 0x0, "RTMPT Header function call", HFILL }},

   { &hf_rtmpt_header_source,
      { "Caller source", "rtmpt.header.caller", FT_UINT32, BASE_DEC, NULL, 0x0, "RTMPT Header caller source", HFILL }},

   { &hf_rtmpt_handshake_data,
      { "Handshake data", "rtmpt.header.handshake", FT_BYTES, BASE_HEX, NULL, 0x0, "RTMPT Header handshake data", HFILL }},

   { &hf_rtmpt_amf_type,
      { "AMF type", "rtmpt.amf.type", FT_UINT8, BASE_DEC, VALS(rtmpt_type_vals), 0x0, "RTMPT AMF type", HFILL }},

   { &hf_rtmpt_amf_number,
      { "AMF number", "rtmpt.amf.number", FT_DOUBLE, BASE_DEC, NULL, 0x0, "RTMPT AMF number", HFILL }},

   { &hf_rtmpt_amf_boolean,
      { "AMF boolean", "rtmpt.amf.boolean", FT_BOOLEAN, BASE_DEC, NULL, 0x0, "RTMPT AMF boolean", HFILL }},

   { &hf_rtmpt_amf_string,
      { "AMF string", "rtmpt.amf.string", FT_STRINGZ, BASE_DEC, NULL, 0x0, "RTMPT AMF string", HFILL }}


  };
  static gint *ett[] = {
    &ett_rtmpt,
    &ett_rtmpt_header,    
    &ett_rtmpt_body,    
    &ett_rtmpt_object,    
    &ett_rtmpt_property    
  };

  module_t *rtmpt_module;

  proto_rtmpt = proto_register_protocol("Real Time Messaging Protocol", "RTMPT", "rtmpt");
  proto_register_field_array(proto_rtmpt, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rtmpt_module = prefs_register_protocol(proto_rtmpt, NULL);
  prefs_register_bool_preference(rtmpt_module, "desegment",
    "Reassemble RTMPT messages spanning multiple TCP segments",
    "Whether the RTMPT dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &rtmpt_desegment);
  
}

void
proto_reg_handoff_rtmpt(void)
{
	heur_dissector_add("tcp", dissect_rtmpt_heur, proto_rtmpt);
	rtmpt_tcp_handle = create_dissector_handle(dissect_rtmpt_tcp, proto_rtmpt);
	dissector_add_handle("tcp.port", rtmpt_tcp_handle);
}
