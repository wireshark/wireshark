/* packet-rmi.c
 * Routines for java rmiregistry dissection
 * Copyright 2002, Michael Stiller <ms@2scale.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-rmi.h"

static void
dissect_ser(tvbuff_t *tvb, proto_tree *tree);

static rmi_type
get_rmi_type(tvbuff_t *tvb, gint offset, int datalen);

/* Initialize the protocol and registered fields */
static int proto_rmi             = -1;
static int proto_ser             = -1;
static int hf_rmi_magic          = -1;
static int hf_rmi_version        = -1;
static int hf_rmi_protocol       = -1;
static int hf_rmi_inputmessage   = -1;
static int hf_rmi_outputmessage  = -1;
static int hf_rmi_epid_length    = -1;
static int hf_rmi_epid_hostname  = -1;
static int hf_rmi_epid_port      = -1;

static int hf_ser_magic          = -1;
static int hf_ser_version        = -1;

/* Initialize the subtree pointers */
static gint ett_rmi               = -1;
static gint ett_rmi_magic         = -1;
static gint ett_rmi_version       = -1;
static gint ett_rmi_inputmessage  = -1;
static gint ett_rmi_outputmessage = -1;
static gint ett_rmi_epid_length   = -1;
static gint ett_rmi_epid_hostname = -1;
static gint ett_rmi_epid_port     = -1;

static gint ett_ser               = -1;

/*
 * See
 *
 *	http://java.sun.com/products/jdk/1.2/docs/guide/rmi/spec/rmi-protocol.doc1.html
 *
 * for RMI, and
 *
 *	http://java.sun.com/products/jdk/1.2/docs/guide/serialization/spec/protocol.doc.html
 *
 * for the serialization protocol.
 */

#define TCP_PORT_RMI	1099

static const value_string rmi_protocol_str[] = {
    {RMI_OUTPUTSTREAM_PROTOCOL_STREAM,    "StreamProtocol"},
    {RMI_OUTPUTSTREAM_PROTOCOL_SINGLEOP,  "SingleOpProtocol"},
    {RMI_OUTPUTSTREAM_PROTOCOL_MULTIPLEX, "MultiPlexProtocol"},
    {0, NULL}
};

static const value_string rmi_output_message_str[] = {
    {RMI_OUTPUTSTREAM_MESSAGE_CALL,       "Call"},
    {RMI_OUTPUTSTREAM_MESSAGE_PING,       "Ping"},
    {RMI_OUTPUTSTREAM_MESSAGE_DGCACK,     "DgcAck"},
    {0, NULL}
};

static const value_string rmi_input_message_str[] = {
    {RMI_INPUTSTREAM_MESSAGE_ACK,          "ProtocolAck"},
    {RMI_INPUTSTREAM_MESSAGE_NOTSUPPORTED, "ProtocolNotSupported"},
    {RMI_INPUTSTREAM_MESSAGE_RETURNDATA,   "ReturnData"},
    {RMI_INPUTSTREAM_MESSAGE_PINGACK,      "PingAck"},
    {0, NULL}
};

static void
dissect_rmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *rmi_tree;

    tvbuff_t   *next_tvb;

    gint       offset;
    gint       next_offset;
    int        datalen;

    guint16    version, len, port;
    guint8     message, proto;

    rmi_type   rmitype;

    const char *epid_hostname;
    guint epid_len;

    offset     = 0;
    rmitype    = 0;

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMI");

    datalen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

    rmitype = get_rmi_type(tvb, offset, datalen);

    if (check_col(pinfo->cinfo, COL_INFO)) {
	switch(rmitype) {
	case RMI_OUTPUTSTREAM:
	    version = tvb_get_ntohs(tvb,4);
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "JRMI, Version: %d, ", version);

	    proto   = tvb_get_guint8(tvb, 6);
	    col_append_str(pinfo->cinfo, COL_INFO,
			   val_to_str_const(proto, rmi_protocol_str,
					    "Unknown protocol"));
	    break;
	case RMI_OUTPUTMESSAGE:
	    message = tvb_get_guint8(tvb,0);
	    col_set_str(pinfo->cinfo, COL_INFO,
			"JRMI, ");
	    col_append_str(pinfo->cinfo, COL_INFO,
			   val_to_str_const(message, rmi_output_message_str,
					    "Unknown message"));
	    break;
	case RMI_INPUTSTREAM:
	    message = tvb_get_guint8(tvb,0);
	    col_set_str(pinfo->cinfo, COL_INFO,
			"JRMI, ");
	    col_append_str(pinfo->cinfo, COL_INFO,
			   val_to_str_const(message, rmi_input_message_str,
					    "Unknown message"));
	    break;
	case SERIALIZATION_DATA:
	    version = tvb_get_ntohs(tvb,2);
	    col_add_fstr(pinfo->cinfo, COL_INFO,
			 "Serialization data, Version: %d", version);
	    break;
	default:
	    col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	    break;
	}
    }

    if (tree) {
	ti = proto_tree_add_item(tree, proto_rmi, tvb, 0, -1, ENC_NA);
	rmi_tree = proto_item_add_subtree(ti, ett_rmi);
	switch(rmitype) {
	case RMI_OUTPUTSTREAM:
	    /* XXX - uint, or string? */
	    proto_tree_add_uint(rmi_tree, hf_rmi_magic,
				tvb, offset,     4, tvb_get_ntohl(tvb,0));
	    proto_tree_add_item(rmi_tree, hf_rmi_version,
				tvb, offset + 4, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(rmi_tree, hf_rmi_protocol,
				  tvb, offset + 6, 1, ENC_BIG_ENDIAN);
	    break;
	case RMI_INPUTSTREAM:
	    message = tvb_get_guint8(tvb, 0);
	    proto_tree_add_uint(rmi_tree, hf_rmi_inputmessage,
				  tvb, offset, 1, message);
	    if(message == RMI_INPUTSTREAM_MESSAGE_ACK) {
		proto_tree_add_text(rmi_tree, tvb, offset + 1, -1,
				    "EndPointIdentifier");
		/* MESSAGE_ACK should include EndpointIdentifier */
		len = tvb_get_ntohs(tvb, 1);
		proto_tree_add_uint(rmi_tree, hf_rmi_epid_length,
				       tvb, offset + 1, 2, len);
		epid_len = len < ITEM_LABEL_LENGTH ? len : ITEM_LABEL_LENGTH;
		if (epid_len > 0) {
			epid_hostname = tvb_format_text(tvb, offset + 3, epid_len);
		} else {
			epid_hostname = "[Empty]";
		}
		proto_tree_add_string(rmi_tree, hf_rmi_epid_hostname,
				      tvb, offset + 3, len, epid_hostname);

		port = tvb_get_ntohs(tvb, offset + len + 5);
  		proto_tree_add_uint(rmi_tree, hf_rmi_epid_port,
  				    tvb, offset + len + 5, 2, port);
	    }
	    if(message == RMI_INPUTSTREAM_MESSAGE_RETURNDATA) {
		proto_tree_add_text(rmi_tree, tvb, offset + 1, -1,
				    "Serialization Data");
		next_tvb = tvb_new_subset_remaining(tvb, offset + 1);
		dissect_ser(next_tvb, tree);
	    }
	    break;
	case RMI_OUTPUTMESSAGE:
	    message = tvb_get_guint8(tvb, 0);
	    proto_tree_add_uint(rmi_tree, hf_rmi_outputmessage,
				  tvb, offset, 1, message);
	    if(message == RMI_OUTPUTSTREAM_MESSAGE_CALL) {
		proto_tree_add_text(rmi_tree, tvb, offset + 1, -1,
				    "Serialization Data");
		/* XXX */
		next_tvb = tvb_new_subset_remaining(tvb, offset + 1);
		dissect_ser(next_tvb, tree);
	    }
	    if(message == RMI_OUTPUTSTREAM_MESSAGE_DGCACK) {
		proto_tree_add_text(rmi_tree, tvb, offset + 1, -1,
				    "UniqueIdentifier");
	    }
	    break;
	case SERIALIZATION_DATA:
	    dissect_ser(tvb, tree);
	    break;
	default:
	    break;
	}
    }
}

static void
dissect_ser(tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *ser_tree;

    gint offset;

    offset = 0;

    if(tree) {
	ti = proto_tree_add_item(tree, proto_ser, tvb, 0, -1, ENC_NA);
	ser_tree = proto_item_add_subtree(ti, ett_ser);
	proto_tree_add_item(ser_tree, hf_ser_magic,
			    tvb, offset,     2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ser_tree, hf_ser_version,
			    tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    }
}

static rmi_type
get_rmi_type(tvbuff_t *tvb, gint offset, int datalen)
{
    guint16 ser_magic;
    guchar data[4];

    tvb_memcpy(tvb, data, offset, (datalen > 4) ? 4 : datalen);

    if (datalen >= 2) {
	ser_magic = data[0] << 8 | data[1];
	if (ser_magic == SER_STREAM_MAGIC) {
	    return SERIALIZATION_DATA;
	}
    }
    if (datalen >= 4) {
	if(strncmp(data, RMI_MAGIC, 4) == 0) {
	    return RMI_OUTPUTSTREAM;
	}
    }
    if (datalen >= 1) {
	if (data[0] == RMI_INPUTSTREAM_MESSAGE_ACK ||
	    data[0] == RMI_INPUTSTREAM_MESSAGE_NOTSUPPORTED ||
	    data[0] == RMI_INPUTSTREAM_MESSAGE_RETURNDATA ||
	    data[0] == RMI_INPUTSTREAM_MESSAGE_PINGACK) {
	    return RMI_INPUTSTREAM;
	}
    }
    if (datalen >= 1) {
	if (data[0] == RMI_OUTPUTSTREAM_MESSAGE_CALL ||
	    data[0] == RMI_OUTPUTSTREAM_MESSAGE_PING ||
	    data[0] == RMI_OUTPUTSTREAM_MESSAGE_DGCACK) {
	    return RMI_OUTPUTMESSAGE;
	}
    }
    return CONTINUATION;
}

void
proto_register_rmi(void)
{

    static hf_register_info hf[] = {
	{ &hf_rmi_magic,
	  { "Magic",   "rmi.magic",
	    FT_UINT32, BASE_HEX, NULL, 0x0,
	    "RMI Header Magic", HFILL }},
	{ &hf_rmi_version,
	  { "Version", "rmi.version",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "RMI Protocol Version", HFILL }},
	{ &hf_rmi_protocol,
	  { "Protocol","rmi.protocol",
	    FT_UINT8, BASE_HEX, VALS(rmi_protocol_str), 0x0,
	    "RMI Protocol Type", HFILL }},
	{ &hf_rmi_inputmessage,
	  { "Input Stream Message", "rmi.inputstream.message",
	    FT_UINT8, BASE_HEX, VALS(rmi_input_message_str), 0x0,
	    "RMI Inputstream Message Token", HFILL }},
	{ &hf_rmi_outputmessage,
	  { "Output Stream Message", "rmi.outputstream.message",
	    FT_UINT8, BASE_HEX, VALS(rmi_output_message_str), 0x0,
	    "RMI Outputstream Message token", HFILL }},
	{ &hf_rmi_epid_length,
	  { "Length", "rmi.endpoint_id.length",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "RMI Endpointidentifier Length", HFILL }},
	{ &hf_rmi_epid_hostname,
	  { "Hostname", "rmi.endpoint_id.hostname",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "RMI Endpointidentifier Hostname", HFILL }},
	{ &hf_rmi_epid_port,
	  { "Port", "rmi.endpoint_id.port",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "RMI Endpointindentifier Port", HFILL }},

	{ &hf_ser_magic,
	  { "Magic",   "rmi.ser.magic",
	    FT_UINT16, BASE_HEX, NULL, 0x0,
	    "Java Serialization Magic", HFILL }},
	{ &hf_ser_version,
	  { "Version", "rmi.ser.version",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Java Serialization Version", HFILL }},
    };

    static gint *ett[] = {
	&ett_rmi,
	&ett_rmi_magic,
	&ett_rmi_version,
	&ett_rmi_inputmessage,
	&ett_rmi_outputmessage,
	&ett_rmi_epid_length,
	&ett_rmi_epid_hostname,
	&ett_rmi_epid_port,
	&ett_ser,
    };

    proto_rmi = proto_register_protocol("Java RMI", "RMI", "rmi");
    proto_ser = proto_register_protocol("Java Serialization", "Serialization",
					"serialization");
    proto_register_field_array(proto_rmi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_rmi(void)
{
    dissector_handle_t rmi_handle;

    rmi_handle = create_dissector_handle(dissect_rmi, proto_rmi);
    dissector_add_uint("tcp.port", TCP_PORT_RMI, rmi_handle);
}
