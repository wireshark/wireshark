/******************************************************************************
** $Id$
**
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
** 
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
** 
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
** 
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Protocol Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
** Last change by: $Author: gergap $
**
******************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include "opcua_transport_layer.h"
#include "opcua_security_layer.h"
#include "opcua_application_layer.h"
#include "opcua_complextypeparser.h"
#include "opcua_serviceparser.h"
#include "opcua_enumparser.h"
#include "opcua_simpletypes.h"
#include "opcua_hfindeces.h"

/* forward reference */
static void dissect_opcua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_opcua_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* declare parse function pointer */
typedef void (*FctParse)(proto_tree *tree, tvbuff_t *tvb, gint *pOffset);

static int proto_opcua = -1;
/** Official IANA registered port for OPC UA Binary Protocol. */
#define OPCUA_PORT 4840

/** subtree types */
gint ett_opcua_transport = -1;
gint ett_opcua_extensionobject = -1;
gint ett_opcua_nodeid = -1;

/** OpcUa Transport Message Types */
enum MessageType
{
    MSG_HELLO = 0,
    MSG_ACKNOWLEDGE,
    MSG_DISCONNECT,
    MSG_DATA_LAST_CHUNK,
    MSG_DATA,
    MSG_ABORT,
    MSG_ERROR,
    MSG_INVALID,
    MSG_UNKNOWN
};

/** OpcUa Transport Message Type Names */
static char* g_szMessageTypes[] =
{
    "Hello message",
    "Acknowledge message",
    "Disconnect message",
    "Data message, last chunk in message.",
    "Data message, further chunks must follow.",
    "Abort message",
    "Error message",
    "Invalid message",
    "Unknown message"
};


/** Setup protocol subtree array */
static gint *ett[] =
{
    &ett_opcua_transport,
    &ett_opcua_extensionobject,
    &ett_opcua_nodeid,
};

/** plugin entry functions.
 * This registers the OpcUa protocol.
 */
void proto_register_opcua(void)
{
    proto_opcua = proto_register_protocol(
        "OpcUa Binary Protocol", /* name */
        "OpcUa",                 /* short name */
        "opcua"                  /* abbrev */
        );
    registerTransportLayerTypes(proto_opcua);
    registerSecurityLayerTypes(proto_opcua);
    registerApplicationLayerTypes(proto_opcua);
    registerSimpleTypes(proto_opcua);
    registerEnumTypes(proto_opcua);
    registerComplexTypes();
    registerServiceTypes();
    registerFieldTypes(proto_opcua);

    proto_register_subtree_array(ett, array_length(ett));    
}

/** Register sub protocol. 
  * For TCP port 4840.
  */
void proto_reg_handoff_opcua(void)
{
    dissector_handle_t opcua_handle;
    opcua_handle = create_dissector_handle(dissect_opcua, proto_opcua);
    dissector_add("tcp.port", OPCUA_PORT, opcua_handle);
}

/** header length that is needed to compute
  * the pdu length.
  * @see get_opcua_message_len
  */
#define FRAME_HEADER_LEN 8

/** returns the length of an OpcUa message.
  * This function reads the length information from
  * the transport header.
  */
static guint get_opcua_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    gint32 plen;

    /* the message length starts at offset 4 */
    plen = tvb_get_letohl(tvb, offset + 4);

    return plen;
}

/** The main OpcUa dissector functions.
  * It uses tcp_dissect_pdus from packet-tcp.h
  * to reassemble the TCP data.
  */
static void dissect_opcua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
      get_opcua_message_len, dissect_opcua_message);
}

/** The OpcUa message dissector.
  * This method dissects full OpcUa messages.
  * It gets only called with reassembled data
  * from tcp_dissect_pdus.
  */
static void dissect_opcua_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    FctParse pfctParse = NULL;
    enum MessageType msgtype = MSG_INVALID;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpcUa");
    }

    /* parse message type */
    if (tvb->real_data[0] == 'U' && tvb->real_data[1] == 'A')
    {
        if (tvb->real_data[2] == 'T')
        {
            switch(tvb->real_data[3])
            {
            case 'H': msgtype = MSG_HELLO;
                pfctParse = parseHello;
                break;
            case 'A': msgtype = MSG_ACKNOWLEDGE;
                pfctParse = parseAcknowledge;
                break;
            case 'D': msgtype = MSG_DISCONNECT;
                pfctParse = parseDisconnect;
                break;
            default: msgtype = MSG_INVALID;
                break;
            }                
        }
        else if (tvb->real_data[2] == 'M')
        {
            switch(tvb->real_data[3])
            {
            case 'G': msgtype = MSG_DATA_LAST_CHUNK;
                pfctParse = parseData;
                break;
            case 'C': msgtype = MSG_DATA;
                pfctParse = parseData;
                break;
            case 'A': msgtype = MSG_ABORT;
                pfctParse = parseAbort;
                break;
            case 'E': msgtype = MSG_ERROR;
                pfctParse = parseError;
                break;
            default: msgtype = MSG_INVALID;
                break;
            }                
        }
    }
    else
    {
        msgtype = MSG_UNKNOWN;
    }

    /* Clear out stuff in the info column */
    if(check_col(pinfo->cinfo, COL_INFO))
    {
        col_set_str(pinfo->cinfo, COL_INFO, g_szMessageTypes[msgtype]);
    }

    if (tree && pfctParse)
    {
        gint offset = 0;

        /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *transport_tree = NULL;

        ti = proto_tree_add_item(tree, proto_opcua, tvb, 0, -1, FALSE);
        transport_tree = proto_item_add_subtree(ti, ett_opcua_transport);

        /* call the transport message dissector */
        (*pfctParse)(transport_tree, tvb, &offset);

    }
}    




