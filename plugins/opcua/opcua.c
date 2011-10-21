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
#include <epan/prefs.h>
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

extern const value_string g_requesttypes[];
extern const int g_NumServices;

/* forward reference */
static void dissect_opcua(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_opcua_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_opcua(void);

/* declare parse function pointer */
typedef int (*FctParse)(proto_tree *tree, tvbuff_t *tvb, gint *pOffset);

static int proto_opcua = -1;
static dissector_handle_t opcua_handle;
static range_t *global_tcp_ports_opcua;
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
    MSG_ERROR,
    MSG_MESSAGE,
    MSG_OPENSECURECHANNEL,
    MSG_CLOSESECURECHANNEL,
    MSG_INVALID
};

/** OpcUa Transport Message Type Names */
static char* g_szMessageTypes[] =
{
    "Hello message",
    "Acknowledge message",
    "Error message",
    "UA Secure Conversation Message",
    "OpenSecureChannel message",
    "CloseSecureChannel message",
    "Invalid message"
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
    module_t *opcua_module;

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

    range_convert_str(&global_tcp_ports_opcua, ep_strdup_printf("%u", OPCUA_PORT),  65535);

    /* register user preferences */
    opcua_module = prefs_register_protocol(proto_opcua, proto_reg_handoff_opcua);
    prefs_register_range_preference(opcua_module, "tcp_ports",
				 "OPC UA TCP Ports",
				 "The TCP ports for the OPC UA TCP Binary Protocol",
				 &global_tcp_ports_opcua, 65535);
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

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpcUa");

    /* parse message type */
    if (tvb_memeql(tvb, 0, "HEL", 3) == 0)
    {
        msgtype = MSG_HELLO;
        pfctParse = parseHello;
    }
    else if (tvb_memeql(tvb, 0, "ACK", 3) == 0)
    {
        msgtype = MSG_ACKNOWLEDGE;
        pfctParse = parseAcknowledge;
    }
    else if (tvb_memeql(tvb, 0, "ERR", 3) == 0)
    {
        msgtype = MSG_ERROR;
        pfctParse = parseError;
    }
    else if (tvb_memeql(tvb, 0, "MSG", 3) == 0)
    {
        msgtype = MSG_MESSAGE;
        pfctParse = parseMessage;
    }
    else if (tvb_memeql(tvb, 0, "OPN", 3) == 0)
    {
        msgtype = MSG_OPENSECURECHANNEL;
        pfctParse = parseOpenSecureChannel;
    }
    else if (tvb_memeql(tvb, 0, "CLO", 3) == 0)
    {
        msgtype = MSG_CLOSESECURECHANNEL;
        pfctParse = parseCloseSecureChannel;
    }
    else
    {
        msgtype = MSG_INVALID;
    }

    /* Clear out stuff in the info column */
    col_set_str(pinfo->cinfo, COL_INFO, g_szMessageTypes[msgtype]);

    if (tree && pfctParse)
    {
        gint offset = 0;
        int iServiceId = -1;

        /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *transport_tree = NULL;

        ti = proto_tree_add_item(tree, proto_opcua, tvb, 0, -1, ENC_NA);
        transport_tree = proto_item_add_subtree(ti, ett_opcua_transport);

        /* call the transport message dissector */
        iServiceId = (*pfctParse)(transport_tree, tvb, &offset);

        /* display the service type in addition to the message type */
        if (iServiceId != -1)
        {
            int index = 0;
            while (index < g_NumServices)
            {
                if (g_requesttypes[index].value == (guint32)iServiceId)
                {
                    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", g_szMessageTypes[msgtype], g_requesttypes[index].strptr);
                    break;
                }
                index++;
            }
        }
    }
}

static void register_tcp_port(guint32 port)
{
  if (port != 0)
    dissector_add_uint("tcp.port", port, opcua_handle);
}

static void unregister_tcp_port(guint32 port)
{
  if (port != 0)
    dissector_delete_uint("tcp.port", port, opcua_handle);
}

void proto_reg_handoff_opcua(void)
{
  static gboolean opcua_initialized = FALSE;
  static range_t *tcp_ports_opcua  = NULL;

  if(!opcua_initialized)
  {
    opcua_handle = create_dissector_handle(dissect_opcua, proto_opcua);
    opcua_initialized = TRUE;
  }
  else
  {
    /* clean up ports and their lists */
    if (tcp_ports_opcua != NULL)
    {
      range_foreach(tcp_ports_opcua, unregister_tcp_port);
      g_free(tcp_ports_opcua);
    }
  }

  /* If we now have a PDU tree, register for the port or ports we have */
  tcp_ports_opcua = range_copy(global_tcp_ports_opcua);
  range_foreach(tcp_ports_opcua, register_tcp_port);
}


