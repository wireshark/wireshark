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
** Description: OpcUa Transport Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
** Last change by: $Author: gergap $
**
******************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>
#include "opcua_security_layer.h"
#include "opcua_application_layer.h"
#include "opcua_simpletypes.h"
#include <string.h>
#include <epan/emem.h>

void dispatchService(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int ServiceId);

static int hf_opcua_transport_sig = -1;
static int hf_opcua_transport_len = -1;
static int hf_opcua_transport_ver = -1;
static int hf_opcua_transport_cid = -1;
static int hf_opcua_transport_lifetime = -1;
static int hf_opcua_transport_sbl = -1;
static int hf_opcua_transport_rbl = -1;
static int hf_opcua_transport_endpoint = -1;
static int hf_opcua_transport_rlifetime = -1;
static int hf_opcua_transport_rsbl = -1;
static int hf_opcua_transport_rrbl = -1;
static int hf_opcua_transport_altendpoint = -1;
static int hf_opcua_transport_rqid = -1;
static int hf_opcua_transport_status = -1;
extern gint ett_opcua_nodeid;

static hf_register_info hf[] =
{
    { &hf_opcua_transport_sig,
    /* full name  ,           abbreviation  ,       type     , display  , strings, bitmask, blurb, id, parent, ref_count, bitshift */
    {  "Signature",           "transport.sig",      FT_STRING, BASE_NONE, NULL,    0x0,     "",    HFILL }
    },
    { &hf_opcua_transport_len,
    {  "Message Length",      "transport.len",      FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_ver,
    {  "Version",             "transport.ver",      FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_cid,
    {  "ConnectionId",        "transport.cid",      FT_GUID,   BASE_NONE, NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_lifetime,
    {  "Lifetime",            "transport.lifetime", FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_sbl,
    {  "SendBufferLength",    "transport.sbl",      FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_rbl,
    {  "ReceiveBufferLength", "transport.rbl",      FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_endpoint,
    {  "EndPoint",            "transport.endpoint", FT_STRING, BASE_NONE, NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_rlifetime,
    {  "Revised Lifetime",    "transport.rlifetime", FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_rsbl,
    {  "Revised SendBufferLength", "transport.rsbl", FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_rrbl,
    {  "Revised ReceiveBufferLength", "transport.rrbl", FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_altendpoint,
    {  "Alternate EndPoint",  "transport.altendpoint", FT_STRING, BASE_NONE, NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_rqid,
    {  "RequestId",           "transport.rqid",     FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_transport_status,
    {  "StatusCode",          "transport.status",   FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
    }
};

/** subtree types */
extern gint ett_opcua_extensionobject;

/** Register transport layer types. */
void registerTransportLayerTypes(int proto)
{
    proto_register_field_array(proto, hf, array_length(hf));
}

/** helper functions for adding strings,
  * that are not zero terminated.
  */
void addString(proto_tree *tree,  
               int  hfindex,  
               tvbuff_t *tvb,  
               gint  start,  
               gint  length,  
               const char *value)
{
    char *szValue = ep_alloc(256);

    if (szValue)
    {
        if (length > 255) length = 255;
        /* copy non null terminated string data */
        strncpy(szValue, value, length);
        /* set null terminator */
        szValue[length] = 0;

        proto_tree_add_string(tree, hfindex, tvb, start, length, szValue);
    }
}

/* Transport Layer: message parsers */
void parseHello(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    addString(tree, hf_opcua_transport_sig, tvb, *pOffset, 4, tvb->real_data); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_len, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_ver, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_cid, tvb, *pOffset, 16, TRUE); *pOffset+=16;
    proto_tree_add_item(tree, hf_opcua_transport_lifetime, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_sbl, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rbl, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    parseString(tree, tvb, pOffset, hf_opcua_transport_endpoint);
}

void parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    addString(tree, hf_opcua_transport_sig, tvb, *pOffset, 4, tvb->real_data); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_len, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_cid, tvb, *pOffset, 16, TRUE); *pOffset+=16;
    proto_tree_add_item(tree, hf_opcua_transport_rlifetime, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rsbl, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rrbl, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    parseString(tree, tvb, pOffset, hf_opcua_transport_altendpoint);
}

void parseDisconnect(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    addString(tree, hf_opcua_transport_sig, tvb, *pOffset, 4, tvb->real_data); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_len, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_cid, tvb, *pOffset, 16, TRUE); *pOffset+=16;
}

void parseData(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_item *ti;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;

    addString(tree, hf_opcua_transport_sig, tvb, *pOffset, 4, tvb->real_data); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_len, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_cid, tvb, *pOffset, 16, TRUE); *pOffset+=16;
    proto_tree_add_item(tree, hf_opcua_transport_rqid, tvb, *pOffset, 4, TRUE); *pOffset+=4;

    /* message data contains the security layer */
    parseSecurityLayer(tree, tvb, pOffset);

    /* AT THE MOMENT NO SECURITY IS IMPLEMENTED IN UA.
     * WE CAN JUST JUMP INTO THE APPLICATION LAYER DATA.
     * THIS WILL CHAHNGE IN THE FUTURE. */

    /* add encodeable object subtree */
    ti = proto_tree_add_text(tree, tvb, 0, -1, "Message : Encodeable Object");
    encobj_tree = proto_item_add_subtree(ti, ett_opcua_extensionobject);

    /* add nodeid subtree */
    ti = proto_tree_add_text(encobj_tree, tvb, 0, -1, "TypeId : ExpandedNodeId");
    nodeid_tree = proto_item_add_subtree(ti, ett_opcua_nodeid);
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset, "NodeId") - 1;

    dispatchService(encobj_tree, tvb, pOffset, ServiceId);
}

void parseAbort(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    addString(tree, hf_opcua_transport_sig, tvb, *pOffset, 4, tvb->real_data); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_len, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_cid, tvb, *pOffset, 16, TRUE); *pOffset+=16;
    proto_tree_add_item(tree, hf_opcua_transport_rqid, tvb, *pOffset, 4, TRUE); *pOffset+=4;
}

void parseError(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    addString(tree, hf_opcua_transport_sig, tvb, *pOffset, 4, tvb->real_data); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_len, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_cid, tvb, *pOffset, 16, TRUE); *pOffset+=16;
    proto_tree_add_item(tree, hf_opcua_transport_rqid, tvb, *pOffset, 4, TRUE); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_status, tvb, *pOffset, 4, TRUE); *pOffset+=4;
}
