/******************************************************************************
** $Id$
**
** Copyright (C) 2006-2009 ascolab GmbH. All Rights Reserved.
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "opcua_security_layer.h"
#include "opcua_application_layer.h"
#include "opcua_simpletypes.h"

void dispatchService(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int ServiceId);

static int hf_opcua_transport_type = -1;
static int hf_opcua_transport_chunk = -1;
static int hf_opcua_transport_size = -1;
static int hf_opcua_transport_ver = -1;
static int hf_opcua_transport_scid = -1;
static int hf_opcua_transport_lifetime = -1;
static int hf_opcua_transport_rbs = -1;
static int hf_opcua_transport_sbs = -1;
static int hf_opcua_transport_mms = -1;
static int hf_opcua_transport_mcc = -1;
static int hf_opcua_transport_endpoint = -1;
static int hf_opcua_transport_error = -1;
static int hf_opcua_transport_reason = -1;
static int hf_opcua_transport_spu = -1;
static int hf_opcua_transport_scert = -1;
static int hf_opcua_transport_rcthumb = -1;
static int hf_opcua_transport_seq = -1;
static int hf_opcua_transport_rqid = -1;
extern gint ett_opcua_nodeid;

/** subtree types */
extern gint ett_opcua_extensionobject;

/** Register transport layer types. */
void registerTransportLayerTypes(int proto)
{
    static hf_register_info hf[] =
    {
        { &hf_opcua_transport_type,
        /* full name  ,           abbreviation  ,       type     , display  , strings, bitmask, blurb, id, parent, ref_count, bitshift */
        {  "Message Type",        "transport.type",     FT_STRING, BASE_NONE, NULL,    0x0,     NULL,    HFILL }
        },
        { &hf_opcua_transport_chunk,
        {  "Chunk Type",          "transport.chunk",    FT_STRING, BASE_NONE, NULL,    0x0,     NULL,    HFILL }
        },
        { &hf_opcua_transport_size,
        {  "Message Size",        "transport.size",     FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_ver,
        {  "Version",             "transport.ver",      FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_scid,
        {  "SecureChannelId",     "transport.scid",     FT_UINT32, BASE_DEC, NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_lifetime,
        {  "Lifetime",            "transport.lifetime", FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_rbs,
        {  "ReceiveBufferSize",   "transport.rbs",      FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_sbs,
        {  "SendBufferSize",      "transport.sbs",      FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_mms,
        {  "MaxMessageSize",      "transport.mms",      FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_mcc,
        {  "MaxChunkCount",       "transport.mcc",      FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_endpoint,
        {  "EndPointUrl",         "transport.endpoint", FT_STRING, BASE_NONE, NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_error,
        {  "Error",               "transport.error",    FT_UINT32, BASE_HEX,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_reason,
        {  "Reason",              "transport.reason",   FT_STRING, BASE_NONE,  NULL, 0x0,    NULL,    HFILL }
        },
    /*    { &hf_opcua_transport_spul,
        {  "SecurityPolicyUriLength", "transport.spul", FT_UINT32, BASE_DEC,  NULL, 0x0,    "",    HFILL }
        },*/
        { &hf_opcua_transport_spu,
        {  "SecurityPolicyUri",   "security.spu",      FT_STRING, BASE_NONE,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_scert,
        {  "SenderCertificate",   "security.scert",    FT_BYTES,  BASE_NONE,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_rcthumb,
        {  "ReceiverCertificateThumbprint", "security.rcthumb", FT_BYTES,  BASE_NONE,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_seq,
        {  "SequenceNumber", "security.seq",           FT_UINT32,  BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_transport_rqid,
        {  "RequestId", "security.rqid",                FT_UINT32,  BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
    };

    proto_register_field_array(proto, hf, array_length(hf));
}

/* Transport Layer: message parsers */
int parseHello(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_ver, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_sbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mms, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mcc, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseString(tree, tvb, pOffset, hf_opcua_transport_endpoint);
    return -1;
}

int parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_ver, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_sbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mms, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mcc, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    return -1;
}

int parseError(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_error, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseString(tree, tvb, pOffset, hf_opcua_transport_reason);
    return -1;
}

int parseMessage(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;

    /* message data contains the security layer */
    parseSecurityLayer(tree, tvb, pOffset);

    return -1;
}

int parseService(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_item *ti;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;

    /* AT THE MOMENT NO SECURITY IS IMPLEMENTED IN UA.
     * WE CAN JUST JUMP INTO THE APPLICATION LAYER DATA.
     * THIS WILL CHAHNGE IN THE FUTURE. */

    /* add encodeable object subtree */
    ti = proto_tree_add_text(tree, tvb, 0, -1, "OpcUa Service : Encodeable Object");
    encobj_tree = proto_item_add_subtree(ti, ett_opcua_extensionobject);

    /* add nodeid subtree */
    ti = proto_tree_add_text(encobj_tree, tvb, 0, -1, "TypeId : ExpandedNodeId");
    nodeid_tree = proto_item_add_subtree(ti, ett_opcua_nodeid);
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset);

    dispatchService(encobj_tree, tvb, pOffset, ServiceId);
    return ServiceId;
}

int parseOpenSecureChannel(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_item *ti;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;
    
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseString(tree, tvb, pOffset, hf_opcua_transport_spu);
    parseByteString(tree, tvb, pOffset, hf_opcua_transport_scert);
    parseByteString(tree, tvb, pOffset, hf_opcua_transport_rcthumb);
    proto_tree_add_item(tree, hf_opcua_transport_seq, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rqid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    
    /* add encodeable object subtree */
    ti = proto_tree_add_text(tree, tvb, 0, -1, "Message : Encodeable Object");
    encobj_tree = proto_item_add_subtree(ti, ett_opcua_extensionobject);

    /* add nodeid subtree */
    ti = proto_tree_add_text(encobj_tree, tvb, 0, -1, "TypeId : ExpandedNodeId");
    nodeid_tree = proto_item_add_subtree(ti, ett_opcua_nodeid);
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset);

    dispatchService(encobj_tree, tvb, pOffset, ServiceId);
    return -1;
}

int parseCloseSecureChannel(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    return -1;
}

