/******************************************************************************
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
******************************************************************************/

#include "config.h"

#include <epan/packet.h>
#include "opcua_security_layer.h"
#include "opcua_application_layer.h"
#include "opcua_simpletypes.h"
#include "opcua_transport_layer.h"
#include "opcua_servicetable.h"

static int hf_opcua_transport_type = -1;
static int hf_opcua_transport_chunk = -1;
static int hf_opcua_transport_size = -1;
static int hf_opcua_transport_ver = -1;
static int hf_opcua_transport_scid = -1;
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

/** subtree types */
extern gint ett_opcua_nodeid;
extern gint ett_opcua_extensionobject;

/** Register transport layer types. */
void registerTransportLayerTypes(int proto)
{
    static hf_register_info hf[] =
    {
        /* id                           full name                        abbreviation                type       display    strings bitmask blurb HFILL */
        {&hf_opcua_transport_type,     {"Message Type",                  "opcua.transport.type",     FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_chunk,    {"Chunk Type",                    "opcua.transport.chunk",    FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_size,     {"Message Size",                  "opcua.transport.size",     FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_ver,      {"Version",                       "opcua.transport.ver",      FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_scid,     {"SecureChannelId",               "opcua.transport.scid",     FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_rbs,      {"ReceiveBufferSize",             "opcua.transport.rbs",      FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_sbs,      {"SendBufferSize",                "opcua.transport.sbs",      FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_mms,      {"MaxMessageSize",                "opcua.transport.mms",      FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_mcc,      {"MaxChunkCount",                 "opcua.transport.mcc",      FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_endpoint, {"EndPointUrl",                   "opcua.transport.endpoint", FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_error,    {"Error",                         "opcua.transport.error",    FT_UINT32, BASE_HEX,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_reason,   {"Reason",                        "opcua.transport.reason",   FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_spu,      {"SecurityPolicyUri",             "opcua.security.spu",       FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_scert,    {"SenderCertificate",             "opcua.security.scert",     FT_BYTES,  BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_rcthumb,  {"ReceiverCertificateThumbprint", "opcua.security.rcthumb",   FT_BYTES,  BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_seq,      {"SequenceNumber",                "opcua.security.seq",       FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_rqid,     {"RequestId",                     "opcua.security.rqid",      FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
    };

    proto_register_field_array(proto, hf, array_length(hf));
}

/* Transport Layer: message parsers */
int parseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_ver, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_sbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mms, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mcc, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_endpoint);
    return -1;
}

int parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint *pOffset)
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

int parseError(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseStatusCode(tree, tvb, pinfo, pOffset, hf_opcua_transport_error);
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_reason);
    return -1;
}

int parseMessage(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;

    /* message data contains the security layer */
    parseSecurityLayer(tree, tvb, pOffset);

    return -1;
}

int parseService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset)
{
    proto_item *ti;
    proto_item *ti_inner;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;

    /* AT THE MOMENT NO SECURITY IS IMPLEMENTED IN UA.
     * WE CAN JUST JUMP INTO THE APPLICATION LAYER DATA.
     * THIS WILL CHAHNGE IN THE FUTURE. */

    /* add encodeable object subtree */
    encobj_tree = proto_tree_add_subtree(tree, tvb, *pOffset, -1, ett_opcua_extensionobject, &ti, "OpcUa Service : Encodeable Object");

    /* add nodeid subtree */
    nodeid_tree = proto_tree_add_subtree(encobj_tree, tvb, *pOffset, -1, ett_opcua_nodeid, &ti_inner, "TypeId : ExpandedNodeId");
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset);
    proto_item_set_end(ti_inner, tvb, *pOffset);

    dispatchService(encobj_tree, tvb, pinfo, pOffset, ServiceId);

    proto_item_set_end(ti, tvb, *pOffset);
    return ServiceId;
}

int parseOpenSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset)
{
    proto_item *ti;
    proto_item *ti_inner;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;

    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_spu);
    parseByteString(tree, tvb, pinfo, pOffset, hf_opcua_transport_scert);
    parseByteString(tree, tvb, pinfo, pOffset, hf_opcua_transport_rcthumb);
    proto_tree_add_item(tree, hf_opcua_transport_seq, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rqid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;

    /* add encodeable object subtree */
    encobj_tree = proto_tree_add_subtree(tree, tvb, *pOffset, -1, ett_opcua_extensionobject, &ti, "Message : Encodeable Object");

    /* add nodeid subtree */
    nodeid_tree = proto_tree_add_subtree(encobj_tree, tvb, *pOffset, -1, ett_opcua_nodeid, &ti_inner, "TypeId : ExpandedNodeId");
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset);
    proto_item_set_end(ti_inner, tvb, *pOffset);

    dispatchService(encobj_tree, tvb, pinfo, pOffset, ServiceId);

    proto_item_set_end(ti, tvb, *pOffset);
    return ServiceId;
}

int parseCloseSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset)
{
    proto_item *ti;
    proto_item *ti_inner;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;

    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;

    parseSecurityLayer(tree, tvb, pOffset);

    /* add encodeable object subtree */
    encobj_tree = proto_tree_add_subtree(tree, tvb, *pOffset, -1, ett_opcua_extensionobject, &ti, "Message : Encodeable Object");

    /* add nodeid subtree */
    nodeid_tree = proto_tree_add_subtree(encobj_tree, tvb, *pOffset, -1, ett_opcua_nodeid, &ti_inner, "TypeId : ExpandedNodeId");
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset);
    proto_item_set_end(ti_inner, tvb, *pOffset);

    dispatchService(encobj_tree, tvb, pinfo, pOffset, ServiceId);

    proto_item_set_end(ti, tvb, *pOffset);
    return ServiceId;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
