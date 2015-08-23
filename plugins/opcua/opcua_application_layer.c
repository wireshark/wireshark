/******************************************************************************
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
** Description: OpcUa Application Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

#include "config.h"

#include <epan/packet.h>
#include "opcua_application_layer.h"

/** NodeId encoding mask table */
static const value_string g_nodeidmasks[] = {
    { 0x00, "Two byte encoded Numeric" },
    { 0x01, "Four byte encoded Numeric" },
    { 0x02, "Numeric of arbitrary length" },
    { 0x03, "String" },
    { 0x04, "GUID" },
    { 0x05, "Opaque" },
    { 0, NULL }
};

/** Service type table */
extern const value_string g_requesttypes[];

static int hf_opcua_nodeid_encodingmask = -1;
static int hf_opcua_app_nsid = -1;
static int hf_opcua_app_numeric = -1;

/** Register application layer types. */
void registerApplicationLayerTypes(int proto)
{
    /** header field definitions */
    static hf_register_info hf[] =
    {
        /* id                               full name                    abbreviation                       type       display   strings               bitmask blurb HFILL */
        {&hf_opcua_nodeid_encodingmask,    {"NodeId EncodingMask",       "opcua.servicenodeid.encodingmask", FT_UINT8,  BASE_HEX, VALS(g_nodeidmasks),  0x0,    NULL, HFILL}},
        {&hf_opcua_app_nsid,               {"NodeId Namespace Index",    "opcua.servicenodeid.nsid",         FT_UINT8,  BASE_DEC, NULL,                 0x0,    NULL, HFILL}},
        {&hf_opcua_app_numeric,            {"NodeId Identifier Numeric", "opcua.servicenodeid.numeric",      FT_UINT32, BASE_DEC, VALS(g_requesttypes), 0x0,    NULL, HFILL}}
    };

    proto_register_field_array(proto, hf, array_length(hf));
}

/** Parses an OpcUa Service NodeId and returns the service type.
 * In this cases the NodeId is always from type numeric and NSId = 0.
 */
int parseServiceNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    gint    iOffset = *pOffset;
    guint8  EncodingMask;
    guint32 Numeric = 0;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(tree, hf_opcua_nodeid_encodingmask, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    switch(EncodingMask)
    {
    case 0x00: /* two byte node id */
        Numeric = tvb_get_guint8(tvb, iOffset);
        proto_tree_add_item(tree, hf_opcua_app_numeric, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
        iOffset+=1;
        break;
    case 0x01: /* four byte node id */
        proto_tree_add_item(tree, hf_opcua_app_nsid, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
        iOffset+=1;
        Numeric = tvb_get_letohs(tvb, iOffset);
        proto_tree_add_item(tree, hf_opcua_app_numeric, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        proto_tree_add_item(tree, hf_opcua_app_nsid, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        Numeric = tvb_get_letohl(tvb, iOffset);
        proto_tree_add_item(tree, hf_opcua_app_numeric, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);
        iOffset+=4;
        break;
    case 0x03: /* string */
    case 0x04: /* guid */
    case 0x05: /* opaque*/
        /* NOT USED */
        break;
    };

    *pOffset = iOffset;

    return Numeric;
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
