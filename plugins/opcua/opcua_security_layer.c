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
** Description: OpcUa Security Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
** Last change by: $Author: gergap $
**
******************************************************************************/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "opcua_application_layer.h"
#include "opcua_simpletypes.h"

/** NodeClass enum table */
static const value_string g_SecSigTable[] = {
  { 0, "GetSecurityPolcies" },
  { 1, "OpenSecureChannel" },
  { 2, "CloseSecureChannel" },
  { 3, "Message" },
  { 0, NULL }
};

static int hf_opcua_security_tokenid = -1;
static int hf_opcua_security_seq = -1;
static int hf_opcua_security_rqid = -1;

/** Register security layer types. */
void registerSecurityLayerTypes(int proto)
{
    static hf_register_info hf[] =
    {
        { &hf_opcua_security_tokenid,
        {  "Security Token Id",        "security.tokenid",   FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_security_seq,
        {  "Security Sequence Number", "security.seq",       FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_security_rqid,
        {  "Security RequestId",       "security.rqid",      FT_UINT32, BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        }
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/* Security Layer: message parsers
 * Only works for Security Policy "NoSecurity" at the moment.
 */
void parseSecurityLayer(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    proto_tree_add_item(tree, hf_opcua_security_tokenid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_security_seq, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_security_rqid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
}


