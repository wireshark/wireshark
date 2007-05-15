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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>
#include "ua_application_layer.h"
#include "opcua_simpletypes.h"

/** NodeClass enum table */
static const value_string g_SecSigTable[] = {
  { 0, "GetSecurityPolcies" },
  { 1, "OpenSecureChannel" },
  { 2, "CloseSecureChannel" },
  { 3, "Message" },
  { 0, NULL }
};
static int hf_opcua_SecuritySigEnum = -1;

static int hf_opcua_security_sig = -1;
static int hf_opcua_security_policy = -1;
static int hf_opcua_security_channel = -1;
static int hf_opcua_security_token = -1;

static hf_register_info hf[] =
{
    { &hf_opcua_security_sig,
    {  "Security Signature",       "security.sig",     FT_UINT16, BASE_HEX,  VALS(g_SecSigTable), 0x0, "", HFILL }
    },
    { &hf_opcua_security_policy,
    {  "Security Policy",          "security.policy",  FT_STRING, BASE_NONE,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_security_channel,
    {  "Secure Channel Id",        "security.channel", FT_GUID,   BASE_NONE,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_security_token,
    {  "Security Token Id",        "security.token",   FT_STRING, BASE_NONE,  NULL, 0x0,    "",    HFILL }
    }
};

/** Register security layer types. */
void registerSecurityLayerTypes(int proto)
{
    proto_register_field_array(proto, hf, array_length(hf));
}


/* Security Layer: message parsers
 * Only works for Security Policy "NoSecurity" at the moment.
 */
void parseSecurityLayer(proto_tree *tree, tvbuff_t *tvb, gint *pOffset)
{
    guint16 Sig;
    
    Sig = tvb_get_letohs(tvb, pOffset[0]);
    proto_tree_add_item(tree, hf_opcua_security_sig, tvb, *pOffset, 2, TRUE); *pOffset+=2;

    switch (Sig)
    {
    case 0: /* GetSecurityPolicies */
        break;
    case 1: /* OpenSecureChannel */
        parseGuid(tree, tvb,   pOffset, hf_opcua_security_channel);
        parseString(tree, tvb, pOffset, hf_opcua_security_policy);
        break;
    case 2: /* CloseSecureChannel */
        parseGuid(tree, tvb,   pOffset, hf_opcua_security_channel);
        parseString(tree, tvb, pOffset, hf_opcua_security_token);
        break;
    case 3: /* Other Services Messages */
        parseGuid(tree, tvb,   pOffset, hf_opcua_security_channel);
        parseString(tree, tvb, pOffset, hf_opcua_security_token);
        break;
    }
}

