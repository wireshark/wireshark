/******************************************************************************
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Security Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

#include "config.h"

#include <epan/packet.h>
#include "opcua_security_layer.h"
#include "opcua_transport_layer.h"

static int hf_opcua_security_tokenid;
static int hf_opcua_security_padding;
static int hf_opcua_security_signature;
static int hf_opcua_sequence_seqno;
static int hf_opcua_sequence_rqid;

/** Register symmetric security layer types. */
void registerSecurityLayerTypes(int proto)
{
    static hf_register_info hf[] =
    {
        /* id                          full name              abbreviation                type       display    strings bitmask blurb HFILL */
        {&hf_opcua_security_tokenid,   {"Security Token Id",  "opcua.security.tokenid",   FT_UINT32, BASE_DEC,  NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_security_padding,   {"Security Padding",   "opcua.security.padding",   FT_BYTES,  BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_security_signature, {"Security Signature", "opcua.security.signature", FT_BYTES,  BASE_NONE, NULL,   0x0,    NULL, HFILL}},
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/** Register sequence header types. */
void registerSequenceLayerTypes(int proto)
{
    static hf_register_info hf[] =
    {
        /* id                           full name          abbreviation              type       display   strings bitmask blurb HFILL */
        {&hf_opcua_sequence_seqno,     {"Sequence Number", "opcua.sequence.seq",     FT_UINT32, BASE_DEC, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_sequence_rqid,      {"RequestId",       "opcua.sequence.rqid",    FT_UINT32, BASE_DEC, NULL,   0x0,    NULL, HFILL}}
    };
    proto_register_field_array(proto, hf, array_length(hf));
}

/* The symmetric security header consists only of one field. */
void parseSecurityHeader(proto_tree *tree, tvbuff_t *tvb, int *pOffset, struct ua_metadata *data _U_)
{
    proto_tree_add_item(tree, hf_opcua_security_tokenid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
}

/* Sequence header can optionally be encrypted. */
void parseSequenceHeader(proto_tree *tree, tvbuff_t *tvb, int *pOffset, struct ua_metadata *data)
{
    if (!data->encrypted) {
        proto_tree_add_item(tree, hf_opcua_sequence_seqno, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
        proto_tree_add_item(tree, hf_opcua_sequence_rqid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    }
}

/* Parse symmetric security footer (signed only) */
void parseSecurityFooterSO(proto_tree *tree, tvbuff_t *tvb, int offset, unsigned sig_len)
{
    proto_tree_add_item(tree, hf_opcua_security_signature, tvb, offset, sig_len, ENC_NA);
}

/* Parse symmetric security footer (signed and encrypted) */
void parseSecurityFooterSAE(proto_tree *tree, tvbuff_t *tvb, int offset, unsigned pad_len, unsigned sig_len)
{
    proto_tree_add_item(tree, hf_opcua_security_padding, tvb, offset, pad_len + 1, ENC_NA);
    proto_tree_add_item(tree, hf_opcua_security_signature, tvb, offset + pad_len + 1, sig_len, ENC_NA);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
