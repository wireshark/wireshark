/******************************************************************************
** Copyright (C) 2006-2009 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
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
#include <epan/conversation.h>
#include "epan/column-utils.h"

#include "opcua_security_layer.h"
#include "opcua_application_layer.h"
#include "opcua_simpletypes.h"
#include "opcua_transport_layer.h"
#include "opcua_servicetable.h"

static int hf_opcua_transport_type;
static int hf_opcua_transport_chunk;
static int hf_opcua_transport_size;
static int hf_opcua_transport_ver;
static int hf_opcua_transport_scid;
static int hf_opcua_transport_rbs;
static int hf_opcua_transport_sbs;
static int hf_opcua_transport_mms;
static int hf_opcua_transport_mcc;
static int hf_opcua_transport_endpoint;
static int hf_opcua_transport_suri;
static int hf_opcua_transport_error;
static int hf_opcua_transport_reason;
static int hf_opcua_transport_spu;
static int hf_opcua_transport_scert;
static int hf_opcua_transport_rcthumb;
static int hf_opcua_transport_seq;
static int hf_opcua_transport_rqid;

/** subtree types */
extern int ett_opcua_nodeid;
extern int ett_opcua_extensionobject;
extern int proto_opcua;

/** Defined security policy URL from Part 7 OPC UA Specification. */
#define UA_SECURITY_POLICY_NONE_STRING "http://opcfoundation.org/UA/SecurityPolicy#None"
/** Defined security policy URL from Part 7 OPC UA Specification. */
#define UA_SECURITY_POLICY_BASIC128RSA15_STRING "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
/** Defined security policy URL from Part 7 OPC UA Specification. */
#define UA_SECURITY_POLICY_BASIC256_STRING "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
/** Defined security policy URL from Part 7 OPC UA Specification. */
#define UA_SECURITY_POLICY_BASIC256SHA256_STRING "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
/** Defined security policy URL from Part 7 OPC UA Specification. */
#define UA_SECURITY_POLICY_AES128_SHA256_RSAOAEP_STRING "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
/** Defined security policy URL from Part 7 OPC UA Specification. */
#define UA_SECURITY_POLICY_AES256_SHA256_RSAPSS_STRING "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

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
        {&hf_opcua_transport_endpoint, {"EndpointUrl",                   "opcua.transport.endpoint", FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
        {&hf_opcua_transport_suri,     {"ServerUri",                     "opcua.transport.suri",     FT_STRING, BASE_NONE, NULL,   0x0,    NULL, HFILL}},
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

void parseMessageHeader(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, struct ua_metadata *data _U_)
{
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
}

/* Transport Layer: message parsers */
int parseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    proto_tree_add_item(tree, hf_opcua_transport_ver, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_sbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mms, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mcc, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_endpoint);
    return -1;
}

int parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    proto_tree_add_item(tree, hf_opcua_transport_ver, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_rbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_sbs, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mms, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_mcc, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    return -1;
}

int parseError(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    parseStatusCode(tree, tvb, pinfo, pOffset, hf_opcua_transport_error);
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_reason);
    return -1;
}

int parseReverseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_suri);
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_endpoint);
    return -1;
}

int parseMessage(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;

    return -1;
}

int parseAbort(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    parseStatusCode(tree, tvb, pinfo, pOffset, hf_opcua_transport_error);
    parseString(tree, tvb, pinfo, pOffset, hf_opcua_transport_reason);

    return -1;
}

int parseService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data _U_)
{
    proto_item *ti;
    proto_item *ti_inner;
    proto_tree *encobj_tree;
    proto_tree *nodeid_tree;
    int ServiceId = 0;

    /* add encodeable object subtree */
    encobj_tree = proto_tree_add_subtree(tree, tvb, *pOffset, -1, ett_opcua_extensionobject, &ti, "Message: Encodeable Object");

    /* add nodeid subtree */
    nodeid_tree = proto_tree_add_subtree(encobj_tree, tvb, *pOffset, -1, ett_opcua_nodeid, &ti_inner, "TypeId: ExpandedNodeId");
    ServiceId = parseServiceNodeId(nodeid_tree, tvb, pOffset);
    proto_item_set_end(ti_inner, tvb, *pOffset);

    if (ServiceId >= 0) {
        dispatchService(encobj_tree, tvb, pinfo, pOffset, ServiceId);
    }

    proto_item_set_end(ti, tvb, *pOffset);
    return ServiceId;
}

/**
 * Stores the messages mode and signature length for this TCP connection.
 * We need to know this mode in the following message to decide if decryption is required or not.
 */
void store_encryption_info(packet_info *pinfo, enum ua_message_mode mode, uint8_t sig_len)
{
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);
    if (conv) {
        uintptr_t data = (uintptr_t)mode;
        data |= ((uintptr_t)sig_len << 8);
        conversation_add_proto_data(conv, proto_opcua, (void *)data);
    }
}

/** Returns the message mode and signature length for current TCP connection. */
void get_encryption_info(packet_info *pinfo, enum ua_message_mode *mode, uint8_t *sig_len)
{
    conversation_t *conv = find_conversation_pinfo(pinfo, 0);
    if (conv) {
        uintptr_t data = (uintptr_t)conversation_get_proto_data(conv, proto_opcua);
        if (data == 0) {
            *mode = g_opcua_default_sig_len ? UA_MessageMode_MaybeEncrypted : UA_MessageMode_None;
            *sig_len = g_opcua_default_sig_len;
        } else {
            *mode = (enum ua_message_mode)(data & 0xff);
            *sig_len = (uintptr_t)(data >> 8);
        }
    }
}

/**
 * Compares an unterminated string of a string constant.
 *
 * @param text Unterminated string to compare.
 * @param text_len String data.
 * @param ref_text Zero terminated string constant to compare with.
 *
 * @return 0 if equal, -1 if not.
 */
static int opcua_string_compare(const char *text, int text_len, const char *ref_text)
{
    int len = (int)strlen(ref_text);
    if (text_len == len && memcmp(text, ref_text, len) == 0) return 0;

    return -1;
}

int parseOpenSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data)
{
    const uint8_t *sec_policy = NULL;
    int sec_policy_len = 0;
    int ServiceId = -1;
    bool encrypted = false;

    // Message Header
    proto_tree_add_item(tree, hf_opcua_transport_type, tvb, *pOffset, 3, ENC_ASCII|ENC_NA); *pOffset+=3;
    proto_tree_add_item(tree, hf_opcua_transport_chunk, tvb, *pOffset, 1, ENC_ASCII|ENC_NA); *pOffset+=1;
    proto_tree_add_item(tree, hf_opcua_transport_size, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;
    // Asym Security Header
    parseString_ret_string_and_length(tree, tvb, pinfo, pOffset, hf_opcua_transport_spu, &sec_policy, &sec_policy_len);
    parseCertificate(tree, tvb, pinfo, pOffset, hf_opcua_transport_scert);
    parseByteString(tree, tvb, pinfo, pOffset, hf_opcua_transport_rcthumb);

    if (opcua_string_compare(sec_policy, sec_policy_len, UA_SECURITY_POLICY_NONE_STRING ) == 0) {
        store_encryption_info(pinfo, UA_MessageMode_None, 0);
    } else {
        uint8_t sig_len = 0;
        // OPN is always encrypted for Policies != None, for both message modes Sign and SignAndEncrypted
        encrypted = true;
        // determine signature length based on security policy
        if (opcua_string_compare(sec_policy, sec_policy_len, UA_SECURITY_POLICY_BASIC128RSA15_STRING ) == 0) {
            sig_len = 20;
        } else if (opcua_string_compare(sec_policy, sec_policy_len, UA_SECURITY_POLICY_BASIC256_STRING ) == 0) {
            sig_len = 20;
        } else if (opcua_string_compare(sec_policy, sec_policy_len, UA_SECURITY_POLICY_BASIC256SHA256_STRING ) == 0) {
            sig_len = 32;
        } else if (opcua_string_compare(sec_policy, sec_policy_len, UA_SECURITY_POLICY_AES128_SHA256_RSAOAEP_STRING ) == 0) {
            sig_len = 32;
        } else if (opcua_string_compare(sec_policy, sec_policy_len, UA_SECURITY_POLICY_AES256_SHA256_RSAPSS_STRING ) == 0) {
            sig_len = 32;
        }
        // We don't know the messagemode without decrypting the OPN, so we assume it is SignAndEncrypt,
        // we will try to decode the next service (CreateSession) and if it succeeds we change the mode to Sign
        // or SignAndEncrypt accordingly
        store_encryption_info(pinfo, UA_MessageMode_MaybeEncrypted, sig_len);
    }

    data->encrypted = encrypted;
    if (!encrypted) {
        parseSequenceHeader(tree, tvb, pOffset, data);
        ServiceId = parseService(tree, tvb, pinfo,pOffset, data);
    }

    return ServiceId;
}

int parseCloseSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data _U_)
{
    parseMessageHeader(tree, tvb, pinfo, pOffset, data);
    proto_tree_add_item(tree, hf_opcua_transport_scid, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN); *pOffset+=4;

    return -1;
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
