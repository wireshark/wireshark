/* packet-pnrp.h
 * Routines for Peer Name Resolution Protocol (PNRP) dissection
 *
 *  Copyright 2010, Jan Gerbecks <jan.gerbecks@stud.uni-due.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* The official Dokumentation for the Peer Name Resolution Protocol can be found at
 http://msdn.microsoft.com/en-us/library/cc239047(PROT.13).aspx
 This dissector is based on Revision 6.1.2
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#define PROTONAME "Peer Network Resolution Protocol"
#define PROTOSHORTNAME "PNRP"
#define PROTOABBREV "pnrp"

#define PNRP_PORT 3540

#define FIELDID_LENGTH = 2
#define LENGTH_FIELD = 2

/* Define all FieldIDs here, so we can use them later on in switch statement etc */
#define PNRP_HEADER         0x0010
#define PNRP_HEADER_ACKED   0x0018
#define PNRP_ID             0x0030
#define TARGET_PNRP_ID      0x0038
#define VALIDATE_PNRP_ID    0x0039
#define FLAGS_FIELD         0x0040
#define FLOOD_CONTROLS      0x0043
#define SOLICIT_CONTROLS    0x0044
#define LOOKUP_CONTROLS     0x0045
#define EXTENDED_PAYLOAD    0x005A
#define PNRP_ID_ARRAY       0x0060
#define CERT_CHAIN          0x0080
#define WCHAR               0x0084
#define CLASSIFIER          0x0085
#define HASHED_NONCE        0x0092
#define NONCE               0x0093
#define SPLIT_CONTROLS      0x0098
#define ROUTING_ENTRY       0x009A
#define VALIDATE_CPA        0x009B
#define REVOKE_CPA          0x009C
#define IPV6_ENDPOINT       0x009D
#define IPV6_ENDPOINT_ARRAY 0x009E

/* Define all message types */
#define SOLICIT             0x01
#define ADVERTISE           0x02
#define REQUEST             0x03
#define FLOOD               0x04
#define INQUIRE             0x07
#define AUTHORITY           0x08
#define ACK                 0x09
#define LOOKUP              0x0B

/* Define flags mask fields */
#define FLAGS_INQUIRE_RESERVED1       0xFFE0
#define FLAGS_INQUIRE_A               0x0010
#define FLAGS_INQUIRE_X               0x0008
#define FLAGS_INQUIRE_C               0x0004
#define FLAGS_INQUIRE_RESERVED2       0x0003

#define FLAGS_AUTHORITY_RESERVED1     0xFC00
#define FLAGS_AUTHORITY_L             0x0200
#define FLAGS_AUTHORITY_RESERVED2     0x01F0
#define FLAGS_AUTHORITY_B             0x0008
#define FLAGS_AUTHORITY_RESERVED3     0x0006
#define FLAGS_AUTHORITY_N             0x0001

#define FLAGS_LOOKUPCONTROLS_RESERVED 0xFFFC
#define FLAGS_LOOKUPCONTROLS_A        0x0002
#define FLAGS_LOOKUPCONTROLS_0        0x0001

#define FLAGS_ENCODED_CPA_RESERVED    0xC0
#define FLAGS_ENCODED_CPA_X           0x20
#define FLAGS_ENCODED_CPA_U           0x02
#define FLAGS_ENCODED_CPA_R           0x01
#define FLAGS_ENCODED_CPA_A           0x04
#define FLAGS_ENCODED_CPA_C           0x08
#define FLAGS_ENCODED_CPA_F           0x10

/* Define all helper methods  */
static void dissect_pnrp_ids(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_ipv6_address(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_route_entry(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_ipv6_endpoint_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_encodedCPA_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_payload_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_publicKey_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);
static void dissect_signature_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree);

/* Define global variables
 ----------------------------*/
static int proto_pnrp = -1;

/* Define FieldIDs */
static const value_string fieldID[] = {
    { PNRP_HEADER,         "PNRP_HEADER" },
    { PNRP_HEADER_ACKED,   "PNRP_HEADER_ACKED" },
    { PNRP_ID,             "PNRP_ID" },
    { TARGET_PNRP_ID,      "TARGET_PNRP_ID" },
    { VALIDATE_PNRP_ID,    "VALIDATE_PNRP_ID" },
    { FLAGS_FIELD,         "FLAGS_FIELD" },
    { FLOOD_CONTROLS,      "FLOOD_CONTROLS" },
    { SOLICIT_CONTROLS,    "SOLICIT_CONTROLS" },
    { LOOKUP_CONTROLS,     "LOOKUP_CONTROLS" },
    { EXTENDED_PAYLOAD,    "EXTENDED_PAYLOAD" },
    { PNRP_ID_ARRAY,       "PNRP_ID_ARRAY" },
    { CERT_CHAIN,          "CERT_CHAIN" },
    { WCHAR,               "WCHAR" },
    { CLASSIFIER,          "CLASSIFIER" },
    { HASHED_NONCE,        "HASHED_NONCE" },
    { NONCE,               "NONCE" },
    { SPLIT_CONTROLS,      "SPLIT_CONTROLS" },
    { ROUTING_ENTRY,       "ROUTING_ENTRY" },
    { VALIDATE_CPA,        "VALIDATE_CPA" },
    { REVOKE_CPA,          "REVOKE_CPA" },
    { IPV6_ENDPOINT,       "IPV6_ENDPOINT" },
    { IPV6_ENDPOINT_ARRAY, "IPV6_ENDPOINT_ARRAY" },
    {0,                     NULL}
};

/* Define Packetnames */
static const value_string messageType[] = {
    { SOLICIT,             "SOLICIT" },
    { ADVERTISE,           "ADVERTISE" },
    { REQUEST,             "REQUEST" },
    { FLOOD,               "FLOOD" },
    { INQUIRE,             "INQUIRE" },
    { AUTHORITY,           "AUTHORITY" },
    { ACK,                 "ACK" },
    { LOOKUP,              "LOOKUP" },
    {0,                     NULL}
};
/* Define Solicit Type */
static const value_string solicitType[] = {
    { 0x00,                "SOLICIT_TYPE_ANY" },
    { 0x01,                "SOLICIT_TYPE_LOCAL" },
    {0,                     NULL}
};
/* Define Resolve Criteria for Lookup Controls */
static const value_string resolveCriteria[] = {
    { 0x00,                "SEARCH_OPCODE_NONE" },
    { 0x01,                "SEARCH_OPCODE_ANY_PEERNAME" },
    { 0x02,                "SEARCH_OPCODE_NEAREST_PEERNAME" },
    { 0x04,                "SEARCH_OPCODE_NEAREST64_PEERNAME" },
    { 0x08,                "SEARCH_OPCODE_UPPER_BITS" },
    {0,                     NULL}
};
/* Define Reason Code for Lookup Controls */
static const value_string reasonCode[] = {
    { 0x00,                "REASON_APP_REQUEST" },
    { 0x01,                "REASON_REGISTRATION" },
    { 0x02,                "REASON_CACHE_MAINTENANCE" },
    { 0x03,                "REASON_SPLIT_DETECTION" },
    {0,                     NULL}
};

/* Define IDs for subcomponents */
/* Message Header */
static gint hf_pnrp_header = -1;
static gint hf_pnrp_header_fieldID = -1;
static gint hf_pnrp_header_length = -1;
static gint hf_pnrp_header_ident = -1;
static gint hf_pnrp_header_versionMajor = -1;
static gint hf_pnrp_header_versionMinor = -1;
static gint hf_pnrp_header_messageType = -1;
static gint hf_pnrp_header_messageID = -1;
/* Message Body */
static gint hf_pnrp_message_type = -1;
static gint hf_pnrp_message_length = -1;
static gint hf_pnrp_message_headerack = -1;
static gint hf_pnrp_message_pnrpID = -1;    /* Generic variable to display pnrp ID in various situations */
/* Inquire Message Flags */
static gint hf_pnrp_message_inquire_flags = -1;
static gint hf_pnrp_message_inquire_flags_reserved1 = -1;
static gint hf_pnrp_message_inquire_flags_Abit = -1;
static gint hf_pnrp_message_inquire_flags_Xbit = -1;
static gint hf_pnrp_message_inquire_flags_Cbit = -1;
static gint hf_pnrp_message_inquire_flags_reserved2 = -1;

static const int *inquire_flags[] = {
    &hf_pnrp_message_inquire_flags_reserved1,
    &hf_pnrp_message_inquire_flags_Abit,
    &hf_pnrp_message_inquire_flags_Xbit,
    &hf_pnrp_message_inquire_flags_Cbit,
    &hf_pnrp_message_inquire_flags_reserved2,
    NULL
};

/* Classifier */
static gint hf_pnrp_message_classifier_unicodeCount = -1;
static gint hf_pnrp_message_classifier_arrayLength = -1;
static gint hf_pnrp_message_classifier_entryLength = -1;
/* ACK Message Flags */
static gint hf_pnrp_message_ack_flags_reserved = -1;
static gint hf_pnrp_message_ack_flags_Nbit = -1;
/* SplitControls */
static gint hf_pnrp_message_splitControls_authorityBuffer = -1;
/* IPv6 Endpoint Array */
static gint hf_pnrp_message_ipv6EndpointArray_NumberOfEntries = -1;
static gint hf_pnrp_message_ipv6EndpointArray_ArrayLength = -1;
static gint hf_pnrp_message_ipv6EndpointArray_EntryLength = -1;
/* AUTHORITY Message Flags */
static gint hf_pnrp_message_authority_flags = -1;
static gint hf_pnrp_message_authority_flags_reserved1 = -1;
static gint hf_pnrp_message_authority_flags_Lbit = -1;
static gint hf_pnrp_message_authority_flags_reserved2 = -1;
static gint hf_pnrp_message_authority_flags_Bbit = -1;
static gint hf_pnrp_message_authority_flags_reserved3= -1;
static gint hf_pnrp_message_authority_flags_Nbit = -1;

static const int *authority_flags[] = {
    &hf_pnrp_message_authority_flags_reserved1,
    &hf_pnrp_message_authority_flags_Lbit,
    &hf_pnrp_message_authority_flags_reserved2,
    &hf_pnrp_message_authority_flags_Bbit,
    &hf_pnrp_message_authority_flags_reserved3,
    &hf_pnrp_message_authority_flags_Nbit,
    NULL
};

/* Flood Control Flags */
static gint hf_pnrp_message_flood_flags_reserved1 = -1;
static gint hf_pnrp_message_flood_flags_Dbit = -1;

/* PNRP ID Array */
static gint hf_pnrp_message_idArray_NumEntries = -1;
static gint hf_pnrp_message_idArray_Length = -1;
static gint hf_pnrp_message_ElementFieldType = -1;
static gint hf_pnrp_message_idarray_Entrylength = -1;

static gint hf_pnrp_message_solicitType = -1;
static gint hf_pnrp_message_certChain = -1;
static gint hf_pnrp_message_nonce = -1;
static gint hf_pnrp_message_hashednonce = -1;
static gint hf_pnrp_message_ipv6 = -1;

/* Encoded CPA */
static gint hf_pnrp_encodedCPA = -1;
static gint hf_pnrp_encodedCPA_length = -1;
static gint hf_pnrp_encodedCPA_minorVersion = -1;
static gint hf_pnrp_encodedCPA_majorVersion = -1;
static gint hf_pnrp_encodedCPA_flags = -1;
static gint hf_pnrp_encodedCPA_flags_reserved = -1;
static gint hf_pnrp_encodedCPA_flags_Xbit = -1;
static gint hf_pnrp_encodedCPA_flags_Fbit = -1;
static gint hf_pnrp_encodedCPA_flags_Cbit = -1;
static gint hf_pnrp_encodedCPA_flags_Abit = -1;
static gint hf_pnrp_encodedCPA_flags_Ubit = -1;
static gint hf_pnrp_encodedCPA_flags_Rbit = -1;
static const int *encodedCPA_flags[] = {
    &hf_pnrp_encodedCPA_flags_reserved,
    &hf_pnrp_encodedCPA_flags_Xbit,
    &hf_pnrp_encodedCPA_flags_Fbit,
    &hf_pnrp_encodedCPA_flags_Cbit,
    &hf_pnrp_encodedCPA_flags_Abit,
    &hf_pnrp_encodedCPA_flags_Ubit,
    &hf_pnrp_encodedCPA_flags_Rbit,
    NULL
};
static gint hf_pnrp_encodedCPA_notAfter = -1;
static gint hf_pnrp_encodedCPA_serviceLocation = -1;
static gint hf_pnrp_encodedCPA_binaryAuthority = -1;
static gint hf_pnrp_encodedCPA_classifiertHash = -1;
static gint hf_pnrp_encodedCPA_friendlyName = -1;

/* Lookup Controls */
static gint hf_pnrp_message_lookupControls_flags = -1;
static gint hf_pnrp_message_lookupControls_flags_reserved = -1;
static gint hf_pnrp_message_lookupControls_flags_Abit = -1;
static gint hf_pnrp_message_lookupControls_flags_0bit = -1;
static const int *lookupControls_flags[] = {
    &hf_pnrp_message_lookupControls_flags_reserved,
    &hf_pnrp_message_lookupControls_flags_Abit,
    &hf_pnrp_message_lookupControls_flags_0bit,
    NULL
};
static gint hf_pnrp_message_lookupControls_precision =-1;
static gint hf_pnrp_message_lookupControls_resolveCriteria =-1;
static gint hf_pnrp_message_lookupControls_reasonCode =-1;

/* Dissect Route Entry */
static gint hf_pnrp_message_routeEntry_portNumber = -1;
static gint hf_pnrp_message_routeEntry_flags = -1;
static gint hf_pnrp_message_routeEntry_addressCount = -1;

/* Public Key Structure */
static gint hf_pnrp_publicKey_objID = -1;
static gint hf_pnrp_publicKey_publicKeyData = -1;

/* Signature Structure */
static gint hf_pnrp_signature_signatureData = -1;

/* Define variables to reference subtrees */
static gint ett_pnrp = -1;
static gint ett_pnrp_header = -1;
static gint ett_pnrp_message = -1;
static gint ett_pnrp_message_inquire_flags = -1;
static gint ett_pnrp_message_authority_flags = -1;
static gint ett_pnrp_message_encodedCPA = -1;
static gint ett_pnrp_message_encodedCPA_flags = -1;
static gint ett_pnrp_message_lookupControls_flags = -1;
static gint ett_pnrp_message_payloadStructure = -1;
static gint ett_pnrp_message_publicKeyStructure = -1;
static gint ett_pnrp_message_signatureStructure = -1;


/* Do actual dissection work */
static int dissect_pnrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Variable declaration */
    gint offset;
    gint padding_bytes;
    guint8 message_type;
    guint16 field_type;
    guint16 data_length;


    /*----------------------------------------
     * Validate if it is really a PNRP Packet
     *----------------------------------------*/
    /* Check that there's enough data */
    /* XXX: ISTR that tvb_length should be used when     */
    /*      initially checking for a valid packet for a  */
    /*      new style dissector.                         */
    /*      ToDo: confirm                                */
    data_length = tvb_reported_length(tvb);

    /* Shortest Message is ACK -> 12 Bytes for Header plus 8 Bytes for Data */
    if (data_length <  12+8 )
    {
        return 0;
    }

    /* Check some values from the packet header */
    /* First 2 bytes must be 0x0010 */
    if (tvb_get_ntohs(tvb,0) != PNRP_HEADER )
    {
        return 0;
    }
    /* Length of Header must be 0x000C = 12 */
    if (tvb_get_ntohs(tvb,2) != 0x000C) {
        return 0;
    }
    /* Identifier must 0x51 */
    if (tvb_get_guint8(tvb,4) != 0x51) {
        return 0;
    }


    /* Assign Values to Variables */
    /* Use to track data */
    offset= 0;
    padding_bytes = 0;
    /* Get the message Information beforehand */
    message_type = tvb_get_guint8(tvb,7);


    /* Simply Display the Protcol Name in the INFO column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "pnrp");
    /* Clear out stuff in the info column */
    col_add_fstr(pinfo->cinfo, COL_INFO, "PNRP %s Message ",
                 val_to_str(message_type, messageType, "Unknown (0x%02x)"));


    /* If tree is NULL we are asked for summary, otherwise for details */
    if(tree){ /* we are beeing asked for details */
        proto_item *ti;
        proto_tree *pnrp_tree;

        proto_item *pnrp_header_item;
        proto_tree *pnrp_header_tree;

        proto_item *pnrp_message_tree = NULL;
        proto_item *pnrp_message_item = NULL;


        /* Lets add a subtree to our dissection to display the info */
        ti = proto_tree_add_item(tree, proto_pnrp, tvb, 0, -1, FALSE);
        proto_item_append_text(ti, ", Message Type %s",
                               val_to_str(message_type, messageType, "Unknown (0x%02x)"));
        /* Get a main tree for the whole protocol */
        pnrp_tree = proto_item_add_subtree(ti, ett_pnrp);

        /*-------------------------------
         *--Add all Header Fields
         *------------------------------*/
        /* Get a subtree for the Header */
        pnrp_header_item = proto_tree_add_item(pnrp_tree, hf_pnrp_header, tvb, offset,12,ENC_NA);
        pnrp_header_tree = proto_item_add_subtree(pnrp_header_item, ett_pnrp_header);

        /* Add Field ID should be 0c0010 */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_fieldID,tvb,offset,2,ENC_BIG_ENDIAN);
        offset += 2;
        /* Add Length should be 0x000C */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_length,tvb,offset,2,ENC_BIG_ENDIAN);
        offset += 2;
        /* Add Ident should be 0x51 */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_ident,tvb,offset,1,ENC_BIG_ENDIAN);
        offset += 1;
        /* Add Major Version */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_versionMajor,tvb,offset,1,ENC_BIG_ENDIAN);
        offset += 1;
        /* Add Minor Version */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_versionMinor,tvb,offset,1,ENC_BIG_ENDIAN);
        offset += 1;
        /* Add Message Type */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_messageType,tvb,offset,1,ENC_BIG_ENDIAN);
        offset += 1;
        /* Add Message ID */
        proto_tree_add_item(pnrp_header_tree,hf_pnrp_header_messageID,tvb,offset,4,ENC_BIG_ENDIAN);
        offset += 4;


        /*-------------------------------
         *--Add all Message Fields
         *------------------------------*/

        /* The following part has dynamic length depending on message type */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            /* Determine the Field Type */
            field_type = tvb_get_ntohs(tvb,offset );
            /* Determine length of this message */
            data_length = tvb_get_ntohs(tvb,offset + 2);

            /* Length must be at least 4, because field_type and data_length are part of data_length information */
            if (data_length < 4) {
                if (tree) {
                    pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset, 4, "Message with invalid length %u (< 4)", data_length);
                    pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                    proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                }
                offset += 4;
                /* Don't continue parsing this message segment */
                break;
            }
            /* Actual Parsing of the message Type */
            switch (field_type) {
                /* First Field in ACK Message */
                case PNRP_HEADER_ACKED:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                        data_length, "Message ACK ID: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_headerack, tvb, offset + 4, data_length -4, ENC_BIG_ENDIAN);

                    }
                    offset += data_length;
                    break;

                    /* A validate pnrp id follows as found in FLOOD */
                case VALIDATE_PNRP_ID:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Validate PNRP ID: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* We can have a large number of pnrp IDs here */
                        dissect_pnrp_ids(tvb,offset+4,data_length-4,pnrp_message_tree);

                    }
                    offset += data_length;
                    break;

                    /* The Flags have different meaning, depending on the message */
                case FLAGS_FIELD:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Flags Field: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        switch (message_type) {
                            case INQUIRE:
                                proto_tree_add_bitmask(pnrp_message_tree, tvb, offset+4, hf_pnrp_message_inquire_flags, ett_pnrp_message_inquire_flags, inquire_flags, FALSE);
                                proto_tree_add_text(pnrp_message_tree, tvb, offset + 6, 2, "Padding : %d - 2 Bytes",tvb_get_ntohs(tvb,offset+6));
                                offset += data_length+2;

                                break;

                            case ACK:
                                /* Reserved 0 - 14 bits */
                                proto_tree_add_bits_item(pnrp_message_tree, hf_pnrp_message_ack_flags_reserved, tvb, (offset + 4)*8, 15, FALSE);
                                /* N - Bit */
                                proto_tree_add_bits_item(pnrp_message_tree, hf_pnrp_message_ack_flags_Nbit, tvb,((offset + 4)*8)+15, 1, FALSE);
                                offset += data_length;
                                break;
                            case AUTHORITY:
                                proto_tree_add_bitmask(pnrp_message_tree, tvb, offset+4, hf_pnrp_message_authority_flags, ett_pnrp_message_authority_flags, authority_flags, FALSE);
                                /* Check if the Flags Field is the last message part. If so, no padding of 2 bytes is added */
                                if(tvb_reported_length_remaining(tvb, offset+data_length)==0)
                                {
                                    offset += data_length;
                                }
                                else {
                                    padding_bytes = 2;
                                    proto_tree_add_text(pnrp_message_tree, tvb, offset + 6, padding_bytes, "Padding: %d bytes", padding_bytes);
                                    offset += data_length+2;
                                }
                                break;


                            default:
                                proto_tree_add_text(pnrp_message_tree, tvb, offset + 4, data_length -4, "Flags");
                                offset += data_length;
                                break;
                        }

                    }

                    break;

                    /* Flood controls found in FLOOD Message */
                case FLOOD_CONTROLS:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Flood Control: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* Reserved 1 - 15 bits */
                        proto_tree_add_bits_item(pnrp_message_tree, hf_pnrp_message_flood_flags_reserved1, tvb, (offset + 4)*8, 15, FALSE);
                        /* D - Bit */
                        proto_tree_add_bits_item(pnrp_message_tree, hf_pnrp_message_flood_flags_Dbit, tvb,((offset + 4)*8)+15, 1, FALSE);
                        /* Reserved 2 */
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 6, 1, "Reserved 2: %d",tvb_get_guint8(tvb,offset+6));
                        /* Padding 1 */
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 7, 1, "Padding: %d",tvb_get_guint8(tvb,offset+7));
                    }

                    offset += data_length+1;
                    break;

                    /* Solicit Controls found in SOLICIT Message */
                case SOLICIT_CONTROLS:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Solicit Controls: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 4, 1, "Reserved : %d",tvb_get_guint8(tvb,offset+4));
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_solicitType, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 6, 2, "Reserved : %d",tvb_get_ntohs(tvb,offset+6));
                    }
                    offset += data_length +2;   /* Padding involved */
                    break;
                    /* Lookup controls found in LOOKUP Message */
                case LOOKUP_CONTROLS:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Lookup Control: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* 2 Bytes of Flags */
                        proto_tree_add_bitmask(pnrp_message_tree, tvb, offset+4, hf_pnrp_message_lookupControls_flags, ett_pnrp_message_lookupControls_flags, lookupControls_flags, FALSE);
                        /* Precision Bytes */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_lookupControls_precision, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
                        /* Resolve Criteria */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_lookupControls_resolveCriteria, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                        /* Reason Code */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_lookupControls_reasonCode, tvb, offset + 9, 1, ENC_BIG_ENDIAN);
                        /* Reserved */
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 10, 2, "Reserved : %d",tvb_get_ntohs(tvb,offset+10));

                    }

                    offset += data_length;
                    break;
                    /* Target PNRP ID found in Lookup Message */
                case TARGET_PNRP_ID:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Target PNRP ID: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        dissect_pnrp_ids(tvb, offset+4, data_length-4, pnrp_message_tree);
                    }

                    offset += data_length;
                    break;

                    /* Extended Payload found in AUTHORITY Message */
                case EXTENDED_PAYLOAD:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Extended Payload: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* TODO: Do actual parsing */
                    }

                    offset += data_length;
                    break;
                    /* Pnrp id Array as found in REQUEST & ADVERTISE Message */
                case PNRP_ID_ARRAY:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "PNRP ID Array: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_idArray_NumEntries, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_idArray_Length, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_ElementFieldType, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_idarray_Entrylength, tvb, offset + 10, 2, ENC_BIG_ENDIAN);
                        dissect_pnrp_ids(tvb,offset+12,data_length-12,pnrp_message_tree);
                    }

                    offset += data_length;
                    break;
                    /* Cert Chain follows as found in AUTHORITY */
                case CERT_CHAIN:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "CERT Chain: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_certChain, tvb, offset + 4, data_length-4, FALSE);
                    }

                    /* There might be padding, so fill up to the next byte */
                    padding_bytes = 0;
                    while (data_length%4 != 0 &&tvb_reported_length_remaining(tvb, offset+data_length)>0) {
                        data_length++;
                        padding_bytes++;
                    }
                    /* Check if we actually had some padding bytes */
                    if (0<padding_bytes) {
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + data_length-padding_bytes, padding_bytes, "Padding: %d bytes", padding_bytes);
                    }
                    offset += data_length;
                    break;
                    /* classifier: A classifier string follows as found in AUTHORITY */
                case CLASSIFIER:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Classifier: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* NumEntries */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_classifier_unicodeCount, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                        /* Array Length: 8+(NumEntries*EntryLength */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_classifier_arrayLength, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
                        /* Element Field Type: WCHAR */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset+8 , 2, ENC_BIG_ENDIAN);
                        /* Entry Length: Must be 0x0002 */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_classifier_entryLength, tvb, offset + 10, 2, ENC_BIG_ENDIAN);
                        /* The actual classifier String */
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 12, tvb_get_ntohs(tvb,offset+6)-8, "Classifier: %s",tvb_get_ephemeral_faked_unicode(tvb, offset + 12, (tvb_get_ntohs(tvb,offset+6)-8)/2, FALSE));
                    }

                    /* There might be padding, so fill up to the next byte */
                    padding_bytes = 0;
                    while (data_length%4 != 0 &&tvb_reported_length_remaining(tvb, offset+data_length)>0) {
                        data_length++;
                        padding_bytes++;
                    }
                    /* Check if we actually had some padding bytes */
                    if (0<padding_bytes) {
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + data_length-padding_bytes, padding_bytes, "Padding: %d bytes", padding_bytes);
                    }
                    offset += data_length;
                    break;
                    /* A hashed nonce follows as found in ADVERTISE & SOLICIT */
                case HASHED_NONCE:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Hashed Nonce: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_hashednonce, tvb, offset + 4, data_length-4, ENC_NA);

                    }

                    offset += data_length;
                    break;

                    /* A nonce follows as found in REQUEST & INQUIRE */
                case NONCE:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Nonce: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_nonce, tvb, offset + 4, data_length-4, ENC_NA);
                    }

                    offset += data_length;
                    break;

                    /* split controls as found in AUTHORITY */
                case SPLIT_CONTROLS:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Split controls: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* Size of Authority Buffer */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_splitControls_authorityBuffer, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                        /* Byte offset */
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + 6, 2, "Offset : %d",tvb_get_ntohs(tvb,offset+6));

                    }

                    /* There could be data offset */
                    offset += data_length+tvb_get_ntohs(tvb,offset+6);
                    break;

                    /* routing entry: A route entry follows as found in ADVERTISE, INQUIRE, LOOKUP & AUTHORITY */
                case ROUTING_ENTRY:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Routing Entry: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        dissect_route_entry(tvb,offset+4, tvb_get_ntohs(tvb,offset+2)-4, pnrp_message_tree);
                    }

                    /* There might be padding, so fill up to the next byte */
                    padding_bytes = 0;
                    while (data_length%4 != 0 &&tvb_reported_length_remaining(tvb, offset+data_length)>0) {
                        data_length++;
                        padding_bytes++;
                    }
                    /* Check if we actually had some padding bytes */
                    if (0<padding_bytes) {
                        proto_tree_add_text(pnrp_message_tree, tvb, offset + data_length-padding_bytes, padding_bytes, "Padding: %d bytes", padding_bytes);
                    }
                    offset += data_length;
                    break;

                    /* validate cpa: an encoded CPA structure follows as found in AUTHORITY */
                case VALIDATE_CPA:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Validate CPA: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* Do the actual parsing in own method */
                        dissect_encodedCPA_structure(tvb, offset+4, data_length-4, pnrp_message_tree);

                    }

                    offset += data_length;
                    break;


                    /* IPV6 Endpoint: an ipv6 endpoint array structure follows as found in LOOKUP */
                case IPV6_ENDPOINT_ARRAY:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "IPv6 Endpoint Array: ");
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        /* Number of route entries */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_ipv6EndpointArray_NumberOfEntries, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                        /* Array length */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_ipv6EndpointArray_ArrayLength, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
                        /* Element Field Type */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset+8 , 2, ENC_BIG_ENDIAN);
                        /* Entry Length: must be 0x0012 (18 bytes) */
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_ipv6EndpointArray_EntryLength, tvb, offset + 10, 2, ENC_BIG_ENDIAN);
                        /* Flagged Path */
                        dissect_ipv6_endpoint_structure(tvb, offset+12, tvb_get_ntohs(tvb,offset+6)-8,pnrp_message_tree);
                    }

                    offset += data_length;
                    break;

                default:
                    if (tree) {
                        pnrp_message_item = proto_tree_add_text(pnrp_tree, tvb, offset,
                                                                data_length, "Type: %s, length: %u",
                                                                val_to_str(field_type, fieldID, "Unknown (0x%04x)"), data_length);
                        pnrp_message_tree = proto_item_add_subtree(pnrp_message_item, ett_pnrp_message);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_type, tvb, offset , 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(pnrp_message_tree, hf_pnrp_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                        if(data_length > 4)
                        {
                            proto_tree_add_text(pnrp_message_tree, tvb, offset + 4, data_length -4, "Data");
                        }
                        else {
                            return 0;
                        }
                    }
                    offset += data_length;
                    break;
            }
        }
    }
    return offset;

}

/*--------------------------------------------------------------*
 * Dissecting helper methods                                    *
 *--------------------------------------------------------------*/

static void dissect_pnrp_ids(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    while (32 <=length) {
        proto_tree_add_item(tree, hf_pnrp_message_pnrpID, tvb, offset, 32, ENC_NA);
        length -= 32;
        offset += 32;
    }

}

static void dissect_route_entry(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    gint tmp_offset;
    /* Check if we don't run out of data */
    if (0 <= tvb_reported_length_remaining(tvb, offset+length)) {
        tmp_offset = 0;
        /* First, we have a 32 Bit long PNRP ID */
        proto_tree_add_item(tree, hf_pnrp_message_pnrpID, tvb, offset+tmp_offset, 32, ENC_NA);
        tmp_offset +=32;
        /* Add PNRP Major Version */
        proto_tree_add_item(tree,hf_pnrp_header_versionMajor,tvb,offset+tmp_offset,1,ENC_BIG_ENDIAN);
        tmp_offset += 1;
        /* Add Minor Version */
        proto_tree_add_item(tree,hf_pnrp_header_versionMinor,tvb,offset+tmp_offset,1,ENC_BIG_ENDIAN);
        tmp_offset +=1;
        /* Port Number */
        proto_tree_add_item(tree,hf_pnrp_message_routeEntry_portNumber,tvb,offset+tmp_offset,2,ENC_BIG_ENDIAN);
        tmp_offset +=2;
        /* Flags */
        proto_tree_add_item(tree,hf_pnrp_message_routeEntry_flags,tvb,offset+tmp_offset,1,ENC_BIG_ENDIAN);
        tmp_offset +=1;
        /* Address count */
        proto_tree_add_item(tree,hf_pnrp_message_routeEntry_addressCount,tvb,offset+tmp_offset,1,ENC_BIG_ENDIAN);
        tmp_offset +=1;
        /* IPv6 Addresses */
        dissect_ipv6_address(tvb, offset+tmp_offset, length -tmp_offset, tree);
    }
}

static void dissect_ipv6_endpoint_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    /* Check if we don't run out of data */
    while (0 <= tvb_reported_length_remaining(tvb, offset+18) && 18 <=length) {
        /* Port Number */
        proto_tree_add_text(tree, tvb, offset, 2, "Port Number : %d",tvb_get_ntohs(tvb, offset));
        /* IPv6 Addresses */
        dissect_ipv6_address(tvb, offset+2,16,tree);
        offset += 18;
        length -= 18;
    }
}

static void dissect_ipv6_address(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    while (0 <= tvb_reported_length_remaining(tvb, offset+16) && 16 <=length) {
        proto_tree_add_item(tree, hf_pnrp_message_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
        length -= 16;
    }
}

static void dissect_encodedCPA_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    /* Check if we don't run out of data */
    if (0 <= tvb_reported_length_remaining(tvb, offset+length)) {
        guint8 flagsField;
        /* Add a new subtree */
        proto_item *pnrp_encodedCPA_tree = NULL;
        proto_item *pnrp_encodedCPA_item = NULL;
        pnrp_encodedCPA_item = proto_tree_add_item(tree, hf_pnrp_encodedCPA, tvb, offset,length,ENC_NA);
        pnrp_encodedCPA_tree = proto_item_add_subtree(pnrp_encodedCPA_item, ett_pnrp_message_encodedCPA);

        /* Length information */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        /* CPA Minor Version */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_minorVersion, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        /* CPA Major Version */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_majorVersion, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        /* PNRP Minor Version */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_header_versionMinor, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        /* PNRP Major Version */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_header_versionMajor, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        /* Flags Field */
        proto_tree_add_bitmask(pnrp_encodedCPA_tree, tvb, offset+6, hf_pnrp_encodedCPA_flags, ett_pnrp_message_encodedCPA_flags, encodedCPA_flags, FALSE);
        flagsField = tvb_get_guint8(tvb,offset+6);
        /* Reserved */
        proto_tree_add_text(pnrp_encodedCPA_tree, tvb, offset + 7, 1, "Reserved");
        /* Not After */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_notAfter, tvb, offset+8, 8, FALSE);
        /* Service Location */
        proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_serviceLocation, tvb, offset+16, 16, ENC_NA);

        /* now, the structure is variable, so add bytes to offset */
        offset +=32;

        /* Check if R Flag is set */
        if ((flagsField & FLAGS_ENCODED_CPA_R)==0x00) {
            /* Nonce follows */
            proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_message_nonce, tvb, offset, 16, ENC_NA);
            offset +=16;
        }
        /* Check if A Flag is set */
        if (flagsField & FLAGS_ENCODED_CPA_A) {
            /* Binary authority */
            proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_binaryAuthority, tvb, offset, 20, ENC_NA);
            offset +=20;
        }
        /* Check if C Flag is set */
        if (flagsField & FLAGS_ENCODED_CPA_C) {
            /* Classifiert Hash */
            proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_classifiertHash, tvb, offset, 20, ENC_NA);
            offset +=20;
        }
        /* Check if F Flag is set */
        if (flagsField & FLAGS_ENCODED_CPA_F) {
            /* Friendly Name Length */
            proto_tree_add_text(pnrp_encodedCPA_tree, tvb, offset,2, "Length of Friendly name : %d",tvb_get_letohs(tvb,offset));
            /* Friendly Name */
            proto_tree_add_item(pnrp_encodedCPA_tree, hf_pnrp_encodedCPA_friendlyName, tvb, offset+2, tvb_get_letohs(tvb,offset), FALSE);
            offset +=tvb_get_letohs(tvb,offset)+2;
        }
        /* Service Address List */
        proto_tree_add_text(pnrp_encodedCPA_tree, tvb, offset,2, "Number of Service Addresses : %d",tvb_get_letohs(tvb,offset));
        offset += 2;
        proto_tree_add_text(pnrp_encodedCPA_tree, tvb, offset,2, "Service Address Length : %d",tvb_get_letohs(tvb,offset));
        offset += 2;
        /* A list of IPV6_Endpoint Structures follows */
        dissect_ipv6_endpoint_structure(tvb, offset,tvb_get_letohs(tvb,offset-4)*tvb_get_letohs(tvb,offset-2) , pnrp_encodedCPA_tree);
        offset += tvb_get_letohs(tvb,offset-4)*tvb_get_letohs(tvb,offset-2);
        /* A number of Payload Structures */
        proto_tree_add_text(pnrp_encodedCPA_tree, tvb, offset,2, "Number of Payload Structures : %d",tvb_get_letohs(tvb,offset));
        offset += 2;
        proto_tree_add_text(pnrp_encodedCPA_tree, tvb, offset,2, "Total Bytes of Payload : %d",tvb_get_letohs(tvb,offset));
        offset += 2;
        dissect_payload_structure(tvb,offset, tvb_get_letohs(tvb,offset-2)-4,pnrp_encodedCPA_tree);
        offset += tvb_get_letohs(tvb,offset-2)-4;
        /* Public Key */
        dissect_publicKey_structure(tvb, offset,tvb_get_letohs(tvb,offset),pnrp_encodedCPA_tree);
        offset += tvb_get_letohs(tvb,offset);
        /* Signature */
        dissect_signature_structure(tvb, offset,tvb_get_letohs(tvb,offset),pnrp_encodedCPA_tree);
        offset += tvb_get_letohs(tvb,offset);
    }
}
static void dissect_payload_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    guint16 lengthOfData;
    /* Add a new Subtree */
    proto_item *pnrp_payload_tree = NULL;
    proto_item *pnrp_payload_item = NULL;
    /* Check if we actually should display something */
    if (0<length ) {
    pnrp_payload_item = proto_tree_add_text(tree, tvb, offset, length, "Payload Structure");
    pnrp_payload_tree = proto_item_add_subtree(pnrp_payload_item, ett_pnrp_message_payloadStructure);

    /* Dissect the Payload Structure */
    /* Payload Type */
    proto_tree_add_text(pnrp_payload_tree, tvb, offset,4, "Payload Type : %d",tvb_get_letohl(tvb,offset));
    offset += 4;
    /* Data Length */
    lengthOfData = tvb_get_letohs(tvb,offset);
    proto_tree_add_text(pnrp_payload_tree, tvb, offset,2, "Length of Data : %d",lengthOfData);
    offset += 2;
    /* IPV6_APP_ENDPOINT Structure */
    while (0 <= tvb_reported_length_remaining(tvb, offset+20)&& 20 <= lengthOfData) {
        dissect_ipv6_address(tvb, offset, 16, pnrp_payload_tree);
        offset += 16;
        proto_tree_add_text(pnrp_payload_tree, tvb, offset,2, "Port Number : %d",tvb_get_letohs(tvb,offset));
        /* proto_tree_add_item(pnrp_payload_tree, hf_pnrp_payload_port, tvb, offset, 2, FALSE); */
        offset += 2;
        proto_tree_add_text(pnrp_payload_tree, tvb, offset,2, "IANA Protocol Number : %d",tvb_get_letohs(tvb,offset));
        offset += 2;
        lengthOfData -=20;
    }
    }
}
static void dissect_publicKey_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    guint16 objIDLength;
    guint16 cbDataLength;
    /* Add a new Subtree */
    proto_item *pnrp_publicKey_tree = NULL;
    proto_item *pnrp_publicKey_item = NULL;
    /* Check if we can safely parse Data */
    if (0 < length && 0 <= tvb_reported_length_remaining(tvb, offset+length)) {
        pnrp_publicKey_item = proto_tree_add_text(tree, tvb, offset, length, "CPA Public Key Structure");
        pnrp_publicKey_tree = proto_item_add_subtree(pnrp_publicKey_item, ett_pnrp_message_publicKeyStructure);
        /* Parsing of Data */
        /* Field Length of Structure */
        proto_tree_add_text(pnrp_publicKey_tree, tvb, offset,2, "Length of Structure : %d",tvb_get_letohs(tvb,offset));
        offset += 2;
        /* ObjID length */
        objIDLength = tvb_get_letohs(tvb,offset);
        proto_tree_add_text(pnrp_publicKey_tree, tvb, offset,2, "Size of Algorithm OID : %d",objIDLength);
        offset += 2;
        /* Reserved */
        proto_tree_add_text(pnrp_publicKey_tree, tvb, offset,2, "Reserved : %d",tvb_get_ntohs(tvb,offset));
        offset +=2;
        /* Public Key cbData Length */
        cbDataLength = tvb_get_letohs(tvb,offset);
        proto_tree_add_text(pnrp_publicKey_tree, tvb, offset,2, "Size of cbData : %d",cbDataLength);
        offset += 2;
        /* Unused Bits, actually only 7... */
        proto_tree_add_text(pnrp_publicKey_tree, tvb, offset,1, "Unused Bits : %d",7);
        offset +=1;
        /* Algorithm ObjID */
        proto_tree_add_item(pnrp_publicKey_tree, hf_pnrp_publicKey_objID, tvb, offset, objIDLength, FALSE);
        offset += objIDLength;
        /*  Public Key Data */
        proto_tree_add_item(pnrp_publicKey_tree, hf_pnrp_publicKey_publicKeyData, tvb, offset, cbDataLength, FALSE);
    }
}
static void dissect_signature_structure(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    guint16 signatureLength;
    /* Add a new Subtree */
    proto_item *pnrp_signature_tree = NULL;
    proto_item *pnrp_signature_item = NULL;
    /* Check if we can safely parse Data */
    if (0 < length && 0 <= tvb_reported_length_remaining(tvb, offset+length)) {
        pnrp_signature_item = proto_tree_add_text(tree, tvb, offset, length, "Signature Structure");
        pnrp_signature_tree = proto_item_add_subtree(pnrp_signature_item, ett_pnrp_message_signatureStructure);
        /* Parsing of Data */
        /* Field Length of Structure */
        proto_tree_add_text(pnrp_signature_tree, tvb, offset,2, "Length of Structure : %d",tvb_get_letohs(tvb,offset));
        offset +=2;
        /* Signature Length */
        signatureLength = tvb_get_letohs(tvb,offset);
        proto_tree_add_text(pnrp_signature_tree, tvb, offset,2, "Length of Signature : %d",signatureLength);
        offset += 2;
        /* Hash Algorithm Identifier */
        proto_tree_add_text(pnrp_signature_tree, tvb, offset,4, "Hash Algorithm Identifier : %x",tvb_get_letohl(tvb,offset));
        offset += 4;
        /* Signature Data */
        proto_tree_add_item(pnrp_signature_tree, hf_pnrp_signature_signatureData, tvb, offset, signatureLength, ENC_NA);
    }
}
/* Register the protocol */
void proto_register_pnrp(void)
{
    /* A header field is something you can search/filter on.
     *
     * We create a structure to register our fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     */
    static hf_register_info hf[] = {
        { &hf_pnrp_header,
            { "Header", "pnrp.header", FT_NONE, BASE_NONE, NULL, 0x0,
                "PNRP Header", HFILL }},
        { &hf_pnrp_header_fieldID,
            { "Header FieldID", "pnrp.header.fieldID", FT_UINT16, BASE_HEX, VALS(fieldID), 0x0,
                NULL, HFILL }},
        { &hf_pnrp_header_length,
            { "Header length", "pnrp.header.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_header_ident,
            { "Ident", "pnrp.ident", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_header_versionMajor,
            { "Version Major", "pnrp.vMajor", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_header_versionMinor,
            { "Version Minor", "pnrp.vMinor", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_header_messageType,
            { "Message Type", "pnrp.messageType", FT_UINT8, BASE_DEC, VALS(messageType), 0x0,
                NULL, HFILL }},
        { &hf_pnrp_header_messageID,
            { "Message ID", "pnrp.header.messageID", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_type,
            { "Segment Type", "pnrp.segment.type", FT_UINT16, BASE_HEX, VALS(fieldID), 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_length,
            { "Segment length", "pnrp.segment.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                "Message length", HFILL }},
        { &hf_pnrp_message_headerack,
            { "ACKed Header ID", "pnrp.segment.headerAck", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_pnrpID,
            { "PNRP ID", "pnrp.segment.pnrpID", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        /* Inquire Flags */
        { &hf_pnrp_message_inquire_flags,
            { "Flags", "pnrp.segment.inquire.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_inquire_flags_reserved1,
            { "Reserved 1", "pnrp.segment.inquire.flags.reserved1", FT_UINT16, BASE_HEX, NULL, FLAGS_INQUIRE_RESERVED1,
                NULL, HFILL }},
        { &hf_pnrp_message_inquire_flags_Abit,
            { "CPA should (a)ppear in response", "pnrp.segment.inquire.flags.Abit", FT_UINT16, BASE_HEX, NULL, FLAGS_INQUIRE_A,
                NULL, HFILL }},
        { &hf_pnrp_message_inquire_flags_Xbit,
            { "E(X)tended Payload sent in Authority response", "pnrp.segment.inquire.flags.Xbit", FT_UINT16, BASE_HEX, NULL, FLAGS_INQUIRE_X,
                NULL, HFILL }},
        { &hf_pnrp_message_inquire_flags_Cbit,
            { "(C)ertificate Chain sent in Authority response", "pnrp.segment.inquire.flags.Cbit", FT_UINT16, BASE_HEX, NULL, FLAGS_INQUIRE_C,
                NULL, HFILL }},
        { &hf_pnrp_message_inquire_flags_reserved2,
            { "Reserved 2", "pnrp.segment.inquire.flags.reserved2", FT_UINT16, BASE_HEX, NULL, FLAGS_INQUIRE_RESERVED2,
                NULL, HFILL }},
        /* Classifier */
        { &hf_pnrp_message_classifier_unicodeCount,
            { "Number of Unicode Characters", "pnrp.segment.classifier.unicodeCount", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_classifier_arrayLength,
            { "Array Length", "pnrp.segment.classifier.arrayLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_classifier_entryLength,
            { "Entry Length", "pnrp.segment.classifier.entryLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        /* Ack Flags */
        { &hf_pnrp_message_ack_flags_reserved,
            { "Reserved", "pnrp.segment.ack.flags.reserved", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_ack_flags_Nbit,
            { "(N)ot found Bit", "pnrp.segment.ack.flags.Nbit", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        /* Authority Flags */
        { &hf_pnrp_message_authority_flags,
            { "Flags", "pnrp.segment.authority.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_authority_flags_reserved1,
            { "Reserved 1", "pnrp.segment.authority.flags.reserved1", FT_UINT16, BASE_HEX, NULL, FLAGS_AUTHORITY_RESERVED1,
                NULL, HFILL }},
        { &hf_pnrp_message_authority_flags_Lbit,
            { "(L)eaf Set", "pnrp.segment.authority.flags.Lbit", FT_UINT16, BASE_HEX, NULL, FLAGS_AUTHORITY_L,
                NULL, HFILL }},
        { &hf_pnrp_message_authority_flags_reserved2,
            { "Reserved 2", "pnrp.segment.authority.flags.reserved2", FT_UINT16, BASE_HEX, NULL, FLAGS_AUTHORITY_RESERVED2,
                NULL, HFILL }},
        { &hf_pnrp_message_authority_flags_Bbit,
            { "(B)usy", "pnrp.segment.authority.flags.Bbit", FT_UINT16, BASE_HEX, NULL, FLAGS_AUTHORITY_B,
                NULL, HFILL }},
        { &hf_pnrp_message_authority_flags_reserved3,
            { "Reserved 3", "pnrp.segment.authority.flags.reserved3", FT_UINT16, BASE_HEX, NULL, FLAGS_AUTHORITY_RESERVED3,
                NULL, HFILL }},
        { &hf_pnrp_message_authority_flags_Nbit,
            { "(N)ot found", "pnrp.segment.authority.flags.Nbit", FT_UINT16, BASE_HEX, NULL, FLAGS_AUTHORITY_N,
                NULL, HFILL }},
        /* Flood Control Flags */
        { &hf_pnrp_message_flood_flags_reserved1,
            { "Reserved", "pnrp.segment.flood.flags.reserved", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_flood_flags_Dbit,
            { "(D)on't send ACK", "pnrp.segment.flood.flags.Dbit", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        /* Split Controls */
        { &hf_pnrp_message_splitControls_authorityBuffer,
            { "Authority  Buffer Size:", "pnrp.segment.splitControls.authorityBuffer", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        /* IPv6 Endpoint Array */
        { &hf_pnrp_message_ipv6EndpointArray_NumberOfEntries,
            { "Number of Entries:", "pnrp.segment.ipv6EndpointArray.NumberOfEntries", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_ipv6EndpointArray_ArrayLength,
            { "Array Length:", "pnrp.segment.ipv6EndpointArray.ArrayLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_ipv6EndpointArray_EntryLength,
            { "Entry Length", "pnrp.segment.ipv6EndpointArray.EntryLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        /* Encoded CPA structrue */
        { &hf_pnrp_encodedCPA,
            { "Encoded CPA structure", "pnrp.encodedCPA", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_length,
            { "Length", "pnrp.encodedCPA.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_majorVersion,
            { "CPA Major Version", "pnrp.encodedCPA.vMajor", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_minorVersion,
            { "CPA Minor Version", "pnrp.encodedCPA.vMinor", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
            /* Encoded CPA flags */
        { &hf_pnrp_encodedCPA_flags,
            { "Flags", "pnrp.encodedCPA.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_reserved,
            { "Reserved", "pnrp.encodedCPA.flags.reserved", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_RESERVED,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_Xbit,
            { "CPA has E(X)tended Payload", "pnrp.encodedCPA.flags.xbit", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_X,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_Fbit,
            { "CPA contains (F)riendly Name", "pnrp.encodedCPA.flags.fbit", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_F,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_Cbit,
            { "CPA contains (C)lassifier Hash", "pnrp.encodedCPA.flags.cbit", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_C,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_Abit,
            { "CPA contains Binary (A)uthority field", "pnrp.encodedCPA.flags.abit", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_A,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_Ubit,
            { "Friendly Name in (U)TF-8", "pnrp.encodedCPA.flags.ubit", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_U,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_flags_Rbit,
            { "This is a (r)evoke CPA", "pnrp.encodedCPA.flags.rbit", FT_UINT8, BASE_HEX, NULL, FLAGS_ENCODED_CPA_R,
                NULL, HFILL }},
        /* TODO: Find correct way to Display Time */
        { &hf_pnrp_encodedCPA_notAfter,
            { "CPA expiration Date", "pnrp.encodedCPA.expirationDate", FT_UINT64,BASE_DEC, NULL, 0x0,
                "CPA expiration Date since January 1, 1601 UTC", HFILL }},
        { &hf_pnrp_encodedCPA_serviceLocation,
            { "Service Location", "pnrp.encodedCPA.serviceLocation", FT_BYTES,BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_encodedCPA_binaryAuthority,
            { "Binary Authoriy", "pnrp.encodedCPA.binaryAuthority", FT_BYTES,BASE_NONE, NULL, 0x0,
                "SHA-1 Hash of PublicKey Data field", HFILL }},
        { &hf_pnrp_encodedCPA_classifiertHash,
            { "Classifiert Hash", "pnrp.encodedCPA.classifierHash", FT_BYTES,BASE_NONE, NULL, 0x0,
                "SHA-1 Hash of the classifier text", HFILL }},
        { &hf_pnrp_encodedCPA_friendlyName,
            { "Friendly Name of PNRP ID", "pnrp.encodedCPA.friendlyName", FT_STRING,BASE_NONE, NULL, 0x0,
                "A human-readable label identifying the PNRP ID", HFILL }},
        /* Lookup Controls */
        { &hf_pnrp_message_lookupControls_flags,
            { "Flags", "pnrp.lookupControls.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_lookupControls_flags_reserved,
            { "Reserved", "pnrp.lookupControls.flags.reserved", FT_UINT16, BASE_HEX, NULL, FLAGS_LOOKUPCONTROLS_RESERVED,
                NULL, HFILL }},
        { &hf_pnrp_message_lookupControls_flags_Abit,
            { "A bit:", "pnrp.lookupControls.flags.Abit", FT_UINT16, BASE_HEX, NULL, FLAGS_LOOKUPCONTROLS_A,
                "Sender is willing to accept returned nodes that are not closer to the target ID than the Validate PNRP ID", HFILL }},
        { &hf_pnrp_message_lookupControls_flags_0bit,
            { "0 bit - reserved:", "pnrp.lookupControls.flags.0bit", FT_UINT16, BASE_HEX, NULL, FLAGS_LOOKUPCONTROLS_0,
                NULL, HFILL }},
        { &hf_pnrp_message_lookupControls_precision,
            { "Precision", "pnrp.lookupControls.precision", FT_UINT16, BASE_HEX, NULL, 0x0,
                "Precision - Number of significant bits to match", HFILL }},
        { &hf_pnrp_message_lookupControls_resolveCriteria,
            { "Resolve Criteria", "pnrp.lookupControls.resolveCriteria", FT_UINT8, BASE_HEX, VALS(resolveCriteria), 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_lookupControls_reasonCode,
            { "Reason Code", "pnrp.lookupControls.reasonCode", FT_UINT8, BASE_HEX, VALS(reasonCode), 0x0,
                NULL, HFILL }},
        /* Public Key Structure */
        { &hf_pnrp_publicKey_objID,
            { "Public Key Object Identifier", "pnrp.publicKey.objID", FT_STRING,BASE_NONE, NULL, 0x0,
                "An ASN.1-encoded object identifier (OID) indicating the public key format", HFILL }},
        { &hf_pnrp_publicKey_publicKeyData,
            { "Public Key Data", "pnrp.publicKey.publicKeyData", FT_STRING,BASE_NONE, NULL, 0x0,
                "An ASN.1-encoded 1024-bit RSA public key", HFILL }},
        /* Signature Structure */
        { &hf_pnrp_signature_signatureData,
            { "Signature", "pnrp.signature.data", FT_BYTES,BASE_NONE, NULL, 0x0,
                "Signature created when signing the CPA", HFILL }},

        /* Route Entry */
        { &hf_pnrp_message_routeEntry_portNumber,
            { "Port Number", "pnrp.segment.routeEntry.portNumber", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_routeEntry_flags,
            { "Flags", "pnrp.segment.routeEntry.flags", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_routeEntry_addressCount,
            { "Address Count", "pnrp.segment.routeEntry.addressCount", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_nonce,
            { "Nonce", "pnrp.segment.nonce", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_hashednonce,
            { "Hashed Nonce", "pnrp.segment.hashednonce", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_idArray_NumEntries,
            { "Number of Entries", "pnrp.segment.idArray.NumEnries", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_idArray_Length,
            { "Length of Array", "pnrp.segment.idArray.Length", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_ElementFieldType,
            { "Type of Array Entry", "pnrp.segment.ElementFieldType", FT_UINT16, BASE_HEX, VALS(fieldID), 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_idarray_Entrylength,
            { "Length of each Array Entry", "pnrp.segment.idArray.Entrylength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_certChain,
            { "Certificate Chain", "pnrp.segment.certChain", FT_BYTES,BASE_NONE, NULL, 0x0,
                "A Certificate Chain, containing the public key used to sign the CPA and its Certificate Chain", HFILL }},
        { &hf_pnrp_message_solicitType,
            { "Solicit Type", "pnrp.segment.solicitType", FT_UINT8, BASE_DEC, VALS(solicitType), 0x0,
                NULL, HFILL }},
        { &hf_pnrp_message_ipv6,
            { "IPv6 Address","pnrp.segment.ipv6Address",FT_IPv6, BASE_NONE, NULL, 0x0,NULL,HFILL}}
    };

    /* Protocol subtree array */
    static gint *ett[] = {
        &ett_pnrp,
        &ett_pnrp_header,
        &ett_pnrp_message,
        &ett_pnrp_message_inquire_flags,
        &ett_pnrp_message_authority_flags,
        &ett_pnrp_message_encodedCPA,
        &ett_pnrp_message_encodedCPA_flags,
        &ett_pnrp_message_payloadStructure,
        &ett_pnrp_message_publicKeyStructure,
        &ett_pnrp_message_signatureStructure,
        &ett_pnrp_message_lookupControls_flags
    };
    /* Register the Dissector with Wireshark */
    proto_pnrp = proto_register_protocol(PROTONAME,PROTOSHORTNAME,PROTOABBREV);

    proto_register_field_array(proto_pnrp,hf,array_length(hf));
    proto_register_subtree_array (ett, array_length(ett));
}

/* Initialise the dissector */
void proto_reg_handoff_pnrp(void)
{
    dissector_handle_t pnrp_handle;
    pnrp_handle = new_create_dissector_handle(dissect_pnrp, proto_pnrp);
    dissector_add_uint("udp.port",PNRP_PORT,pnrp_handle);
}

