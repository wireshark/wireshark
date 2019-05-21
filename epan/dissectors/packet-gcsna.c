/*
 * packet-gcsna.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref GCSNA: 3GPP2 C.S0097 v2.0
 */

# include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

void proto_reg_handoff_gcsna(void);
void proto_register_gcsna(void);

 /* gcsna Handle for the dissection */
static dissector_handle_t gcsna_handle;
static dissector_handle_t cdma2k_handle;

/* Function handlers for each message/information fields */
static void gcsna_message_decode(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset, proto_tree *mainTree, guint16 *noerror, packet_info *pinfo);
static void gcsna_message_GCSNA1xCircuitService(proto_item *item, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mainTree, proto_tree *tree, guint *offset);
static void gcsna_message_GCSNAL2Ack(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void gcsna_message_GCSNAServiceReject(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset);

/*Initialize all the header parameters that are to be displayed*/
int proto_gcsna = -1;
static int hf_gcsna_msghdr = -1;
static int hf_gcsna_msgid = -1;
static int hf_gcsna_rejSequence = -1;
static int hf_gcsna_cause = -1;
static int hf_gcsna_ackSequence = -1;
static int hf_gcsna_recordType = -1;
static int hf_gcsna_1xProtocolRevision = -1;
static int hf_gcsna_invalidMessageId = -1;
static int hf_gcsna_l2ack = -1;
static int hf_gcsna_servicereject = -1;
static int hf_gcsna_gcsna_option = -1;
static int hf_gcsna_gcsnaClass = -1;
static int hf_gcsna_gcsnaClassRev = -1;
static int hf_gcsna_altGCSNAOption = -1;
static int hf_gcsna_altGCSNAOptionIncluded = -1;
static int hf_gcsna_NumaltGCSNAOption = -1;
static int hf_gcsna_ackRequired = -1;
static int hf_gcsna_stopDupDetect = -1;
static int hf_gcsna_msgSequence = -1;
static int hf_gcsna_tlacEncapsulated = -1;
static int hf_gcsna_NumTLACEncapsulated1xL3PDU = -1;
static int hf_gcsna_tlacReserved = -1;
static int hf_gcsna_iwsidIncluded = -1;
static int hf_gcsna_iwsidValue = -1;
static int hf_gcsna_unsupported_reject_seq = -1;

/* Toggle sub-tree items */
static gint ett_gcsna_msghdr = -1;
static gint ett_gcsna_subtree = -1;
static gint ett_gcsna_option = -1;

static expert_field ei_gcsna_error = EI_INIT;

#define GCSNA1XCIRCUITSERVICE 0x01
#define GCSNAL2ACK       0x02
#define GCSNASERVICEREJECT    0x03

/* Msg Types */
static const value_string gcsna_message_types[] = {
    { 0x01, "GCSNA 1X Circuitservice" },
    { 0x02, "GCSNA L2 Ack"},
    { 0x03, "GCSNA Servicereject"},
    { 0, NULL },
};

/* Cause Types */
static const value_string gcsna_cause_types[] = {
    { 0, "Invalid GCSNAOption" },
    { 1, "Invalid 1xProtocolRevision" },
    { 2, "Invalid GCSNAOption and 1xProtocolRevision"},
    { 3, "Invalid Message Id"},
    { 4, "GCSNA 1xParameters provisioning is not supported" },
    { 5, "Unsupported RecordType in GCSNA 1xParameters message"},
    { 0, NULL },
};

/*
    GCSNA Class GCSNA ClassRevision 1x Service
    +----------+-------------------+--------------------------------+
    |          |         0         | Release 8 1xCSFB from E-UTRAN  |
    |          +-------------------+--------------------------------+
    |    0     |         1         | Release 9 e1xCSFB from E-UTRAN |
    |          +-------------------+--------------------------------+
    |          |         2         | C.S0097-A supported eCSFB      |
    +----------+-------------------+--------------------------------+
    |    1     |         0         | SRVCC from E-UTRAN             |
    +----------+-------------------+--------------------------------+

*/
static const value_string gcsna_option_values[] = {
    { 0, "Release 8 1xCSFB from E-UTRAN" },
    { 1, "Release 9 e1xCSFB from E-UTRAN" },
    { 2, "C.S0097-A supported eCSFB"},
    { 8, "SRVCC from E-UTRAN"},
    { 0, NULL },
};

static const value_string gcsna_tru_false_values[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL },
};

/* Decoder for all the information elements of A21 Message Type */
static void
gcsna_message_decode(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset, proto_tree *mainTree, guint16 *noerror, packet_info *pinfo)
{
    guint16 msgId = -1;
    msgId = tvb_get_guint8(tvb, *offset);
    *offset += 1;

    switch (msgId)
    {
    case GCSNA1XCIRCUITSERVICE:
    {
        gcsna_message_GCSNA1xCircuitService(item, tvb, pinfo, mainTree, tree, offset);
        break;
    }

    case GCSNAL2ACK:
    {
        gcsna_message_GCSNAL2Ack(item, tvb, tree, offset);
        break;
    }

    case GCSNASERVICEREJECT:
    {
        gcsna_message_GCSNAServiceReject(item, tvb, tree, offset);
        break;
    }

    default:
    {
        *noerror = 0;
        break;
    }
    }
}

static void
gcsna_message_GCSNA1xCircuitService(proto_item *item, tvbuff_t *tvb, packet_info *pinfo, proto_tree *mainTree, proto_tree *tree, guint *offset)
{
    guint16 alt_gcsna_incl = 0, num_alt_gcsna_opt = -1, iws_incl = 0;
    guint8 num_res;
    guint bit_offset = *offset * 8;
    proto_tree *subtree = NULL;
    tvbuff_t *new_tvb;

    /* GCSNAOption 8 bits */
    item = proto_tree_add_item(tree, hf_gcsna_gcsna_option, tvb, *offset, 1, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_gcsna_option);
    proto_tree_add_bits_item(subtree, hf_gcsna_gcsnaClass, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    bit_offset += 5;
    proto_tree_add_bits_item(subtree, hf_gcsna_gcsnaClassRev, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;

    alt_gcsna_incl = tvb_get_bits8(tvb, bit_offset, 1);
    proto_tree_add_bits_item(tree, hf_gcsna_altGCSNAOptionIncluded, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    if (alt_gcsna_incl)
    {
        num_alt_gcsna_opt = tvb_get_bits8(tvb, bit_offset, 8);
        proto_tree_add_bits_item(tree, hf_gcsna_NumaltGCSNAOption, tvb, bit_offset, 8, ENC_BIG_ENDIAN);
        bit_offset += 8;

        while (num_alt_gcsna_opt != 0)
        {
            proto_tree_add_bits_item(tree, hf_gcsna_altGCSNAOption, tvb, bit_offset, 8, ENC_BIG_ENDIAN);
            bit_offset += 8;
            num_alt_gcsna_opt--;
        }
    }

    iws_incl = tvb_get_bits8(tvb, bit_offset, 1);
    proto_tree_add_bits_item(tree, hf_gcsna_iwsidIncluded, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    if (iws_incl)
    {
        proto_tree_add_bits_item(tree, hf_gcsna_iwsidValue, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
        bit_offset += 16;
    }

    proto_tree_add_bits_item(tree, hf_gcsna_ackRequired, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_gcsna_stopDupDetect, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_gcsna_msgSequence, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    bit_offset += 6;

    proto_tree_add_bits_item(tree, hf_gcsna_NumTLACEncapsulated1xL3PDU, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;

    /* The sender shall include reserved bits to make this message integral number of octets up to TLACEncapsulated1xL3PDU field.
     * The sender shall set all bits in this field to '0'. The receiver shall ignore this field.
     */

     /* calculate number of reserved bits */
    num_res = 8 - (bit_offset & 0x3);
    proto_tree_add_bits_item(tree, hf_gcsna_tlacReserved, tvb, bit_offset, num_res, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + num_res;
    *offset = bit_offset >> 3;

    proto_tree_add_item(tree, hf_gcsna_tlacEncapsulated, tvb, *offset, -1, ENC_NA);

    if (cdma2k_handle) {
        new_tvb = tvb_new_subset_length_caplen(tvb, *offset, -1, -1);
        call_dissector(cdma2k_handle, new_tvb, pinfo, mainTree);
    }
    /* set the offset to the end of the message */
    *offset += tvb_reported_length_remaining(tvb, *offset);

}

static void gcsna_message_GCSNAL2Ack(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    proto_tree *subtree = NULL;

    item = proto_tree_add_item(tree, hf_gcsna_l2ack, tvb, *offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_gcsna_subtree);

    proto_tree_add_bits_item(subtree, hf_gcsna_ackSequence, tvb, *offset * 8, 6, ENC_BIG_ENDIAN);
    *offset += 1;
}

static void gcsna_message_GCSNAServiceReject(proto_item *item, tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint16 cause_val = -1, num_fields = -1, l_offset = -1;
    proto_tree *subtree = NULL;

    item = proto_tree_add_item(tree, hf_gcsna_servicereject, tvb, *offset, 1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_gcsna_subtree);

    l_offset = *offset * 8;
    proto_tree_add_bits_item(subtree, hf_gcsna_rejSequence, tvb, l_offset, 6, ENC_BIG_ENDIAN);
    l_offset += 6;
    proto_tree_add_bits_item(subtree, hf_gcsna_cause, tvb, l_offset, 8, ENC_BIG_ENDIAN);
    cause_val = tvb_get_bits8(tvb, *offset * 8 + 6, 8);
    l_offset += 8;

    switch (cause_val)
    {
    case 0:
    case 2:
    {
        num_fields = tvb_get_bits8(tvb, l_offset, 8);
        l_offset += 8;

        while (num_fields > 0)
        {
            proto_tree_add_bits_item(subtree, hf_gcsna_gcsnaClass, tvb, l_offset, 5, ENC_BIG_ENDIAN);
            l_offset += 5;
            proto_tree_add_bits_item(subtree, hf_gcsna_gcsnaClassRev, tvb, l_offset, 3, ENC_BIG_ENDIAN);
            l_offset += 3;
            num_fields--;
        }

        if (cause_val == 2)
        {
            proto_tree_add_bits_item(subtree, hf_gcsna_1xProtocolRevision, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset += 8;
        }

        break;
    }

    case 1:
    {
        proto_tree_add_bits_item(subtree, hf_gcsna_1xProtocolRevision, tvb, l_offset, 8, ENC_BIG_ENDIAN);
        l_offset += 8;
        break;
    }

    case 3:
    {
        proto_tree_add_bits_item(subtree, hf_gcsna_invalidMessageId, tvb, l_offset, 8, ENC_BIG_ENDIAN);
        l_offset += 8;
        break;
    }

    /*This Cause Value is not supported in IWS Stack*/
    case 5:
    {
        num_fields = tvb_get_bits8(tvb, l_offset, 8);
        l_offset += 8;

        while (num_fields > 0)
        {
            proto_tree_add_bits_item(subtree, hf_gcsna_recordType, tvb, l_offset, 8, ENC_BIG_ENDIAN);
            l_offset += 8;
            num_fields--;
        }
        break;
    }

    default:
    {
        proto_tree_add_item(subtree, hf_gcsna_unsupported_reject_seq, tvb, l_offset, -1, ENC_NA);
        break;
    }
    }

    if (l_offset % 8 == 0)
    {
        *offset = (l_offset / 8);
    } else
    {
        *offset = (l_offset / 8) + 1;
    }

}

/*Method called when the dissection starts.....Starting point*/
static int
dissect_gcsna(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{

    /* Initialization*/
    proto_tree *gcsna_msghdr_tree_start = NULL;

    proto_item *item = NULL;

    guint32 offset = 0;
    guint16 noerror = 1;


    /*Add the protocol name to display*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "gcsna");
    col_add_fstr(pinfo->cinfo, COL_INFO, "[gcsna]");

    item = proto_tree_add_item(tree, hf_gcsna_msghdr, tvb, 0, -1, ENC_NA);
    gcsna_msghdr_tree_start = proto_item_add_subtree(item, ett_gcsna_msghdr);

    if (tree)
    {
        proto_tree_add_item(gcsna_msghdr_tree_start, hf_gcsna_msgid, tvb, offset, 1, ENC_BIG_ENDIAN);

        while (tvb_captured_length_remaining(tvb, offset) != 0 && noerror == 1)
            gcsna_message_decode(item, tvb, gcsna_msghdr_tree_start, &offset, tree, &noerror, pinfo);

        if (noerror == 0)
        {
            expert_add_info(pinfo, item, &ei_gcsna_error);
        }
    }
    return tvb_reported_length(tvb);
}

/*Register gcsna to be accessed by other dissectors/plugins*/
void
proto_register_gcsna(void)
{
    static hf_register_info hf[] = {
            { &hf_gcsna_servicereject,
            { "GCSNA SERVICEREJECT", "gcsna.servicereject", FT_NONE, BASE_NONE,NULL, 0x0, NULL, HFILL } },
            /*{ & hf_gcsna_msgid,
            { "GCSNA Message Type", "gcsna.MsgType", FT_UINT8, BASE_HEX_DEC, VALS(A21_Message_Types), 0x0, NULL, HFILL } },*/
            { &hf_gcsna_l2ack,
            { "L2ACK", "gcsna.l2ack", FT_NONE, BASE_NONE,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_msghdr,
            { "General Circuit Services Notification Application Protocol", "gcsna.msghdr", FT_NONE, BASE_NONE,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_NumTLACEncapsulated1xL3PDU,
            { "NumTLACEncapsulated1xL3PDU", "gcsna.NumTLACEncapsulated1xL3PDU", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_tlacReserved,
            { "Reserved", "gcsna.tlacReserved", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_tlacEncapsulated,
            { "TLAC Encapsulated", "gcsna.tlacEncapsulated", FT_BYTES, BASE_NONE,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_msgSequence,
            { "Msg Sequence", "gcsna.msgSequence", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_stopDupDetect,
            { "Stop Dup Detect", "gcsna.stopDupDetect", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_ackRequired,
            { "Ack Required", "gcsna.ackRequired", FT_UINT8, BASE_DEC,VALS(gcsna_tru_false_values), 0x0, NULL, HFILL } },
            { &hf_gcsna_altGCSNAOptionIncluded,
            { "AlternativeGCSNAOption_INCL", "gcsna.altGCSNAOptionIncluded", FT_UINT8, BASE_DEC,VALS(gcsna_tru_false_values), 0x0, NULL, HFILL } },
            { &hf_gcsna_altGCSNAOption,
            { "Alternate GCSNA Option", "gcsna.altGCSNAOption", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_gcsna_option,
            { "GCSNA Option", "gcsna.Option", FT_UINT8, BASE_HEX, VALS(gcsna_option_values), 0x0, NULL, HFILL } },
            { &hf_gcsna_NumaltGCSNAOption,
            { "NumAlternativeGCSNAOptions", "gcsna.NumaltGCSNAOption", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_iwsidValue,
            { "IWS_ID", "gcsna.iwsidValue", FT_UINT16, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_iwsidIncluded,
            { "IWSIDIncl", "gcsna.iwsidIncluded", FT_UINT8, BASE_DEC,VALS(gcsna_tru_false_values), 0x0, NULL, HFILL } },
            { &hf_gcsna_gcsnaClassRev,
            { "GCSNA Class revision", "gcsna.ClassRev", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_gcsnaClass,
            { "GCSNA Class", "gcsna.Class", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_invalidMessageId,
            { "InvalidMessageId", "gcsna.invalidMessageId", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_1xProtocolRevision,
            { "1xProtocolRevision", "gcsna.1xProtocolRevision", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_recordType,
            { "Record Type", "gcsna.recordType", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_ackSequence,
            { "Ack Sequence", "gcsna.ackSequence", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_cause,
            { "Cause", "gcsna.cause", FT_UINT8, BASE_HEX_DEC,VALS(gcsna_cause_types), 0x0, NULL, HFILL } },
            { &hf_gcsna_rejSequence,
            { "Reject Sequence", "gcsna.rejSequence", FT_UINT8, BASE_HEX_DEC,NULL, 0x0, NULL, HFILL } },
            { &hf_gcsna_msgid,
            { "GCSNA Message Type", "gcsna.msgId", FT_UINT8, BASE_HEX_DEC,VALS(gcsna_message_types), 0x0, NULL, HFILL } },
            { &hf_gcsna_unsupported_reject_seq,
            { "Invalid / Unsupported GCSNA Message Reject Sequence", "gcsna.unsupportedrejectseq", FT_NONE, BASE_NONE, NULL,  0x0, NULL, HFILL } }
    };


    static gint *ett[] = {
            &ett_gcsna_msghdr,
            &ett_gcsna_subtree,
            &ett_gcsna_option
    };


    static ei_register_info ei[] = {
        { &ei_gcsna_error, { "gcsna.error", PI_PROTOCOL, PI_ERROR, "Violation of protocol specs (e.g. invalid information element)", EXPFILL }},
    };

    expert_module_t* expert_gcsna;

    proto_gcsna = proto_register_protocol(
        "GCSNA",    /* name */
        "GCSNA",    /* short name */
        "gcsna"     /* abbrev */
    );

    register_dissector("gcsna", dissect_gcsna, proto_gcsna);

    proto_register_field_array(proto_gcsna, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_gcsna = expert_register_protocol(proto_gcsna);
    expert_register_field_array(expert_gcsna, ei, array_length(ei));

}

void
proto_reg_handoff_gcsna(void)
{
    static int once = 1;

    if (once == 1)
    {
        cdma2k_handle = find_dissector("cdma2k");
        gcsna_handle = create_dissector_handle(dissect_gcsna, proto_gcsna);
        once = 0;
    }
}
