/* packet-moldudp64.c
 * Routines for MoldUDP64 dissection
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/moldudp64.pdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/decode_as.h>

void proto_register_moldudp64(void);
void proto_reg_handoff_moldudp64(void);

/* Initialize the protocol and registered fields */
static int proto_moldudp64       = -1;
static int hf_moldudp64_session  = -1;
static int hf_moldudp64_sequence = -1;
static int hf_moldudp64_count    = -1;
static int hf_moldudp64_msgblk   = -1;
static int hf_moldudp64_msglen   = -1;
static int hf_moldudp64_msgseq   = -1;
static int hf_moldudp64_msgdata  = -1;

#define MOLDUDP64_SESSION_LEN  10
#define MOLDUDP64_SEQUENCE_LEN  8
#define MOLDUDP64_COUNT_LEN     2
#define MOLDUDP64_MSGLEN_LEN    2

#define MOLDUDP64_HEARTBEAT 0x0000
#define MOLDUDP64_ENDOFSESS 0xFFFF

/* Initialize the subtree pointers */
static gint ett_moldudp64        = -1;
static gint ett_moldudp64_msgblk = -1;

static expert_field ei_moldudp64_msglen_invalid = EI_INIT;
static expert_field ei_moldudp64_end_of_session_extra = EI_INIT;
static expert_field ei_moldudp64_count_invalid = EI_INIT;
static expert_field ei_moldudp64_request = EI_INIT;

static dissector_table_t moldudp64_payload_table;

static void moldudp64_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Payload as");
}

/* Code to dissect a message block */
static guint
dissect_moldudp64_msgblk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset, guint64 sequence)
{
    proto_item *ti;
    proto_tree *blk_tree;
    guint16     msglen, real_msglen, whole_len;
    gint        remaining;
    tvbuff_t*   next_tvb;

    if (tvb_captured_length_remaining(tvb, offset) < MOLDUDP64_MSGLEN_LEN)
        return 0;

    msglen = tvb_get_ntohs(tvb, offset);
    remaining = tvb_reported_length(tvb) - offset - MOLDUDP64_MSGLEN_LEN;

    if (remaining < 0)
        real_msglen = 0;
    else if (msglen <= remaining)
        real_msglen = msglen;
    else
        real_msglen = remaining;

    /* msglen and real_msglen only count the data section, and don't
     * include the two bytes for the length field itself. */
    whole_len = real_msglen + MOLDUDP64_MSGLEN_LEN;

    ti = proto_tree_add_item(tree, hf_moldudp64_msgblk,
            tvb, offset, whole_len, ENC_NA);

    blk_tree = proto_item_add_subtree(ti, ett_moldudp64_msgblk);

    ti = proto_tree_add_uint64(blk_tree, hf_moldudp64_msgseq,
            tvb, offset, 0, sequence);

    proto_item_set_generated(ti);

    ti = proto_tree_add_item(blk_tree, hf_moldudp64_msglen,
            tvb, offset, MOLDUDP64_MSGLEN_LEN, ENC_BIG_ENDIAN);

    if (msglen != real_msglen)
        expert_add_info_format(pinfo, ti, &ei_moldudp64_msglen_invalid,
                "Invalid Message Length (claimed %u, found %u)",
                msglen, real_msglen);

    offset += MOLDUDP64_MSGLEN_LEN;

    next_tvb = tvb_new_subset_length(tvb, offset, real_msglen);
    if (!dissector_try_payload_new(moldudp64_payload_table, next_tvb, pinfo, tree, FALSE, NULL))
    {
        proto_tree_add_item(blk_tree, hf_moldudp64_msgdata, tvb, offset, real_msglen, ENC_NA);
    }

    return whole_len;
}

/* Code to actually dissect the packets */
static int
dissect_moldudp64(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *moldudp64_tree;
    guint       offset            = 0;
    guint16     count, real_count = 0;
    guint64     sequence;

    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < (MOLDUDP64_SESSION_LEN  +
                                    MOLDUDP64_SEQUENCE_LEN +
                                    MOLDUDP64_COUNT_LEN))
        return 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MoldUDP64");

    /* Clear the info column so it's sane if we crash. We fill it in later when
     * we've dissected more of the packet. */
    col_clear(pinfo->cinfo, COL_INFO);

    sequence = tvb_get_ntoh64(tvb, MOLDUDP64_SESSION_LEN);
    count = tvb_get_ntohs(tvb, MOLDUDP64_SESSION_LEN + MOLDUDP64_SEQUENCE_LEN);

    if (count == MOLDUDP64_HEARTBEAT)
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP64 Heartbeat");
    else if (count == MOLDUDP64_ENDOFSESS)
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP64 End Of Session");
    else if (count > 0 && tvb_reported_length(tvb) == (MOLDUDP64_SESSION_LEN  +
                                                       MOLDUDP64_SEQUENCE_LEN +
                                                       MOLDUDP64_COUNT_LEN))
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP64 Request");
    else
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP64 Messages");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_moldudp64,
                             tvb, offset, -1, ENC_NA);

    moldudp64_tree = proto_item_add_subtree(ti, ett_moldudp64);

    proto_tree_add_item(moldudp64_tree, hf_moldudp64_session,
                        tvb, offset, MOLDUDP64_SESSION_LEN, ENC_ASCII|ENC_NA);
    offset += MOLDUDP64_SESSION_LEN;

    proto_tree_add_item(moldudp64_tree, hf_moldudp64_sequence,
                        tvb, offset, MOLDUDP64_SEQUENCE_LEN, ENC_BIG_ENDIAN);
    offset += MOLDUDP64_SEQUENCE_LEN;

    ti = proto_tree_add_item(moldudp64_tree, hf_moldudp64_count,
                             tvb, offset, MOLDUDP64_COUNT_LEN, ENC_BIG_ENDIAN);
    offset += MOLDUDP64_COUNT_LEN;

    while (tvb_reported_length(tvb) >= offset + MOLDUDP64_MSGLEN_LEN)
    {
        offset += dissect_moldudp64_msgblk(tvb, pinfo, moldudp64_tree,
                                           offset, sequence++);
        real_count++;
    }

    if (count == MOLDUDP64_ENDOFSESS && real_count != 0)
    {
        expert_add_info(pinfo, ti, &ei_moldudp64_end_of_session_extra);
    }
    else if (count > 0 && real_count == 0)
    {
        expert_add_info(pinfo, ti, &ei_moldudp64_request);
    }
    else if (real_count != count)
    {
        expert_add_info_format(pinfo, ti, &ei_moldudp64_count_invalid,
                               "Invalid Message Count (claimed %u, found %u)",
                               count, real_count);
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_moldudp64(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_moldudp64_session,
        { "Session",       "moldudp64.session",  FT_STRING, BASE_NONE, NULL, 0,
          "The session to which this packet belongs.", HFILL }},

        { &hf_moldudp64_sequence,
        { "Sequence",      "moldudp64.sequence", FT_UINT64, BASE_DEC,  NULL, 0,
          "The sequence number of the first message in this packet.", HFILL }},

        { &hf_moldudp64_count,
        { "Count",         "moldudp64.count",    FT_UINT16, BASE_DEC,  NULL, 0,
          "The number of messages contained in this packet.", HFILL }},

        { &hf_moldudp64_msgblk,
        { "Message Block", "moldudp64.msgblock", FT_NONE,   BASE_NONE, NULL, 0,
          "A message.", HFILL }},

        { &hf_moldudp64_msglen,
        { "Length",        "moldudp64.msglen",   FT_UINT16, BASE_DEC,  NULL, 0,
          "The length of this message.", HFILL }},

        { &hf_moldudp64_msgseq,
        { "Sequence",      "moldudp64.msgseq",   FT_UINT64, BASE_DEC,  NULL, 0,
          "The sequence number of this message.", HFILL }},

        { &hf_moldudp64_msgdata,
        { "Payload",       "moldudp64.msgdata",  FT_BYTES,  BASE_NONE, NULL, 0,
          "The payload data of this message.", HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_moldudp64,
        &ett_moldudp64_msgblk
    };

    static ei_register_info ei[] = {
        { &ei_moldudp64_msglen_invalid, { "moldudp64.msglen.invalid", PI_MALFORMED, PI_ERROR, "Invalid Message Length", EXPFILL }},
        { &ei_moldudp64_end_of_session_extra, { "moldudp64.end_of_session_extra", PI_MALFORMED, PI_ERROR, "End Of Session packet with extra data.", EXPFILL }},
        { &ei_moldudp64_count_invalid, { "moldudp64.count.invalid", PI_MALFORMED, PI_ERROR, "Invalid Message Count", EXPFILL }},
        { &ei_moldudp64_request, { "moldudp64.request", PI_COMMENTS_GROUP, PI_COMMENT, "Number of Requested Messages", EXPFILL }},
    };

    expert_module_t* expert_moldudp64;

    /* Register the protocol name and description */
    proto_moldudp64 = proto_register_protocol("MoldUDP64",
            "MoldUDP64", "moldudp64");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_moldudp64, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_moldudp64 = expert_register_protocol(proto_moldudp64);
    expert_register_field_array(expert_moldudp64, ei, array_length(ei));

    moldudp64_payload_table = register_decode_as_next_proto(proto_moldudp64, "moldudp64.payload",
                                                            "MoldUDP64 Payload", moldudp64_prompt);
}


void
proto_reg_handoff_moldudp64(void)
{
    dissector_handle_t moldudp64_handle;

    moldudp64_handle = create_dissector_handle(dissect_moldudp64, proto_moldudp64);
    dissector_add_for_decode_as_with_preference("udp.port", moldudp64_handle);
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
