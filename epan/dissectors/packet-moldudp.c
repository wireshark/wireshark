/* packet-moldudp.c
 * Routines for MoldUDP dissection
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/moldudp.pdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

void proto_register_moldudp(void);
void proto_reg_handoff_moldudp(void);

/* Initialize the protocol and registered fields */
static int proto_moldudp       = -1;
static int hf_moldudp_session  = -1;
static int hf_moldudp_sequence = -1;
static int hf_moldudp_count    = -1;
static int hf_moldudp_msgblk   = -1;
static int hf_moldudp_msgseq   = -1;
static int hf_moldudp_msglen   = -1;
static int hf_moldudp_msgdata  = -1;

#define MOLDUDP_SESSION_LEN  10
#define MOLDUDP_SEQUENCE_LEN  4
#define MOLDUDP_COUNT_LEN     2
#define MOLDUDP_MSGLEN_LEN    2

#define MOLDUDP_HEARTBEAT 0x0000

/* Global port pref */
static guint pf_moldudp_port = 0;

/* Initialize the subtree pointers */
static gint ett_moldudp        = -1;
static gint ett_moldudp_msgblk = -1;

static expert_field ei_moldudp_msglen_invalid = EI_INIT;
static expert_field ei_moldudp_count_invalid = EI_INIT;

/* Code to dissect a message block */
static guint
dissect_moldudp_msgblk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset, guint32 sequence)
{
    proto_item *ti;
    proto_tree *blk_tree;
    guint16     msglen, real_msglen, whole_len;
    guint       remaining;

    if (tvb_reported_length(tvb) - offset < MOLDUDP_MSGLEN_LEN)
        return 0;

    msglen = tvb_get_letohs(tvb, offset);
    remaining = tvb_reported_length(tvb) - offset - MOLDUDP_MSGLEN_LEN;

    if (msglen == 0)
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP Messages (End Of Session)");

    if (tvb_reported_length(tvb) < (offset + MOLDUDP_MSGLEN_LEN))
        real_msglen = 0;
    else if (msglen <= remaining)
        real_msglen = msglen;
    else
        real_msglen = remaining;

    /* msglen and real_msglen only count the data section, and don't
     * include the two bytes for the length field itself. */
    whole_len = real_msglen + MOLDUDP_MSGLEN_LEN;

    ti = proto_tree_add_item(tree, hf_moldudp_msgblk,
            tvb, offset, whole_len, ENC_NA);

    blk_tree = proto_item_add_subtree(ti, ett_moldudp_msgblk);

    ti = proto_tree_add_uint(blk_tree, hf_moldudp_msgseq,
            tvb, offset, 0, sequence);

    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_item(blk_tree, hf_moldudp_msglen,
            tvb, offset, MOLDUDP_MSGLEN_LEN, ENC_LITTLE_ENDIAN);

    if (msglen != real_msglen)
        expert_add_info_format(pinfo, ti, &ei_moldudp_msglen_invalid,
                "Invalid Message Length (claimed %u, found %u)",
                msglen, real_msglen);

    offset += MOLDUDP_MSGLEN_LEN;

    proto_tree_add_item(blk_tree, hf_moldudp_msgdata,
            tvb, offset, real_msglen, ENC_NA);

    return whole_len;
}

/* Code to actually dissect the packets */
static int
dissect_moldudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *moldudp_tree;
    guint       offset            = 0;
    guint16     count, real_count = 0;
    guint32     sequence;

    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < (MOLDUDP_SESSION_LEN  +
                                    MOLDUDP_SEQUENCE_LEN +
                                    MOLDUDP_COUNT_LEN))
        return 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MoldUDP");

    /* Clear the info column so it's sane if we crash. We fill it in later when
     * we've dissected more of the packet. */
    col_clear(pinfo->cinfo, COL_INFO);

    count = tvb_get_letohs(tvb, MOLDUDP_SESSION_LEN + MOLDUDP_SEQUENCE_LEN);

    if (count == MOLDUDP_HEARTBEAT)
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP Heartbeat");
    else
        col_set_str(pinfo->cinfo, COL_INFO, "MoldUDP Messages");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_moldudp,
                             tvb, offset, -1, ENC_NA);

    moldudp_tree = proto_item_add_subtree(ti, ett_moldudp);

    proto_tree_add_item(moldudp_tree, hf_moldudp_session,
                        tvb, offset, MOLDUDP_SESSION_LEN, ENC_ASCII|ENC_NA);
    offset += MOLDUDP_SESSION_LEN;

    sequence = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(moldudp_tree, hf_moldudp_sequence,
                        tvb, offset, MOLDUDP_SEQUENCE_LEN, ENC_LITTLE_ENDIAN);
    offset += MOLDUDP_SEQUENCE_LEN;

    ti = proto_tree_add_item(moldudp_tree, hf_moldudp_count,
                             tvb, offset, MOLDUDP_COUNT_LEN, ENC_LITTLE_ENDIAN);
    offset += MOLDUDP_COUNT_LEN;

    while (tvb_reported_length(tvb) >= offset + MOLDUDP_MSGLEN_LEN)
    {
        offset += dissect_moldudp_msgblk(tvb, pinfo, moldudp_tree,
                                         offset, sequence++);
        real_count++;
    }

    if (real_count != count)
    {
        expert_add_info_format(pinfo, ti, &ei_moldudp_count_invalid,
                               "Invalid Message Count (claimed %u, found %u)",
                               count, real_count);
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_moldudp(void)
{
    module_t *moldudp_module;

    /* Setup list of header fields */
    static hf_register_info hf[] = {

        { &hf_moldudp_session,
        { "Session",       "moldudp.session",  FT_STRING, BASE_NONE, NULL, 0,
          "The session to which this packet belongs.", HFILL }},

        { &hf_moldudp_sequence,
        { "Sequence",      "moldudp.sequence", FT_UINT32, BASE_DEC,  NULL, 0,
          "The sequence number of the first message in this packet.", HFILL }},

        { &hf_moldudp_count,
        { "Count",         "moldudp.count",    FT_UINT16, BASE_DEC,  NULL, 0,
          "The number of messages contained in this packet.", HFILL }},

        { &hf_moldudp_msgblk,
        { "Message Block", "moldudp.msgblock", FT_NONE,   BASE_NONE, NULL, 0,
          "A message.", HFILL }},

        { &hf_moldudp_msglen,
        { "Length",        "moldudp.msglen",   FT_UINT16, BASE_DEC,  NULL, 0,
          "The length of this message.", HFILL }},

        { &hf_moldudp_msgseq,
        { "Sequence",      "moldudp.msgseq",   FT_UINT32, BASE_DEC,  NULL, 0,
          "The sequence number of this message.", HFILL }},

        { &hf_moldudp_msgdata,
        { "Payload",       "moldudp.msgdata",  FT_BYTES,  BASE_NONE, NULL, 0,
          "The payload data of this message.", HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_moldudp,
        &ett_moldudp_msgblk
    };

    static ei_register_info ei[] = {
        { &ei_moldudp_msglen_invalid, { "moldudp.msglen.invalid", PI_MALFORMED, PI_ERROR, "Invalid Message Length", EXPFILL }},
        { &ei_moldudp_count_invalid, { "moldudp.count.invalid", PI_MALFORMED, PI_ERROR, "Invalid Count", EXPFILL }},
    };

    expert_module_t* expert_moldudp;

    /* Register the protocol name and description */
    proto_moldudp = proto_register_protocol("MoldUDP",
            "MoldUDP", "moldudp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_moldudp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_moldudp = expert_register_protocol(proto_moldudp);
    expert_register_field_array(expert_moldudp, ei, array_length(ei));

    /* Register preferences module */
    moldudp_module = prefs_register_protocol(proto_moldudp,
            proto_reg_handoff_moldudp);

    /* Register a port preference   */
    prefs_register_uint_preference(moldudp_module, "udp.port", "MoldUDP UDP Port",
            "MoldUDP UDP port to capture on.",
            10, &pf_moldudp_port);
}


void
proto_reg_handoff_moldudp(void)
{
    static gboolean           initialized = FALSE;
    static dissector_handle_t moldudp_handle;
    static int                currentPort;

    if (!initialized) {
        moldudp_handle = create_dissector_handle(dissect_moldudp,
                proto_moldudp);
        initialized = TRUE;
    } else {

        dissector_delete_uint("udp.port", currentPort, moldudp_handle);
    }

    currentPort = pf_moldudp_port;

    dissector_add_uint("udp.port", currentPort, moldudp_handle);

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
