/* packet-soupbintcp.c
 * Routines for SoupBinTCP 3.0 protocol dissection
 * Copyright 2013 David Arnold <davida@pobox.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 *   Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA.
 */

/*
 * SoupBinTCP is a framing protocol published and used by NASDAQ to
 * encapsulate both market data (ITCH) and order entry (OUCH)
 * protocols.  It is derived from the original SOUP protocol, which
 * was ASCII-based, and relied on an EOL indicator as a message
 * boundary.
 *
 * SoupBinTCP was introduced with OUCH-4.0 / ITCH-4.0 when those
 * protocols also switched to using a binary representation for
 * numerical values.
 *
 * The SOUP/SoupBinTCP protocols are also commonly used by other
 * financial exchanges, although frequently they are more SOUP-like
 * than exactly the same.  This dissector doesn't attempt to support
 * any other SOUP-like variants; I think it's probably better to have
 * separate (if similar) dissectors for them.
 *
 * The only really complexity in the protocol is the message sequence
 * numbering.  See the comments below for an explanation of how it is
 * handled.
 *
 * Specifications are available from NASDAQ's website, although the
 * links to find them tend to move around over time.  At the time of
 * writing the correct URL is:
 *
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/soupbintcp.pdf
 *
 */

#include "config.h"

#include <stdlib.h>

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>

/* For tcp_dissect_pdus() */
#include "packet-tcp.h"

void proto_register_soupbintcp(void);
void proto_reg_handoff_soupbintcp(void);

/** Session data stored in the conversation */
struct conv_data {
    /** Next expected sequence number
     *
     * Set by the Login Accepted packet, and then updated for each
     * subsequent Sequenced Data packet during dissection. */
    guint next_seq;
};


/** Per-PDU data, stored in the frame's private data pointer */
struct pdu_data {
    /** Sequence number for this PDU */
    guint seq_num;
};


/** Packet names, indexed by message type code value */
static const value_string pkt_type_val[] = {
    { '+', "Debug Packet" },
    { 'A', "Login Accepted" },
    { 'H', "Server Heartbeat" },
    { 'J', "Login Rejected" },
    { 'L', "Login Request" },
    { 'O', "Logout Request" },
    { 'R', "Client Heartbeat" },
    { 'S', "Sequenced Data" },
    { 'U', "Unsequenced Data" },
    { 'Z', "End of Session" },
    { 0, NULL }
};


/** Login reject reasons, indexed by code value */
static const value_string reject_code_val[] = {
    { 'A', "Not authorized" },
    { 'S', "Session not available" },
    { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_soupbintcp = -1;
static dissector_handle_t soupbintcp_handle;
static heur_dissector_list_t heur_subdissector_list;

/* Preferences */
static gboolean soupbintcp_desegment = TRUE;
static range_t *global_soupbintcp_range = NULL;
static range_t *soupbintcp_range = NULL;

/* Initialize the subtree pointers */
static gint ett_soupbintcp = -1;

/* Header field formatting */
static int hf_soupbintcp_packet_length = -1;
static int hf_soupbintcp_packet_type = -1;
static int hf_soupbintcp_message = -1;
static int hf_soupbintcp_text = -1;
static int hf_soupbintcp_username = -1;
static int hf_soupbintcp_password = -1;
static int hf_soupbintcp_session = -1;
static int hf_soupbintcp_seq_num = -1;
static int hf_soupbintcp_next_seq_num = -1;
static int hf_soupbintcp_req_seq_num = -1;
static int hf_soupbintcp_reject_code = -1;


/** Format the display of the packet type code
 *
 * This function is called via BASE_CUSTOM, and displays the packet
 * type code as a character like it is in the specification, rather
 * than using BASE_DEC which shows it as an integer value. */
static void
format_packet_type(
    gchar   *buf,
    guint32  value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
               "%s (%c)",
               val_to_str(value, pkt_type_val, "Unknown packet"),
               (char)(value & 0xff));
}


/** Format the display of the login rejection reason code
 *
 * This function is called via BASE_CUSTOM, and displays the login
 * rejection reason code as a character like it is in the
 * specification, rather than using BASE_DEC which show it as an
 * integer value. */
static void
format_reject_code(
    gchar   *buf,
    guint32  value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
               "%s (%c)",
               val_to_str(value, reject_code_val, "Unknown reject code"),
               (char)(value & 0xff));
}


/** Dissector for SoupBinTCP messages */
static void
dissect_soupbintcp_common(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree)
{
    struct conv_data *conv_data;
    struct pdu_data  *pdu_data;
    const char       *pkt_name;
    const char       *tmp_buf;
    proto_item       *ti;
    proto_tree       *soupbintcp_tree = NULL;
    conversation_t   *conv            = NULL;
    guint16           expected_len;
    guint8            pkt_type;
    gint              offset          = 0;
    guint             this_seq        = 0, next_seq;
    heur_dtbl_entry_t *hdtbl_entry;

    /* Get the 16-bit big-endian SOUP packet length */
    expected_len = tvb_get_ntohs(tvb, 0);

    /* Get the 1-byte SOUP message type */
    pkt_type = tvb_get_guint8(tvb, 2);

    /* Since we use the packet name a few times, get and save that value */
    pkt_name = val_to_str(pkt_type, pkt_type_val, "Unknown (%u)");

    /* Set the protocol name in the summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SoupBinTCP");

    /* Set the packet name in the info column */
    col_add_str(pinfo->cinfo, COL_INFO, pkt_name);

    /* Sequence number tracking
     *
     * SOUP does not number packets from client to server (the server
     * acknowledges all important messages, so the client should use
     * the acks to figure out if the server received the message, and
     * otherwise resend it).
     *
     * Packets from server to client are numbered, but it's implicit.
     * The Login Accept packet contains the next sequence number that
     * the server will send, and the client needs to count the
     * Sequenced Data packets that it receives to know what their
     * sequence numbers are.
     *
     * So, we grab the next sequence number from the Login Acceptance
     * packet, and save it in a conversation_t we associate with the
     * TCP session.  Then, for each Sequenced Data packet we receive,
     * the first time it's processed (when PINFO_FD_VISITED() is
     * false), we write it into the PDU's frame's private data pointer
     * and increment the saved sequence number (in the conversation_t).
     *
     * If the visited flag is true, then we've dissected this packet
     * already, and so we can fetch the sequence number from the
     * frame's private data area.
     *
     * In either case, if there's any problem, we report zero as the
     * sequence number, and try to continue dissecting. */

    /* If first dissection of Login Accept, save sequence number */
    if (pkt_type == 'A' && !PINFO_FD_VISITED(pinfo)) {
        tmp_buf = tvb_get_string_enc(wmem_packet_scope(), tvb, 13, 20, ENC_ASCII);
        next_seq = atoi(tmp_buf);

        /* Create new conversation for this session */
        conv = conversation_new(PINFO_FD_NUM(pinfo),
                                &pinfo->src,
                                &pinfo->dst,
                                pinfo->ptype,
                                pinfo->srcport,
                                pinfo->destport,
                                0);

        /* Store starting sequence number for session's packets */
        conv_data = (struct conv_data *)wmem_alloc(wmem_file_scope(), sizeof(struct conv_data));
        conv_data->next_seq = next_seq;
        conversation_add_proto_data(conv, proto_soupbintcp, conv_data);
    }

    /* Handle sequence numbering for a Sequenced Data packet */
    if (pkt_type == 'S') {
        if (!PINFO_FD_VISITED(pinfo)) {
            /* Get next expected sequence number from conversation */
            conv = find_conversation(PINFO_FD_NUM(pinfo),
                                     &pinfo->src,
                                     &pinfo->dst,
                                     pinfo->ptype,
                                     pinfo->srcport,
                                     pinfo->destport,
                                     0);
            if (!conv) {
                this_seq = 0;
            } else {
                conv_data = (struct conv_data *)conversation_get_proto_data(conv,
                                                        proto_soupbintcp);
                if (conv_data) {
                    this_seq = conv_data->next_seq++;
                } else {
                    this_seq = 0;
                }

                pdu_data = (struct pdu_data *)wmem_alloc(
                    wmem_file_scope(),
                    sizeof(struct pdu_data));
                pdu_data->seq_num = this_seq;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_soupbintcp, 0, pdu_data);
            }
        } else {
            pdu_data = (struct pdu_data *)p_get_proto_data(wmem_file_scope(), pinfo, proto_soupbintcp, 0);
            if (pdu_data) {
                this_seq = pdu_data->seq_num;
            } else {
                this_seq = 0;
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", SeqNum = %u", this_seq);
    }

    if (tree) {
        /* Create sub-tree for SoupBinTCP details */
        ti = proto_tree_add_item(tree,
                                 proto_soupbintcp,
                                 tvb, 0, -1, ENC_NA);

        soupbintcp_tree = proto_item_add_subtree(ti, ett_soupbintcp);

        /* Append the packet name to the sub-tree item */
        proto_item_append_text(ti, ", %s", pkt_name);

        /* Length */
        proto_tree_add_item(soupbintcp_tree,
                            hf_soupbintcp_packet_length,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Type */
        proto_tree_add_item(soupbintcp_tree,
                            hf_soupbintcp_packet_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch (pkt_type) {
        case '+': /* Debug Message */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_text,
                                tvb, offset, expected_len - 1, ENC_ASCII|ENC_NA);
            break;

        case 'A': /* Login Accept */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_session,
                                tvb, offset, 10, ENC_ASCII|ENC_NA);
            offset += 10;

            tmp_buf = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 20, ENC_ASCII);
            proto_tree_add_string_format_value(soupbintcp_tree,
                                               hf_soupbintcp_next_seq_num,
                                               tvb, offset, 20,
                                               "X", "%d", atoi(tmp_buf));
            break;

        case 'J': /* Login Reject */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_reject_code,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        case 'U': /* Unsequenced Data */
            /* Display handled by sub-dissector */
            break;

        case 'S': /* Sequenced Data */
            proto_item_append_text(ti, ", SeqNum=%u", this_seq);
            proto_tree_add_string_format_value(soupbintcp_tree,
                                               hf_soupbintcp_seq_num,
                                               tvb, offset, 0,
                                               "X",
                                               "%u (Calculated)",
                                               this_seq);

            /* Display handled by sub-dissector */
            break;

        case 'L': /* Login Request */
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_username,
                                tvb, offset, 6, ENC_ASCII|ENC_NA);
            offset += 6;

            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_password,
                                tvb, offset, 10, ENC_ASCII|ENC_NA);
            offset += 10;

            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_session,
                                tvb, offset, 10, ENC_ASCII|ENC_NA);
            offset += 10;

            tmp_buf = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 20, ENC_ASCII);
            proto_tree_add_string_format_value(soupbintcp_tree,
                                               hf_soupbintcp_req_seq_num,
                                               tvb, offset, 20,
                                               "X", "%d", atoi(tmp_buf));
            break;

        case 'H': /* Server Heartbeat */
            break;

        case 'O': /* Logout Request */
            break;

        case 'R': /* Client Heartbeat */
            break;

        case 'Z': /* End of Session */
            break;

        default:
            /* Unknown */
            proto_tree_add_item(tree,
                                hf_soupbintcp_message,
                                tvb, offset, -1, ENC_ASCII|ENC_NA);
            break;
        }
    }

    /* Call sub-dissector for encapsulated data */
    if (pkt_type == 'S' || pkt_type == 'U') {
        tvbuff_t         *sub_tvb;

        /* Sub-dissector tvb starts at 3 (length (2) + pkt_type (1)) */
        sub_tvb = tvb_new_subset_remaining(tvb, 3);

#if 0   /* XXX: It's not valid for a soupbintcp subdissector to call       */
        /*  conversation_set_dissector() since the conversation is really  */
        /*  a TCP conversation.  (A 'soupbintcp' port type would need to   */
        /*  be defined to be able to use conversation_set_dissector()).    */
        /* In addition, no current soupbintcp subdissector calls           */
        /*  conversation_set_dissector().                                  */

        /* If this packet is part of a conversation, call dissector
         * for the conversation if available */
        if (try_conversation_dissector(&pinfo->dst, &pinfo->src, pinfo->ptype,
                                       pinfo->srcport, pinfo->destport,
                                       sub_tvb, pinfo, tree, NULL)) {
            return;
        }
#endif

        /* Otherwise, try heuristic dissectors */
        if (dissector_try_heuristic(heur_subdissector_list,
                                    sub_tvb,
                                    pinfo,
                                    tree,
                                    &hdtbl_entry,
                                    NULL)) {
            return;
        }

        /* Otherwise, give up, and just print the bytes in hex */
        if (tree) {
            proto_tree_add_item(soupbintcp_tree,
                                hf_soupbintcp_message,
                                sub_tvb, 0, -1,
                                ENC_ASCII|ENC_NA);
        }
    }
}


/** Return the size of the PDU in @p tvb, starting at @p offset */
static guint
get_soupbintcp_pdu_len(
    packet_info *pinfo _U_,
    tvbuff_t    *tvb,
    int          offset)
{
    /* Determine the length of the PDU using the SOUP header's 16-bit
       big-endian length (at offset zero).  We're guaranteed to get at
       least two bytes here because we told tcp_dissect_pdus() that we
       needed them.  Add 2 to the retrieved value, because the SOUP
       length doesn't include the length field itself. */
    return (guint)tvb_get_ntohs(tvb, offset) + 2;
}


/** Dissect a possibly-reassembled TCP PDU */
static int
dissect_soupbintcp_tcp_pdu(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree,
    void        *data _U_)
{
    dissect_soupbintcp_common(tvb, pinfo, tree);
    return tvb_length(tvb);
}


/** Dissect a TCP segment containing SoupBinTCP data */
static int
dissect_soupbintcp_tcp(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree,
    void        *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree,
                     soupbintcp_desegment, 2,
                     get_soupbintcp_pdu_len,
                     dissect_soupbintcp_tcp_pdu, data);
    return tvb_length(tvb);
}

static void
soupbintcp_prefs(void)
{
    dissector_delete_uint_range("tcp.port", soupbintcp_range, soupbintcp_handle);
    g_free(soupbintcp_range);
    soupbintcp_range = range_copy(global_soupbintcp_range);
    dissector_add_uint_range("tcp.port", soupbintcp_range, soupbintcp_handle);
}


void
proto_register_soupbintcp(void)
{
    static hf_register_info hf[] = {

        { &hf_soupbintcp_packet_length,
          { "Packet Length", "soupbintcp.packet_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Packet length, in bytes, NOT including these two bytes.",
            HFILL }},

        { &hf_soupbintcp_packet_type,
          { "Packet Type", "soupbintcp.packet_type",
            FT_UINT8, BASE_CUSTOM, format_packet_type, 0x0,
            "Message type code",
            HFILL }},

        { &hf_soupbintcp_reject_code,
          { "Login Reject Code", "soupbintcp.reject_code",
            FT_UINT8, BASE_CUSTOM, format_reject_code, 0x0,
            "Login reject reason code",
            HFILL }},

        { &hf_soupbintcp_message,
          { "Message", "soupbintcp.message",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Content of SoupBinTCP frame",
            HFILL }},

        { &hf_soupbintcp_text,
          { "Debug Text", "soupbintcp.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Free-form, human-readable text",
            HFILL }},

        { &hf_soupbintcp_username,
          { "User Name", "soupbintcp.username",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "User's login name",
            HFILL }},

        { &hf_soupbintcp_password,
          { "Password", "soupbintcp.password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "User's login password",
            HFILL }},

        { &hf_soupbintcp_session,
          { "Session", "soupbintcp.session",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Session identifier, or send all spaces to log into the currently "
            "active session",
            HFILL }},

        { &hf_soupbintcp_seq_num,
          { "Sequence number", "soupbintcp.seq_num",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Calculated sequence number for this message",
            HFILL }},

        { &hf_soupbintcp_next_seq_num,
          { "Next sequence number", "soupbintcp.next_seq_num",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Sequence number of next Sequenced Data message to be delivered",
            HFILL }},

        { &hf_soupbintcp_req_seq_num,
          { "Requested sequence number", "soupbintcp.req_seq_num",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Request to begin (re)transmission of Sequenced Data at this "
            "sequence number, or, if zero, to begin transmission with the "
            "next message generated",
            HFILL }}
    };

    static gint *ett[] = {
        &ett_soupbintcp
    };

    module_t *soupbintcp_module;

    proto_soupbintcp
        = proto_register_protocol("SoupBinTCP", "SoupBinTCP", "soupbintcp");

    proto_register_field_array(proto_soupbintcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    soupbintcp_module
        = prefs_register_protocol(proto_soupbintcp,
                                  soupbintcp_prefs);

    prefs_register_bool_preference(
        soupbintcp_module,
        "desegment",
        "Reassemble SoupBinTCP messages spanning multiple TCP segments",
        "Whether the SoupBinTCP dissector should reassemble messages "
        "spanning multiple TCP segments.",
        &soupbintcp_desegment);

    prefs_register_range_preference(
        soupbintcp_module,
        "tcp.port",
        "TCP Ports",
        "TCP Ports range",
        &global_soupbintcp_range,
        65535);

    soupbintcp_range = range_empty();

    register_heur_dissector_list("soupbintcp", &heur_subdissector_list);
}


void
proto_reg_handoff_soupbintcp(void)
{
    soupbintcp_handle = new_create_dissector_handle(dissect_soupbintcp_tcp,
                                                proto_soupbintcp);

    /* For "decode-as" */
    dissector_add_for_decode_as("tcp.port", soupbintcp_handle);
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
