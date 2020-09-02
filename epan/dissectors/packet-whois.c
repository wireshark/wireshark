/* packet-whois.c
 * Routines for whois dissection (see https://tools.ietf.org/html/rfc3912)
 * Copyright 2013, Christopher Maynard <Christopher.Maynard@gtech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#define WHOIS_PORT      43  /* This is the registered IANA port (nicname) */

void proto_register_whois(void);
void proto_reg_handoff_whois(void);

static int proto_whois = -1;
static int hf_whois_query = -1;
static int hf_whois_answer = -1;
static int hf_whois_answer_in = -1;
static int hf_whois_answer_to = -1;
static int hf_whois_response_time = -1;

static expert_field ei_whois_nocrlf = EI_INIT;

static gint ett_whois = -1;

typedef struct _whois_transaction_t {
    guint32  req_frame;
    guint32  rep_frame;
    nstime_t req_time;
    guint8*  query;
} whois_transaction_t;

static int
dissect_whois(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    proto_item          *ti, *expert_ti;
    proto_tree          *whois_tree;
    conversation_t      *conversation;
    whois_transaction_t *whois_trans;
    gboolean             is_query;
    guint                len;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WHOIS");

    if (pinfo->destport == WHOIS_PORT) {
        is_query = TRUE;
        col_set_str(pinfo->cinfo, COL_INFO, "Query");
    } else {
        is_query = FALSE;
        col_set_str(pinfo->cinfo, COL_INFO, "Answer");
    }

    conversation = find_or_create_conversation(pinfo);
    whois_trans = (whois_transaction_t *)conversation_get_proto_data(conversation, proto_whois);
    if (whois_trans == NULL) {
        gint linelen;
        whois_trans = wmem_new0(wmem_file_scope(), whois_transaction_t);

        /*
         * Find the end of the first line.
         */
        linelen = tvb_find_line_end(tvb, 0, -1, NULL, FALSE);
        if (linelen != -1)
            whois_trans->query = tvb_get_string_enc(wmem_file_scope(), tvb, 0, linelen, ENC_ASCII|ENC_NA);
        conversation_add_proto_data(conversation, proto_whois, whois_trans);
    }

    if (whois_trans->query) {
        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        col_append_str(pinfo->cinfo, COL_INFO, whois_trans->query);
    }

    len = tvb_reported_length(tvb);
    if (!PINFO_FD_VISITED(pinfo)) {
        if (pinfo->can_desegment) {
            if (is_query) {
                if ((len < 2) || (tvb_memeql(tvb, len - 2, "\r\n", 2))) {
                    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                    pinfo->desegment_offset = 0;
                    return -1;
                } else {
                    whois_trans->req_frame = pinfo->num;
                    whois_trans->req_time = pinfo->abs_ts;
                }
            } else {
                pinfo->desegment_len = DESEGMENT_UNTIL_FIN;
                pinfo->desegment_offset = 0;
                return -1;
            }
        }
    } else if (is_query && (whois_trans->req_frame == 0)) {
        whois_trans->req_frame = pinfo->num;
        whois_trans->req_time = pinfo->abs_ts;
    }

    if (!is_query && (whois_trans->rep_frame == 0)) {
        /* By comparing whois_trans->rep_frame to 0, if reassembly is turned
         * on, whois_trans->rep_frame will be assigned to the reassembled frame
         * number, and if reassembly is turned off, whois_trans->rep_frame will
         * be assigned to the first frame number of the response.  This seems
         * to match other protocols' behavior.  The alternative is:
         *      if (pinfo->num > whois_trans->rep_frame)
         * which will give us the same frame number either way.
         */
        whois_trans->rep_frame = pinfo->num;
    }

    ti = proto_tree_add_protocol_format(tree, proto_whois, tvb, 0, -1,
        "WHOIS: %s", is_query ? "Query" : "Answer");
    whois_tree = proto_item_add_subtree(ti, ett_whois);

    /*
     * XXX - WHOIS, as RFC 3912 says, "has no mechanism for indicating
     * the character set in use."  We assume ASCII; if somebody wants
     * to support non-ASCII WHOIS requets or responses, they should
     * add a preference to specify the character encoding.  These
     * days, it'd probably be UTF-8, but there might be older servers
     * using other character encodings.
     */
    if (is_query) {
        expert_ti = proto_tree_add_item(whois_tree, hf_whois_query, tvb, 0, -1, ENC_ASCII|ENC_NA);
        if ((len < 2) || (tvb_memeql(tvb, len - 2, "\r\n", 2))) {
            /*
             * From RFC3912, section 2:
             * All requests are terminated with ASCII CR and then ASCII LF.
             */
            expert_add_info(pinfo, expert_ti, &ei_whois_nocrlf);
        }
        if (tree && whois_trans->rep_frame) {
            ti = proto_tree_add_uint(whois_tree, hf_whois_answer_in,
                tvb, 0, 0, whois_trans->rep_frame);
            proto_item_set_generated(ti);
        }
    } else if (tree && whois_trans->rep_frame) {
        /*
         * If we know the request frame, show it and the time delta between
         * the request and the response.
         */
        if (whois_trans->req_frame) {
            nstime_t ns;

            ti = proto_tree_add_uint(whois_tree, hf_whois_answer_to,
                tvb, 0, 0, whois_trans->req_frame);
            proto_item_set_generated(ti);

            if (pinfo->num == whois_trans->rep_frame) {
                nstime_delta(&ns, &pinfo->abs_ts, &whois_trans->req_time);
                ti = proto_tree_add_time(whois_tree, hf_whois_response_time, tvb, 0, 0, &ns);
                proto_item_set_generated(ti);
            }
        }

        /*
         * Show the response as text, a line at a time.
         */
	int offset = 0, next_offset;
        while (tvb_offset_exists(tvb, offset)) {
            /*
             * Find the end of the line.
             */
            tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

            /*
             * Put this line.
             */
            proto_tree_add_item(whois_tree, hf_whois_answer, tvb, offset,
                next_offset - offset, ENC_ASCII|ENC_NA);
            offset = next_offset;
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_whois(void)
{
    expert_module_t *expert_whois;

    static hf_register_info hf[] = {
        { &hf_whois_query,
            { "Query", "whois.query", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_whois_answer,
            { "Answer", "whois.answer", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_whois_answer_in,
            { "Answer In", "whois.answer_in", FT_FRAMENUM, BASE_NONE, NULL,
              0x0, "The answer to this WHOIS query is in this frame",
              HFILL }
        },
        { &hf_whois_answer_to,
            { "Query In", "whois.answer_to", FT_FRAMENUM, BASE_NONE, NULL,
              0x0, "This is the answer to the WHOIS query in this frame",
              HFILL }
        },
        { &hf_whois_response_time,
            { "Response Time", "whois.response_time", FT_RELATIVE_TIME,
              BASE_NONE, NULL, 0x0,
              "The time between the Query and the Answer", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_whois
    };

    static ei_register_info ei[] = {
        { &ei_whois_nocrlf,
            { "whois.nocrlf", PI_MALFORMED, PI_WARN, "Missing <CR><LF>", EXPFILL}
        }
    };

    proto_whois = proto_register_protocol("whois", "WHOIS", "whois");
    proto_register_field_array(proto_whois, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_whois = expert_register_protocol(proto_whois);
    expert_register_field_array(expert_whois, ei, array_length(ei));
}

void
proto_reg_handoff_whois(void)
{
    static dissector_handle_t whois_handle;

    whois_handle = create_dissector_handle(dissect_whois, proto_whois);
    dissector_add_uint_with_preference("tcp.port", WHOIS_PORT, whois_handle);
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

