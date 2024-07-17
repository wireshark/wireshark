/* packet-acap.c
 * Routines for ACAP packet dissection
 * RFC 2244
 * Copyright 2003, Brad Hards <bradh@frogmouth.net>
 * Heavily based in packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-imap.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>

/* Forward declarations */
void proto_register_acap(void);
void proto_reg_handoff_acap(void);

static dissector_handle_t acap_handle;

static int proto_acap;

static int hf_acap_request;
static int hf_acap_request_data;
static int hf_acap_request_tag;
static int hf_acap_response;
static int hf_acap_response_data;
static int hf_acap_response_tag;

static int ett_acap;
static int ett_acap_reqresp;

#define TCP_PORT_ACAP           674

static int
dissect_acap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    bool          is_request;
    proto_tree   *acap_tree, *reqresp_tree;
    proto_item   *ti, *hidden_item;
    int           offset = 0;
    const unsigned char *line;
    int           next_offset;
    int           linelen;
    int           tokenlen;
    const unsigned char *next_token;


    /*
     * If this should be a request or response, do this quick check to see if
     * it begins with a string...
     * Otherwise, looking for the end of line in a binary file can take a long time
     * and this probably isn't ACAP
     */
    if (!g_ascii_isprint(tvb_get_uint8(tvb, offset))) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACAP");

    /*
     * Find the end of the first line.
     *
     * Note that "tvb_find_line_end()" will return a value that is
     * not longer than what's in the buffer, so the "tvb_get_ptr()"
     * call won't throw an exception.
     */
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
    line = tvb_get_ptr(tvb, offset, linelen);

    if (pinfo->match_uint == pinfo->destport)
        is_request = true;
    else
        is_request = false;

    /*
     * Put the first line from the buffer into the summary
     * (but leave out the line terminator).
     */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
        is_request ? "Request" : "Response",
        format_text(pinfo->pool, line, linelen));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_acap, tvb, offset, -1,
            ENC_NA);
        acap_tree = proto_item_add_subtree(ti, ett_acap);

        if (is_request) {
            hidden_item = proto_tree_add_boolean(acap_tree,
                hf_acap_request, tvb, 0, 0, true);
            proto_item_set_hidden(hidden_item);
        } else {
            hidden_item = proto_tree_add_boolean(acap_tree,
                hf_acap_response, tvb, 0, 0, true);
            proto_item_set_hidden(hidden_item);
        }

        /*
         * Put the line into the protocol tree.
         */
        ti = proto_tree_add_format_text(acap_tree, tvb, offset, next_offset - offset);
        reqresp_tree = proto_item_add_subtree(ti, ett_acap_reqresp);

        /*
         * Show the first line as tags + requests or replies.
         */

        /*
         * Extract the first token, and, if there is a first
         * token, add it as the request or reply tag.
         */
        tokenlen = get_token_len(line, line + linelen, &next_token);
        if (tokenlen != 0) {
            if (is_request) {
                proto_tree_add_string(reqresp_tree, hf_acap_request_tag, tvb, offset,
                    tokenlen, format_text(pinfo->pool, line, tokenlen));
            } else {
                proto_tree_add_string(reqresp_tree, hf_acap_response_tag, tvb, offset,
                    tokenlen, format_text(pinfo->pool, line, tokenlen));
            }
            offset += (int)(next_token - line);
            linelen -= (int)(next_token - line);
            line = next_token;
        }

        /*
         * Add the rest of the line as request or reply data.
         */
        if (linelen != 0) {
            if (is_request) {
                proto_tree_add_string(reqresp_tree, hf_acap_request_data, tvb, offset,
                    linelen, format_text(pinfo->pool, line, linelen));
            } else {
                proto_tree_add_string(reqresp_tree, hf_acap_response_data, tvb, offset,
                    linelen, format_text(pinfo->pool, line, linelen));
            }
        }

        /*
         * XXX - show the rest of the frame; this requires that
         * we handle literals, quoted strings, continuation
         * responses, etc..
         *
         * This involves a state machine, and attaching
         * state information to the packets.
         */
    }
    return tvb_captured_length(tvb);
}

void
proto_register_acap(void)
{
    static hf_register_info hf[] = {
        { &hf_acap_response,
            { "Response", "acap.response",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "true if ACAP response", HFILL }
        },
        { &hf_acap_request,
            { "Request", "acap.request",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "true if ACAP request", HFILL }
        },
        { &hf_acap_request_tag,
            { "Request Tag", "acap.request_tag",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_acap_response_tag,
            { "Response Tag", "acap.response_tag",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_acap_request_data,
            { "Request", "acap.request_data",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_acap_response_data,
            { "Response", "acap.response_data",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_acap,
        &ett_acap_reqresp,
    };

    proto_acap = proto_register_protocol("Application Configuration Access Protocol",
                         "ACAP", "acap");
    proto_register_field_array(proto_acap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    acap_handle = register_dissector("acap", dissect_acap, proto_acap);
}

void
proto_reg_handoff_acap(void)
{
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_ACAP, acap_handle);
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
