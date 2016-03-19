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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>

/* Forward declarations */
void proto_register_acap(void);
void proto_reg_handoff_acap(void);

static dissector_handle_t acap_handle;

static header_field_info *hfi_acap = NULL;

#define HFI_ACAP HFI_INIT(proto_acap)

static header_field_info hfi_acap_response HFI_ACAP = {
    "Response",           "acap.response",
    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
    "TRUE if ACAP response", HFILL };

static header_field_info hfi_acap_request HFI_ACAP = {
    "Request",            "acap.request",
    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
    "TRUE if ACAP request", HFILL };

static header_field_info hfi_acap_request_tag HFI_ACAP = {
    "Request Tag",            "acap.request_tag",
    FT_STRING, BASE_NONE, NULL, 0x0,
    NULL, HFILL };

static header_field_info hfi_acap_response_tag HFI_ACAP = {
    "Response Tag",            "acap.response_tag",
    FT_STRING, BASE_NONE, NULL, 0x0,
    NULL, HFILL };

static header_field_info hfi_acap_request_data HFI_ACAP = {
    "Request",            "acap.request_data",
    FT_STRING, BASE_NONE, NULL, 0x0,
    NULL, HFILL };

static header_field_info hfi_acap_response_data HFI_ACAP = {
    "Response",            "acap.response_data",
    FT_STRING, BASE_NONE, NULL, 0x0,
    NULL, HFILL };

static gint ett_acap = -1;
static gint ett_acap_reqresp = -1;

#define TCP_PORT_ACAP           674

static int
dissect_acap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gboolean      is_request;
    proto_tree   *acap_tree, *reqresp_tree;
    proto_item   *ti, *hidden_item;
    gint          offset = 0;
    const guchar *line;
    gint          next_offset;
    int           linelen;
    int           tokenlen;
    const guchar *next_token;


    /*
     * If this should be a request or response, do this quick check to see if
     * it begins with a string...
     * Otherwise, looking for the end of line in a binary file can take a long time
     * and this probably isn't ACAP
     */
    if (!g_ascii_isprint(tvb_get_guint8(tvb, offset))) {
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
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
    line = tvb_get_ptr(tvb, offset, linelen);

    if (pinfo->match_uint == pinfo->destport)
        is_request = TRUE;
    else
        is_request = FALSE;

    /*
     * Put the first line from the buffer into the summary
     * (but leave out the line terminator).
     */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
        is_request ? "Request" : "Response",
        format_text(line, linelen));

    if (tree) {
        ti = proto_tree_add_item(tree, hfi_acap, tvb, offset, -1,
            ENC_NA);
        acap_tree = proto_item_add_subtree(ti, ett_acap);

        if (is_request) {
            hidden_item = proto_tree_add_boolean(acap_tree,
                &hfi_acap_request, tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        } else {
            hidden_item = proto_tree_add_boolean(acap_tree,
                &hfi_acap_response, tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
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
                proto_tree_add_string(reqresp_tree, &hfi_acap_request_tag, tvb, offset,
                    tokenlen, format_text(line, tokenlen));
            } else {
                proto_tree_add_string(reqresp_tree, &hfi_acap_response_tag, tvb, offset,
                    tokenlen, format_text(line, tokenlen));
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
                proto_tree_add_string(reqresp_tree, &hfi_acap_request_data, tvb, offset,
                    linelen, format_text(line, linelen));
            } else {
                proto_tree_add_string(reqresp_tree, &hfi_acap_response_data, tvb, offset,
                    linelen, format_text(line, linelen));
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
#ifndef HAVE_HFI_SECTION_INIT
    static header_field_info *hfi[] = {
        &hfi_acap_response,
        &hfi_acap_request,
        &hfi_acap_request_tag,
        &hfi_acap_response_tag,
        &hfi_acap_request_data,
        &hfi_acap_response_data,
    };
#endif

    static gint *ett[] = {
        &ett_acap,
        &ett_acap_reqresp,
    };

    int proto_acap;

    proto_acap = proto_register_protocol("Application Configuration Access Protocol",
                         "ACAP", "acap");
    hfi_acap = proto_registrar_get_nth(proto_acap);

    proto_register_fields(proto_acap, hfi, array_length(hfi));
    proto_register_subtree_array(ett, array_length(ett));

    acap_handle = create_dissector_handle(dissect_acap, proto_acap);
}

void
proto_reg_handoff_acap(void)
{
    dissector_add_uint("tcp.port", TCP_PORT_ACAP, acap_handle);
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
