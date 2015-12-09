/* packet-gopher.c
 * Routines for RFC 1436 Gopher protocol dissection
 * Copyright 2010, Gerald Combs <gerald@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-banana.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * RFC 1436: http://tools.ietf.org/html/rfc1436
 * http://en.wikipedia.org/wiki/Gopher_%28protocol%29
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_gopher(void);
void proto_reg_handoff_gopher(void);

/* Initialize the protocol and registered fields */
static int proto_gopher = -1;
static int hf_gopher_request = -1;
static int hf_gopher_dir_item = -1;
static int hf_gopher_di_type = -1;
static int hf_gopher_di_name = -1;
static int hf_gopher_di_selector = -1;
static int hf_gopher_di_host = -1;
static int hf_gopher_di_port = -1;
static int hf_gopher_unknown = -1;

/* Initialize the subtree pointers */
static gint ett_gopher = -1;
static gint ett_dir_item = -1;

static dissector_handle_t gopher_handle;

/* RFC 1436 section 3.8 */
static const value_string item_types[] = {
    { '+',  "Redundant server" },
    { '0',  "Text file" },
    { '1',  "Menu" },
    { '2',  "CSO phone book entity" },
    { '3',  "Error" },
    { '4',  "BinHexed Macintosh file" },
    { '5',  "DOS binary file" },
    { '6',  "Uuencoded file" },
    { '7',  "Index server" },
    { '8',  "Telnet session" },
    { '9',  "Binary file" },
    { 'g',  "GIF file" },
    { 'h',  "HTML file" },              /* Not in RFC 1436 */
    { 'i',  "Informational message"},   /* Not in RFC 1436 */
    { 'I',  "Image file" },
    { 's',  "Audio file" },             /* Not in RFC 1436 */
    { 'T',  "Tn3270 session" },
    { 0, NULL }
};

#define TCP_DEFAULT_RANGE "70"

static range_t *global_gopher_tcp_range = NULL;
static range_t *gopher_tcp_range = NULL;

/* Returns TRUE if the packet is from a client */
static gboolean
is_client(packet_info *pinfo) {
    if (value_is_in_range(gopher_tcp_range, pinfo->destport)) {
        return TRUE;
    }
    return FALSE;
}

/* Name + Tab + Selector + Tab + Host + Tab + Port */
#define MAX_DIR_LINE_LEN (70 + 1 + 255 + 1 + 255 + 1 + 5)
#define MIN_DIR_LINE_LEN (0 + 1 + 0 + 1 + 1 + 1 + 1)
static gboolean
find_dir_tokens(tvbuff_t *tvb, gint name_start, gint *sel_start, gint *host_start, gint *port_start, gint *line_len, gint *next_offset) {
    gint remain;

    if (tvb_captured_length_remaining(tvb, name_start) < MIN_DIR_LINE_LEN)
        return FALSE;

    if (! (sel_start && host_start && port_start && line_len && next_offset) )
        return FALSE;

    *line_len = tvb_find_line_end(tvb, name_start, MAX_DIR_LINE_LEN, next_offset, FALSE);
    if (*line_len < MIN_DIR_LINE_LEN)
        return FALSE;

    remain = *line_len;
    *sel_start = tvb_find_guint8(tvb, name_start, remain, '\t') + 1;
    if (*sel_start < name_start + 1)
        return FALSE;

    remain -= *sel_start - name_start;
    *host_start = tvb_find_guint8(tvb, *sel_start, remain, '\t') + 1;
    if (*host_start < *sel_start + 1)
        return FALSE;

    remain -= *host_start - *sel_start;
    *port_start = tvb_find_guint8(tvb, *host_start, remain, '\t') + 1;
    if (*port_start < *host_start + 1)
        return FALSE;

    return TRUE;
}

/* Dissect the packets */

static int
dissect_gopher(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti;
    proto_tree *gopher_tree, *dir_tree = NULL;
    gboolean client = is_client(pinfo);
    gint line_len;
    const gchar *request = "[Invalid request]";
    gboolean is_dir = FALSE;
    gint offset = 0, next_offset;
    gint sel_start, host_start, port_start;
    gchar *name;

    /* Fill in our protocol and info columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gopher");

    if (client) {
        line_len = tvb_find_line_end(tvb, 0, -1, NULL, FALSE);
        if (line_len == 0) {
            request = "[Directory list]";
        } else if (line_len > 0) {
            request = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, line_len, ENC_ASCII);
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "Request: %s", request);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Response");
    }

    if (tree) {
        /* Create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_gopher, tvb, 0, -1, ENC_NA);
        gopher_tree = proto_item_add_subtree(ti, ett_gopher);

        if (client) {
            proto_item_append_text(ti, " request: %s", request);
            proto_tree_add_string(gopher_tree, hf_gopher_request, tvb,
                                  0, -1, request);
        } else {
            proto_item_append_text(ti, " response: ");

            while (find_dir_tokens(tvb, offset + 1, &sel_start, &host_start, &port_start, &line_len, &next_offset)) {
                if (!is_dir) { /* First time */
                    proto_item_append_text(ti, "[Directory list]");
                    col_append_str(pinfo->cinfo, COL_INFO, ": [Directory list]");
                }

                name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, sel_start - offset - 2, ENC_ASCII);
                ti = proto_tree_add_string(gopher_tree, hf_gopher_dir_item, tvb,
                                offset, line_len + 1, name);
                dir_tree = proto_item_add_subtree(ti, ett_dir_item);
                proto_tree_add_item(dir_tree, hf_gopher_di_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(dir_tree, hf_gopher_di_name, tvb, offset + 1,
                                    sel_start - offset - 2, ENC_ASCII|ENC_NA);
                proto_tree_add_item(dir_tree, hf_gopher_di_selector, tvb, sel_start,
                                    host_start - sel_start - 1, ENC_ASCII|ENC_NA);
                proto_tree_add_item(dir_tree, hf_gopher_di_host, tvb, host_start,
                                    port_start - host_start - 1, ENC_ASCII|ENC_NA);
                proto_tree_add_item(dir_tree, hf_gopher_di_port, tvb, port_start,
                                    line_len - (port_start - offset - 1), ENC_ASCII|ENC_NA);
                is_dir = TRUE;
                offset = next_offset;
            }

            if (!is_dir) {
                proto_item_append_text(ti, "[Unknown]");
                proto_tree_add_item(gopher_tree, hf_gopher_unknown, tvb, 0, -1, ENC_ASCII|ENC_NA);
            }
        }

    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_captured_length(tvb);
}

/* Preference callbacks */
static void
range_delete_gopher_tcp_callback(guint32 port) {
      dissector_delete_uint("tcp.port", port, gopher_handle);
}

static void
range_add_gopher_tcp_callback(guint32 port) {
    dissector_add_uint("tcp.port", port, gopher_handle);
}

static void
gopher_prefs_apply(void) {
    range_foreach(gopher_tcp_range, range_delete_gopher_tcp_callback);
    g_free(gopher_tcp_range);
    gopher_tcp_range = range_copy(global_gopher_tcp_range);
    range_foreach(gopher_tcp_range, range_add_gopher_tcp_callback);
}

/* Register the protocol with Wireshark */

void
proto_register_gopher(void)
{
    static hf_register_info hf[] = {
        { &hf_gopher_request,
            { "Gopher client request", "gopher.request",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },

        { &hf_gopher_dir_item,
            { "Directory item", "gopher.directory",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_gopher_di_type,
            { "Type", "gopher.directory.type",
                FT_UINT8, BASE_HEX, VALS(item_types), 0,
                NULL, HFILL }
        },
        { &hf_gopher_di_name,
            { "Name", "gopher.directory.name",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_gopher_di_selector,
            { "Selector", "gopher.directory.selector",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_gopher_di_host,
            { "Host", "gopher.directory.host",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_gopher_di_port,
            { "Port", "gopher.directory.port",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },

        { &hf_gopher_unknown,
            { "Unknown Gopher transaction data", "gopher.unknown",
                FT_STRING, BASE_NONE, NULL, 0,
                NULL, HFILL }
        }
    };

    module_t *gopher_module;

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_gopher,
        &ett_dir_item
    };

    /* Register the protocol name and description */
    proto_gopher = proto_register_protocol("Gopher",
        "Gopher", "gopher");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_gopher, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Initialize dissector preferences */
    gopher_module = prefs_register_protocol(proto_gopher, gopher_prefs_apply);

    range_convert_str(&global_gopher_tcp_range, TCP_DEFAULT_RANGE, 65535);
    gopher_tcp_range = range_empty();
    prefs_register_range_preference(gopher_module, "tcp.port", "TCP Ports",
                                    "TCP Ports range",
                                    &global_gopher_tcp_range, 65535);
}

void
proto_reg_handoff_gopher(void)
{
    gopher_handle = create_dissector_handle(dissect_gopher, proto_gopher);
    gopher_prefs_apply();
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


