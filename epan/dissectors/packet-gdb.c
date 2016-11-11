/* packet-gdb.c
 * Routines for dissection of GDB's Remote Serial Protocol
 *
 * Copyright 2014, Martin Kaiser <martin@kaiser.cx>
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

/*
 * The GDB Remote Serial Protocol is used between an instance of the
 * GNU Debugger and a remote target such as an embedded system.
 * It can be run over TCP/IP or a serial line, we support only TCP/IP.
 *
 * The protocol specification is in Annex E of the GDB user manual
 * http://www.gnu.org/software/gdb/documentation/
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tvbparse.h>

enum {
    GDB_TOK_ACK,
    GDB_TOK_START,
    GDB_TOK_PAYLOAD,
    GDB_TOK_END,
    GDB_TOK_CHKSUM
};

static const value_string gdb_ack[] = {
    { '+', "Transmission successful" },
    { '-', "Transmission failed" },
    { 0, NULL }
};


void proto_register_gdb(void);
void proto_reg_handoff_gdb(void);

static int proto_gdb = -1;

static gint ett_gdb = -1;

static int hf_gdb_ack = -1;
static int hf_gdb_start = -1;
static int hf_gdb_payload = -1;
static int hf_gdb_end = -1;
static int hf_gdb_chksum = -1;

static tvbparse_wanted_t *want;

static void
dissect_gdb_token(void *tvbparse_data, const void *wanted_data, tvbparse_elem_t *tok)
{
    proto_tree *tree;
    guint       token;
    guint8      ack;

    if (!tok)   /* XXX - is this check necessary? */
        return;

    tree = (proto_tree *)tvbparse_data;
    token = GPOINTER_TO_UINT(wanted_data);

    /* XXX - check that tok->len is what we expect? */
    switch (token) {
        case GDB_TOK_ACK:
            ack = tvb_get_guint8(tok->tvb, tok->offset);
            proto_tree_add_uint_format(tree, hf_gdb_ack,
                    tok->tvb, tok->offset, tok->len, ack,
                    "Acknowledgement: %s (%c)",
                    val_to_str_const(ack, gdb_ack, "unknown"), ack);
            break;
        case GDB_TOK_START:
            proto_tree_add_item(tree, hf_gdb_start,
                    tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
            break;
        case GDB_TOK_PAYLOAD:
            proto_tree_add_item(tree, hf_gdb_payload,
                    tok->tvb, tok->offset, tok->len, ENC_NA);
            break;
        case GDB_TOK_END:
            proto_tree_add_item(tree, hf_gdb_end,
                    tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
            break;
        case GDB_TOK_CHKSUM:
            proto_tree_add_item(tree, hf_gdb_chksum,
                    tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
            break;
        default:
            break;
    }
}

static void init_gdb_parser(void) {
    tvbparse_wanted_t *want_ack;
    tvbparse_wanted_t *want_start;
    tvbparse_wanted_t *want_payload;
    tvbparse_wanted_t *want_end;
    tvbparse_wanted_t *want_chksum;

    want_ack = tvbparse_chars(-1, 1, 1, "+-",
            GUINT_TO_POINTER(GDB_TOK_ACK), NULL, dissect_gdb_token);
    want_start = tvbparse_chars(-1, 1, 1, "$",
            GUINT_TO_POINTER(GDB_TOK_START), NULL, dissect_gdb_token);
    want_payload = tvbparse_not_chars(-1, 1, 0, "$#",
            GUINT_TO_POINTER(GDB_TOK_PAYLOAD), NULL, dissect_gdb_token);
    want_end = tvbparse_chars(-1, 1, 1, "#",
            GUINT_TO_POINTER(GDB_TOK_END), NULL, dissect_gdb_token);
    want_chksum = tvbparse_chars(-1, 2, 2, "0123456789abcdefABCDEF",
            GUINT_TO_POINTER(GDB_TOK_CHKSUM), NULL, dissect_gdb_token);

    want = tvbparse_set_seq(-1, NULL, NULL, NULL,
            tvbparse_some(-1, 0, 1, NULL, NULL, NULL, want_ack),
            want_start, want_payload, want_end, want_chksum, NULL);
}


static void
dissect_gdb_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *gdb_tree;
    tvbparse_t  *tt;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GDB");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_protocol_format(tree, proto_gdb,
            tvb, 0, tvb_reported_length(tvb), "GDB Remote Serial Protocol");
    gdb_tree = proto_item_add_subtree(ti, ett_gdb);

    /* XXX support multiple sub-trees */
    tt = tvbparse_init(tvb, 0, -1, (void *)gdb_tree, NULL);

    while(tvbparse_get(tt, want)) {
        ;
    }
}


static int
dissect_gdb_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint      offset=0, offset_start;
    gint      pos;
    guint     packet_len;
    tvbuff_t *packet_tvb;

    while (tvb_captured_length_remaining(tvb, offset) > 0) {
        packet_tvb = NULL;
        offset_start = offset;
        pos = tvb_find_guint8(tvb, offset, -1, '#');
        if (pos != -1) {
            offset += pos;
            offset++; /* skip the hash sign */
            /* to have a complete packet, we need another two bytes
               for the checksum */
            if (tvb_bytes_exist(tvb, offset, 2)) {
                offset += 2;
                packet_len = offset-offset_start;
                packet_tvb = tvb_new_subset_length(tvb, offset_start,
                        packet_len);
            }
        }

        if (packet_tvb)
            dissect_gdb_packet(tvb, pinfo, tree);
        else {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return tvb_captured_length(tvb);
        }
    }
    return tvb_captured_length(tvb);
}


void
proto_register_gdb(void)
{
    static hf_register_info hf[] = {
        { &hf_gdb_ack,
          { "Acknowledge", "gdb.ack", FT_UINT8, BASE_HEX,
              VALS(gdb_ack), 0, NULL, HFILL } },
        { &hf_gdb_start,
          { "Start character", "gdb.start", FT_STRING, BASE_NONE,
              NULL, 0, NULL, HFILL } },
        { &hf_gdb_payload,
          { "Payload", "gdb.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL } },
        { &hf_gdb_end,
          { "Terminating character", "gdb.end", FT_STRING, BASE_NONE,
              NULL, 0, NULL, HFILL } },
        { &hf_gdb_chksum,
          { "Checksum", "gdb.chksum", FT_STRING, BASE_NONE,
              NULL, 0, NULL, HFILL } }
    };

    static gint *ett[] = {
        &ett_gdb
    };


    proto_gdb = proto_register_protocol(
            "GDB Remote Serial Protocol", "GDB remote", "gdb");

    proto_register_field_array(proto_gdb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    init_gdb_parser();
}


void
proto_reg_handoff_gdb(void)
{
    static gboolean            initialized = FALSE;
    static dissector_handle_t  gdb_handle;

    if (!initialized) {
        gdb_handle = create_dissector_handle(dissect_gdb_tcp, proto_gdb);
        initialized = TRUE;
    }

    dissector_add_for_decode_as("tcp.port", gdb_handle);
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
