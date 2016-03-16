/* packet-bzr.c
 * Routines for Bazaar packet dissection
 * Copyright 2011,2013 Jelmer Vernooij <jelmer@samba.org>
 *
 * http://doc.bazaar.canonical.com/developers/network-protocol.html
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_bzr(void);
void proto_reg_handoff_bzr(void);

static int proto_bzr = -1;

static gint ett_bzr = -1;
static gint ett_prefixed_bencode = -1;
static gint ett_prefixed_bytes = -1;

static gint hf_bzr_prefixed_bencode = -1;
static gint hf_bzr_prefixed_bencode_len = -1;
static gint hf_bzr_bytes = -1;
static gint hf_bzr_bytes_data = -1;
static gint hf_bzr_bytes_length = -1;
static gint hf_bzr_result = -1;
static gint hf_bzr_packet_protocol_version = -1;
static gint hf_bzr_packet_kind = -1;

static dissector_handle_t bencode_handle;

#define REQUEST_VERSION_TWO   "bzr request 2\n"
#define RESPONSE_VERSION_TWO  "bzr response 2\n"
#define MESSAGE_VERSION_THREE "bzr message 3 (bzr 1.6)\n"

#define TCP_PORT_BZR   4155

static const value_string message_part_kind[] = {
    {'s', "Structure"},
    {'b', "Bytes"},
    {'o', "Single byte"},
    {'e', "End"},
    {0, NULL}
};

static const value_string message_results[] = {
    {'S', "Success"},
    {'E', "Error"},
    {0, NULL}
};

/* desegmentation of Bazaar over TCP */
static gboolean bzr_desegment = TRUE;

static guint get_bzr_prefixed_len(tvbuff_t *tvb, int offset)
{
    guint header_len;
    header_len = tvb_get_ntohl(tvb, offset);
    return 4 + header_len;
}

static guint
get_bzr_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    int    next_offset;
    gint   len = 0;
    gint   protocol_version_len;
    guint8 cmd = 0;

    /* Protocol version */
    protocol_version_len = tvb_find_line_end(tvb, offset, -1, &next_offset,
                                             TRUE);
    if (protocol_version_len == -1) /* End of the packet not seen yet */
        return -1;

    len += protocol_version_len + 1;

    /* Headers */
    len += get_bzr_prefixed_len(tvb, next_offset);

    while (tvb_reported_length_remaining(tvb, offset + len) > 0) {
        cmd = tvb_get_guint8(tvb, offset + len);
        len += 1;

        switch (cmd) {
        case 's':
        case 'b':
            len += get_bzr_prefixed_len(tvb, offset + len);
            break;
        case 'o':
            len += 1;
            break;
        case 'e':
            return len;
        }
    }

    return -1;
}

static gint
dissect_prefixed_bencode(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                         proto_tree *tree)
{
    guint32     plen;
    proto_tree *prefixed_bencode_tree;
    proto_item *ti;
    tvbuff_t *subtvb;

    plen = tvb_get_ntohl(tvb, offset);

    ti = proto_tree_add_item(tree, hf_bzr_prefixed_bencode, tvb, offset, 4 +
                             plen, ENC_NA);
    prefixed_bencode_tree = proto_item_add_subtree(ti, ett_prefixed_bencode);

    proto_tree_add_item(prefixed_bencode_tree, hf_bzr_prefixed_bencode_len,
                            tvb, offset, 4, ENC_BIG_ENDIAN);

    subtvb = tvb_new_subset_length(tvb, offset+4, plen);
    call_dissector(bencode_handle, subtvb, pinfo, prefixed_bencode_tree);

    return 4 + plen;
}

static gint
dissect_prefixed_bytes(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree)
{
    guint32     plen;
    proto_tree *prefixed_bytes_tree;
    proto_item *ti;

    plen = tvb_get_ntohl(tvb, offset);

    ti = proto_tree_add_item(tree, hf_bzr_bytes, tvb, offset, 4 +
                             plen, ENC_NA);
    prefixed_bytes_tree = proto_item_add_subtree(ti, ett_prefixed_bytes);

    if (prefixed_bytes_tree)
    {
        proto_tree_add_item(prefixed_bytes_tree, hf_bzr_bytes_length,
                            tvb, offset, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(prefixed_bytes_tree, hf_bzr_bytes_data,
                            tvb, offset+4, plen, ENC_NA);
    }

    return 4 + plen;
}

static gint
dissect_body(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
    guint8 cmd = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        cmd = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_bzr_packet_kind, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch (cmd) {
        case 's':
            offset += dissect_prefixed_bencode(tvb, offset, pinfo, tree);
            break;
        case 'b':
            offset += dissect_prefixed_bytes(tvb, offset, pinfo, tree);
            break;
        case 'o':
            proto_tree_add_item(tree, hf_bzr_result, tvb, offset, 1,
                                ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 'e':
            break;
        }
    }

    return offset;
}

static void
dissect_bzr_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *bzr_tree;
    proto_item *ti;
    int         offset = 0;
    gint        protocol_version_len;

    ti = proto_tree_add_item(tree, proto_bzr, tvb, offset, -1, ENC_NA);
    bzr_tree = proto_item_add_subtree(ti, ett_bzr);

    protocol_version_len = tvb_find_line_end(tvb, offset, -1, &offset, TRUE);
    if (protocol_version_len == -1) /* Invalid packet */
        return;

    if (bzr_tree)
    {
        proto_tree_add_item(bzr_tree, hf_bzr_packet_protocol_version, tvb, 0,
                            protocol_version_len+1, ENC_ASCII|ENC_NA);
    }

    offset += dissect_prefixed_bencode(tvb, offset, pinfo, bzr_tree);
    /*offset +=*/ dissect_body(tvb, offset, pinfo, bzr_tree);
}

static int
dissect_bzr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint      offset = 0, pdu_len;
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BZR");

    col_set_str(pinfo->cinfo, COL_INFO, "Bazaar Smart Protocol");

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        pdu_len = get_bzr_pdu_len(pinfo, tvb, offset);
        if (pdu_len == -1) {
            if (pinfo->can_desegment && bzr_desegment) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return tvb_captured_length(tvb);
            } else {
                pdu_len = tvb_reported_length_remaining(tvb, offset);
            }
        }
        next_tvb = tvb_new_subset_length(tvb, offset, pdu_len);
        dissect_bzr_pdu(next_tvb, pinfo, tree);
        offset += pdu_len;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_bzr(void)
{
    static hf_register_info hf[] = {
        { &hf_bzr_packet_kind,
          { "Packet kind", "bzr.kind", FT_UINT8, BASE_DEC,
            VALS(message_part_kind), 0x0, NULL, HFILL },
        },
        { &hf_bzr_packet_protocol_version,
          { "Protocol version", "bzr.protocol_version", FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL },
        },
        { &hf_bzr_prefixed_bencode,
          { "Bencode packet", "bzr.bencode", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Serialized structure of integers, dictionaries, strings and "
            "lists.", HFILL },
        },
        { &hf_bzr_prefixed_bencode_len,
          { "Bencode packet length", "bzr.bencode.length", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL },
        },
        { &hf_bzr_bytes,
          { "Prefixed bytes", "bzr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Bytes field with prefixed 32-bit length", HFILL },
        },
        { &hf_bzr_bytes_data,
          { "Prefixed bytes data", "bzr.bytes.data", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL },
        },
        { &hf_bzr_bytes_length,
          { "Prefixed bytes length", "bzr.bytes.length", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL },
        },
        { &hf_bzr_result,
          { "Result", "bzr.result", FT_UINT8, BASE_HEX,
            VALS(message_results), 0x0,
            "Command result (success or failure with error message)", HFILL
          },
        },
    };

    static gint *ett[] = {
        &ett_bzr,
        &ett_prefixed_bencode,
        &ett_prefixed_bytes,
    };

    module_t *bzr_module;
    proto_bzr = proto_register_protocol("Bazaar Smart Protocol", "Bazaar", "bzr");
    register_dissector("bzr", dissect_bzr, proto_bzr);
    proto_register_field_array(proto_bzr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bzr_module = prefs_register_protocol(proto_bzr, NULL);

    prefs_register_bool_preference(bzr_module, "desegment",
                                   "Reassemble Bazaar messages spanning multiple TCP segments",
                                   "Whether the Bazaar dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\""
                                   " in the TCP protocol settings.",
                                   &bzr_desegment);
}

void
proto_reg_handoff_bzr(void)
{
    dissector_handle_t bzr_handle;

    bencode_handle = find_dissector_add_dependency("bencode", proto_bzr);

    bzr_handle = find_dissector("bzr");
    dissector_add_uint("tcp.port", TCP_PORT_BZR, bzr_handle);
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
