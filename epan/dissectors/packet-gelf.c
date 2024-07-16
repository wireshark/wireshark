/* packet-gelf.c
 * Routines for Graylog Extended Log Format (GELF) dissection
 *
 * Slava Bacherikov <slava@bacher09.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/reassemble.h>

#define HEADER_GZIP 0x1f8b
#define HEADER_CHUNKED 0x1e0f
/* not sure if this really used
seen this here: https://github.com/lusis/gelfd/blob/229cf5f1f913a35db648b195300d1aaae841d522/lib/gelfd.rb#L7 */
#define HEADER_UNCOMPRESSED 0x1f3c
#define HEADER_UNCOMPRESSED_PLAIN 0x7b22 // json payload without real header

/* minimal size of json message with only required fields */
#define MIN_PLAIN_MSG 48
#define MIN_ZLIB_MSG  46

/* make 32 bit message id from 64 bit message id */
#define BUILD_MESSAGE_ID(X) ((X[3] << 3 | X[2] << 2 | X[1] << 1 | X[0]) ^ \
                            (X[4] << 3 | X[5] << 2 | X[6] << 1 | X[7]))


void proto_register_gelf(void);
void proto_reg_handoff_gelf(void);

static dissector_handle_t json_handle;
static int proto_gelf;
static dissector_handle_t gelf_udp_handle;

static int ett_gelf;
static int hf_gelf_pdu_type;
static int hf_gelf_pdu_message_id;
static int hf_gelf_pdu_chunk_number;
static int hf_gelf_pdu_chunk_count;
static int hf_gelf_pdu_chunked;

static const value_string gelf_udp_types[] = {
    { HEADER_GZIP, "gzip" },
    { 0x7801, "zlib" },
    { 0x785e, "zlib" },
    { 0x789c, "zlib" },
    { 0x78da, "zlib" },
    { HEADER_CHUNKED, "chunked" },
    { HEADER_UNCOMPRESSED, "uncompressed" },
    { HEADER_UNCOMPRESSED_PLAIN, "uncompressed plain json" },
    { 0, NULL }
};

static reassembly_table gelf_udp_reassembly_table;

static int ett_gelf_fragment;
static int ett_gelf_fragments;

static int hf_gelf_fragments;
static int hf_gelf_fragment;
static int hf_gelf_fragment_overlap;
static int hf_gelf_fragment_overlap_conflict;
static int hf_gelf_fragment_multiple_tails;
static int hf_gelf_fragment_too_long_fragment;
static int hf_gelf_fragment_error;
static int hf_gelf_fragment_count;
static int hf_gelf_reassembled_in;
static int hf_gelf_reassembled_length;

static const fragment_items gelf_fragment_items = {
    &ett_gelf_fragment,
    &ett_gelf_fragments,
    &hf_gelf_fragments,
    &hf_gelf_fragment,
    &hf_gelf_fragment_overlap,
    &hf_gelf_fragment_overlap_conflict,
    &hf_gelf_fragment_multiple_tails,
    &hf_gelf_fragment_too_long_fragment,
    &hf_gelf_fragment_error,
    &hf_gelf_fragment_count,
    &hf_gelf_reassembled_in,
    &hf_gelf_reassembled_length,
    NULL,
    "GELF fragments"
};

static expert_field ei_gelf_invalid_header;
static expert_field ei_gelf_broken_compression;

static inline bool
is_simple_zlib(uint16_t header) {
    return header == 0x7801 || header == 0x785e || header == 0x789c || header == 0x78da;
}

static int
dissect_gelf_simple_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint16_t header,
                        proto_item* pdu_item)
{
    int len;
    tvbuff_t *next_tvb;

    len = tvb_captured_length(tvb);
    if (header == HEADER_GZIP || is_simple_zlib(header)) {
        next_tvb = tvb_child_uncompress_zlib(tvb, tvb, 0, len);
        if (next_tvb) {
            add_new_data_source(pinfo, next_tvb, "compressed data");
            call_dissector(json_handle, next_tvb, pinfo, tree);
        } else {
            expert_add_info_format(pinfo, pdu_item, &ei_gelf_broken_compression,
                                   "Can't uncompress message");
        }
        return len;
    } else if (header == HEADER_UNCOMPRESSED) {
        next_tvb = tvb_new_subset_remaining(tvb, 2);
        if (next_tvb) {
            call_dissector(json_handle, next_tvb, pinfo, tree);
        }
        return len;
    } else if (header == HEADER_UNCOMPRESSED_PLAIN) {
        if (call_dissector(json_handle, tvb, pinfo, tree) == 0) {
            return 0;
        }
        return len;
    }
    return 0;
}

static int
dissect_gelf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool heur_check)
{
    uint16_t header;
    unsigned captured_length;
    proto_item *it;

    captured_length = tvb_captured_length(tvb);

    if (captured_length < 2)
        return 0;

    header = tvb_get_ntohs(tvb, 0);

    if (heur_check) {
        unsigned min_len;
        uint8_t number, count;

        switch(header) {
            case HEADER_GZIP:
                min_len = MIN_ZLIB_MSG;
                break;
            case HEADER_UNCOMPRESSED_PLAIN:
                min_len = MIN_PLAIN_MSG;
                break;
            case HEADER_UNCOMPRESSED:
                min_len = MIN_PLAIN_MSG + 2;
                break;
            case HEADER_CHUNKED:
                /* 10 bytes is chunked header + 2 bytes of data */
                min_len = 10 + 2;
                break;
            default:
                if (is_simple_zlib(header)) {
                    min_len = MIN_ZLIB_MSG;
                } else {
                    return 0;
                }
                break;
        }

        if (tvb_reported_length(tvb) < min_len)
            return 0;

        if (header == HEADER_CHUNKED && captured_length >= 10) {
            number = tvb_get_guint8(tvb, 10);
            count = tvb_get_guint8(tvb, 11);
            if (number >= count)
                return 0;
        }
    }


    proto_item *ti = proto_tree_add_item(tree, proto_gelf, tvb, 0, -1, ENC_NA);
    proto_tree *gelf_tree = proto_item_add_subtree(ti, ett_gelf);
    proto_item *pdu_item = proto_tree_add_item(gelf_tree, hf_gelf_pdu_type, tvb, 0, 2, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GELF");

    if (header == HEADER_CHUNKED) {
        uint32_t number, count, short_id, data_len;
        GByteArray *bytes;
        char message_id[17];
        bool more_frags;
        fragment_head *fd_head;

        message_id[0] = '\0';
        bytes = g_byte_array_sized_new(8);

        it = proto_tree_add_boolean(gelf_tree, hf_gelf_pdu_chunked, tvb, 0, 2, true);
        proto_item_set_generated(it);
        proto_tree_add_bytes_item(gelf_tree, hf_gelf_pdu_message_id, tvb, 2, 8, ENC_BIG_ENDIAN, bytes,
                                  NULL, NULL);
        proto_tree_add_item_ret_uint(gelf_tree, hf_gelf_pdu_chunk_number, tvb, 10, 1, ENC_BIG_ENDIAN,
                                     &number);
        proto_tree_add_item_ret_uint(gelf_tree, hf_gelf_pdu_chunk_count, tvb, 11, 1, ENC_BIG_ENDIAN,
                                     &count);
        bytes_to_hexstr(message_id, bytes->data, 8);
        message_id[16] = '\0';
        // HACK: convert 64 bit message id to 32 bit :)
        short_id = BUILD_MESSAGE_ID(bytes->data);
        g_byte_array_free(bytes, true);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Chunked packet: id: %s, number %u, count %u", message_id,
                     number, count);
        data_len = tvb_captured_length_remaining(tvb, 12);
        more_frags = (count == number + 1) ? false : true;
        fd_head = fragment_add_seq_check(&gelf_udp_reassembly_table, tvb, 12, pinfo, short_id, NULL, number,
                                         data_len, more_frags);
        if (fd_head != NULL) {
            tvbuff_t *newtvb;
            newtvb = process_reassembled_data(tvb, 12, pinfo, "Reassembled GELF", fd_head,
                                              &gelf_fragment_items, NULL, gelf_tree);
            if (newtvb != NULL) {
                uint16_t newheader = tvb_get_ntohs(newtvb, 0);
                dissect_gelf_simple_udp(newtvb, pinfo, tree, newheader, pdu_item);
           }
        }
        return captured_length;
    } else {
        it = proto_tree_add_boolean(gelf_tree, hf_gelf_pdu_chunked, tvb, 0, 2, false);
        proto_item_set_generated(it);

        switch(header) {
            case HEADER_GZIP:
                col_set_str(pinfo->cinfo, COL_INFO, "GZIP");
                break;
            case HEADER_UNCOMPRESSED_PLAIN:
                col_set_str(pinfo->cinfo, COL_INFO, "uncompressed plain");
                break;
            case HEADER_UNCOMPRESSED:
                col_set_str(pinfo->cinfo, COL_INFO, "uncompressed");
                break;
            default:
                if (is_simple_zlib(header)) {
                    col_set_str(pinfo->cinfo, COL_INFO, "ZLIB");
                } else {
                    expert_add_info_format(pinfo, pdu_item, &ei_gelf_invalid_header,
                                           "Invalid header magic");
                    return 0;
                }
                break;
        }

        return dissect_gelf_simple_udp(tvb, pinfo, tree, header, pdu_item);
    }
}

static int
dissect_gelf_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_gelf(tvb, pinfo, tree, false);
}

static bool
dissect_gelf_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (dissect_gelf(tvb, pinfo, tree, true) > 0) {
        return true;
    } else {
        return false;
    }
}

void
proto_register_gelf(void)
{
    static  hf_register_info hf[] = {
        { &hf_gelf_pdu_type,
            {
                "GELF Type", "gelf.type", FT_UINT16,
                BASE_HEX, VALS(gelf_udp_types), 0x0,
                NULL, HFILL
            }
        },
        { &hf_gelf_pdu_message_id,
            {
                "Message id", "gelf.chunk.msg_id", FT_BYTES,
                BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        { &hf_gelf_pdu_chunk_number,
            {
                "Chunk number", "gelf.chunk.number", FT_UINT8,
                BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        { &hf_gelf_pdu_chunk_count,
            {
                "Chunk count", "gelf.chunk.count", FT_UINT8,
                BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        { &hf_gelf_pdu_chunked,
            {
                "Chunked message", "gelf.chunked", FT_BOOLEAN,
                BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        }
        /* Fragmentation */,
        { &hf_gelf_fragments,
            {
                "GELF fragments", "gelf.fragments", FT_NONE, BASE_NONE,
                NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment,
            {
                "GELF fragment", "gelf.fragment", FT_FRAMENUM, BASE_NONE,
                NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment_overlap,
            {
                "GELF fragment overlap", "gelf.fragment.overlap", FT_BOOLEAN,
                BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment_overlap_conflict,
            {
                "GELF fragment overlapping with conflicting data",
                "gelf.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment_multiple_tails,
            {
                "GELF has multiple tail fragments",
                "gelf.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment_too_long_fragment,
            {
                "GELF fragment too long", "gelf.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment_error,
            {
                "GELF defragmentation error", "gelf.fragment.error", FT_FRAMENUM,
                BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_fragment_count,
            {
                "GELF fragment count", "gelf.fragment.count", FT_UINT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL
            }
        },
        { &hf_gelf_reassembled_in,
            {
                "Reassembled GELF in frame", "gelf.reassembled.in", FT_FRAMENUM, BASE_NONE,
                NULL, 0x00, "This GELF packet is reassembled in this frame", HFILL
            }
        },
        { &hf_gelf_reassembled_length,
            {
                "Reassembled GELF length", "gelf.reassembled.length", FT_UINT32, BASE_DEC,
                NULL, 0x00, "The total length of the reassembled payload", HFILL
            }
        },
    };

    static ei_register_info ei_gelf[] = {
        { &ei_gelf_invalid_header,
            {
                "gelf.invalid_header", PI_MALFORMED, PI_ERROR, "Invalid header", EXPFILL
            }
        },
        { &ei_gelf_broken_compression,
            {
                "gelf.broken_compression", PI_MALFORMED, PI_ERROR, "Can't unpack message", EXPFILL
            }
        }
    };

    static int *ett[] = {
        &ett_gelf,
        &ett_gelf_fragment,
        &ett_gelf_fragments
    };

    expert_module_t *expert_gelf;

    proto_gelf = proto_register_protocol("Graylog Extended Log Format", "GELF", "gelf");
    gelf_udp_handle = register_dissector("gelf-udp", dissect_gelf_udp, proto_gelf);
    proto_register_field_array(proto_gelf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gelf = expert_register_protocol(proto_gelf);
    expert_register_field_array(expert_gelf, ei_gelf, array_length(ei_gelf));
    reassembly_table_register(&gelf_udp_reassembly_table, &addresses_reassembly_table_functions);
}


void
proto_reg_handoff_gelf(void)
{
    dissector_add_for_decode_as("udp.port", gelf_udp_handle);
    heur_dissector_add("udp", dissect_gelf_heur_udp,  "GELF over UDP", "gelf_udp", proto_gelf,
                       HEURISTIC_DISABLE);
    json_handle = find_dissector_add_dependency("json", proto_gelf);
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
