/* file-ogg.c
 *
 * Routines for audio/ogg media dissection
 * Copyright 2025, Bence Csókás.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * The Ogg specification is found at Xiph.org:
 * https://xiph.org/ogg/doc/
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>

/** Size of the Ogg header without the segment table */
#define OGG_HDR_LEN 27U

void proto_register_ogg(void);
void proto_reg_handoff_ogg(void);

static dissector_handle_t ogg_handle;

/** Ogg payload dissectors, e.g. Vorbis, Theora, Opus */
static heur_dissector_list_t ogg_pl_dissectors;

static int proto_ogg;

static int hf_ogg_page;
static int hf_magic;
static int hf_version;
static int hf_type;
static int hf_position;
static int hf_serial_no;
static int hf_seq_no;
static int hf_crc;
static int hf_n_segs;

static int hf_type_flags_cont;
static int hf_type_flags_bos;
static int hf_type_flags_eos;

static int * const hf_type_flags[] = {
    &hf_type_flags_cont,
    &hf_type_flags_bos,
    &hf_type_flags_eos,
    NULL
};

static int ett_ogg;
static int ett_ogg_page;
static int ett_ogg_seg;
static int ett_ogg_type;

static expert_field ei_ogg_missing_magic;

static unsigned
dissect_ogg_segment_table(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, unsigned offset, uint8_t n_segs)
{
    uint8_t i;
    proto_tree *subtree;
    uint8_t seg_sizes[256];
    heur_dtbl_entry_t *hdtbl_e;

    for (i = 0; i < n_segs; i++)
        seg_sizes[i] = tvb_get_uint8(tvb, offset + i);

    offset += n_segs;

    for (i = 0; i < n_segs; i++) {
        tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, seg_sizes[i]);
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, seg_sizes[i], ett_ogg_seg,
                                      NULL, "Segment %d", i + 1);
        if (!dissector_try_heuristic(ogg_pl_dissectors, next_tvb, pinfo, subtree, &hdtbl_e, NULL))
            call_data_dissector(next_tvb, pinfo, subtree);

        offset += seg_sizes[i];
    }

    return offset;
}

static unsigned
find_ogg_page(tvbuff_t *tvb, unsigned offset, size_t len, bool *found)
{
    unsigned old_offset = offset;

    /* Find sync word */
    while ((ssize_t)offset < (ssize_t)(len - OGG_HDR_LEN)) {
        if (tvb_strneql(tvb, offset, "OggS", 4) == 0) {
            *found = true;
            return offset;
        }
        offset++;
    }

    *found = false;
    return old_offset;
}

static unsigned
dissect_ogg_page(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, unsigned offset)
{
    uint8_t n_segs;
    proto_item *ti_tree;
    proto_tree *ogg_tree;

    ti_tree = proto_tree_add_item(tree, hf_ogg_page, tvb, offset, -1, ENC_NA);
    ogg_tree = proto_item_add_subtree(ti_tree, ett_ogg_page);

    proto_tree_add_item(ogg_tree, hf_magic,
            tvb, offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_item(ogg_tree, hf_version,
            tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);

    proto_tree_add_bitmask(ogg_tree, tvb, offset + 5, hf_type, ett_ogg_type, hf_type_flags, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(ogg_tree, hf_position,
            tvb, offset + 6, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ogg_tree, hf_serial_no,
            tvb, offset + 14, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ogg_tree, hf_seq_no,
            tvb, offset + 18, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ogg_tree, hf_crc,
            tvb, offset + 22, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ogg_tree, hf_n_segs,
            tvb, offset + 26, 1, ENC_LITTLE_ENDIAN);
    n_segs = tvb_get_uint8(tvb, offset + 26);

    offset += OGG_HDR_LEN;
    if (n_segs > 0)
        offset = dissect_ogg_segment_table(tvb, ogg_tree, pinfo, offset, n_segs);

    proto_item_set_end(ti_tree, tvb, offset);

    return offset;
}

static int
dissect_ogg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    bool found;
    unsigned offset = 0;
    proto_item *ti_tree;
    proto_tree *ogg_tree;
    size_t len = tvb_reported_length(tvb);

    offset = find_ogg_page(tvb, offset, len, &found);

    if (!found) {
        expert_add_info(pinfo, tree, &ei_ogg_missing_magic);
        return 0;
    }

    ti_tree = proto_tree_add_item(tree, proto_ogg, tvb, offset, -1, ENC_NA);
    ogg_tree = proto_item_add_subtree(ti_tree, ett_ogg);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ogg");
    col_clear(pinfo->cinfo, COL_INFO);

    while (found) {
        offset = dissect_ogg_page(tvb, ogg_tree, pinfo, offset);
        offset = find_ogg_page(tvb, offset, len, &found);
    }

    proto_item_set_end(ti_tree, tvb, offset);
    return offset;
}

static bool
dissect_ogg_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_ogg(tvb, pinfo, tree, data) > 0;
}

void
proto_register_ogg(void)
{
    static hf_register_info hf[] = {
        { &hf_ogg_page,
            { "Ogg Page", "ogg.page",
              FT_NONE, BASE_NONE, NULL, 0x00,
              "Ogg Stream Page", HFILL }
        },
        { &hf_magic,
            { "Capture Pattern", "ogg.magic",
              FT_STRING, BASE_NONE, NULL, 0x00,
              "Ogg Stream Capture Pattern", HFILL }
        },
        { &hf_version,
            { "Version", "ogg.version",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Ogg Stream Structure Version", HFILL }
        },
        { &hf_type,
            { "Type Flags", "ogg.type_flags",
              FT_UINT8, BASE_HEX, NULL, 0x00,
              "Page Header Type Flags", HFILL }
        },
        { &hf_type_flags_cont,
            { "Continuation Flag", "ogg.type_flags.cont",
            FT_BOOLEAN, 8, NULL, 0x01,
            "This packet is a continuation of the previous one.", HFILL }
        },
        { &hf_type_flags_bos,
            { "Beginning of Stream", "ogg.type_flags.bos",
            FT_BOOLEAN, 8, NULL, 0x02,
            "First page of logical bitstream.", HFILL }
        },
        { &hf_type_flags_eos,
            { "End of Stream", "ogg.type_flags.eos",
            FT_BOOLEAN, 8, NULL, 0x04,
            "Last page of logical bitstream.", HFILL }
        },
        { &hf_position,
            { "Absolute Granule Position", "ogg.position",
              FT_UINT64, BASE_DEC, NULL, 0x00,
              "Total samples encoded after including all packets finished on this page.", HFILL }
        },
        { &hf_serial_no,
            { "Serial Number", "ogg.serial_no",
              FT_UINT32, BASE_HEX, NULL, 0x00,
              "Logical bitstream identifier", HFILL }
        },
        { &hf_seq_no,
            { "Sequence Number", "ogg.seq_no",
              FT_UINT32, BASE_DEC, NULL, 0x00,
              "Page counter", HFILL }
        },
        { &hf_crc,
            { "CRC32", "ogg.crc32",
              FT_UINT32, BASE_HEX, NULL, 0x00,
              "Page Checksum", HFILL }
        },
        { &hf_n_segs,
            { "Segments", "ogg.segment_table.len",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              "Ogg Stream Structure Version", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ogg,
        &ett_ogg_page,
        &ett_ogg_seg,
        &ett_ogg_type,
    };

    static ei_register_info ei[] = {
        { &ei_ogg_missing_magic,
            { "ogg.magic.missing", PI_PROTOCOL, PI_ERROR,
                "Capture Pattern not found!", EXPFILL }
        }
    };

    expert_module_t* expert_ogg;

    /* Register the protocol name and description */
    proto_ogg = proto_register_protocol(
            "Xiph.org Ogg Stream",
            "Ogg",
            "ogg"
    );

    /* Required function calls to register the header fields
     * and subtrees used */
    proto_register_field_array(proto_ogg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ogg = expert_register_protocol(proto_ogg);
    expert_register_field_array(expert_ogg, ei, array_length(ei));

    ogg_handle = register_dissector("ogg", dissect_ogg, proto_ogg);

    ogg_pl_dissectors = register_heur_dissector_list_with_description("ogg_payload", "Ogg-encapsulated codecs", proto_ogg);
}

void
proto_reg_handoff_ogg(void)
{
    dissector_add_string("media_type", "audio/ogg", ogg_handle);
    dissector_add_string("media_type", "video/ogg", ogg_handle);
    dissector_add_string("media_type", "application/ogg", ogg_handle);
    dissector_add_string("media_type", "audio/x-vorbis+ogg", ogg_handle);
    dissector_add_string("media_type", "audio/x-opus+ogg", ogg_handle);
    dissector_add_string("media_type", "video/theora+ogg", ogg_handle);

    heur_dissector_add("http", dissect_ogg_heur, "Ogg file in HTTP", "ogg_http", proto_ogg, HEURISTIC_ENABLE);
    heur_dissector_add("wtap_file", dissect_ogg_heur, "Ogg file", "ogg_wtap", proto_ogg, HEURISTIC_ENABLE);
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
