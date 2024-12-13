/* file-riff.c
 *
 * Routines for RIFF (Resource Interchange File Format) dissection
 * Copyright 2024, John Thacker <johnthacker@gmail.com>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * https://www.loc.gov/preservation/digital/formats/fdd/fdd000025.shtml
 * https://learn.microsoft.com/en-us/windows/win32/xaudio2/resource-interchange-file-format--riff-
 * https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/riffmci.pdf
 * https://www-mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/RIFFNEW.pdf
 * https://developers.google.com/speed/webp/docs/riff_container
 * https://learn.microsoft.com/en-us/previous-versions/aa904731(v=vs.80)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
//#include <epan/expert.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>

void proto_reg_handoff_riff(void);
void proto_register_riff(void);

static int proto_riff;

static dissector_handle_t riff_handle;

static dissector_table_t riff_fourcc_dissector_table;

// Header fields
static int hf_riff_header_magic;
static int hf_riff_file_size;
static int hf_riff_file_type;

static int hf_riff_chunk;
static int hf_riff_chunk_id;
static int hf_riff_chunk_size;
static int hf_riff_chunk_data;

static int ett_riff;
static int ett_riff_chunk;

#define RIFF_MAGIC "\x52\x49\x46\x46" // "RIFF"

static int
dissect_riff(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    int offset = 0;
    tvbuff_t* chunk_tvb;
    proto_tree *riff_tree, *chunk_tree;
    proto_item *ti;

    uint32_t chunk_size;
    const uint8_t* file_type;
    const uint8_t* chunk_id;

    // Reject if we don't have enough room for the heuristics
    if (tvb_captured_length(tvb) < strlen(RIFF_MAGIC)) {
        return 0;
    }

    if (tvb_memeql(tvb, 0, (const uint8_t*)RIFF_MAGIC, strlen(RIFF_MAGIC)) != 0) {
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_riff, tvb, offset, -1, ENC_NA);
    riff_tree = proto_item_add_subtree(ti, ett_riff);

    proto_tree_add_item(riff_tree, hf_riff_header_magic, tvb, offset, 4, ENC_ASCII);
    offset += 4;
    proto_tree_add_item_ret_uint(riff_tree, hf_riff_file_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &chunk_size);
    offset += 4;
    proto_tree_add_item_ret_string(riff_tree, hf_riff_file_type, tvb, offset, 4, ENC_ASCII, pinfo->pool, &file_type);
    offset += 4;
    chunk_tvb = tvb_new_subset_length(tvb, offset, chunk_size);

    /* add proto name because this is a file type */
    if (!dissector_try_string_with_data(riff_fourcc_dissector_table,
        file_type, chunk_tvb, pinfo, tree, true, data)) {

        // Keep dissecting chunks
        while (tvb_reported_length_remaining(tvb, offset)) {
            ti = proto_tree_add_item(riff_tree, hf_riff_chunk, tvb, offset, 8, ENC_NA);
            chunk_tree = proto_item_add_subtree(ti, ett_riff_chunk);
            proto_tree_add_item_ret_string(chunk_tree, hf_riff_chunk_id, tvb, offset, 4, ENC_ASCII, pinfo->pool, &chunk_id);
            proto_item_prepend_text(ti, "%s ", chunk_id);
            offset += 4;
            proto_tree_add_item_ret_uint(chunk_tree, hf_riff_chunk_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &chunk_size);
            offset += 4;
            proto_item_set_len(ti, 8 + chunk_size);
            chunk_tvb = tvb_new_subset_length(tvb, offset, chunk_size);
            /* do not add proto name for other chunks */
            if (!dissector_try_string_with_data(riff_fourcc_dissector_table,
                chunk_id, chunk_tvb, pinfo, chunk_tree, false, data)) {

                proto_tree_add_item(chunk_tree, hf_riff_chunk_data, tvb, offset, chunk_size, ENC_NA);
            }
            offset += chunk_size;
        }
    }

    return tvb_reported_length(tvb);
}

void
proto_register_riff(void)
{
    static hf_register_info hf[] = {
        { &hf_riff_header_magic,
            { "Magic", "riff.magic",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_riff_file_size,
            { "File Size", "riff.file.size",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL }
        },
        { &hf_riff_file_type,
            { "File Type", "riff.file.type",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_riff_chunk,
            { "Chunk", "riff.chunk",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_riff_chunk_id,
            { "Chunk ID", "riff.chunk.id",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_riff_chunk_size,
            { "Chunk Size", "riff.chunk.size",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL }
        },
        { &hf_riff_chunk_data,
            { "Chunk Data", "riff.chunk.data",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_riff,
        &ett_riff_chunk,
    };

    proto_riff = proto_register_protocol("Resource Interchange File Format", "RIFF", "riff");

    riff_handle = register_dissector("riff", dissect_riff, proto_riff);
    proto_register_field_array(proto_riff, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

#if 0
    static ei_register_info ei[] = {
    };

    expert_module_t *expert_riff = expert_register_protocol(proto_riff);
    expert_register_field_array(expert_riff, ei, array_length(ei));
#endif

    // Some file types share chunk types. A convention is that all-capital
    // chunk FOURCCs are used for shared types, but WebP doesn't follow this.

    // Can we at least assume that FOURCCs for file types (aka forms) don't
    // conflict with FOURCCs for shared chunk types? If not, we might need
    // a second table
    riff_fourcc_dissector_table = register_dissector_table("riff.fourcc",
        "RIFF FOURCC", proto_riff, FT_STRING, STRING_CASE_SENSITIVE);
}

static bool
dissect_riff_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_riff(tvb, pinfo, tree, data) > 0;
}

void
proto_reg_handoff_riff(void)
{
    // Register some media types to handle in a generic way
    dissector_add_string("media_type", "image/webp", riff_handle);
    // WAV and AVI were never registered in
    // https://www.iana.org/assignments/media-types/media-types.xhtml
    // But are referenced here:
    // https://www.iana.org/assignments/wave-avi-codec-registry/wave-avi-codec-registry.xml
    // https://www.rfc-editor.org/rfc/rfc2361.html
    dissector_add_string("media_type", "audio/vnd.wave", riff_handle);
    dissector_add_string("media_type", "video/vnd.avi", riff_handle);
    // And MDN, WHATWG, and other sources mention a wide variety of media types
    // used as a result
    dissector_add_string("media_type", "audio/x-wav", riff_handle);
    dissector_add_string("media_type", "audio/wav", riff_handle);
    dissector_add_string("media_type", "audio/wave", riff_handle);
    dissector_add_string("media_type", "video/avi", riff_handle);
    dissector_add_string("media_type", "video/msvideo", riff_handle);
    dissector_add_string("media_type", "video/x-msvideo", riff_handle);

    // Register the RIFF heuristic dissector
    heur_dissector_add("wtap_file", dissect_riff_heur, "RIFF file", "riff_wtap", proto_riff, HEURISTIC_ENABLE);
}
