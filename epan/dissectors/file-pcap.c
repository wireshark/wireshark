/* file-pcap.c
 * Routines for PCAP File Format
 * http://www.tcpdump.org/manpages/pcap-savefile.5.html
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>

#include "packet-pcap_pktdata.h"

static int proto_pcap;

static dissector_handle_t pcap_pktdata_handle;

static int hf_pcap_header;
static int hf_pcap_header_magic_number;
static int hf_pcap_header_version_major;
static int hf_pcap_header_version_minor;
static int hf_pcap_header_this_zone;
static int hf_pcap_header_sigfigs;
static int hf_pcap_header_snapshot_length;
static int hf_pcap_header_link_type;
static int hf_pcap_packet;
static int hf_pcap_packet_timestamp;
static int hf_pcap_packet_timestamp_sec;
static int hf_pcap_packet_timestamp_usec;
static int hf_pcap_packet_captured_length;
static int hf_pcap_packet_original_length;
static int hf_pcap_packet_data;

static expert_field ei_pcap_capt_larger_than_orig;
static expert_field ei_pcap_capt_larger_than_snap;

static int ett_pcap;
static int ett_pcap_header;
static int ett_pcap_packet;
static int ett_pcap_packet_data;
static int ett_pcap_timestamp;

static bool pref_dissect_next_layer;

void proto_register_file_pcap(void);
void proto_reg_handoff_file_pcap(void);

#define MAGIC_NUMBER_SIZE    4

static int
dissect_pcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static const uint8_t pcap_big_endian_magic[MAGIC_NUMBER_SIZE] = {
        0xa1, 0xb2, 0xc3, 0xd4
    };
    static const uint8_t pcap_little_endian_magic[MAGIC_NUMBER_SIZE] = {
        0xd4, 0xc3, 0xb2, 0xa1
    };
    static const uint8_t pcap_nsec_big_endian_magic[MAGIC_NUMBER_SIZE] = {
        0xa1, 0xb2, 0x3c, 0x4d
    };
    static const uint8_t pcap_nsec_little_endian_magic[MAGIC_NUMBER_SIZE] = {
        0x4d, 0x3c, 0xb2, 0xa1
    };
    volatile int     offset = 0;
    proto_tree      *main_tree;
    proto_item      *main_item;
    proto_tree      *header_tree;
    proto_item      *header_item;
    proto_item      *magic_number_item;
    proto_tree      *packet_tree;
    proto_item      *packet_item;
    proto_tree      *timestamp_tree;
    proto_item      *timestamp_item;
    proto_tree      *packet_data_tree;
    proto_item      *packet_data_item;
    proto_item      *capt_len_item;
    volatile uint32_t encoding;
    volatile unsigned   timestamp_scale_factor;
    const char      *magic;
    uint32_t         snap_length;
    uint32_t         captured_length;
    uint32_t         original_length;
    uint32_t         link_type;
    volatile uint32_t frame_number = 1;
    nstime_t         timestamp;

    if (tvb_memeql(tvb, 0, pcap_big_endian_magic, MAGIC_NUMBER_SIZE) == 0) {
        encoding = ENC_BIG_ENDIAN;
        timestamp_scale_factor = 1000;
        magic = "Big-endian";
    } else if (tvb_memeql(tvb, 0, pcap_little_endian_magic, MAGIC_NUMBER_SIZE) == 0) {
        encoding = ENC_LITTLE_ENDIAN;
        timestamp_scale_factor = 1000;
        magic = "Little-endian";
    } else if (tvb_memeql(tvb, 0, pcap_nsec_big_endian_magic, MAGIC_NUMBER_SIZE) == 0) {
        encoding = ENC_BIG_ENDIAN;
        timestamp_scale_factor = 1;
        magic = "Big-endian, nanosecond resolution";
    } else if (tvb_memeql(tvb, 0, pcap_nsec_little_endian_magic, MAGIC_NUMBER_SIZE) == 0) {
        encoding = ENC_LITTLE_ENDIAN;
        timestamp_scale_factor = 1;
        magic = "Little-endian, nanosecond resolution";
    } else {
        /*
         * Not one of the magic numbers we recognize.
         * XXX - add them?
         */
        return 0;
    }

    main_item = proto_tree_add_item(tree, proto_pcap, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_pcap);

    header_item = proto_tree_add_item(main_tree, hf_pcap_header    , tvb, offset, 24, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_pcap_header);

    magic_number_item = proto_tree_add_item(header_tree, hf_pcap_header_magic_number, tvb, offset, 4, ENC_NA);
    proto_item_append_text(magic_number_item, " (%s)", magic);
    offset += 4;

    proto_tree_add_item(header_tree, hf_pcap_header_version_major, tvb, offset, 2, encoding);
    offset += 2;

    proto_tree_add_item(header_tree, hf_pcap_header_version_minor, tvb, offset, 2, encoding);
    offset += 2;

    proto_tree_add_item(header_tree, hf_pcap_header_this_zone, tvb, offset, 4, encoding);
    offset += 4;

    proto_tree_add_item(header_tree, hf_pcap_header_sigfigs, tvb, offset, 4, encoding);
    offset += 4;

    proto_tree_add_item_ret_uint(header_tree, hf_pcap_header_snapshot_length, tvb, offset, 4, encoding, &snap_length);
    offset += 4;

    proto_tree_add_item(header_tree, hf_pcap_header_link_type, tvb, offset, 4, encoding);
    link_type = tvb_get_uint32(tvb, offset, encoding);
    offset += 4;

    while (offset < (int) tvb_reported_length(tvb)) {
        packet_item = proto_tree_add_item(main_tree, hf_pcap_packet, tvb, offset, 4 * 4, ENC_NA);
        packet_tree = proto_item_add_subtree(packet_item, ett_pcap_packet);
        proto_item_append_text(packet_item, " %u", frame_number);

        timestamp.secs = tvb_get_uint32(tvb, offset, encoding);
        timestamp.nsecs = tvb_get_uint32(tvb, offset + 4, encoding) * timestamp_scale_factor;

        timestamp_item = proto_tree_add_time(packet_tree, hf_pcap_packet_timestamp, tvb, offset, 8, &timestamp);
        timestamp_tree = proto_item_add_subtree(timestamp_item, ett_pcap_timestamp);

        proto_tree_add_item(timestamp_tree, hf_pcap_packet_timestamp_sec, tvb, offset, 4, encoding);
        offset += 4;

        proto_tree_add_item(timestamp_tree, hf_pcap_packet_timestamp_usec, tvb, offset, 4, encoding);
        offset += 4;

        capt_len_item = proto_tree_add_item_ret_uint(packet_tree, hf_pcap_packet_captured_length, tvb, offset, 4, encoding, &captured_length);
        offset += 4;

        proto_tree_add_item_ret_uint(packet_tree, hf_pcap_packet_original_length, tvb, offset, 4, encoding, &original_length);
        offset += 4;

        if (captured_length > snap_length)
        {
            expert_add_info(pinfo, capt_len_item,
                    &ei_pcap_capt_larger_than_snap);
        }

        if (captured_length > original_length) {
            expert_add_info(pinfo, capt_len_item,
                    &ei_pcap_capt_larger_than_orig);
            break;
        }

        packet_data_item = proto_tree_add_item(packet_tree, hf_pcap_packet_data, tvb, offset, captured_length, ENC_NA);
        packet_data_tree = proto_item_add_subtree(packet_data_item, ett_pcap_packet_data);

        pinfo->num = frame_number;
        pinfo->abs_ts = timestamp;

        if (pref_dissect_next_layer) {
            TRY {
                call_dissector_with_data(pcap_pktdata_handle, tvb_new_subset_length_caplen(tvb, offset, captured_length, original_length), pinfo, packet_data_tree, &link_type);
            }
            CATCH_BOUNDS_ERRORS {
                show_exception(tvb, pinfo, packet_data_tree, EXCEPT_CODE, GET_MESSAGE);
            }
            ENDTRY;
        }
        offset += captured_length;

        proto_item_set_len(packet_item, 4 * 4 + captured_length);
        frame_number += 1;
    }

    return offset;
}

static bool
dissect_pcap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_pcap(tvb, pinfo, tree, data) > 0;
}

void
proto_register_file_pcap(void)
{
    module_t         *module;
    expert_module_t  *expert_pcap;

    static hf_register_info hf[] = {
        { &hf_pcap_header,
            { "Header",                                    "pcap.header",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_magic_number,
            { "Magic Number",                              "pcap.header.magic_number",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_version_major,
            { "Version Major",                             "pcap.header.version.major",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_version_minor,
            { "Version Minor",                             "pcap.header.version.minor",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_this_zone,
            { "This Zone",                                 "pcap.header.this_zone",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_sigfigs,
            { "Sigfigs",                                   "pcap.header.sigfigs",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_snapshot_length,
            { "Snapshot Length",                           "pcap.header.snapshot_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_header_link_type,
            { "Link Type",                                 "pcap.header.link_type",
            FT_UINT32, BASE_DEC_HEX, VALS(link_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet,
            { "Packet",                                    "pcap.packet",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet_timestamp,
            { "Timestamp",                             "pcap.packet.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet_timestamp_sec,
            { "Timestamp sec",                             "pcap.packet.timestamp.sec",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet_timestamp_usec,
            { "Timestamp usec",                            "pcap.packet.timestamp.usec",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet_captured_length,
            { "Captured Packet Length",                    "pcap.packet.captured_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet_original_length,
            { "Original Packet Length",                    "pcap.packet.original_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pcap_packet_data,
            { "Data",                                      "pcap.packet.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_pcap_capt_larger_than_orig,
            { "pcap.capt_len_larger_than_orig_len", PI_MALFORMED, PI_ERROR,
                "captured length is larger than original length",
                EXPFILL }},
        { &ei_pcap_capt_larger_than_snap,
            { "pcap.capt_len_larger_than_snap_len", PI_PROTOCOL, PI_WARN,
                "captured length is larger than snapshot length",
                EXPFILL }}
    };

    static int *ett[] = {
        &ett_pcap,
        &ett_pcap_header,
        &ett_pcap_packet,
        &ett_pcap_packet_data,
        &ett_pcap_timestamp
    };

    proto_pcap = proto_register_protocol("PCAP File Format", "File-PCAP", "file-pcap");
    proto_register_field_array(proto_pcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pcap = expert_register_protocol(proto_pcap);
    expert_register_field_array(expert_pcap, ei, array_length(ei));

    register_dissector("file-pcap", dissect_pcap, proto_pcap);

    module = prefs_register_protocol(proto_pcap, NULL);
    prefs_register_static_text_preference(module, "version",
            "PCAP version: >=2.4",
            "Version of file-format supported by this dissector.");

    prefs_register_bool_preference(module, "dissect_next_layer",
            "Dissect next layer",
            "Dissect next layer",
            &pref_dissect_next_layer);
}

void
proto_reg_handoff_file_pcap(void)
{
    heur_dissector_add("wtap_file", dissect_pcap_heur, "PCAP File", "pcap_wtap", proto_pcap, HEURISTIC_ENABLE);
    pcap_pktdata_handle = find_dissector_add_dependency("pcap_pktdata", proto_pcap);
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
