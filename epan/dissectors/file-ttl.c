/* file-ttl.c
 *
 * TTX Logger (TTL) file format from TTTech Computertechnik AG dissector by
 * Giovanni Musto <giovanni.musto@italdesign.it>
 * Copyright 2024-2026 Giovanni Musto
 *
 * This dissector allows to parse TTL files.
 * You can find the PDF with the documentation of the format at
 * https://servicearea.tttech-auto.com/ (registration and approval required).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tvbuff.h>

#include <wiretap/ttl.h>

static int proto_file_ttl;

static dissector_handle_t ttl_handle;
static dissector_handle_t xml_handle;

static int hf_ttl_header;
static int hf_ttl_header_magic;
static int hf_ttl_header_file_format_version;
static int hf_ttl_header_block_size;
static int hf_ttl_header_header_size;
static int hf_ttl_header_logfile_info;

static int hf_ttl_header_logfile_info_logger_sn;
static int hf_ttl_header_logfile_info_logger_sw_version;
static int hf_ttl_header_logfile_info_measurement_creation_date;
static int hf_ttl_header_logfile_info_measurement_creation_timestamp;
static int hf_ttl_header_logfile_info_supplier_name;
static int hf_ttl_header_logfile_info_description;
static int hf_ttl_header_logfile_info_hw_version;
static int hf_ttl_header_logfile_info_configuration_file_name;
static int hf_ttl_header_logfile_info_tracefile_sorted;
static int hf_ttl_header_logfile_info_tracefile_split_index;
static int hf_ttl_header_logfile_info_completion_date;
static int hf_ttl_header_logfile_info_completion_timestamp;
static int hf_ttl_header_logfile_info_tc_sw_bootloader_version;
static int hf_ttl_header_logfile_info_tc_sw_firmware_version;
static int hf_ttl_header_logfile_info_most25_fw_version;
static int hf_ttl_header_logfile_info_most150_fw_version;
static int hf_ttl_header_logfile_info_split_file_creation_date;
static int hf_ttl_header_logfile_info_split_file_creation_timestamp;
static int hf_ttl_header_logfile_info_unused_bytes;
static int hf_ttl_header_logfile_info_sleep_counter;
static int hf_ttl_header_logfile_info_reserved_bytes;
static int hf_ttl_header_configuration;

static int hf_ttl_trace_data;
static int hf_ttl_block;

static expert_field ei_ttl_block_size_too_short;
static expert_field ei_ttl_header_size_too_short;
static expert_field ei_ttl_header_size_implausible;
static expert_field ei_ttl_header_logfile_info_too_short;

static int ett_ttl;
static int ett_ttl_header;
static int ett_ttl_header_logfile_info;
static int ett_ttl_header_configuration;
static int ett_ttl_trace_data;
static int ett_ttl_block;

static const value_string hf_ttl_header_logfile_info_tracefile_sorted_vals[] = {
    { '0',  "Not Sorted" },
    { '1',  "Sorted" },
    { 0, NULL }
};

void proto_register_file_ttl(void);
void proto_reg_handoff_file_ttl(void);

#define TTL_MAGIC_SIZE 4
static const uint8_t ttl_magic[TTL_MAGIC_SIZE] = { 'T', 'T', 'L', ' ' };

static proto_item*
dissect_ttl_sw_version(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int length) {
    uint8_t             major, minor, build, patch;
    header_field_info*  hfinfo;

    major = tvb_get_uint8(tvb, offset);
    minor = tvb_get_uint8(tvb, offset + 1);
    build = tvb_get_uint8(tvb, offset + 2);
    patch = tvb_get_uint8(tvb, offset + 3);

    hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d.%d.%d",
        hfinfo->name, major, minor, build, patch);
}

static proto_item*
dissect_ttl_hw_version(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int length) {
    uint16_t            major, minor;
    header_field_info*  hfinfo;

    major = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    minor = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);

    hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d",
        hfinfo->name, major, minor);
}

static proto_item*
dissect_ttl_tc_sw_version(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int length) {
    uint8_t             major, minor;
    header_field_info*  hfinfo;

    major = tvb_get_uint8(tvb, offset);
    minor = tvb_get_uint8(tvb, offset + 1);

    hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d",
        hfinfo->name, major, minor);
}

static int
dissect_ttl_logfile_information(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset) {
    int orig_offset = offset;

    proto_tree_add_item(tree, hf_ttl_header_logfile_info_logger_sn, tvb, offset, 20, ENC_NA);
    offset += 20;
    dissect_ttl_sw_version(tree, hf_ttl_header_logfile_info_logger_sw_version, tvb, offset, 4);
    offset += 4;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_measurement_creation_date, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_time_item(tree, hf_ttl_header_logfile_info_measurement_creation_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, NULL, NULL, NULL);
    offset += 8;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_supplier_name, tvb, offset, 28, ENC_NA);
    offset += 28;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_description, tvb, offset, 128, ENC_NA);
    offset += 128;
    dissect_ttl_hw_version(tree, hf_ttl_header_logfile_info_hw_version, tvb, offset, 4);
    offset += 4;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_configuration_file_name, tvb, offset, 64, ENC_NA);
    offset += 64;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_tracefile_sorted, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_tracefile_split_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_completion_date, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_time_item(tree, hf_ttl_header_logfile_info_completion_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, NULL, NULL, NULL);
    offset += 8;
    dissect_ttl_tc_sw_version(tree, hf_ttl_header_logfile_info_tc_sw_bootloader_version, tvb, offset, 2);
    offset += 2;
    dissect_ttl_tc_sw_version(tree, hf_ttl_header_logfile_info_tc_sw_firmware_version, tvb, offset, 2);
    offset += 2;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_most25_fw_version, tvb, offset, 32, ENC_NA);
    offset += 32;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_most150_fw_version, tvb, offset, 32, ENC_NA);
    offset += 32;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_split_file_creation_date, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_time_item(tree, hf_ttl_header_logfile_info_split_file_creation_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, NULL, NULL, NULL);
    offset += 8;
    proto_tree_add_bytes_item(tree, hf_ttl_header_logfile_info_unused_bytes, tvb, offset, 512, ENC_NA, NULL, NULL, NULL);
    offset += 512;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_sleep_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bytes_item(tree, hf_ttl_header_logfile_info_reserved_bytes, tvb, offset, 3161, ENC_NA, NULL, NULL, NULL);
    offset += 3161;

    return offset - orig_offset;
}

static int
dissect_ttl_block(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int size) {
    proto_tree* block_subtree;
    proto_item* ti;
    tvbuff_t* new_tvb;
    int orig_offset = offset;
    int dissected;

    if (size > 0) {
        ti = proto_tree_add_item(tree, hf_ttl_block, tvb, offset, size, ENC_NA);
        block_subtree = proto_item_add_subtree(ti, ett_ttl_block);

        if (ttl_handle) {
            while (size >= (int)sizeof(ttl_entryheader_t)) {
                new_tvb = tvb_new_subset_length(tvb, offset, size);
                dissected = call_dissector(ttl_handle, new_tvb, pinfo, block_subtree);
                offset += dissected;
                size -= dissected;
            }
        }
    }

    return offset - orig_offset;
}

static int
dissect_file_ttl(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    unsigned        offset = 0;
    proto_tree     *ttl_tree, *header_subtree, *logfile_info_subtree, *configuration_subtree, *trace_data_subtree;
    proto_item*     ti;
    uint32_t        format_version, header_length, block_size;
    unsigned        logfile_info_length, xml_length, remaining;

    if (tvb_captured_length(tvb) < sizeof(ttl_fileheader_t) || tvb_memeql(tvb, 0, ttl_magic, TTL_MAGIC_SIZE) != 0) {
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_file_ttl, tvb, offset, -1, ENC_NA);
    ttl_tree = proto_item_add_subtree(ti, ett_ttl);
    header_length = tvb_get_uint32(tvb, 12, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(ttl_tree, hf_ttl_header, tvb, offset, header_length, ENC_NA);
    header_subtree = proto_item_add_subtree(ti, ett_ttl_header);

    proto_tree_add_item(header_subtree, hf_ttl_header_magic, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item_ret_uint(header_subtree, hf_ttl_header_file_format_version, tvb, offset, 4, ENC_LITTLE_ENDIAN, &format_version);
    offset += 4;
    ti = proto_tree_add_item_ret_uint(header_subtree, hf_ttl_header_block_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &block_size);
    offset += 4;
    if (block_size == 0) {
        expert_add_info(pinfo, ti, &ei_ttl_block_size_too_short);
    }
    ti = proto_tree_add_item(header_subtree, hf_ttl_header_header_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (header_length < sizeof(ttl_fileheader_t)) {
        expert_add_info(pinfo, ti, &ei_ttl_header_size_too_short);
    }
    else if (header_length > INT32_MAX) {
        expert_add_info(pinfo, ti, &ei_ttl_header_size_implausible);
    }
    else {
        logfile_info_length = MIN(MIN(tvb_captured_length_remaining(tvb, offset), header_length - offset), TTL_LOGFILE_INFO_SIZE);
        ti = proto_tree_add_item(header_subtree, hf_ttl_header_logfile_info, tvb, offset, logfile_info_length, ENC_NA);
        logfile_info_subtree = proto_item_add_subtree(ti, ett_ttl_header_logfile_info);

        if ((logfile_info_length < TTL_LOGFILE_INFO_SIZE) && format_version >= 10) {
            /* Starting from format version 10, the header is at least TTL_LOGFILE_INFO_SIZE bytes */
            expert_add_info(pinfo, ti, &ei_ttl_header_logfile_info_too_short);
        }

        offset += dissect_ttl_logfile_information(tvb, pinfo, logfile_info_subtree, offset);

        if (format_version >= 10 && header_length > offset) {
            xml_length = MIN(tvb_captured_length_remaining(tvb, offset), header_length - offset);
            ti = proto_tree_add_item(header_subtree, hf_ttl_header_configuration, tvb, offset, xml_length, ENC_NA);

            if (xml_handle) {
                configuration_subtree = proto_item_add_subtree(ti, ett_ttl_header_configuration);
                tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, xml_length);
                call_dissector(xml_handle, new_tvb, pinfo, configuration_subtree);
            }
        }

        offset = header_length;

        ti = proto_tree_add_item(ttl_tree, hf_ttl_trace_data, tvb, offset, -1, ENC_NA);
        trace_data_subtree = proto_item_add_subtree(ti, ett_ttl_trace_data);

        if (block_size != 0) {
            while ((remaining = tvb_captured_length_remaining(tvb, offset)) > 0) {
                dissect_ttl_block(tvb, pinfo, trace_data_subtree, offset, MIN(block_size, remaining));
                offset += block_size;
            }
        }

    }

    return offset;
}

static bool
dissect_file_ttl_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
    return dissect_file_ttl(tvb, pinfo, tree, data) > 0;
}

void
proto_register_file_ttl(void) {
    expert_module_t* expert_file_ttl;

    static hf_register_info hf[] = {
        { &hf_ttl_header,
            { "Header Section", "ttl.header", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_magic,
            { "Magic", "ttl.header.magic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_file_format_version,
            { "File Format Version", "ttl.header.version", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_block_size,
            { "Block Size", "ttl.header.block_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_header_size,
            { "Header Size", "ttl.header.header_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info,
            { "Logfile Information", "ttl.header.logfile_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ttl_header_logfile_info_logger_sn,
            { "Logger Serial Number", "ttl.header.logfile_info.logger_sn", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_logger_sw_version,
            { "Logger Software Version", "ttl.header.logfile_info.logger_sw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_measurement_creation_date,
            { "Measurement Creation Date", "ttl.header.logfile_info.measurement_creation_date", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_measurement_creation_timestamp,
            { "Measurement Creation Timestamp", "ttl.header.logfile_info.measurement_creation_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_supplier_name,
            { "Supplier Name", "ttl.header.logfile_info.supplier_name", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_description,
            { "Description", "ttl.header.logfile_info.description", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_hw_version,
            { "Hardware Version", "ttl.header.logfile_info.hw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_configuration_file_name,
            { "Configuration File Name", "ttl.header.logfile_info.config_filename", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_tracefile_sorted,
            { "Tracefile Sorted", "ttl.header.logfile_info.tracefile_sorted", FT_UINT8, BASE_HEX, VALS(hf_ttl_header_logfile_info_tracefile_sorted_vals), 0x0, NULL, HFILL} },
        { &hf_ttl_header_logfile_info_tracefile_split_index,
            { "Tracefile Split Index", "ttl.header.logfile_info.tracefile_split_index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_completion_date,
            { "Completion Date", "ttl.header.logfile_info.completion_date", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_completion_timestamp,
            { "Completion Timestamp", "ttl.header.logfile_info.completion_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_tc_sw_bootloader_version,
            { "TC SW Bootloader Version", "ttl.header.logfile_info.tc_sw_bootloader_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_tc_sw_firmware_version,
            { "TC SW Firmware Version", "ttl.header.logfile_info.tc_sw_firmware_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_most25_fw_version,
            { "MOST25 Piggy Firmware Version", "ttl.header.logfile_info.most25_fw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_most150_fw_version,
            { "MOST150 Piggy Firmware Version", "ttl.header.logfile_info.most150_fw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_split_file_creation_date,
            { "Split File Creation Date", "ttl.header.logfile_info.split_file_creation_date", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_split_file_creation_timestamp,
            { "Split File Creation Timestamp", "ttl.header.logfile_info.split_file_creation_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_unused_bytes,
            { "Unused Bytes", "ttl.header.logfile_info.unused", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_sleep_counter,
            { "Sleep Counter", "ttl.header.logfile_info.sleep_counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_reserved_bytes,
            { "Reserved Bytes", "ttl.header.logfile_info.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_configuration,
            { "Configuration", "ttl.header.configuration", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ttl_trace_data,
            { "Trace Data Section", "ttl.trace_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_block,
            { "Trace Data Block", "ttl.trace_data_block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static ei_register_info ei[] = {
        { &ei_ttl_block_size_too_short,
            { "ttl.block_size_too_short", PI_MALFORMED, PI_ERROR,
                "block size is too short",
                EXPFILL }},
        { &ei_ttl_header_size_too_short,
            { "ttl.header_size_too_short", PI_MALFORMED, PI_ERROR,
                "header size is too short",
                EXPFILL }},
        { &ei_ttl_header_size_implausible,
            { "ttl.header_size_implausible", PI_MALFORMED, PI_ERROR,
                "header size is implausible",
                EXPFILL }},
        { &ei_ttl_header_logfile_info_too_short,
            { "ttl.header.logfile_info_too_short", PI_MALFORMED, PI_ERROR,
                "logfile info is too short",
                EXPFILL }},
    };

    static int* ett[] = {
        &ett_ttl,
        &ett_ttl_header,
        &ett_ttl_header_logfile_info,
        &ett_ttl_header_configuration,
        &ett_ttl_trace_data,
        &ett_ttl_block,
    };

    proto_file_ttl = proto_register_protocol("TTL File Format", "File-TTL", "file-ttl");
    expert_file_ttl = expert_register_protocol(proto_file_ttl);
    expert_register_field_array(expert_file_ttl, ei, array_length(ei));

    proto_register_field_array(proto_file_ttl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("file-ttl", dissect_file_ttl, proto_file_ttl);
}

void
proto_reg_handoff_file_ttl(void) {
    heur_dissector_add("wtap_file", dissect_file_ttl_heur, "TTL File", "ttl_wtap", proto_file_ttl, HEURISTIC_ENABLE);
    ttl_handle = find_dissector_add_dependency("ttl", proto_file_ttl);
    xml_handle = find_dissector_add_dependency("xml", proto_file_ttl);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
