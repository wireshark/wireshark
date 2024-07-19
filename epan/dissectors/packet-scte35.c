/* packet-scte35.c
 * Routines for SCTE-35 dissection
 * Author: Ben Stewart <bst[at]google.com>
 * Copyright 2016 Google Inc.
 *
 * The SCTE-35 protocol is described by the Society of Cable Telecommunications
 * Engineers at <https://www.scte.org/documents/pdf/Standards/Top%20Ten/ANSI_SCTE%2035%202013.pdf>.
 *
 * This module implements a dissector for the main table in a SCTE-35 message, a
 * splice_info_section. This payload is carried in a MPEG Section Table with a
 * table ID of 0xFC. PIDs carrying this sort of table are also noted in the PMT
 * with a stream type of 0x86, and a registration descriptor with fourcc 'CUEI'.
 *
 * The various splice command types are implemented in separate modules, and are
 * linked to this dissector through the field scte35.splice_command_type. All
 * field names follow the conventions documented in the SCTE35 specification.
 *
 * This dissector does not support encrypted SCTE35 messages, other than
 * indicating through the scte35.encrypted_packet flag.
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#define SCTE35_CMD_SPLICE_NULL (0x00)
#define SCTE35_CMD_SPLICE_SCHEDULE (0x04)
#define SCTE35_CMD_SPLICE_INSERT (0x05)
#define SCTE35_CMD_TIME_SIGNAL (0x06)
#define SCTE35_CMD_BANDWIDTH_RESERVATION (0x07)
#define SCTE35_CMD_PRIVATE_COMMAND (0xff)

#define SCTE35_AVAIL_DESCRIPTOR (0x00)
#define SCTE35_DTMF_DESCRIPTOR (0x01)
#define SCTE35_SEGMENTATION_DESCRIPTOR (0x02)

void proto_register_scte35(void);
void proto_register_scte35_private_command(void);
void proto_register_scte35_splice_insert(void);
void proto_register_scte35_splice_schedule(void);
void proto_register_scte35_time_signal(void);
void proto_reg_handoff_scte35(void);
void proto_reg_handoff_scte35_private_command(void);
void proto_reg_handoff_scte35_splice_insert(void);
void proto_reg_handoff_scte35_splice_schedule(void);
void proto_reg_handoff_scte35_time_signal(void);

/* MPEG Section Table ID for a SCTE35 splice_info_section. */
static const unsigned char SCTE35_TABLE_ID = 0xFCU;

/* Minimum length for a splice_info_section, excluding any splice commands,
 * splice descriptors, encrypted CRC or alignment stuffing.
 */
static const int SCTE35_SI_MIN_LEN = 20;

/* Protocol handle */
static int proto_scte35;

/* Dissector table for scte35.splice_command_type */
static dissector_table_t scte35_cmd_dissector_table;


/* splice_info_section table */
static int ett_scte35_splice_info_section;

/* splice_info_section fields */
static int hf_table_id;
static int hf_section_syntax_indicator;
static int hf_private_indicator;
static int hf_reserved;
static int hf_section_length;
static int hf_protocol_version;
static int hf_encrypted_packet;
static int hf_encryption_algorithm;
static int hf_pts_adjustment;
static int hf_cw_index;
static int hf_tier;
static int hf_splice_command_length;
static int hf_splice_command_type;
static int hf_descriptor_loop_length;
static int hf_splice_descriptor_tag;
static int hf_splice_descriptor_length;
static int hf_splice_descriptor_identifier;
static int hf_descriptor_provider_avail_id;
static int hf_descriptor_preroll;
static int hf_descriptor_dtmf_count;
static int hf_descriptor_dtmf_reserved;
static int hf_descriptor_dtmf;
static int hf_descriptor_event_id;
static int hf_descriptor_cancel_indicator;
static int hf_descriptor_reserved0;
static int hf_descriptor_psf;
static int hf_descriptor_segmentation_duration_flag;
static int hf_descriptor_delivery_not_restricted_flag;
static int hf_descriptor_web_delivery_allowed_flag;
static int hf_descriptor_no_regional_blackout_flag;
static int hf_descriptor_archive_allow_flag;
static int hf_descriptor_device_restrictions;
static int hf_descriptor_reserved1;
static int hf_descriptor_component_count;
static int hf_descriptor_component_tag;
static int hf_descriptor_component_reserved;
static int hf_descriptor_component_pts_offset;
static int hf_descriptor_segmentation_duration;
static int hf_descriptor_segmentation_upid_type;
static int hf_descriptor_segmentation_upid_length;
static int hf_descriptor_segmentation_upid;
static int hf_descriptor_segmentation_type_id;
static int hf_descriptor_segment_num;
static int hf_descriptor_segments_expected;
static int hf_e_crc32;
static int hf_crc32;

/* time_signal protocol and fields */
static int proto_scte35_time;
static int ett_scte35_time_signal;
static int ett_scte35_time_signal_splice_time;
static int hf_time_specified;
static int hf_time_reserved;
static int hf_time_pts;

/* private_command protocol and fields */
static int proto_private_command;
static int ett_private_command;
static int hf_identifier;
static int hf_private_byte;

/* Dissector table for scte35_private_command.identifier */
static dissector_table_t private_identifier_table;

static dissector_handle_t scte35_handle;
static dissector_handle_t scte35_time_handle;
static dissector_handle_t scte35_private_command_handle;
static dissector_handle_t scte35_si_handle;
static dissector_handle_t scte35_ss_handle;

/* splice_insert protocol and fields */
static int proto_scte35_si;
static int ett_scte35_splice_insert;
static int hf_splice_insert_event_id;
static int hf_splice_cancel_indicator;
static int hf_reserved0;
static int hf_out_of_network_indicator;
static int hf_program_splice_flag;
static int hf_duration_flag;
static int hf_splice_immediate_flag;
static int hf_reserved1;
static int hf_splice_time_specified_flag;
static int hf_splice_time_reserved;
static int hf_splice_time_pts_time;
static int hf_component_count;
static int hf_component_tag;
static int hf_component_splice_time_tsf;
static int hf_component_splice_time_reserved;
static int hf_component_splice_time_pts_time;
static int hf_break_duration_auto_return;
static int hf_break_duration_reserved;
static int hf_break_duration_duration;
static int hf_unique_program_id;
static int hf_avail_num;
static int hf_avails_expected;

/* splice_schedule protocol and fields */
static int proto_scte35_splice_schedule;
static int ett_scte35_splice_schedule;
static int hf_splice_count;
static int hf_splice_event_id;
static int hf_splice_event_cancel_indicator;
static int hf_splice_reserved0;
static int hf_splice_out_of_network;
static int hf_splice_program_splice_flag;
static int hf_splice_duration_flag;
static int hf_splice_reserved1;
static int hf_splice_utc_splice_time;
static int hf_splice_component_count;
static int hf_splice_component_tag;
static int hf_splice_component_utc_splice_time;
static int hf_splice_break_duration_auto_return;
static int hf_splice_break_duration_reserved;
static int hf_splice_break_duration_duration;
static int hf_splice_unique_program_id;
static int hf_splice_avail_num;
static int hf_splice_avails_expected;

static const true_false_string tfs_section_syntax_indicator = {
    "Reserved", "MPEG short sections in use"};

static const true_false_string tfs_private_indicator = {
    "Reserved", "Mandatory value"};

static const true_false_string tfs_encrypted_packet = {
    "Encrypted data", "Cleartext"};

static const true_false_string tfs_descriptor_cancel_indicator = {
    "Cancel Request", "New or existing event"};

static const true_false_string tfs_descriptor_psf = {
    "All PIDs to be spliced", "Component Splice Mode"};

static const true_false_string tfs_descriptor_sdf = {
    "Segmentation duration present", "No duration present"};

static const true_false_string tfs_descriptor_dnr = {
    "No delivery restrictions", "Restricted delivery"};

static const true_false_string tfs_descriptor_web = {
    "Permitted", "Restricted"};

static const true_false_string tfs_descriptor_blackout = {
    "No regional blackouts", "Regional restrictions"};

static const true_false_string tfs_descriptor_archive = {
    "No recording restrictions", "Recording is restricted"};

static const range_string rv_splice_command_type[] = {
    { SCTE35_CMD_SPLICE_NULL, SCTE35_CMD_SPLICE_NULL, "splice_null" },
    { 0x01, 0x03, "Reserved" },
    { SCTE35_CMD_SPLICE_SCHEDULE, SCTE35_CMD_SPLICE_SCHEDULE, "splice_schedule" },
    { SCTE35_CMD_SPLICE_INSERT, SCTE35_CMD_SPLICE_INSERT, "splice_insert" },
    { SCTE35_CMD_TIME_SIGNAL, SCTE35_CMD_TIME_SIGNAL, "time_signal" },
    { SCTE35_CMD_BANDWIDTH_RESERVATION, SCTE35_CMD_BANDWIDTH_RESERVATION, "bandwidth_reservation" },
    { 0x08, 0xfe, "Reserved" },
    { SCTE35_CMD_PRIVATE_COMMAND, SCTE35_CMD_PRIVATE_COMMAND, "private_command" },
    {    0,    0, NULL }
};

static const range_string rv_splice_descriptor_tag[] = {
    { SCTE35_AVAIL_DESCRIPTOR,        SCTE35_AVAIL_DESCRIPTOR,        "avail_descriptor" },
    { SCTE35_DTMF_DESCRIPTOR,         SCTE35_DTMF_DESCRIPTOR,         "DTMF_descriptor" },
    { SCTE35_SEGMENTATION_DESCRIPTOR, SCTE35_SEGMENTATION_DESCRIPTOR, "segmentation_descriptor" },
    { 0x03, 0xff, "Reserved" },
    {    0,    0, NULL }
};

static const range_string scte35_device_restrictions[] = {
    { 0x00, 0x00, "Restrict Group 0" },
    { 0x01, 0x01, "Restrict Group 1" },
    { 0x02, 0x02, "Restrict Group 2" },
    { 0x03, 0x03, "No Restrictions" },
    {    0,    0, NULL }
};

static const range_string scte35_segmentation_upid_type[] = {
    { 0x00, 0x00, "Not Used" },
    { 0x01, 0x01, "User Defined (deprecated)" },
    { 0x02, 0x02, "ISCI" },
    { 0x03, 0x03, "Ad-ID" },
    { 0x04, 0x04, "UMID (SMPTE 330M)" },
    { 0x05, 0x05, "ISAN" },
    { 0x06, 0x06, "Versioned ISAN" },
    { 0x07, 0x07, "Tribune TID" },
    { 0x08, 0x08, "Turner Identifier" },
    { 0x09, 0x09, "CableLabs ADI Identifier" },
    { 0x0a, 0x0a, "EIDR" },
    { 0x0b, 0x0b, "ATSC A57/B Content Identifier" },
    { 0x0c, 0x0c, "Managed Private UPID" },
    { 0x0d, 0x0d, "Multiple UPIDs" },
    { 0x0e, 0xff, "Reserved" },
    {    0,    0, NULL }
};

static const range_string scte35_segmentation_type_id[] = {
    { 0x00, 0x00, "Not Indicated" },
    { 0x01, 0x01, "Content Identification" },
    { 0x10, 0x10, "Program Start" },
    { 0x11, 0x11, "Program End" },
    { 0x12, 0x12, "Program Early Termination" },
    { 0x13, 0x13, "Program Breakaway" },
    { 0x14, 0x14, "Program Resumption" },
    { 0x15, 0x15, "Program Runover Planned" },
    { 0x16, 0x16, "Program Runover Unplanned" },
    { 0x17, 0x17, "Program Overlap Start" },
    { 0x20, 0x20, "Chapter Start" },
    { 0x21, 0x21, "Chapter End" },
    { 0x30, 0x30, "Provider Advertisement Start" },
    { 0x31, 0x31, "Provider Advertisement End" },
    { 0x32, 0x32, "Distributor Advertisement Start" },
    { 0x33, 0x33, "Distributor Advertisement End" },
    { 0x34, 0x34, "Placement Opportunity Start" },
    { 0x35, 0x35, "Placement Opportunity End" },
    { 0x40, 0x40, "Unscheduled Event Start" },
    { 0x41, 0x41, "Unscheduled Event End" },
    {    0,    0, NULL }
};

static const range_string rv_encryption_algorithm[] = {
    { 0x00, 0x00, "No encryption"},
    { 0x01, 0x01, "DES - ECB mode"},
    { 0x02, 0x02, "DES - CBC mode"},
    { 0x03, 0x03, "Triple DES EDE3 - ECB mode"},
    { 0x04, 0x1F, "Reserved"},
    { 0x20, 0x3F, "User private"},
    {    0,    0, NULL }
};


/* time_signal dissector */
static int
dissect_scte35_time_signal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int tvb_len, min_length = 1, offset = 0;
    uint8_t time_specified_flag;
    proto_item *ti;
    proto_tree *time_tree;

    /* Check packet length. */
    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < min_length)
        return 0;

    time_specified_flag = tvb_get_uint8(tvb, offset) & 0x80;
    if (time_specified_flag)
        min_length += 4;
    if (tvb_len < min_length)
        return 0;

    /* Set up headers in the packet list */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Time Signal (%s)",
                 time_specified_flag ? "Future" : "Immediate");

    /* Create a subtree for the time_signal */
    ti = proto_tree_add_item(tree, proto_scte35_time, tvb, 0, -1, ENC_NA);
    time_tree = proto_item_add_subtree(ti, ett_scte35_time_signal);

    /* Parse out the fields. */
    proto_tree_add_item(time_tree, hf_time_specified, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(time_tree, hf_time_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (time_specified_flag) {
        proto_tree_add_item(time_tree, hf_time_pts, tvb, offset, 5, ENC_BIG_ENDIAN);
        offset += 4;
    }
    offset += 1;

    return offset;
}

void
proto_register_scte35_time_signal(void)
{
    static int *ett[] = {
        &ett_scte35_time_signal,
        &ett_scte35_time_signal_splice_time,
    };

    static hf_register_info hf[] = {
        {&hf_time_specified,
         {"Time Specified", "scte35_time.splice.time_specified", FT_BOOLEAN, 8,
             NULL, 0x80, NULL, HFILL}},
        {&hf_time_reserved,
         {"Reserved", "scte35_time.splice.reserved", FT_UINT8, BASE_HEX,
             NULL, 0x7E, NULL, HFILL}},
        {&hf_time_pts,
         {"PTS Time", "scte35_time.splice.pts", FT_UINT64, BASE_DEC,
             NULL, UINT64_C(0x01FFFFFFFF), NULL, HFILL}},
    };

    proto_scte35_time = proto_register_protocol("SCTE-35 Time Signal", "SCTE35 TS", "scte35_time");
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_scte35_time, hf, array_length(hf));

    /* Create a dissector for time_signal packets. */
    scte35_time_handle = register_dissector("scte35_time", dissect_scte35_time_signal, proto_scte35_time);
}

void
proto_reg_handoff_scte35_time_signal(void)
{
    dissector_add_uint("scte35.splice_command_type", SCTE35_CMD_TIME_SIGNAL, scte35_time_handle);
}


/* scte35 private_command dissector */
static int
dissect_scte35_private_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int tvb_len;
    uint32_t identifier;
    int offset = 0;
    proto_item *ti;
    proto_tree *pc_tree;

    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < 4)
        return 0;

    /* Display rudimentary header information. */
    ti = proto_tree_add_item(tree, proto_private_command, tvb, 0, -1, ENC_NA);
    pc_tree = proto_item_add_subtree(ti, ett_private_command);

    proto_tree_add_item_ret_uint(pc_tree, hf_identifier, tvb, offset, 4, ENC_BIG_ENDIAN, &identifier);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Private Command (0x%08x)", identifier);
    offset += 4;
    proto_tree_add_item(pc_tree, hf_private_byte, tvb, offset, -1, ENC_NA);

    /* Let another dissector try to decode this data. */
    dissector_try_uint(private_identifier_table, identifier, tvb, pinfo, tree);

    return tvb_len;
}

void
proto_register_scte35_private_command(void)
{
    static int *ett[] = {
        &ett_private_command,
    };

    static hf_register_info hf[] = {
        {&hf_identifier,
         {"Identifier", "scte35_private_command.identifier", FT_UINT32,
           BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_private_byte,
          {"Private Bytes", "scte35_private_command.private_byte", FT_BYTES, 0,
            NULL, 0, NULL, HFILL}},
    };

    proto_private_command = proto_register_protocol("SCTE-35 Private Command", "SCTE35 PC", "scte35_private_command");

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_private_command, hf, array_length(hf));

    /* Allow other modules to hook private commands and decode them. */
    private_identifier_table = register_dissector_table(
        "scte35_private_command.identifier", "SCTE-35 Private Command Identifier",
        proto_private_command, FT_UINT32, BASE_HEX);

    /* Create a dissector for private commands. */
    scte35_private_command_handle = register_dissector("scte35_private_command", dissect_scte35_private_command, proto_private_command);
}

void
proto_reg_handoff_scte35_private_command(void)
{
    dissector_add_uint("scte35.splice_command_type", SCTE35_CMD_PRIVATE_COMMAND, scte35_private_command_handle);
}


/* scte35 splice_insert dissector */
static int
dissect_component(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint8_t sif, int idx)
{
    int offset = 0;
    uint8_t component_tag, tsf = 0;
    proto_tree *component_tree;
    int tvb_len, min_length = sif ? 1 : 2;

    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < min_length)
        return 0;

    if (!sif) {
        /* Check whether time is present in the component. */
        tsf = tvb_get_uint8(tvb, offset + 1) & 0x80;
        if (tsf) {
            min_length += 4;
            if (tvb_len < min_length)
                return 0;
        }
    }

    /* Create a subtree for the component. */
    component_tag = tvb_get_uint8(tvb, offset);
    proto_tree_add_subtree_format(
        tree, tvb, offset, min_length, idx, &component_tree,
        "Component %d (0x%02x)", idx, component_tag);

    /* Parse out component flags. */
    proto_tree_add_item(component_tree, hf_component_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* For non-immediate splices.. */
    if (!sif) {
        proto_tree_add_item(component_tree, hf_component_splice_time_tsf, tvb,
                            offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(component_tree, hf_component_splice_time_reserved,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        /* And the PTS if present. */
        if (tsf) {
            proto_tree_add_item(component_tree, hf_component_splice_time_pts_time,
                tvb, offset, 5, ENC_BIG_ENDIAN);
            offset += 4;
        }
        offset++;
    }

    return offset;
}

static int
dissect_scte35_splice_insert(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int tvb_len, min_length = 5, dissected_length;
    uint8_t cancel_flag, psf, df, sif, tsf, component_count;
    uint32_t event_id;
    int component;
    int offset = 0;
    proto_item *ti;
    proto_tree *si_tree, *st_tree;

    static int * const new_event_fields[] = {
        &hf_out_of_network_indicator,
        &hf_program_splice_flag,
        &hf_duration_flag,
        &hf_splice_immediate_flag,
        &hf_reserved1,
        NULL
    };

    /* Check with no optional subfields */
    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < min_length)
        return 0;

    cancel_flag = tvb_get_uint8(tvb, offset + 4) & 0x80;
    event_id = tvb_get_ntohl(tvb, 0);

    if (!cancel_flag) {
        min_length += 5;
        if (tvb_len < min_length)
            return 0;
    }

    /* Set up headers in the packet list */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Splice %s Event 0x%08x",
                 cancel_flag ? "Cancellation" : "Insertion", event_id);

    /* Create a root tree element for the splice_insert protocol. */
    ti = proto_tree_add_item(tree, proto_scte35_si, tvb, 0, -1, ENC_NA);
    si_tree = proto_item_add_subtree(ti, ett_scte35_splice_insert);

    /* Parse header fields */
    proto_tree_add_item(si_tree, hf_splice_insert_event_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(si_tree, hf_splice_cancel_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(si_tree, hf_reserved0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Check for a new event. */
    if (!cancel_flag) {

        /* Parse out the 'new event' fields. */
        psf = tvb_get_uint8(tvb, offset) & 0x40;
        df = tvb_get_uint8(tvb, offset) & 0x20;
        sif = tvb_get_uint8(tvb, offset) & 0x10;

        proto_tree_add_bitmask_list(si_tree, tvb, offset, 1, new_event_fields, ENC_BIG_ENDIAN);
        offset++;

        /* Parse out the program-level splice fields. */
        if (psf && !sif) {
            min_length += 1;
            if (tvb_len < min_length)
                return offset;

            tsf = tvb_get_bits8(tvb, offset * 8, 1);
            proto_tree_add_subtree(si_tree, tvb, offset, tsf ? 5 : 1, 0, &st_tree, "Program Splice Time");
            proto_tree_add_item(st_tree, hf_splice_time_specified_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(st_tree, hf_splice_time_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);

            /* If a time is specified, display it too. */
            if (tsf) {
                min_length += 4;
                if (tvb_len < min_length)
                    return offset;

                proto_tree_add_item(st_tree, hf_splice_time_pts_time, tvb, offset, 5, ENC_BIG_ENDIAN);
                offset += 4;
            }
            offset++;
        }

        /* For component-level splices, parse the component table. */
        if (!psf) {
            min_length += 1;
            if (tvb_len < min_length)
                return offset;

            component_count = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(si_tree, hf_component_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            min_length += component_count * (sif ? 1 : 2);
            if (tvb_len < min_length)
                return offset;

            /* Dissect each splice component. */
            for (component = 0; component < component_count; ++component) {
                dissected_length = dissect_component(
                    tvb_new_subset_remaining(tvb, offset),
                    pinfo, si_tree, sif, component);

                /* Propagate failures. */
                if (dissected_length < 1)
                    return offset;
                offset += dissected_length;
            }
        }

        /* If present, parse out the duration field. */
        if (df) {
            min_length += 5;
            if (tvb_len < min_length)
                return offset;

            proto_tree_add_item(si_tree, hf_break_duration_auto_return, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(si_tree, hf_break_duration_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(si_tree, hf_break_duration_duration, tvb, offset, 5, ENC_BIG_ENDIAN);
            offset += 5;
        }

        /* Parse the UPID and avails fields. */
        proto_tree_add_item(si_tree, hf_unique_program_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(si_tree, hf_avail_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(si_tree, hf_avails_expected, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    return offset;
}

void
proto_register_scte35_splice_insert(void)
{
    static hf_register_info hf[] = {
        {&hf_splice_insert_event_id,
         {"Event ID", "scte35_si.event_id", FT_UINT32, BASE_HEX,
             NULL, 0, NULL, HFILL}},
        {&hf_splice_cancel_indicator,
         {"Cancelled", "scte35_si.cancelled", FT_BOOLEAN, 8,
             NULL, 0x80, NULL, HFILL}},
        {&hf_reserved0,
         {"Reserved", "scte35_si.reserved0", FT_UINT8, 1,
             NULL, 0x7F, NULL, HFILL}},
        {&hf_out_of_network_indicator,
         {"Out of Network", "scte35_si.out_of_net", FT_BOOLEAN, 8,
             NULL, 0x80, NULL, HFILL}},
        {&hf_program_splice_flag,
         {"Program Splice Point", "scte35_si.psf", FT_BOOLEAN, 8,
             NULL, 0x40, NULL, HFILL}},
        {&hf_duration_flag,
         {"Duration Present", "scte35_si.duration_flag", FT_BOOLEAN, 8,
             NULL, 0x20, NULL, HFILL}},
        {&hf_splice_immediate_flag,
         {"Splice Immediate", "scte35_si.splice_immediate", FT_BOOLEAN, 8,
             NULL, 0x10, NULL, HFILL}},
        {&hf_reserved1,
         {"Reserved", "scte35_si.reserved1", FT_UINT8, 1,
             NULL, 0x0f, NULL, HFILL}},
        {&hf_splice_time_specified_flag,
         {"Time Specified", "scte35_si.splice_time.time_specified", FT_BOOLEAN,
             8, NULL, 0x80, NULL, HFILL}},
        {&hf_splice_time_reserved,
         {"Reserved", "scte35_si.splice_time.reserved", FT_UINT8, 1,
             NULL, 0x7E, NULL, HFILL}},
        {&hf_splice_time_pts_time,
         {"PTS Time", "scte35_si.splice_time.pts", FT_UINT64, 5,
             NULL, UINT64_C(0x1FFFFFFFF), NULL, HFILL}},
        {&hf_component_count,
         {"Component Count", "scte35_si.component_count", FT_UINT8, BASE_DEC,
             NULL, 0, NULL, HFILL}},
        {&hf_component_tag,
         {"Component Tag", "scte35_si.component.tag", FT_UINT8, BASE_HEX,
             NULL, 0, NULL, HFILL}},
        {&hf_component_splice_time_tsf,
         {"Time Specified", "scte35_si.component.time_specified", FT_BOOLEAN, 8,
             NULL, 0x80, NULL, HFILL}},
        {&hf_component_splice_time_reserved,
         {"Reserved", "scte35_si.component.reserved", FT_UINT8, 1,
             NULL, 0x7E, NULL, HFILL}},
        {&hf_component_splice_time_pts_time,
         {"PTS Time", "scte35_si.component.pts", FT_UINT64, 5,
             NULL, UINT64_C(0x1FFFFFFFF), NULL, HFILL}},
        {&hf_break_duration_auto_return,
         {"Auto Return", "scte35_si.break.auto_return", FT_BOOLEAN, 8,
             NULL, 0x80, NULL, HFILL}},
        {&hf_break_duration_reserved,
         {"Reserved", "scte35_si.break.reserved", FT_UINT8, 1,
             NULL, 0x7E, NULL, HFILL}},
        {&hf_break_duration_duration,
         {"Duration", "scte35_si.break.duration", FT_UINT64, 5,
             NULL, UINT64_C(0x1FFFFFFFF), NULL, HFILL}},
        {&hf_unique_program_id,
         {"Unique Program ID", "scte35_si.upid", FT_UINT16, BASE_HEX,
             NULL, 0, NULL, HFILL}},
        {&hf_avail_num,
         {"Avail Number", "scte35_si.avail", FT_UINT8, BASE_DEC,
             NULL, 0, NULL, HFILL}},
        {&hf_avails_expected,
         {"Avails Expected", "scte35_si.avails_expected", FT_UINT8, BASE_DEC,
             NULL, 0, NULL, HFILL}},
    };

    static int *ett[] = {
        &ett_scte35_splice_insert,
    };

    proto_scte35_si = proto_register_protocol("SCTE-35 Splice Insert", "SCTE35 SI", "scte35_si");

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_scte35_si, hf, array_length(hf));

    /* Create a splice_insert dissector. */
    scte35_si_handle = register_dissector("scte35_si", dissect_scte35_splice_insert, proto_scte35_si);
}

void
proto_reg_handoff_scte35_splice_insert(void)
{
    dissector_add_uint("scte35.splice_command_type", SCTE35_CMD_SPLICE_INSERT, scte35_si_handle);
}


/* scte35 splice_schedule dissector */
static int
dissect_scte35_splice_schedule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int tvb_len, min_length = 1;
    uint8_t splice_count, cancel_flag, psf, df, component_count;
    int component, splice;
    int offset = 0, splice_length;
    proto_item *ti;
    proto_tree *ss_tree, *sp_tree, *component_tree;

    static int * const splice_event_flags[] = {
        &hf_splice_out_of_network,
        &hf_splice_program_splice_flag,
        &hf_splice_duration_flag,
        &hf_splice_reserved1,
        NULL
    };

    /* Check with no optional subfields */
    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < min_length)
        return 0;

    /* Set up headers in the packet list */
    splice_count = tvb_get_uint8(tvb, 0);
    min_length += splice_count * 5;
    if (tvb_len < min_length)
        return 0;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Splice Schedule (%d splices)", splice_count);

    /* Create the root of the dissection */
    ti = proto_tree_add_item(tree, proto_scte35_splice_schedule, tvb, 0, -1, ENC_NA);
    ss_tree = proto_item_add_subtree(ti, ett_scte35_splice_schedule);

    /* Header fields for splice_schedule() message */
    proto_tree_add_item(ss_tree, hf_splice_count, tvb, offset, 1, ENC_NA);
    offset++;

    /* Process each splice. */
    for (splice = 0; splice < splice_count; ++splice) {
        cancel_flag = tvb_get_bits8(tvb, offset * 8 + 32, 1);
        psf = cancel_flag ? 0 : tvb_get_bits8(tvb, offset * 8 + 41, 1);
        df = cancel_flag ? 0 : tvb_get_bits8(tvb, offset * 8 + 42, 1);
        component_count = cancel_flag ? 0 : (psf ? 0 : tvb_get_uint8(tvb, offset + 6));

        splice_length = 5;
        if (!cancel_flag)
            splice_length += 4 + 1;
        if (!cancel_flag && psf)
            splice_length += 4;
        if (!cancel_flag && !psf)
            splice_length += 1 + 5 * component_count;
        if (!cancel_flag && df)
            splice_length += 5;

        /* Add a subtree for the splice. */
        proto_tree_add_subtree_format(
            ss_tree, tvb, offset, splice_length, splice, &sp_tree,
            "Splice %d", splice);

        /* Show the splice header. */
        proto_tree_add_item(ss_tree, hf_splice_event_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(ss_tree, hf_splice_event_cancel_indicator, tvb,
                            offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ss_tree, hf_splice_reserved0, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (!cancel_flag) {
            min_length += 5;
            if (tvb_len < min_length)
                return offset;

            df = tvb_get_bits8(tvb, offset * 8 + 2, 1);

            /* Parse out the splice event flags. */
            proto_tree_add_bitmask_list(ss_tree, tvb, offset, 1, splice_event_flags, ENC_BIG_ENDIAN);
            offset++;

            min_length += (psf ? 4 : 1);
            if (tvb_len < min_length)
                return offset;

            if (psf) {
                proto_tree_add_item(ss_tree, hf_splice_utc_splice_time, tvb,
                                    offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else {
                component_count = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(ss_tree, hf_splice_component_count, tvb, offset, 1, ENC_NA);
                offset++;

                min_length += 5 * component_count;
                if (tvb_len < min_length)
                    return offset;

                /* Parse out each component stream. */
                for (component = 0; component < component_count; ++component) {
                    proto_tree_add_subtree_format(sp_tree, tvb, offset, 5, component, &component_tree,
                        "Component %d", component);
                    proto_tree_add_item(component_tree, hf_splice_component_tag, tvb,
                        offset, 1, ENC_NA);
                    offset++;

                    proto_tree_add_item(component_tree, hf_splice_component_utc_splice_time, tvb,
                        offset, 4, ENC_NA);
                    offset += 4;
                }
            }

            /* Parse out break duration, if present. */
            if (df) {
                min_length += 5;
                if (tvb_len < min_length)
                    return offset;

                proto_tree_add_item(ss_tree, hf_splice_break_duration_auto_return, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ss_tree, hf_splice_break_duration_reserved, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ss_tree, hf_splice_break_duration_duration, tvb,
                    offset, 5, ENC_BIG_ENDIAN);
                offset += 5;
            }
        }

        proto_tree_add_item(ss_tree, hf_splice_unique_program_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(ss_tree, hf_splice_avail_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(ss_tree, hf_splice_avails_expected, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    return offset;
}

void
proto_register_scte35_splice_schedule(void)
{
    static hf_register_info hf[] = {
        {&hf_splice_count,
         {"Splice Count", "scte35_splice_schedule.splice_count",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_splice_event_id,
         {"Event ID", "scte35_splice_schedule.splice.event_id",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_splice_event_cancel_indicator,
         {"Event Cancel Indicator", "scte35_splice_schedule.splice.event_cancel_indicator",
             FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},
        {&hf_splice_reserved0,
         {"Reserved", "scte35_splice_schedule.splice.reserved0",
             FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL}},
        {&hf_splice_out_of_network,
         {"Out of Network Indicator", "scte35_splice_schedule.splice.out_of_network_indicator",
             FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},
        {&hf_splice_program_splice_flag,
         {"Program Splice Flag", "scte35_splice_schedule.splice.program_splice_flag",
             FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},
        {&hf_splice_duration_flag,
         {"Duration Flag", "scte35_splice_schedule.splice.duration_flag",
             FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},
        {&hf_splice_reserved1,
         {"Reserved", "scte35_splice_schedule.splice.reserved1",
             FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}},
        {&hf_splice_utc_splice_time,
         {"UTC Splice Time", "scte35_splice_schedule.splice.utc_splice_time",
             FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_splice_component_count,
         {"Component Count", "scte35_splice_schedule.splice.component_count",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_splice_component_tag,
         {"Component Tag", "scte35_splice_schedule.splice.component.tag",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_splice_component_utc_splice_time,
         {"UTC Splice Time", "scte35_splice_schedule.splice.component.utc_splice_time",
             FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_splice_break_duration_auto_return,
         {"Auto Return", "scte35_splice_schedule.splice.break_duration.auto_return",
             FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},
        {&hf_splice_break_duration_reserved,
         {"Reserved", "scte35_splice_schedule.splice.break_duration.reserved",
             FT_UINT8, BASE_HEX, NULL, 0x7E, NULL, HFILL}},
        {&hf_splice_break_duration_duration,
         {"Duration", "scte35_splice_schedule.splice.break_duration.duration",
             FT_UINT64, BASE_DEC, NULL, UINT64_C(0x1FFFFFFFF), NULL, HFILL}},
        {&hf_splice_unique_program_id,
         {"Unique Program ID", "scte35_splice_schedule.splice.unique_program_id",
             FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_splice_avail_num,
         {"Avail Number", "scte35_splice_schedule.splice.avail_num",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_splice_avails_expected,
         {"Avails Expected", "scte35_splice_schedule.splice.avails_expected",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
    };

    static int *ett[] = {
        &ett_scte35_splice_schedule,
    };

    proto_scte35_splice_schedule = proto_register_protocol("SCTE-35 Splice Schedule", "SCTE35 SS", "scte35_splice_schedule");

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_scte35_splice_schedule, hf, array_length(hf));

    scte35_ss_handle = register_dissector("scte35_splice_schedule", dissect_scte35_splice_schedule, proto_scte35_splice_schedule);
}

void
proto_reg_handoff_scte35_splice_schedule(void)
{
    dissector_add_uint("scte35.splice_command_type", SCTE35_CMD_SPLICE_SCHEDULE, scte35_ss_handle);
}


/* core scte35 splice_info_section dissector */
static int
dissect_scte35_avail_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    int offset = 0;
    int tvb_len;

    /* Check length. */
    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < 4)
        return 0;

    /* Show the field. */
    proto_tree_add_item(tree, hf_descriptor_provider_avail_id, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

static int
dissect_scte35_dtmf_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    int offset = 0;
    int tvb_len, min_length = 2;
    uint8_t dtmf_count;

    /* Check length. */
    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < min_length)
        return 0;

    dtmf_count = tvb_get_bits8(tvb, (offset+1)* 8, 3);

    /* Check length with DTMF string too. */
    min_length += dtmf_count;
    if (tvb_len < min_length)
        return 0;

    /* Describe header. */
    proto_tree_add_item(tree, hf_descriptor_preroll, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_descriptor_dtmf_count, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_descriptor_dtmf_reserved, tvb, offset, 1, ENC_NA);
    offset++;

    /* Show the DTMF string field. */
    proto_tree_add_item(tree, hf_descriptor_dtmf, tvb,
                        offset, dtmf_count, ENC_NA | ENC_ASCII);

    offset += dtmf_count;
    return offset;
}

static int
dissect_scte35_component(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int idx) {
    int offset = 0;
    proto_tree *subtree;

    /* Create the subtree. */
    proto_tree_add_subtree_format(tree, tvb, offset, 6, idx, &subtree, "Component %d", idx);

    /* Display the component fields. */
    proto_tree_add_item(subtree, hf_descriptor_component_tag, tvb,
                        offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(subtree, hf_descriptor_component_reserved, tvb,
                        offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_descriptor_component_pts_offset, tvb,
                        offset, 5, ENC_BIG_ENDIAN);
    offset += 5;

    return offset;
}

static int
dissect_scte35_segmentation_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0, dissected_length = 0, component;
    uint8_t cancel_indicator, psf, sdf, dnr, component_count, upid_length;

    /* Parse the common header */
    proto_tree_add_item(tree, hf_descriptor_event_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    cancel_indicator = tvb_get_bits8(tvb, offset * 8, 1);
    proto_tree_add_item(tree, hf_descriptor_cancel_indicator, tvb,
                        offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_descriptor_reserved0, tvb,
                        offset, 1, ENC_NA);
    offset++;

    /* Parse fields for new segmentation events. */
    if (!cancel_indicator) {
        psf = tvb_get_bits8(tvb, offset * 8, 1);
        sdf = tvb_get_bits8(tvb, offset * 8 + 1, 1);
        dnr = tvb_get_bits8(tvb, offset * 8 + 2, 1);
        proto_tree_add_item(tree, hf_descriptor_psf, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_descriptor_segmentation_duration_flag,
            tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_descriptor_delivery_not_restricted_flag,
            tvb, offset, 1, ENC_NA);

        /* Parse delivery flags */
        if (dnr) {
            proto_tree_add_item(tree, hf_descriptor_reserved1, tvb, offset, 1, ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_descriptor_web_delivery_allowed_flag,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_descriptor_no_regional_blackout_flag,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_descriptor_archive_allow_flag,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_descriptor_device_restrictions,
                                tvb, offset, 1, ENC_NA);
        }
        offset++;

        /* Parse component segmentation offsets if not switched as a program. */
        if (!psf) {
            component_count = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(tree, hf_descriptor_component_count, tvb,
                                offset, 1, ENC_NA);
            offset++;

            /* Parse each component */
            for (component = 0; component < component_count; ++component) {
                dissected_length = dissect_scte35_component(
                        tvb_new_subset_length(tvb, offset, 6),
                        pinfo, tree, component);

                /* Propagate errors. */
                if (dissected_length < 1)
                    return dissected_length;
                offset += dissected_length;
            }
        }

        /* Parse segmentation duration if present. */
        if (sdf) {
            proto_tree_add_item(tree, hf_descriptor_segmentation_duration, tvb,
                                offset, 5, ENC_BIG_ENDIAN);
            offset += 5;
        }

        /* Parse UPID. */
        proto_tree_add_item(tree, hf_descriptor_segmentation_upid_type, tvb,
                            offset, 1, ENC_NA);
        offset++;

        upid_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf_descriptor_segmentation_upid_length, tvb,
                            offset, 1, ENC_NA);
        offset++;

        /* Only show non-empty UPIDs. */
        if (upid_length) {
            proto_tree_add_item(tree, hf_descriptor_segmentation_upid, tvb,
                                offset, upid_length, ENC_NA | ENC_ASCII);
            offset += upid_length;
        }

        /* Parse Segment counts. */
        proto_tree_add_item(tree, hf_descriptor_segmentation_type_id, tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(tree, hf_descriptor_segment_num, tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(tree, hf_descriptor_segments_expected, tvb, offset, 1, ENC_NA);
        offset++;
    }

    return offset;
}

static int
dissect_scte35_splice_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int idx)
{
    proto_tree *subtree;
    tvbuff_t *descriptor_tvb;
    int offset = 0, dissected_length = 0;
    uint8_t tag, length = 0;

    /* Create the subtree header for the descriptor. */
    tag = tvb_get_uint8(tvb, offset);
    length = tvb_get_uint8(tvb, offset + 1);
    proto_tree_add_subtree_format(
            tree, tvb, offset, length + 2, idx, &subtree,
            "Descriptor %d (0x%02x)", idx, tag);

    /* Parse descriptor headers */
    proto_tree_add_item(subtree, hf_splice_descriptor_tag, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(subtree, hf_splice_descriptor_length, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item(subtree, hf_splice_descriptor_identifier, tvb,
            offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Parse the specific descriptor type. */
    descriptor_tvb = tvb_new_subset_length(tvb, offset, length - 4);
    switch (tag) {
        case SCTE35_AVAIL_DESCRIPTOR:
            dissected_length = dissect_scte35_avail_descriptor(descriptor_tvb, pinfo, subtree);
            break;

        case SCTE35_DTMF_DESCRIPTOR:
            dissected_length = dissect_scte35_dtmf_descriptor(descriptor_tvb, pinfo, subtree);
            break;

        case SCTE35_SEGMENTATION_DESCRIPTOR:
            dissected_length = dissect_scte35_segmentation_descriptor(descriptor_tvb, pinfo, subtree);
            break;

        default:
            /* Just trust the descriptor_length field. */
            dissected_length = length - 4;
    }

    /* Propagate errors. */
    if (dissected_length < 1)
        return dissected_length;

    offset += dissected_length;
    return offset;
}

static int
dissect_scte35_splice_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int tvb_len, min_length = SCTE35_SI_MIN_LEN, dissected_length = 0;
    uint8_t table_id, encrypted_packet, command_type;
    uint16_t command_length, descriptor_loop_length, i;

    proto_item *ti;
    proto_tree *splice_info_tree;
    int offset = 0, descriptor_offset = 0;
    tvbuff_t *command_tvb;

    static int * const section_flags[] = {
        &hf_section_syntax_indicator,
        &hf_private_indicator,
        &hf_reserved,
        &hf_section_length,
        NULL
    };

    static int * const encrypt_flags[] = {
        &hf_encrypted_packet,
        &hf_encryption_algorithm,
        &hf_pts_adjustment,
        NULL
    };

    tvb_len = (int)tvb_reported_length(tvb);
    if (tvb_len < min_length)
        return 0;

    /* Pre-fetch a few fields in the message. */
    table_id = tvb_get_uint8(tvb, offset);
    encrypted_packet = tvb_get_uint8(tvb, offset + 4) & 0x80;
    command_type = tvb_get_uint8(tvb, offset + 13);
    command_length = tvb_get_ntohs(tvb, offset + 11) & 0xFFF;

    /* Check for excessive length before indexing past the command. */
    min_length += command_length;
    if (tvb_len < min_length)
        return 0;

    /* Determine length of descriptors. */
    descriptor_loop_length = tvb_get_ntohs(tvb, 14 + command_length);
    min_length += descriptor_loop_length;
    if (tvb_len < min_length)
        return 0;

    /* Check for excessive length before parsing the remainder of the packet. */
    if (encrypted_packet)
        min_length += 4;

    if (tvb_len < min_length)
        return 0;

    /* Set up headers in the packet list */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCTE-35");
    col_add_fstr(pinfo->cinfo, COL_INFO, "Table 0x%02x", table_id);

    /* Create the protocol header. */
    ti = proto_tree_add_item(tree, proto_scte35, tvb, 0, -1, ENC_NA);
    splice_info_tree = proto_item_add_subtree(ti, ett_scte35_splice_info_section);

    /* Explain the root fields. */
    proto_tree_add_item(splice_info_tree, hf_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_bitmask_list(splice_info_tree, tvb, offset, 2, section_flags, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(splice_info_tree, hf_protocol_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 7 bits of flags, 33 bits of PTS */
    proto_tree_add_bitmask_list(splice_info_tree, tvb, offset, 5, encrypt_flags, ENC_BIG_ENDIAN);
    offset += 5;

    proto_tree_add_item(splice_info_tree, hf_cw_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Two twelve-bit fields */
    proto_tree_add_item(splice_info_tree, hf_tier, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(splice_info_tree, hf_splice_command_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(splice_info_tree, hf_splice_command_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Extract the splice command payload for later use. */
    command_tvb = tvb_new_subset_length(tvb, offset, command_length);
    offset += command_length;

    /* Process the descriptor loop. */
    proto_tree_add_item(splice_info_tree, hf_descriptor_loop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Explain each descriptor. */
    for (i = 0, descriptor_offset = offset;
         descriptor_offset < offset + descriptor_loop_length;
         ++i) {
        dissected_length = dissect_scte35_splice_descriptor( tvb_new_subset_remaining(tvb, descriptor_offset),
                pinfo, splice_info_tree, i);

        /* Escalate failure. */
        if (dissected_length < 1)
            return offset;
        descriptor_offset += dissected_length;
    }
    offset += descriptor_loop_length;

    /* Explain the packet footer. */
    if (encrypted_packet) {
        proto_tree_add_item(splice_info_tree, hf_e_crc32, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    proto_tree_add_item(splice_info_tree, hf_crc32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* We've reached the end. Run a child dissector for the splice command. */
    dissector_try_uint_new(scte35_cmd_dissector_table, command_type, command_tvb, pinfo, tree,
        false, NULL);

    return offset;
}


void
proto_register_scte35(void)
{
    static int *ett[] = {
        &ett_scte35_splice_info_section,
    };

    static hf_register_info hf[] = {
        /* MPEG Section Table Headers. Field members taken from mpeg-sect.c. */
        {&hf_table_id,
         {"Table ID", "scte35.tid", FT_UINT8, BASE_HEX,
             NULL, 0, NULL, HFILL}},
        {&hf_section_syntax_indicator,
         {"Section Syntax Identifier", "scte35.syntax_indicator", FT_BOOLEAN,
             16, TFS(&tfs_section_syntax_indicator), 0x8000, NULL, HFILL }},
        {&hf_private_indicator,
         {"Private Indicator", "scte35.private", FT_BOOLEAN,
             16, TFS(&tfs_private_indicator), 0x4000, NULL, HFILL }},
        {&hf_reserved,
         {"Reserved", "scte35.reserved", FT_UINT16, BASE_HEX,
             NULL, 0x3000, NULL, HFILL }},
        {&hf_section_length,
         {"Section length", "scte35.len", FT_UINT16, BASE_DEC,
             NULL, 0x0FFF, NULL, HFILL}},

        /* SCTE35-specific headers */
        {&hf_protocol_version,
         {"Protocol Version", "scte35.protocol_version", FT_UINT8, BASE_DEC,
             NULL, 0, NULL, HFILL}},
        {&hf_encrypted_packet,
         {"Encrypted Packet", "scte35.encrypted_packet", FT_BOOLEAN, 40,
             TFS(&tfs_encrypted_packet), UINT64_C(0x8000000000), NULL, HFILL}},
        {&hf_encryption_algorithm,
         {"Encryption Algorithm", "scte35.encryption_algorithm", FT_UINT40,
             BASE_HEX | BASE_RANGE_STRING, RVALS(rv_encryption_algorithm),
             UINT64_C(0x7E00000000), NULL, HFILL}},
        {&hf_pts_adjustment,
         {"PTS Adjustment", "scte35.pts_adjustment", FT_UINT40, BASE_DEC,
             NULL, UINT64_C(0x1FFFFFFFF), NULL, HFILL}},
        {&hf_cw_index,
         {"Control Word Index", "scte35.cw_index", FT_UINT8, BASE_HEX,
             NULL, 0, NULL, HFILL}},
        {&hf_tier,
         {"Authorisation Tier", "scte35.tier", FT_UINT16, BASE_DEC,
             NULL, 0xFFF0, NULL, HFILL}},
        {&hf_splice_command_length,
         {"Command Length", "scte35.splice_command_length", FT_UINT16, BASE_DEC,
             NULL, 0x0FFF, NULL, HFILL}},
        {&hf_splice_command_type,
         {"Command Type", "scte35.splice_command_type", FT_UINT8,
             BASE_HEX | BASE_RANGE_STRING, RVALS(rv_splice_command_type),
             0, NULL, HFILL}},

        /* Splice command payload goes here via the dissector table. */

        /* Descriptor loop header. */
        {&hf_descriptor_loop_length,
         {"Descriptor Loop Length", "scte35.desc_len", FT_UINT16, BASE_DEC,
             NULL, 0, NULL, HFILL}},

        /* Descriptor loop entries. */
        {&hf_splice_descriptor_tag,
         {"Tag", "scte35.splice_descriptor.tag", FT_UINT8,
             BASE_HEX | BASE_RANGE_STRING, RVALS(rv_splice_descriptor_tag),
             0, NULL, HFILL}},
        {&hf_splice_descriptor_length,
         {"Length", "scte35.splice_descriptor.length", FT_UINT8, BASE_DEC,
             NULL, 0, NULL, HFILL}},
        {&hf_splice_descriptor_identifier,
         {"Descriptor ID", "scte35.splice_descriptor.identifier", FT_UINT32,
             BASE_HEX, NULL, 0, NULL, HFILL}},

        /* avail_descriptor */
        {&hf_descriptor_provider_avail_id,
         {"Provider Avail ID", "scte35.splice_descriptor.provider_avail_id",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},

        /* dtmf_descriptor */
        {&hf_descriptor_preroll,
         {"Preroll", "scte35.splice_descriptor.preroll",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_dtmf_count,
         {"DTMF Count", "scte35.splice_descriptor.dtmf_count",
             FT_UINT8, BASE_DEC, NULL, 0xE0, NULL, HFILL}},
        {&hf_descriptor_dtmf_reserved,
         {"DTMF Reserved", "scte35.splice_descriptor.dtmf_reserved",
             FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}},
        {&hf_descriptor_dtmf,
         {"DTMF", "scte35.splice_descriptor.dtmf",
             FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}},

        /* segmentation_descriptor */
        {&hf_descriptor_event_id,
         {"Segmentation Event ID", "scte35.splice_descriptor.event_id",
             FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_cancel_indicator,
         {"Cancel Indicator", "scte35.splice_descriptor.cancel_indicator",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_cancel_indicator), 0x80, NULL, HFILL}},
        {&hf_descriptor_reserved0,
         {"Reserved", "scte35.splice_descriptor.reserved0",
             FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL}},
        {&hf_descriptor_psf,
         {"Program Segmentation Flag", "scte35.splice_descriptor.psf",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_psf), 0x80, NULL, HFILL}},
        {&hf_descriptor_segmentation_duration_flag,
         {"Segmentation Duration Flag", "scte35.splice_descriptor.sdf",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_sdf), 0x40, NULL, HFILL}},
        {&hf_descriptor_delivery_not_restricted_flag,
         {"Delivery not Restricted", "scte35.splice_descriptor.dnr",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_dnr), 0x20, NULL, HFILL}},
        {&hf_descriptor_web_delivery_allowed_flag,
         {"Web Delivery Allowed", "scte35.splice_descriptor.web_delivery_allowed",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_web), 0x10, NULL, HFILL}},
        {&hf_descriptor_no_regional_blackout_flag,
         {"No Regional Blackout", "scte35.splice_descriptor.no_regional_blackout",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_blackout), 0x08, NULL, HFILL}},
        {&hf_descriptor_archive_allow_flag,
         {"Archive Allowed", "scte35.splice_descriptor.archive_allowed",
             FT_BOOLEAN, 8, TFS(&tfs_descriptor_archive), 0x04, NULL, HFILL}},
        {&hf_descriptor_device_restrictions,
         {"Device Restrictions", "scte35.splice_descriptor.device_restrictions",
             FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
             RVALS(scte35_device_restrictions), 0x03, NULL, HFILL}},
        {&hf_descriptor_reserved1,
         {"Reserved", "scte35.splice_descriptor.reserved1",
             FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL}},
        {&hf_descriptor_component_count,
         {"Component Count", "scte35.splice_descriptor.component_count",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_component_tag,
         {"Component Tag", "scte35.splice_descriptor.component.tag",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_component_reserved,
         {"Reserved", "scte35.splice_descriptor.component.reserved",
             FT_UINT8, BASE_HEX, NULL, 0xFE, NULL, HFILL}},
        {&hf_descriptor_component_pts_offset,
         {"PTS Offset", "scte35.splice_descriptor.component.pts_offset",
             FT_UINT64, BASE_DEC, NULL, 0x1FFFFFFFF, NULL, HFILL}},
        {&hf_descriptor_segmentation_duration,
         {"Segmentation Duration", "scte35.splice_descriptor.segmentation_duration",
             FT_UINT64, BASE_DEC, NULL, 0xFFFFFFFFFF, NULL, HFILL}},
        {&hf_descriptor_segmentation_upid_type,
         {"UPID Type", "scte35.splice_descriptor.upid_type",
             FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
             RVALS(scte35_segmentation_upid_type), 0, NULL, HFILL}},
        {&hf_descriptor_segmentation_upid_length,
         {"UPID Length", "scte35.splice_descriptor.upid_length",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_segmentation_upid,
         {"UPID", "scte35.splice_descriptor.upid",
             FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_segmentation_type_id,
         {"Segmentation Type", "scte35.splice_descriptor.segmentation_type_id",
             FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
             RVALS(scte35_segmentation_type_id), 0, NULL, HFILL}},
        {&hf_descriptor_segment_num,
         {"Segment Number", "scte35.splice_descriptor.segment_num",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_descriptor_segments_expected,
         {"Segments Expected", "scte35.splice_descriptor.segments_expected",
             FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},

        /* Optional alignment padding, encrypted CRC32 suffix. */
        {&hf_e_crc32,
         {"Encrypted CRC32", "scte35.ecrc32", FT_UINT32, BASE_HEX,
             NULL, 0, NULL, HFILL}},

        /* MPEG Section table CRC suffix */
        {&hf_crc32,
         {"CRC32", "scte35.crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
    };

    /* Allocate a protocol number. */
    proto_scte35 = proto_register_protocol("SCTE-35 Splice Information", "SCTE 35", "scte35");
    scte35_handle = register_dissector("scte35", dissect_scte35_splice_info, proto_scte35);

    /* Register groups and fields. */
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_scte35, hf, array_length(hf));

    /* Allow other protocols to discriminate against the splice command type
     * to further dissect the payload.
     */
    scte35_cmd_dissector_table = register_dissector_table(
        "scte35.splice_command_type", "SCTE-35 Command", proto_scte35, FT_UINT8,
        BASE_HEX);
}

void
proto_reg_handoff_scte35(void)
{
    /* Invoke the splice_info_section parser for a section table with ID 0xFC */
    dissector_add_uint("mpeg_sect.tid", SCTE35_TABLE_ID, scte35_handle);
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
