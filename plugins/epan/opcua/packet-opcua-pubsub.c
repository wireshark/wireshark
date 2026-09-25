/* packet-opcua-pubsub.c
 * Routines for OPC UA PubSub UADP dissection
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * OPC UA UADP PubSub (Part 14)
 */

#include "config.h"
#include "packet-opcua-pubsub.h"

/* Initialize the protocol and registered fields */
static int proto_opcua_pubsub;

static int hf_opcua_pubsub_uadp_version;

static int hf_opcua_pubsub_uadp_flags;
    static int hf_opcua_pubsub_uadp_flags_pid_enabled;
    static int hf_opcua_pubsub_uadp_flags_group_hdr_enabled;
    static int hf_opcua_pubsub_uadp_flags_payload_hdr_enabled;
    static int hf_opcua_pubsub_uadp_flags_ext_f1_enabled;

static int hf_opcua_pubsub_ext_f1_flags;
    static int hf_opcua_pubsub_ext_f1_pid_type;
    static int hf_opcua_pubsub_ext_f1_dataset_classid_enabled;
    static int hf_opcua_pubsub_ext_f1_security_hdr_enabled;
    static int hf_opcua_pubsub_ext_f1_timestamp_enabled;
    static int hf_opcua_pubsub_ext_f1_pico_enabled;
    static int hf_opcua_pubsub_ext_f1_ext_f2_enabled;

static int hf_opcua_pubsub_ext_f2_flags;
    static int hf_opcua_pubsub_ext_f2_chunk_enabled;
    static int hf_opcua_pubsub_ext_f2_promoted_fields_enabled;
    static int hf_opcua_pubsub_ext_f2_nm_type;

static int hf_opcua_pubsub_pid_uint8;
static int hf_opcua_pubsub_pid_uint16;
static int hf_opcua_pubsub_pid_uint32;
static int hf_opcua_pubsub_pid_uint64;
static int hf_opcua_pubsub_pid_string;

static int hf_opcua_pubsub_dataset_classid;

static int hf_opcua_pubsub_group_hdr_flags;
    static int hf_opcua_pubsub_group_hdr_writer_gid_enabled;
    static int hf_opcua_pubsub_group_hdr_grp_version_enabled;
    static int hf_opcua_pubsub_group_hdr_nm_num_enabled;
    static int hf_opcua_pubsub_group_hdr_seq_num_enabled;

static int hf_opcua_pubsub_group_hdr_writer_gid;
static int hf_opcua_pubsub_group_hdr_grp_version;
static int hf_opcua_pubsub_group_hdr_nm_num;
static int hf_opcua_pubsub_group_hdr_seq_num;

static int hf_opcua_pubsub_payload_hdr_dataset_msg_count;
static int hf_opcua_pubsub_payload_hdr_dataset_writerid;

static int hf_opcua_pubsub_ext_nw_hdr_timestamp;
static int hf_opcua_pubsub_ext_nw_hdr_picosec;
static int hf_opcua_pubsub_ext_nw_hdr_promfields_size;
static int hf_opcua_pubsub_ext_nw_hdr_promfields_fields;

static int hf_opcua_pubsub_sec_flags;
    static int hf_opcua_pubsub_sec_sign_enabled;
    static int hf_opcua_pubsub_sec_encrypt_enabled;
    static int hf_opcua_pubsub_sec_footer_enabled;
    static int hf_opcua_pubsub_sec_key_reset;

static int hf_opcua_pubsub_sec_tokenid;
static int hf_opcua_pubsub_sec_nonce_len;
static int hf_opcua_pubsub_sec_nonce;
static int hf_opcua_pubsub_sec_footer_size;

static int hf_opcua_pubsub_payload_enc;
static int hf_opcua_pubsub_sec_footer_enc;

static int hf_opcua_pubsub_dsm_size;

static int hf_opcua_pubsub_dsm_f1;
    static int hf_opcua_pubsub_dsm_f1_valid;
    static int hf_opcua_pubsub_dsm_f1_field_enc;
    static int hf_opcua_pubsub_dsm_f1_seqnum_enabled;
    static int hf_opcua_pubsub_dsm_f1_status_enabled;
    static int hf_opcua_pubsub_dsm_f1_conf_major_ver_enabled;
    static int hf_opcua_pubsub_dsm_f1_conf_minor_ver_enabled;
    static int hf_opcua_pubsub_dsm_f1_dsm_f2_enabled;

static int hf_opcua_pubsub_dsm_f2;
    static int hf_opcua_pubsub_dsm_f2_dsm_type;
    static int hf_opcua_pubsub_dsm_f2_timestamp_enabled;
    static int hf_opcua_pubsub_dsm_f2_pico_enabled;

static int hf_opcua_pubsub_dsm_seqnum;
static int hf_opcua_pubsub_dsm_timestamp;
static int hf_opcua_pubsub_dsm_pico;
static int hf_opcua_pubsub_dsm_status;
static int hf_opcua_pubsub_dsm_conf_major_ver;
static int hf_opcua_pubsub_dsm_conf_minor_ver;

static int hf_opcua_pubsub_dsm_chunk_offset;
static int hf_opcua_pubsub_dsm_total_size;
static int hf_opcua_pubsub_dsm_chunk_data;

static int hf_opcua_pubsub_dsm_kf_field_count;
static int hf_opcua_pubsub_dsm_kf_rawdata;

static int hf_opcua_pubsub_sec_footer;
static int hf_opcua_pubsub_sign;

static int hf_opcua_pubsub_fragments;
static int hf_opcua_pubsub_fragment;
static int hf_opcua_pubsub_fragment_overlap;
static int hf_opcua_pubsub_fragment_overlap_conflict;
static int hf_opcua_pubsub_fragment_multiple_tails;
static int hf_opcua_pubsub_fragment_too_long_fragment;
static int hf_opcua_pubsub_fragment_error;
static int hf_opcua_pubsub_fragment_count;
static int hf_opcua_pubsub_reassembled_in;
static int hf_opcua_pubsub_reassembled_length;
static int hf_opcua_pubsub_reassembled_data;

/* Initialize expert fields */
static expert_field ei_opcua_pubsub_invalid_value = EI_INIT;
static expert_field ei_opcua_pubsub_not_implemented = EI_INIT;
static expert_field ei_opcua_pubsub_dissection_failure = EI_INIT;

/* value_string definitions for certain flag values */
static const value_string pid_types[] = {
    { 0x00, "Byte" },
    { 0x01, "UInt16" },
    { 0x02, "UInt32" },
    { 0x03, "UInt64" },
    { 0x04, "String" },
    { 0x05, "Reserved" },
    { 0x06, "Reserved" },
    { 0x07, "Reserved" },
    { 0, NULL }
};

static const value_string nm_types[] = {
    { 0x00, "DataSetMessage Payload" },
    { 0x01, "Discovery Request Payload" },
    { 0x02, "Discovery Response Payload" },
    { 0x03, "Reserved" },
    { 0x04, "Reserved" },
    { 0x05, "Reserved" },
    { 0x06, "Reserved" },
    { 0x07, "Reserved" },
    { 0, NULL }
};

static const value_string field_encs[] = {
    { 0x00, "Variant" },
    { 0x01, "RawData" },
    { 0x02, "DataValue" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

static const value_string dsm_types[] = {
    { 0x00, "Data Key Frame" },
    { 0x01, "Data Delta Frame" },
    { 0x02, "Event" },
    { 0x03, "Keep Alive" },
    { 0x04, "Reserved" },
    { 0x05, "Reserved" },
    { 0x06, "Reserved" },
    { 0x07, "Reserved" },
    { 0x08, "Reserved" },
    { 0x09, "Reserved" },
    { 0x0A, "Reserved" },
    { 0x0B, "Reserved" },
    { 0x0C, "Reserved" },
    { 0x0D, "Reserved" },
    { 0x0E, "Reserved" },
    { 0x0F, "Reserved" },
    { 0, NULL }
};

static const enum_val_t security_policies[] = {
    { "none",       "None",       OPCUA_PUBSUB_SECURITY_POLICY_NONE },
    { "aes128-ctr", "AES128-CTR", OPCUA_PUBSUB_SECURITY_POLICY_AES128_CTR },
    { "aes256-ctr", "AES256-CTR", OPCUA_PUBSUB_SECURITY_POLICY_AES256_CTR },
    {  NULL,         NULL,        -1}
};

/* variables to store user preferences (except UDP port range) */
static unsigned int opcua_pubsub_ethertype = OPCUA_PUBSUB_ETHERTYPE;
static unsigned int opcua_pubsub_dsap = OPCUA_PUBSUB_DSAP;
static int security_policy = OPCUA_PUBSUB_SECURITY_POLICY_NONE;


/* Initialize the subtree pointers */
static int ett_opcua_pubsub;
static int ett_opcua_pubsub_nm_header;
static int ett_opcua_pubsub_uadp_flags;
static int ett_opcua_pubsub_ext_f1;
static int ett_opcua_pubsub_ext_f2;
static int ett_opcua_pubsub_group_hdr;
static int ett_opcua_pubsub_group_hdr_flags;
static int ett_opcua_pubsub_payload_hdr;
static int ett_opcua_pubsub_extended_nm_hdr;
static int ett_opcua_pubsub_promoted_fields;
static int ett_opcua_pubsub_sec_hdr;
static int ett_opcua_pubsub_sec_hdr_flags;
static int ett_opcua_pubsub_payload;
static int ett_opcua_pubsub_dsm;
static int ett_opcua_pubsub_dsm_f1;
static int ett_opcua_pubsub_dsm_f2;
static int ett_opcua_pubsub_keyframe;

static int ett_opcua_pubsub_fragment;
static int ett_opcua_pubsub_fragments;

/* Chunk reassembly extras */
static const fragment_items opcua_pubsub_frag_items = {
    /* Fragment subtrees */
    &ett_opcua_pubsub_fragment,
    &ett_opcua_pubsub_fragments,
    /* Fragment fields */
    &hf_opcua_pubsub_fragments,
    &hf_opcua_pubsub_fragment,
    &hf_opcua_pubsub_fragment_overlap,
    &hf_opcua_pubsub_fragment_overlap_conflict,
    &hf_opcua_pubsub_fragment_multiple_tails,
    &hf_opcua_pubsub_fragment_too_long_fragment,
    &hf_opcua_pubsub_fragment_error,
    &hf_opcua_pubsub_fragment_count,
    /* Reassembled in field */
    &hf_opcua_pubsub_reassembled_in,
    /* Reassembled length field */
    &hf_opcua_pubsub_reassembled_length,
    &hf_opcua_pubsub_reassembled_data,
    /* Tag */
    "OpcUa PubSub UADP NetworkMessage Chunks"
};

static reassembly_table opcua_pubsub_reassembly_table;


/* Helper functions */
static void check_sign(proto_tree* tree, tvbuff_t* tvb, int* offset, unsigned int sign_len) {
    proto_tree_add_item(tree, hf_opcua_pubsub_sign, tvb, *offset, sign_len, ENC_NA);
    (*offset) += sign_len;
}

static int
dissect_network_message_payload(tvbuff_t *tvb, packet_info *pinfo, int *pOffset, uint8_t nm_type, uint8_t msg_count,
    bool payload_hdr_enabled, proto_item *msg_count_ti, proto_item *payload_tree, proto_item *opcua_pubsub_ti,
    proto_item *ext_f2_ti, uint16_t remaining_data) {
    uint8_t flags;
    int iOffset = *pOffset;
    if (nm_type == 0x00) {
        /* Dissect DataSetMessage Payload */
        if (!(msg_count > 0)) {
            expert_add_info_format(pinfo, msg_count_ti, &ei_opcua_pubsub_invalid_value,
                "Invalid Message Count: %d", msg_count);
            return tvb_captured_length(tvb);
        }
        /* uint32_t dataset_sizes[msg_count]; */
        uint32_t *dataset_sizes = (uint32_t *)wmem_alloc(pinfo->pool, sizeof(uint32_t) * msg_count);
        if (payload_hdr_enabled && msg_count > 1) { /* no sizes if there's only 1 message */
            unsigned int i;
            for (i = 0; i < msg_count; i++)
            {
                proto_item *size_ti = proto_tree_add_item(payload_tree, hf_opcua_pubsub_dsm_size, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
                dataset_sizes[i] = tvb_get_uint16(tvb, iOffset, ENC_LITTLE_ENDIAN);
                proto_item_prepend_text(size_ti, "DataSetMessage[%d] ", i);
                iOffset += 2;
            }
        }
        else {
            dataset_sizes[0] = tvb_captured_length_remaining(tvb, iOffset) - remaining_data;
        }
        unsigned int i;
        for (i = 0; i < msg_count; i++) {
            unsigned int dsm_offset = iOffset;
            proto_item *dsm_ti, *dsm_f1_ti, *dsm_f2_ti = NULL;
            proto_tree *dsm_tree = proto_tree_add_subtree_format(
                payload_tree, tvb, iOffset, dataset_sizes[i], ett_opcua_pubsub_dsm, &dsm_ti, "DataSetMessage[%d]", i);

            bool dsm_f2_enabled = false;
            bool seqnum_enabled = false;
            bool dsm_timestamp_enabled = false;
            bool dsm_pico_enabled = false;
            bool status_enabled = false;
            bool conf_major_ver_enabled = false;
            bool conf_minor_ver_enabled = false;
            uint8_t dsm_type = 0x00;
            uint8_t field_enc = 0x00;

            /* DataSetMessage Header */
            static int *const dsm_f1_flags[] = {
                &hf_opcua_pubsub_dsm_f1_valid,
                &hf_opcua_pubsub_dsm_f1_field_enc,
                &hf_opcua_pubsub_dsm_f1_seqnum_enabled,
                &hf_opcua_pubsub_dsm_f1_status_enabled,
                &hf_opcua_pubsub_dsm_f1_conf_major_ver_enabled,
                &hf_opcua_pubsub_dsm_f1_conf_minor_ver_enabled,
                &hf_opcua_pubsub_dsm_f1_dsm_f2_enabled,
                NULL
            };
            dsm_f1_ti = proto_tree_add_bitmask(dsm_tree, tvb, iOffset, hf_opcua_pubsub_dsm_f1, ett_opcua_pubsub_dsm_f1, dsm_f1_flags, ENC_LITTLE_ENDIAN);
            flags = tvb_get_uint8(tvb, iOffset); iOffset += 1;
            dsm_f2_enabled = flags & OPCUA_PUBSUB_DSM_F1_DSM_F2_ENABLED;
            field_enc = (flags & OPCUA_PUBSUB_DSM_F1_FIELD_ENC) >> 1; /* Bits 1-2 */
            seqnum_enabled = flags & OPCUA_PUBSUB_DSM_F1_SEQNUM_ENABLED;
            status_enabled = flags & OPCUA_PUBSUB_DSM_F1_STATUS_ENABLED;
            conf_major_ver_enabled = flags & OPCUA_PUBSUB_DSM_F1_CONF_MAJOR_VER_ENABLED;
            conf_minor_ver_enabled = flags & OPCUA_PUBSUB_DSM_F1_CONF_MINOR_VER_ENABLED;

            if (dsm_f2_enabled) {
                static int *const dsm_f2_flags[] = {
                    &hf_opcua_pubsub_dsm_f2_dsm_type,
                    &hf_opcua_pubsub_dsm_f2_timestamp_enabled,
                    &hf_opcua_pubsub_dsm_f2_pico_enabled,
                    NULL
                };
                dsm_f2_ti = proto_tree_add_bitmask(dsm_tree, tvb, iOffset, hf_opcua_pubsub_dsm_f2, ett_opcua_pubsub_dsm_f2, dsm_f2_flags, ENC_LITTLE_ENDIAN);
                flags = tvb_get_uint8(tvb, iOffset); iOffset += 1;
                dsm_type = flags & OPCUA_PUBSUB_DSM_F2_DSM_TYPE;
                dsm_timestamp_enabled = flags & OPCUA_PUBSUB_DSM_F2_TIMESTAMP_ENABLED;
                dsm_pico_enabled = flags & OPCUA_PUBSUB_DSM_F2_PICO_ENABLED;
            }

            if (seqnum_enabled) {
                proto_tree_add_item(dsm_tree, hf_opcua_pubsub_dsm_seqnum, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
                iOffset += 2;
            }

            if (dsm_timestamp_enabled) {
                dissect_nttime(tvb, dsm_tree, iOffset, hf_opcua_pubsub_dsm_timestamp, ENC_LITTLE_ENDIAN);
                iOffset += 8;
            }

            if (dsm_pico_enabled) {
                proto_tree_add_item(dsm_tree, hf_opcua_pubsub_dsm_pico, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
                iOffset += 2;
            }

            if (status_enabled) {
                proto_tree_add_item(dsm_tree, hf_opcua_pubsub_dsm_status, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
                iOffset += 2;
            }

            /* TODO: Could Major and Minor ConfigurationVersion be parsed better? */
            if (conf_major_ver_enabled) {
                proto_tree_add_item(dsm_tree, hf_opcua_pubsub_dsm_conf_major_ver, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);
                iOffset += 4;
            }

            if (conf_minor_ver_enabled) {
                proto_tree_add_item(dsm_tree, hf_opcua_pubsub_dsm_conf_minor_ver, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);
                iOffset += 4;
            }

            /* Message Data */
            if (dsm_type == 0x00) { /* Data Key Frames */
                proto_item_append_text(dsm_ti, " (Data Key Frame Data)");
                proto_item *keyframe_ti;
                proto_tree *keyframe_tree = proto_tree_add_subtree(
                    dsm_tree, tvb, iOffset, -1, ett_opcua_pubsub_keyframe, &keyframe_ti, "Data Key Frame");

                uint16_t field_count = 0;
                if (field_enc != 0x01) {
                    proto_tree_add_item(keyframe_tree, hf_opcua_pubsub_dsm_kf_field_count, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
                    field_count = tvb_get_uint16(tvb, iOffset, ENC_LITTLE_ENDIAN); iOffset += 2;
                }

                if (field_enc == 0x00) { /* Variant */
                    unsigned int j;
                    for (j = 0; j < field_count; j++) { /* call parser for OPC UA datatypes, taken from the OPC UA dissector source */
                        int previous_offset = iOffset;

                        char datasetfield_name[DATASETFIELD_NAME_LENGTH];
                        snprintf(datasetfield_name, DATASETFIELD_NAME_LENGTH, "DataSetField[%d]", j);
                        parseVariant(keyframe_tree, tvb, pinfo, &iOffset, datasetfield_name);

                        if (previous_offset == iOffset) {
                            expert_add_info_format(pinfo, keyframe_ti, &ei_opcua_pubsub_dissection_failure,
                                "Variant could not be dissected");
                            return tvb_captured_length(tvb);
                        }
                    }
                }
                else if (field_enc == 0x01) { /* RawData */
                    unsigned int raw_data_length = dataset_sizes[i] - (iOffset - dsm_offset);
                    proto_tree_add_item(keyframe_tree, hf_opcua_pubsub_dsm_kf_rawdata, tvb, iOffset, raw_data_length, ENC_NA);
                    iOffset += raw_data_length;
                }
                else if (field_enc == 0x02) { /* DataValue */
                    unsigned int j;
                    for (j = 0; j < field_count; j++) {
                        int previous_offset = iOffset;

                        char datasetfield_name[DATASETFIELD_NAME_LENGTH];
                        snprintf(datasetfield_name, DATASETFIELD_NAME_LENGTH, "DataSetField[%d]", j);
                        parseDataValue(keyframe_tree, tvb, pinfo, &iOffset, datasetfield_name);

                        if (previous_offset == iOffset) {
                            expert_add_info_format(pinfo, keyframe_ti, &ei_opcua_pubsub_dissection_failure,
                                "DataValue could not be dissected");
                            return tvb_captured_length(tvb);
                        }
                    }
                }
                else {
                    expert_add_info_format(pinfo, dsm_f1_ti, &ei_opcua_pubsub_invalid_value, "Invalid Field Encoding: %d", field_enc);
                    return tvb_captured_length(tvb);
                }
            }
            else if (dsm_type == 0x01) { /* Data Delta Frames */
                expert_add_info_format(pinfo, dsm_ti, &ei_opcua_pubsub_not_implemented,
                    "Data Delta Frames are not yet implemented");
                return tvb_captured_length(tvb);
            }
            else if (dsm_type == 0x02) { /* Event */
                expert_add_info_format(pinfo, dsm_ti, &ei_opcua_pubsub_not_implemented,
                    "Events are not yet implemented");
                return tvb_captured_length(tvb);
            }
            else if (dsm_type == 0x03) { /* Keep Alive */
                expert_add_info_format(pinfo, dsm_ti, &ei_opcua_pubsub_not_implemented,
                    "Keep Alives are not yet implemented");
                return tvb_captured_length(tvb);
            }
            else {
                expert_add_info_format(pinfo, dsm_f2_ti, &ei_opcua_pubsub_invalid_value,
                    "Invalid DataSetMessage type: %d", dsm_type);
                return tvb_captured_length(tvb);
            }
            proto_item_set_end(dsm_ti, tvb, iOffset);
            if (iOffset - dsm_offset != dataset_sizes[i]) {
                expert_add_info_format(pinfo, dsm_ti, &ei_opcua_pubsub_not_implemented,
                    "DataSetMessage could not be fully dissected, dissected bytes: %d (expected: %d)",
                    iOffset - dsm_offset, dataset_sizes[i]);
                return tvb_captured_length(tvb);
            }
        }
        wmem_free(pinfo->pool, dataset_sizes);
    }
    else if (nm_type == 0x01) {
        expert_add_info_format(pinfo, opcua_pubsub_ti, &ei_opcua_pubsub_not_implemented,
            "Discovery Request Payloads are not yet implemented");
        return tvb_captured_length(tvb);
    }
    else if (nm_type == 0x02) {
        expert_add_info_format(pinfo, opcua_pubsub_ti, &ei_opcua_pubsub_not_implemented,
            "Discovery Response Payloads are not yet implemented");
        return tvb_captured_length(tvb);
    }
    else {
/* ext_f2_ti can't be uninitialized because nm_type is something other than 0x00 */
        expert_add_info_format(pinfo, ext_f2_ti, &ei_opcua_pubsub_invalid_value,
            "Invalid NetworkMessage type: %d", nm_type);
        return tvb_captured_length(tvb);
    }

    *pOffset = iOffset;
    return 0;
}

/* Code to actually dissect the packets */
static int
dissect_opcua_pubsub(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    /** TODO: find sensible use for Info column
      * (e.g., publisherID, security enabled yes/no, writerGroupID, encoding settings)
      */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UADP NetworkMessage");
    col_clear(pinfo->cinfo, COL_INFO);

    /* various default values */
    uint8_t pid_type = 0x00;
    uint8_t nm_type = 0x00;
    uint8_t msg_count = 1;
    uint16_t sec_footer_size = 0;

    bool dataset_classid_enabled = false;
    bool chunk_enabled = false;
    bool timestamp_enabled = false;
    bool pico_enabled = false;
    bool promoted_fields_enabled = false;
    bool security_hdr_enabled = false;
    bool security_footer_enabled = false;
    bool encrypt_enabled = false;
    bool sign_enabled = false;

    uint8_t sign_len;
    switch (security_policy) {
        case OPCUA_PUBSUB_SECURITY_POLICY_AES128_CTR: sign_len = 16; break;
        case OPCUA_PUBSUB_SECURITY_POLICY_AES256_CTR: sign_len = 32; break;
        case OPCUA_PUBSUB_SECURITY_POLICY_NONE:
        default:
            sign_len = 0;
            break;
    }

    /* some proto_items to attach expert info in case certain values are off */
    proto_item *ext_f1_ti = NULL, *ext_f2_ti = NULL, *msg_count_ti = NULL;

    /* create display subtree for the protocol */
    proto_item *opcua_pubsub_ti = proto_tree_add_item(tree, proto_opcua_pubsub, tvb, 0, -1, ENC_NA);
    proto_tree *opcua_pubsub_tree = proto_item_add_subtree(opcua_pubsub_ti, ett_opcua_pubsub);

    /* NetworkMessage Header */
    proto_item *nm_header_ti;
    proto_tree *nm_header_tree = proto_tree_add_subtree(
        opcua_pubsub_tree, tvb, 0, -1, ett_opcua_pubsub_nm_header, &nm_header_ti, "NetworkMessage Header");

    proto_tree_add_item(nm_header_tree, hf_opcua_pubsub_uadp_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    static int* const uadp_flags[] = {
        &hf_opcua_pubsub_uadp_flags_pid_enabled,
        &hf_opcua_pubsub_uadp_flags_group_hdr_enabled,
        &hf_opcua_pubsub_uadp_flags_payload_hdr_enabled,
        &hf_opcua_pubsub_uadp_flags_ext_f1_enabled,
        NULL
    };

    proto_tree_add_bitmask(
        nm_header_tree, tvb, offset, hf_opcua_pubsub_uadp_flags,
        ett_opcua_pubsub_uadp_flags, uadp_flags, ENC_LITTLE_ENDIAN);
    uint8_t flags = tvb_get_uint8(tvb, offset); offset += 1;
    bool pid_enabled         = flags & OPCUA_PUBSUB_FLAGS_PID_ENABLED;
    bool group_hdr_enabled   = flags & OPCUA_PUBSUB_FLAGS_GROUP_HDR_ENABLED;
    bool payload_hdr_enabled = flags & OPCUA_PUBSUB_FLAGS_PAYLOAD_HDR_ENABLED;
    bool ext_f1_enabled      = flags & OPCUA_PUBSUB_FLAGS_EXT_F1_ENABLED;

    /* Parse ExtendedFlags1, if enabled */
    if (ext_f1_enabled) {
        static int* const ext_f1_flags[] = {
            &hf_opcua_pubsub_ext_f1_pid_type,
            &hf_opcua_pubsub_ext_f1_dataset_classid_enabled,
            &hf_opcua_pubsub_ext_f1_security_hdr_enabled,
            &hf_opcua_pubsub_ext_f1_timestamp_enabled,
            &hf_opcua_pubsub_ext_f1_pico_enabled,
            &hf_opcua_pubsub_ext_f1_ext_f2_enabled,
            NULL
        };

        ext_f1_ti = proto_tree_add_bitmask(
            nm_header_tree, tvb, offset, hf_opcua_pubsub_ext_f1_flags,
            ett_opcua_pubsub_ext_f1, ext_f1_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_uint8(tvb, offset); offset += 1;
        pid_type                = flags & OPCUA_PUBSUB_EXT_F1_PID_TYPE;
        dataset_classid_enabled = flags & OPCUA_PUBSUB_EXT_F1_DATASET_CLASSID_ENABLED;
        timestamp_enabled       = flags & OPCUA_PUBSUB_EXT_F1_TIMESTAMP_ENABLED;
        pico_enabled            = flags & OPCUA_PUBSUB_EXT_F1_PICO_ENABLED;
        security_hdr_enabled    = flags & OPCUA_PUBSUB_EXT_F1_SECURITY_ENABLED;

        bool ext_f2_enabled = flags & OPCUA_PUBSUB_EXT_F1_EXT_F2_ENABLED;

        if (!flags) { /* the packet is technically not malformed, but the flags could be omitted */
            expert_add_info_format(pinfo, ext_f1_ti, &ei_opcua_pubsub_invalid_value,
                "Extended Flags 1 are enabled but all false!");
        }

        /* Parse ExtendedFlags2, if enabled */
        if (ext_f2_enabled) {
            static int* const ext_f2_flags[] = {
                &hf_opcua_pubsub_ext_f2_chunk_enabled,
                &hf_opcua_pubsub_ext_f2_promoted_fields_enabled,
                &hf_opcua_pubsub_ext_f2_nm_type,
                NULL
            };

            ext_f2_ti = proto_tree_add_bitmask(
                nm_header_tree, tvb, offset, hf_opcua_pubsub_ext_f2_flags,
                ett_opcua_pubsub_ext_f2, ext_f2_flags, ENC_LITTLE_ENDIAN
            );
            flags = tvb_get_uint8(tvb, offset); offset += 1;
            chunk_enabled           = flags & OPCUA_PUBSUB_EXT_F2_CHUNK_ENABLED;
            promoted_fields_enabled = flags & OPCUA_PUBSUB_EXT_F2_PROMOTED_FIELDS_ENABLED;
            nm_type                = (flags & OPCUA_PUBSUB_EXT_F2_NM_TYPE) >> 2; /* Bits 2-4 */

            if (!flags) { /* the packet is technically not malformed, but the flags could be omitted */
                expert_add_info_format(pinfo, ext_f2_ti, &ei_opcua_pubsub_invalid_value,
                    "Extended Flags 2 are enabled but all false!");
            }
        }
    }

    /* Parse PublisherId Type */
    if (pid_enabled) {
        if (pid_type == 0x00) {      /* Byte */
            proto_tree_add_item(nm_header_tree, hf_opcua_pubsub_pid_uint8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }
        else if (pid_type == 0x01) { /* UInt16 */
            proto_tree_add_item(nm_header_tree, hf_opcua_pubsub_pid_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (pid_type == 0x02) { /* UInt32 */
            proto_tree_add_item(nm_header_tree, hf_opcua_pubsub_pid_uint32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        else if (pid_type == 0x03) { /* UInt64 */
            proto_tree_add_item(nm_header_tree, hf_opcua_pubsub_pid_uint64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        else if (pid_type == 0x04) { /* String */
            parseString(nm_header_tree, tvb, pinfo, &offset, hf_opcua_pubsub_pid_string);
        }
        else {
            expert_add_info_format(pinfo, ext_f1_ti, &ei_opcua_pubsub_invalid_value,
                "Invalid PublisherId type: %d", pid_type);
            return tvb_captured_length(tvb);
        }
    }

    if (dataset_classid_enabled) {
        proto_tree_add_item(nm_header_tree, hf_opcua_pubsub_dataset_classid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;
    }

    proto_item_set_end(nm_header_ti, tvb, offset);

    /* Group Header */
    if (group_hdr_enabled) {
        proto_item *group_hdr_ti;
        proto_tree *group_hdr_tree = proto_tree_add_subtree(
            opcua_pubsub_tree, tvb, offset, -1, ett_opcua_pubsub_group_hdr, &group_hdr_ti, "Group Header");

        static int *const group_hdr_flags[] = {
            &hf_opcua_pubsub_group_hdr_writer_gid_enabled,
            &hf_opcua_pubsub_group_hdr_grp_version_enabled,
            &hf_opcua_pubsub_group_hdr_nm_num_enabled,
            &hf_opcua_pubsub_group_hdr_seq_num_enabled,
            NULL
        };

        proto_tree_add_bitmask(group_hdr_tree, tvb, offset, hf_opcua_pubsub_group_hdr_flags,
            ett_opcua_pubsub_group_hdr_flags, group_hdr_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_uint8(tvb, offset); offset += 1;
        bool writer_gid_enabled = flags & OPCUA_PUBSUB_GROUP_HDR_FLAGS_WRITER_GID_ENABLED;
        bool group_version_enabled = flags & OPCUA_PUBSUB_GROUP_HDR_FLAGS_GROUP_VERSION_ENABLED;
        bool nm_num_enabled = flags & OPCUA_PUBSUB_GROUP_HDR_FLAGS_NM_NUM_ENABLED;
        bool seq_num_enabled = flags & OPCUA_PUBSUB_GROUP_HDR_FLAGS_SEQ_NUM_ENABLED;

        if (writer_gid_enabled) {
            proto_tree_add_item(group_hdr_tree, hf_opcua_pubsub_group_hdr_writer_gid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        if (group_version_enabled) {
            proto_tree_add_item(group_hdr_tree, hf_opcua_pubsub_group_hdr_grp_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
        if (nm_num_enabled) {
            proto_tree_add_item(group_hdr_tree, hf_opcua_pubsub_group_hdr_nm_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        if (seq_num_enabled) {
            proto_tree_add_item(group_hdr_tree, hf_opcua_pubsub_group_hdr_seq_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        proto_item_set_end(group_hdr_ti, tvb, offset);
    }

    if (payload_hdr_enabled) {
        proto_item *payload_hdr_ti;
        proto_tree *payload_hdr_tree = proto_tree_add_subtree(
            opcua_pubsub_tree, tvb, offset, -1, ett_opcua_pubsub_payload_hdr, &payload_hdr_ti, "Payload Header");
        if (nm_type == 0x00) {
            if (!chunk_enabled) {
                proto_item_append_text(payload_hdr_ti, " (DataSet Payload)");
                msg_count_ti = proto_tree_add_item(
                    payload_hdr_tree, hf_opcua_pubsub_payload_hdr_dataset_msg_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                msg_count = tvb_get_uint8(tvb, offset); offset += 1;

                unsigned int i;
                for (i = 0; i < msg_count; i++) {
                    proto_item *writer_id_ti = proto_tree_add_item(payload_hdr_tree, hf_opcua_pubsub_payload_hdr_dataset_writerid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_prepend_text(writer_id_ti, "DataSetMessage[%d] ", i);
                    offset += 2;
                }
            }
            else {
                proto_tree_add_item(payload_hdr_tree, hf_opcua_pubsub_payload_hdr_dataset_writerid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_item_append_text(payload_hdr_ti, " (Chunk - DataSet Payload)");
            }
        }
        else if (nm_type == 0x01) {
            proto_item_append_text(payload_hdr_ti, " (Discovery Request Payload)");
            proto_tree_add_item(payload_hdr_tree, hf_opcua_pubsub_payload_hdr_dataset_writerid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        else if (nm_type == 0x02) {
            if (!chunk_enabled) {
                proto_item_append_text(payload_hdr_ti, " (Discovery Response Payload)");
                proto_tree_add_item(payload_hdr_tree, hf_opcua_pubsub_payload_hdr_dataset_writerid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            else {
                /* TODO: Assert DataSetWriterId(UInt16) is equal to 0 */
                proto_item_append_text(payload_hdr_ti, " (Chunk - Discovery Response Payload)");
                expert_add_info_format(pinfo, payload_hdr_ti, &ei_opcua_pubsub_not_implemented, "Chunked Payloads are not yet implemented");
                return tvb_captured_length(tvb);
            }
        /* TODO: (undocumented?) MIME type 0x03 in LUA? */
        }
        else if (ext_f2_ti) {
            expert_add_info_format(pinfo, ext_f2_ti, &ei_opcua_pubsub_invalid_value,
                "Invalid NetworkMessage type: %d", nm_type);
            return tvb_captured_length(tvb);
        }

        proto_item_set_end(payload_hdr_ti, tvb, offset);
    }

    /* Extended NetworkMessage Header */
    if (timestamp_enabled || pico_enabled || promoted_fields_enabled) {
        proto_item* extended_nm_hdr_ti;
        proto_tree* extended_nm_hdr_tree = proto_tree_add_subtree(
            opcua_pubsub_tree, tvb, offset, -1, ett_opcua_pubsub_extended_nm_hdr, &extended_nm_hdr_ti, "Extended NetworkMessage Header");
        if (timestamp_enabled) {
            dissect_nttime(tvb, extended_nm_hdr_tree, offset, hf_opcua_pubsub_ext_nw_hdr_timestamp, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
        if (pico_enabled) {
            /* TODO Add correct support for Picoseconds as defined in Part 6:
                -- "The Picoseconds fields store the difference between a high-resolution timestamp with a
                -- resolution of 10 picoseconds and the Timestamp field value which only has a 100 ns
                -- resolution.The Picoseconds fields shall contain values less than 10 000. The decoder shall
                -- treat values greater than or equal to 10 000 as the value '9999'."
            */

            proto_tree_add_item(extended_nm_hdr_tree, hf_opcua_pubsub_ext_nw_hdr_picosec, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            /* picoseconds shall be <= 9999 */
            uint16_t picoseconds = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN); offset += 2;
            if (picoseconds >= 10000) {
                expert_add_info_format(pinfo, extended_nm_hdr_ti, &ei_opcua_pubsub_invalid_value,
                    "Picoseconds are supposed to be less than 10000");
            }
        }
        if (promoted_fields_enabled) {
            proto_item* promoted_fields_ti;
            proto_tree* promoted_fields_tree = proto_tree_add_subtree(
                extended_nm_hdr_tree, tvb, offset, -1, ett_opcua_pubsub_promoted_fields, &promoted_fields_ti, "Promoted Fields");
            proto_tree_add_item(promoted_fields_tree, hf_opcua_pubsub_ext_nw_hdr_promfields_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            uint16_t promoted_size = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN); offset += 2;

            /* TODO this is not quite complete, DataSetMetaData is relevant for proper dissection */
            proto_tree_add_item(promoted_fields_tree, hf_opcua_pubsub_ext_nw_hdr_promfields_fields, tvb, offset, promoted_size, ENC_NA);
            offset += promoted_size;
            proto_item_set_len(promoted_fields_ti, promoted_size + 2);
        }

        proto_item_set_end(extended_nm_hdr_ti, tvb, offset);
    }

    if (security_hdr_enabled) {
        proto_item* sec_hdr_ti;
        proto_tree* sec_hdr_tree = proto_tree_add_subtree(opcua_pubsub_tree, tvb, offset, -1, ett_opcua_pubsub_sec_hdr, &sec_hdr_ti, "Security Header");
        static int* const sec_hdr_flags[] = {
            &hf_opcua_pubsub_sec_sign_enabled,
            &hf_opcua_pubsub_sec_encrypt_enabled,
            &hf_opcua_pubsub_sec_footer_enabled,
            &hf_opcua_pubsub_sec_key_reset,
            NULL
        };
        proto_tree_add_bitmask(sec_hdr_tree, tvb, offset, hf_opcua_pubsub_sec_flags, ett_opcua_pubsub_sec_hdr_flags, sec_hdr_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_uint8(tvb, offset); offset += 1;
        sign_enabled            = flags & OPCUA_PUBSUB_SEC_FLAGS_SIGN_ENABLED;
        encrypt_enabled         = flags & OPCUA_PUBSUB_SEC_FLAGS_ENCRYPT_ENABLED;
        security_footer_enabled = flags & OPCUA_PUBSUB_SEC_FLAGS_SEC_FOOTER_ENABLED;

        if (sign_enabled && encrypt_enabled) {
            proto_item_append_text(opcua_pubsub_ti, " [Signed + Encrypted]");
        }
        else if (sign_enabled) {
            proto_item_append_text(opcua_pubsub_ti, " [Signed]");
        }
        else if (encrypt_enabled) {
            proto_item_append_text(opcua_pubsub_ti, " [Encrypted]");
        }

        if ((sign_enabled || encrypt_enabled) && security_policy == OPCUA_PUBSUB_SECURITY_POLICY_NONE) {
            expert_add_info_format(pinfo, opcua_pubsub_ti, &ei_opcua_pubsub_invalid_value,
                "Signing and/or encryption enabled, but \"None\" SecurityPolicy selected");
        }

        proto_tree_add_item(sec_hdr_tree, hf_opcua_pubsub_sec_tokenid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(sec_hdr_tree, hf_opcua_pubsub_sec_nonce_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        uint8_t nonce_len = tvb_get_uint8(tvb, offset); offset += 1;

        if (nonce_len > 0) {
            proto_tree_add_item(sec_hdr_tree, hf_opcua_pubsub_sec_nonce, tvb, offset, nonce_len, ENC_NA);
            offset += nonce_len;
        }

        if (security_footer_enabled) {
            proto_tree_add_item(sec_hdr_tree, hf_opcua_pubsub_sec_footer_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            sec_footer_size = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN); offset += 2;
        }

        proto_item_set_end(sec_hdr_ti, tvb, offset);
    }

    /* Payload */
    if (encrypt_enabled) {
        unsigned int payload_size = tvb_captured_length_remaining(tvb, offset) - sec_footer_size - sign_len;
        proto_tree_add_item(opcua_pubsub_tree, hf_opcua_pubsub_payload_enc, tvb, offset, payload_size, ENC_NA);
        offset += payload_size;
        if (security_footer_enabled) {
            proto_tree_add_item(opcua_pubsub_tree, hf_opcua_pubsub_sec_footer_enc, tvb, offset, sec_footer_size, ENC_NA);
            offset += sec_footer_size;
        }
        /* TODO: Check how to use prefs to decrypt payload if key is set up */
        /* TODO: Consider Padding */
    }
    else {
        /* payload not encrypted -> continue dissection */
        proto_item *payload_ti;
        proto_tree *payload_tree = proto_tree_add_subtree(
            opcua_pubsub_tree, tvb, offset, -1, ett_opcua_pubsub_payload, &payload_ti, "NetworkMessage Payload");

        /* Using Wiresharks reassembly methods to support chunked NetworkMessages */
        /* See https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectReassemble.html */
        bool save_fragmented = pinfo->fragmented;
        tvbuff_t *next_tvb = NULL;
        if (chunk_enabled) { /* Chunked Payload */
            col_append_str(pinfo->cinfo, COL_INFO, "Chunked NetworkMessage");

            tvbuff_t *new_tvb = NULL;
            fragment_head *chunk_data = NULL;
            proto_tree_add_item(payload_tree, hf_opcua_pubsub_dsm_seqnum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            uint16_t msg_seq_num = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN); offset += 2;
            proto_tree_add_item(payload_tree, hf_opcua_pubsub_dsm_chunk_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            uint32_t chunk_offset = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN); offset += 4;
            proto_tree_add_item(payload_tree, hf_opcua_pubsub_dsm_total_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            uint32_t total_size = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN); offset += 4;

            uint16_t chunk_data_len = tvb_captured_length_remaining(tvb, offset) - sign_len;
            pinfo->fragmented = true;
            chunk_data = fragment_add_check(&opcua_pubsub_reassembly_table, tvb, offset, pinfo,
                msg_seq_num, NULL, chunk_offset, chunk_data_len, chunk_offset + chunk_data_len != total_size);

            new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled NetworkMessage", chunk_data,
                &opcua_pubsub_frag_items, NULL, opcua_pubsub_tree);

            if (chunk_data) { /* Reassembled */
                col_append_str(pinfo->cinfo, COL_INFO, " [Reassembled]");

                if (new_tvb) { /* Reassembled in this packet */
                    next_tvb = new_tvb;
                }
            }
            else { /* Not (yet) reassembled */
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Not reassembled - Sequence: %u, Offset: %u]", msg_seq_num, chunk_offset);
            }

            proto_tree_add_item(payload_tree, hf_opcua_pubsub_dsm_chunk_data, tvb, offset, chunk_data_len, ENC_NA);
            offset += chunk_data_len;
        }
        else { /* Not chunked, just a usual payload */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
        }
        pinfo->fragmented = save_fragmented;

        int new_offset = 0;

        if (next_tvb) { /* only dissect if: normal payload or completely reassembled */
            if (dissect_network_message_payload(next_tvb, pinfo, &new_offset, nm_type, msg_count, payload_hdr_enabled,
                msg_count_ti, payload_tree, opcua_pubsub_ti, ext_f2_ti, sec_footer_size - sign_len)) {
                return tvb_captured_length(tvb);
            }
        }

        /* TODO Padding: Not Implemented */

        if (security_footer_enabled) {
            /* TODO interpret Security Footer with regard to SecurityPolicy */
            proto_tree_add_item(opcua_pubsub_tree, hf_opcua_pubsub_sec_footer, next_tvb, new_offset, sec_footer_size, ENC_NA);
            new_offset += sec_footer_size;
        }

        /* Bring old tvb offset up to date */
        offset += new_offset;
    }

    if (sign_enabled) {
        /* TODO: Check signature given public key */
        check_sign(opcua_pubsub_tree, tvb, &offset, sign_len);
    }

    int remaining = tvb_captured_length_remaining(tvb, offset);
    if (remaining) {
        expert_add_info_format(pinfo, opcua_pubsub_ti, &ei_opcua_pubsub_not_implemented,
            "Packet could not be fully dissected, %d bytes left", remaining);
    }
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark. */
void
proto_register_opcua_pubsub(void)
{
    /* Setup the various header fields possible in OPC UA PubSub */
    static hf_register_info hf_base[] = {
        /* id                                                name                                          abbreviation (display filter)                         type              display              strings           bitmask                                             blurb HFILL*/
        { &hf_opcua_pubsub_uadp_version,                   { "UADPVersion",                                "opcua_pubsub.version",                               FT_UINT8,         BASE_DEC,            NULL,             0x0F,                                               NULL, HFILL } },

        { &hf_opcua_pubsub_uadp_flags,                     { "UADP Flags",                                 "opcua_pubsub.flags",                                 FT_UINT8,         BASE_HEX,            NULL,             0xF0,                                               NULL, HFILL } },
        { &hf_opcua_pubsub_uadp_flags_pid_enabled,         { "PublisherId enabled",                        "opcua_pubsub.flags.pidEnable",                       FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_FLAGS_PID_ENABLED,                     NULL, HFILL } },
        { &hf_opcua_pubsub_uadp_flags_group_hdr_enabled,   { "DataSet GroupHeader enabled",                "opcua_pubsub.flags.groupHdrEnable",                  FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_FLAGS_GROUP_HDR_ENABLED,               NULL, HFILL } },
        { &hf_opcua_pubsub_uadp_flags_payload_hdr_enabled, { "DataSet PayloadHeader enabled",              "opcua_pubsub.flags.payloadHdrEnable",                FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_FLAGS_PAYLOAD_HDR_ENABLED,             NULL, HFILL } },
        { &hf_opcua_pubsub_uadp_flags_ext_f1_enabled,      { "ExtendedFlags1 enabled",                     "opcua_pubsub.flags.extF1Enable",                     FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_FLAGS_EXT_F1_ENABLED,                  NULL, HFILL } },

        { &hf_opcua_pubsub_ext_f1_flags,                   { "ExtendedFlags1",                             "opcua_pubsub.ext_f1",                                FT_UINT8,         BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f1_pid_type,                { "PublisherId Type",                           "opcua_pubsub.ext_f1.pid_type",                       FT_UINT8,         BASE_DEC,            VALS(pid_types),  OPCUA_PUBSUB_EXT_F1_PID_TYPE,                       NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f1_dataset_classid_enabled, { "DataSetClassId enabled",                     "opcua_pubsub.ext_f1.dataset_classid_enabled",        FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F1_DATASET_CLASSID_ENABLED,        NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f1_security_hdr_enabled,    { "Security (Header) enabled",                  "opcua_pubsub.ext_f1.security_hdr_enabled",           FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F1_SECURITY_ENABLED,               NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f1_timestamp_enabled,       { "NetworkMessage Timestamp enabled",           "opcua_pubsub.ext_f1.timestamp_enabled",              FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F1_TIMESTAMP_ENABLED,              NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f1_pico_enabled,            { "NetworkMessage Picoseconds enabled",         "opcua_pubsub.ext_f1.pico_enabled",                   FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F1_PICO_ENABLED,                   NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f1_ext_f2_enabled,          { "ExtendedFlags2 enabled",                     "opcua_pubsub.ext_f1.ext_f2_enabled",                 FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F1_EXT_F2_ENABLED,                 NULL, HFILL } },

        { &hf_opcua_pubsub_ext_f2_flags,                   { "ExtendedFlags2",                             "opcua_pubsub.ext_f2",                                FT_UINT8,         BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f2_chunk_enabled,           { "Chunked Payload (Header) enabled",           "opcua_pubsub.ext_f2.chunk_enabled",                  FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F2_CHUNK_ENABLED,                  NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f2_promoted_fields_enabled, { "PromotedFields enabled",                     "opcua_pubsub.ext_f2.promoted_fields_enabled",        FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_EXT_F2_PROMOTED_FIELDS_ENABLED,        NULL, HFILL } },
        { &hf_opcua_pubsub_ext_f2_nm_type,                 { "NetworkMessage Type",                        "opcua_pubsub.ext_f2.nm_type",                        FT_UINT8,         BASE_DEC,            VALS(nm_types),   OPCUA_PUBSUB_EXT_F2_NM_TYPE,                        NULL, HFILL } },

        { &hf_opcua_pubsub_pid_uint8,                      { "PublisherId (UInt8)",                        "opcua_pubsub.pid_uint8",                             FT_UINT8,         BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_pid_uint16,                     { "PublisherId (UInt16)",                       "opcua_pubsub.pid_uint16",                            FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_pid_uint32,                     { "PublisherId (UInt32)",                       "opcua_pubsub.pid_uint32",                            FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_pid_uint64,                     { "PublisherId (UInt64)",                       "opcua_pubsub.pid_uint64",                            FT_UINT64,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_pid_string,                     { "PublisherId (String)",                       "opcua_pubsub.pid_string",                            FT_STRING,        BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_dataset_classid,                { "DataSetClassId",                             "opcua_pubsub.dataset_classid",                       FT_GUID,          BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_group_hdr_flags,                { "GroupFlags",                                 "opcua_pubsub.group_hdr.flags",                       FT_UINT8,         BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_writer_gid_enabled,   { "WriterGroupId enabled",                      "opcua_pubsub.group_hdr.flags.writer_gid_enabled",    FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_GROUP_HDR_FLAGS_WRITER_GID_ENABLED,    NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_grp_version_enabled,  { "GroupVersion enabled",                       "opcua_pubsub.group_hdr.flags.group_version_enabled", FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_GROUP_HDR_FLAGS_GROUP_VERSION_ENABLED, NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_nm_num_enabled,       { "NetworkMessageNumber enabled",               "opcua_pubsub.group_hdr.flags.nm_num_enabled",        FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_GROUP_HDR_FLAGS_NM_NUM_ENABLED,        NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_seq_num_enabled,      { "SequenceNumber enabled",                     "opcua_pubsub.group_hdr.flags.seq_num_enabled",       FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_GROUP_HDR_FLAGS_SEQ_NUM_ENABLED,       NULL, HFILL } },

        { &hf_opcua_pubsub_group_hdr_writer_gid,           { "WriterGroupId",                              "opcua_pubsub.group_hdr.writer_gid",                  FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_grp_version,          { "GroupVersion",                               "opcua_pubsub.group_hdr.group_version",               FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_nm_num,               { "NetworkMessage Number",                      "opcua_pubsub.group_hdr.nm_num",                      FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_group_hdr_seq_num,              { "Sequence Number",                            "opcua_pubsub.group_hdr.seq_num",                     FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_payload_hdr_dataset_writerid,   { "DataSetWriterId",                            "opcua_pubsub.payload_hdr.dataset_writerid",          FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_payload_hdr_dataset_msg_count,  { "Message Count",                              "opcua_pubsub.payload_hdr.ds.msg_count",              FT_UINT8,         BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_ext_nw_hdr_timestamp,           { "Timestamp (Local Time)",                     "opcua_pubsub.ext_nw_hdr.timestamp",                  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_ext_nw_hdr_picosec,             { "Picoseconds",                                "opcua_pubsub.ext_nw_hdr.picosec",                    FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_ext_nw_hdr_promfields_size,     { "Promoted Fields Size",                       "opcua_pubsub.ext_nw_hdr.promoted_size",              FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_ext_nw_hdr_promfields_fields,   { "Promoted Fields",                            "opcua_pubsub.ext_nw_hdr.promoted_fields",            FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_sec_flags,                      { "Security Flags",                             "opcua_pubsub.sec.flags",                             FT_UINT8,         BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_sec_sign_enabled,               { "Signed",                                     "opcua_pubsub.sec.flags.sign_enabled",                FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_SEC_FLAGS_SIGN_ENABLED,                NULL, HFILL } },
        { &hf_opcua_pubsub_sec_encrypt_enabled,            { "Encrypted",                                  "opcua_pubsub.sec.flags.encrypt_enabled",             FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_SEC_FLAGS_ENCRYPT_ENABLED,             NULL, HFILL } },
        { &hf_opcua_pubsub_sec_footer_enabled,             { "SecurityFooter enabled",                     "opcua_pubsub.sec.flags.sec_footer_enabled",          FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_SEC_FLAGS_SEC_FOOTER_ENABLED,          NULL, HFILL } },
        { &hf_opcua_pubsub_sec_key_reset,                  { "Force key reset",                            "opcua_pubsub.sec.flags.key_reset",                   FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_SEC_FLAGS_KEY_RESET,                   NULL, HFILL } },

        { &hf_opcua_pubsub_sec_tokenid,                    { "Security TokenId",                           "opcua_pubsub.sec.tokenid",                           FT_UINT32,        BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_sec_nonce_len,                  { "Nonce Length",                               "opcua_pubsub.sec.nonce_len",                         FT_UINT8,         BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_sec_nonce,                      { "Message Nonce",                              "opcua_pubsub.sec.nonce",                             FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_sec_footer_size,                { "Security Footer Size",                       "opcua_pubsub.sec.footer_size",                       FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_payload_enc,                    { "DataSet Payload [Encrypted]",                "opcua_pubsub.payload_enc",                           FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_sec_footer_enc,                 { "Security Footer [Encrypted]",                "opcua_pubsub.sec_footer_enc",                        FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_dsm_size,                       { "Size",                                       "opcua_pubsub.dsm_size",                              FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_dsm_f1,                         { "DataSetFlags1",                              "opcua_pubsub.dsm_f1",                                FT_UINT8,         BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_valid,                   { "DataSetMessage is valid",                    "opcua_pubsub.dsm_f1.valid",                          FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F1_VALID_ENABLED,                  NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_field_enc,               { "Field Encoding",                             "opcua_pubsub.dsm_f1.field_enc",                      FT_UINT8,         BASE_DEC,            VALS(field_encs), OPCUA_PUBSUB_DSM_F1_FIELD_ENC,                      NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_seqnum_enabled,          { "SequenceNumber enabled",                     "opcua_pubsub.dsm_f1.seqnum_enabled",                 FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F1_SEQNUM_ENABLED,                 NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_status_enabled,          { "Status enabled",                             "opcua_pubsub.dsm_f1.status_enabled",                 FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F1_STATUS_ENABLED,                 NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_conf_major_ver_enabled,  { "ConfigurationVersionMajorVersion enabled",   "opcua_pubsub.dsm_f1.conf_major_ver_enabled",         FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F1_CONF_MAJOR_VER_ENABLED,         NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_conf_minor_ver_enabled,  { "ConfigurationVersionMinorVersion enabled",   "opcua_pubsub.dsm_f1.conf_minor_ver_enabled",         FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F1_CONF_MINOR_VER_ENABLED,         NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f1_dsm_f2_enabled,          { "DataSetFlags2 enabled",                      "opcua_pubsub.dsm_f1.dsm_f2_enabled",                 FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F1_DSM_F2_ENABLED,                 NULL, HFILL } },

        { &hf_opcua_pubsub_dsm_f2,                         { "DataSetFlags2",                              "opcua_pubsub.dsm_f2",                                FT_UINT8,         BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f2_dsm_type,                { "DataSetMessage Type",                        "opcua_pubsub.dsm_f2.dsm_type",                       FT_UINT8,         BASE_DEC,            VALS(dsm_types),  OPCUA_PUBSUB_DSM_F2_DSM_TYPE,                       NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f2_timestamp_enabled,       { "DataSetMessage Timestamp enabled",           "opcua_pubsub.dsm_f2.timestamp_enabled",              FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F2_TIMESTAMP_ENABLED,              NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_f2_pico_enabled,            { "DataSetMessage Picoseconds enabled",         "opcua_pubsub.dsm_f2.pico_enabled",                   FT_BOOLEAN,       8,                   NULL,             OPCUA_PUBSUB_DSM_F2_PICO_ENABLED,                   NULL, HFILL } },

        { &hf_opcua_pubsub_dsm_seqnum,                     { "SequenceNumber",                             "opcua_pubsub.dsm_seqnum",                            FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_timestamp,                  { "Timestamp (Local Time)",                     "opcua_pubsub.dsm_timestamp",                         FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_pico,                       { "Picoseconds",                                "opcua_pubsub.dsm_pico",                              FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_status,                     { "Status",                                     "opcua_pubsub.dsm_status",                            FT_UINT16,        BASE_HEX,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_conf_major_ver,             { "ConfigurationVersion MajorVersion",          "opcua_pubsub.dsm_conf_major_ver",                    FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_conf_minor_ver,             { "ConfigurationVersion MinorVersion",          "opcua_pubsub.dsm_conf_minor_ver",                    FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_dsm_chunk_offset,               { "Chunk Offset",                               "opcua_pubsub.dsm_chunk_offset",                      FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_total_size,                 { "Total Size",                                 "opcua_pubsub.dsm_total_size",                        FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_chunk_data,                 { "Chunk Data",                                 "opcua_pubsub.dsm_chunk_data",                        FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_dsm_kf_field_count,             { "Field Count",                                "opcua_pubsub.dsm_kf.field_count",                    FT_UINT16,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_dsm_kf_rawdata,                 { "RawData",                                    "opcua_pubsub.dsm_kf.rawdata",                        FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_sec_footer,                     { "Security Footer",                            "opcua_pubsub.sec_footer",                            FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_sign,                           { "Signature",                                  "opcua_pubsub.sign",                                  FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } },

        { &hf_opcua_pubsub_fragments,                      { "NetworkMessage Chunks",                      "opcua_pubsub.chunks",                                FT_NONE,          BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment,                       { "NetworkMessage Chunk",                       "opcua_pubsub.chunk",                                 FT_FRAMENUM,      BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment_overlap,               { "NetworkMessage Chunk Overlap",               "opcua_pubsub.chunk.overlap",                         FT_BOOLEAN,       BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment_overlap_conflict,      { "NetworkMessage Chunk Overlap (conflicting)", "opcua_pubsub.chunk.overlap.conflicts",               FT_BOOLEAN,       BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment_multiple_tails,        { "NetworkMessage Chunk has multiple tails",    "opcua_pubsub.chunk.multiple_tails",                  FT_BOOLEAN,       BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment_too_long_fragment,     { "NetworkMessage Chunk too long",              "opcua_pubsub.chunk.too_long_chunk",                  FT_BOOLEAN,       BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment_error,                 { "NetworkMessage Chunk reassembly error",      "opcua_pubsub.chunk.error",                           FT_FRAMENUM,      BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_fragment_count,                 { "NetworkMessage Chunk count",                 "opcua_pubsub.chunk.count",                           FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_reassembled_in,                 { "NetworkMessage reassembled in",              "opcua_pubsub.reassembled.in",                        FT_FRAMENUM,      BASE_NONE,           NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_reassembled_length,             { "NetworkMessage reassembled length",          "opcua_pubsub.reassembled.length",                    FT_UINT32,        BASE_DEC,            NULL,             0x0,                                                NULL, HFILL } },
        { &hf_opcua_pubsub_reassembled_data,               { "NetworkMessage reassembled data",            "opcua_pubsub.reassembled.data",                      FT_BYTES,         SEP_DASH,            NULL,             0x0,                                                NULL, HFILL } }
    };

    /* Setup protocol subtree array */
    static int *ett_base[] = {
        &ett_opcua_pubsub,
        &ett_opcua_pubsub_nm_header,
        &ett_opcua_pubsub_uadp_flags,
        &ett_opcua_pubsub_ext_f1,
        &ett_opcua_pubsub_ext_f2,
        &ett_opcua_pubsub_group_hdr,
        &ett_opcua_pubsub_group_hdr_flags,
        &ett_opcua_pubsub_payload_hdr,
        &ett_opcua_pubsub_extended_nm_hdr,
        &ett_opcua_pubsub_promoted_fields,
        &ett_opcua_pubsub_sec_hdr,
        &ett_opcua_pubsub_sec_hdr_flags,
        &ett_opcua_pubsub_payload,
        &ett_opcua_pubsub_dsm,
        &ett_opcua_pubsub_dsm_f1,
        &ett_opcua_pubsub_dsm_f2,
        &ett_opcua_pubsub_keyframe,

        &ett_opcua_pubsub_fragment,
        &ett_opcua_pubsub_fragments
    };

    /* Setup expert info array */
    static ei_register_info ei[] = {
        /* id                                     abbreviation (display filter)     group         severity   summary                               EXPFILL */
        { &ei_opcua_pubsub_invalid_value,      { "opcua_pubsub.invalid_value",      PI_PROTOCOL,  PI_WARN,  "Invalid or Reserved Value",           EXPFILL } },
        { &ei_opcua_pubsub_not_implemented,    { "opcua_pubsub.not_implemented",    PI_UNDECODED, PI_WARN,  "This feature is not yet implemented", EXPFILL } },
        { &ei_opcua_pubsub_dissection_failure, { "opcua_pubsub.dissection_failure", PI_MALFORMED, PI_ERROR, "Dissection of the packet failed",     EXPFILL } }
    };

    reassembly_table_register(&opcua_pubsub_reassembly_table, &addresses_ports_reassembly_table_functions);

    /* Register the protocol full-name, short-name and filter-name */
    proto_opcua_pubsub = proto_register_protocol(
        "OPC UA PubSub UADP Binary Protocol",
        "OPC UA PubSub UADP",
        "opcua_pubsub"
    );

    /* Register expert items */
    expert_module_t *expert_opcua_pubsub = expert_register_protocol(proto_opcua_pubsub);
    expert_register_field_array(expert_opcua_pubsub, ei, array_length(ei));

    /* Register the header fields and subtrees */
    proto_register_field_array(proto_opcua_pubsub, hf_base, array_length(hf_base));
    proto_register_subtree_array(ett_base, array_length(ett_base));

    /* Register most preferences (except UDP port range) */
    module_t *opcua_pubsub_module = prefs_register_protocol(proto_opcua_pubsub, proto_reg_handoff_opcua_pubsub);
    prefs_register_uint_preference(opcua_pubsub_module, "ethertype", "Ethertype", "OPC UA PubSub Ethertype (in Hex)", 16, &opcua_pubsub_ethertype);
    prefs_register_uint_preference(opcua_pubsub_module, "llc.dsap", "LLC DSAP Address", "OPC UA PubSub LLC DSAP Address (in Hex)", 16, &opcua_pubsub_dsap);

    prefs_register_enum_preference(opcua_pubsub_module, "security_policy", "Security Policy", "OPC UA PubSub Security Policy", &security_policy, security_policies, false);
    prefs_set_preference_effect_fields(opcua_pubsub_module, "security_policy");
}

void
proto_reg_handoff_opcua_pubsub(void)
{
    static bool initialized = false;
    static dissector_handle_t opcua_pubsub_handle;
    static unsigned int prev_opcua_pubsub_ethertype;
    static unsigned int prev_opcua_pubsub_dsap;

    if (!initialized) {
        opcua_pubsub_handle = create_dissector_handle(dissect_opcua_pubsub, proto_opcua_pubsub);
        dissector_add_uint_range_with_preference("udp.port", OPCUA_PUBSUB_UDP_PORT_RANGE, opcua_pubsub_handle);
        initialized = true;
    }
    else {
        dissector_delete_uint("ethertype", prev_opcua_pubsub_ethertype, opcua_pubsub_handle);
        dissector_delete_uint("llc.dsap", prev_opcua_pubsub_dsap, opcua_pubsub_handle);
    }

    dissector_add_uint("ethertype", opcua_pubsub_ethertype, opcua_pubsub_handle);
    prev_opcua_pubsub_ethertype = opcua_pubsub_ethertype;

    dissector_add_uint("llc.dsap", opcua_pubsub_dsap, opcua_pubsub_handle);
    prev_opcua_pubsub_dsap = opcua_pubsub_dsap;
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
