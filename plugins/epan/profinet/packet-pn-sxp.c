/* packet-pn-sxp.c
 * Routines for PN-SXP packet dissection.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>

#include "packet-pn.h"

/* Register SXP protocol fields and expert info. */
void proto_register_pn_sxp(void);
/* Register SXP dissector handoffs (TCP and PN-RT heuristic). */
void proto_reg_handoff_pn_sxp(void);

#define SXP_IANA_CALLING_HOME_PORT 0x8892
#define SXP_IANA_SERVER_PORT 0x8894
#define SXP_BLOCK_TYPE_INITIATOR 0x0700
#define SXP_BLOCK_TYPE_RESPONDER 0x0701
#define SXP_ENDPOINT_ENTITY_BLOCK_TYPE 0x0003

/* protocol handles */
static int proto_pn_sxp;

static dissector_handle_t pn_sxp_handle;

/* SXP header fields */

static int hf_pn_sxp_dst_srv_access_point;
static int hf_pn_sxp_src_srv_access_point;

static int hf_pn_sxp_pdu_type;
static int hf_pn_sxp_pdu_type_type;
static int hf_pn_sxp_pdu_type_version;

static int hf_pn_sxp_add_flags;
static int hf_pn_sxp_add_flags_windowsize;
static int hf_pn_sxp_add_flags_reserved1;
static int hf_pn_sxp_add_flags_tack;
static int hf_pn_sxp_add_flags_morefrag;
static int hf_pn_sxp_add_flags_notification;
static int hf_pn_sxp_add_flags_reserved2;

static int hf_pn_sxp_send_seq_num;
static int hf_pn_sxp_ack_seq_num;
static int hf_pn_sxp_var_part_len;

static int hf_pn_sxp_block_type;
static int hf_pn_sxp_block_length;
static int hf_pn_sxp_block_version_high;
static int hf_pn_sxp_block_version_low;
static int hf_pn_sxp_arid;
static int hf_pn_sxp_priority;
static int hf_pn_sxp_fragment_flags;
static int hf_pn_sxp_fragment_flags_first;
static int hf_pn_sxp_fragment_flags_last;
static int hf_pn_sxp_fragment_flags_reserved;
static int hf_pn_sxp_call_seq_nr;
static int hf_pn_sxp_reserved;

static int hf_pn_sxp_service_block_type;
static int hf_pn_sxp_service_block_length;
static int hf_pn_sxp_service_block_version_high;
static int hf_pn_sxp_service_block_version_low;
static int hf_pn_sxp_service_reserved;
static int hf_pn_sxp_service_max_rsp_len;
static int hf_pn_sxp_service_pnio_status;

static int hf_pn_sxp_destination_endpoint;
static int hf_pn_sxp_endpoint_id;
static int hf_pn_sxp_endpoint_reserved;
static int hf_pn_sxp_vendor_id;
static int hf_pn_sxp_device_id;
static int hf_pn_sxp_instance_id;

static int hf_pn_sxp_vendor_device_error_info;
static int hf_pn_sxp_vendor_device_error_data;

static int hf_pn_sxp_station_block_type;
static int hf_pn_sxp_station_block_length;
static int hf_pn_sxp_station_block_version_high;
static int hf_pn_sxp_station_block_version_low;
static int hf_pn_sxp_station_name_length;
static int hf_pn_sxp_station_name;

static int hf_pn_sxp_rtc_frame_id;

static int hf_pn_sxp_notification_pdu;
static int hf_pn_sxp_notification_ack_pdu;
static int hf_pn_sxp_notification_block1_type;
static int hf_pn_sxp_notification_block1_length;
static int hf_pn_sxp_notification_block1_version_high;
static int hf_pn_sxp_notification_block1_version_low;
static int hf_pn_sxp_notification_block2_type;
static int hf_pn_sxp_notification_block2_length;
static int hf_pn_sxp_notification_block2_version_high;
static int hf_pn_sxp_notification_block2_version_low;
static int hf_pn_sxp_notification_data;

static int hf_pn_sxp_segments;
static int hf_pn_sxp_segment;
static int hf_pn_sxp_segment_overlap;
static int hf_pn_sxp_segment_overlap_conflict;
static int hf_pn_sxp_segment_multiple_tails;
static int hf_pn_sxp_segment_too_long_segment;
static int hf_pn_sxp_segment_error;
static int hf_pn_sxp_segment_count;
static int hf_pn_sxp_reassembled_in;
static int hf_pn_sxp_reassembled_length;

static int hf_pn_sxp_block_header;
static int hf_pn_sxp_header_req;
static int hf_pn_sxp_header_rsp;

static int hf_pn_sxp_iodconnect_req;
static int hf_pn_sxp_iodconnect_rsp;
static int hf_pn_sxp_pnservice_req_pdu;
static int hf_pn_sxp_pnservice_rsp_pdu;
static int hf_pn_sxp_alarm_notif_pdu;
static int hf_pn_sxp_alarm_ack_pdu;

/* protocol subtrees */
static int ett_pn_sxp;
static int ett_pn_sxp_pdu_type;
static int ett_pn_sxp_add_flags;
static int ett_pn_sxp_rta;
static int ett_pn_sxp_fragment_flags;
static int ett_pn_sxp_service;
static int ett_pn_sxp_block_header;
static int ett_pn_sxp_header_req;
static int ett_pn_sxp_header_rsp;
static int ett_pn_sxp_endpoint;
static int ett_pn_sxp_vendor_device_error_info;
static int ett_pn_sxp_station;
static int ett_pn_sxp_segments;
static int ett_pn_sxp_segment;
static int ett_pn_sxp_notification_pdu;
static int ett_pn_sxp_notification_ack_pdu;
static int ett_pn_sxp_iodconnect_req;
static int ett_pn_sxp_iodconnect_rsp;
static int ett_pn_sxp_pnservice_req_pdu;
static int ett_pn_sxp_pnservice_rsp_pdu;
static int ett_pn_sxp_alarm_notif_pdu;
static int ett_pn_sxp_alarm_ack_pdu;

static expert_field ei_pn_sxp_malformed;
static expert_field ei_pn_sxp_priority_range;

static reassembly_table pn_sxp_reassembly_table;

static const value_string pn_sxp_fragment_type[] = {
    { SXP_BLOCK_TYPE_INITIATOR, "AR Initiator Fragment" },
    { SXP_BLOCK_TYPE_RESPONDER, "AR Responder Fragment" },
    { 0, NULL }
};

static const value_string pn_sxp_services[] = {
    { 0x0710, "Abort AR REQ" },
    { 0x0720, "Connect REQ" },
    { 0x0721, "Read Background REQ" },
    { 0x0722, "Write Background REQ" },
    { 0x0723, "Read Security REQ" },
    { 0x0724, "Write Security REQ" },
    { 0x0725, "Read User REQ" },
    { 0x0726, "Write User REQ" },
    { 0x0727, "Read Parametrization Phase REQ" },
    { 0x0728, "Write Parametrization Phase REQ" },
    { 0x0729, "Control Parametrization Phase REQ" },
    { 0x072A, "Alarm High REQ" },
    { 0x072B, "Alarm Low REQ" },
    { 0x072C, "Notification REQ" },
    { 0x072D, "IO Data REQ" },
    { 0x0740, "Real-Time Cyclic Input Data" },
    { 0x0741, "Real-Time Cyclic Output Data" },
    { 0x0815, "Record Service SXP EPI Read" },
    { 0x0816, "Record Service CIM Cap Read" },
    { 0x8720, "Connect RSP" },
    { 0x8721, "Read Background RSP" },
    { 0x8722, "Write Background RSP" },
    { 0x8723, "Read Security RSP" },
    { 0x8724, "Write Security RSP" },
    { 0x8725, "Read User RSP" },
    { 0x8726, "Write User RSP" },
    { 0x8727, "Read Parametrization Phase RSP" },
    { 0x8728, "Write Parametrization Phase RSP" },
    { 0x8729, "Control Parametrization Phase RSP" },
    { 0x872A, "Alarm High Ack" },
    { 0x872B, "Alarm Low Ack" },
    { 0x872C, "Notification Ack" },
    { 0x872D, "Reserved RSP" },
    { 0x8740, "SXP EndPoint Information" },
    { 0, NULL }
};

static const value_string pn_sxp_priority_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Background Read / Write" },
    { 0x02, "Security Read / Write" },
    { 0x03, "User Read / Write" },
    { 0x04, "AR control" },
    { 0x05, "Alarm low" },
    { 0x06, "Notification" },
    { 0x07, "Alarm high" },
    { 0x08, "IO data" },
    { 0x09, "Management" },
    { 0, NULL }
};

static const value_string pn_sxp_endpoint_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "CIM endpoint" },
    { 0x02, "IOC endpoint" },
    { 0x03, "IOD endpoint" },
    { 0, NULL }
};

static const range_string pn_sxp_alarm_endpoint_vals[] = {
    { 0x0000, 0x7FFF, "Reserved" },
    { 0x8000, 0x8891, "Reserved for well-known server SAPs" },
    { SXP_IANA_CALLING_HOME_PORT, SXP_IANA_CALLING_HOME_PORT, "PNIO_SXP_CallingHome_Server" },
    { 0x8893, 0x8893, "Reserved for well-known server RSAPs" },
    { SXP_IANA_SERVER_PORT, SXP_IANA_SERVER_PORT, "PNIO_SXP_Server" },
    { 0x8895, 0xBFFF, "Reserved for well-known server SAPs" },
    { 0xC000, 0xFFFE, "ISAP_Range (Initiator Service Access Points)" },
    { 0xFFFF, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const value_string pn_sxp_rta_pdu_type_vals[] = {
    { 0x01, "DATA-RTA-PDU" },
    { 0x02, "NACK-RTA-PDU" },
    { 0x03, "ACK-RTA-PDU" },
    { 0x04, "ERR-RTA-PDU" },
    { 0, NULL }
};

static const fragment_items pn_sxp_frag_items = {
    &ett_pn_sxp_segment,
    &ett_pn_sxp_segments,
    &hf_pn_sxp_segments,
    &hf_pn_sxp_segment,
    &hf_pn_sxp_segment_overlap,
    &hf_pn_sxp_segment_overlap_conflict,
    &hf_pn_sxp_segment_multiple_tails,
    &hf_pn_sxp_segment_too_long_segment,
    &hf_pn_sxp_segment_error,
    &hf_pn_sxp_segment_count,
    &hf_pn_sxp_reassembled_in,
    &hf_pn_sxp_reassembled_length,
    NULL,
    "segments"
};

/* Register the reassembly table for SXP payload fragments. */
/* Initialize the SXP reassembly table. */
static void
pn_sxp_reassemble_init(void)
{
    reassembly_table_register(&pn_sxp_reassembly_table, &addresses_reassembly_table_functions);
}

/* Validate the SXP fragment header to avoid false positives. */
static bool
pn_sxp_heuristic_check(tvbuff_t *tvb, int offset, int remaining, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type;
    uint16_t block_length;
    uint16_t arid;
    uint8_t  priority;
    uint8_t  flags;
    uint8_t  reserved;
    int      total_len;

    if (remaining < 12) {
        return false;
    }

    block_type = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (block_type != SXP_BLOCK_TYPE_INITIATOR && block_type != SXP_BLOCK_TYPE_RESPONDER) {
        return false;
    }

    block_length = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
    if (block_length < 8) {
        return false;
    }

    total_len = block_length + 4;
    if (total_len > remaining) {
        return false;
    }

    arid = tvb_get_uint16(tvb, offset + 6, ENC_BIG_ENDIAN);
    if (arid == 0x0000 || arid > 0xEFFF) {
        return false;
    }

    priority = tvb_get_uint8(tvb, offset + 8);
    if (priority > 9) {
        if (tree) {
            expert_add_info_format(pinfo, tree, &ei_pn_sxp_priority_range,
                "SXP priority out of range: %u", priority);
        }
        return false;
    }

    flags = tvb_get_uint8(tvb, offset + 9);
    if (flags & 0x01) {
        return false;
    }

    /* SXP_FragmentFlags Bits 2-7 shall be set to zero */
    if (flags & 0xF8) {
        return false;
    }

    reserved = tvb_get_uint8(tvb, offset + 11);
    if (reserved != 0x00) {
        return false;
    }

    return true;
}

/*
 * ============================================================================
 * SXP Service Layer Dissection Functions
 * Based on PROFINET SXP Service Layer specification (Table 303-310)
 * ============================================================================
 */

/* Dissect SXP BlockHeader: BlockType(2) + BlockLength(2) + BlockVersionHigh(1) + BlockVersionLow(1) = 6 bytes */
static int
dissect_sxp_block_header(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree,
                         uint16_t *block_type, uint16_t *block_length)
{
    proto_item *header_item;
    proto_tree *header_tree;

    header_item = proto_tree_add_item(tree, hf_pn_sxp_block_header, tvb, offset, 6, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_pn_sxp_block_header);

    proto_tree_add_item_ret_uint16(header_tree, hf_pn_sxp_service_block_type, tvb, offset, 2,
        ENC_BIG_ENDIAN, block_type);
    proto_tree_add_item_ret_uint16(header_tree, hf_pn_sxp_service_block_length, tvb, offset + 2, 2,
        ENC_BIG_ENDIAN, block_length);
    proto_tree_add_item(header_tree, hf_pn_sxp_service_block_version_high, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(header_tree, hf_pn_sxp_service_block_version_low, tvb, offset + 5, 1, ENC_BIG_ENDIAN);

    return offset + 6;
}

/* Dissect SXP-Header-REQ: BlockHeader + Reserved(2) + MaxRspLength(4) = 12 bytes total */
static int
dissect_sxp_header_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                       uint16_t *block_type, uint16_t *block_length, uint32_t *max_rsp_len)
{
    proto_item *header_req_item;
    proto_tree *header_req_tree;
    uint16_t reserved16;
    proto_item *reserved_item;

    header_req_item = proto_tree_add_item(tree, hf_pn_sxp_header_req, tvb, offset, 12, ENC_NA);
    header_req_tree = proto_item_add_subtree(header_req_item, ett_pn_sxp_header_req);

    offset = dissect_sxp_block_header(tvb, offset, pinfo, header_req_tree, block_type, block_length);

    reserved_item = proto_tree_add_item_ret_uint16(header_req_tree, hf_pn_sxp_service_reserved, tvb, offset, 2,
        ENC_BIG_ENDIAN, &reserved16);
    if (reserved16 != 0) {
        expert_add_info_format(pinfo, reserved_item, &ei_pn_sxp_malformed,
            "Service reserved field non-zero: 0x%04x", reserved16);
    }
    offset += 2;

    proto_tree_add_item_ret_uint(header_req_tree, hf_pn_sxp_service_max_rsp_len, tvb, offset, 4,
        ENC_BIG_ENDIAN, max_rsp_len);
    offset += 4;

    return offset;
}

/* Dissect SXP-Header-RSP: BlockHeader + Reserved(2) + PNIOStatus(4) = 12 bytes total */
static int
dissect_sxp_header_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                       uint16_t *block_type, uint16_t *block_length)
{
    proto_item *header_rsp_item;
    proto_tree *header_rsp_tree;
    uint16_t reserved16;
    proto_item *reserved_item;
    uint8_t drep[4] = { 0, 0, 0, 0 };

    header_rsp_item = proto_tree_add_item(tree, hf_pn_sxp_header_rsp, tvb, offset, 12, ENC_NA);
    header_rsp_tree = proto_item_add_subtree(header_rsp_item, ett_pn_sxp_header_rsp);

    offset = dissect_sxp_block_header(tvb, offset, pinfo, header_rsp_tree, block_type, block_length);

    reserved_item = proto_tree_add_item_ret_uint16(header_rsp_tree, hf_pn_sxp_service_reserved, tvb, offset, 2,
        ENC_BIG_ENDIAN, &reserved16);
    if (reserved16 != 0) {
        expert_add_info_format(pinfo, reserved_item, &ei_pn_sxp_malformed,
            "Service reserved field non-zero: 0x%04x", reserved16);
    }
    offset += 2;

    proto_tree_add_item(header_rsp_tree, hf_pn_sxp_service_pnio_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    dissect_PNIO_status(tvb, offset, pinfo, header_rsp_tree, drep);
    offset += 4;

    return offset;
}

/* Dissect SXP-Destination-Endpoint: EndPointID(1) + Reserved(1) + VendorID(2) + DeviceID(2) + InstanceID(2) = 8 bytes */
static int
dissect_sxp_destination_endpoint(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item *endpoint_item;
    proto_tree *endpoint_tree;
    uint8_t endpoint_reserved;
    proto_item *endpoint_reserved_item;

    endpoint_item = proto_tree_add_item(parent_tree, hf_pn_sxp_destination_endpoint, tvb, offset, 8, ENC_NA);
    endpoint_tree = proto_item_add_subtree(endpoint_item, ett_pn_sxp_endpoint);

    proto_tree_add_item(endpoint_tree, hf_pn_sxp_endpoint_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    endpoint_reserved_item = proto_tree_add_item_ret_uint8(endpoint_tree, hf_pn_sxp_endpoint_reserved,
        tvb, offset + 1, 1, ENC_BIG_ENDIAN, &endpoint_reserved);
    if (endpoint_reserved != 0) {
        expert_add_info_format(pinfo, endpoint_reserved_item, &ei_pn_sxp_malformed,
            "Endpoint reserved field non-zero: 0x%02x", endpoint_reserved);
    }

    proto_tree_add_item(endpoint_tree, hf_pn_sxp_vendor_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(endpoint_tree, hf_pn_sxp_device_id, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(endpoint_tree, hf_pn_sxp_instance_id, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

    return offset + 8;
}

/* Dissect all PNIO blocks within SXP service PDUs
 * All PNIO blocks (including SXP-specific) are handled by dissect_blocks() from packet-dcerpc-pn-io.c. */
static int
dissect_sxp_pnio_blocks(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint8_t drep[4] = { 0, 0, 0, 0 };

    /* dissect_blocks handles all block types in a loop */
    offset = dissect_blocks(tvb, offset, pinfo, tree, drep);

    return offset;
}

/* Dissect SXP-Connect-REQ: SXP-Header-REQ + SXP-Destination-Endpoint + IODConnectReq */
static int
dissect_sxp_connect_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint32_t max_rsp_len;
    proto_item *req_item;
    proto_tree *req_tree;
    int start_offset;

    offset = dissect_sxp_header_req(tvb, offset, pinfo, tree, &block_type, &block_length, &max_rsp_len);
    offset = dissect_sxp_destination_endpoint(tvb, offset, pinfo, tree);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        start_offset = offset;
        req_item = proto_tree_add_item(tree, hf_pn_sxp_iodconnect_req, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        req_tree = proto_item_add_subtree(req_item, ett_pn_sxp_iodconnect_req);
        offset = dissect_sxp_pnio_blocks(tvb, offset, pinfo, req_tree);
        proto_item_set_len(req_item, offset - start_offset);
    }

    return offset;
}

/* Dissect SXP-Connect-RSP: SXP-Header-RSP + [IODConnectRsp] */
static int
dissect_sxp_connect_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    proto_item *rsp_item;
    proto_tree *rsp_tree;
    int start_offset;

    offset = dissect_sxp_header_rsp(tvb, offset, pinfo, tree, &block_type, &block_length);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        start_offset = offset;
        rsp_item = proto_tree_add_item(tree, hf_pn_sxp_iodconnect_rsp, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        rsp_tree = proto_item_add_subtree(rsp_item, ett_pn_sxp_iodconnect_rsp);
        offset = dissect_sxp_pnio_blocks(tvb, offset, pinfo, rsp_tree);
        proto_item_set_len(rsp_item, offset - start_offset);
    }

    return offset;
}

/* Dissect SXP-PNService-REQ: SXP-Header-REQ + PROFINETIOServiceReqPDU */
static int
dissect_sxp_pnservice_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint32_t max_rsp_len;
    uint8_t  drep[4] = { 0, 0, 0, 0 }; /* Big-Endian, no DCE/RPC */
    proto_item *pdu_item;
    proto_tree *pdu_tree;
    int start_offset;

    offset = dissect_sxp_header_req(tvb, offset, pinfo, tree, &block_type, &block_length, &max_rsp_len);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        start_offset = offset;
        pdu_item = proto_tree_add_item(tree, hf_pn_sxp_pnservice_req_pdu, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        pdu_tree = proto_item_add_subtree(pdu_item, ett_pn_sxp_pnservice_req_pdu);
        offset = dissect_blocks(tvb, offset, pinfo, pdu_tree, drep);
        proto_item_set_len(pdu_item, offset - start_offset);
    }

    return offset;
}

/* Dissect SXP-PNService-RSP: SXP-Header-RSP + [PROFINETIOServiceRspPDU] */
static int
dissect_sxp_pnservice_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint8_t  drep[4] = { 0, 0, 0, 0 }; /* Big-Endian, no DCE/RPC */
    proto_item *pdu_item;
    proto_tree *pdu_tree;
    int start_offset;

    offset = dissect_sxp_header_rsp(tvb, offset, pinfo, tree, &block_type, &block_length);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        start_offset = offset;
        pdu_item = proto_tree_add_item(tree, hf_pn_sxp_pnservice_rsp_pdu, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        pdu_tree = proto_item_add_subtree(pdu_item, ett_pn_sxp_pnservice_rsp_pdu);
        offset = dissect_blocks(tvb, offset, pinfo, pdu_tree, drep);
        proto_item_set_len(pdu_item, offset - start_offset);
    }

    return offset;
}

/* Dissect SXP-Alarm-REQ: SXP-Header-REQ + AlarmNotification-PDU */
static int
dissect_sxp_alarm_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint32_t max_rsp_len;
    uint8_t  drep[4] = { 0, 0, 0, 0 }; /* Big-Endian, no DCE/RPC */
    proto_item *pdu_item;
    proto_tree *pdu_tree;
    int start_offset;

    offset = dissect_sxp_header_req(tvb, offset, pinfo, tree, &block_type, &block_length, &max_rsp_len);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        start_offset = offset;
        pdu_item = proto_tree_add_item(tree, hf_pn_sxp_alarm_notif_pdu, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        pdu_tree = proto_item_add_subtree(pdu_item, ett_pn_sxp_alarm_notif_pdu);
        offset = dissect_blocks(tvb, offset, pinfo, pdu_tree, drep);
        proto_item_set_len(pdu_item, offset - start_offset);
    }

    return offset;
}

/* Dissect SXP-Alarm-RSP: SXP-Header-RSP + AlarmAck-PDU */
static int
dissect_sxp_alarm_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint8_t  drep[4] = { 0, 0, 0, 0 }; /* Big-Endian, no DCE/RPC */
    proto_item *pdu_item;
    proto_tree *pdu_tree;
    int start_offset;

    offset = dissect_sxp_header_rsp(tvb, offset, pinfo, tree, &block_type, &block_length);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        start_offset = offset;
        pdu_item = proto_tree_add_item(tree, hf_pn_sxp_alarm_ack_pdu, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        pdu_tree = proto_item_add_subtree(pdu_item, ett_pn_sxp_alarm_ack_pdu);
        offset = dissect_blocks(tvb, offset, pinfo, pdu_tree, drep);
        proto_item_set_len(pdu_item, offset - start_offset);
    }

    return offset;
}

/* Dissect SXP-Notification-PDU: BlockHeader + BlockHeader + Data* */
static int
dissect_sxp_notification_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item *pdu_item;
    proto_tree *pdu_tree;
    int start_offset = offset;
    int remaining;

    remaining = tvb_captured_length_remaining(tvb, offset);
    if (remaining < 12) {
        /* Not enough data for two BlockHeaders */
        if (remaining > 0) {
            offset = dissect_pn_user_data(tvb, offset, pinfo, parent_tree, remaining, "NotificationData");
        }
        return offset;
    }

    pdu_item = proto_tree_add_item(parent_tree, hf_pn_sxp_notification_pdu, tvb, offset, remaining, ENC_NA);
    pdu_tree = proto_item_add_subtree(pdu_item, ett_pn_sxp_notification_pdu);

    /* First BlockHeader */
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_version_high, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_version_low, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
    offset += 6;

    /* Second BlockHeader */
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_version_high, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_version_low, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
    offset += 6;

    /* Data* */
    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_data, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    proto_item_set_len(pdu_item, offset - start_offset);
    return offset;
}

/* Dissect SXP-NotificationAck-PDU: BlockHeader + BlockHeader + Data* */
static int
dissect_sxp_notification_ack_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item *pdu_item;
    proto_tree *pdu_tree;
    int start_offset = offset;
    int remaining;

    remaining = tvb_captured_length_remaining(tvb, offset);
    if (remaining < 12) {
        /* Not enough data for two BlockHeaders */
        if (remaining > 0) {
            offset = dissect_pn_user_data(tvb, offset, pinfo, parent_tree, remaining, "NotificationAckData");
        }
        return offset;
    }

    pdu_item = proto_tree_add_item(parent_tree, hf_pn_sxp_notification_ack_pdu, tvb, offset, remaining, ENC_NA);
    pdu_tree = proto_item_add_subtree(pdu_item, ett_pn_sxp_notification_ack_pdu);

    /* First BlockHeader */
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_version_high, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block1_version_low, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
    offset += 6;

    /* Second BlockHeader */
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_version_high, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_block2_version_low, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
    offset += 6;

    /* Data* */
    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(pdu_tree, hf_pn_sxp_notification_data, tvb, offset,
            tvb_captured_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    proto_item_set_len(pdu_item, offset - start_offset);
    return offset;
}

/* Dissect SXP-Notification-REQ: SXP-Header-REQ + SXP-Notification-PDU */
static int
dissect_sxp_notification_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint32_t max_rsp_len;

    offset = dissect_sxp_header_req(tvb, offset, pinfo, tree, &block_type, &block_length, &max_rsp_len);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        offset = dissect_sxp_notification_pdu(tvb, offset, pinfo, tree);
    }

    return offset;
}

/* Dissect SXP-Notification-RSP: SXP-Header-RSP + SXP-NotificationAck-PDU */
static int
dissect_sxp_notification_rsp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;

    offset = dissect_sxp_header_rsp(tvb, offset, pinfo, tree, &block_type, &block_length);

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        offset = dissect_sxp_notification_ack_pdu(tvb, offset, pinfo, tree);
    }

    return offset;
}

/* Dissect SXP-IOData-REQ: SXP-Header-REQ + SXP-RTC-PDU */
static int
dissect_sxp_iodata_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint32_t max_rsp_len;
    uint16_t rtc_block_type, rtc_block_length;

    offset = dissect_sxp_header_req(tvb, offset, pinfo, tree, &block_type, &block_length, &max_rsp_len);

    /* SXP-RTC-PDU: BlockHeader + FrameID + RTC-PDU */
    if (tvb_captured_length_remaining(tvb, offset) >= 6) {
        offset = dissect_sxp_block_header(tvb, offset, pinfo, tree, &rtc_block_type, &rtc_block_length);
    }

    if (tvb_captured_length_remaining(tvb, offset) >= 2) {
        proto_tree_add_item(tree, hf_pn_sxp_rtc_frame_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        offset = dissect_pn_user_data(tvb, offset, pinfo, tree,
            tvb_captured_length_remaining(tvb, offset), "RTC-PDU");
    }

    return offset;
}

/* Dissect SXP-Abort-REQ: SXP-Header-REQ + Reserved(1) + Reserved(1) + PNIOStatus + [VendorDeviceErrorInfo] */
static int
dissect_sxp_abort_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type, block_length;
    uint32_t max_rsp_len;
    uint8_t drep[4] = { 0, 0, 0, 0 };

    offset = dissect_sxp_header_req(tvb, offset, pinfo, tree, &block_type, &block_length, &max_rsp_len);

    /* Reserved(1) */
    if (tvb_captured_length_remaining(tvb, offset) >= 1) {
        proto_tree_add_item(tree, hf_pn_sxp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    /* Reserved(1) */
    if (tvb_captured_length_remaining(tvb, offset) >= 1) {
        proto_tree_add_item(tree, hf_pn_sxp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    /* PNIOStatus */
    if (tvb_captured_length_remaining(tvb, offset) >= 4) {
        proto_tree_add_item(tree, hf_pn_sxp_service_pnio_status, tvb, offset, 4, ENC_BIG_ENDIAN);
        dissect_PNIO_status(tvb, offset, pinfo, tree, drep);
        offset += 4;
    }

    /* VendorDeviceErrorInfo (optional, max 64 bytes) */
    if (tvb_captured_length_remaining(tvb, offset) >= 4) {
        proto_item *error_info_item;
        proto_tree *error_info_tree;
        int remaining = tvb_captured_length_remaining(tvb, offset);
        int error_info_len = MIN(remaining, 64);
        int start_offset = offset;

        error_info_item = proto_tree_add_item(tree, hf_pn_sxp_vendor_device_error_info, tvb, offset, error_info_len, ENC_NA);
        error_info_tree = proto_item_add_subtree(error_info_item, ett_pn_sxp_vendor_device_error_info);

        proto_tree_add_item(error_info_tree, hf_pn_sxp_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(error_info_tree, hf_pn_sxp_device_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        offset += 4;

        if (tvb_captured_length_remaining(tvb, offset) > 0 && offset - start_offset < 64) {
            int data_len = tvb_captured_length_remaining(tvb, offset);
            if (data_len > 60) data_len = 60;
            proto_tree_add_item(error_info_tree, hf_pn_sxp_vendor_device_error_data, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
    }

    return offset;
}

/* Get the SXP service name for subtree display (e.g., "SXP-Connect-REQ") */
static const char*
get_sxp_service_name(uint16_t block_type)
{
    switch (block_type) {
    case 0x0710:
        return "SXP-Abort-AR-REQ";
    case 0x0720:
        return "SXP-Connect-REQ";
    case 0x0721:
    case 0x0722:
    case 0x0723:
    case 0x0724:
    case 0x0725:
    case 0x0726:
    case 0x0727:
    case 0x0728:
    case 0x0729:
        return "SXP-PNService-REQ";
    case 0x072A:
    case 0x072B:
        return "SXP-Alarm-REQ";
    case 0x072C:
        return "SXP-Notification-REQ";
    case 0x072D:
        return "SXP-IOData-REQ";
    case 0x0740:
        return "SXP-Real-Time-Cyclic-Input-Data";
    case 0x0741:
        return "SXP-Real-Time-Cyclic-Output-Data";
    case 0x0815:
        return "SXP-Record-Service-EPI-Read";
    case 0x0816:
        return "SXP-Record-Service-CIM-Cap-Read";
    case 0x8720:
        return "SXP-Connect-RSP";
    case 0x8721:
    case 0x8722:
    case 0x8723:
    case 0x8724:
    case 0x8725:
    case 0x8726:
    case 0x8727:
    case 0x8728:
    case 0x8729:
        return "SXP-PNService-RSP";
    case 0x872A:
    case 0x872B:
        return "SXP-Alarm-Ack";
    case 0x872C:
        return "SXP-Notification-Ack";
    case 0x872D:
        return "SXP-Reserved-RSP";
    case 0x8740:
        return "SXP-EndPoint-Information";
    default:
        return "SXP-Unknown-Service";
    }
}

/*
 * ============================================================================
 * Main SXP Service Payload Dissector
 * ============================================================================
 */

/* Dissect an SXP service header and its payload. */
static int
dissect_sxp_service_payload(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_type;
    proto_tree *service_tree;
    bool is_response;
    int remaining;
    const char *service_name;

    remaining = tvb_captured_length_remaining(tvb, offset);
    if (remaining < 12) {
        return offset;
    }

    block_type = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    is_response = (block_type & 0x8000) != 0;
    service_name = get_sxp_service_name(block_type);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
        val_to_str(pinfo->pool, block_type, pn_sxp_services, "Service 0x%04x"));

    /* Create service-specific subtree with service name */
    service_tree = proto_tree_add_subtree_format(tree, tvb, offset, remaining,
        ett_pn_sxp_service, NULL, "%s", service_name);

    switch (block_type) {
    /* ===== REQUEST Services (0x07xx) ===== */
    case 0x0710: /* Abort AR REQ */
        offset = dissect_sxp_abort_req(tvb, offset, pinfo, service_tree);
        break;

    case 0x0720: /* Connect REQ */
        offset = dissect_sxp_connect_req(tvb, offset, pinfo, service_tree);
        break;

    case 0x0721: /* Read Background REQ */
    case 0x0722: /* Write Background REQ */
    case 0x0723: /* Read Security REQ */
    case 0x0724: /* Write Security REQ */
    case 0x0725: /* Read User REQ */
    case 0x0726: /* Write User REQ */
    case 0x0727: /* Read Parametrization Phase REQ */
    case 0x0728: /* Write Parametrization Phase REQ */
    case 0x0729: /* Control Parametrization Phase REQ */
        offset = dissect_sxp_pnservice_req(tvb, offset, pinfo, service_tree);
        break;

    case 0x072A: /* Alarm High REQ */
    case 0x072B: /* Alarm Low REQ */
        offset = dissect_sxp_alarm_req(tvb, offset, pinfo, service_tree);
        break;

    case 0x072C: /* Notification REQ */
        offset = dissect_sxp_notification_req(tvb, offset, pinfo, service_tree);
        break;

    case 0x072D: /* IO Data REQ */
        offset = dissect_sxp_iodata_req(tvb, offset, pinfo, service_tree);
        break;

    case 0x0740: /* Real-Time Cyclic Input Data */
    case 0x0741: /* Real-Time Cyclic Output Data */
        offset = dissect_sxp_iodata_req(tvb, offset, pinfo, service_tree);
        break;

    /* ===== RESPONSE Services (0x87xx) ===== */
    case 0x8720: /* Connect RSP */
        offset = dissect_sxp_connect_rsp(tvb, offset, pinfo, service_tree);
        break;

    case 0x8721: /* Read Background RSP */
    case 0x8722: /* Write Background RSP */
    case 0x8723: /* Read Security RSP */
    case 0x8724: /* Write Security RSP */
    case 0x8725: /* Read User RSP */
    case 0x8726: /* Write User RSP */
    case 0x8727: /* Read Parametrization Phase RSP */
    case 0x8728: /* Write Parametrization Phase RSP */
    case 0x8729: /* Control Parametrization Phase RSP */
        offset = dissect_sxp_pnservice_rsp(tvb, offset, pinfo, service_tree);
        break;

    case 0x872A: /* Alarm High Ack */
    case 0x872B: /* Alarm Low Ack */
        offset = dissect_sxp_alarm_rsp(tvb, offset, pinfo, service_tree);
        break;

    case 0x872C: /* Notification Ack */
        offset = dissect_sxp_notification_rsp(tvb, offset, pinfo, service_tree);
        break;

    case 0x872D: /* Reserved RSP */
    case 0x8740: /* SXP EndPoint Information */
        offset = dissect_sxp_pnservice_rsp(tvb, offset, pinfo, service_tree);
        break;

    default:
        /* Unknown service - dissect as generic */
        {
            uint16_t block_length;
            uint32_t max_rsp_len;
            if (is_response) {
                offset = dissect_sxp_header_rsp(tvb, offset, pinfo, service_tree, &block_type, &block_length);
            } else {
                offset = dissect_sxp_header_req(tvb, offset, pinfo, service_tree, &block_type, &block_length, &max_rsp_len);
            }

            if (tvb_captured_length_remaining(tvb, offset) > 0) {
                offset = dissect_pn_user_data(tvb, offset, pinfo, service_tree,
                    tvb_captured_length_remaining(tvb, offset), "ServiceData");
            }
        }
        break;
    }

    return offset;
}

/* Dissect a fully reassembled SXP service APDU. */
static int
dissect_sxp_reassembled_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_sxp_service_payload(tvb, 0, pinfo, tree);

    return tvb_captured_length(tvb);
}

/* Dissect a single SXP fragment and manage reassembly. */
static int
dissect_sxp_packet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t block_length;
    uint16_t arid;
    uint8_t call_seq;
    uint8_t flags;
    bool is_last;
    proto_item *sxp_item;
    proto_tree *sxp_tree;
    int remaining;
    int total_len;
    int payload_offset;
    tvbuff_t *payload_tvb;
    fragment_head *fd_reass;
    bool update_col_info = true;

    remaining = tvb_captured_length_remaining(tvb, offset);
    if (!pn_sxp_heuristic_check(tvb, offset, remaining, pinfo, tree)) {
        return offset + remaining;
    }

    block_length = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
    total_len = block_length + 4;

    sxp_item = proto_tree_add_protocol_format(tree, proto_pn_sxp, tvb, offset, total_len,
        "PROFINET SXP");
    sxp_tree = proto_item_add_subtree(sxp_item, ett_pn_sxp);

    proto_tree_add_item(sxp_tree, hf_pn_sxp_block_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sxp_tree, hf_pn_sxp_block_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sxp_tree, hf_pn_sxp_block_version_high, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sxp_tree, hf_pn_sxp_block_version_low, tvb, offset + 5, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint16(sxp_tree, hf_pn_sxp_arid, tvb, offset + 6, 2,
        ENC_BIG_ENDIAN, &arid);
    proto_tree_add_item(sxp_tree, hf_pn_sxp_priority, tvb, offset + 8, 1, ENC_BIG_ENDIAN);

    {
        proto_item *flags_item = proto_tree_add_item_ret_uint8(sxp_tree, hf_pn_sxp_fragment_flags,
            tvb, offset + 9, 1, ENC_BIG_ENDIAN, &flags);
        proto_tree *flags_tree = proto_item_add_subtree(flags_item, ett_pn_sxp_fragment_flags);
        const bool is_first_flag = (flags & 0x02) != 0;
        const bool is_last_flag = (flags & 0x04) != 0;

        proto_tree_add_item(flags_tree, hf_pn_sxp_fragment_flags_reserved, tvb, offset + 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_pn_sxp_fragment_flags_first, tvb, offset + 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_pn_sxp_fragment_flags_last, tvb, offset + 9, 1, ENC_BIG_ENDIAN);

        if ((flags & 0x01) || (flags & 0xF8)) {
            expert_add_info_format(pinfo, flags_item, &ei_pn_sxp_malformed,
                "Reserved fragment flags set: 0x%02x", flags);
        }

        if (is_first_flag && is_last_flag) {
            proto_item_append_text(flags_item, " (Single Fragment)");
        } else if (is_first_flag) {
            proto_item_append_text(flags_item, " (First Fragment)");
        } else if (is_last_flag) {
            proto_item_append_text(flags_item, " (Last Fragment)");
        } else {
            proto_item_append_text(flags_item, " (Middle Fragment)");
        }
    }

    proto_tree_add_item_ret_uint8(sxp_tree, hf_pn_sxp_call_seq_nr, tvb, offset + 10, 1,
        ENC_BIG_ENDIAN, &call_seq);
    {
        uint8_t header_reserved;
        proto_item *header_reserved_item = proto_tree_add_item_ret_uint8(sxp_tree, hf_pn_sxp_reserved,
            tvb, offset + 11, 1, ENC_BIG_ENDIAN, &header_reserved);
        if (header_reserved != 0) {
            expert_add_info_format(pinfo, header_reserved_item, &ei_pn_sxp_malformed,
                "Header reserved field non-zero: 0x%02x", header_reserved);
        }
    }

    payload_offset = offset + 12;
    payload_tvb = tvb_new_subset_length(tvb, payload_offset, total_len - 12);

    is_last = (flags & 0x04) != 0;

    if ((flags & 0x02) && is_last) {
        dissect_sxp_reassembled_payload(payload_tvb, pinfo, sxp_tree);
        return offset + total_len;
    }

    if (!pinfo->fd->visited) {
        uint32_t reassembly_id = ((uint32_t)arid << 16) | call_seq;

        fragment_add_seq_next(&pn_sxp_reassembly_table, payload_tvb, 0, pinfo,
            reassembly_id, NULL, tvb_captured_length(payload_tvb), !is_last);
    }

    fd_reass = fragment_get_reassembled_id(&pn_sxp_reassembly_table, pinfo,
        ((uint32_t)arid << 16) | call_seq);

    if (fd_reass != NULL && pinfo->fd->num == fd_reass->reassembled_in) {
        tvbuff_t *reass_tvb = process_reassembled_data(tvb, offset, pinfo,
            "Reassembled SXP packet", fd_reass, &pn_sxp_frag_items, &update_col_info, sxp_tree);
        if (reass_tvb) {
            dissect_sxp_reassembled_payload(reass_tvb, pinfo, sxp_tree);
        }
    } else {
        if (fd_reass != NULL) {
            proto_item *pi = proto_tree_add_uint(sxp_tree, hf_pn_sxp_reassembled_in,
                tvb, 0, 0, fd_reass->reassembled_in);
            proto_item_set_generated(pi);
        }
        if ((flags & 0x02) && tvb_captured_length(payload_tvb) >= 12) {
            dissect_sxp_reassembled_payload(payload_tvb, pinfo, sxp_tree);
        }
    }

    return offset + total_len;
}

/* Walk a buffer and dissect one or more concatenated SXP packets. */
static int
dissect_sxp_from_offset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    int remaining = tvb_captured_length_remaining(tvb, offset);

    while (remaining >= 12) {
        int start_offset = offset;
        uint16_t block_length = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
        int total_len = block_length + 4;

        if (!pn_sxp_heuristic_check(tvb, offset, remaining, pinfo, tree)) {
            break;
        }

        if (total_len <= 0 || total_len > remaining) {
            break;
        }

        offset = dissect_sxp_packet(tvb, offset, pinfo, tree);
        if (offset <= start_offset) {
            break;
        }
        remaining = tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}

/* Dissect RTAv3 DATA-RTA-PDU and extract SXP over Layer 2. */
static int
dissect_sxp_rta_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    uint16_t dst_sap;
    uint16_t src_sap;
    uint8_t pdu_type;
    uint8_t pdu_type_type;
    uint8_t pdu_type_version;
    uint16_t var_part_len;
    int remaining;
    int payload_len;
    int payload_offset;
    proto_item *dst_sap_item;
    proto_item *src_sap_item;
    proto_item *rta_item;
    proto_tree *rta_tree;
    proto_item *pdu_type_item;
    proto_tree *pdu_type_tree;
    proto_item *add_flags_item;
    proto_tree *add_flags_tree;

    if (tvb_captured_length(tvb) < 12) {
        return 0;
    }

    rta_item = proto_tree_add_protocol_format(tree, proto_pn_sxp, tvb, 0,
        tvb_captured_length(tvb), "RTA Header");
    rta_tree = proto_item_add_subtree(rta_item, ett_pn_sxp_rta);

    /* Reference (DSAP, SSAP) */
    dst_sap_item = proto_tree_add_item_ret_uint16(rta_tree, hf_pn_sxp_dst_srv_access_point,
        tvb, offset, 2, ENC_BIG_ENDIAN, &dst_sap);
    proto_item_append_text(dst_sap_item, " (%s)",
        rval_to_str_const(dst_sap, pn_sxp_alarm_endpoint_vals, "Unknown"));
    offset += 2;
    src_sap_item = proto_tree_add_item_ret_uint16(rta_tree, hf_pn_sxp_src_srv_access_point,
        tvb, offset, 2, ENC_BIG_ENDIAN, &src_sap);
    proto_item_append_text(src_sap_item, " (%s)",
        rval_to_str_const(src_sap, pn_sxp_alarm_endpoint_vals, "Unknown"));
    offset += 2;

    pdu_type_item = proto_tree_add_item_ret_uint8(rta_tree, hf_pn_sxp_pdu_type, tvb, offset, 1,
        ENC_BIG_ENDIAN, &pdu_type);
    pdu_type_tree = proto_item_add_subtree(pdu_type_item, ett_pn_sxp_pdu_type);
    proto_tree_add_item(pdu_type_tree, hf_pn_sxp_pdu_type_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pdu_type_tree, hf_pn_sxp_pdu_type_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    pdu_type_type = pdu_type & 0x0F;
    pdu_type_version = (pdu_type >> 4) & 0x0F;
    offset += 1;

    if (pdu_type_version != 0x03) {
        return 0;
    }

    add_flags_item = proto_tree_add_item(rta_tree, hf_pn_sxp_add_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    add_flags_tree = proto_item_add_subtree(add_flags_item, ett_pn_sxp_add_flags);
    proto_tree_add_item(add_flags_tree, hf_pn_sxp_add_flags_windowsize, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(add_flags_tree, hf_pn_sxp_add_flags_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(add_flags_tree, hf_pn_sxp_add_flags_tack, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(add_flags_tree, hf_pn_sxp_add_flags_morefrag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(add_flags_tree, hf_pn_sxp_add_flags_notification, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(add_flags_tree, hf_pn_sxp_add_flags_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(rta_tree, hf_pn_sxp_send_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(rta_tree, hf_pn_sxp_ack_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint16(rta_tree, hf_pn_sxp_var_part_len, tvb, offset, 2,
        ENC_BIG_ENDIAN, &var_part_len);
    offset += 2;

    remaining = tvb_captured_length_remaining(tvb, offset);

    payload_len = 0;
    switch (pdu_type_type) {
    case 0x01: /* DATA */
    case 0x04: /* ERR */
        if (var_part_len > 0) {
            payload_len = var_part_len;
            if (payload_len > remaining) {
                expert_add_info_format(pinfo, rta_item, &ei_pn_sxp_malformed,
                    "VarPartLen (%u) exceeds remaining bytes (%d)",
                    var_part_len, remaining);
                payload_len = remaining;
            }
        }
        break;
    case 0x02: /* NACK */
    case 0x03: /* ACK */
        payload_len = 0;
        break;
    default:
        return 0;
    }

    if (payload_len == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
            val_to_str_const(pdu_type_type, pn_sxp_rta_pdu_type_vals, "Unknown RTA-PDU"));
        return offset;
    }

    if (pdu_type_type == 0x04) {
        uint8_t drep[4] = { 0, 0, 0, 0 };

        if (payload_len >= 4) {
            proto_tree_add_item(rta_tree, hf_pn_sxp_service_pnio_status, tvb, offset, 4, ENC_BIG_ENDIAN);
            dissect_PNIO_status(tvb, offset, pinfo, rta_tree, drep);
        }
        return offset + payload_len;
    }

    payload_offset = offset;

    if (payload_len >= 6) {
        uint16_t block_type = tvb_get_uint16(tvb, payload_offset, ENC_BIG_ENDIAN);
        if (block_type == SXP_ENDPOINT_ENTITY_BLOCK_TYPE) {
            uint16_t block_length = tvb_get_uint16(tvb, payload_offset + 2, ENC_BIG_ENDIAN);
            int total_len = block_length + 4;

            int station_len = total_len;

            if (station_len > payload_len) {
                station_len = payload_len;
            }

            proto_item *station_item = proto_tree_add_item(tree, hf_pn_sxp_station_block_type,
                tvb, payload_offset, station_len, ENC_BIG_ENDIAN);
            proto_tree *station_tree = proto_item_add_subtree(station_item, ett_pn_sxp_station);

            proto_tree_add_item(station_tree, hf_pn_sxp_station_block_type, tvb, payload_offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(station_tree, hf_pn_sxp_station_block_length, tvb, payload_offset + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(station_tree, hf_pn_sxp_station_block_version_high, tvb, payload_offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(station_tree, hf_pn_sxp_station_block_version_low, tvb, payload_offset + 5, 1, ENC_BIG_ENDIAN);

            if (total_len > 6 && tvb_captured_length_remaining(tvb, payload_offset + 6) > 0) {
                uint8_t name_len;
                proto_tree_add_item_ret_uint8(station_tree, hf_pn_sxp_station_name_length,
                    tvb, payload_offset + 6, 1, ENC_BIG_ENDIAN, &name_len);
                if (name_len > 0 && tvb_captured_length_remaining(tvb, payload_offset + 7) >= name_len) {
                    proto_tree_add_item(station_tree, hf_pn_sxp_station_name, tvb, payload_offset + 7,
                        name_len, ENC_ASCII);
                }
            }

            if (total_len > 0 && total_len <= payload_len) {
                payload_offset += total_len;
            }
        }
    }

    if (payload_offset < offset + payload_len) {
        tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, offset, payload_len);
        dissect_sxp_from_offset(payload_tvb, payload_offset - offset, pinfo, tree);
    }

    return offset + payload_len;
}

/* Heuristic dissector for SXP over PN-RT (FrameID 0xFE03). */
static bool
dissect_pn_sxp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t frame_id = GPOINTER_TO_UINT(data);

    if (frame_id != 0xFE03) {
        return false;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-SXP");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "SXP over RTAv3");

    if (dissect_sxp_rta_pdu(tvb, pinfo, tree) <= 0) {
        return false;
    }

    return true;
}

static unsigned
get_pn_sxp_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint16_t block_length;

    block_length = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
    return (unsigned)block_length + 4;
}

static int
dissect_pn_sxp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dissect_sxp_packet(tvb, 0, pinfo, tree);
    return tvb_reported_length(tvb);
}

/* Port-based TCP dissector entry point for SXP. */
static int
dissect_pn_sxp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-SXP");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "SXP over TCP");

    tcp_dissect_pdus(tvb, pinfo, tree, true, 4, get_pn_sxp_tcp_pdu_len,
        dissect_pn_sxp_tcp_pdu, data);

    return tvb_reported_length(tvb);
}

/* Heuristic dissector for SXP over TCP (used if port-based dissection does not apply). */
static bool
dissect_pn_sxp_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int remaining = tvb_captured_length(tvb);

    if (!pn_sxp_heuristic_check(tvb, 0, remaining, pinfo, tree)) {
        return false;
    }

    dissect_pn_sxp_tcp(tvb, pinfo, tree, NULL);
    return true;
}

/* Register SXP protocol fields, trees, and expert info. */
void
proto_register_pn_sxp(void)
{
    static hf_register_info hf[] = {
        { &hf_pn_sxp_dst_srv_access_point,
            { "DestinationServiceAccessPoint", "pn_sxp.dst_srv_access_point",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_src_srv_access_point,
            { "SourceServiceAccessPoint", "pn_sxp.src_srv_access_point",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_pdu_type,
            { "PDUType", "pn_sxp.pdu_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_pdu_type_type,
            { "Type", "pn_sxp.pdu_type.type",
            FT_UINT8, BASE_HEX, VALS(pn_sxp_rta_pdu_type_vals), 0x0F,
            NULL, HFILL }},

        { &hf_pn_sxp_pdu_type_version,
            { "Version", "pn_sxp.pdu_type.version",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags,
            { "AddFlags", "pn_sxp.add_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags_windowsize,
            { "WindowSize", "pn_sxp.add_flags.windowsize",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags_reserved1,
            { "Reserved", "pn_sxp.add_flags.reserved1",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags_tack,
            { "TACK", "pn_sxp.add_flags.tack",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags_morefrag,
            { "MoreFrag", "pn_sxp.add_flags.morefrag",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags_notification,
            { "Notification", "pn_sxp.add_flags.notification",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }},

        { &hf_pn_sxp_add_flags_reserved2,
            { "Reserved", "pn_sxp.add_flags.reserved2",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }},

        { &hf_pn_sxp_send_seq_num,
            { "SendSeqNum", "pn_sxp.send_seq_num",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_ack_seq_num,
            { "AckSeqNum", "pn_sxp.ack_seq_num",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_var_part_len,
            { "VarPartLen", "pn_sxp.var_part_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_block_type,
          { "BlockType", "pn_sxp.block_type",
            FT_UINT16, BASE_HEX, VALS(pn_sxp_fragment_type), 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_block_length,
          { "BlockLength", "pn_sxp.block_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_block_version_high,
            { "BlockVersionHigh", "pn_sxp.block_version_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_block_version_low,
            { "BlockVersionLow", "pn_sxp.block_version_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_arid,
          { "SXP_ARID", "pn_sxp.arid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_priority,
          { "SXP_Priority", "pn_sxp.priority",
            FT_UINT8, BASE_DEC, VALS(pn_sxp_priority_vals), 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_fragment_flags,
          { "SXP_FragmentFlags", "pn_sxp.fragment_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_fragment_flags_reserved,
          { "Reserved", "pn_sxp.fragment_flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }},

        { &hf_pn_sxp_fragment_flags_first,
          { "FirstFragment", "pn_sxp.fragment_flags.first",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }},

        { &hf_pn_sxp_fragment_flags_last,
          { "LastFragment", "pn_sxp.fragment_flags.last",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }},

        { &hf_pn_sxp_call_seq_nr,
          { "SXP_CallSequenceNr", "pn_sxp.call_seq_nr",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_reserved,
          { "Reserved", "pn_sxp.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_block_type,
          { "BlockType", "pn_sxp.service.block_type",
            FT_UINT16, BASE_HEX, VALS(pn_sxp_services), 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_block_length,
          { "BlockLength", "pn_sxp.service.block_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_block_version_high,
          { "BlockVersionHigh", "pn_sxp.service.block_version_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_block_version_low,
          { "BlockVersionLow", "pn_sxp.service.block_version_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_reserved,
          { "Reserved", "pn_sxp.service.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_max_rsp_len,
          { "MaxRspLength", "pn_sxp.service.max_rsp_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_service_pnio_status,
          { "PNIOStatus", "pn_sxp.service.pnio_status",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_destination_endpoint,
          { "SXP-Destination-Endpoint", "pn_sxp.destination_endpoint",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_endpoint_id,
          { "SXP_EndPointID", "pn_sxp.endpoint.id",
            FT_UINT8, BASE_HEX, VALS(pn_sxp_endpoint_vals), 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_endpoint_reserved,
          { "Reserved", "pn_sxp.endpoint.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_vendor_id,
          { "VendorID", "pn_sxp.vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_device_id,
          { "DeviceID", "pn_sxp.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_instance_id,
          { "InstanceID", "pn_sxp.instance_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_vendor_device_error_info,
          { "VendorDeviceErrorInfo", "pn_sxp.vendor_device_error_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_vendor_device_error_data,
          { "Data", "pn_sxp.vendor_device_error_info.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_station_block_type,
          { "BlockType", "pn_sxp.station.block_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_station_block_length,
          { "BlockLength", "pn_sxp.station.block_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_station_block_version_high,
          { "BlockVersionHigh", "pn_sxp.station.block_version_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_station_block_version_low,
          { "BlockVersionLow", "pn_sxp.station.block_version_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_station_name_length,
          { "StationNameLength", "pn_sxp.station.name_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_station_name,
          { "StationName", "pn_sxp.station.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_rtc_frame_id,
          { "FrameID", "pn_sxp.rtc.frame_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_segment,
          { "SXP Segment", "pn_sxp.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_segments,
          { "PN SXP Segments", "pn_sxp.segments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_segment_overlap,
          { "Segment overlap", "pn_sxp.segment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }},

        { &hf_pn_sxp_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "pn_sxp.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL }},

        { &hf_pn_sxp_segment_multiple_tails,
          { "Multiple tail segments found", "pn_sxp.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the packet", HFILL }},

        { &hf_pn_sxp_segment_too_long_segment,
          { "Segment too long", "pn_sxp.segment.toolongsegment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of packet", HFILL }},

        { &hf_pn_sxp_segment_error,
          { "Reassembly error", "pn_sxp.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembly error due to illegal segments", HFILL }},

        { &hf_pn_sxp_segment_count,
          { "Segment count", "pn_sxp.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_reassembled_in,
          { "Reassembled pn_sxp in frame", "pn_sxp.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This pn_sxp packet is reassembled in this frame", HFILL }},

        { &hf_pn_sxp_reassembled_length,
          { "Reassembled pn_sxp length", "pn_sxp.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        { &hf_pn_sxp_notification_pdu,
          { "SXP-Notification-PDU", "pn_sxp.notification_pdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_ack_pdu,
          { "SXP-NotificationAck-PDU", "pn_sxp.notification_ack_pdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block1_type,
          { "BlockType (1)", "pn_sxp.notification.block1_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block1_length,
          { "BlockLength (1)", "pn_sxp.notification.block1_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block1_version_high,
          { "BlockVersionHigh (1)", "pn_sxp.notification.block1_version_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block1_version_low,
          { "BlockVersionLow (1)", "pn_sxp.notification.block1_version_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block2_type,
          { "BlockType (2)", "pn_sxp.notification.block2_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block2_length,
          { "BlockLength (2)", "pn_sxp.notification.block2_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block2_version_high,
          { "BlockVersionHigh (2)", "pn_sxp.notification.block2_version_high",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_block2_version_low,
          { "BlockVersionLow (2)", "pn_sxp.notification.block2_version_low",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_notification_data,
          { "NotificationData", "pn_sxp.notification.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_block_header,
          { "BlockHeader", "pn_sxp.block_header",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "SXP Block Header", HFILL }},

        { &hf_pn_sxp_header_req,
          { "SXP-Header-REQ", "pn_sxp.header_req",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "SXP Request Header", HFILL }},

        { &hf_pn_sxp_header_rsp,
          { "SXP-Header-RSP", "pn_sxp.header_rsp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "SXP Response Header", HFILL }},

        { &hf_pn_sxp_iodconnect_req,
          { "IODConnectReq", "pn_sxp.iodconnect_req",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_iodconnect_rsp,
          { "IODConnectRsp", "pn_sxp.iodconnect_rsp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_pnservice_req_pdu,
          { "PROFINETIOServiceReqPDU", "pn_sxp.pnservice_req_pdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_pnservice_rsp_pdu,
          { "PROFINETIOServiceRspPDU", "pn_sxp.pnservice_rsp_pdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_alarm_notif_pdu,
          { "AlarmNotification-PDU", "pn_sxp.alarm_notif_pdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_sxp_alarm_ack_pdu,
          { "AlarmAck-PDU", "pn_sxp.alarm_ack_pdu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

    };

    static int *ett[] = {
        &ett_pn_sxp,
        &ett_pn_sxp_pdu_type,
        &ett_pn_sxp_add_flags,
        &ett_pn_sxp_rta,
        &ett_pn_sxp_fragment_flags,
        &ett_pn_sxp_service,
        &ett_pn_sxp_block_header,
        &ett_pn_sxp_header_req,
        &ett_pn_sxp_header_rsp,
        &ett_pn_sxp_endpoint,
        &ett_pn_sxp_vendor_device_error_info,
        &ett_pn_sxp_station,
        &ett_pn_sxp_segments,
        &ett_pn_sxp_segment,
        &ett_pn_sxp_notification_pdu,
        &ett_pn_sxp_notification_ack_pdu,
        &ett_pn_sxp_iodconnect_req,
        &ett_pn_sxp_iodconnect_rsp,
        &ett_pn_sxp_pnservice_req_pdu,
        &ett_pn_sxp_pnservice_rsp_pdu,
        &ett_pn_sxp_alarm_notif_pdu,
        &ett_pn_sxp_alarm_ack_pdu
    };

    static ei_register_info ei[] = {
        { &ei_pn_sxp_malformed, { "pn_sxp.malformed", PI_MALFORMED, PI_ERROR, "Malformed SXP", EXPFILL }},
        { &ei_pn_sxp_priority_range, { "pn_sxp.priority.invalid", PI_PROTOCOL, PI_WARN, "Priority out of range", EXPFILL }}
    };

    expert_module_t *expert_pn_sxp;

    proto_pn_sxp = proto_register_protocol("PROFINET SXP", "PN-SXP", "pn_sxp");
    pn_sxp_handle = register_dissector("pn_sxp", dissect_pn_sxp_tcp, proto_pn_sxp);

    proto_register_field_array(proto_pn_sxp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pn_sxp = expert_register_protocol(proto_pn_sxp);
    expert_register_field_array(expert_pn_sxp, ei, array_length(ei));

    register_init_routine(pn_sxp_reassemble_init);
}

/* Register SXP dissector with TCP ports and PN-RT heuristics. */
void
proto_reg_handoff_pn_sxp(void)
{
    dissector_add_uint_with_preference("tcp.port", SXP_IANA_SERVER_PORT, pn_sxp_handle);
    dissector_add_uint_with_preference("tcp.port", SXP_IANA_CALLING_HOME_PORT, pn_sxp_handle);
    heur_dissector_add("pn_rt", dissect_pn_sxp_heur, "PROFINET SXP", "pn_sxp_pn_rt", proto_pn_sxp, HEURISTIC_ENABLE);
    heur_dissector_add("tcp", dissect_pn_sxp_tcp_heur, "PROFINET SXP", "pn_sxp_tcp", proto_pn_sxp, HEURISTIC_ENABLE);
}
