/* packet-uavcan-can.c
 * Routines for dissection of UAVCAN/CAN
 *
 * Copyright 2020-2021 NXP
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <inttypes.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/proto_data.h>
#include <epan/crc16-tvb.h>

#include "packet-socketcan.h"
#include "packet-uavcan-dsdl.h"

#define ANONYMOUS_FLAG 0x8000
#define BROADCAST_FLAG 0x4000
#define ADDR_MASK 0XFF

#define START_OF_TRANSFER 0x80
#define END_OF_TRANSFER 0x40
#define TOGGLE 0x20
#define TRANSFER_ID 0x1F

#define UAVCAN_SUBJECT_ID(can_id) ((can_id & 0x001FFF00) >> 8)
#define UAVCAN_SERVICE_ID(can_id) ((can_id & 0x007FC000) >> 14)
#define UAVCAN_DESTINATION_ID(can_id) ((can_id & 0x00003F80) >> 7)
#define UAVCAN_SOURCE_ID(can_id) ((can_id & 0x0000007F))
#define UAVCAN_IS_SERVICE(can_id) ((can_id & 0x2000000) != 0)
#define UAVCAN_IS_MESSAGE(can_id) ((can_id & 0x2000000) == 0)
#define UAVCAN_IS_REQUEST(can_id) ((can_id & 0x01000000) != 0)
#define UAVCAN_IS_RESPONSE(can_id) ((can_id & 0x01000000) == 0)
#define UAVCAN_IS_ANONYMOUS(can_id) ((can_id & 0x01000000) != 0)

struct uavcan_proto_data
{
    uint32_t seq_id;
    bool toggle_error;
};

void proto_register_uavcan(void);
void proto_reg_handoff_uavcan(void);

static dissector_handle_t uavcan_handle;

static int proto_uavcan;

static int hf_uavcan_can_id;
static int hf_uavcan_priority;
static int hf_uavcan_anonymous;
static int hf_uavcan_req_not_rsp;
static int hf_uavcan_serv_not_msg;
static int hf_uavcan_subject_id;
static int hf_uavcan_service_id;
static int hf_uavcan_dst_addr;
static int hf_uavcan_src_addr;
static int hf_uavcan_data;
static int hf_uavcan_start_of_transfer;
static int hf_uavcan_end_of_transfer;
static int hf_uavcan_toggle;
static int hf_uavcan_transfer_id;

static int uavcan_address_type = -1;

static wmem_tree_t *fragment_info_table;

static reassembly_table uavcan_reassembly_table;

static int hf_uavcan_packet_crc;

static int ett_uavcan;
static int ett_uavcan_can;
static int ett_uavcan_message;

static expert_field ei_uavcan_toggle_bit_error;
static expert_field ei_uavcan_transfer_crc_error;

static int ett_uavcan_fragment;
static int ett_uavcan_fragments;
static int hf_uavcan_fragments;
static int hf_uavcan_fragment;
static int hf_uavcan_fragment_overlap;
static int hf_uavcan_fragment_overlap_conflicts;
static int hf_uavcan_fragment_multiple_tails;
static int hf_uavcan_fragment_too_long_fragment;
static int hf_uavcan_fragment_error;
static int hf_uavcan_fragment_count;
static int hf_uavcan_reassembled_in;
static int hf_uavcan_reassembled_length;

/* fragment struct to store packet assembly data */
typedef struct _fragment_info_t
{
    int toggle;
    int fragment_id;
    uint32_t seq_id;
} fragment_info_t;

uint32_t uavcan_seq_id;

static const fragment_items uavcan_frag_items = {
    /* Fragment subtrees */
    &ett_uavcan_fragment,
    &ett_uavcan_fragments,

    /* Fragment fields */
    &hf_uavcan_fragments,
    &hf_uavcan_fragment,
    &hf_uavcan_fragment_overlap,
    &hf_uavcan_fragment_overlap_conflicts,
    &hf_uavcan_fragment_multiple_tails,
    &hf_uavcan_fragment_too_long_fragment,
    &hf_uavcan_fragment_error,

    &hf_uavcan_fragment_count,

    /* Reassembled in field */
    &hf_uavcan_reassembled_in,

    /* Reassembled length field */
    &hf_uavcan_reassembled_length,

    /* Reassembled data field */
    NULL,

    /* Tag */
    "Message fragments"
};

static dissector_handle_t dsdl_message_handle;
static dissector_handle_t dsdl_request_handle;
static dissector_handle_t dsdl_response_handle;

static const value_string uavcan_priority_vals[] = {
    {  0, "Exceptional" },
    {  1, "Immediate"   },
    {  2, "Fast"        },
    {  3, "High"        },
    {  4, "Nominal"     },
    {  5, "Low"         },
    {  6, "Slow"        },
    {  7, "Optional"    },
    {  0, NULL          }
};

static int
dissect_uavcan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti, *toggle, *transfer_crc;
    proto_tree *uavcan_tree, *can_id_tree, *can_data_tree, *dsdl_tree;

    int offset = 0;
    struct can_info can_info;
    uint16_t *src_addr, *dest_addr;
    uint8_t tail_byte;
    fragment_info_t *fragment_info = NULL;
    unsigned reported_length;
    uint32_t lookup_id = 0;

    /* Semi-unique lookup id for reassembly lookup table note transfer-ID rolls-over every 32 times  */

    reported_length = tvb_reported_length(tvb);

    DISSECTOR_ASSERT(data);
    can_info = *((struct can_info *) data);

    tail_byte = tvb_get_uint8(tvb, reported_length - 1);

    if ((can_info.id & CAN_ERR_FLAG) ||
        !(can_info.id & CAN_EFF_FLAG)) {
        /* Error frames and frames with standards ids are not for us */
        return 0;
    }

    if ((tail_byte & (START_OF_TRANSFER | TOGGLE)) ==
        (START_OF_TRANSFER)) {
        /* UAVCAN v0 Frame */
        return 0;
    }

    if ((tail_byte & (START_OF_TRANSFER | END_OF_TRANSFER)) !=
        (START_OF_TRANSFER | END_OF_TRANSFER)) { /* Multi-frame */
        if (UAVCAN_IS_MESSAGE(can_info.id)) { /* Message */
            lookup_id  = 0; // Bit 0 false indicates message
            lookup_id |= UAVCAN_SUBJECT_ID(can_info.id) << 1;
            lookup_id |= UAVCAN_SOURCE_ID(can_info.id)  << 11;
            lookup_id |= (tail_byte & TRANSFER_ID)      << 18;
        } else { /* Service */
            lookup_id = 1; // Bit 0 true indicates service
            lookup_id |= ((can_info.id & 0x01000000) >> 24) << 1;
            lookup_id |= UAVCAN_SERVICE_ID(can_info.id)     << 2;
            lookup_id |= UAVCAN_DESTINATION_ID(can_info.id) << 11;
            lookup_id |= UAVCAN_SOURCE_ID(can_info.id)      << 18;
            lookup_id |= (tail_byte & TRANSFER_ID)          << 25;
        }

        fragment_info = (fragment_info_t *) wmem_tree_lookup32(fragment_info_table, lookup_id);

        if (!(tail_byte & START_OF_TRANSFER) && fragment_info == NULL) {
            /* Lookup id doesn't exist, but not a start of transfer discard potentially a UAVCANv0 frame */
            return 0;
        }
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UAVCAN/CAN");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_uavcan, tvb, offset, reported_length, ENC_NA);
    uavcan_tree = proto_item_add_subtree(ti, ett_uavcan);

    can_id_tree = proto_tree_add_subtree_format(uavcan_tree, tvb, 0, 0,
                                                ett_uavcan_can, &ti, "CAN ID field: 0x%08x",
                                                can_info.id);
    proto_item_set_generated(ti);

    ti = proto_tree_add_uint(can_id_tree, hf_uavcan_can_id, tvb, 0, 0, can_info.id);
    proto_item_set_generated(ti);

    /* Dissect UAVCAN/CAN Message frame */
    if (UAVCAN_IS_MESSAGE(can_info.id)) {
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_priority, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_serv_not_msg, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_anonymous, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_subject_id, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_src_addr, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);

        /* Set source address */
        src_addr = wmem_new(pinfo->pool, uint16_t);
        *src_addr = (uint16_t) UAVCAN_SOURCE_ID(can_info.id);

        if (UAVCAN_IS_ANONYMOUS(can_info.id)) {
            *src_addr |= ANONYMOUS_FLAG;
        }

        set_address(&pinfo->src, uavcan_address_type, 2, (const void *) src_addr);

        /* Fill in "destination" address even if its "broadcast" */
        dest_addr = wmem_new(pinfo->pool, uint16_t);
        *dest_addr = BROADCAST_FLAG;
        set_address(&pinfo->dst, uavcan_address_type, 2, (const void *) dest_addr);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Message: %d (%s)", UAVCAN_SUBJECT_ID(can_info.id),
                     rval_to_str_const(UAVCAN_SUBJECT_ID(can_info.id), uavcan_subject_id_vals, "Reserved"));
    } else { /* UAVCAN/CAN Service frame */
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_priority, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_serv_not_msg, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_req_not_rsp, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_service_id, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_dst_addr, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_id_tree, hf_uavcan_src_addr, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);

        /* Set source address */
        src_addr = wmem_new(pinfo->pool, uint16_t);
        *src_addr = (uint16_t) UAVCAN_SOURCE_ID(can_info.id);
        set_address(&pinfo->src, uavcan_address_type, 2, (const void *) src_addr);

        dest_addr = wmem_new(pinfo->pool, uint16_t);
        *dest_addr = (uint16_t) UAVCAN_DESTINATION_ID(can_info.id);
        set_address(&pinfo->dst, uavcan_address_type, 2, (const void *) dest_addr);
        if (UAVCAN_IS_RESPONSE(can_info.id)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Service response: %d (%s)", UAVCAN_SERVICE_ID(can_info.id),
                         rval_to_str_const(UAVCAN_SERVICE_ID(can_info.id), uavcan_service_id_vals, "Reserved"));
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Service request: %d (%s)", UAVCAN_SERVICE_ID(can_info.id),
                         rval_to_str_const(UAVCAN_SERVICE_ID(can_info.id), uavcan_service_id_vals, "Reserved"));
        }
    }

    can_data_tree = proto_tree_add_subtree(uavcan_tree, tvb, 0, -1, ett_uavcan_message, NULL, "CAN data field");

    proto_tree_add_item(can_data_tree, hf_uavcan_start_of_transfer, tvb,
                        reported_length - 1, 1, ENC_NA);
    proto_tree_add_item(can_data_tree, hf_uavcan_end_of_transfer, tvb,
                        reported_length - 1, 1, ENC_NA);
    toggle = proto_tree_add_item(can_data_tree, hf_uavcan_toggle, tvb,
                                 reported_length - 1, 1, ENC_NA);
    proto_tree_add_item(can_data_tree, hf_uavcan_transfer_id, tvb,
                        reported_length - 1, 1, ENC_NA);
    proto_tree_add_item(can_data_tree, hf_uavcan_data, tvb, 0, reported_length - 1,
                        ENC_NA);

    if ((tail_byte & (START_OF_TRANSFER | END_OF_TRANSFER)) ==
        (START_OF_TRANSFER | END_OF_TRANSFER)) { /* Single frame */
        dsdl_tree = proto_tree_add_subtree(uavcan_tree, tvb, 0, tvb_reported_length(
                                               tvb) - 1, ett_uavcan_message, NULL, "");
        tvb_set_reported_length(tvb, reported_length - 1); /* Don't pass Tail byte to DSDL */

        if (UAVCAN_IS_MESSAGE(can_info.id)) {
            uint32_t id;
            id = UAVCAN_SUBJECT_ID(can_info.id);
            proto_item_append_text(dsdl_tree, "Message");
            call_dissector_with_data(dsdl_message_handle, tvb, pinfo, dsdl_tree,
                                     GUINT_TO_POINTER((unsigned) id));
        } else if (UAVCAN_IS_SERVICE(can_info.id)) {
            uint32_t id;
            id = UAVCAN_SERVICE_ID(can_info.id);

            if (UAVCAN_IS_REQUEST(can_info.id)) {
                proto_item_append_text(dsdl_tree, "Service request");
                call_dissector_with_data(dsdl_request_handle, tvb, pinfo, dsdl_tree, GUINT_TO_POINTER(
                                             (unsigned) id));
            } else {
                proto_item_append_text(dsdl_tree, "Service response");
                call_dissector_with_data(dsdl_response_handle, tvb, pinfo, dsdl_tree, GUINT_TO_POINTER(
                                             (unsigned) id));
            }
        }
    }

    /* Re-assembly attempt */

    if ((tail_byte & (START_OF_TRANSFER | END_OF_TRANSFER)) !=
        (START_OF_TRANSFER | END_OF_TRANSFER)) { /* Multi-frame */
        struct uavcan_proto_data *uavcan_frame_data;

        if (!PINFO_FD_VISITED(pinfo)) { /* Not visited */
            if (fragment_info == NULL) { /* Doesn't exist, allocate lookup_id */
                fragment_info = (fragment_info_t *) wmem_new(wmem_file_scope(), fragment_info_t);
                fragment_info->fragment_id = 0;
                fragment_info->toggle = tail_byte & TOGGLE;

                wmem_tree_insert32(fragment_info_table, lookup_id, fragment_info);
            }

            /* Store sequence number and status in pinfo so we can revisit later */
            uavcan_frame_data =
                wmem_new0(wmem_file_scope(), struct uavcan_proto_data);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_uavcan, 0, uavcan_frame_data);

            if ((tail_byte & START_OF_TRANSFER) != 0) { /* Start of transfer */
                uavcan_frame_data->toggle_error = 0;
                fragment_info->fragment_id = 0;
                fragment_info->seq_id = uavcan_seq_id;
                uavcan_seq_id += 1;
            } else { /* Update transfer */
                fragment_info->fragment_id += 1;
                uavcan_frame_data->toggle_error =
                    ((tail_byte & TOGGLE) == fragment_info->toggle) ? true : false;
            }

            uavcan_frame_data->seq_id = fragment_info->seq_id;

            fragment_info->toggle = tail_byte & TOGGLE;

            pinfo->fragmented = true;
            fragment_add_seq_check(&uavcan_reassembly_table,
                                   tvb, offset, pinfo, fragment_info->seq_id, NULL, /* ID for fragments belonging together */
                                   fragment_info->fragment_id, /* fragment sequence number */
                                   tvb_captured_length_remaining(tvb, offset) - 1, /* fragment length - minus tail byte */
                                   ((tail_byte & END_OF_TRANSFER) == 0) ? true : false); /* More fragments? */
        } else { /* Visited reassembled data */
            fragment_head *reassembled = NULL;
            tvbuff_t *reassembled_tvb;
            proto_tree *multi_tree;

            uavcan_frame_data = (struct uavcan_proto_data *) p_get_proto_data(
                wmem_file_scope(), pinfo, proto_uavcan, 0);

            reassembled = fragment_get_reassembled_id(&uavcan_reassembly_table, pinfo,
                                                      uavcan_frame_data->seq_id);

            if (reassembled) {
                if (uavcan_frame_data->toggle_error == 1) {
                    expert_add_info_format(pinfo, toggle, &ei_uavcan_toggle_bit_error,
                                           "Expected Toggle %u got %u.",
                                           !((tail_byte & TOGGLE) != 0),
                                           ((tail_byte & TOGGLE) != 0));
                }

                col_append_str(pinfo->cinfo, COL_INFO,
                               " (Multi-frame)");

                reassembled_tvb = tvb_new_chain(tvb, reassembled->tvb_data); /* Reassembled tvb chain */

                multi_tree = proto_tree_add_subtree(uavcan_tree, reassembled_tvb, 0,
                                                    -1, ett_uavcan_message, NULL,
                                                    "Multi-frame");

                process_reassembled_data(tvb, offset, pinfo,
                                         "Reassembled Message", reassembled, &uavcan_frag_items,
                                         NULL, multi_tree);

                /* Parsing reassembled data */
                if ((tail_byte & END_OF_TRANSFER) != 0) {
                    transfer_crc = proto_tree_add_item(multi_tree, hf_uavcan_packet_crc,
                                                       reassembled_tvb,
                                                       tvb_reported_length(reassembled_tvb) - 2,
                                                       2, ENC_BIG_ENDIAN);

                    uint16_t packet_crc = tvb_get_uint16(reassembled_tvb,
                                                         tvb_reported_length(reassembled_tvb) - 2,
                                                         ENC_BIG_ENDIAN);
                    uint16_t calc_crc = crc16_x25_ccitt_tvb(reassembled_tvb,
                                                   tvb_reported_length(reassembled_tvb) - 2);

                    if (packet_crc != calc_crc) {
                        expert_add_info_format(pinfo, transfer_crc, &ei_uavcan_transfer_crc_error,
                                               "Expected CRC16 %X got %X.",
                                               calc_crc, packet_crc);
                    }

                    tvb_set_reported_length(reassembled_tvb, tvb_reported_length(reassembled_tvb) - 2); /* Don't pass CRC16 to DSDL */

                    dsdl_tree = proto_tree_add_subtree(uavcan_tree, reassembled_tvb, 0,
                                                       -1, ett_uavcan_message, NULL, "");

                    /* Pass payload to DSDL dissector */
                    if (UAVCAN_IS_MESSAGE(can_info.id)) {
                        uint32_t id = UAVCAN_SUBJECT_ID(can_info.id);
                        proto_item_append_text(dsdl_tree, "Message");

                        call_dissector_with_data(dsdl_message_handle, reassembled_tvb, pinfo,
                                                 dsdl_tree,
                                                 GUINT_TO_POINTER((unsigned) id));
                    } else if (UAVCAN_IS_SERVICE(can_info.id)) {
                        uint32_t id = UAVCAN_SERVICE_ID(can_info.id);

                        if (UAVCAN_IS_REQUEST(can_info.id)) {
                            proto_item_append_text(dsdl_tree, "Service request");
                            call_dissector_with_data(dsdl_request_handle, reassembled_tvb, pinfo,
                                                     dsdl_tree, GUINT_TO_POINTER((unsigned) id));
                        } else {
                            proto_item_append_text(dsdl_tree, "Service response");
                            call_dissector_with_data(dsdl_response_handle, reassembled_tvb, pinfo,
                                                     dsdl_tree, GUINT_TO_POINTER((unsigned) id));
                        }
                    }
                }
            }
        }
    }

    return tvb_captured_length(tvb);
}

static int
UAVCAN_addr_to_str(const address *addr, char *buf, int buf_len)
{
    const uint16_t *addrdata = (const uint16_t *) addr->data;

    if ((*addrdata & ANONYMOUS_FLAG) != 0) {
        return (int) snprintf(buf, buf_len, "Anonymous");
    } else if ((*addrdata & BROADCAST_FLAG) != 0) {
        return (int) snprintf(buf, buf_len, "Broadcast");
    } else {
        uint8_t real_addr = (uint8_t) (*addrdata & ADDR_MASK);
        guint32_to_str_buf(real_addr, buf, buf_len);
        return (int) strlen(buf);
    }
}

static int
UAVCAN_addr_str_len(const address *addr _U_)
{
    return 12; /* Leaves required space (10 bytes) for uint_to_str_back() */
}

static const char *
UAVCAN_col_filter_str(const address *addr _U_, bool is_src)
{
    if (is_src)
        return "uavcan_can.src_addr";

    return "uavcan_can.dst_addr";
}

static int
UAVCAN_addr_len(void)
{
    return 2;
}

void
proto_register_uavcan(void)
{
    static hf_register_info hf[] = {
        {&hf_uavcan_can_id,
           {"CAN Identifier",                                    "uavcan_can.can_id",
           FT_UINT32, BASE_HEX, NULL, CAN_EFF_MASK, NULL, HFILL}},
        {&hf_uavcan_priority,
           {"Priority",                                          "uavcan_can.priority",
           FT_UINT32, BASE_DEC, VALS(uavcan_priority_vals), 0x1C000000, NULL, HFILL}},
        {&hf_uavcan_serv_not_msg,
           {"Service, not message",                              "uavcan_can.serv_not_msg",
           FT_UINT32, BASE_DEC, NULL, 0x02000000, NULL, HFILL}},
        {&hf_uavcan_anonymous,
           {"Anonymous",                                         "uavcan_can.anonymous",
           FT_UINT32, BASE_DEC, NULL, 0x01000000, NULL, HFILL}},
        {&hf_uavcan_req_not_rsp,
           {"Request, not response",                             "uavcan_can.req_not_rsp",
           FT_UINT32, BASE_DEC, NULL, 0x01000000, NULL, HFILL}},
        {&hf_uavcan_subject_id,
           {"Subject ID",                                        "uavcan_can.subject_id",
           FT_UINT32, BASE_DEC|BASE_RANGE_STRING, RVALS(uavcan_subject_id_vals), 0x001FFF00, NULL, HFILL}},
        {&hf_uavcan_service_id,
           {"Service ID",                                        "uavcan_can.service_id",
           FT_UINT32, BASE_DEC|BASE_RANGE_STRING, RVALS(uavcan_service_id_vals), 0x007FC000, NULL, HFILL}},
        {&hf_uavcan_dst_addr,
           {"Destination node-ID",                               "uavcan_can.dst_addr",
           FT_UINT32, BASE_DEC, NULL, 0x00003F80, NULL, HFILL}},
        {&hf_uavcan_src_addr,
           {"Source node-ID",                                    "uavcan_can.src_addr",
           FT_UINT32, BASE_DEC, NULL, 0x0000007F, NULL, HFILL}},
        {&hf_uavcan_data,
           {"Payload",                                           "uavcan_can.payload",
           FT_BYTES, BASE_NONE | BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_start_of_transfer,
           {"Start of transfer",                                 "uavcan_can.start_of_transfer",
           FT_UINT8, BASE_DEC, NULL, START_OF_TRANSFER, NULL, HFILL}},
        {&hf_uavcan_end_of_transfer,
           {"End of transfer",                                   "uavcan_can.end_of_transfer",
           FT_UINT8, BASE_DEC, NULL, END_OF_TRANSFER, NULL, HFILL}},
        {&hf_uavcan_toggle,
           {"Toggle",                                            "uavcan_can.toggle",
           FT_UINT8, BASE_DEC, NULL, TOGGLE, NULL, HFILL}},
        {&hf_uavcan_transfer_id,
           {"Transfer-ID",                                       "uavcan_can.transfer_id",
           FT_UINT8, BASE_DEC, NULL, TRANSFER_ID, NULL, HFILL}},
        {&hf_uavcan_fragments,
           {"Message fragments",                                 "uavcan_can.multiframe.fragments",
           FT_NONE, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment,
           {"Message fragment",                                  "uavcan_can.multiframe.fragment",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment_overlap,
           {"Message fragment overlap",
           "uavcan_can.multiframe.fragment.overlap",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment_overlap_conflicts,
           {"Message fragment overlapping with conflicting data",
           "uavcan_can.multiframe.fragment.overlap.conflicts",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment_multiple_tails,
           {"Message has multiple tail fragments",
           "uavcan_can.multiframe.fragment.multiple_tails",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment_too_long_fragment,
           {"Message fragment too long",
           "uavcan_can.multiframe.fragment.too_long_fragment",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment_error,
           {"Message defragmentation error",
           "uavcan_can.multiframe.fragment.error",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_fragment_count,
           {"Message fragment count",                            "uavcan_can.fragment.count",
           FT_UINT32, BASE_DEC, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_reassembled_in,
           {"Reassembled in",
           "uavcan_can.multiframe.reassembled.in",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_reassembled_length,
           {"Reassembled payload length",
           "uavcan_can.multiframe.reassembled.length",
           FT_UINT32, BASE_DEC, NULL, 0x00,
           NULL, HFILL}},
        {&hf_uavcan_packet_crc,
           {"Transfer CRC",                                      "uavcan_can.multiframe.crc",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}}
    };

    static int *ett[] = {
        &ett_uavcan,
        &ett_uavcan_can,
        &ett_uavcan_message,
        &ett_uavcan_fragment,
        &ett_uavcan_fragments
    };

    reassembly_table_register(&uavcan_reassembly_table,
                              &addresses_reassembly_table_functions);
    fragment_info_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());


    expert_module_t *expert_uavcan;

    proto_uavcan = proto_register_protocol("UAVCAN/CAN", "UAVCAN/CAN", "uavcan_can");


    static ei_register_info ei[] = {
        {&ei_uavcan_toggle_bit_error,
           {"uavcan_can.toggle_bit.error",    PI_MALFORMED,   PI_ERROR,
           "Toggle bit error",
           EXPFILL}},
        {&ei_uavcan_transfer_crc_error,
           {"uavcan_can.transfer_crc.error",  PI_MALFORMED,   PI_ERROR,
           "Transfer CRC don't match",
           EXPFILL}}
    };


    proto_register_field_array(proto_uavcan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    uavcan_handle = register_dissector("uavcan_can", dissect_uavcan, proto_uavcan);

    expert_uavcan = expert_register_protocol(proto_uavcan);
    expert_register_field_array(expert_uavcan, ei, array_length(ei));

    uavcan_address_type = address_type_dissector_register("AT_UAVCAN", "UAVCAN Address",
                                                          UAVCAN_addr_to_str, UAVCAN_addr_str_len,
                                                          NULL, UAVCAN_col_filter_str,
                                                          UAVCAN_addr_len, NULL, NULL);
}

void
proto_reg_handoff_uavcan(void)
{
    dsdl_message_handle = find_dissector_add_dependency("uavcan_dsdl.message", proto_uavcan);
    dsdl_request_handle = find_dissector_add_dependency("uavcan_dsdl.request", proto_uavcan);
    dsdl_response_handle = find_dissector_add_dependency("uavcan_dsdl.response", proto_uavcan);

    dissector_add_for_decode_as("can.subdissector", uavcan_handle);
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
