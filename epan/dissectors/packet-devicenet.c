/* packet-devicenet.c
 * Routines for dissection of DeviceNet
 * DeviceNet Home: www.odva.org
 *
 * This dissector includes items from:
 *    CIP Volume 3: DeviceNet Adaptation of CIP, Edition 1.14
 *
 * Michael Mann
 * Erik Ivarsson <eriki@student.chalmers.se>
 * Hans-Jorgen Gunnarsson <hag@hms.se>
 * Copyright 2012
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/uat.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/address_types.h>
#include <epan/to_str.h>

#include "packet-cip.h"
#include "packet-socketcan.h"

void proto_register_devicenet(void);
void proto_reg_handoff_devicenet(void);

static dissector_handle_t devicenet_handle;

#define DEVICENET_CANID_MASK            CAN_SFF_MASK
#define MESSAGE_GROUP_1_ID              0x03FF
#define MESSAGE_GROUP_1_MSG_MASK        0x03C0
#define MESSAGE_GROUP_1_MAC_ID_MASK     0x003F

#define MESSAGE_GROUP_2_ID              0x05FF
#define MESSAGE_GROUP_2_MSG_MASK        0x0007
#define MESSAGE_GROUP_2_MAC_ID_MASK     0x01F8

#define MESSAGE_GROUP_3_ID              0x07BF
#define MESSAGE_GROUP_3_MSG_MASK        0x01C0
#define MESSAGE_GROUP_3_MAC_ID_MASK     0x3F
#define MESSAGE_GROUP_3_FRAG_MASK       0x80
#define MESSAGE_GROUP_3_XID_MASK        0x40

#define MESSAGE_GROUP_4_ID              0x07EF
#define MESSAGE_GROUP_4_MSG_MASK        0x3F

static int proto_devicenet;

static int hf_devicenet_can_id;
static int hf_devicenet_src_mac_id;
static int hf_devicenet_data;
static int hf_devicenet_grp_msg1_id;
static int hf_devicenet_grp_msg2_id;
static int hf_devicenet_grp_msg3_id;
static int hf_devicenet_grp_msg3_frag;
static int hf_devicenet_grp_msg3_xid;
static int hf_devicenet_grp_msg3_dest_mac_id;
static int hf_devicenet_grp_msg4_id;
static int hf_devicenet_rr_bit;
static int hf_devicenet_service_code;
static int hf_devicenet_connection_id;
static int hf_devicenet_open_exp_src_message_id;
static int hf_devicenet_open_exp_dest_message_id;
static int hf_devicenet_open_exp_msg_req_body_format;
static int hf_devicenet_open_exp_msg_actual_body_format;
static int hf_devicenet_open_exp_group_select;
static int hf_devicenet_open_exp_msg_reserved;
static int hf_devicenet_dup_mac_id_rr_bit;
static int hf_devicenet_dup_mac_id_physical_port_number;
static int hf_devicenet_dup_mac_id_serial_number;
static int hf_devicenet_dup_mac_id_vendor;
static int hf_devicenet_comm_fault_rsv;
static int hf_devicenet_comm_fault_match;
static int hf_devicenet_comm_fault_value;
static int hf_devicenet_offline_ownership_reserved;
static int hf_devicenet_offline_ownership_client_mac_id;
static int hf_devicenet_offline_ownership_allocate;
static int hf_devicenet_vendor;
static int hf_devicenet_serial_number;
static int hf_devicenet_class8;
static int hf_devicenet_class16;
static int hf_devicenet_instance8;
static int hf_devicenet_instance16;
static int hf_devicenet_attribute;
static int hf_devicenet_fragment_type;
static int hf_devicenet_fragment_count;

static int ett_devicenet;
static int ett_devicenet_can;
static int ett_devicenet_contents;
static int ett_devicenet_8_8;
static int ett_devicenet_8_16;
static int ett_devicenet_16_8;
static int ett_devicenet_16_16;

static expert_field ei_devicenet_invalid_service;
static expert_field ei_devicenet_invalid_can_id;
static expert_field ei_devicenet_invalid_msg_id;
static expert_field ei_devicenet_frag_not_supported;

static int devicenet_address_type = -1;

enum node_behavior {
    NODE_BEHAVIOR_8_8   = 0,
    NODE_BEHAVIOR_8_16  = 1,
    NODE_BEHAVIOR_16_8  = 2,
    NODE_BEHAVIOR_16_16 = 3
};

/* UAT entry structure. */
typedef struct {
    unsigned mac_id;
    enum node_behavior behavior;

} uat_devicenet_record_t;

static uat_devicenet_record_t *uat_devicenet_records;
static uat_t *devicenet_uat;
static unsigned num_devicenet_records_uat;

static bool uat_devicenet_record_update_cb(void* r, char** err) {
    uat_devicenet_record_t* rec = (uat_devicenet_record_t *)r;

    if (rec->mac_id > 63) {
        *err = g_strdup("MAC ID must be between 0-63");
        return false;
    }
    return true;
}

UAT_DEC_CB_DEF(uat_devicenet_records, mac_id, uat_devicenet_record_t)
UAT_VS_DEF(uat_devicenet_records, behavior, uat_devicenet_record_t, enum node_behavior, NODE_BEHAVIOR_8_8, "string")

#if 0
static const enum_val_t bodytype_devicenet_protocol_options[] = {
    { "eightovereight", "8/8", 0 },
    { "eightoversixteen", "8/16", 1 },
    { "sixteenovereight", "16/8", 2 },
    { "sixteenoversixteen", "16/16", 3 },
    { NULL, NULL, 0 }
};
#endif

#define SC_OPEN_EXPLICIT_MESSAGE    0x4B
#define SC_CLOSE_EXPLICIT_MESSAGE   0x4C
#define SC_DEVICE_HEARTBEAT_MESSAGE 0x4D
#define SC_DEVICE_SHUTOWN_MESSAGE   0x4E

static const value_string devicenet_service_code_vals[] = {
    GENERIC_SC_LIST

    { SC_OPEN_EXPLICIT_MESSAGE,     "Open Explicit Message Connection Request" },
    { SC_CLOSE_EXPLICIT_MESSAGE,    "Close Connection Request" },
    { SC_DEVICE_HEARTBEAT_MESSAGE,  "Device Heartbeat Message" },
    { SC_DEVICE_SHUTOWN_MESSAGE,    "Device Shutdown Message" },
    { 0, NULL }
};

static const value_string devicenet_grp_msg1_vals[] = {
    { 0x0300, "Slave's I/O Multicast Poll Response" },
    { 0x0340, "Slave's I/O Change of State or Cyclic Message" },
    { 0x0380, "Slave's I/O Bit-Strobe Response Message" },
    { 0x03C0, "Slave's I/O Poll Response or COS/Cyclic Ack Message" },
    { 0, NULL }
};

static const value_string devicenet_grp_msg2_vals[] = {
    { 0x00, "Master's I/O Bit-Strobe Command Message" },
    { 0x01, "Master's I/O Multicast Poll Group ID" },
    { 0x02, "Master's Change of State or Cyclic Acknowledge Message" },
    { 0x03, "Slave's Explicit/Unconnected Response Messages" },
    { 0x04, "Master's Explicit Request Messages" },
    { 0x05, "Master's I/O Poll Command/COS/Cyclic Messages" },
    { 0x06, "Group 2 Only Unconnected Explicit Request Messages" },
    { 0x07, "Duplicate MAC ID Check Messages" },
    { 0, NULL }
};

static const value_string devicenet_grp_msg3_vals[] = {
    { 0x000, "Group 3 Message" },
    { 0x040, "Group 3 Message" },
    { 0x080, "Group 3 Message" },
    { 0x0C0, "Group 3 Message" },
    { 0x100, "Group 3 Message" },
    { 0x140, "Unconnected Explicit Response Message" },
    { 0x180, "Unconnected Explicit Request Message" },
    { 0x1C0, "Invalid Group 3 Message" },
    { 0, NULL }
};

#define GRP4_COMM_FAULT_RESPONSE    0x2C
#define GRP4_COMM_FAULT_REQUEST     0x2D
#define GRP4_OFFLINE_OWNER_RESPONSE 0x2E
#define GRP4_OFFLINE_OWNER_REQUEST  0x2F

static const value_string devicenet_grp_msg4_vals[] = {
    { GRP4_COMM_FAULT_RESPONSE, "Communication Faulted Response Message" },
    { GRP4_COMM_FAULT_REQUEST, "Communication Faulted Request Message" },
    { GRP4_OFFLINE_OWNER_RESPONSE, "Offline Ownership Response Message" },
    { GRP4_OFFLINE_OWNER_REQUEST, "Offline Ownership Request Message" },
    { 0, NULL }
};

static const value_string devicenet_message_body_format_vals[] = {
    { 0x00, "DeviceNet 8/8. Class ID = 8 bit integer, Instance ID = 8 bit integer" },
    { 0x01, "DeviceNet 8/16. Class ID = 8 bit integer, Instance ID = 16 bit integer" },
    { 0x02, "DeviceNet 16/16. Class ID = 16 bit integer. Instance ID = 16 bit integer" },
    { 0x03, "DeviceNet 16/8. Class ID = 16 bit integer. Instance ID = 8 bit integer" },
    { 0x04, "CIP Path. The addressing size is variable and is provided as a Packed EPATH on each request" },
    { 0x05, "Reserved by DeviceNet" },
    { 0x06, "Reserved by DeviceNet" },
    { 0x07, "Reserved by DeviceNet" },
    { 0x08, "Reserved by DeviceNet" },
    { 0x09, "Reserved by DeviceNet" },
    { 0x0A, "Reserved by DeviceNet" },
    { 0x0B, "Reserved by DeviceNet" },
    { 0x0C, "Reserved by DeviceNet" },
    { 0x0D, "Reserved by DeviceNet" },
    { 0x0E, "Reserved by DeviceNet" },
    { 0x0F, "Reserved by DeviceNet" },
    { 0, NULL }
};

static const value_string devicenet_group_select_vals[] = {
    { 0x00, "Message Group 1" },
    { 0x01, "Message Group 2" },
    { 0x02, "Reserved" },
    { 0x03, "Message Group 3" },
    { 0x04, "Reserved by DeviceNet" },
    { 0x05, "Reserved by DeviceNet" },
    { 0x06, "Reserved by DeviceNet" },
    { 0x07, "Reserved by DeviceNet" },
    { 0x08, "Reserved by DeviceNet" },
    { 0x09, "Reserved by DeviceNet" },
    { 0x0A, "Reserved by DeviceNet" },
    { 0x0B, "Reserved by DeviceNet" },
    { 0x0C, "Reserved by DeviceNet" },
    { 0x0D, "Reserved by DeviceNet" },
    { 0x0E, "Reserved by DeviceNet" },
    { 0x0F, "Reserved by Node Ping" },
    { 0, NULL }
};

static const value_string devicenet_fragmented_message_type_vals[] = {
    { 0,    "First Fragment" },
    { 1,    "Middle fragment" },
    { 2,    "Last fragment" },
    { 3,    "Fragment Acknowledge" },
    { 0, NULL }
};

#if 0
static const value_string devicenet_io_attribute_vals[] = {
    {0x01, "Vendor ID"},
    {0x02, "Device Type"},
    {0x03, "Product Code"},
    {0x04, "Revision"},
    {0x05, "Status"},
    {0x06, "Serial Number"},
    {0x07, "Product Name"},
    { 0, NULL }
};
#endif

static int body_type_8_over_8_dissection(uint8_t data_length, proto_tree *devicenet_tree,
                                          tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    uint16_t class_id, instance, attribute;
    const attribute_info_t* att_info;
    int start_offset = offset, length;
    proto_item* ti;

    devicenet_tree = proto_tree_add_subtree(devicenet_tree, tvb, offset, -1, ett_devicenet_8_8, NULL, "DeviceNet 8/8");

    proto_tree_add_item(devicenet_tree, hf_devicenet_class8,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_uint8(tvb, offset);
    offset++;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance8,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    instance = tvb_get_uint8(tvb, offset);

    offset++;
    if (data_length > 3)
    {
        attribute = tvb_get_uint8(tvb, offset);
        ti = proto_tree_add_item(devicenet_tree, hf_devicenet_attribute,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_item_append_text(ti, " (%s)", att_info->text);

        offset++;
    }

    if (data_length > 4)
    {
        length = offset-start_offset;
        proto_tree_add_item(devicenet_tree, hf_devicenet_data, tvb, offset, length, ENC_NA);
        offset += length;
    }
    return offset;
}

static int body_type_8_over_16_dissection(uint8_t data_length, proto_tree *devicenet_tree,
                                           tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    uint16_t class_id, instance, attribute;
    const attribute_info_t* att_info;
    proto_item* ti;

    devicenet_tree = proto_tree_add_subtree(devicenet_tree, tvb, offset, -1, ett_devicenet_8_16, NULL, "DeviceNet 8/16");

    proto_tree_add_item(devicenet_tree, hf_devicenet_class8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_uint8(tvb, offset);
    offset++;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    instance = tvb_get_letohs(tvb, offset);

    if (data_length > 4)
    {
        attribute = tvb_get_uint8(tvb, offset);
        ti = proto_tree_add_item(devicenet_tree, hf_devicenet_attribute,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_item_append_text(ti, " (%s)", att_info->text);

        offset++;
    }

    return offset;
}

static int body_type_16_over_8_dissection(uint8_t data_length, proto_tree *devicenet_tree, tvbuff_t *tvb,
                                           packet_info *pinfo _U_, int offset)
{
    uint16_t class_id, instance, attribute;
    const attribute_info_t* att_info;
    proto_item* ti;

    devicenet_tree = proto_tree_add_subtree(devicenet_tree, tvb, offset, -1, ett_devicenet_16_8, NULL, "DeviceNet 16/8");

    proto_tree_add_item(devicenet_tree, hf_devicenet_class16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    instance = tvb_get_uint8(tvb, offset);
    offset++;

    if (data_length > 4)
    {
        attribute = tvb_get_uint8(tvb, offset);
        ti = proto_tree_add_item(devicenet_tree, hf_devicenet_attribute,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_item_append_text(ti, " (%s)", att_info->text);

        offset++;
    }

    return offset;
}

static int body_type_16_over_16_dissection(uint8_t data_length, proto_tree *devicenet_tree, tvbuff_t *tvb,
                                            packet_info *pinfo _U_, int offset)
{
    uint16_t class_id, instance, attribute;
    const attribute_info_t* att_info;
    proto_item* ti;

    devicenet_tree = proto_tree_add_subtree(devicenet_tree, tvb, offset, 4, ett_devicenet_16_16, NULL, "DeviceNet 16/16");

    proto_tree_add_item(devicenet_tree, hf_devicenet_class16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    instance = tvb_get_letohs(tvb, offset);
    offset+=2;

    if (data_length > 5)
    {
        attribute = tvb_get_uint8(tvb, offset);
        ti = proto_tree_add_item(devicenet_tree, hf_devicenet_attribute,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_item_append_text(ti, " (%s)", att_info->text);

        offset++;
    }

    return offset;
}

static int dissect_devicenet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *ti, *can_id_item,
               *msg_id_item, *service_item;
    proto_tree *devicenet_tree, *can_tree, *content_tree;

    int offset = 0;
    uint16_t message_id;
    uint32_t data_length = tvb_reported_length(tvb);
    uint8_t source_mac;
    struct can_info can_info;
    uint8_t service_rr;
    uint8_t *src_address, *dest_address;

    DISSECTOR_ASSERT(data);
    can_info = *((struct can_info*)data);

    if (can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG | CAN_EFF_FLAG))
    {
        /* Error, RTR and frames with extended ids are not for us. */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DeviceNet");

    ti = proto_tree_add_item(tree, proto_devicenet, tvb, offset, -1, ENC_NA);
    devicenet_tree = proto_item_add_subtree(ti, ett_devicenet);

    can_tree = proto_tree_add_subtree_format(devicenet_tree, tvb, 0, 0, ett_devicenet_can, NULL, "CAN Identifier: 0x%04x", can_info.id);
    can_id_item = proto_tree_add_uint(can_tree, hf_devicenet_can_id, tvb, 0, 0, can_info.id);
    proto_item_set_generated(can_id_item);

    /*
     * Message group 1
     */
    if ( can_info.id <= MESSAGE_GROUP_1_ID )
    {
        ti = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg1_id, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(can_tree, hf_devicenet_src_mac_id, tvb, 0, 0, can_info.id & MESSAGE_GROUP_1_MAC_ID_MASK);
        proto_item_set_generated(ti);

        /* Set source address */
        src_address = (uint8_t*)wmem_alloc(pinfo->pool, 1);
        *src_address = (uint8_t)(can_info.id & MESSAGE_GROUP_1_MAC_ID_MASK);
        set_address(&pinfo->src, devicenet_address_type, 1, (const void*)src_address);

        message_id = can_info.id & MESSAGE_GROUP_1_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg1_vals, "Other Group 1 Message"));

        proto_tree_add_item(devicenet_tree, hf_devicenet_data, tvb, offset, data_length, ENC_NA);
    }
    /*
     * Message group 2
     */
    else if (can_info.id <= MESSAGE_GROUP_2_ID )
    {
        ti = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg2_id, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);

        /* create display subtree for the protocol */
        message_id = can_info.id & MESSAGE_GROUP_2_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg2_vals, "Unknown"));

        ti = proto_tree_add_uint(can_tree, hf_devicenet_src_mac_id, tvb, 0, 0, (can_info.id & MESSAGE_GROUP_2_MAC_ID_MASK) >> 3);
        proto_item_set_generated(ti);

        /* Set source address */
        src_address = (uint8_t*)wmem_alloc(pinfo->pool, 1);
        *src_address = (uint8_t)((can_info.id & MESSAGE_GROUP_2_MAC_ID_MASK) >> 3);
        set_address(&pinfo->src, devicenet_address_type, 1, (const void*)src_address);

        content_tree = proto_tree_add_subtree(devicenet_tree, tvb, offset, -1, ett_devicenet_contents, NULL, "Contents");

        switch (message_id)
        {
        case 0x0:
        case 0x1:
        case 0x2:
        case 0x3:
        case 0x4:
        case 0x5:
            proto_tree_add_item(content_tree, hf_devicenet_data, tvb, offset, data_length, ENC_NA);
            break;

        case 0x6:
            proto_tree_add_item(content_tree, hf_devicenet_data, tvb, offset, data_length, ENC_NA);
            break;

        case 0x7:
            proto_tree_add_item(content_tree, hf_devicenet_dup_mac_id_rr_bit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(content_tree, hf_devicenet_dup_mac_id_physical_port_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset ++;

            proto_tree_add_item(content_tree, hf_devicenet_dup_mac_id_vendor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            proto_tree_add_item(content_tree, hf_devicenet_dup_mac_id_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    /*
     * Message group 3
     */
    else if (can_info.id <= MESSAGE_GROUP_3_ID )
    {
        uint8_t byte1;

        msg_id_item = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg3_id, tvb, 0, 0, can_info.id);
        proto_item_set_generated(msg_id_item);
        ti = proto_tree_add_uint(can_tree, hf_devicenet_src_mac_id, tvb, 0, 0, can_info.id & MESSAGE_GROUP_3_MAC_ID_MASK);
        proto_item_set_generated(ti);

        /* Set source address */
        src_address = (uint8_t*)wmem_alloc(pinfo->pool, 1);
        *src_address = (uint8_t)(can_info.id & MESSAGE_GROUP_3_MAC_ID_MASK);
        set_address(&pinfo->src, devicenet_address_type, 1, (const void*)src_address);

        message_id = can_info.id & MESSAGE_GROUP_3_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg3_vals, "Unknown"));

        proto_tree_add_item(devicenet_tree, hf_devicenet_grp_msg3_frag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(devicenet_tree, hf_devicenet_grp_msg3_xid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(devicenet_tree, hf_devicenet_grp_msg3_dest_mac_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        byte1 = tvb_get_uint8(tvb, offset);
        source_mac = byte1 & MESSAGE_GROUP_3_MAC_ID_MASK;

        /* Set destination address */
        /* XXX - This may be source address depending on message type.  Need to adjust accordingly) */
        dest_address = (uint8_t*)wmem_alloc(pinfo->pool, 1);
        *dest_address = (uint8_t)source_mac;
        set_address(&pinfo->dst, devicenet_address_type, 1, (const void*)dest_address);
        offset++;

        if (byte1 & MESSAGE_GROUP_3_FRAG_MASK)
        {
            col_set_str(pinfo->cinfo, COL_INFO, "Group 3 Message Fragment");

            content_tree = proto_tree_add_subtree(devicenet_tree, tvb, offset, -1, ett_devicenet_contents, NULL, "Fragmentation");

            proto_tree_add_item(content_tree, hf_devicenet_fragment_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(content_tree, hf_devicenet_fragment_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            /* TODO: Handle fragmentation */
            proto_tree_add_expert(content_tree, pinfo, &ei_devicenet_frag_not_supported, tvb, offset, -1);

            col_set_str(pinfo->cinfo, COL_INFO,
                        val_to_str_const((tvb_get_uint8(tvb, offset) & 0xC0) >> 6,
                                         devicenet_fragmented_message_type_vals,
                                         "Unknown fragmented message type"));
        }
        else
        {
            service_rr = tvb_get_uint8(tvb, offset);

            content_tree = proto_tree_add_subtree_format(devicenet_tree, tvb, offset, -1, ett_devicenet_contents, NULL,
                        "Service: %s (%s)", val_to_str_const(service_rr & CIP_SC_MASK, devicenet_service_code_vals, "Unknown"),
                        service_rr & CIP_SC_RESPONSE_MASK ? "Response" : "Request");

            proto_tree_add_item(content_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            service_item = proto_tree_add_item(content_tree, hf_devicenet_service_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(service_rr & CIP_SC_MASK, devicenet_service_code_vals, "Unknown Service Code"));
            if (service_rr & CIP_SC_RESPONSE_MASK)
            {
                col_append_str(pinfo->cinfo, COL_INFO, " - Response");
            }
            else
            {
                col_append_str(pinfo->cinfo, COL_INFO, " - Request");
            }

            switch(message_id)
            {
            case 0x140:
                switch(service_rr & CIP_SC_MASK)
                {
                case SC_OPEN_EXPLICIT_MESSAGE:
                case SC_CLOSE_EXPLICIT_MESSAGE:
                case SC_DEVICE_HEARTBEAT_MESSAGE:
                case SC_DEVICE_SHUTOWN_MESSAGE:
                /* XXX - ERROR RESPONSE? */
                    break;
                default:
                    expert_add_info_format(pinfo, service_item, &ei_devicenet_invalid_service,
                        "Invalid service code (0x%x) for Group 3 Message ID 5", service_rr & CIP_SC_MASK);
                    break;
                }
                break;
            case 0x180:
                switch(service_rr & CIP_SC_MASK)
                {
                case SC_OPEN_EXPLICIT_MESSAGE:
                case SC_CLOSE_EXPLICIT_MESSAGE:
                    break;
                default:
                    expert_add_info_format(pinfo, service_item, &ei_devicenet_invalid_service,
                        "Invalid service code (0x%x) for Group 3 Message ID 6", service_rr & CIP_SC_MASK);
                    break;
                }
                break;
            case 0x1C0:
                expert_add_info_format(pinfo, msg_id_item, &ei_devicenet_invalid_msg_id,
                        "Invalid Group 3 Message ID (%d)", message_id);
                break;
            }

            switch(service_rr & CIP_SC_MASK)
            {
            case SC_OPEN_EXPLICIT_MESSAGE:
                /* XXX - Create conversation to track connections */
                if (service_rr & CIP_SC_RESPONSE_MASK)
                {
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_actual_body_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_dest_message_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_src_message_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    proto_tree_add_item(content_tree, hf_devicenet_connection_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                else
                {
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_req_body_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_group_select, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_src_message_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                }
                break;
            case SC_CLOSE_EXPLICIT_MESSAGE:
                /* XXX - Use conversation to track connections */
                if ((service_rr & CIP_SC_RESPONSE_MASK) == 0)
                {
                    proto_tree_add_item(content_tree, hf_devicenet_connection_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                break;
            default:
                if(service_rr & CIP_SC_MASK)
                {
                    proto_tree_add_item(devicenet_tree, hf_devicenet_data, tvb, offset, data_length - 2, ENC_NA);
                }
                else
                {
                    unsigned channel;

                    for (channel = 0; channel < num_devicenet_records_uat; channel++)
                    {
                        if (uat_devicenet_records[channel].mac_id == source_mac)
                        {
                            switch(uat_devicenet_records[channel].behavior)
                            {
                            case 0:
                                body_type_8_over_8_dissection(data_length, content_tree, tvb, pinfo, offset);
                                break;
                            case 1:
                                body_type_8_over_16_dissection(data_length, content_tree, tvb, pinfo, offset);
                                break;
                            case 2:
                                body_type_16_over_8_dissection(data_length, content_tree, tvb, pinfo, offset);
                                break;
                            case 3:
                                body_type_16_over_16_dissection(data_length, content_tree, tvb, pinfo, offset);
                                break;
                            default:
                                proto_tree_add_item(content_tree, hf_devicenet_data, tvb, offset, data_length, ENC_NA);
                                break;
                            }
                        }
                    }

                    /* Don't have a behavior defined for this address, default to 8 over 8 */
                    if (channel >= num_devicenet_records_uat)
                    {
                        body_type_8_over_8_dissection(data_length, content_tree, tvb, pinfo, offset);
                    }
                }
                break;
            }
        }
    }
    /*Message group 4*/
    else if (can_info.id <= MESSAGE_GROUP_4_ID )
    {
        ti = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg4_id, tvb, 0, 0, can_info.id);
        proto_item_set_generated(ti);

        message_id = can_info.id & MESSAGE_GROUP_4_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg4_vals, "Reserved Group 4 Message"));

        switch(message_id)
        {
        case GRP4_COMM_FAULT_RESPONSE:
        case GRP4_COMM_FAULT_REQUEST:
            if(data_length == 2)
            {
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_rsv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_match, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_value, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;

                proto_tree_add_item(devicenet_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(devicenet_tree, hf_devicenet_service_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                if( tvb_get_uint8(tvb, offset) & CIP_SC_RESPONSE_MASK)
                {
                    col_append_str(pinfo->cinfo, COL_INFO, " - Response");
                }
                else
                {
                    col_append_str(pinfo->cinfo, COL_INFO, " - Request");
                }
            }
            else if(data_length == 8)
            {
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_rsv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset++;

                proto_tree_add_item(devicenet_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(devicenet_tree, hf_devicenet_service_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);

                if( tvb_get_uint8(tvb, offset) & CIP_SC_RESPONSE_MASK)
                {
                    col_append_str(pinfo->cinfo, COL_INFO, " - Response");
                }
                else
                {
                    col_append_str(pinfo->cinfo, COL_INFO, " - Request");
                }
                offset++;

                proto_tree_add_item(devicenet_tree, hf_devicenet_vendor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset +=2;
                proto_tree_add_item(devicenet_tree, hf_devicenet_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            break;
        case GRP4_OFFLINE_OWNER_REQUEST:
        case GRP4_OFFLINE_OWNER_RESPONSE:
            proto_tree_add_item(devicenet_tree, hf_devicenet_offline_ownership_reserved,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(devicenet_tree, hf_devicenet_offline_ownership_client_mac_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            proto_tree_add_item(devicenet_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            if( tvb_get_uint8(tvb, offset) & CIP_SC_RESPONSE_MASK)
            {
                col_append_str(pinfo->cinfo, COL_INFO, " - Response");
            }
            else
            {
                col_append_str(pinfo->cinfo, COL_INFO, " - Request");
            }

            proto_tree_add_item(devicenet_tree, hf_devicenet_offline_ownership_allocate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(devicenet_tree, hf_devicenet_vendor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset +=2;
            proto_tree_add_item(devicenet_tree, hf_devicenet_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    /*Invalid CAN message*/
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid CAN Message 0x%06X", can_info.id);
        expert_add_info_format(pinfo, can_id_item, &ei_devicenet_invalid_can_id,
                    "Invalid CAN Message 0x%04X", can_info.id);
    }

    return tvb_captured_length(tvb);
}

static int devicenet_addr_to_str(const address* addr, char *buf, int buf_len)
{
    const uint8_t *addrdata = (const uint8_t *)addr->data;

    guint32_to_str_buf(*addrdata, buf, buf_len);
    return (int)strlen(buf);
}

static int devicenet_addr_str_len(const address* addr _U_)
{
    return 11; /* Leaves required space (10 bytes) for uint_to_str_back() */
}

static int devicenet_addr_len(void)
{
    return 1;
}

void proto_register_devicenet(void)
{
    module_t *devicenet_module;
    expert_module_t*expert_devicenet;

    static hf_register_info hf[] = {
        { &hf_devicenet_can_id,
            {"CAN Identifier", "devicenet.can_id",
            FT_UINT16, BASE_HEX, NULL, DEVICENET_CANID_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_src_mac_id,
            { "Source MAC ID", "devicenet.src_mac_id",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_connection_id,
            { "Connection ID", "devicenet.connection_id",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_data,
            { "Data", "devicenet.data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg1_id,
            { "Group 1 message ID", "devicenet.grp_msg1.id",
            FT_UINT16, BASE_DEC, NULL, MESSAGE_GROUP_1_MSG_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg2_id,
            { "Group 2 message ID", "devicenet.grp_msg2.id",
            FT_UINT16, BASE_DEC, NULL, MESSAGE_GROUP_2_MSG_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg3_id,
            { "Group 3 message ID", "devicenet.grp_msg3.id",
            FT_UINT16, BASE_DEC, NULL, MESSAGE_GROUP_3_MSG_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg3_dest_mac_id,
            { "Destination MAC ID", "devicenet.dest_mac_id",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg3_frag,
            { "Frag", "devicenet.grp_msg3.frag",
            FT_BOOLEAN, 8, NULL, MESSAGE_GROUP_3_FRAG_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg3_xid,
            { "XID", "devicenet.grp_msg3.xid",
            FT_BOOLEAN, 8, NULL, MESSAGE_GROUP_3_XID_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_grp_msg4_id,
            { "Group 4 message ID", "devicenet.grp_msg4.id",
            FT_UINT16, BASE_DEC, NULL, MESSAGE_GROUP_4_MSG_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_rr_bit,
            { "Request/Response", "devicenet.rr",
            FT_UINT8, BASE_DEC, VALS(cip_sc_rr), CIP_SC_RESPONSE_MASK,
            "Request or Response message", HFILL }
        },
        { &hf_devicenet_service_code,
            { "Service Code", "devicenet.service",
            FT_UINT8, BASE_DEC, VALS(devicenet_service_code_vals), CIP_SC_MASK,
            NULL, HFILL }
        },
        { &hf_devicenet_open_exp_src_message_id,
            { "Source Message ID", "devicenet.open_message.src_message_id",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_devicenet_open_exp_dest_message_id,
            { "Destination Message ID", "devicenet.open_message.dest_message_id",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_devicenet_open_exp_msg_reserved,
            { "Reserved", "devicenet.open_message.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_devicenet_open_exp_msg_req_body_format,
            { "Requested Message Body Format", "devicenet.open_message.req_body_format",
            FT_UINT8, BASE_DEC, VALS(devicenet_message_body_format_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_devicenet_open_exp_msg_actual_body_format,
            { "Actual Message Body Format", "devicenet.open_message.actual_body_format",
            FT_UINT8, BASE_DEC, VALS(devicenet_message_body_format_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_devicenet_open_exp_group_select,
            { "Group Select", "devicenet.open_message.group_select",
            FT_UINT8, BASE_DEC, VALS(devicenet_group_select_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_devicenet_dup_mac_id_rr_bit,
            { "Request/Response", "devicenet.dup_mac_id.rr",
            FT_UINT8, BASE_DEC, VALS(cip_sc_rr), CIP_SC_RESPONSE_MASK,
            "Duplicate MAC ID Request or Response message", HFILL }
        },
        { &hf_devicenet_dup_mac_id_physical_port_number,
            { "Physical port number", "devicenet.dup_mac_id.physical_port_number",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            "Duplicate MAC ID check message physical port number", HFILL }
        },
        { &hf_devicenet_dup_mac_id_vendor,
            { "Vendor ID", "devicenet.dup_mac_id.vendor",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_dup_mac_id_serial_number,
            { "Serial Number", "devicenet.dup_mac_id.serial_number",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devicenet_vendor,
            { "Vendor ID", "devicenet.vendor",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_vendor_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_serial_number,
            { "Serial Number", "devicenet.serial_number",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devicenet_instance8,
            { "Instance", "devicenet.instance",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devicenet_instance16,
            { "Instance", "devicenet.instance",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devicenet_attribute,
            { "Attribute", "devicenet.attribute",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devicenet_fragment_type,
            { "Fragment Type", "devicenet.fragment_type",
            FT_UINT8, BASE_HEX, VALS(devicenet_fragmented_message_type_vals), 0xC0,
            NULL, HFILL }
        },
        { &hf_devicenet_fragment_count,
            { "Fragment Count", "devicenet.fragment_count",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_devicenet_class8,
            { "Class",  "devicenet.class",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &cip_class_names_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_class16,
            { "Class",  "devicenet.class",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &cip_class_names_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_devicenet_comm_fault_rsv,
            { "Reserved",  "devicenet.comm_fault.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_devicenet_comm_fault_match,
            { "Match", "devicenet.comm_fault.match",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        {&hf_devicenet_comm_fault_value,
            { "Value", "devicenet.comm_fault.value",
            FT_UINT8, BASE_HEX, NULL, 0x3F,
            "Comm Fault Value", HFILL }
        },
        {&hf_devicenet_offline_ownership_reserved,
            { "Reserved", "devicenet.offline_ownership.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            "Offline ownership Response Message Reserved", HFILL }
        },
        {&hf_devicenet_offline_ownership_client_mac_id,
            { "Client MAC ID", "devicenet.offline_ownership.client_mac_id",
            FT_UINT8, BASE_HEX, NULL, MESSAGE_GROUP_4_MSG_MASK,
            "Offline ownership message client MAC ID", HFILL }
        },
        {&hf_devicenet_offline_ownership_allocate,
            { "Allocate", "devicenet.offline_ownership.allocate",
            FT_UINT8, BASE_HEX, NULL, CIP_SC_MASK,
            "Offline ownership response message allocate", HFILL }
        },
    };

    static int *ett[] = {
        &ett_devicenet,
        &ett_devicenet_can,
        &ett_devicenet_contents,
        &ett_devicenet_8_8,
        &ett_devicenet_8_16,
        &ett_devicenet_16_8,
        &ett_devicenet_16_16
    };

    static ei_register_info ei[] = {
        { &ei_devicenet_invalid_service, { "devicenet.invalid_service", PI_PROTOCOL, PI_WARN, "Invalid service", EXPFILL }},
        { &ei_devicenet_invalid_can_id, { "devicenet.invalid_can_id", PI_PROTOCOL, PI_WARN, "Invalid CAN ID", EXPFILL }},
        { &ei_devicenet_invalid_msg_id, { "devicenet.invalid_msg_id", PI_PROTOCOL, PI_WARN, "Invalid Message ID", EXPFILL }},
        { &ei_devicenet_frag_not_supported, { "devicenet.frag_not_supported", PI_UNDECODED, PI_WARN, "Fragmentation not currently supported", EXPFILL }},
    };

    static uat_field_t devicenet_uat_flds[] = {
        UAT_FLD_DEC(uat_devicenet_records, mac_id, "Option number", "Custom Option Number"),
        UAT_FLD_VS(uat_devicenet_records, behavior, "Option type", devicenet_message_body_format_vals, "Option datatype"),
        UAT_END_FIELDS
    };

    proto_devicenet = proto_register_protocol("DeviceNet Protocol", "DeviceNet", "devicenet");

    proto_register_field_array(proto_devicenet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_devicenet = expert_register_protocol(proto_devicenet);
    expert_register_field_array(expert_devicenet, ei, array_length(ei));

    devicenet_address_type = address_type_dissector_register("AT_DEVICENET", "DeviceNet Address", devicenet_addr_to_str, devicenet_addr_str_len, NULL, NULL, devicenet_addr_len, NULL, NULL);

    devicenet_module = prefs_register_protocol(proto_devicenet, NULL);

    devicenet_uat = uat_new("Node bodytypes",
                            sizeof(uat_devicenet_record_t), /* record size           */
                            "devicenet_bodytypes",          /* filename              */
                            true,                           /* from_profile          */
                            &uat_devicenet_records,         /* data_ptr              */
                            &num_devicenet_records_uat,     /* numitems_ptr          */
                            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
                            NULL,                           /* help                  */
                            NULL,   /* copy callback         */
                            uat_devicenet_record_update_cb, /* update callback       */
                            NULL,   /* free callback         */
                            NULL,    /* post update callback  */
                            NULL,   /* reset callback */
                            devicenet_uat_flds);    /* UAT field definitions */

    prefs_register_uat_preference(devicenet_module,
                                      "bodytype_table",
                                      "Node bodytypes",
                                      "Node bodytypes",
                                      devicenet_uat);

    devicenet_handle = register_dissector("devicenet",  dissect_devicenet, proto_devicenet );
}

void
proto_reg_handoff_devicenet(void)
{
    dissector_add_for_decode_as("can.subdissector", devicenet_handle );
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
