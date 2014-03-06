/* packet-devicenet.c
 * Routines for dissection of DeviceNet
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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/uat.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include "packet-cip.h"

void proto_register_devicenet(void);

#define DEVICENET_CANID_MASK            0x7FF
#define MESSAGE_GROUP_1_ID              0x3FF
#define MESSAGE_GROUP_1_MSG_MASK        0x3C0
#define MESSAGE_GROUP_1_MAC_ID_MASK     0x03F

#define MESSAGE_GROUP_2_ID              0x5FF
#define MESSAGE_GROUP_2_MSG_MASK        0x007
#define MESSAGE_GROUP_2_MAC_ID_MASK     0x1F8

#define MESSAGE_GROUP_3_ID              0x7BF
#define MESSAGE_GROUP_3_MSG_MASK        0x1C0
#define MESSAGE_GROUP_3_MAC_ID_MASK     0x03F
#define MESSAGE_GROUP_3_FRAG_MASK       0x80
#define MESSAGE_GROUP_3_XID_MASK        0x40

#define MESSAGE_GROUP_4_ID              0x7EF
#define MESSAGE_GROUP_4_MSG_MASK        0x03F

static int proto_devicenet = -1;

static int hf_devicenet_can_id = -1;
static int hf_devicenet_src_mac_id = -1;
static int hf_devicenet_data = -1;
static int hf_devicenet_grp_msg1_id = -1;
static int hf_devicenet_grp_msg2_id = -1;
static int hf_devicenet_grp_msg3_id = -1;
static int hf_devicenet_grp_msg3_frag = -1;
static int hf_devicenet_grp_msg3_xid = -1;
static int hf_devicenet_grp_msg3_dest_mac_id = -1;
static int hf_devicenet_grp_msg4_id = -1;
static int hf_devicenet_rr_bit = -1;
static int hf_devicenet_service_code = -1;
static int hf_devicenet_connection_id = -1;
static int hf_devicenet_open_exp_src_message_id = -1;
static int hf_devicenet_open_exp_dest_message_id = -1;
static int hf_devicenet_open_exp_msg_req_body_format = -1;
static int hf_devicenet_open_exp_msg_actual_body_format = -1;
static int hf_devicenet_open_exp_group_select = -1;
static int hf_devicenet_open_exp_msg_reserved = -1;
static int hf_devicenet_dup_mac_id_rr_bit = -1;
static int hf_devicenet_dup_mac_id_physical_port_number = -1;
static int hf_devicenet_dup_mac_id_serial_number = -1;
static int hf_devicenet_dup_mac_id_vendor = -1;
static int hf_devicenet_comm_fault_rsv = -1;
static int hf_devicenet_comm_fault_match = -1;
static int hf_devicenet_comm_fault_value = -1;
static int hf_devicenet_offline_ownership_reserved = -1;
static int hf_devicenet_offline_ownership_client_mac_id = -1;
static int hf_devicenet_offline_ownership_allocate = -1;
static int hf_devicenet_vendor = -1;
static int hf_devicenet_serial_number = -1;
static int hf_devicenet_class8 = -1;
static int hf_devicenet_class16 = -1;
static int hf_devicenet_instance8 = -1;
static int hf_devicenet_instance16 = -1;
static int hf_devicenet_fragment_type = -1;
static int hf_devicenet_fragment_count = -1;

static gint ett_devicenet = -1;
static gint ett_devicenet_can = -1;
static gint ett_devicenet_contents = -1;
static gint ett_devicenet_8_8 = -1;
static gint ett_devicenet_8_16 = -1;
static gint ett_devicenet_16_8 = -1;
static gint ett_devicenet_16_16 = -1;

static expert_field ei_devicenet_invalid_service = EI_INIT;
static expert_field ei_devicenet_invalid_can_id = EI_INIT;
static expert_field ei_devicenet_invalid_msg_id = EI_INIT;
static expert_field ei_devicenet_frag_not_supported = EI_INIT;

enum node_behavior {
    NODE_BEHAVIOR_8_8   = 0,
    NODE_BEHAVIOR_8_16  = 1,
    NODE_BEHAVIOR_16_8  = 2,
    NODE_BEHAVIOR_16_16 = 3
};

/* UAT entry structure. */
typedef struct {
    guint mac_id;
    enum node_behavior behavior;

} uat_devicenet_record_t;

static uat_devicenet_record_t *uat_devicenet_records = NULL;
static uat_t *devicenet_uat = NULL;
static guint num_devicenet_records_uat = 0;

static void uat_devicenet_record_update_cb(void* r, const char** err) {
    uat_devicenet_record_t* rec = (uat_devicenet_record_t *)r;

    if (rec->mac_id > 63)
        *err = g_strdup_printf("MAC ID must be between 0-63");
}

UAT_DEC_CB_DEF(uat_devicenet_records, mac_id, uat_devicenet_record_t)
UAT_VS_DEF(uat_devicenet_records, behavior, uat_devicenet_record_t, enum node_behavior, NODE_BEHAVIOR_8_8, "string")

#if 0
static const enum_val_t bodytype_devicenet_protocol_options[] = {
    { "eightovereight", "8/8", 0 },
    { "eightoversixten", "8/16", 1 },
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
    { 0x40, "Middle fragment" },
    { 0x80, "Last fragment" },
    { 0xC0, "Fragment Acknowledge" },
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

static gint body_type_8_over_8_dissection(guint8 data_length, proto_tree *devicenet_tree,
                                          tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    proto_item *devicenet_8_8;
    guint16 class_id, instance, attribute;
    attribute_info_t* att_info;
    gint start_offset = offset, length;

    devicenet_8_8 = proto_tree_add_text(devicenet_tree, tvb, offset, -1, "DeviceNet 8/8");
    devicenet_tree = proto_item_add_subtree(devicenet_8_8, ett_devicenet_8_8);

    proto_tree_add_item(devicenet_tree, hf_devicenet_class8,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_guint8(tvb, offset);
    offset++;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance8,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    instance = tvb_get_guint8(tvb, offset);

    offset++;
    if (data_length > 3)
    {
        attribute = tvb_get_guint8(tvb, offset);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_tree_add_text(devicenet_tree, tvb, offset, 1, "Instance Attribute: %s", att_info->text);

        offset++;
    }

    if (data_length > 4)
    {
        length = offset-start_offset;
        proto_tree_add_bytes_format_value(devicenet_tree, hf_devicenet_data, tvb, offset, length,
                            NULL, "%s", tvb_bytes_to_ep_str_punct(tvb, offset, length, ' '));
        offset += length;
    }
    return offset;
}

static gint body_type_8_over_16_dissection(guint8 data_length, proto_tree *devicenet_tree,
                                           tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
    proto_item *devicenet_8_16;
    guint16 class_id, instance, attribute;
    attribute_info_t* att_info;

    devicenet_8_16 = proto_tree_add_text(devicenet_tree, tvb, offset, -1, "DeviceNet 8/16");
    devicenet_tree = proto_item_add_subtree(devicenet_8_16, ett_devicenet_8_16);

    proto_tree_add_item(devicenet_tree, hf_devicenet_class8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_guint8(tvb, offset);
    offset++;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    instance = tvb_get_letohs(tvb, offset);

    if (data_length > 4)
    {
        attribute = tvb_get_guint8(tvb, offset);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_tree_add_text(devicenet_tree, tvb, offset, 1, "Instance Attribute: %s", att_info->text);

        offset++;
    }

    return offset;
}

static gint body_type_16_over_8_dissection(guint8 data_length, proto_tree *devicenet_tree, tvbuff_t *tvb,
                                           packet_info *pinfo _U_, gint offset)
{
    proto_item *devicenet_16_8;
    guint16 class_id, instance, attribute;
    attribute_info_t* att_info;

    devicenet_16_8 = proto_tree_add_text(devicenet_tree, tvb, offset, -1, "DeviceNet 16/8");
    devicenet_tree = proto_item_add_subtree(devicenet_16_8, ett_devicenet_16_8);

    proto_tree_add_item(devicenet_tree, hf_devicenet_class16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    instance = tvb_get_guint8(tvb, offset);
    offset++;

    if (data_length > 4)
    {
        attribute = tvb_get_guint8(tvb, offset);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_tree_add_text(devicenet_tree, tvb, offset, 1, "Instance Attribute: %s" ,att_info->text);

        offset++;
    }

    return offset;
}

static gint body_type_16_over_16_dissection(guint8 data_length, proto_tree *devicenet_tree, tvbuff_t *tvb,
                                            packet_info *pinfo _U_, gint offset)
{
    proto_item *devicenet_16_16;

    guint16 class_id, instance, attribute;
    attribute_info_t* att_info;

    devicenet_16_16 = proto_tree_add_text(devicenet_tree, tvb, offset, 4, "DeviceNet 16/16");
    devicenet_tree = proto_item_add_subtree(devicenet_16_16, ett_devicenet_16_16);

    proto_tree_add_item(devicenet_tree, hf_devicenet_class16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    class_id = tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(devicenet_tree, hf_devicenet_instance16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    instance = tvb_get_letohs(tvb, offset);
    offset+=2;

    if (data_length > 5)
    {
        attribute = tvb_get_guint8(tvb, offset);
        att_info = cip_get_attribute(class_id, instance, attribute);

        if (att_info != NULL)
            proto_tree_add_text(devicenet_tree, tvb, offset, 1, "Instance Attribute: %s" ,att_info->text);

        offset++;
    }

    return offset;
}

struct can_identifier
{
    guint32 id;
};

static int dissect_devicenet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *ti, *can_id_item, *devicenet_contents,
               *msg_id_item, *service_item;
    proto_tree *devicenet_tree, *can_tree, *content_tree;

    gint offset = 0;
    guint16 message_id;
    guint32 data_length = tvb_reported_length(tvb);
    guint8 source_mac;
    struct can_identifier can_id;
    guint8 service_rr;
    guint8 *src_address, *dest_address;

    DISSECTOR_ASSERT(data);
    can_id = *((struct can_identifier*)data);

    if (can_id.id & (~DEVICENET_CANID_MASK))
    {
        /* Not for us */
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DeviceNet");

    ti = proto_tree_add_item(tree, proto_devicenet, tvb, offset, -1, ENC_NA);
    devicenet_tree = proto_item_add_subtree(ti, ett_devicenet);

    ti = proto_tree_add_text(devicenet_tree, tvb, 0, 0, "CAN Identifier: 0x%04x", can_id.id);
    can_tree = proto_item_add_subtree(ti, ett_devicenet_can);
    can_id_item = proto_tree_add_uint(can_tree, hf_devicenet_can_id, tvb, 0, 0, can_id.id);
    PROTO_ITEM_SET_GENERATED(can_id_item);

    /*
     * Message group 1
     */
    if ( can_id.id <= MESSAGE_GROUP_1_ID )
    {
        ti = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg1_id, tvb, 0, 0, can_id.id);
        PROTO_ITEM_SET_GENERATED(ti);
        ti = proto_tree_add_uint(can_tree, hf_devicenet_src_mac_id, tvb, 0, 0, can_id.id & MESSAGE_GROUP_1_MAC_ID_MASK);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Set source address */
        src_address = (guint8*)wmem_alloc(pinfo->pool, 1);
        *src_address = (guint8)(can_id.id & MESSAGE_GROUP_1_MAC_ID_MASK);
        SET_ADDRESS(&pinfo->src, AT_DEVICENET, 1, (const void*)src_address);

        message_id = can_id.id & MESSAGE_GROUP_1_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg1_vals, "Other Group 1 Message"));

        proto_tree_add_bytes_format_value(devicenet_tree, hf_devicenet_data, tvb, offset, data_length,
            NULL, "%s", tvb_bytes_to_ep_str_punct(tvb, offset, data_length, ' '));
    }
    /*
     * Message group 2
     */
    else if (can_id.id <= MESSAGE_GROUP_2_ID )
    {
        ti = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg2_id, tvb, 0, 0, can_id.id);
        PROTO_ITEM_SET_GENERATED(ti);

        /* create display subtree for the protocol */
        message_id = can_id.id & MESSAGE_GROUP_2_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg2_vals, "Unknown"));

        ti = proto_tree_add_uint(can_tree, hf_devicenet_src_mac_id, tvb, 0, 0, (can_id.id & MESSAGE_GROUP_2_MAC_ID_MASK) >> 3);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Set source address */
        src_address = (guint8*)wmem_alloc(pinfo->pool, 1);
        *src_address = (guint8)((can_id.id & MESSAGE_GROUP_2_MAC_ID_MASK) >> 3);
        SET_ADDRESS(&pinfo->src, AT_DEVICENET, 1, (const void*)src_address);

        devicenet_contents = proto_tree_add_text(devicenet_tree, tvb, offset, -1, "Contents");
        content_tree = proto_item_add_subtree(devicenet_contents, ett_devicenet_contents);

        switch (message_id)
        {
        case 0x0:
        case 0x1:
        case 0x2:
        case 0x3:
        case 0x4:
        case 0x5:
            proto_tree_add_bytes_format_value(content_tree, hf_devicenet_data, tvb, offset, data_length,
                NULL, "%s", tvb_bytes_to_ep_str_punct(tvb, offset, data_length, ' '));
            break;

        case 0x6:
            proto_tree_add_bytes_format_value(content_tree, hf_devicenet_data, tvb, offset, data_length,
                NULL, "%s", tvb_bytes_to_ep_str_punct(tvb, offset, data_length, ' '));
            break;

        case 0x7:
            proto_tree_add_item(content_tree, hf_devicenet_dup_mac_id_rr_bit, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(content_tree, hf_devicenet_dup_mac_id_physical_port_number, tvb, offset, 1, ENC_NA);
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
    else if (can_id.id <= MESSAGE_GROUP_3_ID )
    {
        guint8 byte1;

        msg_id_item = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg3_id, tvb, 0, 0, can_id.id);
        PROTO_ITEM_SET_GENERATED(msg_id_item);
        ti = proto_tree_add_uint(can_tree, hf_devicenet_src_mac_id, tvb, 0, 0, can_id.id & MESSAGE_GROUP_3_MAC_ID_MASK);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Set source address */
        src_address = (guint8*)wmem_alloc(pinfo->pool, 1);
        *src_address = (guint8)(can_id.id & MESSAGE_GROUP_3_MAC_ID_MASK);
        SET_ADDRESS(&pinfo->src, AT_DEVICENET, 1, (const void*)src_address);

        message_id = can_id.id & MESSAGE_GROUP_3_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg3_vals, "Unknown"));

        proto_tree_add_item(devicenet_tree, hf_devicenet_grp_msg3_frag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(devicenet_tree, hf_devicenet_grp_msg3_xid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(devicenet_tree, hf_devicenet_grp_msg3_dest_mac_id, tvb, offset, 1, ENC_NA);
        byte1 = tvb_get_guint8(tvb, offset);
        source_mac = byte1 & MESSAGE_GROUP_3_MAC_ID_MASK;

        /* Set destination address */
        /* XXX - This may be source address depending on message type.  Need to adjust accordingly) */
        dest_address = (guint8*)wmem_alloc(pinfo->pool, 1);
        *dest_address = (guint8)source_mac;
        SET_ADDRESS(&pinfo->dst, AT_DEVICENET, 1, (const void*)dest_address);
        offset++;

        if (byte1 & MESSAGE_GROUP_3_FRAG_MASK)
        {
            col_set_str(pinfo->cinfo, COL_INFO, "Group 3 Message Fragment");

            devicenet_contents = proto_tree_add_text(devicenet_tree, tvb, offset, -1, "Fragmentation");
            content_tree = proto_item_add_subtree(devicenet_contents, ett_devicenet_contents);

            proto_tree_add_item(content_tree, hf_devicenet_fragment_type, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(content_tree, hf_devicenet_fragment_count, tvb, offset, 1, ENC_NA);

            /* TODO: Handle fragmentation */
            proto_tree_add_expert(content_tree, pinfo, &ei_devicenet_frag_not_supported, tvb, offset, -1);

            col_set_str(pinfo->cinfo, COL_INFO, try_val_to_str((tvb_get_guint8(tvb, offset) & 0xC0) >> 6, devicenet_fragmented_message_type_vals));
        }
        else
        {
            service_rr = tvb_get_guint8(tvb, offset);

            devicenet_contents = proto_tree_add_text(devicenet_tree, tvb, offset, -1, "Service: %s (%s)",
                        val_to_str_const(service_rr & CIP_SC_MASK, devicenet_service_code_vals, "Unknown"),
                        service_rr & CIP_SC_RESPONSE_MASK ? "Response" : "Request");
            content_tree = proto_item_add_subtree(devicenet_contents, ett_devicenet_contents);

            proto_tree_add_item(content_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_NA);
            service_item = proto_tree_add_item(content_tree, hf_devicenet_service_code, tvb, offset, 1, ENC_NA);
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
                        "Invalid service code (0x%x) for Group 3 Messsage ID 5", service_rr & CIP_SC_MASK);
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
                        "Invalid service code (0x%x) for Group 3 Messsage ID 6", service_rr & CIP_SC_MASK);
                    break;
                }
                break;
            case 0x1C0:
                expert_add_info_format(pinfo, msg_id_item, &ei_devicenet_invalid_msg_id,
                        "Invalid Group 3 Messsage ID (%d)", message_id);
                break;
            }

            switch(service_rr & CIP_SC_MASK)
            {
            case SC_OPEN_EXPLICIT_MESSAGE:
                /* XXX - Create conversation to track connections */
                if (service_rr & CIP_SC_RESPONSE_MASK)
                {
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_reserved, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_actual_body_format, tvb, offset, 1, ENC_NA);
                    offset++;
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_dest_message_id, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_src_message_id, tvb, offset, 1, ENC_NA);
                    offset++;
                    proto_tree_add_item(content_tree, hf_devicenet_connection_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
                else
                {
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_reserved, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_msg_req_body_format, tvb, offset, 1, ENC_NA);
                    offset++;
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_group_select, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(content_tree, hf_devicenet_open_exp_src_message_id, tvb, offset, 1, ENC_NA);
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
                    proto_tree_add_bytes_format_value(devicenet_tree, hf_devicenet_data, tvb, offset, data_length - 2,
                        NULL, "%s", tvb_bytes_to_ep_str_punct(tvb, offset, data_length - 2, ' '));
                }
                else
                {
                    guint channel;

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
                                proto_tree_add_bytes_format_value(content_tree, hf_devicenet_data, tvb, offset, data_length,
                                    NULL, "%s", tvb_bytes_to_ep_str_punct(tvb, offset, data_length, ' '));
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
    else if (can_id.id <= MESSAGE_GROUP_4_ID )
    {
        ti = proto_tree_add_uint(can_tree, hf_devicenet_grp_msg4_id, tvb, 0, 0, can_id.id);
        PROTO_ITEM_SET_GENERATED(ti);

        message_id = can_id.id & MESSAGE_GROUP_4_MSG_MASK;
        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_id, devicenet_grp_msg4_vals, "Reserved Group 4 Message"));

        switch(message_id)
        {
        case GRP4_COMM_FAULT_RESPONSE:
        case GRP4_COMM_FAULT_REQUEST:
            if(data_length == 2)
            {
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_rsv, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_match, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_value, tvb, offset, 1, ENC_NA);
                offset++;

                proto_tree_add_item(devicenet_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(devicenet_tree, hf_devicenet_service_code, tvb, offset, 1, ENC_NA);

                if( tvb_get_guint8(tvb, offset) & CIP_SC_RESPONSE_MASK)
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
                proto_tree_add_item(devicenet_tree, hf_devicenet_comm_fault_rsv, tvb, offset, 1, ENC_NA);
                offset++;

                proto_tree_add_item(devicenet_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(devicenet_tree, hf_devicenet_service_code, tvb, offset, 1, ENC_NA);

                if( tvb_get_guint8(tvb, offset) & CIP_SC_RESPONSE_MASK)
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
            proto_tree_add_item(devicenet_tree, hf_devicenet_offline_ownership_reserved,  tvb, offset, 1, ENC_NA);
            proto_tree_add_item(devicenet_tree, hf_devicenet_offline_ownership_client_mac_id, tvb, offset, 1, ENC_NA);
            offset++;

            proto_tree_add_item(devicenet_tree, hf_devicenet_rr_bit, tvb, offset, 1, ENC_NA);

            if( tvb_get_guint8(tvb, offset) & CIP_SC_RESPONSE_MASK)
            {
                col_append_str(pinfo->cinfo, COL_INFO, " - Response");
            }
            else
            {
                col_append_str(pinfo->cinfo, COL_INFO, " - Request");
            }

            proto_tree_add_item(devicenet_tree, hf_devicenet_offline_ownership_allocate, tvb, offset, 1, ENC_NA);
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
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid CAN Message 0x%06X", can_id.id);
        expert_add_info_format(pinfo, can_id_item, &ei_devicenet_invalid_can_id,
                    "Invalid CAN Message 0x%04X", can_id.id);
    }

    return tvb_length(tvb);
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

    static gint *ett[] = {
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

    new_register_dissector("devicenet", dissect_devicenet, proto_devicenet);

    devicenet_module = prefs_register_protocol(proto_devicenet, NULL);

    devicenet_uat = uat_new("Node bodytypes",
                            sizeof(uat_devicenet_record_t), /* record size           */
                            "devicenet_bodytypes",          /* filename              */
                            TRUE,                           /* from_profile          */
                            &uat_devicenet_records,         /* data_ptr              */
                            &num_devicenet_records_uat,     /* numitems_ptr          */
                            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
                            NULL,                           /* help                  */
                            NULL,   /* copy callback         */
                            uat_devicenet_record_update_cb, /* update callback       */
                            NULL,   /* free callback         */
                            NULL,    /* post update callback  */
                            devicenet_uat_flds);    /* UAT field definitions */

    prefs_register_uat_preference(devicenet_module,
                                      "bodytype_table",
                                      "Node bodytypes",
                                      "Node bodytypes",
                                      devicenet_uat);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
