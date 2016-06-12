/* packet-mqtt-sn.c
 *
 * Routines for MQTT-SN v1.2 <http://mqtt.org>
 *
 * Copyright (c) 2015, Jan-Hendrik Bolte <jabolte@uni-osnabrueck.de>
 * Copyright (c) 2015, University of Osnabrueck
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
#include <epan/packet.h>

/* MQTT-SN message types. */
#define MQTTSN_ADVERTISE              0x00
#define MQTTSN_SEARCHGW               0x01
#define MQTTSN_GWINFO                 0x02
#define MQTTSN_RESERVED_03            0x03
#define MQTTSN_CONNECT                0x04
#define MQTTSN_CONNACK                0x05
#define MQTTSN_WILLTOPICREQ           0x06
#define MQTTSN_WILLTOPIC              0x07
#define MQTTSN_WILLMSGREQ             0x08
#define MQTTSN_WILLMSG                0x09
#define MQTTSN_REGISTER               0x0A
#define MQTTSN_REGACK                 0x0B
#define MQTTSN_PUBLISH                0x0C
#define MQTTSN_PUBACK                 0x0D
#define MQTTSN_PUBCOMP                0x0E
#define MQTTSN_PUBREC                 0x0F
#define MQTTSN_PUBREL                 0x10
#define MQTTSN_RESERVED_11            0x11
#define MQTTSN_SUBSCRIBE              0x12
#define MQTTSN_SUBACK                 0x13
#define MQTTSN_UNSUBSCRIBE            0x14
#define MQTTSN_UNSUBACK               0x15
#define MQTTSN_PINGREQ                0x16
#define MQTTSN_PINGRESP               0x17
#define MQTTSN_DISCONNECT             0x18
#define MQTTSN_RESERVED_19            0x19
#define MQTTSN_WILLTOPICUPD           0x1A
#define MQTTSN_WILLTOPICRESP          0x1B
#define MQTTSN_WILLMSGUPD             0x1C
#define MQTTSN_WILLMSGRESP            0x1D
#define MQTTSN_ENCAPSULATED_MSG       0xFE

/* Masks to extract flag values. */
#define MQTTSN_MASK_DUP_FLAG          0x80
#define MQTTSN_MASK_QOS               0x60
#define MQTTSN_MASK_RETAIN            0x10
#define MQTTSN_MASK_WILL              0x08
#define MQTTSN_MASK_CLEAN             0x04
#define MQTTSN_MASK_TOPIC_ID_TYPE     0x03

/* Mask to extract radius from control. */
#define MQTTSN_MASK_CONTROL           0x03

/* MQTT-SN QoS levels. */
#define MQTTSN_QOS_ATMOST_ONCE      0x00
#define MQTTSN_QOS_ATLEAST_ONCE     0x01
#define MQTTSN_QOS_EXACTLY_ONCE     0x02
#define MQTTSN_QOS_NO_CONNECTION    0x03

/* MQTT-SN topic types. */
#define MQTTSN_TOPIC_NORMAL_ID      0x00
#define MQTTSN_TOPIC_PREDEF_ID      0x01
#define MQTTSN_TOPIC_SHORT_NAME     0x02
#define MQTTSN_TOPIC_RESERVED       0x03

/* MQTT-SN connection return types. */
#define MQTTSN_CON_ACCEPTED                   0x00
#define MQTTSN_CON_REFUSED_CONGESTION         0x01
#define MQTTSN_CON_REFUSED_INVALID_TOPIC_ID   0x02
#define MQTTSN_CON_REFUSED_NOT_SUPPORTED      0x03

void proto_register_mqttsn(void);
void proto_reg_handoff_mqttsn(void);

/* MQTT-SN message type values. */
static const value_string mqttsn_msgtype_vals[] = {
    { MQTTSN_ADVERTISE,           "Advertise Gateway" },
    { MQTTSN_SEARCHGW,            "Search Gateway" },
    { MQTTSN_GWINFO,              "Gateway Info" },
    { MQTTSN_RESERVED_03,         "Reserved_03" },
    { MQTTSN_CONNECT,             "Connect Command" },
    { MQTTSN_CONNACK,             "Connect Ack" },
    { MQTTSN_WILLTOPICREQ,        "Will Topic Request" },
    { MQTTSN_WILLTOPIC,           "Will Topic" },
    { MQTTSN_WILLMSGREQ,          "Will Message Request" },
    { MQTTSN_WILLMSG,             "Will Message" },
    { MQTTSN_REGISTER,            "Register" },
    { MQTTSN_REGACK,              "Register Ack" },
    { MQTTSN_PUBLISH,             "Publish Message" },
    { MQTTSN_PUBACK,              "Publish Ack" },
    { MQTTSN_PUBCOMP,             "Publish Complete" },
    { MQTTSN_PUBREC,              "Publish Received" },
    { MQTTSN_PUBREL,              "Publish Release" },
    { MQTTSN_RESERVED_11,         "Reserved_11" },
    { MQTTSN_SUBSCRIBE,           "Subscribe Request" },
    { MQTTSN_SUBACK,              "Subscribe Ack" },
    { MQTTSN_UNSUBSCRIBE,         "Unsubscribe Request" },
    { MQTTSN_UNSUBACK,            "Unsubscribe Ack" },
    { MQTTSN_PINGREQ,             "Ping Request" },
    { MQTTSN_PINGRESP,            "Ping Response" },
    { MQTTSN_DISCONNECT,          "Disconnect Req" },
    { MQTTSN_RESERVED_19,         "Reserved_19" },
    { MQTTSN_WILLTOPICUPD,        "Will Topic Update" },
    { MQTTSN_WILLTOPICRESP,       "Will Topic Response" },
    { MQTTSN_WILLMSGUPD,          "Will Message Update" },
    { MQTTSN_WILLMSGRESP,         "Will Message Response" },
    { MQTTSN_ENCAPSULATED_MSG,    "Encapsulated Message" },
    { 0,                          NULL }
};
static value_string_ext mqttsn_msgtype_vals_ext = VALUE_STRING_EXT_INIT(mqttsn_msgtype_vals);

/* MQTT-SN QoS level values. */
static const value_string mqttsn_qos_vals[] = {
    { MQTTSN_QOS_ATMOST_ONCE,         "Fire and Forget" },
    { MQTTSN_QOS_ATLEAST_ONCE,        "Acknowledged deliver" },
    { MQTTSN_QOS_EXACTLY_ONCE,        "Assured Delivery" },
    { MQTTSN_QOS_NO_CONNECTION,       "No Connection required" },
    { 0,                              NULL }
};

/* MQTT-SN topic type values. */
static const value_string mqttsn_typeid_vals[] = {
    { MQTTSN_TOPIC_NORMAL_ID,         "Normal ID" },
    { MQTTSN_TOPIC_PREDEF_ID,         "Pre-defined ID" },
    { MQTTSN_TOPIC_SHORT_NAME,        "Short Topic Name" },
    { MQTTSN_TOPIC_RESERVED,          "Reserved" },
    { 0,                              NULL }
};

/* MQTT-SN connection return type values. */
static const value_string mqttsn_return_vals[] = {
    { MQTTSN_CON_ACCEPTED,                      "Accepted" },
    { MQTTSN_CON_REFUSED_CONGESTION,            "Rejected: Congestion" },
    { MQTTSN_CON_REFUSED_INVALID_TOPIC_ID,      "Rejected: invalid topic ID" },
    { MQTTSN_CON_REFUSED_NOT_SUPPORTED,         "Rejected: not supported" },
    { 0,                                        NULL }
};

/* MQTT-SN Handle */
static dissector_handle_t mqttsn_handle;

/* Initialize the protocol and registered fields. */
static int proto_mqttsn = -1;

static int hf_mqttsn_msg = -1;
static int hf_mqttsn_msg_len = -1;
static int hf_mqttsn_msg_type = -1;
static int hf_mqttsn_dup = -1;
static int hf_mqttsn_qos = -1;
static int hf_mqttsn_retain = -1;
static int hf_mqttsn_will = -1;
static int hf_mqttsn_clean_session = -1;
static int hf_mqttsn_topic_id_type = -1;
static int hf_mqttsn_return_code = -1;
static int hf_mqttsn_gw_id = -1;
static int hf_mqttsn_gw_addr = -1;
static int hf_mqttsn_adv_interv = -1;
static int hf_mqttsn_radius = -1;
static int hf_mqttsn_protocol_id = -1;
static int hf_mqttsn_topic_id = -1;
static int hf_mqttsn_msg_id = -1;
static int hf_mqttsn_topic = -1;
static int hf_mqttsn_topic_name_or_id = -1;
static int hf_mqttsn_sleep_timer = -1;
static int hf_mqttsn_will_topic = -1;
static int hf_mqttsn_will_msg = -1;
static int hf_mqttsn_pub_msg = -1;
static int hf_mqttsn_client_id = -1;
static int hf_mqttsn_keep_alive = -1;
static int hf_mqttsn_control_info = -1;
static int hf_mqttsn_wireless_node_id = -1;

/* Initialize subtree pointers. */
static gint ett_mqttsn_hdr = -1;
static gint ett_mqttsn_msg = -1;
static gint ett_mqttsn_flags = -1;

/* Dissect a single MQTT-SN packet. */
static void dissect_mqttsn_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    /* Various variables. */
    int long_hdr_len = 0;
    guint8 mqttsn_msg_type_id;
    guint16 mqttsn_msg_len;

    /* Get the message length. */
    mqttsn_msg_len = tvb_get_guint8(tvb, offset);

    /* If the message length is equal to 1 then the next two bytes define the real message length. */
    if (mqttsn_msg_len == 1)
    {
        long_hdr_len = 1;
        mqttsn_msg_len = tvb_get_ntohs(tvb, offset + 1);
    }

    /* If this is an encapsulated message, we need to add the offset of the previous packet. */
    mqttsn_msg_len += offset;

    /* Get the message type id (in byte 1 or 3 - depending on the message length). */
    mqttsn_msg_type_id = tvb_get_guint8(tvb, offset + (long_hdr_len ? 3 : 1));

    if (tree)
    {
        /* Variables for the message items and trees. */
        proto_item *ti = NULL;
        proto_item *ti_mqttsn = NULL;
        proto_tree *mqttsn_tree = NULL;
        proto_tree *mqttsn_msg_tree = NULL;
        proto_tree *mqttsn_flag_tree = NULL;

        /* Add MQTT-SN subtree to the main tree. */
        if (offset == 0)
        {
            ti = proto_tree_add_item(tree, proto_mqttsn, tvb, 0, -1, ENC_NA);
            mqttsn_tree = proto_item_add_subtree(ti, ett_mqttsn_hdr);
        }
        /* If this is an encapsulated message, we add the message to the existing subtree. */
        else
        {
            mqttsn_tree = tree;
        }

        /* Add message subtree. */
        ti_mqttsn = proto_tree_add_item(mqttsn_tree, hf_mqttsn_msg, tvb, offset + (long_hdr_len ? 3 : 1), -1, ENC_NA);
        mqttsn_msg_tree = proto_item_add_subtree(ti_mqttsn, ett_mqttsn_msg);

        /* | Message type (1 octet) | */
        proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_type, tvb, offset + (long_hdr_len ? 3 : 1), 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* | Message length (1 - 2 octets) | */
        proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_len, tvb, offset - 1 + (long_hdr_len ? 1 : 0), (long_hdr_len ? 2 : 1), ENC_BIG_ENDIAN);
        offset += (long_hdr_len ? 3 : 1);

        /*
         * Only some message types contain flags (1 octet).
         * ______________________________________________________________________________________
         * |         |           |            |          |                  |                   |
         * |  bit 7  | bit 6 + 5 |    bit 4   |   bit 3  |      bit 2       |     bit 1 + 0     |
         * |   DUP   |    QoS    |   Retain   |   Will   |   CleanSession   |    TopicIdType    |
         * |_________|___________|____________|__________|__________________|___________________|
         */
        switch (mqttsn_msg_type_id)
        {
            /* Connect */
            case MQTTSN_CONNECT:
                /* Add Will, CleanSession and Topic ID Type flags. */
                mqttsn_flag_tree = proto_item_add_subtree(ti_mqttsn, ett_mqttsn_flags);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_will, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_clean_session, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_topic_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            /* Publish */
            case MQTTSN_PUBLISH:
                /* Add DUP, QoS, Retain and Topic ID Type flags. */
                mqttsn_flag_tree = proto_item_add_subtree(ti_mqttsn, ett_mqttsn_flags);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_dup, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_retain, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_topic_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            /* Will Topic + Subscribe + Subscribe Acknowledgement + Unsubscribe + Will Topic Update */
            case MQTTSN_WILLTOPIC:
            case MQTTSN_SUBSCRIBE:
            case MQTTSN_SUBACK:
            case MQTTSN_UNSUBSCRIBE:
            case MQTTSN_WILLTOPICUPD:
                /* Add Topic ID Type flag. */
                mqttsn_flag_tree = proto_item_add_subtree(ti_mqttsn, ett_mqttsn_flags);
                proto_tree_add_item(mqttsn_flag_tree, hf_mqttsn_topic_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;

            /* Default Case */
            default:
                break;
        }

        /* Add message specific informations. */
        switch (mqttsn_msg_type_id)
        {
            /* Advertise Gateway */
            case MQTTSN_ADVERTISE:
                /* | 1 - Gateway ID | 2,3 - Duration until next Advertise | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_gw_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_adv_interv, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;

            /* Search Gateway */
            case MQTTSN_SEARCHGW:
                /* | 1 - Broadcast Radius | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_radius, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            /* Gateway Information */
            case MQTTSN_GWINFO:
                /* | 1 - Gateway ID | 2:n - Gateway Address (optional) | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_gw_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Gateway Address is only present if message is sent by client. */
                if (offset < mqttsn_msg_len)
                {
                    proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_gw_addr, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                }
                break;

            /* Connect */
            case MQTTSN_CONNECT:
                /* | 1 - Protocol ID | 2,3 - Keep Alive Duration | 4:n - Client ID | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_protocol_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_keep_alive, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_client_id, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Connection Acknowledgement */
            case MQTTSN_CONNACK:
                /* | 1 - Return code | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            /* Will Topic Request + Will Message Request */
            case MQTTSN_WILLTOPICREQ:
            case MQTTSN_WILLMSGREQ:
                /* Will topic/message requests don't have a variable header. */
                break;

            /* Will Topic */
            case MQTTSN_WILLTOPIC:
                /* | 1:n - Will topic | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_will_topic, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Will Message */
            case MQTTSN_WILLMSG:
                /* | 1:n - Will message | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_will_msg, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Register */
            case MQTTSN_REGISTER:
                /* | 1,2 - Topic ID | 3,4 - Message ID | 5:n - Topic name | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Register Acknowledgement */
            case MQTTSN_REGACK:
                /* | 1,2 - Topic ID | 3,4 - Message ID | 5 - Return code | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            /* Publish */
            case MQTTSN_PUBLISH:
                /* | 1,2 - Topic ID | 3,4 - Message ID | 5:n - Publish data | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_pub_msg, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Publish Acknowledgement */
            case MQTTSN_PUBACK:
                /* | 1,2 - Topic ID | 3,4 - Message ID | 5 - Return code | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            /* Publish Complete + Publish Received + Publish Released */
            case MQTTSN_PUBCOMP:
            case MQTTSN_PUBREC:
            case MQTTSN_PUBREL:
                /* | 1,2 - Message ID | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;

            /* Subscribe + Unsubscribe */
            case MQTTSN_SUBSCRIBE:
            case MQTTSN_UNSUBSCRIBE:
                /* | 1,2 - Message ID | 5:n - Topic name _OR_ 5,6 - Topic ID | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic_name_or_id, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Subscribe Acknowledgment */
            case MQTTSN_SUBACK:
                /* | 1,2 - Topic ID | 3,4 - Message ID | 5 - Return code | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_topic_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            /* Unsubscribe Acknowledgement */
            case MQTTSN_UNSUBACK:
                /* | 1,2 - Message ID | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;

            /* Ping Request */
            case MQTTSN_PINGREQ:
                /* | 1:n - Client ID (optional) | */
                if (offset < mqttsn_msg_len)
                {
                    proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_client_id, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                }
                break;

            /* Ping Response */
            case MQTTSN_PINGRESP:
                /* Ping responses don't have a variable header. */
                break;

            /* Disconnect */
            case MQTTSN_DISCONNECT:
                /* | 1,2 - Sleep Time Duration (optional) | */
                if (offset < mqttsn_msg_len)
                {
                    proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_sleep_timer, tvb, offset, 2, ENC_BIG_ENDIAN);
                }
                break;

            /* Will Topic Update */
            case MQTTSN_WILLTOPICUPD:
                /* | 1:n - Will topic | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_will_topic, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Will Message Update */
            case MQTTSN_WILLMSGUPD:
                /* | 1:n - Will message | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_will_msg, tvb, offset, (mqttsn_msg_len - offset), ENC_ASCII|ENC_NA);
                break;

            /* Will Topic Response + Will Message Response */
            case MQTTSN_WILLTOPICRESP:
            case MQTTSN_WILLMSGRESP:
                /* | 1 - Return code | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case MQTTSN_ENCAPSULATED_MSG:
                /* | 1 - Control information | 2:n - Wireless Node ID | n+1:m - MQTT-SN message | */
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_control_info, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(mqttsn_msg_tree, hf_mqttsn_wireless_node_id, tvb, offset, (mqttsn_msg_len - offset), ENC_BIG_ENDIAN);
                offset += (mqttsn_msg_len - offset);

                /* Dissect encapsulated message (if present). */
                if (tvb_reported_length_remaining(tvb, offset) > 0)
                {
                    dissect_mqttsn_packet(tvb, pinfo, mqttsn_msg_tree, offset);
                }

            /* Default Case */
            default:
                break;
        }
    }
}

/* Dissect a complete MQTT-SN message. */
static int dissect_mqttsn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Various variables. */
    int offset = 0;
    guint8 mqttsn_msg_type_id;

    /*
     * If the value in byte 0 is unequal to 1 then the value defines the
     * message length and the message type id is contained in byte 1.
     */
    if (tvb_get_guint8(tvb, 0) != 1)
    {
        mqttsn_msg_type_id = tvb_get_guint8(tvb, 1);
    }
    /*
     * If the value in byte 0 is equal to 1 then the next two bytes define
     * the real message length and the message type id is contained in byte 3.
     */
    else
    {
        mqttsn_msg_type_id = tvb_get_guint8(tvb, 3);
    }

    /* Add the protcol name to the protocol column. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQTT-SN");

    /* Add the message type to the info column. */
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(mqttsn_msg_type_id, &mqttsn_msgtype_vals_ext, "Unknown (0x%02x)"));

    /* Dissect a MQTT-SN packet. */
    dissect_mqttsn_packet(tvb, pinfo, tree, offset);
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark. */
void proto_register_mqttsn(void)
{
    static hf_register_info hf_mqttsn[] = {
        { &hf_mqttsn_msg,
            { "Message", "mqttsn.msg",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_mqttsn_msg_len,
            { "Message Length", "mqttsn.msg.len",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_msg_type,
            { "Message Type", "mqttsn.msg.type",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mqttsn_msgtype_vals_ext, 0,
                NULL, HFILL }
        },
        { &hf_mqttsn_dup,
            { "DUP", "mqttsn.dup",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), MQTTSN_MASK_DUP_FLAG,
                NULL, HFILL }
        },
        { &hf_mqttsn_will,
            { "Will", "mqttsn.will",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), MQTTSN_MASK_WILL,
                NULL, HFILL }
        },
        { &hf_mqttsn_clean_session,
            { "Clean Session", "mqttsn.clean.session",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), MQTTSN_MASK_CLEAN,
                NULL, HFILL }
        },
        { &hf_mqttsn_topic_id_type,
            { "Topic ID Type", "mqttsn.topic.id.type",
                FT_UINT8, BASE_HEX, VALS(mqttsn_typeid_vals), MQTTSN_MASK_TOPIC_ID_TYPE,
                NULL, HFILL }
        },
        { &hf_mqttsn_qos,
            { "QoS", "mqttsn.qos",
                FT_UINT8, BASE_HEX, VALS(mqttsn_qos_vals), MQTTSN_MASK_QOS,
                NULL, HFILL }
        },
        { &hf_mqttsn_retain,
            { "Retain", "mqttsn.retain",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), MQTTSN_MASK_RETAIN,
                NULL, HFILL }
        },
        { &hf_mqttsn_return_code,
            { "Return Code", "mqttsn.return.code",
                FT_UINT8, BASE_HEX, VALS(mqttsn_return_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_gw_id,
            { "Gateway ID", "mqttsn.gw.id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_gw_addr,
            { "Gateway Address", "mqttsn.gw.addr",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_adv_interv,
            { "Advertise Interval", "mqttsn.adv.interv",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_radius,
            { "Broadcast Radius", "mqttsn.radius",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_protocol_id,
            { "Protocol ID", "mqttsn.protocol.id",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_topic_id,
            { "Topic ID", "mqttsn.topic.id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_msg_id,
            { "Message ID", "mqttsn.msg.id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_topic,
            { "Topic Name", "mqttsn.topic",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_topic_name_or_id,
            { "Topic Name/ID", "mqttsn.topic.name.or.id",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_sleep_timer,
            { "Sleep Timer", "mqttsn.sleep.timer",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_will_topic,
            { "Will Topic", "mqttsn.will.topic",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_will_msg,
            { "Will Message", "mqttsn.will.msg",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_pub_msg,
            { "Message", "mqttsn.pub.msg",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_client_id,
            { "Client ID", "mqttsn.client.id",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_keep_alive,
            { "Keep Alive", "mqttsn.keep.alive",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_mqttsn_control_info,
            { "Control", "mqttsn.control.info",
                FT_UINT8, BASE_HEX, NULL, MQTTSN_MASK_CONTROL,
                NULL, HFILL }
        },
        { &hf_mqttsn_wireless_node_id,
            { "Wireless Node ID", "mqttsn.wireless.node.id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        }
    };

    /* Setup protocol subtree arrays. */
    static gint* ett_mqttsn[] = {
        &ett_mqttsn_hdr,
        &ett_mqttsn_msg,
        &ett_mqttsn_flags
    };

    /* Register protocol names and descriptions. */
    proto_mqttsn = proto_register_protocol("MQ Telemetry Transport Protocol for Sensor Networks", "MQTT-SN", "mqttsn");

    /* Create the dissector handle. */
    mqttsn_handle = create_dissector_handle(dissect_mqttsn, proto_mqttsn);

    /* Register fields and subtrees. */
    proto_register_field_array(proto_mqttsn, hf_mqttsn, array_length(hf_mqttsn));
    proto_register_subtree_array(ett_mqttsn, array_length(ett_mqttsn));
}

/* Dissector Handoff */
void proto_reg_handoff_mqttsn(void)
{
    dissector_add_for_decode_as("udp.port", mqttsn_handle);
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
