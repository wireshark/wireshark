/* packet-aruba-ubt.c
 * Routines for Aruba UBT dissection
 *
 * Real name of UBT : User Based Tunneling
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /* header files */
#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include "packet-ipv6.h"

/* This is not IANA assigned nor registered */
#define PORT_UBT 15560

void proto_register_ubt(void);
void proto_reg_handoff_ubt(void);

/* declaring dissector handle */
static dissector_handle_t ubt_handle;

/* Initialize the protocol and registered fields */
static int proto_ubt;
static int hf_ubt_packet_len;
static int hf_ubt_msg_type;
static int hf_ubt_tlv_header;
static int hf_ubt_tlv;
static int hf_ubt_type;
static int hf_ubt_length;
static int hf_ubt_switch_seqno;
static int hf_ubt_switch_macaddr;

/* for data attributes */
static int hf_ubt_dt_unknown;
static int hf_ubt_dt_grekey;
static int hf_ubt_dt_firmwareversion;
static int hf_ubt_dt_userkey;
static int hf_ubt_dt_sacmode;
static int hf_ubt_dt_sacipv4;
static int hf_ubt_dt_sacipv6;
static int hf_ubt_dt_heartbeattimeout;
static int hf_ubt_dt_usermac;
static int hf_ubt_dt_uservlan;
static int hf_ubt_dt_flags;

/* for ip attributes */
static int hf_ubt_ip_type;
static int hf_ubt_ip_padding;
static int hf_ubt_ip_unassigned;

/* for switch & user flags */
static int hf_ubt_switch_flags_bcmctoucast;
static int hf_ubt_user_flags_tag;
static int hf_ubt_user_flags_auth;
static int hf_ubt_user_flags_bcmctoucast;
static int hf_ubt_user_flags_dormant;
static int hf_ubt_user_flags_uback;

static int hf_ubt_dt_tunnelmtu;
static int hf_ubt_dt_userrole;
static int hf_ubt_dt_reasoncode;
static int hf_ubt_dt_nodelist;
static int hf_ubt_dt_clustername;
static int hf_ubt_dt_clusterenabled;
static int hf_ubt_dt_ssacindex;
static int hf_ubt_dt_reserved;
static int hf_ubt_dt_uaccount;
static int hf_ubt_dt_uaciplist;
static int hf_ubt_dt_uacipv4;
static int hf_ubt_dt_uacipv6;
static int hf_ubt_dt_bucketmap;
static int hf_ubt_dt_timestamp;
static int hf_ubt_dt_identifier;

/* for active map arrays */
static int hf_ubt_dt_activemap1;
static int hf_ubt_dt_activemap2;
static int hf_ubt_dt_activemap3;
static int hf_ubt_dt_activemap4;
static int hf_ubt_dt_activemap5;
static int hf_ubt_dt_activemap6;
static int hf_ubt_dt_activemap7;
static int hf_ubt_dt_activemap8;

/* for standby map arrays */
static int hf_ubt_dt_standbymap1;
static int hf_ubt_dt_standbymap2;
static int hf_ubt_dt_standbymap3;
static int hf_ubt_dt_standbymap4;
static int hf_ubt_dt_standbymap5;
static int hf_ubt_dt_standbymap6;
static int hf_ubt_dt_standbymap7;
static int hf_ubt_dt_standbymap8;

/* for l2conn arrays */
static int hf_ubt_dt_l2conn1;
static int hf_ubt_dt_l2conn2;
static int hf_ubt_dt_l2conn3;
static int hf_ubt_dt_l2conn4;
static int hf_ubt_dt_l2conn5;
static int hf_ubt_dt_l2conn6;
static int hf_ubt_dt_l2conn7;
static int hf_ubt_dt_l2conn8;

static int hf_ubt_dt_status;
static int hf_ubt_dt_mcastkey;
static int hf_ubt_dt_serveripv4;
static int hf_ubt_dt_serveripv6;
static int hf_ubt_dt_userauthmethod;
static int hf_ubt_dt_username;
static int hf_ubt_dt_userportname;
static int hf_ubt_dt_switchname;
static int hf_ubt_dt_silentclientvlans;
static int hf_ubt_dt_silentclientvlan;
static int hf_ubt_dt_maxmsgs;

static expert_field ei_ubt_unknown;

/* Initialize the subtree pointers */
static int ett_ubt;
static int ett_ubt_tlv;
static int ett_ubt_flags;

/* Definition of different sizes and counts used throughout the program */
#define PAPI_PACKET_SIZE 76
#define SIZE_AT_DEST_PORT 16
#define SIZE_AT_SRC_PORT 18
#define PACKET_LENGTH_SIZE 4
#define MESSAGE_TYPE_SIZE 4
#define MAC_ADDR_SIZE 6
#define SEQ_NO_SIZE 4
#define TYPE_SIZE 1
#define LENGTH_SIZE 2
#define CLUSTER_NAME_SIZE 32
#define CLUSTER_ENABLED 1
#define SSAC_INDEX 1
#define RESERVED_COUNT 1
#define UAC_COUNT_SIZE 1
#define UAC_MAX_COUNT 12
#define IP_SIZE 20
#define TIMESTAMP_SIZE 8
#define IDENTIFIER_SIZE 33
#define MAP_SIZE 256
#define MAP_SUBSET_SIZE 32
#define MAP_ARRAY_SIZE 8
#define INCREMENT_SIZE 2
#define TYPE_IPV4 0x02
#define TYPE_IPV6 0x0a
#define TYPE_NOT_ASSIGNED 0x0
#define AUTH_METHOD_8021X 2
#define AUTH_METHOD_WEB 3
#define AUTH_METHOD_MAC 4
#define AUTH_METHOD_LMA 6

static const value_string ubt_authmethod_vals[] = {
    { AUTH_METHOD_8021X, "UB_AUTH_METHOD_8021X" },
    { AUTH_METHOD_WEB, "UB_AUTH_METHOD_WEB" },
    { AUTH_METHOD_MAC, "UB_AUTH_METHOD_MAC" },
    { AUTH_METHOD_LMA, "UB_AUTH_METHOD_LMA" },
    { 0,     NULL     }
};

static const value_string ubt_iptype_vals[] = {
    { TYPE_IPV4, "IPv4" },
    { TYPE_IPV6, "IPv6" },
    { TYPE_NOT_ASSIGNED, "Not Assigned" },
    { 0,     NULL     }
};

/* to enumerate different UBT message types */
enum messagetype {
    NotKnown,                   //Type 0, undefined
    SwitchBootstrapMessage,     //Type 1
    SwitchBootstrapACK,         //Type 2
    ControllerNodelistMessage,  //Type 3
    ControllerNodelistACK,      //Type 4
    ControllerBucketmapMessage, //Type 5
    ControllerBucketmapACK,     //Type 6
    SwitchFailoverMessage,      //Type 7
    SwitchFailoverACK,          //Type 8
    SwitchUnbootstrapMessage,   //Type 9
    SwitchUnbootstrapACK,       //Type 10
    UserBootstrapMessage,       //Type 11
    UserBootstrapACK,           //Type 12
    UserUnbootstrapMessage,     //Type 13
    UserUnbootstrapACK,         //Type 14
    SwitchKeepaliveMessage,     //Type 15
    SwitchKeepaliveACK,         //Type 16
    SwitchHeartbeatRequest,     //Type 17
    SwitchHeartbeatACK,         //Type 18
    SwitchSilentVLANMessage,    //Type 19
    SwitchSilentVLANACK         //Type 20
};

static const value_string ubt_msgtype_vals[] = {
    { SwitchBootstrapMessage, "Switch Bootstrap Message" },
    { SwitchBootstrapACK, "Switch Bootstrap ACK" },
    { ControllerNodelistMessage, "Controller Nodelist Message" },
    { ControllerNodelistACK, "Controller Nodelist ACK" },
    { ControllerBucketmapMessage, "Controller Bucketmap Message" },
    { ControllerBucketmapACK, "Controller Bucketmap ACK" },
    { SwitchFailoverMessage, "Switch Failover Message" },
    { SwitchFailoverACK, "Switch Failover ACK" },
    { SwitchUnbootstrapMessage, "Switch Unbootstrap Message" },
    { SwitchUnbootstrapACK, "Switch Unbootstrap ACK" },
    { UserBootstrapMessage, "User Bootstrap Message" },
    { UserBootstrapACK, "User Bootstrap ACK" },
    { UserUnbootstrapMessage, "User Unbootstrap Message" },
    { UserUnbootstrapACK, "User Unbootstrap ACK" },
    { SwitchKeepaliveMessage, "Switch Keepalive Message" },
    { SwitchKeepaliveACK, "Switch Keepalive ACK" },
    { SwitchHeartbeatRequest, "Switch Heartbeat Request" },
    { SwitchHeartbeatACK, "Switch Heartbeat ACK" },
    { SwitchSilentVLANMessage, "Switch Silent VLAN Message" },
    { SwitchSilentVLANACK, "Switch Silent VLAN ACK" },
    { 0,     NULL     }
};

/* to enumerate different data attributes */
enum datatypes {
    Unknown,            //Type 0, undefined
    GREKey,             //Type 1
    FirmwareVersion,    //Type 2
    UserKey,            //Type 3
    SACMode,            //Type 4
    SACIPAddress,       //Type 5
    HeartbeatTimeout,   //Type 6
    UserMAC,            //Type 7
    UserVLAN,           //Type 8
    Flags,              //Type 9
    TunnelMTU,          //Type 10
    UserRole,           //Type 11
    ReasonCode,         //Type 12
    Nodelist,           //Type 13
    Bucketmap,          //Type 14
    Status,             //Type 15
    MCASTKey,           //Type 16
    ServerIP,           //Type 17
    UserAuthMethod,     //Type 18
    Username,           //Type 19
    UserPortName,       //Type 20
    SwitchName,         //Type 21
    SilentClientVLANs,  //Type 22
    MaxMsgs             //Type 23
};

static const value_string ubt_dttype_vals[] = {
    { GREKey, "GRE Key" },
    { FirmwareVersion, "Firmware Version" },
    { UserKey, "User Key" },
    { SACMode, "SAC Mode" },
    { SACIPAddress, "SAC IP Address" },
    { HeartbeatTimeout, "Heartbeat Timeout" },
    { UserMAC, "User MAC Address" },
    { UserVLAN, "User VLAN" },
    { Flags, "Flags" },
    { TunnelMTU, "Tunnel MTU" },
    { UserRole, "User Role" },
    { ReasonCode, "Reason Code" },
    { Nodelist, "Node List" },
    { Bucketmap, "Bucket Map" },
    { Status, "Status" },
    { MCASTKey, "MCast Key" },
    { ServerIP, "Server IP Address" },
    { UserAuthMethod, "User Auth Method" },
    { Username, "Username" },
    { UserPortName, "User Port Name" },
    { SwitchName, "Switch Name" },
    { SilentClientVLANs, "Silent Client VLANs" },
    { MaxMsgs, "Max Messages" },
    { 0,     NULL     }
};

/* main dissector function */
static int
dissect_ubt(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    /* declaration of variables used */
    proto_item* ti, * ubt_msg_type;
    proto_tree* message_tree, * message_subtree, * message_subtree2, * message_subtree3, * message_subtree4;
    unsigned offset_end = 0, msgtype = 0, offset = 0;
    tvbuff_t* next_tvb;

    /* Setting protocol column to UBT */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBT");

    /* clearing info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* setting proto_item & tree to the current offset */
    ti = proto_tree_add_item(tree, proto_ubt, tvb, offset, -1, ENC_NA);

    /* adding it as a subtree to Wireshark tree */
    message_tree = proto_item_add_subtree(ti, ett_ubt);

    /* determining packet length & message type */
    proto_tree_add_item(message_tree, hf_ubt_packet_len, tvb, offset, PACKET_LENGTH_SIZE, ENC_BIG_ENDIAN);
    offset += PACKET_LENGTH_SIZE;
    ubt_msg_type = proto_tree_add_item_ret_uint(message_tree, hf_ubt_msg_type, tvb, offset, MESSAGE_TYPE_SIZE, ENC_BIG_ENDIAN, &msgtype);

    proto_item_append_text(ubt_msg_type, "(%s)", val_to_str(msgtype, ubt_msgtype_vals, "Unknown Type (%02d)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(msgtype, ubt_msgtype_vals, "Unknown Type (%02d)"));

    offset += MESSAGE_TYPE_SIZE;

    /* Condition to check if Switch MAC address to be added or not */
    if (msgtype != UserBootstrapACK && msgtype != SwitchKeepaliveACK) {
        proto_tree_add_item(message_tree, hf_ubt_switch_macaddr, tvb, offset, MAC_ADDR_SIZE, ENC_NA);

        /* appending to info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " switchmac:%s", tvb_get_ether_name(tvb, offset));
        offset += MAC_ADDR_SIZE;
    }

    /* adding Switch Sequence Number to tree */
    proto_tree_add_item(message_tree, hf_ubt_switch_seqno, tvb, offset, SEQ_NO_SIZE, ENC_NA);

    /* appending to info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " seq:%d", tvb_get_uint32(tvb, offset, ENC_NA));
    offset += SEQ_NO_SIZE;

    /* if Switch Keepalive Message type, terminate dissection */
    if (msgtype == SwitchKeepaliveMessage) {
        return offset;
    }

    /* storing length of buffer */
    offset_end = tvb_reported_length(tvb);

    /* dealing with TLVs */
    proto_item* tlv_header;
    tlv_header = proto_tree_add_item(message_tree, hf_ubt_tlv_header, tvb, offset, -1, ENC_NA);
    message_subtree = proto_item_add_subtree(tlv_header, ett_ubt);

    while (offset < offset_end) {

        /* variable to store T, L, V of TLVs & other data */
        unsigned optlen = 0, type = 0, val = 0;
        bool bool_val = false;
        proto_item* tlv, * tlv_item, * tlv_item2;

        /* reading type & length of TLVS from stream */
        type = tvb_get_uint8(tvb, offset);
        optlen = tvb_get_uint16(tvb, offset + TYPE_SIZE, ENC_BIG_ENDIAN);

        /* Adding TLV items to the tree */
        tlv = proto_tree_add_item(message_subtree, hf_ubt_tlv, tvb, offset, optlen + TYPE_SIZE + LENGTH_SIZE, ENC_NA);
        proto_item_append_text(tlv, ": t=%d, l=%d, %s", type, optlen, val_to_str(type, ubt_dttype_vals, "Unknown Type (%02d)"));
        message_subtree2 = proto_item_add_subtree(tlv, ett_ubt_tlv);

        /* adding type & length to TLV subtree */
        proto_tree_add_item(message_subtree2, hf_ubt_type, tvb, offset, TYPE_SIZE, ENC_NA);
        offset += TYPE_SIZE;
        proto_tree_add_item(message_subtree2, hf_ubt_length, tvb, offset, LENGTH_SIZE, ENC_NA);
        offset += LENGTH_SIZE;

        /* Different data types */
        switch (type) {

        case Unknown:/* Unknown, because type 0 is undefined */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_unknown, tvb, offset, optlen, ENC_NA);
            offset += optlen;
            break;

        case GREKey:/* Type 1: GRE Key */

            /* adding GRE key as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_grekey, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %#x(%u)", val, val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " grekey:%u", val);
            offset += optlen;
            break;

        case FirmwareVersion:/* Type 2: Firmware version */

            /* adding Firmware version as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_firmwareversion, tvb, offset, optlen, ENC_ASCII);
            proto_item_append_text(tlv, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, optlen, ENC_ASCII));
            offset += optlen;
            break;

        case UserKey:/* Type 3: User key */

            /* adding User key as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_userkey, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %#x(%u)", val, val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " userkey:%u", val);
            offset += optlen;
            break;

        case SACMode:/* Type 4: SAC Mode */

            /* adding SAC mode as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_sacmode, tvb, offset, optlen, ENC_NA, &val);
            proto_item_append_text(tlv, ": %u", val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " sacMode:%u", val);
            offset += optlen;
            break;

        case SACIPAddress:/* Type 5: SAC IP Address */

            /* adding SAC IP Address as proto_item to the tree */

            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_ip_type, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
            offset += 2;

            switch (val) {

            case TYPE_IPV6:
                proto_tree_add_item(message_subtree2, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(message_subtree2, hf_ubt_dt_sacipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
                offset += IPv6_ADDR_SIZE;
                break;

            case TYPE_IPV4:
                proto_tree_add_item(message_subtree2, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(message_subtree2, hf_ubt_dt_sacipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(message_subtree2, hf_ubt_ip_padding, tvb, offset, 12, ENC_NA);
                offset += 12;
                break;

            case TYPE_NOT_ASSIGNED:
                proto_tree_add_item(message_subtree2, hf_ubt_ip_unassigned, tvb, offset, IP_SIZE - 2, ENC_NA);
                offset += IP_SIZE - 2;
                break;

            default:
                proto_tree_add_expert_format(message_subtree2, pinfo, &ei_ubt_unknown, tvb, offset, IP_SIZE - 2, "Invalid IP Type");
                offset += IP_SIZE - 2;

            }
            break;

        case HeartbeatTimeout:/* Type 6: Heartbeat Timeout */

            /* adding Heartbeat timeout as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_heartbeattimeout, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %u", val);
            offset += optlen;
            break;

        case UserMAC:/* Type 7: User MAC Address */

            /* adding User MAC address as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_usermac, tvb, offset, optlen, ENC_NA);
            proto_item_append_text(tlv, ": %s", tvb_get_ether_name(tvb, offset));

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " usermac:%s", tvb_get_ether_name(tvb, offset));
            offset += optlen;
            break;

        case UserVLAN:/* Type 8: User VLAN */

            /* adding User VLAN as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_uservlan, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %#x(%u)", val, val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " vlan:%u", val);
            offset += optlen;
            break;

        case Flags:/* Type 9: Flags */

            /* adding flags for switch */
            if (msgtype == SwitchBootstrapMessage) {
                static int* const ubt_switch_flags[] = {
                &hf_ubt_switch_flags_bcmctoucast,
                NULL
                };
                proto_tree_add_bitmask_with_flags(message_subtree2, tvb, offset, hf_ubt_dt_flags, ett_ubt_flags, ubt_switch_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            }

            /* adding flags for user */
            else if (msgtype == UserBootstrapMessage) {
                static int* const ubt_user_flags[] = {
                &hf_ubt_user_flags_tag,
                &hf_ubt_user_flags_auth,
                &hf_ubt_user_flags_bcmctoucast,
                &hf_ubt_user_flags_dormant,
                &hf_ubt_user_flags_uback,
                NULL
                };
                proto_tree_add_bitmask_with_flags(message_subtree2, tvb, offset, hf_ubt_dt_flags, ett_ubt_flags, ubt_user_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
            }

            val = tvb_get_uint8(tvb, offset);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " flags:%u", val);
            offset += optlen;
            break;

        case TunnelMTU:/* Type 10: Tunnel MTU */

            /* adding Tunnel MTU as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_tunnelmtu, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %#x(%u)", val, val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " mtu:%u", val);
            offset += optlen;
            break;

        case UserRole:/* Type 11: User Role */

            /* adding User Role as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_userrole, tvb, offset, optlen, ENC_ASCII);
            char* userrole = tvb_get_string_enc(pinfo->pool, tvb, offset, optlen, ENC_ASCII);
            proto_item_append_text(tlv, ": %s", userrole);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " role:%s", userrole);
            offset += optlen;
            break;

        case ReasonCode:/* Type 12: Reason Code */

            /* adding Reason Code as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_reasoncode, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %u", val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " reason:%u", val);
            offset += optlen;
            break;

        case Nodelist:/* Type 13: Nodelist */

            /* adding Nodelist as proto_item to the tree */
            tlv_item = proto_tree_add_item(message_subtree2, hf_ubt_dt_nodelist, tvb, offset, optlen, ENC_NA);
            message_subtree3 = proto_item_add_subtree(tlv_item, ett_ubt_tlv);

            /* adding name of cluster to tree */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_clustername, tvb, offset, CLUSTER_NAME_SIZE, ENC_ASCII);
            offset += CLUSTER_NAME_SIZE;

            /* determining if cluster enabled or not */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_clusterenabled, tvb, offset, CLUSTER_ENABLED, ENC_NA);
            offset += CLUSTER_ENABLED;

            /* adding SSAC index to tree */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_ssacindex, tvb, offset, SSAC_INDEX, ENC_NA);
            offset += SSAC_INDEX;

            /* adding no of reserved to tree */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_reserved, tvb, offset, RESERVED_COUNT, ENC_NA);
            offset += RESERVED_COUNT;

            /* adding no of UACs assigned */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_uaccount, tvb, offset, UAC_COUNT_SIZE, ENC_NA);
            offset += UAC_COUNT_SIZE;

            /* adding list of UAC IPs assigned */
            for (int i = 0; i < UAC_MAX_COUNT; i++) {
                tlv_item = proto_tree_add_item(message_subtree3, hf_ubt_dt_uaciplist, tvb, offset, IP_SIZE, ENC_NA);
                message_subtree4 = proto_item_add_subtree(tlv_item, ett_ubt_tlv);
                proto_item_append_text(tlv_item, "(%d)", i + 1);

                proto_tree_add_item_ret_uint(message_subtree4, hf_ubt_ip_type, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
                offset += 2;

                switch (val) {

                case TYPE_IPV6:
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(message_subtree4, hf_ubt_dt_uacipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
                    offset += IPv6_ADDR_SIZE;
                    break;

                case TYPE_IPV4:
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(message_subtree4, hf_ubt_dt_uacipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_padding, tvb, offset, 12, ENC_NA);
                    offset += 12;
                    break;

                case TYPE_NOT_ASSIGNED:
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_unassigned, tvb, offset, IP_SIZE - 2, ENC_NA);
                    offset += IP_SIZE - 2;
                    break;

                default:
                    proto_tree_add_expert_format(message_subtree4, pinfo, &ei_ubt_unknown, tvb, offset, IP_SIZE - 2, "Invalid IP Type");
                    offset += IP_SIZE - 2;

                }
            }
            break;

        case Bucketmap:/* Type 14: Bucketmap */

            /* adding Bucketmap as proto_item to the tree */
            tlv_item = proto_tree_add_item(message_subtree2, hf_ubt_dt_bucketmap, tvb, offset, optlen, ENC_NA);
            message_subtree3 = proto_item_add_subtree(tlv_item, ett_ubt_tlv);

            /* adding timestamp to tree */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_timestamp, tvb, offset, TIMESTAMP_SIZE, ENC_NA);
            offset += TIMESTAMP_SIZE;

            /* adding identifier string to tree */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_identifier, tvb, offset, IDENTIFIER_SIZE, ENC_ASCII);
            offset += IDENTIFIER_SIZE;

            /* array to store activemaps in size of 32 */
            int arr[MAP_ARRAY_SIZE] = { hf_ubt_dt_activemap1 ,hf_ubt_dt_activemap2 ,hf_ubt_dt_activemap3 ,hf_ubt_dt_activemap4 ,hf_ubt_dt_activemap5 ,hf_ubt_dt_activemap6 ,hf_ubt_dt_activemap7 ,hf_ubt_dt_activemap8 };
            /* adding activemaps of size 32 at a time */
            for (int i = 0; i < MAP_SIZE; i += MAP_SUBSET_SIZE) {
                if ((i / MAP_SUBSET_SIZE) == 0) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "    %02d", tvb_get_int8(tvb, offset));
                }
                else if ((i / MAP_SUBSET_SIZE) == 1 || (i / MAP_SUBSET_SIZE) == 2) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "   %02d", tvb_get_int8(tvb, offset));
                }
                else if ((i / MAP_SUBSET_SIZE) == 3) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "  %02d", tvb_get_int8(tvb, offset));
                }
                else {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, " %02d", tvb_get_int8(tvb, offset));
                }
                offset += 1;
                for (int j = 1; j < MAP_SUBSET_SIZE; j += 1) {
                    proto_item_append_text(tlv_item2, " %02d", tvb_get_int8(tvb, offset));
                    offset += 1;
                }
            }

            /* array to store standbymaps in size of 32 */
            int arr2[MAP_ARRAY_SIZE] = { hf_ubt_dt_standbymap1 ,hf_ubt_dt_standbymap2 ,hf_ubt_dt_standbymap3 ,hf_ubt_dt_standbymap4 ,hf_ubt_dt_standbymap5 ,hf_ubt_dt_standbymap6 ,hf_ubt_dt_standbymap7 ,hf_ubt_dt_standbymap8 };

            /* adding standbymaps of size 32 at a time */
            for (int i = 0; i < MAP_SIZE; i += MAP_SUBSET_SIZE) {
                if ((i / MAP_SUBSET_SIZE) == 0) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr2[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "    %02d", tvb_get_int8(tvb, offset));
                }
                else if ((i / MAP_SUBSET_SIZE) == 1 || (i / MAP_SUBSET_SIZE) == 2) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr2[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "   %02d", tvb_get_int8(tvb, offset));
                }
                else if ((i / MAP_SUBSET_SIZE) == 3) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr2[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "  %02d", tvb_get_int8(tvb, offset));
                }
                else {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr2[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, " %02d", tvb_get_int8(tvb, offset));
                }
                offset += 1;
                for (int j = 1; j < MAP_SUBSET_SIZE; j += 1) {
                    proto_item_append_text(tlv_item2, " %02d", tvb_get_int8(tvb, offset));
                    offset += 1;
                }
            }

            /* array to store l2conn in size of 32 */
            int arr3[MAP_ARRAY_SIZE] = { hf_ubt_dt_l2conn1 ,hf_ubt_dt_l2conn2 ,hf_ubt_dt_l2conn3 ,hf_ubt_dt_l2conn4 ,hf_ubt_dt_l2conn5 ,hf_ubt_dt_l2conn6 ,hf_ubt_dt_l2conn7 ,hf_ubt_dt_l2conn8 };

            /* adding l2conn of size 32 at a time */
            for (int i = 0; i < MAP_SIZE; i += MAP_SUBSET_SIZE) {
                if ((i / MAP_SUBSET_SIZE) == 0) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr3[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "    %02d", tvb_get_int8(tvb, offset));
                }
                else if ((i / MAP_SUBSET_SIZE) == 1 || (i / MAP_SUBSET_SIZE) == 2) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr3[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "   %02d", tvb_get_int8(tvb, offset));
                }
                else if ((i / MAP_SUBSET_SIZE) == 3) {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr3[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, "  %02d", tvb_get_int8(tvb, offset));
                }
                else {
                    tlv_item2 = proto_tree_add_bytes_format_value(message_subtree3, arr3[i / MAP_SUBSET_SIZE], tvb, offset, MAP_SUBSET_SIZE, NULL, " %02d", tvb_get_int8(tvb, offset));
                }
                offset += 1;
                for (int j = 1; j < MAP_SUBSET_SIZE; j += 1) {
                    proto_item_append_text(tlv_item2, " %02d", tvb_get_int8(tvb, offset));
                    offset += 1;
                }
            }

            /* adding no of UACs assigned */
            proto_tree_add_item(message_subtree3, hf_ubt_dt_uaccount, tvb, offset, UAC_COUNT_SIZE, ENC_NA);
            offset += UAC_COUNT_SIZE;

            /* adding list of UAC IPs assigned */
            for (int i = 0; i < UAC_MAX_COUNT; i++) {
                tlv_item = proto_tree_add_item(message_subtree3, hf_ubt_dt_uaciplist, tvb, offset, IP_SIZE, ENC_NA);
                message_subtree4 = proto_item_add_subtree(tlv_item, ett_ubt_tlv);
                proto_item_append_text(tlv_item, "(%d)", i + 1);

                proto_tree_add_item_ret_uint(message_subtree4, hf_ubt_ip_type, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
                offset += 2;

                switch (val) {

                case TYPE_IPV6:
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(message_subtree4, hf_ubt_dt_uacipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
                    offset += IPv6_ADDR_SIZE;
                    break;

                case TYPE_IPV4:
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(message_subtree4, hf_ubt_dt_uacipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_padding, tvb, offset, 12, ENC_NA);
                    offset += 12;
                    break;

                case TYPE_NOT_ASSIGNED:
                    proto_tree_add_item(message_subtree4, hf_ubt_ip_unassigned, tvb, offset, IP_SIZE - 2, ENC_NA);
                    offset += IP_SIZE - 2;
                    break;

                default:
                    proto_tree_add_expert_format(message_subtree4, pinfo, &ei_ubt_unknown, tvb, offset, IP_SIZE - 2, "Invalid IP Type");
                    offset += IP_SIZE - 2;

                }
            }
            break;

        case Status:/* Type 15: Status */

            /* adding Status as proto_item to the tree */
            proto_tree_add_item_ret_boolean(message_subtree2, hf_ubt_dt_status, tvb, offset, optlen, ENC_BIG_ENDIAN, &bool_val);
            proto_item_append_text(tlv, ": %u(%s)", bool_val, bool_val ? "Success" : "Failure");
            col_append_fstr(pinfo->cinfo, COL_INFO, " status:%02d(%s)", bool_val, bool_val ? "Success" : "Failure");
            offset += optlen;
            break;

        case MCASTKey:/* Type 16: MCAST Key */

            /* adding MCAST key as proto_item to the tree */
            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_mcastkey, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %#x(%u)", val, val);

            /* appending to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " mcastkey:%u", val);
            offset += optlen;
            break;

        case ServerIP:/* Type 17: Server IP Address */

            /* adding Server IP Address as proto_item to the tree */

            proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_ip_type, tvb, offset, 2, ENC_BIG_ENDIAN, &val);
            offset += 2;

            switch (val) {

            case TYPE_IPV6:
                proto_tree_add_item(message_subtree2, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(message_subtree2, hf_ubt_dt_serveripv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
                offset += IPv6_ADDR_SIZE;
                break;

            case TYPE_IPV4:
                proto_tree_add_item(message_subtree2, hf_ubt_ip_padding, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(message_subtree2, hf_ubt_dt_serveripv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(message_subtree2, hf_ubt_ip_padding, tvb, offset, 12, ENC_NA);
                offset += 12;
                break;

            case TYPE_NOT_ASSIGNED:
                proto_tree_add_item(message_subtree2, hf_ubt_ip_unassigned, tvb, offset, IP_SIZE - 2, ENC_NA);
                offset += IP_SIZE - 2;
                break;

            default:
                proto_tree_add_expert_format(message_subtree2, pinfo, &ei_ubt_unknown, tvb, offset, IP_SIZE - 2, "Invalid IP Type");
                offset += IP_SIZE - 2;

            }
            break;

        case UserAuthMethod:/* Type 18: User Authentication method */

            /* adding User Authentication method as proto_item to the tree */
            tlv_item = proto_tree_add_item_ret_uint(message_subtree2, hf_ubt_dt_userauthmethod, tvb, offset, optlen, ENC_BIG_ENDIAN, &val);
            proto_item_append_text(tlv, ": %u(%s)", val, val_to_str(val, ubt_authmethod_vals, "Unknown Type (%02d)"));
            proto_item_append_text(tlv_item, "(%s)", val_to_str(val, ubt_authmethod_vals, "Unknown Type (%02d)"));
            offset += optlen;
            break;

        case Username:/* Type 19: Username */

            /* adding username as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_username, tvb, offset, optlen, ENC_ASCII);
            proto_item_append_text(tlv, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, optlen, ENC_ASCII));
            offset += optlen;
            break;

        case UserPortName:/* Type 20: User Port name */

            /* adding user port name as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_userportname, tvb, offset, optlen, ENC_ASCII);
            proto_item_append_text(tlv, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, optlen, ENC_ASCII));
            offset += optlen;
            break;

        case SwitchName:/* Type 21: Switch Name */

            /* adding Switch name as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_switchname, tvb, offset, optlen, ENC_ASCII);
            proto_item_append_text(tlv, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, optlen, ENC_ASCII));
            offset += optlen;
            break;

        case SilentClientVLANs:/* Type 22: Silent Client VLANs */

            /* adding Silent Client VLANs as proto_item to the tree */
            tlv_item = proto_tree_add_item(message_subtree2, hf_ubt_dt_silentclientvlans, tvb, offset, optlen, ENC_NA);
            message_subtree3 = proto_item_add_subtree(tlv_item, ett_ubt_tlv);
            proto_item_append_text(tlv, ": %u", tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN));

            /* adding each silent client VLAN assigned */
            for (int i = 0; i < 200; i++) {
                proto_tree_add_item(message_subtree3, hf_ubt_dt_silentclientvlan, tvb, offset, 2, ENC_NA);
                offset += 2;
            }
            break;

        case MaxMsgs:/* Type 23: Maximum Messages */

            /* adding Max Msgs as proto_item to the tree */
            proto_tree_add_item(message_subtree2, hf_ubt_dt_maxmsgs, tvb, offset, optlen, ENC_NA);
            offset += optlen;
            break;

        default:
            proto_tree_add_expert_format(message_subtree2, pinfo, &ei_ubt_unknown, tvb, offset, optlen, "Unknown");
            offset += optlen;
        }
    }
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

/* function to register the protocol & hf values used */
void
proto_register_ubt(void)
{

    /* hf array to store datatypes of different fields */
    static hf_register_info hf[] = {

        { &hf_ubt_packet_len,/* length of packet/buffer */
            { "Packet Length", "ubt.packet_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_tlv_header,/* header for TLV */
            { "Type-Length-Value", "ubt.tlv_header",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_tlv,/* for each TLV */
            { "TLV", "ubt.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_type,/* type of each TLV */
            { "Type", "ubt.tlv_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_length,/* length of each TLV */
            { "Length", "ubt.tlv_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_switch_macaddr,/* MAC address of Switch */
            { "Switch MAC Address", "ubt.switch.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_switch_seqno,/* sequence number of Switch */
            { "Switch Sequence Number", "ubt.switch.seq_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_msg_type,/* type of UBT message */
            { "Message Type", "ubt.msg_type",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_unknown,/* Unknown data type */
            { "Unknown Datatype", "ubt.unknown_datatype",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_grekey,/* GRE key */
            { "GRE Key", "ubt.gre_key",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_firmwareversion,/* version of the firmware */
            { "Firmware Version", "ubt.firmware_version",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_userkey,/* userkey */
            { "User Key", "ubt.user_key",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_sacmode,/* mode of SAC */
            { "SAC Mode", "ubt.sac_mode",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_sacipv4,/* IPv4 address of SAC */
            { "SAC IP Address (IPv4)", "ubt.sac_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_sacipv6,/* IPv6 address of SAC */
            { "SAC IP Address (IPv6)", "ubt.sac_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_heartbeattimeout,/* heartbeat timeout in secs */
            { "Heartbeat Timeout", "ubt.heartbeat_timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_usermac,/* MAC address of User */
            { "User MAC Address", "ubt.user_macaddress",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_uservlan,/* VLAN assigned to user */
            { "User VLAN", "ubt.user_vlan",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_ip_type,/* IP type */
            { "IP Type", "ubt.ip_type",
            FT_UINT16, BASE_HEX, VALS(ubt_iptype_vals), 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_ip_padding,/* IP Padding */
            { "IP Padding", "ubt.ip_padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_ip_unassigned,/* IP Padding */
            { "IP Unassigned", "ubt.ip_unassigned",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_flags,/* Flags, both switch & user */
            { "Flags", "ubt.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_switch_flags_bcmctoucast,/* switch flag: BCMC to UCAST? */
            { "SB_FLAGS_CONV_BCMC_TO_UCAST", "ubt.flags.switch.bcmctoucast",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
            NULL, HFILL }
        },
        { &hf_ubt_user_flags_tag,/* user flag: Tagged? */
            { "UB_FLAGS_TAGGED", "ubt.flags.user.tag",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
            NULL, HFILL }
        },
        { &hf_ubt_user_flags_auth,/* user flag: Authenticated? */
            { "UB_FLAGS_IS_AUTHENTICATED", "ubt.flags.user.auth",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
            NULL, HFILL }
        },
        { &hf_ubt_user_flags_bcmctoucast,/* user flag: BCMC to UCAST? */
            { "UB_FLAGS_CONV_BCMC_TO_UCAST", "ubt.flags.user.bcmctoucast",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
            NULL, HFILL }
        },
        { &hf_ubt_user_flags_dormant,/* user flag: Dormant? */
            { "UB_FLAGS_DORMANT", "ubt.flags.user.dormant",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
            NULL, HFILL }
        },
        { &hf_ubt_user_flags_uback,/* user flag: UB ACK sent? */
            { "UB_FLAGS_IS_UB_ACK_SENT", "ubt.flags.user.uback",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
            NULL, HFILL }
        },

        { &hf_ubt_dt_tunnelmtu,/* Tunnel MTU */
            { "Tunnel MTU", "ubt.tunnel_mtu",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_userrole,/* role of user */
            { "User Role", "ubt.user_role",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_reasoncode,/* reason code */
            { "Reason Code", "ubt.reason_code",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_nodelist,/* nodelist header */
            { "Node List", "ubt.node_list",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_clustername,/* name of the cluster */
            { "Cluster Name", "ubt.node_list.cluster_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_clusterenabled,/* if cluster enabled or not */
            { "Cluster Enabled", "ubt.node_list.cluster_enabled",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_ssacindex,/* index of SSAC */
            { "SSAC Index", "ubt.node_list.ssac_index",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_reserved,/* no of reserved */
            { "Reserved", "ubt.node_list.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_uaccount,/* no of UACs assigned */
            { "UAC Count", "ubt.uac_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_uaciplist,/* IP addresses of each UAC */
            { "UAC IP", "ubt.uac_ip_list",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_uacipv4,/* IPv4 address of UAC */
            { "UAC IP Address (IPv4)", "ubt.uac_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_uacipv6,/* IPv6 address of UAC */
            { "UAC IP Address (IPv6)", "ubt.uac_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_bucketmap,/* bucketmap header */
            { "Bucket Map", "ubt.bucket_map",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_timestamp,/* timestamp */
            { "Timestamp", "ubt.bucket_map.time_stamp",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_identifier,/* identifier string */
            { "Identifier", "ubt.bucket_map.identifier",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* arrays to hold active maps */
        { &hf_ubt_dt_activemap1,/* array 1 */
            { "Active Map[0-31]", "ubt.bucket_map.active_map_0-031",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap2,/* array 2 */
            { "Active Map[32-63]", "ubt.bucket_map.active_map_032-063",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap3,/* array 3 */
            { "Active Map[64-95]", "ubt.bucket_map.active_map_064-095",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap4,/* array 4 */
            { "Active Map[96-127]", "ubt.bucket_map.active_map_096-127",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap5,/* array 5 */
            { "Active Map[128-159]", "ubt.bucket_map.active_map_128-159",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap6,/* array 6 */
            { "Active Map[160-191]", "ubt.bucket_map.active_map_160-191",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap7,/* array 7 */
            { "Active Map[192-223]", "ubt.bucket_map.active_map_192-223",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_activemap8,/* array 8 */
            { "Active Map[224-255]", "ubt.bucket_map.active_map_224-255",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* arrays to hold standby maps */
        { &hf_ubt_dt_standbymap1,/* array 1 */
            { "Standby Map[0-31]", "ubt.bucket_map.standby_map_0-031",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap2,/* array 2 */
            { "Standby Map[32-63]", "ubt.bucket_map.standby_map_032-063",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap3,/* array 3 */
            { "Standby Map[64-95]", "ubt.bucket_map.standby_map_064-095",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap4,/* array 4 */
            { "Standby Map[96-127]", "ubt.bucket_map.standby_map_096-127",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap5,/* array 5 */
            { "Standby Map[128-159]", "ubt.bucket_map.standby_map_128-159",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap6,/* array 6 */
            { "Standby Map[160-191]", "ubt.bucket_map.standby_map_160-191",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap7,/* array 7 */
            { "Standby Map[192-223]", "ubt.bucket_map.standby_map_192-223",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_standbymap8,/* array 8 */
            { "Standby Map[224-255]", "ubt.bucket_map.standby_map_224-255",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* arrays to hold l2conn */
        { &hf_ubt_dt_l2conn1,/* array 1 */
            { "L2Connect[0-31]", "ubt.bucket_map.l2conn_0-031",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn2,/* array 2 */
            { "L2Connect[32-63]", "ubt.bucket_map.l2conn_032-063",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn3,/* array 3 */
            { "L2Connect[64-95]", "ubt.bucket_map.l2conn_064-095",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn4,/* array 4 */
            { "L2Connect[96-127]", "ubt.bucket_map.l2conn_096-127",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn5,/* array 5 */
            { "L2Connect[128-159]", "ubt.bucket_map.l2conn_128-159",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn6,/* array 6 */
            { "L2Connect[160-191]", "ubt.bucket_map.l2conn_160-191",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn7,/* array 7 */
            { "L2Connect[192-223]", "ubt.bucket_map.l2conn_192-223",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ubt_dt_l2conn8,/* array 8 */
            { "L2Connect[224-255]", "ubt.bucket_map.l2conn_224-255",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },


        { &hf_ubt_dt_status,/* status of message */
            { "Status", "ubt.status",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_success_fail), 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_mcastkey,/* MCAST key used */
            { "MCAST Key", "ubt.mcast_key",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_serveripv4,/* IPv4 address of server */
            { "Server IP Address (IPv4)", "ubt.server_ipaddressv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_serveripv6,/* IPv6 address of server */
            { "Server IP Address (IPv6)", "ubt.server_ipaddressv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_userauthmethod,/* user authentication method used */
            { "User Auth Method", "ubt.user_authmethod",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_username,/* username */
            { "Username", "ubt.username",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_userportname,/* Port name of the user */
            { "User Port Name", "ubt.user_portname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_switchname,/* name of the switch */
            { "Switch Name", "ubt.switch_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_silentclientvlans,/* Silent Client VLANs header */
            { "Silent Client VLANs", "ubt.silent_client_vlans",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_silentclientvlan,/* each silent client VLAN assigned */
            { "Silent Client VLAN", "ubt.silent_client_vlan",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_ubt_dt_maxmsgs,/* maximum messages allowed */
            { "Max Messages", "ubt.max_msgs",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }

    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_ubt,
        &ett_ubt_tlv,
        &ett_ubt_flags
    };

    static ei_register_info ei[] = {
        { &ei_ubt_unknown, {"ubt.unknown", PI_PROTOCOL, PI_WARN, "Unknown", EXPFILL}},
    };

    /* registering protocol with proto_register_protocol() function */
    proto_ubt = proto_register_protocol("Aruba UBT", "UBT", "ubt");

    /* registering field array */
    proto_register_field_array(proto_ubt, hf, array_length(hf));

    /* registering subtree array */
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t* expert_ubt;

    /* registering UBT protocol with expert info */
    expert_ubt = expert_register_protocol(proto_ubt);

    /* registering expert field array for UBT */
    expert_register_field_array(expert_ubt, ei, array_length(ei));

    /* handling proto_ubt & dissector function using handle */
    ubt_handle = register_dissector("ubt", dissect_ubt, proto_ubt);
}

void
proto_reg_handoff_ubt(void)
{
    /* adding port numbers to the handle */
    dissector_add_uint("papi.port", PORT_UBT, ubt_handle);
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
