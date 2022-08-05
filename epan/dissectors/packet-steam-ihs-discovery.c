/* packet-steam_ihs_discovery.c
 * Routines for Steam In-Home Streaming Discovery Protocol dissection
 * Copyright 2017, Jan Holthuis <jan.holthuis@ruhr-uni-bochum.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Steam In-Home Streaming Discovery Protocol detects servers and negotiates
 * connections to stream video games over the networks. It is used by
 * Valve Software's Steam Client and Steam Link devices.
 *
 * Further Information:
 * https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol
 * https://codingrange.com/blog/steam-in-home-streaming-control-protocol
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_steam_ihs_discovery(void);
void proto_register_steam_ihs_discovery(void);

static int proto_steam_ihs_discovery = -1;

static int hf_steam_ihs_discovery_signature = -1;
static int hf_steam_ihs_discovery_header_length = -1;
static int hf_steam_ihs_discovery_header_clientid = -1;
static int hf_steam_ihs_discovery_header_msgtype = -1;
static int hf_steam_ihs_discovery_header_instanceid = -1;
static int hf_steam_ihs_discovery_body_length = -1;
static int hf_steam_ihs_discovery_body_discovery_seqnum = -1;
static int hf_steam_ihs_discovery_body_discovery_clientids = -1;
static int hf_steam_ihs_discovery_body_status_version = -1;
static int hf_steam_ihs_discovery_body_status_minversion = -1;
static int hf_steam_ihs_discovery_body_status_connectport = -1;
static int hf_steam_ihs_discovery_body_status_hostname = -1;
static int hf_steam_ihs_discovery_body_status_enabledservices = -1;
static int hf_steam_ihs_discovery_body_status_ostype = -1;
static int hf_steam_ihs_discovery_body_status_is64bit = -1;
static int hf_steam_ihs_discovery_body_status_euniverse = -1;
static int hf_steam_ihs_discovery_body_status_timestamp = -1;
static int hf_steam_ihs_discovery_body_status_screenlocked = -1;
static int hf_steam_ihs_discovery_body_status_gamesrunning = -1;
static int hf_steam_ihs_discovery_body_status_macaddresses = -1;
static int hf_steam_ihs_discovery_body_status_user_steamid = -1;
static int hf_steam_ihs_discovery_body_status_user_authkeyid = -1;
static int hf_steam_ihs_discovery_body_authrequest_devicetoken = -1;
static int hf_steam_ihs_discovery_body_authrequest_devicename = -1;
static int hf_steam_ihs_discovery_body_authrequest_encryptedrequest = -1;
static int hf_steam_ihs_discovery_body_authresponse_authresult = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_requestid = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_maximumresolutionx = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_maximumresolutiony = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_audiochannelcount = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_deviceversion = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_streamdesktop = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_devicetoken = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_pin = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_enablevideostreaming = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_enableaudiostreaming = -1;
static int hf_steam_ihs_discovery_body_streamingrequest_enableinputstreaming = -1;
static int hf_steam_ihs_discovery_body_streamingcancelrequest_requestid = -1;
static int hf_steam_ihs_discovery_body_streamingresponse_requestid = -1;
static int hf_steam_ihs_discovery_body_streamingresponse_result = -1;
static int hf_steam_ihs_discovery_body_streamingresponse_port = -1;
static int hf_steam_ihs_discovery_body_streamingresponse_encryptedsessionkey = -1;
static int hf_steam_ihs_discovery_body_streamingresponse_virtualherelicenseddevicecount = -1;
static int hf_steam_ihs_discovery_body_proofrequest_challenge = -1;
static int hf_steam_ihs_discovery_body_proofresponse_response = -1;
static int hf_steam_ihs_discovery_unknown_data = -1;
static int hf_steam_ihs_discovery_unknown_number = -1;

static const val64_string hf_steam_ihs_discovery_header_msgtype_strings[] = {
    {  0, "Client Discovery" },
    {  1, "Client Status" },
    {  2, "Client Offline" },
    {  3, "Device Authorization Request" },
    {  4, "Device Authorization Response" },
    {  5, "Device Streaming Request" },
    {  6, "Device Streaming Response" },
    {  7, "Device Proof Request" },
    {  8, "Device Proof Response" },
    {  9, "Device Authorization Cancel Request" },
    { 10, "Device Streaming Cancel Request" },
    {  0, NULL }
};

static const val64_string hf_steam_ihs_discovery_body_authresponse_authresult_strings[] = {
    { 0, "Success" },
    { 1, "Denied" },
    { 2, "Not Logged In" },
    { 3, "Offline" },
    { 4, "Busy" },
    { 5, "In Progress" },
    { 6, "TimedOut" },
    { 7, "Failed" },
    { 8, "Canceled" },
    { 0, NULL }
};

static const val64_string hf_steam_ihs_discovery_body_streamingresponse_result_strings[] = {
    {  0, "Success" },
    {  1, "Unauthorized" },
    {  2, "Screen Locked" },
    {  3, "Failed" },
    {  4, "Busy" },
    {  5, "In Progress" },
    {  6, "Canceled" },
    {  7, "Drivers Not Installed" },
    {  8, "Disabled" },
    {  9, "Broadcasting Active" },
    { 10, "VR Active" },
    { 11, "PIN Required" },
    { 0, NULL }
};

static expert_field ei_steam_ihs_discovery_unknown_data = EI_INIT;
static expert_field ei_steam_ihs_discovery_unknown_number = EI_INIT;
static expert_field ei_steam_ihs_discovery_unknown_lengthdelimited = EI_INIT;
static expert_field ei_steam_ihs_discovery_invalid_wiretype = EI_INIT;
static expert_field ei_steam_ihs_discovery_invalid_length = EI_INIT;

#define STEAM_IHS_DISCOVERY_UDP_PORT 27036

/* Initialize the subtree pointers */
static gint ett_steam_ihs_discovery = -1;
static gint ett_steam_ihs_discovery_body_status_user = -1;

#define STEAM_IHS_DISCOVERY_MIN_LENGTH 12
#define STEAM_IHS_DISCOVERY_SIGNATURE_LENGTH 8
#define STEAM_IHS_DISCOVERY_SIGNATURE_VALUE 0xFFFFFFFF214C5FA0

/* Helper functions and structs for reading Protocol Buffers.
 *
 * Detailed information about protobuf message encoding can be found at:
 * https://developers.google.com/protocol-buffers/docs/encoding#structure
 */
#define PROTOBUF_WIRETYPE_VARINT          0
#define PROTOBUF_WIRETYPE_64BIT           1
#define PROTOBUF_WIRETYPE_LENGTHDELIMITED 2
#define PROTOBUF_WIRETYPE_32BIT           5

static const char * const protobuf_wiretype_names[] = {"VarInt", "64-bit", "Length-delimited", "Start group", "End group", "32-bit"};
static const char protobuf_wiretype_name_unknown[] = "Unknown";

static const char* protobuf_get_wiretype_name(guint8 wire_type) {
    if (wire_type <= 5) {
        return protobuf_wiretype_names[wire_type];
    }
    return protobuf_wiretype_name_unknown;
}

static gint64
get_varint64(tvbuff_t *tvb, gint offset, gint bytes_left, gint* len)
{
    guint8 b;
    gint64 result = 0;
    *len = 0;
    while ((*len) < bytes_left) {
        b = tvb_get_guint8(tvb, offset+(*len));
        result |= ((gint64)b & 0x7f) << ((*len)*7);
        (*len)++;
        if ((b & 0x80) == 0) {
            break;
        }
    }
    return result;
}

typedef struct {
    tvbuff_t *tvb;
    gint offset;
    gint bytes_left;
} protobuf_desc_t;

typedef struct {
    guint64 value;
    guint64 field_number;
    guint8 wire_type;
} protobuf_tag_t;

static void
protobuf_seek_forward(protobuf_desc_t* pb, gint len)
{
    pb->offset += len;
    pb->bytes_left -= len;
}

static gint
protobuf_iter_next(protobuf_desc_t* pb, protobuf_tag_t* tag)
{
    gint len;
    if (pb->bytes_left <= 0) {
        return 0;
    }
    tag->value = get_varint64(pb->tvb, pb->offset, pb->bytes_left, &len);
    tag->field_number = tag->value >> 3;
    tag->wire_type = tag->value & 0x7;
    protobuf_seek_forward(pb, len);
    return pb->bytes_left;
}

static gint
protobuf_dissect_unknown_field(protobuf_desc_t *pb, protobuf_tag_t *tag, packet_info *pinfo, proto_tree *tree, proto_item** tiptr)
{
    gint len;
    gint64 value;
    proto_item* ti;

    switch(tag->wire_type) {
        case PROTOBUF_WIRETYPE_VARINT:
            value = get_varint64(pb->tvb, pb->offset, pb->bytes_left, &len);
            ti = proto_tree_add_uint64(tree, hf_steam_ihs_discovery_unknown_number, pb->tvb,
                    pb->offset, len, (guint64)value);
            expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_unknown_number, "Unknown numeric protobuf field (wire type %d = %s)", tag->wire_type, protobuf_get_wiretype_name(tag->wire_type));
            break;
        case PROTOBUF_WIRETYPE_64BIT:
            len = 8;
            ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_number, pb->tvb, pb->offset+len, len, ENC_LITTLE_ENDIAN);
            expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_unknown_number, "Unknown numeric protobuf field (wire type %d = %s)", tag->wire_type, protobuf_get_wiretype_name(tag->wire_type));
            break;
        case PROTOBUF_WIRETYPE_LENGTHDELIMITED:
            value = get_varint64(pb->tvb, pb->offset, pb->bytes_left, &len);
            if((guint64)value > (guint64)(pb->bytes_left-len)) {
                ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_data, pb->tvb, pb->offset+len, pb->bytes_left-len, ENC_NA);
                expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_invalid_length, "Length-delimited field %"PRIu64" has length prefix %"PRIu64", but buffer is only %d bytes long.", tag->field_number, (guint64)value, (pb->bytes_left-len));
                len = pb->bytes_left;
            } else {
                ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_data, pb->tvb, pb->offset+len, (gint)value, ENC_NA);
                len += (gint)value;
            }
            expert_add_info(pinfo, ti, &ei_steam_ihs_discovery_unknown_lengthdelimited);
            break;
        case PROTOBUF_WIRETYPE_32BIT:
            len = 4;
            ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_number, pb->tvb, pb->offset+len, len, ENC_LITTLE_ENDIAN);
            expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_unknown_number, "Unknown numeric protobuf field (wire type %d = %s)", tag->wire_type, protobuf_get_wiretype_name(tag->wire_type));
            break;
        default:
            len = pb->bytes_left;
            ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_data, pb->tvb, pb->offset, len, ENC_NA);
            expert_add_info(pinfo, ti, &ei_steam_ihs_discovery_unknown_data);
            break;
    }
    if(tiptr != NULL) {
        *tiptr = ti;
    }

    return len;
}

static gint
protobuf_verify_wiretype(protobuf_desc_t *pb, protobuf_tag_t *tag, packet_info *pinfo, proto_tree *tree, guint8 expected_wire_type)
{
    gint len;
    gint64 len_prefix;
    proto_item *ti = NULL;

    if(expected_wire_type == tag->wire_type) {
        if(expected_wire_type == PROTOBUF_WIRETYPE_LENGTHDELIMITED) {
            len_prefix = get_varint64(pb->tvb, pb->offset, pb->bytes_left, &len);
            if(len_prefix < 0 || len_prefix > G_MAXINT) {
                ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_data, pb->tvb, pb->offset+len, pb->bytes_left-len, ENC_NA);
                expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_invalid_length, "Length-delimited field %"PRIu64" has length prefix %"PRId64" outside valid range (0 <= x <= G_MAXINT).", tag->field_number, len_prefix);
                return pb->bytes_left;
            } else if(((gint)len_prefix) > (pb->bytes_left-len)) {
                ti = proto_tree_add_item(tree, hf_steam_ihs_discovery_unknown_data, pb->tvb, pb->offset+len, pb->bytes_left-len, ENC_NA);
                expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_invalid_length, "Length-delimited field %"PRIu64" has length prefix %"PRId64", but buffer is only %d bytes long.", tag->field_number, len_prefix, (pb->bytes_left-len));
                return pb->bytes_left;
            }
        }
        return 0;
    }
    len = protobuf_dissect_unknown_field(pb, tag, pinfo, tree, &ti);

    expert_add_info_format(pinfo, ti, &ei_steam_ihs_discovery_invalid_wiretype, "Expected wiretype %d (%s) for field %"PRIu64", but got %d (%s) instead.", expected_wire_type, protobuf_get_wiretype_name(expected_wire_type), tag->field_number, tag->wire_type, protobuf_get_wiretype_name(tag->wire_type));
    return len;
}

/* The actual protocol-specific stuff */

#define STEAMDISCOVER_FN_HEADER_CLIENTID   1
#define STEAMDISCOVER_FN_HEADER_MSGTYPE    2
#define STEAMDISCOVER_FN_HEADER_INSTANCEID 3

#define STEAMDISCOVER_FN_DISCOVERY_SEQNUM                       1
#define STEAMDISCOVER_FN_DISCOVERY_CLIENTIDS                    2

#define STEAMDISCOVER_FN_STATUS_VERSION                         1
#define STEAMDISCOVER_FN_STATUS_MINVERSION                      2
#define STEAMDISCOVER_FN_STATUS_CONNECTPORT                     3
#define STEAMDISCOVER_FN_STATUS_HOSTNAME                        4
#define STEAMDISCOVER_FN_STATUS_ENABLEDSERVICES                 6
#define STEAMDISCOVER_FN_STATUS_OSTYPE                          7
#define STEAMDISCOVER_FN_STATUS_IS64BIT                         8
#define STEAMDISCOVER_FN_STATUS_USERS                           9
#define STEAMDISCOVER_FN_STATUS_EUNIVERSE                      11
#define STEAMDISCOVER_FN_STATUS_TIMESTAMP                      12
#define STEAMDISCOVER_FN_STATUS_SCREENLOCKED                   13
#define STEAMDISCOVER_FN_STATUS_GAMESRUNNING                   14
#define STEAMDISCOVER_FN_STATUS_MACADDRESSES                   15
#define STEAMDISCOVER_FN_STATUS_USER_STEAMID                    1
#define STEAMDISCOVER_FN_STATUS_USER_AUTHKEYID                  2

#define STEAMDISCOVER_FN_AUTHREQUEST_DEVICETOKEN                1
#define STEAMDISCOVER_FN_AUTHREQUEST_DEVICENAME                 2
#define STEAMDISCOVER_FN_AUTHREQUEST_ENCRYPTEDREQUEST           3

#define STEAMDISCOVER_FN_AUTHRESPONSE_AUTHRESULT                1

#define STEAMDISCOVER_FN_STREAMINGREQUEST_REQUESTID             1
#define STEAMDISCOVER_FN_STREAMINGREQUEST_MAXIMUMRESOLUTIONX    2
#define STEAMDISCOVER_FN_STREAMINGREQUEST_MAXIMUMRESOLUTIONY    3
#define STEAMDISCOVER_FN_STREAMINGREQUEST_AUDIOCHANNELCOUNT     4
#define STEAMDISCOVER_FN_STREAMINGREQUEST_DEVICEVERSION         5
#define STEAMDISCOVER_FN_STREAMINGREQUEST_STREAMDESKTOP         6
#define STEAMDISCOVER_FN_STREAMINGREQUEST_DEVICETOKEN           7
#define STEAMDISCOVER_FN_STREAMINGREQUEST_PIN                   8
#define STEAMDISCOVER_FN_STREAMINGREQUEST_ENABLEVIDEOSTREAMING  9
#define STEAMDISCOVER_FN_STREAMINGREQUEST_ENABLEAUDIOSTREAMING 10
#define STEAMDISCOVER_FN_STREAMINGREQUEST_ENABLEINPUTSTREAMING 11

#define STEAMDISCOVER_FN_STREAMINGCANCELREQUEST_REQUESTID       1

#define STEAMDISCOVER_FN_STREAMINGRESPONSE_REQUESTID            1
#define STEAMDISCOVER_FN_STREAMINGRESPONSE_RESULT               2
#define STEAMDISCOVER_FN_STREAMINGRESPONSE_PORT                 3
#define STEAMDISCOVER_FN_STREAMINGRESPONSE_ENCRYPTEDSESSIONKEY  4
#define STEAMDISCOVER_FN_STREAMINGRESPONSE_VIRTUALHERELICENSEDDEVICECOUNT 5

#define STEAMDISCOVER_FN_PROOFREQUEST_CHALLENGE                 1
#define STEAMDISCOVER_FN_PROOFRESPONSE_RESPONSE                 1

#define STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGDISCOVERY       0
#define STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGSTATUS          1
#define STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGOFFLINE         2
#define STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONREQUEST        3
#define STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONRESPONSE       4
#define STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGREQUEST            5
#define STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGRESPONSE           6
#define STEAMDISCOVER_MSGTYPE_DEVICEPROOFREQUEST                7
#define STEAMDISCOVER_MSGTYPE_DEVICEPROOFRESPONSE               8
#define STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONCANCELREQUEST  9
#define STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGCANCELREQUEST     10
#define STEAMDISCOVER_MSGTYPES_MAX                             10

#define STEAMDISCOVER_ENSURE_WIRETYPE(X) if((len = protobuf_verify_wiretype(&pb, &tag, pinfo, tree, X))) break;

/* Dissect the header section of a packet. The header is a
 * CMsgRemoteClientBroadcastHeader protobuf message.
 *
 *     enum ERemoteClientBroadcastMsg {
 *         k_ERemoteClientBroadcastMsgDiscovery = 0;
 *         k_ERemoteClientBroadcastMsgStatus = 1;
 *         k_ERemoteClientBroadcastMsgOffline = 2;
 *         k_ERemoteDeviceAuthorizationRequest = 3;
 *         k_ERemoteDeviceAuthorizationResponse = 4;
 *         k_ERemoteDeviceStreamingRequest = 5;
 *         k_ERemoteDeviceStreamingResponse = 6;
 *         k_ERemoteDeviceProofRequest = 7;
 *         k_ERemoteDeviceProofResponse = 8;
 *         k_ERemoteDeviceAuthorizationCancelRequest = 9;
 *         k_ERemoteDeviceStreamingCancelRequest = 10;
 *     }
 *
 *     message CMsgRemoteClientBroadcastHeader {
 *         optional uint64 client_id = 1;
 *         optional ERemoteClientBroadcastMsg msg_type = 2;
 *         optional uint64 instance_id = 3;
 *     }
 */
static gint64
steamdiscover_dissect_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             gint offset, gint bytes_left)
{
    gint len;
    gint64 value;
    gint64 msg_type = -1;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_HEADER_CLIENTID:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint64(tree, hf_steam_ihs_discovery_header_clientid, pb.tvb,
                        pb.offset, len, (guint64)value);
                break;
            case STEAMDISCOVER_FN_HEADER_MSGTYPE:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                msg_type = value;
                proto_tree_add_uint64(tree, hf_steam_ihs_discovery_header_msgtype, pb.tvb,
                        pb.offset, len, (guint64)value);
                break;
            case STEAMDISCOVER_FN_HEADER_INSTANCEID:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint64(tree, hf_steam_ihs_discovery_header_instanceid, pb.tvb,
                        pb.offset, len, (guint64)value);
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
    return msg_type;
}

/* Dissect a CMsgRemoteClientBroadcastDiscovery protobuf message body.
 *
 *     message CMsgRemoteClientBroadcastDiscovery {
 *          optional uint32 seq_num = 1;
 *          repeated uint64 client_ids = 2;
 *     }
 */
static void
steamdiscover_dissect_body_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     gint offset, gint bytes_left)
{
    gint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_DISCOVERY_SEQNUM:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_discovery_seqnum, pb.tvb,
                        pb.offset, len, (guint32)value);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%"PRIu32, (guint32)value);
                break;
            case STEAMDISCOVER_FN_DISCOVERY_CLIENTIDS:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint64(tree, hf_steam_ihs_discovery_body_discovery_clientids, pb.tvb,
                        pb.offset, len, value);
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteClientBroadcastStatus protobuf message body.
 *
 *     message CMsgRemoteClientBroadcastStatus {
 *         message User {
 *             optional fixed64 steamid = 1;
 *             optional uint32 auth_key_id = 2;
 *         }
 *         optional int32 version = 1;
 *         optional int32 min_version = 2;
 *         optional uint32 connect_port = 3;
 *         optional string hostname = 4;
 *         optional uint32 enabled_services = 6;
 *         optional int32 ostype = 7 [default = 0];
 *         optional bool is64bit = 8 [default = false];
 *         repeated CMsgRemoteClientBroadcastStatus.User users = 9;
 *         optional int32 euniverse = 11;
 *         optional uint32 timestamp = 12;
 *         optional bool screen_locked = 13;
 *         optional bool games_running = 14;
 *         repeated string mac_addresses = 15;
 *         optional uint32 download_lan_peer_group = 16;
 *         optional bool broadcasting_active = 17;
 *         optional bool vr_active = 18;
 *     }
 */
static void
steamdiscover_dissect_body_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     gint offset, gint bytes_left)
{
    gint64 value;
    gint len;
    gint len2;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_desc_t pb2 = { tvb, 0, 0 };
    protobuf_tag_t tag = { 0, 0, 0 };
    guint8 *hostname;
    nstime_t timestamp;
    proto_tree *user_tree;
    proto_item *user_it;
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_STATUS_VERSION:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_status_version, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_MINVERSION:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_status_minversion, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_CONNECTPORT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_status_connectport, pb.tvb,
                        pb.offset, len, (guint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_HOSTNAME:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_status_hostname, pb.tvb,
                        pb.offset+len, (gint)value, ENC_UTF_8);
                hostname = tvb_get_string_enc(pinfo->pool, pb.tvb, pb.offset+len, (gint)value, ENC_UTF_8);
                if(hostname && strlen(hostname)) {
                    col_add_fstr(pinfo->cinfo, COL_INFO, "%s from %s", hf_steam_ihs_discovery_header_msgtype_strings[STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGSTATUS].strptr, hostname);
                }
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_STATUS_ENABLEDSERVICES:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_status_enabledservices, pb.tvb,
                        pb.offset, len, (guint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_OSTYPE:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_status_ostype, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_IS64BIT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_status_is64bit, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_USERS:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                pb2.offset = pb.offset+len;
                pb2.bytes_left = (gint)value;
                len += (gint)value;
                user_tree = proto_tree_add_subtree(tree, pb.tvb, pb.offset, len, ett_steam_ihs_discovery_body_status_user, &user_it, "User");
                while (protobuf_iter_next(&pb2, &tag)) {
                    switch(tag.field_number) {
                        case STEAMDISCOVER_FN_STATUS_USER_STEAMID:
                            if((len2 = protobuf_verify_wiretype(&pb2, &tag, pinfo, user_tree, PROTOBUF_WIRETYPE_64BIT))) break;
                            len2 = 8;
                            value = tvb_get_letoh64(pb2.tvb, pb2.offset);
                            proto_tree_add_uint64(user_tree, hf_steam_ihs_discovery_body_status_user_steamid, pb2.tvb,
                                    pb2.offset, len2, (guint64)value);
                            proto_item_append_text(user_it, ", Steam ID: %"PRIu64, (guint64)value);
                            break;
                        case STEAMDISCOVER_FN_STATUS_USER_AUTHKEYID:
                            if((len2 = protobuf_verify_wiretype(&pb2, &tag, pinfo, user_tree, PROTOBUF_WIRETYPE_VARINT))) break;
                            value = get_varint64(pb2.tvb, pb2.offset, pb2.bytes_left, &len2);
                            proto_tree_add_uint(user_tree, hf_steam_ihs_discovery_body_status_user_authkeyid, pb2.tvb,
                                    pb2.offset, len2, (guint32)value);
                            proto_item_append_text(user_it, ", Auth Key ID: %"PRIu32, (guint32)value);
                            break;
                        default:
                            len2 = protobuf_dissect_unknown_field(&pb2, &tag, pinfo, tree, NULL);
                            break;
                    }
                    protobuf_seek_forward(&pb2, len2);
                }
                break;
            case STEAMDISCOVER_FN_STATUS_EUNIVERSE:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_status_euniverse, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_TIMESTAMP:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                timestamp.secs = (time_t)get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                timestamp.nsecs = 0;
                proto_tree_add_time(tree, hf_steam_ihs_discovery_body_status_timestamp, pb.tvb,
                        pb.offset, len, &timestamp);
                break;
            case STEAMDISCOVER_FN_STATUS_SCREENLOCKED:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_status_screenlocked, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_GAMESRUNNING:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_status_gamesrunning, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STATUS_MACADDRESSES:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_status_macaddresses, pb.tvb,
                        pb.offset+len, (gint)value, ENC_UTF_8);
                len += (gint)value;
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceAuthorizationRequest protobuf message body.
 *
 *     message CMsgRemoteDeviceAuthorizationRequest {
 *         message CKeyEscrow_Ticket {
 *             optional bytes password = 1;
 *             optional uint64 identifier = 2;
 *             optional bytes payload = 3;
 *             optional uint32 timestamp = 4;
 *             optional CMsgRemoteDeviceAuthorizationRequest.EKeyEscrowUsage usage = 5;
 *             optional string device_name = 6;
 *             optional string device_model = 7;
 *             optional string device_serial = 8;
 *             optional uint32 device_provisioning_id = 9;
 *         }
 *         enum EKeyEscrowUsage {
 *             k_EKeyEscrowUsageStreamingDevice = 0;
 *         }
 *         required bytes device_token = 1;
 *         optional string device_name = 2;
 *         required bytes encrypted_request = 3;
 *     }
 */
static void
steamdiscover_dissect_body_authrequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       gint offset, gint bytes_left)
{
    guint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    guint8* devicename;
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_AUTHREQUEST_DEVICETOKEN:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_authrequest_devicetoken, pb.tvb,
                        pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_AUTHREQUEST_DEVICENAME:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_authrequest_devicename, pb.tvb,
                        pb.offset+len, (gint)value, ENC_UTF_8);
                devicename = tvb_get_string_enc(pinfo->pool, pb.tvb, pb.offset+len, (gint)value, ENC_UTF_8);
                if (devicename && strlen(devicename)) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " from %s", devicename);
                }
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_AUTHREQUEST_ENCRYPTEDREQUEST:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_authrequest_encryptedrequest, pb.tvb,
                        pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceAuthorizationResponse protobuf message body.
 *
 *     message CMsgRemoteDeviceAuthorizationResponse {
 *         required ERemoteDeviceAuthorizationResult result = 1;
 *     }
 */
static void
steamdiscover_dissect_body_authresponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        gint offset, gint bytes_left)
{
    gint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_AUTHRESPONSE_AUTHRESULT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint64(tree, hf_steam_ihs_discovery_body_authresponse_authresult, pb.tvb,
                        pb.offset, len, (guint64)value);
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s Result=%"PRIu64"(%s)", hf_steam_ihs_discovery_header_msgtype_strings[STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONRESPONSE].strptr,
                        (guint64)value, val64_to_str_const((guint64)value, hf_steam_ihs_discovery_body_authresponse_authresult_strings, "Unknown"));
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceStreamingRequest protobuf message body.
 *
 *     message CMsgRemoteDeviceStreamingRequest {
 *         required uint32 request_id = 1;
 *         optional int32 maximum_resolution_x = 2;
 *         optional int32 maximum_resolution_y = 3;
 *         optional int32 audio_channel_count = 4 [default = 2];
 *         optional string device_version = 5;
 *         optional bool stream_desktop = 6;
 *         optional bytes device_token = 7;
 *         optional bytes pin = 8;
 *         optional bool enable_video_streaming = 9 [default = true];
 *         optional bool enable_audio_streaming = 10 [default = true];
 *         optional bool enable_input_streaming = 11 [default = true];
 *     }
 */
static void
steamdiscover_dissect_body_streamingrequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            gint offset, gint bytes_left)
{
    gint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_STREAMINGREQUEST_REQUESTID:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_streamingrequest_requestid, pb.tvb,
                        pb.offset, len, (guint32)value);
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s ID=%08x", hf_steam_ihs_discovery_header_msgtype_strings[STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGREQUEST].strptr, (guint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_MAXIMUMRESOLUTIONX:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_streamingrequest_maximumresolutionx, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_MAXIMUMRESOLUTIONY:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_streamingrequest_maximumresolutiony, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_AUDIOCHANNELCOUNT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_streamingrequest_audiochannelcount, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_DEVICEVERSION:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_streamingrequest_deviceversion, pb.tvb, pb.offset+len, (gint)value, ENC_UTF_8);
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_STREAMDESKTOP:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_streamingrequest_streamdesktop, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_DEVICETOKEN:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_streamingrequest_devicetoken, pb.tvb, pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_PIN:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_streamingrequest_pin, pb.tvb, pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_ENABLEVIDEOSTREAMING:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_streamingrequest_enablevideostreaming, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_ENABLEAUDIOSTREAMING:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_streamingrequest_enableaudiostreaming, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGREQUEST_ENABLEINPUTSTREAMING:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_boolean(tree, hf_steam_ihs_discovery_body_streamingrequest_enableinputstreaming, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceStreamingCancelRequest protobuf message body.
 *
 *     message CMsgRemoteDeviceStreamingCancelRequest {
 *         required uint32 request_id = 1;
 *     }
 */
static void
steamdiscover_dissect_body_streamingcancelrequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  gint offset, gint bytes_left)
{
    guint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_STREAMINGCANCELREQUEST_REQUESTID:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_streamingcancelrequest_requestid, pb.tvb,
                        pb.offset, len, (guint32)value);
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s, ID=%08x", hf_steam_ihs_discovery_header_msgtype_strings[STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGCANCELREQUEST].strptr, (guint32)value);
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceStreamingResponse protobuf message body.
 *
 *     enum ERemoteDeviceStreamingResult {
 *         k_ERemoteDeviceStreamingSuccess = 0;
 *         k_ERemoteDeviceStreamingUnauthorized = 1;
 *         k_ERemoteDeviceStreamingScreenLocked = 2;
 *         k_ERemoteDeviceStreamingFailed = 3;
 *         k_ERemoteDeviceStreamingBusy = 4;
 *         k_ERemoteDeviceStreamingInProgress = 5;
 *         k_ERemoteDeviceStreamingCanceled = 6;
 *         k_ERemoteDeviceStreamingDriversNotInstalled = 7;
 *         k_ERemoteDeviceStreamingDisabled = 8;
 *         k_ERemoteDeviceStreamingBroadcastingActive = 9;
 *         k_ERemoteDeviceStreamingVRActive = 10;
 *         k_ERemoteDeviceStreamingPINRequired = 11;
 *     }
 *
 *     message CMsgRemoteDeviceStreamingResponse {
 *         required uint32 request_id = 1;
 *         required ERemoteDeviceStreamingResult result = 2;
 *         optional uint32 port = 3;
 *         optional bytes encrypted_session_key = 4;
 *         optional int32 virtualhere_licensed_device_count_OBSOLETE = 5;
 *     }
 */
static void
steamdiscover_dissect_body_streamingresponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  gint offset, gint bytes_left)
{
    guint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_STREAMINGRESPONSE_REQUESTID:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_streamingresponse_requestid, pb.tvb,
                        pb.offset, len, (guint32)value);
                col_append_fstr(pinfo->cinfo, COL_INFO, " ID=%08x", (guint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGRESPONSE_RESULT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint64(tree, hf_steam_ihs_discovery_body_streamingresponse_result, pb.tvb,
                        pb.offset, len, (guint64)value);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Result=%"PRIu64"(%s)", (guint64)value, val64_to_str_const((guint64)value, hf_steam_ihs_discovery_body_streamingresponse_result_strings, "Unknown"));
                break;
            case STEAMDISCOVER_FN_STREAMINGRESPONSE_PORT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_uint(tree, hf_steam_ihs_discovery_body_streamingresponse_port, pb.tvb,
                        pb.offset, len, (guint32)value);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Port=%"PRIu32, (guint32)value);
                break;
            case STEAMDISCOVER_FN_STREAMINGRESPONSE_ENCRYPTEDSESSIONKEY:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_streamingresponse_encryptedsessionkey, pb.tvb, pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            case STEAMDISCOVER_FN_STREAMINGRESPONSE_VIRTUALHERELICENSEDDEVICECOUNT:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_VARINT);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_int(tree, hf_steam_ihs_discovery_body_streamingresponse_virtualherelicenseddevicecount, pb.tvb,
                        pb.offset, len, (gint32)value);
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceProofRequest protobuf message body.
 *
 *     message CMsgRemoteDeviceProofRequest {
 *         required bytes challenge = 1;
 *     }
 */
static void
steamdiscover_dissect_body_proofrequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  gint offset, gint bytes_left)
{
    gint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_PROOFREQUEST_CHALLENGE:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_proofrequest_challenge, pb.tvb, pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

/* Dissect a CMsgRemoteDeviceProofResponse protobuf message body.
 *
 *     message CMsgRemoteDeviceProofResponse {
 *         required bytes response = 1;
 *     }
 */
static void
steamdiscover_dissect_body_proofresponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         gint offset, gint bytes_left)
{
    gint len;
    gint64 value;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        switch(tag.field_number) {
            case STEAMDISCOVER_FN_PROOFRESPONSE_RESPONSE:
                STEAMDISCOVER_ENSURE_WIRETYPE(PROTOBUF_WIRETYPE_LENGTHDELIMITED);
                value = get_varint64(pb.tvb, pb.offset, pb.bytes_left, &len);
                proto_tree_add_item(tree, hf_steam_ihs_discovery_body_proofresponse_response, pb.tvb, pb.offset+len, (gint)value, ENC_NA);
                len += (gint)value;
                break;
            default:
                len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
                break;
        }
        protobuf_seek_forward(&pb, len);
    }
}

static void
steamdiscover_dissect_body_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         gint offset, gint bytes_left)
{
    gint len;
    protobuf_desc_t pb = { tvb, offset, bytes_left };
    protobuf_tag_t tag = { 0, 0, 0 };
    while (protobuf_iter_next(&pb, &tag)) {
        len = protobuf_dissect_unknown_field(&pb, &tag, pinfo, tree, NULL);
        protobuf_seek_forward(&pb, len);
    }
}

/* Code to actually dissect the packets */
static int
dissect_steam_ihs_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *steam_ihs_discovery_tree;
    /* Other misc. local variables. */
    gint offset = 0;
    gint header_length = 0;
    gint body_length = 0;
    gint total_length = 0;
    gint64 msg_type;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < STEAM_IHS_DISCOVERY_MIN_LENGTH)
        return 0;

    if (tvb_captured_length(tvb) < STEAM_IHS_DISCOVERY_MIN_LENGTH)
        return 0;

    /* Check if packet starts with the 8 byte signature value. */
    if (tvb_get_ntoh64(tvb, 0) != STEAM_IHS_DISCOVERY_SIGNATURE_VALUE)
        return 0;

    /* Parse header and body lengths.
     *
     * A packet looks like this:
     *   1. Signature Value (8 bytes)
     *   2. Header length (4 bytes)
     *   3. Header
     *   4. Body length (4 bytes)
     *   6. Body
     * */
    header_length = tvb_get_letohl(tvb, STEAM_IHS_DISCOVERY_SIGNATURE_LENGTH);
    body_length = tvb_get_letohl(tvb, STEAM_IHS_DISCOVERY_SIGNATURE_LENGTH + 4 + header_length);
    total_length = STEAM_IHS_DISCOVERY_SIGNATURE_LENGTH + 4 + header_length + 4 + body_length;

    /* Check if expected and captured packet length are equal. */
    if (tvb_reported_length(tvb) != (guint)total_length)
        return 0;

    if (tvb_captured_length(tvb) != (guint)total_length)
        return 0;

    /* Set the Protocol column to the constant string of steam_ihs_discovery */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STEAMDISCOVER");

    col_clear(pinfo->cinfo, COL_INFO);

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_steam_ihs_discovery, tvb, 0, -1, ENC_NA);

    steam_ihs_discovery_tree = proto_item_add_subtree(ti, ett_steam_ihs_discovery);

    proto_tree_add_item(steam_ihs_discovery_tree, hf_steam_ihs_discovery_signature, tvb,
            offset, STEAM_IHS_DISCOVERY_SIGNATURE_LENGTH, ENC_LITTLE_ENDIAN);
    offset += STEAM_IHS_DISCOVERY_SIGNATURE_LENGTH;

    proto_tree_add_item(steam_ihs_discovery_tree, hf_steam_ihs_discovery_header_length, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    msg_type = steamdiscover_dissect_header(tvb, pinfo, steam_ihs_discovery_tree, offset, header_length);

    if ((0 <= msg_type) && (msg_type <= STEAMDISCOVER_MSGTYPES_MAX)) {
        col_set_str(pinfo->cinfo, COL_INFO, hf_steam_ihs_discovery_header_msgtype_strings[msg_type].strptr);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown Message");
    }

    offset += header_length;

    proto_tree_add_item(steam_ihs_discovery_tree, hf_steam_ihs_discovery_body_length, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    switch(msg_type)
    {
        case STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGDISCOVERY:
            steamdiscover_dissect_body_discovery(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGSTATUS:
            steamdiscover_dissect_body_status(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_CLIENTBROADCASTMSGOFFLINE:
            /* Message seems to have no body */
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONREQUEST:
            steamdiscover_dissect_body_authrequest(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONCANCELREQUEST:
            /* Message seems to have no body */
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICEAUTHORIZATIONRESPONSE:
            steamdiscover_dissect_body_authresponse(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGREQUEST:
            steamdiscover_dissect_body_streamingrequest(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGCANCELREQUEST:
            steamdiscover_dissect_body_streamingcancelrequest(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICESTREAMINGRESPONSE:
            steamdiscover_dissect_body_streamingresponse(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICEPROOFREQUEST:
            steamdiscover_dissect_body_proofrequest(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        case STEAMDISCOVER_MSGTYPE_DEVICEPROOFRESPONSE:
            steamdiscover_dissect_body_proofresponse(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
        default:
            steamdiscover_dissect_body_unknown(tvb, pinfo, steam_ihs_discovery_tree, offset, body_length);
            break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark. */
void
proto_register_steam_ihs_discovery(void)
{
    expert_module_t *expert_steam_ihs_discovery;

    static hf_register_info hf[] = {
        /* Non-protobuf header fields */
        { &hf_steam_ihs_discovery_signature,
          { "Signature", "steam_ihs_discovery.signature",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Every packet of the Steam In-Home Streaming Discovery Protocol begins with this signature.", HFILL }
        },
        { &hf_steam_ihs_discovery_header_length,
          { "Header Length", "steam_ihs_discovery.header_length",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_length,
          { "Body Length", "steam_ihs_discovery.body_length",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_unknown_data,
          { "Unknown Data", "steam_ihs_discovery.unknown_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_unknown_number,
          { "Unknown Number", "steam_ihs_discovery.unknown_number",
            FT_UINT64, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteClientBroadcastHeader */
        { &hf_steam_ihs_discovery_header_clientid,
          { "Client ID", "steam_ihs_discovery.header_client_id",
            FT_UINT64, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_header_msgtype,
          { "Message Type", "steam_ihs_discovery.header_msg_type",
            FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(hf_steam_ihs_discovery_header_msgtype_strings), 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_header_instanceid,
          { "Instance ID", "steam_ihs_discovery.header_instance_id",
            FT_UINT64, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteClientBroadcastDiscovery message */
        { &hf_steam_ihs_discovery_body_discovery_seqnum,
          { "Sequence Number", "steam_ihs_discovery.body_discovery_seqnum",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_discovery_clientids,
          { "Client IDs", "steam_ihs_discovery.body_discovery_clientids",
            FT_UINT64, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteClientBroadcastStatus message */
        { &hf_steam_ihs_discovery_body_status_version,
          { "Version", "steam_ihs_discovery.body_status_version",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_minversion,
          { "Minimum Version", "steam_ihs_discovery.body_status_minversion",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_connectport,
          { "Connect Port", "steam_ihs_discovery.body_status_connectport",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_hostname,
          { "Hostname", "steam_ihs_discovery.body_status_hostname",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_enabledservices,
          { "Enabled Services", "steam_ihs_discovery.body_status_enabledservices",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_ostype,
          { "OS Type", "steam_ihs_discovery.body_status_ostype",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_is64bit,
          { "Is 64 Bit", "steam_ihs_discovery.body_status_is64bit",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_euniverse,
          { "EUniverse", "steam_ihs_discovery.body_status_euniverse",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_timestamp,
          { "Timestamp", "steam_ihs_discovery.body_status_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_screenlocked,
          { "Screen Locked", "steam_ihs_discovery.body_status_screenlocked",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_gamesrunning,
          { "Games Running", "steam_ihs_discovery.body_status_gamesrunning",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_macaddresses,
          { "MAC Addresses", "steam_ihs_discovery.body_status_macaddresses",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteClientBroadcastStatus.User */
        { &hf_steam_ihs_discovery_body_status_user_steamid,
          { "Steam ID", "steam_ihs_discovery.body_status_user_steamid",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_status_user_authkeyid,
          { "Auth Key ID", "steam_ihs_discovery.body_status_user_authkeyid",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceAuthorizationRequest */
        { &hf_steam_ihs_discovery_body_authrequest_devicetoken,
          { "Device Token", "steam_ihs_discovery.body_authrequest_devicetoken",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_authrequest_devicename,
          { "Device Name", "steam_ihs_discovery.body_authrequest_devicename",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_authrequest_encryptedrequest,
          { "Encrypted Request", "steam_ihs_discovery.body_authrequest_encryptedrequest",
            FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceAuthorizationResponse */
        { &hf_steam_ihs_discovery_body_authresponse_authresult,
          { "Result", "steam_ihs_discovery.body_authresponse_authresult",
            FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(hf_steam_ihs_discovery_body_authresponse_authresult_strings), 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceStreamingRequest */
        { &hf_steam_ihs_discovery_body_streamingrequest_requestid,
          { "Request ID", "steam_ihs_discovery.body_streamingrequest_requestid",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_maximumresolutionx,
          { "Maximum Resolution X", "steam_ihs_discovery.body_streamingrequest_maximumresolutionx",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_maximumresolutiony,
          { "Maximum Resolution Y", "steam_ihs_discovery.body_streamingrequest_maximumresolutiony",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_audiochannelcount,
          { "Audio Channel Count", "steam_ihs_discovery.body_streamingrequest_audiochannelcount",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_deviceversion,
          { "Device Version", "steam_ihs_discovery.body_streamingrequest_deviceversion",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_streamdesktop,
          { "Stream Desktop", "steam_ihs_discovery.body_streamingrequest_streamdesktop",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_devicetoken,
          { "Device Token", "steam_ihs_discovery.body_streamingrequest_devicetoken",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_pin,
          { "PIN", "steam_ihs_discovery.body_streamingrequest_pin",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_enablevideostreaming,
          { "Enable Video Streaming", "steam_ihs_discovery.body_streamingrequest_enablevideostreaming",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_enableaudiostreaming,
          { "Enable Audio Streaming", "steam_ihs_discovery.body_streamingrequest_enableaudiostreaming",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingrequest_enableinputstreaming,
          { "Enable Input Streaming", "steam_ihs_discovery.body_streamingrequest_enableinputstreaming",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceStreamingCancelRequest */
        { &hf_steam_ihs_discovery_body_streamingcancelrequest_requestid,
          { "Request ID", "steam_ihs_discovery.body_streamingcancelrequest_requestid",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceStreamingResponse */
        { &hf_steam_ihs_discovery_body_streamingresponse_requestid,
          { "Request ID", "steam_ihs_discovery.body_streamingresponse_requestid",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingresponse_result,
          { "Result", "steam_ihs_discovery.body_streamingresponse_result",
            FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(hf_steam_ihs_discovery_body_streamingresponse_result_strings), 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingresponse_port,
          { "Port", "steam_ihs_discovery.body_streamingresponse_port",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingresponse_encryptedsessionkey,
          { "Encrypted Session Key", "steam_ihs_discovery.body_streamingresponse_encryptedsessionkey",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_steam_ihs_discovery_body_streamingresponse_virtualherelicenseddevicecount,
          { "VirtualHere Licensed Device Count", "steam_ihs_discovery.body_streamingresponse_virtualherelicenseddevicecount",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceProofRequest */
        { &hf_steam_ihs_discovery_body_proofrequest_challenge,
          { "Challenge", "steam_ihs_discovery.body_proofrequest_challenge",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        /* CMsgRemoteDeviceProofResponse */
        { &hf_steam_ihs_discovery_body_proofresponse_response,
          { "Response", "steam_ihs_discovery.body_proofresponse_response",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_steam_ihs_discovery,
        &ett_steam_ihs_discovery_body_status_user
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_steam_ihs_discovery_unknown_data,
          { "steam_ihs_discovery.unknowndata", PI_UNDECODED, PI_WARN,
            "Unknown data section", EXPFILL }
        },
        { &ei_steam_ihs_discovery_unknown_number,
          { "steam_ihs_discovery.unknownnumber", PI_UNDECODED, PI_WARN,
            "Unknown numeric protobuf field", EXPFILL }
        },
        { &ei_steam_ihs_discovery_unknown_lengthdelimited,
          { "steam_ihs_discovery.unknownlengthdelimited", PI_UNDECODED, PI_WARN,
            "Unknown length-delimited protobuf field", EXPFILL }
        },
        { &ei_steam_ihs_discovery_invalid_wiretype,
          { "steam_ihs_discovery.invalid_wiretype", PI_MALFORMED, PI_ERROR,
            "Unexpected wire type", EXPFILL }
        },
        { &ei_steam_ihs_discovery_invalid_length,
          { "steam_ihs_discovery.invalid_length", PI_MALFORMED, PI_ERROR,
            "Length-delimited field has invalid length", EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_steam_ihs_discovery = proto_register_protocol("Steam In-Home Streaming Discovery Protocol",
            "Steam IHS Discovery", "steam_ihs_discovery");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_steam_ihs_discovery, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_steam_ihs_discovery = expert_register_protocol(proto_steam_ihs_discovery);
    expert_register_field_array(expert_steam_ihs_discovery, ei, array_length(ei));

    /* Register a preferences module - handled by Decode As. */
    /* steam_ihs_discovery_module = prefs_register_protocol(proto_steam_ihs_discovery, NULL); */
}

void
proto_reg_handoff_steam_ihs_discovery(void)
{
    static dissector_handle_t steam_ihs_discovery_handle;

    steam_ihs_discovery_handle = create_dissector_handle(dissect_steam_ihs_discovery, proto_steam_ihs_discovery);

    dissector_add_uint_with_preference("udp.port", STEAM_IHS_DISCOVERY_UDP_PORT, steam_ihs_discovery_handle);
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
