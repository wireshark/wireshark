/* packet-opensafety.c
 *
 * $Id$
 *
 *   openSAFETY is a machine-safety protocol, encapsulated in modern fieldbus
 *   and industrial ethernet solutions.
 *
 *   For more information see http://www.open-safety.org
 *
 *   This dissector currently supports the following transport protocols
 *
 *   - openSAFETY using POWERLINK
 *   - openSAFETY using SercosIII
 *   - openSAFETY using Generic UDP
 *   - openSAFETY using Modbus/TCP
 *   - openSAFETY using (openSAFETY over UDP) transport
 *   - openSAFETY using ProfiNet IO
 *
 * By Roland Knall <roland.knall@br-automation.com>
 * Copyright 2011-2012 Bernecker + Rainer Industrie-Elektronik Ges.m.b.H.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-udp.h>

#include <wsutil/crc8.h>
#include <wsutil/crc16.h>

#include <stdio.h>
#include <string.h>


/* General definitions */

/* openSAFETY UDP Port */
#ifndef UDP_PORT_OPENSAFETY
#define UDP_PORT_OPENSAFETY   9877
#endif

/* SercosIII UDP Port */
#ifndef UDP_PORT_SIII
#define UDP_PORT_SIII         8755
#endif

/* Under linux, this get's defined in netinet/in.h */
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 0x11
#endif

#ifndef OPENSAFETY_PINFO_CONST_DATA
#define OPENSAFETY_PINFO_CONST_DATA 0xAABBCCDD
#endif

/* openSAFETY CRC types */
#define OPENSAFETY_CHECKSUM_CRC8   0x01
#define OPENSAFETY_CHECKSUM_CRC16  0x02
#define OPENSAFETY_CHECKSUM_CRC32  0x04

static const value_string message_crc_type[] = {
    { OPENSAFETY_CHECKSUM_CRC8,  "CRC8" },
    { OPENSAFETY_CHECKSUM_CRC16, "CRC16" },
    { OPENSAFETY_CHECKSUM_CRC32, "CRC32" },
    { 0, NULL }
};

/* openSAFETY Message Types */
#define OPENSAFETY_SPDO_MESSAGE_TYPE           0xC0
#define OPENSAFETY_SSDO_MESSAGE_TYPE           0xE0
#define OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE      0xE8
#define OPENSAFETY_SNMT_MESSAGE_TYPE           0xA0

static const value_string message_id_values[] = {
    { OPENSAFETY_SPDO_MESSAGE_TYPE,      "openSAFETY SPDO" },
    { OPENSAFETY_SSDO_MESSAGE_TYPE,      "openSAFETY SSDO" },
    { OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE, "openSAFETY Slim SSDO" },
    { OPENSAFETY_SNMT_MESSAGE_TYPE,      "openSAFETY SNMT" },
    { 0, NULL }
};

/* openSAFETY Message IDs */
#define OPENSAFETY_MSG_SPDO_DATA_ONLY                  0xC0
#define OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST     0xC8
#define OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE    0xD0
#define OPENSAFETY_MSG_SPDO_RESERVED                   0xD8

#define OPENSAFETY_MSG_SSDO_SERVICE_REQUEST            0xE0
#define OPENSAFETY_MSG_SSDO_SERVICE_RESPONSE           0xE4
#define OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST       0xE8
#define OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE      0xEC

#define OPENSAFETY_MSG_SNMT_REQUEST_UDID               0xA0
#define OPENSAFETY_MSG_SNMT_RESPONSE_UDID              0xA4
#define OPENSAFETY_MSG_SNMT_ASSIGN_SADR                0xA8
#define OPENSAFETY_MSG_SNMT_SADR_ASSIGNED              0xAC
#define OPENSAFETY_MSG_SNMT_SERVICE_REQUEST            0xB0
#define OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE           0xB4
#define OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM      0xBC

static const value_string message_type_values[] = {
    { OPENSAFETY_MSG_SPDO_DATA_ONLY,               "SPDO Data only" },
    { OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST,  "SPDO Data with Time Request" },
    { OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE, "SPDO Data with Time Response" },
    { OPENSAFETY_MSG_SPDO_RESERVED,                "SPDO Reserved" },

    { OPENSAFETY_MSG_SSDO_SERVICE_REQUEST,         "SSDO Service Request" },
    { OPENSAFETY_MSG_SSDO_SERVICE_RESPONSE,        "SSDO Service Response" },
    { OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST,    "SSDO Slim Service Request" },
    { OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE,   "SSDO Slim Service Response" },

    { OPENSAFETY_MSG_SNMT_REQUEST_UDID,            "SNMT Request UDID" },
    { OPENSAFETY_MSG_SNMT_RESPONSE_UDID,           "SNMT Response UDID" },
    { OPENSAFETY_MSG_SNMT_ASSIGN_SADR,             "SNMT Assign SADR" },
    { OPENSAFETY_MSG_SNMT_SADR_ASSIGNED,           "SNMT SADR Assigned" },
    { OPENSAFETY_MSG_SNMT_SERVICE_REQUEST,         "SNMT Service Request" },
    { OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE,        "SNMT Service Response" },
    { OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM,   "SNMT SN reset guarding SCM" },
    {0, NULL }
};

/* SNTM extended Services */
#define OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_PRE_OP              0x00
#define OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP                  0x02
#define OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP               0x04
#define OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP                 0x06
#define OPENSAFETY_MSG_SNMT_EXT_SCM_GUARD_SN                  0x08
#define OPENSAFETY_MSG_SNMT_EXT_ASSIGN_ADDITIONAL_SADR        0x0A
#define OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE                0x0C
#define OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM            0x0E
#define OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_PRE_OP              0x01
#define OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_OP                  0x03
#define OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_ADDITIONAL_SADR   0x05
#define OPENSAFETY_MSG_SNMT_EXT_SN_FAIL                       0x07
#define OPENSAFETY_MSG_SNMT_EXT_SN_BUSY                       0x09
#define OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM          0x0F

static const value_string message_service_type[] = {
    { OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_PRE_OP,             "SN set to pre Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP,                 "SN set to Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP,              "SCM set to Stop" },
    { OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP,                "SCM set to Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SCM_GUARD_SN,                 "SCM guard SN" },
    { OPENSAFETY_MSG_SNMT_EXT_ASSIGN_ADDITIONAL_SADR,       "Assign additional SADR" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE,               "SN Acknowledge" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM,           "SN assign UDID SCM" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_PRE_OP,             "SN status pre Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_OP,                 "SN status Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_ADDITIONAL_SADR,  "Assigned additional SADR" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_FAIL,                      "SN Fail" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_BUSY,                      "SN Busy" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM,         "SN assigned UDID SCM" },
    { 0, NULL }
};

/* Values 5-255 are reserved for future use. They will be presented as "Reserved [%d]"
 * during dissection
 */
static const value_string sn_fail_error_group[] = {
    { 1, "Application" },
    { 2, "Parameter" },
    { 3, "Vendor specific" },
    { 4, "openSAFETY Stack" },
    { 0, NULL }
};

/* SNTM extended Services */
#define OPENSAFETY_MSG_SSDO_ABORT                           0x04
#define OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE           0x08
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE         0x09
#define OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED       0x20
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED     0x21
#define OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED       0x28
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED     0x29
#define OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END              0x48
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END            0x49
#if 0
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_MIDDLE     0x88
#define OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_MIDDLE   0x89
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE           0xA8
#define OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_INITIATE         0xA9
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE_EXPEDITED 0xC0
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_END        0x40
#define OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_END      0xC9
#endif

static const value_string ssdo_sacmd_values[] = {
#if 0
    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_END,     "Block Download Segment End" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE,          "Block Upload Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE_EXPEDITED,"Block Upload Initiate" },
    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_INITIATE,        "Block Download Initiate" },
    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_MIDDLE,  "Block Download Middle Segment" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_MIDDLE,    "Block Upload Middle Segment" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_END,       "Block Upload End Segment" },
#endif
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END,           "Download End Segment" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END,             "Upload End Segment" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED,    "Download Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED,      "Upload Initiate Segmented" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED,    "Download Initiate Segmented" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED,      "Upload Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE,        "Download Middle Segment" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE,          "Upload Middle Segment" },
    { OPENSAFETY_MSG_SSDO_ABORT,                           "Abort" },
    { 0, NULL }
};

#define OPENSAFETY_SSDO_SACMD_ACC  0x01
#define OPENSAFETY_SSDO_SACMD_RES  0x02
#define OPENSAFETY_SSDO_SACMD_ABRT 0x04
#define OPENSAFETY_SSDO_SACMD_SEG  0x08
#define OPENSAFETY_SSDO_SACMD_TGL  0x10
#define OPENSAFETY_SSDO_SACMD_INI  0x20
#define OPENSAFETY_SSDO_SACMD_ENSG 0x40
#define OPENSAFETY_SSDO_SACMD_BLK  0x80

static const true_false_string opensafety_sacmd_acc  = { "Write Access", "Read Access" };
static const true_false_string opensafety_sacmd_res  = { "Reserved", "Reserved" };
static const true_false_string opensafety_sacmd_abrt = { "Abort Transfer", "Successful Transfer" };
static const true_false_string opensafety_sacmd_seg  = { "Segmented Access", "Expedited Access" };
static const true_false_string opensafety_on_off     = { "On", "Off" };
static const true_false_string opensafety_set_notset = { "Set", "Not set" };
static const true_false_string opensafety_sacmd_ini  = { "Initiate", "No Initiate" };
static const true_false_string opensafety_sacmd_ensg = { "No more segments", "More segments" };
static const true_false_string opensafety_sacmd_blk  = { "Block Transfer", "Normal Transfer" };

#define OPENSAFETY_SPDO_CONNECTION_VALID  0x04


static const value_string abort_codes[] = {

    /* SSDO abort codes */
    { 0x05030000,  "Reserved" },

    { 0x05040000,  "SSDO protocol timed out" },
    { 0x05040001,  "Client/server Command ID not valid or unknown" },
    { 0x05040002,  "Invalid block size" },
    { 0x05040003,  "Invalid sequence number" },
    { 0x05040004,  "Reserved" },
    { 0x05040005,  "Out of memory" },

    { 0x06010000,  "Unsupported access to an object" },
    { 0x06010001,  "Attempt to read a write-only object" },
    { 0x06010002,  "Attempt to write a read-only object" },

    { 0x06020000,  "Object does not exist in the object dictionary" },

    { 0x06040041,  "Object cannot be mapped to the SPDO" },
    { 0x06040042,  "The number and length of the objects to be mapped would exceed SPDO length" },
    { 0x06040043,  "General parameter incompatibility" },
    { 0x06040047,  "General internal incompatibility in the device" },

    { 0x06060000,  "Access failed due to a hardware error" },

    { 0x06070010,  "Data type does not match, length of service parameter does not match" },
    { 0x06070012,  "Data type does not match, length of service parameter too high" },
    { 0x06070013,  "Data type does not match, length of service parameter too low" },

    { 0x06090011,  "Sub-index does not exist" },
    { 0x06090030,  "Value range o parameter exceeded (only for write access)" },
    { 0x06090031,  "Value of parameter written too high" },
    { 0x06090032,  "Value of parameter written too low" },
    { 0x06090036,  "Maximum value is less than minimum value" },

    { 0x08000000,  "General error" },
    { 0x08000020,  "Data cannot be transferred or stored to the application" },
    { 0x08000021,  "Data cannot be transferred or stored to the application because of local control" },
    { 0x08000022,  "Data cannot be transferred or stored to the application because of the present device state" },
    { 0x08000023,  "Data cannot be transferred or stored to the application because of the object data is not available now" },

    { 0, NULL }
};

static const true_false_string opensafety_message_direction = { "Request", "Response" };
#define OPENSAFETY_REQUEST  TRUE
#define OPENSAFETY_RESPONSE FALSE

#define OSS_FRAME_POS_ADDR   0
#define OSS_FRAME_POS_ID     1
#define OSS_FRAME_POS_LEN    2
#define OSS_FRAME_POS_CT     3
#define OSS_FRAME_POS_DATA   4

#define OSS_PAYLOAD_MAXSIZE_FOR_CRC8        0x08
#define OSS_SLIM_FRAME_WITH_CRC8_MAXSIZE    0x13   /* 19 */
#define OSS_SLIM_FRAME2_WITH_CRC8           0x06   /*  6 */
#define OSS_SLIM_FRAME2_WITH_CRC16          0x07   /*  7 */
#define OSS_MINIMUM_LENGTH                  0x0b   /* 11 */

#define OSS_FRAME_ADDR(f, offset)        (f[OSS_FRAME_POS_ADDR + offset] + ((guint8)((f[OSS_FRAME_POS_ADDR + offset + 1]) << 6) << 2))
#define OSS_FRAME_ID(f, offset)          ((f[OSS_FRAME_POS_ID + offset] >> 2 ) << 2)
#define OSS_FRAME_LENGTH(f, offset)      (f[OSS_FRAME_POS_LEN + offset])
#define OSS_FRAME_FIELD(f, position)       (f[position])


static int proto_opensafety = -1;

static gint ett_opensafety = -1;
static gint ett_opensafety_checksum = -1;
static gint ett_opensafety_snmt = -1;
static gint ett_opensafety_ssdo = -1;
static gint ett_opensafety_spdo = -1;
static gint ett_opensafety_ssdo_sacmd = -1;
static gint ett_opensafety_sender = -1;
static gint ett_opensafety_receiver = -1;

static int hf_oss_msg = -1;
static int hf_oss_msg_direction = -1;
static int hf_oss_msg_category = -1;
static int hf_oss_msg_node = -1;
static int hf_oss_msg_network = -1;
static int hf_oss_msg_sender = -1;
static int hf_oss_msg_receiver = -1;
static int hf_oss_length= -1;
static int hf_oss_data = -1;
static int hf_oss_crc = -1;

static int hf_oss_crc_valid = -1;
static int hf_oss_crc_type  = -1;

static int hf_oss_snmt_slave         = -1;
static int hf_oss_snmt_master        = -1;
static int hf_oss_snmt_udid          = -1;
static int hf_oss_snmt_scm           = -1;
static int hf_oss_snmt_tool          = -1;
static int hf_oss_snmt_timestamp     = -1;
static int hf_oss_snmt_service_id    = -1;
static int hf_oss_snmt_error_group   = -1;
static int hf_oss_snmt_error_code    = -1;

static int hf_oss_ssdo_server        = -1;
static int hf_oss_ssdo_client        = -1;
static int hf_oss_ssdo_sano          = -1;
static int hf_oss_ssdo_sacmd         = -1;
static int hf_oss_ssdo_sod_index     = -1;
static int hf_oss_ssdo_sod_subindex  = -1;
static int hf_oss_ssdo_payload       = -1;
static int hf_oss_ssdo_payload_size  = -1;
static int hf_oss_ssdo_segment_size  = -1;
static int hf_oss_ssdo_inhibit_time  = -1;
static int hf_oss_ssdo_abort_code    = -1;

static int hf_oss_ssdo_sacmd_access_type     = -1;
static int hf_oss_ssdo_sacmd_reserved        = -1;
static int hf_oss_ssdo_sacmd_abort_transfer  = -1;
static int hf_oss_ssdo_sacmd_segmentation    = -1;
static int hf_oss_ssdo_sacmd_toggle          = -1;
static int hf_oss_ssdo_sacmd_initiate        = -1;
static int hf_oss_ssdo_sacmd_end_segment     = -1;
static int hf_oss_ssdo_sacmd_block_transfer  = -1;

static int hf_oss_scm_udid           = -1;
static int hf_oss_scm_udid_valid     = -1;

static int hf_oss_spdo_connection_valid   = -1;
static int hf_oss_spdo_payload            = -1;
static int hf_oss_spdo_producer           = -1;
static int hf_oss_spdo_producer_time      = -1;
static int hf_oss_spdo_time_value_sn      = -1;
static int hf_oss_spdo_time_request       = -1;
static int hf_oss_spdo_time_request_to    = -1;
static int hf_oss_spdo_time_request_from  = -1;

static const char *global_scm_udid = "00:00:00:00:00:00";
static gboolean global_udp_frame2_first = FALSE;
static gboolean global_mbtcp_big_endian = FALSE;
static guint global_network_udp_port = UDP_PORT_OPENSAFETY;
static guint global_network_udp_port_sercosiii = UDP_PORT_SIII;

void proto_register_opensafety(void);
void proto_reg_handoff_opensafety(void);

/* Conversation functions */

/* This is defined by the specification. The Address field is 10 bits long, and the node with the number
 *  1 is always the SCM, therefore ( 2 ^ 10 ) - 1 nodes can be addressed. We use 2 ^ 10 here, because the
 *  SCM can talk to himself (Assign SADR for instance ) */
#define MAX_NUMBER_OF_SAFETY_NODES      ( 2 ^ 10 )

/* Tracks the information that the packet pinfo has been received by receiver, and adds that information to the tree, using pos, as
 * byte position in the PDU */
#define PACKET_RECEIVER(pinfo, recv, pos, posnet, sdn)                       { \
        proto_item * psf_item = NULL; \
        proto_tree *psf_tree = NULL; \
        psf_item = proto_tree_add_uint(opensafety_tree, hf_oss_msg_receiver, message_tvb, pos, 2, recv); \
        psf_tree = proto_item_add_subtree(psf_item, ett_opensafety_receiver); \
        psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_node, message_tvb, pos, 2, recv);\
        PROTO_ITEM_SET_GENERATED(psf_item); \
        if ( sdn > 0 ) \
        { \
        	psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn, "0x%04X", sdn); \
        } else if ( sdn <= 0 ) { \
            psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn * -1, "0x%04X", sdn * -1); \
            expert_add_info_format(pinfo, psf_item, PI_UNDECODED, PI_NOTE, "SCM UDID unknown, assuming 00 as first UDID octet" ); \
        } \
        PROTO_ITEM_SET_GENERATED(psf_item); \
        }

/* Tracks the information that the packet pinfo has been sent by sender, and received by everyone else, and adds that information to
 * the tree, using pos, as byte position in the PDU */
#define PACKET_SENDER(pinfo, sender, pos, posnet, sdn)                { \
        proto_item * psf_item = NULL; \
        proto_tree *psf_tree = NULL; \
        psf_item = proto_tree_add_uint(opensafety_tree, hf_oss_msg_sender, message_tvb, pos, 2, sender); \
        psf_tree = proto_item_add_subtree(psf_item, ett_opensafety_sender); \
        psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_node, message_tvb, pos, 2, sender);\
        PROTO_ITEM_SET_GENERATED(psf_item); \
        if ( sdn > 0 ) \
        { \
        	psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn, "0x%04X", sdn); \
        } else if ( sdn <= 0 ) { \
            psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn * -1, "0x%04X", sdn * -1); \
            expert_add_info_format(pinfo, psf_item, PI_UNDECODED, PI_NOTE, "SCM UDID unknown, assuming 00 as first UDID octet" ); \
        } \
        PROTO_ITEM_SET_GENERATED(psf_item); \
        }

/* Tracks the information that the packet pinfo has been sent by sender, and received by receiver, and adds that information to
 * the tree, using pos for the sender and pos2 for the receiver, as byte position in the PDU */
#define PACKET_SENDER_RECEIVER(pinfo, send, pos, recv, pos2, posnet, sdn)         { \
        PACKET_SENDER(pinfo, send, pos, posnet, sdn); \
        PACKET_RECEIVER(pinfo, recv, pos2, posnet, sdn); \
        }

static guint16
findFrame1Position ( guint8 byteStream[], guint8 dataLength, gboolean checkIfSlimMistake )
{
    guint16 i_wFrame1Position = 0;
    guint16 i_payloadLength, i_calculatedLength = 0;
    guint16 i_offset = 0, calcCRC = 0, frameCRC = 0;
    guint8 b_tempByte = 0;

    /*
     * First, a normal package get's assumed. Calculation of frame 1 position is
     * pretty easy, because, the length of the whole package is 11 + 2*n + 2*o, which
     * results in frame 1 start at (6 + n + o), which is length / 2 + 1
     */
    i_wFrame1Position = dataLength / 2 + 1;
    i_payloadLength = byteStream [ i_wFrame1Position + 2 ];
    /* Calculating the assumed frame length, taking CRC8/CRC16 into account */
    i_calculatedLength = i_payloadLength * 2 + 11 + 2 * (i_payloadLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? 1 : 0);

    /* To prevent miscalculations, where by chance the byte at [length / 2] + 3 is a value matching a possible payload length,
     * but in reality the frame is a slim ssdo, the CRC of frame 1 get's checked additionally. This check
     * is somewhat time consuming, so it will only run if the normal check led to a mistake detected along the line */
    if ( checkIfSlimMistake && i_calculatedLength == dataLength )
    {
        if ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
            calcCRC = crc16_0x5935(&byteStream[i_wFrame1Position], dataLength + 4, 0);
        else
            calcCRC = crc8_0x2F(&byteStream[i_wFrame1Position], dataLength + 4, 0);

        frameCRC = byteStream[i_wFrame1Position + dataLength + OSS_FRAME_POS_DATA];
        if (dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
            frameCRC += (byteStream[i_wFrame1Position + dataLength + OSS_FRAME_POS_DATA + 1] << 8);

        /* if the calculated crc does not match the detected, the package is not a normal openSAFETY package */
        if ( frameCRC != calcCRC )
            dataLength = 0;
    }

    /* If the calculated length differs from the given length, a slim package is assumed. */
    if ( i_calculatedLength != dataLength )
    {
        /* possible slim package */
        i_wFrame1Position = 0;
        /*
         * Slim packages have a fixed sublength of either 6 bytes for frame 2 in
         * case of crc8 and 7 bytes in case of crc16
         */
        i_offset = OSS_SLIM_FRAME2_WITH_CRC8 + ( dataLength < (OSS_SLIM_FRAME_WITH_CRC8_MAXSIZE + 1) ? 0 : 1 );
        /* Last 2 digits belong to addr, therefore have to be cleared */
        b_tempByte = ( ( byteStream [ i_offset + 1 ] ) >> 2 ) << 2;

        /* If the id byte xor 0xE8 is 0, we have a slim package */
        if ( ( ( b_tempByte ^ OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST ) == 0 ) ||
             ( ( b_tempByte ^ OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) == 0 ) )
        {
            /* Slim package found */
            i_wFrame1Position = i_offset;
        }
    }

    return i_wFrame1Position;
}

/*
 * This function applies the given UDID to the bytestream, considering the start of frame 2
 */
static guint8 * unxorFrame(guint dataLength, guint8 byteStream[], guint16 frameStart1, guint16 frameStart2, guint8 scmUDID[])
{
    guint8 * pb_sendMemBlock;
    guint k;
    guint8 frame1Size;

    frame1Size = ( frameStart2 > frameStart1 ? frameStart2 : dataLength - frameStart1 );
    frame1Size = MIN(frame1Size, dataLength);

    pb_sendMemBlock = (guint8*) ep_alloc0( sizeof(guint8) * dataLength);

    memcpy ( &pb_sendMemBlock[frameStart1], &byteStream[frameStart1], frame1Size );

    for ( k = 0; k < (guint)(dataLength - frame1Size); k++)
        pb_sendMemBlock [ k + frameStart2 ] = byteStream [ k + frameStart2 ] ^ scmUDID[ ( k % 6 ) ];

    return pb_sendMemBlock;
}

static guint8 findSafetyFrame ( guint8 * pBuffer, guint32 length, guint u_Offset, gboolean b_frame2first, guint *u_frameOffset, guint *u_frameLength )
{
    guint n;
    guint16 crc, calcCrc;
    guint8 b_ID, b_Length, crcOffset, leftShifted;
    gboolean found;

    found = 0;
    for ( n = u_Offset; n < ( u_Offset + length ); n++)
    {
        /* The ID byte must ALWAYS be the second byte, therefore 0 is invalid */
        if ( n == 0 )
            continue;

        *u_frameLength = 0;
        *u_frameOffset = 0;

        crcOffset = 0;
        b_ID = pBuffer [ n ];
        b_Length = pBuffer [ n + 1 ];

        /* 0xFF is often used, but always false, otherwise start detection, if the highest
         *  bit is set */
        if ( ( b_ID != 0xFF ) && ( b_ID & 0x80 ) )
        {
            /* If the determined size could be bigger then the data to be dissected,
             * we have an error, return */
            if ( ( b_Length + n ) > ( u_Offset + length ) )
                continue;

            leftShifted = b_ID >> 4;
            /* An openSAFETY command has to have a high-byte range between 0x0A and 0x0E
             *  b_ID 0x80 took care of everything underneath, we check for 0x09 and 0x0F,
             *  as they remain the only values left, which are not valid */
            if ( ( leftShifted == 0x09 ) || ( leftShifted == 0x0F ) )
                continue;

            /* Find CRC position and calculate checksum */
            calcCrc = 0;
            crc = pBuffer [ n + 3 + b_Length ];
            if ( b_Length > 8 ) {
                crc += ( ( pBuffer [ n + 4 + b_Length ] ) << 8 );
                crcOffset = 1;
                if ( crc != 0x00 )
                    calcCrc = crc16_0x5935( &pBuffer [ n - 1 ], b_Length + 4, 0 );
            } else {
                if ( crc != 0x00 )
                    calcCrc = crc8_0x2F ( &pBuffer [ n - 1 ], b_Length + 4, 0 );
            }

            if ( ( crc != 0x00 ) && ( crc ^ calcCrc ) == 0 )
            {
                /* We have found a Slim frame. Those are not correctly identified yet */
                if ( ( b_ID >> 3 ) == ( OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE >> 3 ) )
                {
                    *u_frameOffset = ( n - 1 );
                    *u_frameLength = b_Length + 2 * crcOffset + 11;
                    found = 1;
                    break;
                }
                else
                {
                    *u_frameLength = 2 * b_Length + 2 * crcOffset + 11;
                    *u_frameOffset = ( n - 1 );
                    /* EPL SoC messages can be falsely detected as openSAFETY frames,
                     *  so we check if both checksums have no lower byte of 0x00. This
                     *  check remains, although SoC and SoA messages get sorted out in
                     *  the dissector */
                    if ( pBuffer [ *u_frameOffset + *u_frameLength - 2 ] == 0x00 &&
                        pBuffer [ *u_frameOffset + *u_frameLength - 1 ] == 0x00 )
                        continue;

                    found = 1;
                    break;
                }
            }
        }
    }

    /** Seem redundant if b_frame2First is false. But in this case, the function is needed for the
     * simple detection of a possible openSAFETY frame.  */
    if ( b_frame2first && found )
        *u_frameOffset = u_Offset;

    return (found ? 1 : 0);
}

static void
dissect_opensafety_spdo_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        guint8 * bytes, guint16 frameStart1, guint16 frameStart2 , gboolean validSCMUDID)
{
    proto_item *item;
    proto_tree *spdo_tree;
    guint16 ct;
    gint16 taddr;
    guint dataLength;
    guint8 tr, b_ID, conn_Valid;

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + frameStart1);
    b_ID = ( bytes[frameStart1 + 1] >> 3 ) << 3;
    conn_Valid = ( (bytes[frameStart1 + 1] & 0x04) == 0x04);

    ct = bytes[frameStart1 + 2];
    if ( validSCMUDID )
        ct = (guint16)(bytes[frameStart2 + 2] << 8) + (bytes[frameStart1 + 2]);

    /* Network address is xor'ed into the start of the second frame, but only legible, if the scm given is valid */
    taddr = ( ( OSS_FRAME_ADDR(bytes, frameStart1) ) ^ ( OSS_FRAME_ADDR(bytes, frameStart2) ) );
    if ( ! validSCMUDID )
        taddr = ( -1 * taddr );

    /* An SPDO get's always send by the producer, to everybody else */
    PACKET_SENDER( pinfo, OSS_FRAME_ADDR(bytes, frameStart1), OSS_FRAME_POS_ADDR + frameStart1, frameStart2, taddr );

    if ( taddr < 0 )
    	taddr = 0;

    item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg_category, message_tvb,
                                            OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_SPDO_MESSAGE_TYPE,
                                            "%s", val_to_str_const(OPENSAFETY_SPDO_MESSAGE_TYPE, message_id_values, "Unknown") );
    PROTO_ITEM_SET_GENERATED(item);

    spdo_tree = proto_item_add_subtree(item, ett_opensafety_spdo);

    if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE )
        proto_tree_add_boolean(spdo_tree, hf_oss_msg_direction, message_tvb,
                               OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST || b_ID == OPENSAFETY_MSG_SPDO_DATA_ONLY )
        proto_tree_add_boolean(spdo_tree, hf_oss_msg_direction, message_tvb,
                               OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    proto_tree_add_uint_format_value(spdo_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                     b_ID, "%s", val_to_str_const(b_ID, message_type_values, "Unknown") );

    proto_tree_add_uint(spdo_tree, hf_oss_spdo_producer, message_tvb,
                        OSS_FRAME_POS_ADDR + frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
    proto_tree_add_boolean(spdo_tree, hf_oss_spdo_connection_valid, message_tvb,
                           OSS_FRAME_POS_ID + frameStart1, 1, conn_Valid);

    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR(bytes, frameStart2 + 3);
    tr = ( bytes[frameStart2 + 4] << 2 ) >> 2;

    if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST )
    {
        item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_time_value_sn, message_tvb, 0, 0, ct,
                                                "0x%04X [%d] (%s)", ct, ct,
                                                (validSCMUDID ? "Complete" : "Low byte only"));
        PROTO_ITEM_SET_GENERATED(item);

        proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request, message_tvb,
                            OSS_FRAME_POS_ADDR + frameStart2 + 4, 1, tr);
        proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request_from, message_tvb,
                            OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
    }
    else
    {
        item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_producer_time, message_tvb, 0, 0, ct,
                "0x%04X [%d] (%s)", ct, ct, (validSCMUDID ? "Complete" : "Low byte only"));
        PROTO_ITEM_SET_GENERATED(item);

        if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE )
        {
            proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request, message_tvb, OSS_FRAME_POS_ADDR + frameStart2 + 4, 1, tr);
            proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request_to, message_tvb, OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
        }
    }

    if ( dataLength > 0 )
    {
        proto_tree_add_bytes(spdo_tree, hf_oss_spdo_payload, message_tvb, OSS_FRAME_POS_ID + 3,
                            dataLength, &bytes[frameStart1 + 4]);

    }
}


static void
dissect_opensafety_ssdo_message(tvbuff_t *message_tvb , packet_info * pinfo, proto_tree *opensafety_tree ,
        guint8 * bytes, guint16 frameStart1, guint16 frameStart2 , gboolean validSCMUDID)
{
    proto_item *item;
    proto_tree *ssdo_tree, *ssdo_sacmd_tree;
    guint16 taddr = 0    ;
    guint32 abortcode;
    guint8 db0Offset, db0, sacmd, payloadOffset, payloadSize, n;
    guint dataLength;
    gboolean isRequest;
    guint8 * payload;

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + frameStart1);

    db0Offset = frameStart1 + OSS_FRAME_POS_DATA;
    db0 = bytes[db0Offset];
    sacmd = db0;

    if ( ( sacmd & OPENSAFETY_SSDO_SACMD_TGL ) == OPENSAFETY_SSDO_SACMD_TGL )
        sacmd = sacmd & ( ~OPENSAFETY_SSDO_SACMD_TGL );

    isRequest = ( ( OSS_FRAME_ID(bytes, frameStart1) & 0x04 ) == 0x04 );

    if ( validSCMUDID )
    {
        /* taddr is the 4th octet in the second frame */
        taddr = OSS_FRAME_ADDR(bytes, frameStart2 + 3);

        PACKET_SENDER_RECEIVER( pinfo, OSS_FRAME_ADDR(bytes, frameStart1), frameStart1, taddr, frameStart2 + 3,
                                frameStart2,
                                ( ( OSS_FRAME_ADDR(bytes, frameStart1) ) ^ ( OSS_FRAME_ADDR(bytes, frameStart2) ) ));
    }
    else if ( ! isRequest )
    {
        PACKET_RECEIVER(pinfo, OSS_FRAME_ADDR(bytes, frameStart1), frameStart1, frameStart2,
        		        -1 * ( ( OSS_FRAME_ADDR(bytes, frameStart1) ) ^ ( OSS_FRAME_ADDR(bytes, frameStart2) ) ) );
    }

    if ( ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) )
        item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg_category, message_tvb,
                                                OSS_FRAME_POS_ID + frameStart1, 1,
                                                OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE,
                                                "%s", val_to_str_const(OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE, message_id_values, "Unknown") );
    else
        item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg_category, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                                OPENSAFETY_SSDO_MESSAGE_TYPE,
                                                "%s", val_to_str_const(OPENSAFETY_SSDO_MESSAGE_TYPE, message_id_values, "Unknown") );
    PROTO_ITEM_SET_GENERATED(item);

    ssdo_tree = proto_item_add_subtree(item, ett_opensafety_ssdo);

    if ( ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SERVICE_RESPONSE ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) )
        proto_tree_add_boolean(ssdo_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else
        proto_tree_add_boolean(ssdo_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    proto_tree_add_uint_format_value(ssdo_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                     OSS_FRAME_ID(bytes, frameStart1),
                                     "%s", val_to_str_const(OSS_FRAME_ID(bytes, frameStart1), message_type_values, "Unknown") );

    if ( isRequest )
    {
        if ( validSCMUDID )
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
        }
    }
    else if ( ! isRequest )
    {
        if ( validSCMUDID )
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
        }
    }

    item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sacmd, message_tvb, db0Offset, 1, sacmd);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", SACMD: %s", val_to_str_const(sacmd, ssdo_sacmd_values, " "));

    ssdo_sacmd_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sacmd);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_block_transfer, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_end_segment, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_initiate, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_toggle, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_segmentation, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_abort_transfer, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_access_type, message_tvb, db0Offset, 1, db0);

    payloadOffset = db0Offset + 1;
    /* When the following clause is met, DB1,2 contain the SOD index, and DB3 the SOD subindex */
    if ( ( ( sacmd & OPENSAFETY_SSDO_SACMD_INI ) == OPENSAFETY_SSDO_SACMD_INI ) ||
            ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE ) ||
            ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END ) ||
            ( sacmd == OPENSAFETY_MSG_SSDO_ABORT )
    )
    {
        proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sod_index, message_tvb, db0Offset + 1, 2,
                ((guint16)(bytes[db0Offset + 2] << 8) + bytes[db0Offset + 1]));
        proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sod_subindex, message_tvb, db0Offset + 3, 1, bytes[db0Offset + 3]);
        payloadOffset += 3;
    }

    if ( sacmd == OPENSAFETY_MSG_SSDO_ABORT )
    {
        abortcode = 0;
        for ( n = 0; n < 4; n++ )
            abortcode += ( bytes[frameStart1 + OSS_FRAME_POS_DATA + 4 + n] ) << (8 * n);

        proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_abort_code, message_tvb, payloadOffset, 4, abortcode,
                "0x%04X %04X - %s", (guint16)(abortcode >> 16), (guint16)(abortcode),
                val_to_str_const(abortcode, abort_codes, "Unknown"));


    } else if ( ( isRequest && (sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED ||
            sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED ||
            sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE ||
            sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END
                                ) ) ||
         ( !isRequest && (sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED ||
            sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED ||
            sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE ||
            sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END
                                 ) )
    )
    {
        if ( ( sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED ) || ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED ) )
        {
            payloadOffset += 4;
            /* using payloadSize as helper var for for-loop */
            payloadSize = dataLength - (payloadOffset - db0Offset);
            payload = (guint8*)ep_alloc(sizeof(guint8)*payloadSize);
            for ( n = 0; n < payloadSize; n++)
                payload[payloadSize - n - 1] = bytes[frameStart1 + OSS_FRAME_POS_DATA + (payloadOffset - db0Offset) + n];

            /* reading real size */
            payloadSize = 0;
            for ( n = 0; n < 4; n++ )
            {
                payloadSize += ( bytes[frameStart1 + OSS_FRAME_POS_DATA + 4 + n] ) << (8 * n);
            }

            proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, payloadOffset - 4, 4,
                    payloadSize, "%d octets total (%d octets in this frame)", payloadSize, dataLength - (payloadOffset - db0Offset));
            proto_tree_add_bytes(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset,
                    dataLength - (payloadOffset - db0Offset), payload );
        }
        else
        {
            payloadSize = dataLength - (payloadOffset - db0Offset);
            payload = (guint8*)ep_alloc(sizeof(guint8)*payloadSize);
            for ( n = 0; n < payloadSize; n++)
                payload[payloadSize - n - 1] = bytes[frameStart1 + OSS_FRAME_POS_DATA + (payloadOffset - db0Offset) + n];

            item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, 0, 0, payloadSize,
                    "%d octets", payloadSize);
            PROTO_ITEM_SET_GENERATED(item);
            proto_tree_add_bytes(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset, payloadSize, payload );
        }
    }
}

static void
dissect_opensafety_snmt_message(tvbuff_t *message_tvb, packet_info *pinfo , proto_tree *opensafety_tree,
        guint8 * bytes, guint16 frameStart1, guint16 frameStart2 )
{
    proto_item *item;
    proto_tree *snmt_tree;
    guint16 addr, taddr;
    guint8 db0, byte;
    guint dataLength;

    dataLength = OSS_FRAME_LENGTH(bytes, frameStart1);

    /* addr is the first field, as well as the recipient of the message */
    addr = OSS_FRAME_ADDR(bytes, frameStart1);
    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR(bytes, frameStart2 + 3);

    db0 = -1;
    if (dataLength > 0)
        db0 = bytes[OSS_FRAME_POS_DATA];

    if ( ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE) == 0 ) &&
         ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 || (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 ) )
    {
        PACKET_RECEIVER( pinfo, addr, OSS_FRAME_POS_ADDR + frameStart1, frameStart2,
                         ( OSS_FRAME_ADDR(bytes, frameStart1) ^ OSS_FRAME_ADDR(bytes, frameStart2) ) );
    }
    else
    {
        PACKET_SENDER_RECEIVER ( pinfo, taddr, frameStart2 + 3, addr, OSS_FRAME_POS_ADDR + frameStart1, frameStart2,
                                 ( OSS_FRAME_ADDR(bytes, frameStart1) ^ OSS_FRAME_ADDR(bytes, frameStart2) ) );
    }

    item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg_category, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                            OPENSAFETY_SNMT_MESSAGE_TYPE,
                                            "%s", val_to_str_const(OPENSAFETY_SNMT_MESSAGE_TYPE, message_id_values, "Unknown") );
    PROTO_ITEM_SET_GENERATED(item);

    snmt_tree = proto_item_add_subtree(item, ett_opensafety_snmt);

    if ( ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SNMT_RESPONSE_UDID ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SNMT_SADR_ASSIGNED ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE ) )
        proto_tree_add_boolean(snmt_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else
        proto_tree_add_boolean(snmt_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    proto_tree_add_uint_format_value(snmt_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                     OSS_FRAME_ID(bytes, frameStart1),
                                     "%s", val_to_str_const(OSS_FRAME_ID(bytes, frameStart1), message_type_values, "Unknown") );

    if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1, db0);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(db0, message_service_type, " "));

        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 )
        {
        	byte = bytes[OSS_FRAME_POS_DATA + frameStart1 + 1];
        	proto_tree_add_uint_format(snmt_tree, hf_oss_snmt_error_group, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 1,
        		byte, "%s",
        		( byte == 0 ? "Device" : val_to_str(byte, sn_fail_error_group, "Reserved [%d]" ) ) );

        	byte = bytes[OSS_FRAME_POS_DATA + frameStart1 + 2];
        	proto_tree_add_uint_format(snmt_tree, hf_oss_snmt_error_code, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 2, 1,
            	byte, "%s [%d]",
            	( byte == 0 ? "Default" : "Vendor Specific" ), byte );
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM) == 0 )
        {
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1,
                    6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6));
        }

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_REQUEST) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1, db0);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(db0, message_service_type, " "));

        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 || (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_scm, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_tool, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM) == 0 )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1,
                    6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6));
        }
        else
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
            if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP) == 0 )
            {
                proto_tree_add_bytes(snmt_tree, hf_oss_snmt_timestamp, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 4,
                                (bytes + frameStart1 + OSS_FRAME_POS_DATA + 1));
            }
        }
    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SADR_ASSIGNED) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb,
                    OSS_FRAME_POS_DATA + frameStart1, 6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6));
    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_ASSIGN_SADR) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb,
                    OSS_FRAME_POS_DATA + frameStart1, 6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6));

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_RESPONSE_UDID) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb,
                    OSS_FRAME_POS_DATA + frameStart1, 6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6));

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_REQUEST_UDID) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);
    }
}

static void
dissect_opensafety_checksum(tvbuff_t *message_tvb, proto_tree *opensafety_tree ,
        guint8 * bytes, guint16 frameStart1 )
{
    guint16 frameCrc;
    guint16 calcCrc;
    guint dataLength;
    proto_item * item;
    proto_tree *checksum_tree;
    gint start;
    gint length;

    dataLength = OSS_FRAME_LENGTH(bytes, frameStart1);
    start = OSS_FRAME_POS_DATA + dataLength  + frameStart1;
    frameCrc = bytes[start];

    if (OSS_FRAME_LENGTH(bytes, frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
        frameCrc += (bytes[start + 1] << 8);

    length = (dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OPENSAFETY_CHECKSUM_CRC16 : OPENSAFETY_CHECKSUM_CRC8);
    item = proto_tree_add_uint(opensafety_tree, hf_oss_crc, message_tvb, start, length, frameCrc);

    checksum_tree = proto_item_add_subtree(item, ett_opensafety_checksum);

    if ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
        calcCrc = crc16_0x5935(&bytes[frameStart1], dataLength + 4, 0);
    else
        calcCrc = crc8_0x2F(&bytes[frameStart1], dataLength + 4, 0);

    item = proto_tree_add_boolean(checksum_tree, hf_oss_crc_valid, message_tvb, start, length, (frameCrc == calcCrc));
    PROTO_ITEM_SET_GENERATED(item);
    /* using the defines, as the values can change */
    proto_tree_add_uint(checksum_tree, hf_oss_crc_type, message_tvb, start, length,
            ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OPENSAFETY_CHECKSUM_CRC16 : OPENSAFETY_CHECKSUM_CRC8 ) );
}

static gboolean
dissect_opensafety_message(guint16 frameStart1, guint16 frameStart2, guint8 type,
                           tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree, guint8 u_nrInPackage)
{
    guint8 b_ID;
    guint length;
    guint8 * bytes;
    GByteArray *scmUDID = NULL;
    gboolean validSCMUDID;
    proto_item * item;
    gboolean messageTypeUnknown;

    messageTypeUnknown = FALSE;
    length = tvb_length(message_tvb);

    bytes = (guint8 *)ep_tvb_memdup(message_tvb, 0, length);

    b_ID = OSS_FRAME_ID(bytes, frameStart1);
    /* Clearing connection valid bit */
    if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
        b_ID = ( b_ID >> 3 ) << 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, (u_nrInPackage > 1 ? " | %s" : "%s" ),
            val_to_str(b_ID, message_type_values, "Unknown Message (0x%02X) "));

    if (opensafety_tree)
    {
        if ( type == OPENSAFETY_SNMT_MESSAGE_TYPE )
        {
            dissect_opensafety_snmt_message ( message_tvb, pinfo, opensafety_tree, bytes, frameStart1, frameStart2 );
        }
        else
        {
            validSCMUDID = FALSE;
            scmUDID = g_byte_array_new();
            if ( hex_str_to_bytes(global_scm_udid, scmUDID, TRUE) && scmUDID->len == 6 )
            {
                validSCMUDID = TRUE;
                bytes = unxorFrame(length, bytes, frameStart1, frameStart2, scmUDID->data);
                /* Now confirm, that the xor operation was successful
                 *  The ID fields of both frames have to be the same, otherwise
                 *  perform the xor again to revert the change
                 */
                if ( ( OSS_FRAME_ID(bytes, frameStart1) ^ OSS_FRAME_ID(bytes, frameStart2 ) ) != 0 )
                {
                    validSCMUDID = FALSE;
                    bytes = unxorFrame(length, bytes, frameStart1, frameStart2, scmUDID->data);
                }
            }

            if ( strlen ( global_scm_udid ) > 0  && scmUDID->len == 6 )
            {
            	item = proto_tree_add_string(opensafety_tree, hf_oss_scm_udid, message_tvb, 0, 0, global_scm_udid);
            	PROTO_ITEM_SET_GENERATED(item);
            }

            item = proto_tree_add_boolean(opensafety_tree, hf_oss_scm_udid_valid, message_tvb, 0, 0, validSCMUDID);
            if ( scmUDID->len != 6 )
            	expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "openSAFETY protocol settings are invalid! SCM UDID first octet will be assumed to be 00" );
            PROTO_ITEM_SET_GENERATED(item);

            if (scmUDID)
                g_byte_array_free( scmUDID, TRUE);

            if ( type == OPENSAFETY_SSDO_MESSAGE_TYPE || type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
            {
                dissect_opensafety_ssdo_message ( message_tvb, pinfo, opensafety_tree, bytes, frameStart1, frameStart2, validSCMUDID );
            }
            else if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                dissect_opensafety_spdo_message ( message_tvb, pinfo, opensafety_tree, bytes, frameStart1, frameStart2, validSCMUDID );
            }
            else
            {
                messageTypeUnknown = TRUE;
            }
        }

        item = proto_tree_add_uint(opensafety_tree, hf_oss_length, message_tvb, OSS_FRAME_POS_LEN + frameStart1, 1, OSS_FRAME_LENGTH(bytes, frameStart1));
        if ( messageTypeUnknown )
        {
            expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Unknown openSAFETY message type" );
        }
        else
        {
            dissect_opensafety_checksum ( message_tvb, opensafety_tree, bytes, frameStart1 );
        }
    }

    return TRUE;
}

static gboolean
opensafety_package_dissector(const gchar * protocolName, const gchar * sub_diss_handle,
                             gboolean b_frame2First, gboolean do_byte_swap, guint8 force_nr_in_package,
                             tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    tvbuff_t *next_tvb;
    guint length, len, frameOffset, frameLength, nodeAddress;
    guint8 *bytes, *bytesOffset;
    gboolean handled, dissectorCalled, call_sub_dissector, markAsMalformed;
    guint8 type, found, packageCounter, i, tempByte;
    guint16 frameStart1, frameStart2;
    gint reported_len;
    dissector_handle_t protocol_dissector = NULL;
    proto_item *opensafety_item;
    proto_tree *opensafety_tree;

    handled = FALSE;
    dissectorCalled = FALSE;
    call_sub_dissector = FALSE;
    markAsMalformed = FALSE;

    length = tvb_length(message_tvb);
    /* Minimum package length is 11 */
    if ( length < 11 )
        return FALSE;

    if ( strlen( sub_diss_handle ) > 0 )
    {
        call_sub_dissector = TRUE;
        protocol_dissector = find_dissector ( sub_diss_handle );
        if ( protocol_dissector == NULL )
            protocol_dissector = find_dissector ( "data" );
    }

    reported_len = tvb_reported_length_remaining(message_tvb, 0);
    bytes = (guint8 *) ep_tvb_memdup(message_tvb, 0, length);

    if ( do_byte_swap == TRUE && global_mbtcp_big_endian == TRUE )
    {
        /* Wordswapping for modbus detection */
        /* Only a even number of bytes can be swapped */
        len = (length / 2);
        for ( i = 0; i < len; i++ )
        {
            tempByte = bytes [ 2 * i ]; bytes [ 2 * i ] = bytes [ 2 * i + 1 ]; bytes [ 2 * i + 1 ] = tempByte;
        }
    }

    frameOffset = 0;
    frameLength = 0;
    found = 0;
    packageCounter = 0;

    while ( frameOffset < length )
    {
        /** This case can occurs only during fuzztest or randpkt testing. */
        if ( ( length - frameOffset ) <= 0 )
            break;

        /** Finding the start of the first possible safety frame */
        if ( findSafetyFrame(bytes, length - frameOffset, frameOffset, b_frame2First, &frameOffset, &frameLength) )
        {
            /** frameLength is calculated/read directly from the dissected data. If frameLenght and frameOffset together
             * are bigger than the reported length, the package is not really an openSAFETY package */
            if ( ( frameOffset + frameLength ) > (guint)reported_len )
                break;
            found++;

            /* Freeing memory before dissector, as otherwise we would waste it */
            if ( do_byte_swap == TRUE && global_mbtcp_big_endian == TRUE )
            {
                next_tvb = tvb_new_child_real_data(message_tvb, &bytes[frameOffset], (frameLength), reported_len);
                /* Adding a visual aid to the dissector tree */
                add_new_data_source(pinfo, next_tvb, "openSAFETY Frame (Swapped)");
            }
            else
            {
                next_tvb = tvb_new_subset(message_tvb, frameOffset, frameLength, reported_len);
                /* Adding a visual aid to the dissector tree */
                add_new_data_source(pinfo, next_tvb, "openSAFETY Frame");
            }

            bytesOffset = &bytes[( b_frame2First ? 0 : frameOffset )];
            /* We determine a possible position for frame 1 and frame 2 */
            if ( b_frame2First )
            {
                frameStart1 = findFrame1Position (bytesOffset, frameLength, FALSE );
                frameStart2 = 0;
            }
            else
            {
                frameStart1 = 0;
                frameStart2 = ((OSS_FRAME_LENGTH(bytesOffset, frameStart1) - 1) +
                        (OSS_FRAME_LENGTH(bytesOffset, frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OSS_SLIM_FRAME2_WITH_CRC16 : OSS_SLIM_FRAME2_WITH_CRC8));
            }

            /* If both frame starts are equal, something went wrong. In which case, we retract the found entry, and
             * also increase the search offset, just doing a continue will result in an infinite loop. */
            if (frameStart1 == frameStart2)
            {
                found--;
                frameOffset += frameLength ;
                continue;
            }

            /* We determine the possible type, and return false, if there could not be one */
            if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SSDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                type = OPENSAFETY_SPDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                type = OPENSAFETY_SNMT_MESSAGE_TYPE;
            else
            {
                /* This is an invalid openSAFETY package, but it could be an undetected slim ssdo message. This specific error
                 * will only occur, if findFrame1Position is in play. So we search once more, but this time calculating the CRC.
                 * The reason for the second run is, that calculating the CRC is time consuming.  */
                if ( b_frame2First )
                {
                    /* Now let's check again, but this time calculate the CRC */
                    frameStart1 = findFrame1Position(bytesOffset, frameLength, TRUE );
                    frameStart2 = 0;

                    if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
                    else if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SSDO_MESSAGE_TYPE;
                    else if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SPDO_MESSAGE_TYPE;
                    else if ( ( OSS_FRAME_ID(bytesOffset, frameStart1) & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                        type = OPENSAFETY_SNMT_MESSAGE_TYPE;
                    else {
                        /* Skip this frame.  We cannot continue without
                           advancing frameOffset - just doing a continue
                           will result in an infinite loop. */
                        frameOffset += frameLength;
                        continue;
                    }
                } else {
                    /* As stated above, you cannot just continue
                       without advancing frameOffset. */
                    frameOffset += frameLength;
                    continue;
                }
            }

            /** Checking if the producer for a SPDO message is valid, otherwise the opensafety package
             * is malformed. Instead of declining dissection, the package get's marked as malformed */
            if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                nodeAddress = OSS_FRAME_ADDR(bytesOffset, frameStart1);
                if ( nodeAddress > 1024 ) {
                    markAsMalformed = TRUE;
                }
            }

            /* If this package is not valid, the next step, which normally occurs in unxorFrame will lead to a
             * frameLength bigger than the maximum data size. This is an indicator, that the package in general
             * is fault, and therefore we return false.
             */
            if ( ( (gint)frameLength - (gint)( frameStart2 > frameStart1 ? frameStart2 : frameLength - frameStart1 ) ) < 0 )
                return FALSE;

            /* A new subtype for package dissection will need to set the actual nr. for the whole dissected package */
            if ( force_nr_in_package > 0 )
            {
            	found = force_nr_in_package + 1;
            	dissectorCalled = TRUE;
            	col_set_str(pinfo->cinfo, COL_PROTOCOL, protocolName);
            }

            if ( ! dissectorCalled )
            {
                if ( call_sub_dissector )
                    call_dissector(protocol_dissector, message_tvb, pinfo, tree);
                dissectorCalled = TRUE;

                col_set_str(pinfo->cinfo, COL_PROTOCOL, protocolName);
                col_clear(pinfo->cinfo,COL_INFO);
            }

            /* if the tree is NULL, we are called for the overview, otherwise for the
             more detailed view of the package */
            if ( tree )
            {
                /* create the opensafety protocol tree */
                opensafety_item = proto_tree_add_item(tree, proto_opensafety, message_tvb, frameOffset, frameLength, ENC_BIG_ENDIAN);
                opensafety_tree = proto_item_add_subtree(opensafety_item, ett_opensafety);
            } else {
            	opensafety_tree = NULL;
            }

            if ( dissect_opensafety_message(frameStart1, frameStart2, type, next_tvb, pinfo, opensafety_tree, found) == TRUE )
                packageCounter++;

            if ( tree && markAsMalformed )
            {
                if ( OSS_FRAME_ADDR(bytesOffset, frameStart1) > 1024 )
                    expert_add_info_format(pinfo, opensafety_item, PI_MALFORMED, PI_ERROR, "SPDO address is invalid" );
            }
            handled = TRUE;
        }
        else
            break;

        frameOffset += frameLength;
    }

    if ( handled == TRUE && packageCounter == 0 )
        handled = FALSE;

    if ( ! handled )
    {
        if ( call_sub_dissector )
            call_dissector(protocol_dissector, message_tvb, pinfo, tree);
        handled = TRUE;
    }
    return ( handled ? TRUE : FALSE );
}

static gboolean
dissect_opensafety_epl(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    static gboolean calledOnce = FALSE;
    gboolean result = FALSE;
    guint8 firstByte;

    /* We will call the epl dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( calledOnce == FALSE )
    {
        calledOnce = TRUE;

        firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );

        /* No frames can be sent in SoA and SoC messages, therefore those get filtered right away */
        if ( ( firstByte != 0x02 ) && ( firstByte != 0x0A ) )
        {
            result = opensafety_package_dissector("openSAFETY/Powerlink", "epl",
                                                  FALSE, FALSE, 0, message_tvb, pinfo, tree);
        }

        calledOnce = FALSE;
    }

    return result;
}


static gboolean
dissect_opensafety_siii(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    static gboolean calledOnce = FALSE;
    gboolean result = FALSE;
    guint8 firstByte;

    if ( pinfo->ipproto == IPPROTO_UDP )
    {
        return  opensafety_package_dissector("openSAFETY/SercosIII UDP", "", FALSE, FALSE, 0, message_tvb, pinfo, tree);
    }

    /* We can assume to have a SercosIII package, as the SercosIII dissector won't detect
     * SercosIII-UDP packages, this is most likely SercosIII-over-ethernet */

    /* We will call the SercosIII dissector by using call_dissector(). The SercosIII dissector will
     * then call the heuristic openSAFETY dissector again. By setting this information, we prevent
     * a dissector loop. */
    if ( calledOnce == FALSE )
    {
        calledOnce = TRUE;
        /* No frames can be sent in AT messages, therefore those get filtered right away */
        firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );
        if ( ( firstByte & 0x40 ) == 0x40 )
        {
            result = opensafety_package_dissector("openSAFETY/SercosIII", "sercosiii",
                                                  FALSE, FALSE, 0, message_tvb, pinfo, tree);
        }
        calledOnce = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_pn_io(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    static gboolean calledOnce = FALSE;
    gboolean result = FALSE;

    /* We will call the epl dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( calledOnce == FALSE )
    {
        calledOnce = TRUE;
        result = opensafety_package_dissector("openSAFETY/Profinet IO", "pn_io",
                                              FALSE, FALSE, 0, message_tvb, pinfo, tree);
        calledOnce = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_mbtcp(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    /* When Modbus/TCP get's dissected, openSAFETY would be sorted as a child protocol. Although,
     * this behaviour is technically correct, it differs from other implemented IEM protocol handlers.
     * Therefore, the openSAFETY frame get's put one up, if the parent is not NULL */
    return opensafety_package_dissector("openSAFETY/Modbus TCP", "", FALSE, TRUE, 0,
                                        message_tvb, pinfo, ( tree->parent != NULL ? tree->parent : tree ));
}

static gboolean
dissect_opensafety_udpdata(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
	gboolean result = FALSE;
	static guint32 frameNum = 0;
	static guint32 frameIdx = 0;

	/* An openSAFETY frame has at least OSS_MINIMUM_LENGTH bytes */
	if ( tvb_length ( message_tvb ) < OSS_MINIMUM_LENGTH )
		return result;

	/* More than one openSAFETY package could be transported in the same frame,
	 * in such a case, we need to establish the number of packages inside the frame */
	if ( pinfo->fd->num != frameNum )
	{
		frameIdx = 0;
		frameNum = pinfo->fd->num;
	}

	result = opensafety_package_dissector((pinfo->destport == UDP_PORT_SIII ? "openSAFETY/SercosIII" : "openSAFETY/UDP" ),
                                        "", global_udp_frame2_first, FALSE, frameIdx, message_tvb, pinfo, tree);

	if ( result )
		frameIdx++;

	return result;
}

static void
apply_prefs ( void )
{
    static gboolean opensafety_init = FALSE;
    static guint opensafety_udp_port_number;
    static guint opensafety_udp_siii_port_number;

    /* It only should delete dissectors, if run for any time except the first */
    if ( opensafety_init )
    {
        /* Delete dissectors in preparation of a changed config setting */
        dissector_delete_uint ("udp.port", opensafety_udp_port_number, find_dissector("opensafety_udpdata"));
        dissector_delete_uint ("udp.port", opensafety_udp_siii_port_number, find_dissector("opensafety_siii"));
    }

    opensafety_init = TRUE;

    /* Storing the port numbers locally, to being able to delete the old associations */
    opensafety_udp_port_number = global_network_udp_port;
    opensafety_udp_siii_port_number = global_network_udp_port_sercosiii;

    /* Default UDP only based dissector */
    dissector_add_uint("udp.port", opensafety_udp_port_number, find_dissector("opensafety_udpdata"));

    /* Sercos III dissector does not handle UDP transport, has to be handled
     *  separately, everything else should be caught by the heuristic dissector
     */
    dissector_add_uint("udp.port", opensafety_udp_siii_port_number, find_dissector("opensafety_siii"));

}

void
proto_register_opensafety(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        /* General fields for subframe 1 */

        { &hf_oss_scm_udid,
          { "SCM UDID Configured",    "opensafety.scm_udid",
            FT_STRING,   BASE_NONE, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_scm_udid_valid,
          { "SCM UDID Valid",    "opensafety.scm_udid_valid",
            FT_BOOLEAN,   BASE_NONE, NULL,   0x0, NULL, HFILL } },

        { &hf_oss_msg,
          { "Message",    "opensafety.msg.id",
            FT_UINT8,   BASE_HEX, VALS(message_type_values),   0x0, NULL, HFILL } },
        { &hf_oss_msg_category,
          { "Type",  "opensafety.msg.type",
            FT_UINT16,   BASE_NONE, VALS(message_id_values),   0x0, NULL, HFILL } },
        { &hf_oss_msg_direction,
          { "Direction",  "opensafety.msg.direction",
            FT_BOOLEAN,   BASE_NONE, TFS(&opensafety_message_direction),   0x0, NULL, HFILL } },
        { &hf_oss_msg_node,
          { "Safety Node",  "opensafety.msg.node",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_network,
          { "Safety Domain",  "opensafety.msg.network",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_sender,
          { "Sender",  "opensafety.msg.sender",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_receiver,
          { "Receiver",  "opensafety.msg.receiver",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_length,
          { "Length",    "opensafety.length",
            FT_UINT8,   BASE_DEC, NULL,     0x0, NULL, HFILL } },
        { &hf_oss_data,
          { "Data",      "opensafety.data",
            FT_BYTES,   BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_crc,
          { "CRC",       "opensafety.crc.data",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        { &hf_oss_crc_valid,
          { "Is Valid", "opensafety.crc.valid",
            FT_BOOLEAN, BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_crc_type,
          { "CRC Type",  "opensafety.crc.type",
            FT_UINT8,   BASE_DEC, VALS(message_crc_type),    0x0, NULL, HFILL } },

        /* SNMT Specific fields */
        { &hf_oss_snmt_slave,
          { "SNMT Slave",    "opensafety.snmt.slave",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_master,
          { "SNMT Master",   "opensafety.snmt.master",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_scm,
          { "SCM",    "opensafety.snmt.scm",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_tool,
          { "Tool ID",   "opensafety.snmt.tool_id",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_udid,
          { "UDID for SN",   "opensafety.snmt.udid",
            FT_ETHER,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_timestamp,
          { "Parameter Timestamp",   "opensafety.snmt.timestamp",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_service_id,
          { "Extended Service ID",   "opensafety.snmt.service_id",
            FT_UINT8,  BASE_HEX, VALS(message_service_type),    0x0, NULL, HFILL } },
        { &hf_oss_snmt_error_group,
          { "Error Group",   "opensafety.snmt.error_group",
            FT_UINT8,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_error_code,
          { "Error Code",   "opensafety.snmt.error_code",
            FT_UINT8,  BASE_DEC, NULL,   0x0, NULL, HFILL } },

        /* SSDO Specific fields */
        { &hf_oss_ssdo_server,
          { "SSDO Server", "opensafety.ssdo.master",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_client,
          { "SSDO Client", "opensafety.ssdo.client",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sano,
          { "SOD Access Request Number", "opensafety.ssdo.sano",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd,
          { "SOD Access Command", "opensafety.ssdo.sacmd",
            FT_UINT8,  BASE_HEX, VALS(ssdo_sacmd_values),    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sod_index,
          { "SOD Index", "opensafety.ssdo.sod_index",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sod_subindex,
          { "SOD Sub Index", "opensafety.ssdo.sod_subindex",
            FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_payload,
          { "SOD Payload", "opensafety.ssdo.payload",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_payload_size,
          { "SOD Payload Size", "opensafety.ssdo.payloadsize",
            FT_UINT32,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_segment_size,
          { "SOD Segment Size", "opensafety.ssdo.segmentsize",
            FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_inhibit_time,
          { "Inhibit Time", "opensafety.ssdo.inhibittime",
            FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_abort_code,
          { "Abort Code", "opensafety.ssdo.abortcode", FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        /* SSDO SACmd specific fields */
        { &hf_oss_ssdo_sacmd_access_type,
          { "Access Type", "opensafety.ssdo.sacmd.access",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_acc), OPENSAFETY_SSDO_SACMD_ACC, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_reserved,
          { "Reserved", "opensafety.ssdo.sacmd.reserved",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_res), OPENSAFETY_SSDO_SACMD_RES, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_abort_transfer,
          { "Abort Transfer", "opensafety.ssdo.sacmd.abort_transfer",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_abrt), OPENSAFETY_SSDO_SACMD_ABRT, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_segmentation,
          { "Segmentation", "opensafety.ssdo.sacmd.segmentation",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_seg), OPENSAFETY_SSDO_SACMD_SEG, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_toggle,
          { "Toggle Bit", "opensafety.ssdo.sacmd.toggle",
            FT_BOOLEAN,  8, TFS(&opensafety_on_off), OPENSAFETY_SSDO_SACMD_TGL, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_initiate,
          { "Initiate Transfer", "opensafety.ssdo.sacmd.initiate",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_ini), OPENSAFETY_SSDO_SACMD_INI, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_end_segment,
          { "End Segment", "opensafety.ssdo.sacmd.end_segment",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_ensg), OPENSAFETY_SSDO_SACMD_ENSG, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd_block_transfer,
          { "Block Transfer", "opensafety.ssdo.sacmd.block_transfer",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_blk), OPENSAFETY_SSDO_SACMD_BLK, NULL, HFILL } },

        /* SPDO Specific fields */
        { &hf_oss_spdo_connection_valid,
          { "Connection Valid Bit", "opensafety.spdo.connection_valid",
            FT_BOOLEAN,  8, TFS(&opensafety_set_notset),  0x0, NULL, HFILL } },
        { &hf_oss_spdo_payload,
          { "SPDO Payload", "opensafety.spdo.payload",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_producer,
          { "Producer", "opensafety.spdo.producer",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_producer_time,
          { "Internal Time Producer", "opensafety.spdo.time.producer",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_value_sn,
          { "Internal Time SN", "opensafety.spdo.time.sn",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_request,
          { "Time Request Counter", "opensafety.spdo.time.request_counter",
            FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_request_to,
          { "Time Request from", "opensafety.spdo.time.request_from",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_spdo_time_request_from,
          { "Time Request by", "opensafety.spdo.time.request_to",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
            &ett_opensafety,
            &ett_opensafety_sender,
            &ett_opensafety_receiver,
            &ett_opensafety_checksum,
            &ett_opensafety_snmt,
            &ett_opensafety_ssdo,
            &ett_opensafety_spdo,
            &ett_opensafety_ssdo_sacmd,
    };

    module_t *opensafety_module;

    /* Register the protocol name and description */
    proto_opensafety = proto_register_protocol("openSAFETY", "openSAFETY",  "opensafety");
    opensafety_module = prefs_register_protocol(proto_opensafety, apply_prefs);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_opensafety, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* register user preferences */
    prefs_register_string_preference(opensafety_module, "scm_udid",
                 "SCM UDID (xx:xx:xx:xx:xx:xx)",
                 "To be able to fully dissect SSDO and SPDO packages, a valid UDID for the SCM has to be provided",
                 &global_scm_udid);
    prefs_register_uint_preference(opensafety_module, "network_udp_port",
                "Port used for Generic UDP",
                "Port used by any UDP demo implementation to transport data", 10,
                &global_network_udp_port);
    prefs_register_uint_preference(opensafety_module, "network_udp_port_sercosiii",
                "Port used for SercosIII/UDP",
                "UDP port used by SercosIII to transport data", 10,
                &global_network_udp_port_sercosiii);
    prefs_register_bool_preference(opensafety_module, "network_udp_frame_first",
    			"openSAFETY frame 2 before frame 1 (UDP only)",
    			"In the transport stream, openSAFETY frame 2 will be expected before frame 1",
    			&global_udp_frame2_first );
    prefs_register_bool_preference(opensafety_module, "mbtcp_big_endian",
                "Big Endian Word Coding (Modbus/TCP only)",
                "Modbus/TCP words can be transcoded either big- or little endian. Default will be little endian",
                &global_mbtcp_big_endian);

    /* Registering default and ModBus/TCP dissector */
    new_register_dissector("opensafety_udpdata", dissect_opensafety_udpdata, proto_opensafety );
    new_register_dissector("opensafety_mbtcp", dissect_opensafety_mbtcp, proto_opensafety );
    new_register_dissector("opensafety_siii", dissect_opensafety_siii, proto_opensafety );
    new_register_dissector("opensafety_pnio", dissect_opensafety_pn_io, proto_opensafety);
}

void
proto_reg_handoff_opensafety(void)
{
    static int opensafety_inited = FALSE;

    if ( !opensafety_inited )
    {
        /* EPL & SercosIII dissector registration */
        heur_dissector_add("epl", dissect_opensafety_epl, proto_opensafety);
        heur_dissector_add("sercosiii", dissect_opensafety_siii, proto_opensafety);

        /* If an openSAFETY UDP transport filter is present, add to its
         * heuristic filter list. Otherwise ignore the transport */
        if ( find_dissector("opensafety_udp") != NULL )
        	heur_dissector_add("opensafety_udp", dissect_opensafety_udpdata, proto_opensafety);

        /* Modbus TCP dissector registration */
        dissector_add_string("mbtcp.modbus.data", "data", find_dissector("opensafety_mbtcp"));

        /* For Profinet we have to register as a heuristic dissector, as Profinet
         *  is implemented as a plugin, and therefore the heuristic dissector is not
         *  added by the time this method is being called
         */
        if ( find_dissector("pn_io") != NULL )
        {
            heur_dissector_add("pn_io", dissect_opensafety_pn_io, proto_opensafety);
        }
        else
        {
            /* The native dissector cannot be loaded. so we add our protocol directly to
             * the ethernet subdissector list. No PNIO specific data will be dissected
             * and a warning will be displayed, recognizing the missing dissector plugin.
             */
            dissector_add_uint("ethertype", ETHERTYPE_PROFINET, find_dissector("opensafety_pnio"));
        }
    }

}
