/* packet-opensafety.c
 *   openSAFETY is a machine-safety protocol, encapsulated in modern fieldbus
 *   and industrial ethernet solutions.
 *   For more information see http://www.open-safety.org
 * By Roland Knall <roland.knall@br-automation.com>
 * Copyright 2011 Bernecker + Rainer Industrie-Elektronik Ges.m.b.H.
 *
 * $Id$
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
#include <epan/tfs.h>
#include <epan/proto.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-udp.h>

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
/*
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_MIDDLE     0x88
#define OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_MIDDLE   0x89
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE           0xA8
#define OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_INITIATE         0xA9
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE_EXPEDITED 0xC0
#define OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_END        0x40
#define OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_END      0xC9
*/
static const value_string ssdo_sacmd_values[] = {
    /*    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_END,     "Block Download Segment End" },
        { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE,          "Block Upload Expedited Initiate" },
        { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE_EXPEDITED,"Block Upload Initiate" },
        { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_INITIATE,        "Block Download Initiate" },
        { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_MIDDLE,  "Block Download Middle Segment" },
        { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_END,       "Block Upload End Segment" },*/
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

static const true_false_string opensafety_message_type = { "Request", "Response" };
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

#define OSS_FRAME_ADDR(f, offset)        (f[OSS_FRAME_POS_ADDR + offset] + ((guint8)((f[OSS_FRAME_POS_ADDR + offset + 1]) << 6) << 2))
#define OSS_FRAME_ID(f, offset)          ((f[OSS_FRAME_POS_ID + offset] >> 2 ) << 2)
#define OSS_FRAME_LENGTH(f, offset)      (f[OSS_FRAME_POS_LEN + offset])
#define OSS_FRAME_FIELD(f, position)       (f[position])


#define CRC8_POLY 0x2F /* CRC-8 Polynom */
#define CRC16_POLY 0x5935 /* CRC-16 Polynom */


static int proto_opensafety = -1;

static gint ett_opensafety = -1;
static gint ett_opensafety_checksum = -1;
static gint ett_opensafety_snmt = -1;
static gint ett_opensafety_ssdo = -1;
static gint ett_opensafety_ssdo_sacmd = -1;

static int hf_oss_msg = -1;
static int hf_oss_msgtype = -1;
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
static int hf_oss_ssdo_sacmd_reserved          = -1;
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
static gboolean global_mbtcp_big_endian = TRUE;
static guint global_network_udp_port = UDP_PORT_OPENSAFETY;
static guint global_network_udp_port_sercosiii = UDP_PORT_SIII;

/* Conversation functions */

/* This is defined by the specification. The Address field is 10 bits long, and the node with the number
 *  1 is always the SCM, therefore ( 2 ^ 10 ) - 1 nodes can be addressed. We use 2 ^ 10 here, because the
 *  SCM can talk to himself (Assign SADR for instance ) */
#define MAX_NUMBER_OF_SAFETY_NODES      ( 2 ^ 10 )

/* Tracks the information that the packet pinfo has been received by receiver, and adds that information to the tree, using pos, as
 * byte position in the PDU */
#define PACKET_RECEIVED_BY(pinfo, recv, pos)                       proto_tree_add_uint(opensafety_tree, hf_oss_msg_receiver, message_tvb, pos, 2, recv);

/* Tracks the information that the packet pinfo has been sent by sender, and received by receiver, and adds that information to
 * the tree, using pos for the sender and pos2 for the receiver, as byte position in the PDU */
#define PACKET_SEND_FROM_TO(pinfo, send, pos, recv, pos2)         proto_tree_add_uint(opensafety_tree, hf_oss_msg_sender, message_tvb, pos, 2, send); \
                                                                proto_tree_add_uint(opensafety_tree, hf_oss_msg_receiver, message_tvb, pos2, 2, recv);

/* Tracks the information that the packet pinfo has been sent by sender, and received by everyone else, and adds that information to
 * the tree, using pos, as byte position in the PDU */
#define PACKET_SEND_FROM_TO_ALL(pinfo, sender, pos)                proto_tree_add_uint(opensafety_tree, hf_oss_msg_sender, message_tvb, pos, 2, sender);

/* Helper Functions & Function Prototypes */

static guint8 opensafety_get_scm_udid(guint8 * scmUDID);
static guint16 findFrame1Position ( guint8 dataLength, guint8 byteStream[] );
static guint8 * unxorFrame(guint8 dataLength, guint8 byteStream[], guint16 startFrame1, guint16 startFrame2, guint8 scmUDID[]);

/*
 * @brief Calculates a CRC8 checksum for the given buffer
 * @param len the length of the given buffer
 * @param pBuffer a pointer to a buffer of the given length
 * @return the CRC8 checksum for the buffer
 */
static guint8 crc8_opensafety(guint32 len, guint8 * pBuffer, guint8 initCRC);

/*
 * @brief Calculates a CRC16 checksum for the given buffer
 * @param len the length of the given buffer
 * @param pBuffer a pointer to a buffer of the given length
 * @return the CRC16 checksum for the buffer
 */
static guint16 crc16_opensafety(guint32 len, guint8 * pBuffer, guint16 initCRC);

static guint stringToBytes( const char * string, guint8 * pBuffer, guint32 length );

static guint8 findSafetyFrame ( guint8 * pBuffer, guint32 length, guint u_Offset, guint *u_frameOffset, guint *u_frameLength );

static guint stringToBytes( const char * stringToBytes, guint8 * pBuffer, guint32 length )
{
    guint k;
    guint32 byte ;
    char * endptr ;
    char * str, * temp, * token;

    k = 0;

    str = ep_strdup(stringToBytes);
    token = strtok( str, ":" );
    temp = token;

    byte = strtol ( temp, &endptr, 16 );
    pBuffer[k] = byte;
    k++;

    for ( temp = token ; ; temp = NULL )
    {
        temp = strtok( NULL, ":" );
        if ( temp == NULL || ( k == length ) )
            break;
        byte = strtol ( temp, &endptr, 16 );
        pBuffer[k] = byte;
        k++;
    }

    return k;
}

static guint16
findFrame1PositionExtended ( guint8 dataLength, guint8 byteStream[], gboolean checkIfSlimMistake )
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
            calcCRC = crc16_opensafety(dataLength + 4, &byteStream[i_wFrame1Position], 0);
        else
            calcCRC = crc8_opensafety(dataLength + 4, &byteStream[i_wFrame1Position], 0);

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

static guint16
findFrame1Position ( guint8 dataLength, guint8 byteStream[] )
{
    /* To safe time, the normal search, does not take the possible mistake into consideration */
    return ( findFrame1PositionExtended(dataLength, byteStream, FALSE) );
}

/*
 * This function applies the given UDID to the bytestream, considering the start of frame 2
 */
static guint8 * unxorFrame(guint8 dataLength, guint8 byteStream[], guint16 frameStart1, guint16 frameStart2, guint8 scmUDID[])
{
    guint8 * pb_sendMemBlock;
    guint k;
    guint8 frame1Size;

    frame1Size = ( frameStart2 > frameStart1 ? frameStart2 : dataLength - frameStart1 );


    pb_sendMemBlock = (guint8*) ep_alloc0( sizeof(guint8) * dataLength);

    memcpy ( &pb_sendMemBlock[frameStart1], &byteStream[frameStart1], frame1Size );

    for ( k = 0; k < (guint)(dataLength - frame1Size); k++)
        pb_sendMemBlock [ k + frameStart2 ] = byteStream [ k + frameStart2 ] ^ scmUDID[ ( k % 6 ) ];

    return pb_sendMemBlock;
}

/* @brief Precompiled table for CRC8 values */
static const guint16 crc16_opensafety_precompiled[256] =
{
        0x0000, 0x5935, 0xB26A, 0xEB5F, 0x3DE1, 0x64D4, 0x8F8B, 0xD6BE,
        0x7BC2, 0x22F7, 0xC9A8, 0x909D, 0x4623, 0x1F16, 0xF449, 0xAD7C,
        0xF784, 0xAEB1, 0x45EE, 0x1CDB, 0xCA65, 0x9350, 0x780F, 0x213A,
        0x8C46, 0xD573, 0x3E2C, 0x6719, 0xB1A7, 0xE892, 0x03CD, 0x5AF8,
        0xB63D, 0xEF08, 0x0457, 0x5D62, 0x8BDC, 0xD2E9, 0x39B6, 0x6083,
        0xCDFF, 0x94CA, 0x7F95, 0x26A0, 0xF01E, 0xA92B, 0x4274, 0x1B41,
        0x41B9, 0x188C, 0xF3D3, 0xAAE6, 0x7C58, 0x256D, 0xCE32, 0x9707,
        0x3A7B, 0x634E, 0x8811, 0xD124, 0x079A, 0x5EAF, 0xB5F0, 0xECC5,
        0x354F, 0x6C7A, 0x8725, 0xDE10, 0x08AE, 0x519B, 0xBAC4, 0xE3F1,
        0x4E8D, 0x17B8, 0xFCE7, 0xA5D2, 0x736C, 0x2A59, 0xC106, 0x9833,
        0xC2CB, 0x9BFE, 0x70A1, 0x2994, 0xFF2A, 0xA61F, 0x4D40, 0x1475,
        0xB909, 0xE03C, 0x0B63, 0x5256, 0x84E8, 0xDDDD, 0x3682, 0x6FB7,
        0x8372, 0xDA47, 0x3118, 0x682D, 0xBE93, 0xE7A6, 0x0CF9, 0x55CC,
        0xF8B0, 0xA185, 0x4ADA, 0x13EF, 0xC551, 0x9C64, 0x773B, 0x2E0E,
        0x74F6, 0x2DC3, 0xC69C, 0x9FA9, 0x4917, 0x1022, 0xFB7D, 0xA248,
        0x0F34, 0x5601, 0xBD5E, 0xE46B, 0x32D5, 0x6BE0, 0x80BF, 0xD98A,
        0x6A9E, 0x33AB, 0xD8F4, 0x81C1, 0x577F, 0x0E4A, 0xE515, 0xBC20,
        0x115C, 0x4869, 0xA336, 0xFA03, 0x2CBD, 0x7588, 0x9ED7, 0xC7E2,
        0x9D1A, 0xC42F, 0x2F70, 0x7645, 0xA0FB, 0xF9CE, 0x1291, 0x4BA4,
        0xE6D8, 0xBFED, 0x54B2, 0x0D87, 0xDB39, 0x820C, 0x6953, 0x3066,
        0xDCA3, 0x8596, 0x6EC9, 0x37FC, 0xE142, 0xB877, 0x5328, 0x0A1D,
        0xA761, 0xFE54, 0x150B, 0x4C3E, 0x9A80, 0xC3B5, 0x28EA, 0x71DF,
        0x2B27, 0x7212, 0x994D, 0xC078, 0x16C6, 0x4FF3, 0xA4AC, 0xFD99,
        0x50E5, 0x09D0, 0xE28F, 0xBBBA, 0x6D04, 0x3431, 0xDF6E, 0x865B,
        0x5FD1, 0x06E4, 0xEDBB, 0xB48E, 0x6230, 0x3B05, 0xD05A, 0x896F,
        0x2413, 0x7D26, 0x9679, 0xCF4C, 0x19F2, 0x40C7, 0xAB98, 0xF2AD,
        0xA855, 0xF160, 0x1A3F, 0x430A, 0x95B4, 0xCC81, 0x27DE, 0x7EEB,
        0xD397, 0x8AA2, 0x61FD, 0x38C8, 0xEE76, 0xB743, 0x5C1C, 0x0529,
        0xE9EC, 0xB0D9, 0x5B86, 0x02B3, 0xD40D, 0x8D38, 0x6667, 0x3F52,
        0x922E, 0xCB1B, 0x2044, 0x7971, 0xAFCF, 0xF6FA, 0x1DA5, 0x4490,
        0x1E68, 0x475D, 0xAC02, 0xF537, 0x2389, 0x7ABC, 0x91E3, 0xC8D6,
        0x65AA, 0x3C9F, 0xD7C0, 0x8EF5, 0x584B, 0x017E, 0xEA21, 0xB314
};

/*
 * @brief Calculates a CRC16 checksum for the given buffer with the polynom
 *     x^16 + x^14 + x^12 + x^11 + x^8 + x^5 + x^4 + x^2 + 1
 * @param len the length of the given buffer
 * @param pBuffer a pointer to a buffer of the given length
 * @return the CRC16 checksum for the buffer
 */
static guint16 crc16_opensafety(guint32 len, guint8 * pBuffer, guint16 initCRC)
{
    guint16 crc;
    guint16 ulTab;

    crc = initCRC;
    while(len-- > 0)
    {
        ulTab = crc16_opensafety_precompiled[(*pBuffer++) ^ (crc >> 8)];
        crc = (crc << 8) ^ ulTab;
    }

    return crc;
}

/* @brief Precompiled table for CRC8 values */
static const guint8 crc8_opensafety_precompiled[256] =
{
        0x00, 0x2F, 0x5E, 0x71, 0xBC, 0x93, 0xE2, 0xCD,
        0x57, 0x78, 0x09, 0x26, 0xEB, 0xC4, 0xB5, 0x9A,
        0xAE, 0x81, 0xF0, 0xDF, 0x12, 0x3D, 0x4C, 0x63,
        0xF9, 0xD6, 0xA7, 0x88, 0x45, 0x6A, 0x1B, 0x34,
        0x73, 0x5C, 0x2D, 0x02, 0xCF, 0xE0, 0x91, 0xBE,
        0x24, 0x0B, 0x7A, 0x55, 0x98, 0xB7, 0xC6, 0xE9,
        0xDD, 0xF2, 0x83, 0xAC, 0x61, 0x4E, 0x3F, 0x10,
        0x8A, 0xA5, 0xD4, 0xFB, 0x36, 0x19, 0x68, 0x47,
        0xE6, 0xC9, 0xB8, 0x97, 0x5A, 0x75, 0x04, 0x2B,
        0xB1, 0x9E, 0xEF, 0xC0, 0x0D, 0x22, 0x53, 0x7C,
        0x48, 0x67, 0x16, 0x39, 0xF4, 0xDB, 0xAA, 0x85,
        0x1F, 0x30, 0x41, 0x6E, 0xA3, 0x8C, 0xFD, 0xD2,
        0x95, 0xBA, 0xCB, 0xE4, 0x29, 0x06, 0x77, 0x58,
        0xC2, 0xED, 0x9C, 0xB3, 0x7E, 0x51, 0x20, 0x0F,
        0x3B, 0x14, 0x65, 0x4A, 0x87, 0xA8, 0xD9, 0xF6,
        0x6C, 0x43, 0x32, 0x1D, 0xD0, 0xFF, 0x8E, 0xA1,
        0xE3, 0xCC, 0xBD, 0x92, 0x5F, 0x70, 0x01, 0x2E,
        0xB4, 0x9B, 0xEA, 0xC5, 0x08, 0x27, 0x56, 0x79,
        0x4D, 0x62, 0x13, 0x3C, 0xF1, 0xDE, 0xAF, 0x80,
        0x1A, 0x35, 0x44, 0x6B, 0xA6, 0x89, 0xF8, 0xD7,
        0x90, 0xBF, 0xCE, 0xE1, 0x2C, 0x03, 0x72, 0x5D,
        0xC7, 0xE8, 0x99, 0xB6, 0x7B, 0x54, 0x25, 0x0A,
        0x3E, 0x11, 0x60, 0x4F, 0x82, 0xAD, 0xDC, 0xF3,
        0x69, 0x46, 0x37, 0x18, 0xD5, 0xFA, 0x8B, 0xA4,
        0x05, 0x2A, 0x5B, 0x74, 0xB9, 0x96, 0xE7, 0xC8,
        0x52, 0x7D, 0x0C, 0x23, 0xEE, 0xC1, 0xB0, 0x9F,
        0xAB, 0x84, 0xF5, 0xDA, 0x17, 0x38, 0x49, 0x66,
        0xFC, 0xD3, 0xA2, 0x8D, 0x40, 0x6F, 0x1E, 0x31,
        0x76, 0x59, 0x28, 0x07, 0xCA, 0xE5, 0x94, 0xBB,
        0x21, 0x0E, 0x7F, 0x50, 0x9D, 0xB2, 0xC3, 0xEC,
        0xD8, 0xF7, 0x86, 0xA9, 0x64, 0x4B, 0x3A, 0x15,
        0x8F, 0xA0, 0xD1, 0xFE, 0x33, 0x1C, 0x6D, 0x42
};

/*
 * @brief Calculates a CRC8 checksum for the given buffer with the polynom
 *     x^8 + x^5 + x^3 + x^2 + x + 1
 * @param len the length of the given buffer
 * @param pBuffer a pointer to a buffer of the given length
 * @return the CRC8 checksum for the buffer
 */
static guint8 crc8_opensafety(guint32 len, guint8 * pBuffer, guint8 initCRC)
{
    guint8 crc;

    crc = initCRC;
    while(len-- > 0)
    {
        crc = (guint8)(*pBuffer++) ^ crc;
        crc = crc8_opensafety_precompiled[crc];
    }

    return crc;
}

static guint8 findSafetyFrame ( guint8 * pBuffer, guint32 length, guint u_Offset, guint *u_frameOffset, guint *u_frameLength )
{
    guint n;
    guint16 crc, calcCrc;
    guint8 b_ID, b_Length, crcOffset, leftShifted;
    gboolean found;

    found = 0;
    DISSECTOR_ASSERT ( u_Offset < ( u_Offset + length ) );
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
            /* If the determined size could be bigger, than the data to be dissect,
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
            crc = 0;
            calcCrc = 0;
            crc = pBuffer [ n + 3 + b_Length ];
            if ( b_Length > 8 ) {
                crc += ( ( pBuffer [ n + 4 + b_Length ] ) << 8 );
                crcOffset = 1;
                if ( crc != 0x00 )
                    calcCrc = crc16_opensafety ( b_Length + 4, &pBuffer [ n - 1 ], 0 );
            } else {
                if ( crc != 0x00 )
                    calcCrc = crc8_opensafety ( b_Length + 4, &pBuffer [ n - 1 ], 0 );
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

    return (found ? 1 : 0);
}

static void
dissect_opensafety_spdo_message(tvbuff_t *message_tvb,  proto_tree *opensafety_tree,
        guint8 * bytes, guint16 frameStart1, guint16 frameStart2 , gboolean validSCMUDID)
{
    proto_item *item;
    proto_tree *spdo_tree;
    guint16 ct, taddr;
    guint dataLength;
    guint8 tr, b_ID;

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + frameStart1);
    b_ID = ( bytes[frameStart1 + 1] >> 3 ) << 3;

    ct = bytes[frameStart1 + 2];
    if ( validSCMUDID )
        ct = (guint16)(bytes[frameStart2 + 2] << 8) + (bytes[frameStart1 + 2]);

    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR(bytes, frameStart2 + 3);
    tr = ( bytes[frameStart2 + 4] << 2 ) >> 2;

    /* An SPDO get's always send by the producer, to everybody else */
    PACKET_SEND_FROM_TO_ALL( pinfo, OSS_FRAME_ADDR(bytes, frameStart1), OSS_FRAME_POS_ADDR + frameStart1 );

    if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE )
        proto_tree_add_boolean(opensafety_tree, hf_oss_msgtype, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST || b_ID == OPENSAFETY_MSG_SPDO_DATA_ONLY )
        proto_tree_add_boolean(opensafety_tree, hf_oss_msgtype, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
            b_ID, "%s", val_to_str(b_ID, message_type_values, "Unknown") );

    spdo_tree = proto_item_add_subtree(item, ett_opensafety_ssdo);

    proto_tree_add_uint(spdo_tree, hf_oss_spdo_producer, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));

    if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST )
    {
        item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_time_value_sn, message_tvb, 0, 0, ct,
                "0x%04X [%d] (%s)", ct, ct, (validSCMUDID ? "Complete" : "Low byte only"));
        PROTO_ITEM_SET_GENERATED(item);

        proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request, message_tvb, OSS_FRAME_POS_ADDR + frameStart2 + 4, 1, tr);
        proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request_from, message_tvb, OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
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

    isRequest = FALSE;
    if ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SERVICE_REQUEST || OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST )
        isRequest = TRUE;

    if ( validSCMUDID )
    {
        /* taddr is the 4th octet in the second frame */
        taddr = OSS_FRAME_ADDR(bytes, frameStart2 + 3);

        PACKET_SEND_FROM_TO( pinfo, OSS_FRAME_ADDR(bytes, frameStart1), frameStart1, taddr, frameStart2 + 3);
    }
    else if ( ! isRequest )
    {
        PACKET_RECEIVED_BY(pinfo, OSS_FRAME_ADDR(bytes, frameStart1), frameStart1 );
    }

    if ( ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SERVICE_RESPONSE ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) )
        proto_tree_add_boolean(opensafety_tree, hf_oss_msgtype, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else
        proto_tree_add_boolean(opensafety_tree, hf_oss_msgtype, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
            OSS_FRAME_ID(bytes, frameStart1), "%s", val_to_str(OSS_FRAME_ID(bytes, frameStart1), message_type_values, "Unknown") );

    ssdo_tree = proto_item_add_subtree(item, ett_opensafety_ssdo);

    if ( isRequest )
    {
        if ( validSCMUDID )
        {
            item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
            item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else
        {
            item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
        }
    }
    else if ( ! isRequest )
    {
        if ( validSCMUDID )
        {
            item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
            item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else
        {
            item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart1, 2, OSS_FRAME_ADDR(bytes, frameStart1));
        }
    }

    item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sacmd, message_tvb, db0Offset, 1, sacmd);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", SACMD: %s", val_to_str(sacmd, ssdo_sacmd_values, " "));

    ssdo_sacmd_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sacmd);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_block_transfer, message_tvb, db0Offset, 1, db0);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_end_segment, message_tvb, db0Offset, 1, db0);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_initiate, message_tvb, db0Offset, 1, db0);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_toggle, message_tvb, db0Offset, 1, db0);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_segmentation, message_tvb, db0Offset, 1, db0);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_abort_transfer, message_tvb, db0Offset, 1, db0);
    item = proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_access_type, message_tvb, db0Offset, 1, db0);

    if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM) == 0 )
    {
        item = proto_tree_add_uint(ssdo_tree, hf_oss_snmt_master, message_tvb, frameStart1 + OSS_FRAME_POS_ADDR, 2, OSS_FRAME_ADDR(bytes, frameStart1));
        if ( validSCMUDID )
            item = proto_tree_add_uint(ssdo_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + OSS_FRAME_POS_ADDR + 2, 2, taddr);
    }

    payloadOffset = db0Offset + 1;
    /* When the following clause is met, DB1,2 contain the SOD index, and DB3 the SOD subindex */
    if ( ( ( sacmd & OPENSAFETY_SSDO_SACMD_INI ) == OPENSAFETY_SSDO_SACMD_INI ) ||
            ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE ) ||
            ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END ) ||
            ( sacmd == OPENSAFETY_MSG_SSDO_ABORT )
    )
    {
        item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sod_index, message_tvb, db0Offset + 1, 2,
                ((guint16)(bytes[db0Offset + 2] << 8) + bytes[db0Offset + 1]));
        item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sod_subindex, message_tvb, db0Offset + 3, 1, bytes[db0Offset + 3]);
        payloadOffset += 3;
    }

    if ( sacmd == OPENSAFETY_MSG_SSDO_ABORT )
    {
        abortcode = 0;
        for ( n = 0; n < 4; n++ )
            abortcode += ( bytes[frameStart1 + OSS_FRAME_POS_DATA + 4 + n] ) << (8 * n);

        item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_abort_code, message_tvb, payloadOffset, 4, abortcode,
                "0x%04X %04X - %s", (guint16)(abortcode >> 16), (guint16)(abortcode),
                val_to_str(abortcode, abort_codes, "Unknown"));


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
            payload = (guint8*)ep_alloc(sizeof(guint8*)*payloadSize);
            for ( n = 0; n < payloadSize; n++)
                payload[payloadSize - n - 1] = bytes[frameStart1 + OSS_FRAME_POS_DATA + (payloadOffset - db0Offset) + n];

            /* reading real size */
            payloadSize = 0;
            for ( n = 0; n < 4; n++ )
            {
                payloadSize += ( bytes[frameStart1 + OSS_FRAME_POS_DATA + 4 + n] ) << (8 * n);
            }


            item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, payloadOffset - 4, 4,
                    payloadSize, "%d octets total (%d octets in this frame)", payloadSize, dataLength - (payloadOffset - db0Offset));
            item = proto_tree_add_bytes(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset,
                    dataLength - (payloadOffset - db0Offset), payload );
        }
        else
        {
            payloadSize = dataLength - (payloadOffset - db0Offset);
            payload = (guint8*)ep_alloc(sizeof(guint8*)*payloadSize);
            for ( n = 0; n < payloadSize; n++)
                payload[payloadSize - n - 1] = bytes[frameStart1 + OSS_FRAME_POS_DATA + (payloadOffset - db0Offset) + n];

            item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, 0, 0, payloadSize,
                    "%d octets", payloadSize);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_bytes(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset, payloadSize, payload );

        }
    }
}

static void
dissect_opensafety_snmt_message(tvbuff_t *message_tvb, packet_info *pinfo , proto_tree *opensafety_tree,
        guint8 * bytes, guint16 frameStart1, guint16 frameStart2 )
{
    proto_item *item;
    proto_tree *snmt_tree ;
    guint16 addr, taddr;
    guint8 db0;
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
        PACKET_RECEIVED_BY( pinfo, addr, OSS_FRAME_POS_ADDR + frameStart1 );
    }
    else
    {
        PACKET_SEND_FROM_TO ( pinfo, taddr, frameStart2 + 3, addr, OSS_FRAME_POS_ADDR + frameStart1 );
    }

    if ( ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SNMT_RESPONSE_UDID ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SNMT_SADR_ASSIGNED ) ||
         ( OSS_FRAME_ID(bytes, frameStart1) == OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE ) )
        proto_tree_add_boolean(opensafety_tree, hf_oss_msgtype, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else
        proto_tree_add_boolean(opensafety_tree, hf_oss_msgtype, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
            OSS_FRAME_ID(bytes, frameStart1), "%s", val_to_str(OSS_FRAME_ID(bytes, frameStart1), message_type_values, "Unknown") );

    snmt_tree = proto_item_add_subtree(item, ett_opensafety_snmt);

    if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1, db0);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(db0, message_service_type, " "));

        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 )
        {
            item = proto_tree_add_item(snmt_tree, hf_oss_snmt_error_group, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 1, FALSE);
            item = proto_tree_add_item(snmt_tree, hf_oss_snmt_error_code, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 2, 1, FALSE);
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM) == 0 )
        {
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1,
                    6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6));
        }

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_REQUEST) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1, db0);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(db0, message_service_type, " "));

        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 || (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 )
        {
            item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_scm, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_tool, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM) == 0 )
        {
            item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1,
                    6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6));
        }
        else
        {
            item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
            if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP) == 0 )
            {
                item = proto_tree_add_bytes(snmt_tree, hf_oss_snmt_timestamp, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 4,
                                (bytes + frameStart1 + OSS_FRAME_POS_DATA + 1));
            }
        }
    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_SADR_ASSIGNED) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb,
                    OSS_FRAME_POS_DATA + frameStart1, 6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6));

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_ASSIGN_SADR) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb,
                    OSS_FRAME_POS_DATA + frameStart1, 6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6));

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_RESPONSE_UDID) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_ether(snmt_tree, hf_oss_snmt_udid, message_tvb,
                    OSS_FRAME_POS_DATA + frameStart1, 6, tvb_get_ptr(message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6));

    }
    else if ( (OSS_FRAME_ID(bytes, frameStart1) ^ OPENSAFETY_MSG_SNMT_REQUEST_UDID) == 0 )
    {
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        item = proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);
    }

}

static guint8 opensafety_get_scm_udid(guint8 * scmUDID )
{
    if ( strlen(global_scm_udid) != (2*6 + 5) )
        return 0;

    return stringToBytes(global_scm_udid, scmUDID, 6);
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
        calcCrc = crc16_opensafety(dataLength + 4, &bytes[frameStart1], 0);
    else
        calcCrc = crc8_opensafety(dataLength + 4, &bytes[frameStart1], 0);

    item = proto_tree_add_boolean(checksum_tree, hf_oss_crc_valid, message_tvb, start, length, (frameCrc == calcCrc));
    PROTO_ITEM_SET_GENERATED(item);
    /* using the defines, as the values can change */
    item = proto_tree_add_uint(checksum_tree, hf_oss_crc_type, message_tvb, start, length,
            ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OPENSAFETY_CHECKSUM_CRC16 : OPENSAFETY_CHECKSUM_CRC8 ) );

}

static gboolean
dissect_opensafety_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree, gboolean b_frame2First, guint8 u_nrInPackage)
{
    guint8 type, b_ID;
    guint length;
    guint16 frameStart1, frameStart2;
    guint8 * bytes, *scmUDID;
    gboolean validSCMUDID;
    proto_item * item;

    length = tvb_length(message_tvb);

    bytes = (guint8 *)ep_tvb_memdup(message_tvb, 0, length);

    if ( b_frame2First )
    {
        frameStart1 = findFrame1Position (length, bytes );
        frameStart2 = 0;
    }
    else
    {
        frameStart1 = 0;
        frameStart2 = ((OSS_FRAME_LENGTH(bytes, frameStart1) - 1) +
                (OSS_FRAME_LENGTH(bytes, frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OSS_SLIM_FRAME2_WITH_CRC16 : OSS_SLIM_FRAME2_WITH_CRC8));
    }

    if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
        type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
    else if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
        type = OPENSAFETY_SSDO_MESSAGE_TYPE;
    else if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
        type = OPENSAFETY_SPDO_MESSAGE_TYPE;
    else if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
        type = OPENSAFETY_SNMT_MESSAGE_TYPE;
    else
    {
        /* This is an invalid openSAFETY package, but it could be an undetected slim ssdo message. This specific error
         * will only occur, if findFrame1Position is in play. So we search once more, but this time calculating the CRC.
         * The reason for the second run is, that calculating the CRC is time consuming.  */
        if ( b_frame2First )
        {
            /* Now let's check again, but this time calculate the CRC */
            frameStart1 = findFrame1PositionExtended(length, bytes, TRUE );
            frameStart2 = 0;

            if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SSDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                type = OPENSAFETY_SPDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID(bytes, frameStart1) & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                type = OPENSAFETY_SNMT_MESSAGE_TYPE;
            else
                return FALSE;
        } else
            return FALSE;
    }

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
            validSCMUDID = TRUE;
            dissect_opensafety_snmt_message ( message_tvb, pinfo, opensafety_tree, bytes, frameStart1, frameStart2 );
        }
        else
        {
            validSCMUDID = FALSE;
            scmUDID = (guint8*)g_malloc(sizeof(guint8)*6);
            memset(scmUDID, 0, 6);
            if ( opensafety_get_scm_udid(scmUDID) == 6 )
            {
                validSCMUDID = TRUE;
                bytes = unxorFrame(length, bytes, frameStart1, frameStart2, scmUDID);
                /* Now confirm, that the xor operation was successful
                 *  The ID fields of both frames have to be the same, otherwise
                 *  perform the xor again to revert the change
                 */
                if ( ( OSS_FRAME_ID(bytes, frameStart1) ^ OSS_FRAME_ID(bytes, frameStart2 ) ) != 0 )
                {
                    validSCMUDID = FALSE;
                    bytes = unxorFrame(length, bytes, frameStart1, frameStart2, scmUDID);
                }
            }
            g_free ( scmUDID );

            item = proto_tree_add_string(opensafety_tree, hf_oss_scm_udid, message_tvb, 0, 0, global_scm_udid);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_boolean(opensafety_tree, hf_oss_scm_udid_valid, message_tvb, 0, 0, validSCMUDID);
            PROTO_ITEM_SET_GENERATED(item);

            if ( type == OPENSAFETY_SSDO_MESSAGE_TYPE || type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
            {
                dissect_opensafety_ssdo_message ( message_tvb, pinfo, opensafety_tree, bytes, frameStart1, frameStart2, validSCMUDID );
            }
            else if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                dissect_opensafety_spdo_message ( message_tvb, opensafety_tree, bytes, frameStart1, frameStart2, validSCMUDID );
            }
        }

        proto_tree_add_uint(opensafety_tree, hf_oss_length, message_tvb, OSS_FRAME_POS_LEN + frameStart1, 1, OSS_FRAME_LENGTH(bytes, frameStart1));

        dissect_opensafety_checksum ( message_tvb, opensafety_tree, bytes, frameStart1 );
    }

    return TRUE;
}

static gboolean
dissect_opensafety_frame(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, gboolean b_frame2First, guint8 u_nrInPackage)
{
    proto_item *opensafety_item;
    proto_tree *opensafety_tree;

    /* if the tree is NULL, we are called for the overview, otherwise for the
     more detailed view of the package */
    if (tree) {
        /* create the opensafety protocol tree */
        opensafety_item = proto_tree_add_item(tree, proto_opensafety, message_tvb, 0, -1, FALSE);
        opensafety_tree = proto_item_add_subtree(opensafety_item, ett_opensafety);
    } else {
        opensafety_tree = NULL;
    };

    /* dissect the message */
    return dissect_opensafety_message(message_tvb, pinfo, opensafety_tree, b_frame2First, u_nrInPackage);
}

static gboolean
dissect_opensafety(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
    /* pinfo is NULL only if dissect_opensafety_message is called from dissect_error cause */
    if (pinfo)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL,
                (pinfo->destport == UDP_PORT_SIII ? "openSAFETY/SercosIII" : "openSAFETY" )
                );
        col_clear(pinfo->cinfo,COL_INFO);
    }

    /* dissect the message, we are called using UDP SHNF, therefore Frame2 allways comes first */
    return dissect_opensafety_frame(message_tvb, pinfo, tree, TRUE, 1);
}

static gboolean
dissect_opensafety_epl(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    tvbuff_t *next_tvb;
    guint length, frameOffset, frameLength;
    guint8 *bytes;
    gboolean handled, dissectorCalled;
    guint8 firstByte, found;
    gint len, reported_len;
    dissector_handle_t epl_handle;
    guint8 packageCounter;
    handled = FALSE;
    dissectorCalled = FALSE;

    epl_handle = find_dissector("epl");
    if ( epl_handle == NULL )
        epl_handle = find_dissector("data");

    firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );
    /* No frames can be sent in SoA and SoC messages, therefore those get filtered right away */
    if ( firstByte == 0x02 || firstByte == 0x0A )
    {
        call_dissector(epl_handle, message_tvb, pinfo, tree);
        return TRUE;
    }

    len = tvb_length_remaining(message_tvb, 0);
    reported_len = tvb_reported_length_remaining(message_tvb, 0);
    length = tvb_length(message_tvb);
    bytes = (guint8 *) ep_tvb_memdup(message_tvb, 0, length);

    frameOffset = 0;
    frameLength = 0;
    found = 0;
    packageCounter = 0;
    while ( frameOffset < length )
    {
        if ( findSafetyFrame(bytes, length - frameOffset, frameOffset, &frameOffset, &frameLength) )
        {
            if ((frameOffset + frameLength) > (guint)reported_len )
                break;
            found++;

            /* Freeing memory before dissector, as otherwise we would waste it */
            next_tvb = tvb_new_subset(message_tvb, frameOffset, frameLength, reported_len);
            /* Adding a visual aid to the dissector tree */
            add_new_data_source(pinfo, next_tvb, "openSAFETY Frame");

            if ( ! dissectorCalled )
            {
                call_dissector(epl_handle, message_tvb, pinfo, tree);
                dissectorCalled = TRUE;

                /* pinfo is NULL only if dissect_opensafety_message is called from dissect_error cause */
                if (pinfo)
                {
                    col_set_str(pinfo->cinfo, COL_PROTOCOL, "openSAFETY/Powerlink");
                    col_clear(pinfo->cinfo,COL_INFO);
                }
            }

            /* Only engage, if we are not called strictly for the overview */
            if ( tree )
            {
                if ( dissect_opensafety_frame(next_tvb, pinfo, tree, FALSE, found) == TRUE )
                    packageCounter++;
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
        call_dissector(epl_handle, message_tvb, pinfo, tree);
        handled = TRUE;
    }
    return ( handled ? TRUE : FALSE );
}

static gboolean
dissect_heur_opensafety_epl(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    guint32 constData;

    constData = 0x0;
    if ( pinfo->private_data != NULL )
        memcpy(&constData, pinfo->private_data, sizeof(guint32));

    /* We will call the epl dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( pinfo->private_data == NULL || ( constData != OPENSAFETY_PINFO_CONST_DATA ) )
    {
        constData = OPENSAFETY_PINFO_CONST_DATA;
        pinfo->private_data = (void*)ep_alloc(sizeof(guint32));
        memcpy(pinfo->private_data, &constData, sizeof(guint32));
        return dissect_opensafety_epl(message_tvb, pinfo, tree );
    }

    return FALSE;
}

static gboolean
dissect_opensafety_siii(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    tvbuff_t *next_tvb;
    guint length, frameOffset, frameLength;
    guint8 *bytes;
    gboolean handled, dissectorCalled, udpDissectorCalled;
    guint8 firstByte, found;
    gint len, reported_len;
    dissector_handle_t siii_handle;
    guint8 packageCounter = 0;
    gboolean internSIIIHandling;

    handled = FALSE;
    dissectorCalled = FALSE;
    udpDissectorCalled = FALSE;
    internSIIIHandling = FALSE;

    siii_handle = find_dissector("sercosiii");
    if ( siii_handle == NULL )
    {
        siii_handle = find_dissector("data");
        /* We can handle the packages internally, if there is no sercos iii plugin available */
        if ( pinfo->ethertype == ETHERTYPE_SERCOS )
            internSIIIHandling = TRUE;
    }

    if ( tree && internSIIIHandling )
    {
        proto_tree_add_text(tree,message_tvb, 0, -1, "SercosIII dissector not available, openSAFETY/SercosIII native dissection.");
    }

    /* We have a SERCOS III package, whether encapsulated in UDP or
       directly atop Ethernet */
    firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );
    /* No frames can be sent in AT messages, therefore those get filtered right away */
    if ( ( (!firstByte) & 0x40 ) == 0x40 )
    {
        if ( pinfo->ipproto != IPPROTO_UDP )
             call_dissector(siii_handle, message_tvb, pinfo, tree);
        return TRUE;
    }

    len = tvb_length_remaining(message_tvb, 0);
    reported_len = tvb_reported_length_remaining(message_tvb, 0);
    length = tvb_length(message_tvb);
    bytes = (guint8 *) ep_tvb_memdup(message_tvb, 0, length);

    frameOffset = 0;
    frameLength = 0;
    found = 0;
    while ( frameOffset < length )
    {
        if ( findSafetyFrame(bytes, length - frameOffset, frameOffset, &frameOffset, &frameLength) )
        {
            if ((frameOffset + frameLength) > (guint)reported_len )
                break;
            found++;

            /* Freeing memory before dissector, as otherwise we would waste it */
            next_tvb = tvb_new_subset(message_tvb, frameOffset, frameLength, reported_len);
            /* Adding a visual aid to the dissector tree */
            add_new_data_source(pinfo, next_tvb, "openSAFETY Frame");

            /* pinfo is NULL only if dissect_opensafety_message is called from dissect_error cause */
            if ( ( ! udpDissectorCalled ) && ( pinfo->ipproto == IPPROTO_UDP ) && pinfo )
            {
                 col_set_str(pinfo->cinfo, COL_PROTOCOL,
                         ( pinfo->ipproto != IPPROTO_UDP ? "openSAFETY/SercosIII" : "openSAFETY/SercosIII UDP" ) );
                   col_clear(pinfo->cinfo,COL_INFO);
                   udpDissectorCalled = TRUE;
            }

            /* Call the dissector */
            if ( ( ! dissectorCalled ) && ( pinfo->ipproto != IPPROTO_UDP ) )
            {
                if ( ! internSIIIHandling )
                call_dissector(siii_handle, message_tvb, pinfo, tree);
                dissectorCalled = TRUE;

                /* pinfo is NULL only if dissect_opensafety_message is called from dissect_error cause */
                if (pinfo)
                {
                    col_set_str(pinfo->cinfo, COL_PROTOCOL, "openSAFETY/SercosIII");
                    col_clear(pinfo->cinfo,COL_INFO);
                }
            }

            /* Only engage, if we are not called strictly for the overview */
            if ( tree )
            {
                if ( dissect_opensafety_frame(next_tvb, pinfo, tree, FALSE, found) == TRUE )
                    packageCounter++;
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
        if ( pinfo->ipproto != IPPROTO_UDP )
            call_dissector(siii_handle, message_tvb, pinfo, tree);
        handled = TRUE;
    }
    return ( handled ? TRUE : FALSE );
}

static gboolean
dissect_heur_opensafety_siii(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    guint32 constData;
    guint8 firstByte;

    /* We can assume to have a SercosIII package, as the SercosIII dissector won't detect
     * SercosIII-UDP packages, this is most likely SercosIII-over-ethernet */

    /* No frames can be sent in AT messages, therefore those get filtered right away */
    firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );
    if ( ( (!firstByte) & 0x40 ) == 0x40 )
        return FALSE;

    constData = 0x0;
    if ( pinfo->private_data != NULL )
        memcpy(&constData, pinfo->private_data, sizeof(guint32));

    /* We will call the SercosIII dissector by using call_dissector(). The SercosIII dissector will
     * then call the heuristic openSAFETY dissector again. By setting this information, we prevent
     * a dissector loop */
    if ( pinfo->private_data == NULL || ( constData != OPENSAFETY_PINFO_CONST_DATA ) )
    {
        constData = OPENSAFETY_PINFO_CONST_DATA;
        pinfo->private_data = (void*)ep_alloc(sizeof(guint32));
        memcpy(pinfo->private_data, &constData, sizeof(guint32));
        return dissect_opensafety_siii(message_tvb, pinfo, tree);
    }

    return FALSE;
}

static gboolean
dissect_opensafety_mbtcp(tvbuff_t *message_tvb , packet_info *pinfo , proto_tree *tree )
{
    tvbuff_t *next_tvb;
    guint length, frameOffset, frameLength;
    guint8 *bytes;
    gboolean handled, dissectorCalled;
    guint8 found, packageCounter, i, tempByte;
    gint len, reported_len;

    length = tvb_length(message_tvb);
    /* Minimum package length is 11 */
    if ( length < 11 )
        return FALSE;

    handled = FALSE;
    dissectorCalled = FALSE;

    bytes = (guint8 *) ep_tvb_memdup(message_tvb, 0, length);

    if ( global_mbtcp_big_endian == TRUE )
    {
        /* Wordswapping for modbus detection */
        /* Only a even number of bytes can be swapped */
        len = (length / 2);
        for ( i = 0; i < len; i++ )
        {
            tempByte = bytes [ 2 * i ]; bytes [ 2 * i ] = bytes [ 2 * i + 1 ]; bytes [ 2 * i + 1 ] = tempByte;
        }
    }
    len = tvb_length_remaining(message_tvb, 0);
    reported_len = tvb_reported_length_remaining(message_tvb, 0);

    frameOffset = 0;
    frameLength = 0;
    found = 0;
    packageCounter = 0;
    while ( frameOffset < length )
    {
        if ( findSafetyFrame(bytes, length - frameOffset, frameOffset, &frameOffset, &frameLength) )
        {
            if ((frameOffset + frameLength) > (guint)reported_len )
                break;

            found++;

            /* Freeing memory before dissector, as otherwise we would waste it */
            if ( global_mbtcp_big_endian == TRUE )
            {
                next_tvb = tvb_new_real_data(&bytes[frameOffset], (frameLength), reported_len);
                tvb_set_child_real_data_tvbuff(message_tvb, next_tvb);
                add_new_data_source(pinfo, next_tvb, "openSAFETY Frame (Swapped)");
            }
            else
            {
                next_tvb = tvb_new_subset(message_tvb, frameOffset, frameLength, reported_len);
                add_new_data_source(pinfo, next_tvb, "openSAFETY Frame");
            }

            if ( ! dissectorCalled )
            {
                dissectorCalled = TRUE;

                /* pinfo is NULL only if dissect_opensafety_message is called from dissect_error cause */
                if (pinfo)
                {
                    col_set_str(pinfo->cinfo, COL_PROTOCOL, "openSAFETY over Modbus");
                    col_clear(pinfo->cinfo,COL_INFO);
                }
            }

            /* Only engage, if we are not called strictly for the overview */
            if ( tree )
            {
                if ( dissect_opensafety_frame(next_tvb, pinfo, tree, FALSE, found ) == TRUE )
                    packageCounter++;
            }
            handled = TRUE;
        }
        else
            break;

        frameOffset += frameLength;
    }

    if ( handled == TRUE && packageCounter == 0 )
        handled = FALSE;

    return ( handled ? TRUE : FALSE );
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
        dissector_delete_uint ("udp.port", opensafety_udp_port_number, find_dissector("opensafety"));
        dissector_delete_uint ("udp.port", opensafety_udp_siii_port_number, find_dissector("opensafety_siii"));
    }

    opensafety_init = TRUE;

    /* Storing the port numbers locally, to being able to delete the old associations */
    opensafety_udp_port_number = global_network_udp_port;
    opensafety_udp_siii_port_number = global_network_udp_port_sercosiii;

    /* Default UDP only based dissector */
    dissector_add_uint("udp.port", opensafety_udp_port_number, find_dissector("opensafety"));

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

            { &hf_oss_scm_udid,     { "SCM UDID Configured",    "opensafety.scm_udid",     FT_STRING,   BASE_NONE, NULL,   0x0, NULL, HFILL } },
            { &hf_oss_scm_udid_valid,     { "SCM UDID Valid",    "opensafety.scm_udid_valid",     FT_BOOLEAN,   BASE_NONE, NULL,   0x0, NULL, HFILL } },

            { &hf_oss_msg,     { "Message",    "opensafety.msg.id",     FT_UINT8,   BASE_HEX, VALS(message_type_values),   0x0, NULL, HFILL } },
            { &hf_oss_msgtype, { "Type",  "opensafety.msg.type", FT_BOOLEAN,   BASE_NONE, TFS(&opensafety_message_type),   0x0, NULL, HFILL } },
            { &hf_oss_msg_sender, { "Sender",  "opensafety.msg.sender", FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
            { &hf_oss_msg_receiver, { "Receiver",  "opensafety.msg.receiver", FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
            { &hf_oss_length,  { "Length",    "opensafety.length",  FT_UINT8,   BASE_DEC, NULL,     0x0, NULL, HFILL } },
            { &hf_oss_data,    { "Data",      "opensafety.data",    FT_BYTES,   BASE_NONE, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_crc,     { "CRC",       "opensafety.crc.data",     FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

            { &hf_oss_crc_valid,   { "Is Valid", "opensafety.crc.valid", FT_BOOLEAN, BASE_NONE, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_crc_type,    { "CRC Type",  "opensafety.crc.type",  FT_UINT8,   BASE_DEC, VALS(message_crc_type),    0x0, NULL, HFILL } },

            /* SNMT Specific fields */
            { &hf_oss_snmt_slave,  { "SNMT Slave",    "opensafety.snmt.slave", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_master, { "SNMT Master",   "opensafety.snmt.master", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_scm,  { "SCM",    "opensafety.snmt.scm", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_tool, { "Tool ID",   "opensafety.snmt.tool_id", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_udid,   { "UDID for SN",   "opensafety.snmt.udid", FT_ETHER,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_timestamp,   { "Parameter Timestamp",   "opensafety.snmt.timestamp", FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_service_id,   { "Extended Service ID",   "opensafety.snmt.service_id", FT_UINT8,  BASE_HEX, VALS(message_service_type),    0x0, NULL, HFILL } },
            { &hf_oss_snmt_error_group,   { "Error Group",   "opensafety.snmt.error_group", FT_UINT8,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_snmt_error_code,   { "Error Code",   "opensafety.snmt.error_code", FT_UINT8,  BASE_DEC, NULL,   0x0, NULL, HFILL } },

            /* SSDO Specific fields */
            { &hf_oss_ssdo_server, { "SSDO Server", "opensafety.ssdo.master", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_oss_ssdo_client, { "SSDO Client", "opensafety.ssdo.client", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
            { &hf_oss_ssdo_sano, { "SOD Access Request Number", "opensafety.ssdo.sano", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd, { "SOD Access Command", "opensafety.ssdo.sacmd", FT_UINT8,  BASE_HEX, VALS(ssdo_sacmd_values),    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_sod_index, { "SOD Index", "opensafety.ssdo.sod_index", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_sod_subindex, { "SOD Sub Index", "opensafety.ssdo.sod_subindex", FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_payload, { "SOD Payload", "opensafety.ssdo.payload", FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_payload_size, { "SOD Payload Size", "opensafety.ssdo.payloadsize", FT_UINT32,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_segment_size, { "SOD Segment Size", "opensafety.ssdo.segmentsize", FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_inhibit_time, { "Inhibit Time", "opensafety.ssdo.inhibittime", FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_ssdo_abort_code, { "Abort Code", "opensafety.ssdo.abortcode", FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

            /* SSDO SACmd specific fields */
            { &hf_oss_ssdo_sacmd_access_type, { "Access Type", "opensafety.ssdo.sacmd.access", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_acc), OPENSAFETY_SSDO_SACMD_ACC, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_reserved, { "Reserved", "opensafety.ssdo.sacmd.reserved", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_res), OPENSAFETY_SSDO_SACMD_RES, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_abort_transfer, { "Abort Transfer", "opensafety.ssdo.sacmd.abort_transfer", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_abrt), OPENSAFETY_SSDO_SACMD_ABRT, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_segmentation, { "Segmentation", "opensafety.ssdo.sacmd.segmentation", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_seg), OPENSAFETY_SSDO_SACMD_SEG, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_toggle, { "Toggle Bit", "opensafety.ssdo.sacmd.toggle", FT_BOOLEAN,  8, TFS(&opensafety_on_off), OPENSAFETY_SSDO_SACMD_TGL, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_initiate, { "Initiate Transfer", "opensafety.ssdo.sacmd.initiate", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_ini), OPENSAFETY_SSDO_SACMD_INI, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_end_segment, { "End Segment", "opensafety.ssdo.sacmd.end_segment", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_ensg), OPENSAFETY_SSDO_SACMD_ENSG, NULL, HFILL } },
            { &hf_oss_ssdo_sacmd_block_transfer, { "Block Transfer", "opensafety.ssdo.sacmd.block_transfer", FT_BOOLEAN,  8, TFS(&opensafety_sacmd_blk), OPENSAFETY_SSDO_SACMD_BLK, NULL, HFILL } },

            /* SPDO Specific fields */
            { &hf_oss_spdo_connection_valid, { "Connection Valid Bit", "opensafety.spdo.connection_valid", FT_BOOLEAN,  8, TFS(&opensafety_set_notset),  0x0, NULL, HFILL } },
            { &hf_oss_spdo_payload, { "SPDO Payload", "opensafety.spdo.payload", FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_spdo_producer, { "Producer", "opensafety.spdo.producer", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_spdo_producer_time, { "Internal Time Producer", "opensafety.spdo.time.producer", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_spdo_time_value_sn, { "Internal Time SN", "opensafety.spdo.time.sn", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_spdo_time_request, { "Time Request Counter", "opensafety.spdo.time.request_counter", FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_spdo_time_request_to, { "Time Request from", "opensafety.spdo.time.request_from", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
            { &hf_oss_spdo_time_request_from, { "Time Request by", "opensafety.spdo.time.request_to", FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
            &ett_opensafety,
            &ett_opensafety_checksum,
            &ett_opensafety_snmt,
            &ett_opensafety_ssdo,
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
                "UDP Port used for the UDP demo ",
                "UDP port used by UDP demo implementation to transport asynchronous data", 10,
                &global_network_udp_port);
    prefs_register_uint_preference(opensafety_module, "network_udp_port_sercosiii",
                "UDP Port used for SercosIII",
                "UDP port used by SercosIII to transport asynchronous data", 10,
                &global_network_udp_port_sercosiii);
    prefs_register_bool_preference(opensafety_module, "mbtcp_big_endian",
                "Modbus/TCP Big Endian Word Coding",
                "Modbus/TCP words can be transmissioned either big- or little endian. Default will be little endian",
                &global_mbtcp_big_endian);

    /* Registering default and ModBus/TCP dissector */
    new_register_dissector("opensafety", dissect_opensafety, proto_opensafety );
    new_register_dissector("opensafety_mbtcp", dissect_opensafety_mbtcp, proto_opensafety );
    new_register_dissector("opensafety_siii", dissect_opensafety_siii, proto_opensafety);

}

void
proto_reg_handoff_opensafety(void)
{
    static int opensafety_inited = FALSE;

    if ( !opensafety_inited )
    {
        heur_dissector_add("epl", dissect_heur_opensafety_epl, proto_opensafety);

        /* For SercosIII we have to register as a heuristic dissector, as SercosIII
         *  is implemented as a plugin, and therefore the heuristic dissector is not
         *  added by the time this method is being called
         */
        if ( find_dissector("sercosiii") != NULL )
        {
            heur_dissector_add("sercosiii", dissect_heur_opensafety_siii, proto_opensafety);
        }
        else
        {
            /* The native dissector cannot be loaded. so we add our protocol directly to
             * the ethernet subdissector list. No SercosIII specific data will be dissected
             * and a warning will be displayed, recognizing the missing dissector plugin.
             */
			g_warning ( "openSAFETY - SercosIII heuristic dissector cannot be registered, openSAFETY/SercosIII native dissection." );
            dissector_add_uint("ethertype", ETHERTYPE_SERCOS, find_dissector("opensafety_siii"));
        }

        /* Modbus TCP dissector registration */
        dissector_add_string("mbtcp.modbus.data", "data", find_dissector("opensafety_mbtcp"));
    }

}
