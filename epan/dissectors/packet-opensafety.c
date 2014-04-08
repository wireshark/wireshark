/* packet-opensafety.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-frame.h>

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

/* Used to clasify incoming traffic and presort the heuristic */
#define OPENSAFETY_CYCLIC_DATA   0x01
#define OPENSAFETY_ACYCLIC_DATA  0x02

#define OPENSAFETY_DEFAULT_DOMAIN       0x1

#ifndef OPENSAFETY_PINFO_CONST_DATA
#define OPENSAFETY_PINFO_CONST_DATA 0xAABBCCDD
#endif

/* openSAFETY CRC types */
#define OPENSAFETY_CHECKSUM_CRC8        0x01
#define OPENSAFETY_CHECKSUM_CRC16       0x02
#define OPENSAFETY_CHECKSUM_CRC32       0x04
#define OPENSAFETY_CHECKSUM_CRC16SLIM   0x08

static const value_string message_crc_type[] = {
    { OPENSAFETY_CHECKSUM_CRC8,         "CRC8" },
    { OPENSAFETY_CHECKSUM_CRC16,        "CRC16" },
    { OPENSAFETY_CHECKSUM_CRC32,        "CRC32" },
    { OPENSAFETY_CHECKSUM_CRC16SLIM,    "CRC16 Slim" },
    { 0, NULL }
};

/* openSAFETY Message Types */
#define OPENSAFETY_SPDO_MESSAGE_TYPE      0xC0
#define OPENSAFETY_SSDO_MESSAGE_TYPE      0xE0
#define OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE 0xE8
#define OPENSAFETY_SNMT_MESSAGE_TYPE      0xA0

static const value_string message_id_values[] = {
    { OPENSAFETY_SPDO_MESSAGE_TYPE,      "openSAFETY SPDO" },
    { OPENSAFETY_SSDO_MESSAGE_TYPE,      "openSAFETY SSDO" },
    { OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE, "openSAFETY Slim SSDO" },
    { OPENSAFETY_SNMT_MESSAGE_TYPE,      "openSAFETY SNMT" },
    { 0, NULL }
};

/* openSAFETY Message IDs */
#define OPENSAFETY_MSG_SPDO_DATA_ONLY               0xC0
#define OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST  0xC8
#define OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE 0xD0
#define OPENSAFETY_MSG_SPDO_RESERVED                0xD8

#define OPENSAFETY_MSG_SSDO_SERVICE_REQUEST         0xE0
#define OPENSAFETY_MSG_SSDO_SERVICE_RESPONSE        0xE4
#define OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST    0xE8
#define OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE   0xEC

#define OPENSAFETY_MSG_SNMT_REQUEST_UDID            0xA0
#define OPENSAFETY_MSG_SNMT_RESPONSE_UDID           0xA4
#define OPENSAFETY_MSG_SNMT_ASSIGN_SADR             0xA8
#define OPENSAFETY_MSG_SNMT_SADR_ASSIGNED           0xAC
#define OPENSAFETY_MSG_SNMT_SERVICE_REQUEST         0xB0
#define OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE        0xB4
#define OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM   0xBC

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
#define OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_PRE_OP            0x00
#define OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP                0x02
#define OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP             0x04
#define OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP               0x06
#define OPENSAFETY_MSG_SNMT_EXT_SCM_GUARD_SN                0x08
#define OPENSAFETY_MSG_SNMT_EXT_ASSIGN_ADDITIONAL_SADR      0x0A
#define OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE              0x0C
#define OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM          0x0E
#define OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_PRE_OP            0x01
#define OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_OP                0x03
#define OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_ADDITIONAL_SADR 0x05
#define OPENSAFETY_MSG_SNMT_EXT_SN_FAIL                     0x07
#define OPENSAFETY_MSG_SNMT_EXT_SN_BUSY                     0x09
#define OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM        0x0F

static const value_string message_service_type[] = {
    { OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_PRE_OP,            "SN set to pre Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP,                "SN set to Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP,             "SCM set to Stop" },
    { OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP,               "SCM set to Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SCM_GUARD_SN,                "SCM guard SN" },
    { OPENSAFETY_MSG_SNMT_EXT_ASSIGN_ADDITIONAL_SADR,      "Assign additional SADR" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ACKNOWLEDGE,              "SN Acknowledge" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM,          "SN assign UDID SCM" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_PRE_OP,            "SN status pre Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_STATUS_OP,                "SN status Operational" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_ADDITIONAL_SADR, "Assigned additional SADR" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_FAIL,                     "SN Fail" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_BUSY,                     "SN Busy" },
    { OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM,        "SN assigned UDID SCM" },
    { 0, NULL }
};

/* Values 6-255 are reserved for future use. They will be presented as "Reserved [%d]"
 * during dissection
 */
#define OPENSAFETY_ERROR_GROUP_APPLICATION                  0x01
#define OPENSAFETY_ERROR_GROUP_PARAMETER                    0x02
#define OPENSAFETY_ERROR_GROUP_VENDOR_SPECIFIC              0x03
#define OPENSAFETY_ERROR_GROUP_OPENSAFETY_STACK             0x04
#define OPENSAFETY_ERROR_GROUP_ADD_PARAMETER                0x05

static const value_string sn_fail_error_group[] = {
    { OPENSAFETY_ERROR_GROUP_APPLICATION,      "Application" },
    { OPENSAFETY_ERROR_GROUP_PARAMETER,        "Parameter" },
    { OPENSAFETY_ERROR_GROUP_VENDOR_SPECIFIC,  "Vendor specific" },
    { OPENSAFETY_ERROR_GROUP_OPENSAFETY_STACK, "openSAFETY Stack" },
    { OPENSAFETY_ERROR_GROUP_ADD_PARAMETER,    "Additional parameter needed" },
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
    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_END,      "Block Download Segment End" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE,           "Block Upload Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_INITIATE_EXPEDITED, "Block Upload Initiate" },
    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_INITIATE,         "Block Download Initiate" },
    { OPENSAFETY_MSG_SSDO_BLOCK_DOWNLOAD_SEGMENT_MIDDLE,   "Block Download Middle Segment" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_MIDDLE,     "Block Upload Middle Segment" },
    { OPENSAFETY_MSG_SSDO_BLOCK_UPLOAD_SEGMENT_END,        "Block Upload End Segment" },
#endif
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END,            "Download End Segment" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END,              "Upload End Segment" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED,     "Download Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED,       "Upload Initiate Segmented" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED,     "Download Initiate Segmented" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED,       "Upload Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE,         "Download Middle Segment" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE,           "Upload Middle Segment" },
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
#if 0
static const true_false_string opensafety_sacmd_res  = { "Reserved", "Reserved" };
#endif
static const true_false_string opensafety_sacmd_abrt = { "Abort Transfer", "Successful Transfer" };
static const true_false_string opensafety_sacmd_seg  = { "Segmented Access", "Expedited Access" };
static const true_false_string opensafety_on_off     = { "On", "Off" };
static const true_false_string opensafety_set_notset = { "Set", "Not set" };
static const true_false_string opensafety_sacmd_ini  = { "Initiate", "No Initiate" };
static const true_false_string opensafety_sacmd_ensg = { "No more segments", "More segments" };
static const true_false_string opensafety_sacmd_blk  = { "Block Transfer", "Normal Transfer" };

#define OPENSAFETY_SPDO_CONNECTION_VALID  0x04

#define OPENSAFETY_SOD_DVI   0x1018
#define OPENSAFETY_SOD_RXMAP 0x1800
#define OPENSAFETY_SOD_TXMAP 0xC000

static const value_string sod_idx_names[] = {
    /* SSDO dictionary names, only names that are in common use are presented */
    { 0x100C0000, "Life Guarding" },
    { 0x100C0001, "Guard Time" },
    { 0x100C0002, "LifeTimeFactor" },

    { 0x100D0000, "Number of Retries for Reset Guarding" },

    { 0x10180000, "Device Vendor Information" },
    { 0x10180001, "VendorID" },
    { 0x10180002, "ProductCode" },
    { 0x10180003, "RevisionNumber" },
    { 0x10180004, "SerialNumber" },
    { 0x10180005, "FirmWareChecksum" },
    { 0x10180006, "Parameter Checksum" },
    { 0x10180007, "Parameter Timestamp" },

    { 0x10190000, "Unique Device ID" },
    { 0x101A0000, "Parameter Download" },
    { 0x101B0000, "SCM Parameters" },

    { 0x12000000, "Common Communication Parameters" },
    { 0x12000001, "Safety Domain Number" },
    { 0x12000002, "SADR" },
    { 0x12000003, "Consecutive Timebase" },
    { 0x12000004, "UDID of SCM" },

    { 0x14000000, "RxSPDO Communication Parameters" },
    { 0x14000001, "SADR" },
    { 0x14000002, "SCT" },
    { 0x14000003, "Number of consecutive TReq" },
    { 0x14000004, "Time delay TReq" },
    { 0x14000005, "Time delay Sync" },
    { 0x14000006, "Min TSync Propagation Delay" },
    { 0x14000007, "Max TSync Propagation Delay" },
    { 0x14000008, "Min SPDO Propagation Delay" },
    { 0x14000009, "Max SPDO Propagation Delay" },
    { 0x1400000A, "Best case TRes Delay" },
    { 0x1400000B, "Time Request Cycle" },
    { 0x1400000C, "TxSPDO No" },

    { 0x18000000, "RxSPDO Mapping Parameters" },

    { 0x1C000000, "TxSPDO Communication Parameters" },
    { 0x1C000001, "SADR for broadcast" },
    { 0x1C000002, "Refresh Prescale" },
    { 0x1C000003, "Number of TRes" },

    { 0x20000000, "Manufacturer Parameters" },
    { 0x20010000, "Used Channels" },

    { 0x21000000, "Safe Machine Options" },

    { 0x21010000, "SDG CRC Configuration" },
    { 0x21010001, "SDG CRC #1" },
    { 0x21010002, "SDG CRC #2" },
    { 0x21010003, "SDG CRC #3" },
    { 0x21010004, "SDG CRC #4" },
    { 0x21010005, "SDG CRC #5" },
    { 0x21010006, "SDG CRC #6" },
    { 0x21010007, "SDG CRC #7" },
    { 0x21010008, "SDG CRC #8" },
    { 0x21010009, "SDG CRC #9" },
    { 0x2101000A, "SDG CRC #10" },

    { 0x21120000, "Manufacturer - Module specific" },
    { 0x21120002, "PDOmapRx" },
    { 0x21120003, "PDOmapTx" },
    { 0x21120004, "CycleTime min [us]" },
    { 0x21120005, "CycleTime max [us]" },
    { 0x21120006, "Used Channels (same as 0x2001)" },
    { 0x21120007, "External Machine Options" },
    { 0x21120008, "Parameter for SafeMC" },

    { 0xC0000000, "TxSPDO Mapping Parameters" },

    { 0xD0000000, "SCM Module Flags" },
    { 0xD0000001, "BCM" },
    { 0xD0000002, "Optional" },
    { 0xD0000003, "Startup" },
    { 0xD0000004, "EMOs" },
    { 0xD0000005, "ext. Startup-Flags allowed" },
    { 0xD0000006, "Remote-Ctrl allowed" },
    { 0xD0000007, "Scans at startup" },
    { 0xD0000008, "Not Present" },
    { 0xD0000009, "Use Remanent Data" },
    { 0xD000000A, "SCM-AR specific" },

    { 0xD0100000, "Remanent Data" },
    { 0xD0100001, "DINT" },

    { 0xD0110000, "Remanent Data" },
    { 0xD0110001, "DUINT" },

    { 0, NULL }
};

static const value_string abort_codes[] = {

    /* SSDO abort codes */
    { 0x05030000, "Reserved" },

    { 0x05040000, "SSDO protocol timed out" },
    { 0x05040001, "Client/server Command ID not valid or unknown" },
    { 0x05040002, "Invalid block size" },
    { 0x05040003, "Invalid sequence number" },
    { 0x05040004, "Reserved" },
    { 0x05040005, "Out of memory" },

    { 0x06010000, "Unsupported access to an object" },
    { 0x06010001, "Attempt to read a write-only object" },
    { 0x06010002, "Attempt to write a read-only object" },

    { 0x06020000, "Object does not exist in the object dictionary" },

    { 0x06040041, "Object cannot be mapped to the SPDO" },
    { 0x06040042, "The number and length of the objects to be mapped would exceed SPDO length" },
    { 0x06040043, "General parameter incompatibility" },
    { 0x06040047, "General internal incompatibility in the device" },

    { 0x06060000, "Access failed due to a hardware error" },

    { 0x06070010, "Data type does not match, length of service parameter does not match" },
    { 0x06070012, "Data type does not match, length of service parameter too high" },
    { 0x06070013, "Data type does not match, length of service parameter too low" },

    { 0x06090011, "Sub-index does not exist" },
    { 0x06090030, "Value range o parameter exceeded (only for write access)" },
    { 0x06090031, "Value of parameter written too high" },
    { 0x06090032, "Value of parameter written too low" },
    { 0x06090036, "Maximum value is less than minimum value" },

    { 0x08000000, "General error" },
    { 0x08000020, "Data cannot be transferred or stored to the application" },
    { 0x08000021, "Data cannot be transferred or stored to the application because of local control" },
    { 0x08000022, "Data cannot be transferred or stored to the application because of the present device state" },
    { 0x08000023, "Data cannot be transferred or stored to the application because of the object data is not available now" },

    { 0, NULL }
};

static const true_false_string opensafety_message_direction = { "Request", "Response" };
#define OPENSAFETY_REQUEST  TRUE
#define OPENSAFETY_RESPONSE FALSE

static const true_false_string opensafety_addparam_request = { "Header only", "Header & Data" };

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
#define OSS_FRAME_ID(f, offset)          (f[OSS_FRAME_POS_ID + offset] & 0xFC )
#define OSS_FRAME_LENGTH(f, offset)      (f[OSS_FRAME_POS_LEN + offset])
#define OSS_FRAME_FIELD(f, position)     (f[position])

#define OSS_FRAME_ADDR_T(f, offset)        (tvb_get_guint8(f, OSS_FRAME_POS_ADDR + offset) + ((guint8)((tvb_get_guint8( f, OSS_FRAME_POS_ADDR + offset + 1)) << 6) << 2))
#define OSS_FRAME_ADDR_T2(f, offset, su1, su2)        (( tvb_get_guint8(f, OSS_FRAME_POS_ADDR + offset) ^ su1) + ((guint8)(((tvb_get_guint8( f, OSS_FRAME_POS_ADDR + offset + 1) ^ su2)) << 6) << 2))
#define OSS_FRAME_ID_T(f, offset)          (tvb_get_guint8(f, OSS_FRAME_POS_ID + offset) & 0xFC)
#define OSS_FRAME_LENGTH_T(f, offset)      (tvb_get_guint8(f, OSS_FRAME_POS_LEN + offset))

static int proto_opensafety = -1;

static gint ett_opensafety = -1;
static gint ett_opensafety_checksum = -1;
static gint ett_opensafety_snmt = -1;
static gint ett_opensafety_ssdo = -1;
static gint ett_opensafety_spdo = -1;
static gint ett_opensafety_ssdo_sacmd = -1;
static gint ett_opensafety_ssdo_payload = -1;
static gint ett_opensafety_ssdo_sodentry = -1;
static gint ett_opensafety_ssdo_extpar = -1;
static gint ett_opensafety_sod_mapping = -1;
static gint ett_opensafety_node = -1;

static expert_field ei_payload_length_not_positive = EI_INIT;
static expert_field ei_payload_unknown_format = EI_INIT;
static expert_field ei_crc_slimssdo_instead_of_spdo = EI_INIT;
static expert_field ei_crc_frame_1_invalid = EI_INIT;
static expert_field ei_crc_frame_1_valid_frame2_invalid = EI_INIT;
static expert_field ei_crc_frame_2_invalid = EI_INIT;
static expert_field ei_crc_frame_2_unknown_scm_udid = EI_INIT;
static expert_field ei_message_unknown_type = EI_INIT;
static expert_field ei_message_reassembly_size_differs_from_header = EI_INIT;
static expert_field ei_message_spdo_address_invalid = EI_INIT;
static expert_field ei_message_id_field_mismatch = EI_INIT;
static expert_field ei_scmudid_autodetected = EI_INIT;
static expert_field ei_scmudid_invalid_preference = EI_INIT;
static expert_field ei_scmudid_unknown = EI_INIT;

static int hf_oss_msg = -1;
static int hf_oss_msg_direction = -1;
static int hf_oss_msg_category = -1;
static int hf_oss_msg_node = -1;
static int hf_oss_msg_network = -1;
static int hf_oss_msg_sender = -1;
static int hf_oss_msg_receiver = -1;
static int hf_oss_length= -1;
static int hf_oss_crc = -1;

static int hf_oss_crc_valid = -1;
static int hf_oss_crc2_valid = -1;
static int hf_oss_crc_type  = -1;

static int hf_oss_snmt_slave = -1;
static int hf_oss_snmt_master = -1;
static int hf_oss_snmt_udid = -1;
static int hf_oss_snmt_scm = -1;
static int hf_oss_snmt_tool = -1;
static int hf_oss_snmt_service_id = -1;
static int hf_oss_snmt_error_group = -1;
static int hf_oss_snmt_error_code = -1;
static int hf_oss_snmt_param_type = -1;
static int hf_oss_snmt_ext_addsaddr = -1;
static int hf_oss_snmt_ext_addtxspdo = -1;

static int hf_oss_ssdo_server = -1;
static int hf_oss_ssdo_client = -1;
static int hf_oss_ssdo_sano = -1;
static int hf_oss_ssdo_sacmd = -1;
static int hf_oss_ssdo_sod_index = -1;
static int hf_oss_ssdo_sod_subindex = -1;
static int hf_oss_ssdo_payload = -1;
static int hf_oss_ssdo_payload_size = -1;
static int hf_oss_ssdo_sodentry_size = -1;
static int hf_oss_ssdo_sodentry_data = -1;
/* static int hf_oss_ssdo_inhibit_time = -1; */
static int hf_oss_ssdo_abort_code = -1;

static int hf_oss_sod_par_timestamp = -1;
static int hf_oss_sod_par_checksum = -1;
static int hf_oss_ssdo_sodmapping = -1;
static int hf_oss_ssdo_sodmapping_bits = -1;

static int hf_oss_ssdo_sacmd_access_type = -1;
/* static int hf_oss_ssdo_sacmd_reserved = -1; */
static int hf_oss_ssdo_sacmd_abort_transfer = -1;
static int hf_oss_ssdo_sacmd_segmentation = -1;
static int hf_oss_ssdo_sacmd_toggle = -1;
static int hf_oss_ssdo_sacmd_initiate = -1;
static int hf_oss_ssdo_sacmd_end_segment = -1;
static int hf_oss_ssdo_sacmd_block_transfer = -1;

static int hf_oss_ssdo_extpar_parset = -1;
static int hf_oss_ssdo_extpar_version = -1;
static int hf_oss_ssdo_extpar_saddr = -1;
static int hf_oss_ssdo_extpar_length = -1;
static int hf_oss_ssdo_extpar_crc = -1;
static int hf_oss_ssdo_extpar_tstamp = -1;
static int hf_oss_ssdo_extpar_data = -1;
static int hf_oss_ssdo_extpar = -1;

static int hf_oss_scm_udid = -1;
static int hf_oss_scm_udid_auto = -1;
static int hf_oss_scm_udid_valid = -1;

static int hf_oss_spdo_connection_valid = -1;
static int hf_oss_spdo_payload = -1;
static int hf_oss_spdo_producer = -1;
static int hf_oss_spdo_producer_time = -1;
static int hf_oss_spdo_time_value_sn = -1;
static int hf_oss_spdo_time_request = -1;
static int hf_oss_spdo_time_request_to = -1;
static int hf_oss_spdo_time_request_from = -1;

static int hf_oss_fragments = -1;
static int hf_oss_fragment = -1;
static int hf_oss_fragment_overlap = -1;
static int hf_oss_fragment_overlap_conflicts = -1;
static int hf_oss_fragment_multiple_tails = -1;
static int hf_oss_fragment_too_long_fragment = -1;
static int hf_oss_fragment_error = -1;
static int hf_oss_fragment_count = -1;
static int hf_oss_reassembled_in = -1;
static int hf_oss_reassembled_length = -1;
static int hf_oss_reassembled_data = -1;

static gint ett_opensafety_ssdo_fragment = -1;
static gint ett_opensafety_ssdo_fragments = -1;

static const fragment_items oss_frag_items = {
    /* Fragment subtrees */
    &ett_opensafety_ssdo_fragment,
    &ett_opensafety_ssdo_fragments,
    /* Fragment fields */
    &hf_oss_fragments,
    &hf_oss_fragment,
    &hf_oss_fragment_overlap,
    &hf_oss_fragment_overlap_conflicts,
    &hf_oss_fragment_multiple_tails,
    &hf_oss_fragment_too_long_fragment,
    &hf_oss_fragment_error,
    &hf_oss_fragment_count,
    /* Reassembled in field */
    &hf_oss_reassembled_in,
    /* Reassembled length field */
    &hf_oss_reassembled_length,
    /* Reassembled data */
    &hf_oss_reassembled_data,
    /* Tag */
    "Message fragments"
};

static const char *global_scm_udid = "00:00:00:00:00:00";

static dissector_handle_t data_dissector = NULL;

static gboolean global_display_intergap_data   = FALSE;
static gboolean global_calculate_crc2          = FALSE;
static gboolean global_scm_udid_autoset        = TRUE;
static gboolean global_udp_frame2_first        = FALSE;
static gboolean global_siii_udp_frame2_first   = FALSE;
static gboolean global_mbtcp_big_endian        = FALSE;
static guint global_network_udp_port           = UDP_PORT_OPENSAFETY;
static guint global_network_udp_port_sercosiii = UDP_PORT_SIII;
static gboolean global_classify_transport      = TRUE;

static gboolean global_enable_plk    = TRUE;
static gboolean global_enable_udp    = TRUE;
static gboolean global_enable_genudp = TRUE;
static gboolean global_enable_siii   = TRUE;
static gboolean global_enable_pnio   = FALSE;
static gboolean global_enable_mbtcp  = TRUE;

static gboolean bDissector_Called_Once_Before = FALSE;
/* Using local_scm_udid as read variable for global_scm_udid, to
 * enable automatic detection of scm udid */
static char *local_scm_udid = NULL;

static reassembly_table os_reassembly_table;

/* Resets the dissector in case the dissection is malformed and the dissector crashes */
static void
reset_dissector(void)
{
    bDissector_Called_Once_Before = FALSE;
}

static void
setup_dissector(void)
{
    if ( local_scm_udid != NULL )
        local_scm_udid = NULL;

    reassembly_table_init(&os_reassembly_table, &addresses_reassembly_table_functions);
}

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
        proto_item *psf_item = NULL; \
        proto_tree *psf_tree  = NULL; \
        psf_item = proto_tree_add_uint(opensafety_tree, hf_oss_msg_receiver, message_tvb, pos, 2, recv); \
        psf_tree = proto_item_add_subtree(psf_item, ett_opensafety_node); \
        psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_node, message_tvb, pos, 2, recv);\
        PROTO_ITEM_SET_GENERATED(psf_item); \
        if ( sdn > 0 ) \
        { \
            psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn, "0x%04X", sdn); \
        } else if ( sdn <= 0 ) { \
            psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn * -1, "0x%04X", sdn * -1); \
            expert_add_info(pinfo, psf_item, &ei_scmudid_unknown ); \
        } \
        PROTO_ITEM_SET_GENERATED(psf_item); \
        }

/* Tracks the information that the packet pinfo has been sent by sender, and received by everyone else, and adds that information to
 * the tree, using pos, as byte position in the PDU */
#define PACKET_SENDER(pinfo, sender, pos, posnet, sdn)                { \
        proto_item *psf_item = NULL; \
        proto_tree *psf_tree  = NULL; \
        psf_item = proto_tree_add_uint(opensafety_tree, hf_oss_msg_sender, message_tvb, pos, 2, sender); \
        psf_tree = proto_item_add_subtree(psf_item, ett_opensafety_node); \
        psf_item = proto_tree_add_uint(psf_tree, hf_oss_msg_node, message_tvb, pos, 2, sender);\
        PROTO_ITEM_SET_GENERATED(psf_item); \
        if ( sdn > 0 ) \
        { \
            psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn, "0x%04X", sdn); \
        } else if ( sdn <= 0 ) { \
            psf_item = proto_tree_add_uint_format_value(psf_tree, hf_oss_msg_network, message_tvb, posnet, 2, sdn * -1, "0x%04X", sdn * -1); \
            expert_add_info(pinfo, psf_item, &ei_scmudid_unknown ); \
        } \
        PROTO_ITEM_SET_GENERATED(psf_item); \
        }

/* Tracks the information that the packet pinfo has been sent by sender, and received by receiver, and adds that information to
 * the tree, using pos for the sender and pos2 for the receiver, as byte position in the PDU */
#define PACKET_SENDER_RECEIVER(pinfo, send, pos, recv, pos2, posnet, sdn)         { \
        PACKET_RECEIVER(pinfo, recv, pos2, posnet, sdn); \
        PACKET_SENDER(pinfo, send, pos, posnet, sdn); \
        }

static guint16
findFrame1Position ( tvbuff_t *message_tvb, guint16 byte_offset, guint8 dataLength, gboolean checkIfSlimMistake )
{
    guint16  i_wFrame1Position                   = 0;
    guint16  i_payloadLength, i_calculatedLength = 0;
    guint16  i_offset                            = 0, calcCRC = 0, frameCRC = 0;
    guint8   b_tempByte                          = 0;
    guint8  *bytes = NULL;

    /*
     * First, a normal package is assumed. Calculation of frame 1 position is
     * pretty easy, because, the length of the whole package is 11 + 2*n + 2*o, which
     * results in frame 1 start at (6 + n + o), which is length / 2 + 1
     */
    i_wFrame1Position = dataLength / 2 + 1;
    i_payloadLength = tvb_get_guint8(message_tvb, byte_offset + i_wFrame1Position + 2 );
    /* Calculating the assumed frame length, taking CRC8/CRC16 into account */
    i_calculatedLength = i_payloadLength * 2 + 11 + 2 * (i_payloadLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? 1 : 0);

    /* To prevent miscalculations, where by chance the byte at [length / 2] + 3 is a value matching a possible payload length,
     * but in reality the frame is a slim ssdo, the CRC of frame 1 gets checked additionally. This check
     * is somewhat time consuming, so it will only run if the normal check led to a mistake detected along the line */
    if ( checkIfSlimMistake && i_calculatedLength == dataLength )
    {
        if (dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
            frameCRC = tvb_get_letohs(message_tvb,  byte_offset + i_wFrame1Position + dataLength + OSS_FRAME_POS_DATA);
        else
            frameCRC = tvb_get_guint8(message_tvb,  byte_offset + i_wFrame1Position + dataLength + OSS_FRAME_POS_DATA);

        bytes = (guint8*)tvb_memdup(wmem_packet_scope(), message_tvb, byte_offset + i_wFrame1Position, dataLength + 4);
        if ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
        {
            calcCRC = crc16_0x755B(bytes, dataLength + 4, 0);
            if ( frameCRC != calcCRC )
                calcCRC = crc16_0x5935(bytes, dataLength + 4, 0);
        }
        else
            calcCRC = crc8_0x2F(bytes, dataLength + 4, 0);

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
        b_tempByte = ( tvb_get_guint8 ( message_tvb, byte_offset + i_offset + 1 ) ) & 0xFC;

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

static guint8 findSafetyFrame ( tvbuff_t *message_tvb, guint u_Offset, gboolean b_frame2first, guint *u_frameOffset, guint *u_frameLength )
{
    guint     ctr, rem_length;
    guint16   crc, f2crc, calcCrc;
    guint8    b_Length, crcOffset;
    guint8   *bytes;
    guint     b_ID;
    gboolean  found;

    found = 0;
    ctr = u_Offset;
    rem_length = tvb_reported_length_remaining (message_tvb, ctr);

    while ( rem_length >= OSS_MINIMUM_LENGTH)
    {
        /* The ID byte must ALWAYS be the second byte, therefore 0 is invalid */
        if ( ctr != 0 )
        {
            *u_frameLength = 0;
            *u_frameOffset = 0;

            crcOffset = 0;
            b_ID = tvb_get_guint8(message_tvb, ctr );

            if ( b_ID != 0x0 )
            {
                b_Length = tvb_get_guint8(message_tvb, ctr + 1 );

                /* 0xFF is often used, but always false, otherwise start detection, if the highest
                 *  bit is set */
                if ( ( b_ID != 0xFF ) && ( b_ID & 0x80 ) )
                {
                    /* The rem_length value might be poluted, due to the else statement of
                     * above if-decision (frame at end position detection). Therefore we
                     * calculate it here again, to have a sane value */
                    rem_length = tvb_reported_length_remaining(message_tvb, ctr);

                    /* Plausability check on length */
                    if ( (guint)( b_Length * 2 ) < ( rem_length + OSS_MINIMUM_LENGTH ) )
                    {

                        /* The calculated length must fit, but for the CRC16 check, also the calculated length
                         * plus the CRC16 end position must fit in the remaining length */
                        if ( ( b_Length <= (guint) 8 && ( b_Length <= rem_length ) ) ||
                            ( b_Length > (guint) 8 && ( ( b_Length + (guint) 5 ) <= rem_length ) ) )
                        {
                            /* Ensure, that the correct length for CRC calculation
                             * still exists in byte stream, so that we can calculate the crc */
                            if ( tvb_bytes_exist(message_tvb, ctr - 1, b_Length + 5) )
                            {
                                /* An openSAFETY command has to have a high-byte range between 0x0A and 0x0E
                                 *  b_ID & 0x80 took care of everything underneath, we check for 0x09 and 0x0F,
                                 *  as they remain the only values left, which are not valid */
                                if ( ( ( b_ID >> 4 ) != 0x09 ) && ( ( b_ID >> 4 ) != 0x0F ) )
                                {
                                    /* Find CRC position and calculate checksum */
                                    crc = tvb_get_guint8(message_tvb, ctr + 3 + b_Length );

                                    bytes = (guint8 *)tvb_memdup(wmem_packet_scope(), message_tvb, ctr - 1, b_Length + 5 );
                                    if ( b_Length > 8 ) {
                                        crc = tvb_get_letohs ( message_tvb, ctr + 3 + b_Length );
                                        crcOffset = 1;

                                        calcCrc = crc16_0x755B( bytes, b_Length + 4, 0 );
                                        if ( ( crc ^ calcCrc ) != 0 )
                                            calcCrc = crc16_0x5935( bytes, b_Length + 4, 0 );
                                    } else {
                                        calcCrc = crc8_0x2F ( bytes, b_Length + 4, 0 );
                                    }

                                    if ( ( crc ^ calcCrc ) == 0 )
                                    {
                                        /* Check if this is a Slim SSDO message */
                                        if ( ( b_ID >> 3 ) == ( OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE >> 3 ) )
                                        {
                                            /* Slim SSDO messages must have a length != 0, as the first byte
                                             * in the payload contains the SOD access command */
                                            if ( b_Length > 0 )
                                            {
                                                *u_frameOffset = ( ctr - 1 );
                                                *u_frameLength = b_Length + 2 * crcOffset + 11;

                                                /* It is highly unlikely, that both frame 1 and frame 2 generate
                                                 * a crc == 0 or equal crc's. Therefore we check, if both crc's are
                                                 * equal. If so, it is a falsely detected frame. */
                                                f2crc = tvb_get_guint8 ( message_tvb, ctr + 3 + 5 + b_Length );
                                                if ( b_Length > 8 )
                                                    f2crc = tvb_get_letohs ( message_tvb, ctr + 3 + 5 + b_Length );
                                                if ( crc != f2crc )
                                                {
                                                    found = 1;
                                                    break;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            *u_frameLength = 2 * b_Length + 2 * crcOffset + 11;
                                            *u_frameOffset = ( ctr - 1 );

                                            /* At this point frames had been checked for SoC and SoA types of
                                             * EPL. This is no longer necessary and leads to false-negatives.
                                             * SoC and SoA frames get filtered out at the EPL entry point, cause
                                             * EPL only provides payload, no longer complete frames. */
                                            found = 1;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    /* There exist frames, where the last openSAFETY frame is sitting in the
                     * very last bytes of the frame, and the complete frame itself contains
                     * more than one openSAFETY frame. It so happens that in such a case, the
                     * last openSAFETY frame will miss detection.
                     *
                     * If so we look at the transported length, calculate the frame length,
                     * and take a look if the calculated frame length, might be a fit for the
                     * remaining length. If such is the case, we increment ctr and increment
                     * rem_length (to hit the while loop one more time) and the frame will be
                     * detected correctly. */
                    if ( rem_length == OSS_MINIMUM_LENGTH )
                    {
                        b_ID = tvb_get_guint8(message_tvb, ctr );
                        b_Length = tvb_get_guint8(message_tvb, ctr + 2 );
                        if ( ( b_ID >> 3 ) == ( OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE >> 3 ) )
                            b_Length = ( 11 + ( b_Length > 8 ? 2 : 0 ) + b_Length );
                        else
                            b_Length = ( 11 + ( b_Length > 8 ? 2 : 0 ) + 2 * b_Length );

                        if ( rem_length == b_Length )
                        {
                            ctr++;
                            rem_length++;
                            continue;
                        }
                    }
                }
            }
        }

        ctr++;
        rem_length = tvb_reported_length_remaining(message_tvb, ctr);

    }

    /* Seem redundant if b_frame2First is false. But in this case, the function is needed for the
     * simple detection of a possible openSAFETY frame.  */
    if ( b_frame2first && found )
        *u_frameOffset = u_Offset;

    return (found ? 1 : 0);
}

static void
dissect_opensafety_spdo_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        guint16 frameStart1, guint16 frameStart2, gboolean validSCMUDID, guint8 *scm_udid)
{
    proto_item *item;
    proto_tree *spdo_tree, *node_tree;
    guint16     ct;
    gint16      taddr;
    guint       dataLength;
    guint8      tr, b_ID, conn_Valid;

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + frameStart1);
    b_ID = tvb_get_guint8(message_tvb, frameStart1 + 1) & 0xF8;
    conn_Valid = ( (tvb_get_guint8(message_tvb, frameStart1 + 1) & 0x04) == 0x04);

    /* Network address is xor'ed into the start of the second frame, but only legible, if the scm given is valid */
    taddr = ( ( OSS_FRAME_ADDR_T(message_tvb, frameStart1) ) ^ ( OSS_FRAME_ADDR_T2(message_tvb, frameStart2, scm_udid[0], scm_udid[1]) ) );
    if ( ! validSCMUDID )
        taddr = ( -1 * taddr );

    /* An SPDO is always sent by the producer, to everybody else */
    PACKET_SENDER( pinfo, OSS_FRAME_ADDR_T(message_tvb, frameStart1), OSS_FRAME_POS_ADDR + frameStart1, frameStart2, taddr );

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
                        OSS_FRAME_POS_ADDR + frameStart1, 2, OSS_FRAME_ADDR_T(message_tvb, frameStart1));
    proto_tree_add_boolean(spdo_tree, hf_oss_spdo_connection_valid, message_tvb,
                           OSS_FRAME_POS_ID + frameStart1, 1, conn_Valid);

    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR_T2(message_tvb, frameStart2 + 3, scm_udid[3], scm_udid[4]);
    tr = ( tvb_get_guint8(message_tvb, frameStart2 + 4)  ^ scm_udid[4] ) & 0xFC;

    /* determine the ct value. if complete it can be used for analysis of the package */
    ct = tvb_get_guint8(message_tvb, frameStart1 + 3);
    if ( validSCMUDID )
    {
        ct = (guint16)((tvb_get_guint8(message_tvb, frameStart2 + 2) ^ scm_udid[2]) << 8) +
            (tvb_get_guint8(message_tvb, frameStart1 + 3));
    }

    if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_REQUEST )
    {
        item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_time_value_sn, message_tvb, 0, 0, ct,
                                                "0x%04X [%d] (%s)", ct, ct,
                                                (validSCMUDID ? "Complete" : "Low byte only"));
        PROTO_ITEM_SET_GENERATED(item);

        proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request, message_tvb,
                            OSS_FRAME_POS_ADDR + frameStart2 + 4, 1, tr);
        item = proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request_from, message_tvb,
                            OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
        node_tree = proto_item_add_subtree(item, ett_opensafety_node);
        item = proto_tree_add_uint(node_tree, hf_oss_msg_node,  message_tvb,
                OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
        PROTO_ITEM_SET_GENERATED(item);
    }
    else
    {
        item = proto_tree_add_uint_format_value(spdo_tree, hf_oss_spdo_producer_time, message_tvb, 0, 0, ct,
                "0x%04X [%d] (%s)", ct, ct, (validSCMUDID ? "Complete" : "Low byte only"));
        PROTO_ITEM_SET_GENERATED(item);

        if ( b_ID == OPENSAFETY_MSG_SPDO_DATA_WITH_TIME_RESPONSE )
        {
            proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request,    message_tvb, OSS_FRAME_POS_ADDR + frameStart2 + 4, 1, tr);
            item = proto_tree_add_uint(spdo_tree, hf_oss_spdo_time_request_to, message_tvb,
                    OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
            node_tree = proto_item_add_subtree(item, ett_opensafety_node);
            item = proto_tree_add_uint(node_tree, hf_oss_msg_node,  message_tvb,
                    OSS_FRAME_POS_ADDR + frameStart2 + 3, 2, taddr);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }

    if ( dataLength > 0 )
        proto_tree_add_item(spdo_tree, hf_oss_spdo_payload, message_tvb, OSS_FRAME_POS_ID + 3, dataLength, ENC_NA);
}

static void dissect_ssdo_payload ( packet_info *pinfo, tvbuff_t *new_tvb, proto_tree *ssdo_payload, guint8 sacmd )
{
    guint       dataLength   = 0, ctr = 0, n = 0;
    guint8      ssdoSubIndex = 0;
    guint16     ssdoIndex    = 0, dispSSDOIndex = 0;
    guint32     sodLength    = 0, entry = 0;
    proto_item *item;
    proto_tree *sod_tree, *ext_tree;

    dataLength = tvb_length(new_tvb);

    ssdoIndex = tvb_get_letohs(new_tvb, 0);

    sodLength = tvb_get_letohl(new_tvb, 4);

    /* first check for extended parameter */
    if ( dataLength == 16 || sodLength == ( dataLength - 16 ) || ssdoIndex == 0x0101 )
    {
        /* extended parameter header & data */
        item = proto_tree_add_string_format(ssdo_payload, hf_oss_ssdo_extpar,
                                            new_tvb, 0, dataLength, "", "Extended Parameter Set: %s",
                                            (dataLength == 16 ? "Header only" : "Header & Data") );
        ext_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_extpar);

        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_parset,  new_tvb, 0, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_version, new_tvb, 1, 1, ENC_BIG_ENDIAN );
        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_saddr,   new_tvb, 2, 2, ENC_LITTLE_ENDIAN );

        proto_tree_add_uint_format_value(ext_tree, hf_oss_ssdo_extpar_length,
                                         new_tvb, 4, 4, sodLength, "0x%04X (%d octets)",
                                         sodLength, sodLength );

        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_crc,    new_tvb,  8, 4, ENC_LITTLE_ENDIAN );
        proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_tstamp, new_tvb, 12, 4, ENC_LITTLE_ENDIAN );

        if ( dataLength != 16 )
        {
            item = proto_tree_add_item(ext_tree, hf_oss_ssdo_extpar_data, new_tvb, 16, dataLength - 16, ENC_NA );

            if ( ( dataLength - sodLength ) != 16 )
                expert_add_info ( pinfo, item, &ei_message_reassembly_size_differs_from_header );
        }
    }
    else
    {
        /* If == upload, it is most likely a par upload */
        if ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END && ( dataLength % 4 == 0 ) )
        {

            item = proto_tree_add_uint_format_value(ssdo_payload, hf_oss_ssdo_sod_index, new_tvb,
                                                    0, 0,  0x1018, "0x%04X (%s)", 0x1018,
                                                    val_to_str_const( ((guint32) (0x1018 << 16) ),
                                                                      sod_idx_names, "Unknown") );
            sod_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sodentry);
            PROTO_ITEM_SET_GENERATED(item);

            item = proto_tree_add_uint_format_value(sod_tree, hf_oss_ssdo_sod_subindex, new_tvb, 0, 0,
                                                             0x06, "0x%02X (%s)", 0x06,
                                                             val_to_str_const(((guint32) (0x1018 << 16) +  0x06),
                                                                                            sod_idx_names, "Unknown") );
            PROTO_ITEM_SET_GENERATED(item);

            entry = tvb_get_letohl ( new_tvb, 0 );
            proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_timestamp, new_tvb, 0,
                        4, entry, "0x%08X", entry );
            for ( n = 4; n < dataLength; n+=4 )
            {
                entry = tvb_get_letohl ( new_tvb, n );
                proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_checksum, new_tvb, (n ),
                        4, entry, "[#%d] 0x%08X", ( n / 4 ), entry );
            }
        }
        /* If != upload, it is most likely a 101A download */
        else
        {

            /* normal parameter set */
            for ( ctr = 0; ctr < dataLength; ctr++ )
            {
                ssdoIndex = tvb_get_letohs(new_tvb, ctr);
                ssdoSubIndex = tvb_get_guint8(new_tvb, ctr + 2);
                dispSSDOIndex = ssdoIndex;

                if ( ssdoIndex >= 0x1400 && ssdoIndex <= 0x17FE )
                    dispSSDOIndex = 0x1400;
                else if ( ssdoIndex >= 0x1800 && ssdoIndex <= 0x1BFE )
                    dispSSDOIndex = 0x1800;
                else if ( ssdoIndex >= 0x1C00 && ssdoIndex <= 0x1FFE )
                    dispSSDOIndex = 0x1C00;
                else if ( ssdoIndex >= 0xC000 && ssdoIndex <= 0xC3FE )
                    dispSSDOIndex = 0xC000;

                item = proto_tree_add_uint_format_value(ssdo_payload, hf_oss_ssdo_sod_index, new_tvb,
                                                        ctr, 2,  ssdoIndex, "0x%04X (%s)", ssdoIndex,
                                                        val_to_str_const( ((guint32) (dispSSDOIndex << 16) ),
                                                                          sod_idx_names, "Unknown") );
                if ( ssdoIndex != dispSSDOIndex )
                    PROTO_ITEM_SET_GENERATED ( item );

                if ( ssdoIndex < 0x1000 || ssdoIndex > 0xE7FF )
                    expert_add_info ( pinfo, item, &ei_payload_unknown_format );

                sod_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sodentry);

                if ( ssdoSubIndex != 0 )
                {
                    proto_tree_add_uint_format_value(sod_tree, hf_oss_ssdo_sod_subindex, new_tvb, ctr + 2, 1,
                                                 ssdoSubIndex, "0x%02X (%s)", ssdoSubIndex,
                                                 val_to_str_const(((guint32) (ssdoIndex << 16) + ssdoSubIndex),
                                                                                sod_idx_names, "Unknown") );
                }
                else
                    proto_tree_add_uint_format_value(sod_tree, hf_oss_ssdo_sod_subindex, new_tvb, ctr + 2, 1,
                                                 ssdoSubIndex, "0x%02X", ssdoSubIndex );
                ctr += 2;

                /* reading real size */
                sodLength = tvb_get_letohl ( new_tvb, ctr + 1 );
                if ( sodLength > (dataLength - ctr) )
                    sodLength = 0;

                if ( ( sodLength + 4 + ctr ) > dataLength )
                    break;

                if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x06 )
                {
                    entry = tvb_get_letohl ( new_tvb, ctr + 5 );
                    proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_timestamp, new_tvb, ctr + 5,
                                4, entry, "0x%08X", entry );
                    for ( n = 4; n < sodLength; n+=4 )
                    {
                        entry = tvb_get_letohl ( new_tvb, ctr + 5 + n );
                        proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_checksum, new_tvb, (ctr + 5 + n ),
                                4, entry, "[#%d] 0x%08X", ( n / 4 ), entry );
                    }
                } else if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x07 ) {
                    entry = tvb_get_letohl ( new_tvb, ctr + 5 );
                    proto_tree_add_uint_format_value ( sod_tree, hf_oss_sod_par_timestamp, new_tvb, ctr + 5,
                                4, entry, "0x%08X", entry );
                } else if ( ( dispSSDOIndex == OPENSAFETY_SOD_RXMAP || dispSSDOIndex == OPENSAFETY_SOD_TXMAP ) && ssdoSubIndex != 0x0 ) {
                    proto_tree_add_uint(sod_tree, hf_oss_ssdo_sodentry_size, new_tvb, ctr + 1, 4, sodLength );
                    item = proto_tree_add_item(sod_tree, hf_oss_ssdo_sodmapping, new_tvb, ctr + 5, sodLength, ENC_NA );
                    ext_tree = proto_item_add_subtree(item, ett_opensafety_sod_mapping);

                    proto_tree_add_item(ext_tree, hf_oss_ssdo_sodmapping_bits, new_tvb, ctr + 5, 1, ENC_NA);

                    entry = tvb_get_letohl ( new_tvb, ctr + 7 );
                    proto_tree_add_item(ext_tree, hf_oss_ssdo_sod_index, new_tvb, ctr + 7, 2, entry);
                    proto_tree_add_item(ext_tree, hf_oss_ssdo_sod_subindex, new_tvb, ctr + 6, 1, ENC_NA);

                } else {
                    proto_tree_add_uint(sod_tree, hf_oss_ssdo_sodentry_size, new_tvb, ctr + 1, 4, sodLength );
                    if ( sodLength > 0 )
                        proto_tree_add_item(sod_tree, hf_oss_ssdo_sodentry_data, new_tvb, ctr + 5, sodLength, ENC_NA );
                }
                ctr += sodLength + 4;
        }
        }
    }


}

static void
dissect_opensafety_ssdo_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        guint16 frameStart1, guint16 frameStart2, gboolean validSCMUDID, guint8 scm_udid[6])
{
    proto_item    *item;
    proto_tree    *ssdo_tree, *ssdo_payload, *ssdo_sacmd_tree;
    guint16        taddr                = 0, sdn = 0, server = 0, client = 0, n = 0, ct = 0;
    guint32        abortcode, ssdoIndex = 0, ssdoSubIndex = 0, payloadSize, fragmentId = 0, entry = 0;
    guint8         db0Offset, db0, sacmd, payloadOffset;
    guint          dataLength;
    gint           calcDataLength;
    gboolean       isResponse, decodePayload, isEndSegment, isSegmented, saveFragmented;
    tvbuff_t      *new_tvb              = NULL;
    fragment_head *frag_msg             = NULL;

    dataLength = tvb_get_guint8(message_tvb, OSS_FRAME_POS_LEN + frameStart1);
    decodePayload = FALSE;

    db0Offset = frameStart1 + OSS_FRAME_POS_DATA;
    db0 = tvb_get_guint8(message_tvb, db0Offset);
    sacmd = db0;
    ssdoIndex = 0;
    ssdoSubIndex = 0;

    if ( ( sacmd & OPENSAFETY_SSDO_SACMD_TGL ) == OPENSAFETY_SSDO_SACMD_TGL )
        sacmd = sacmd & ( ~OPENSAFETY_SSDO_SACMD_TGL );

    isResponse = ( ( OSS_FRAME_ID_T(message_tvb, frameStart1) & 0x04 ) == 0x04 );

    if ( validSCMUDID )
    {
        /* taddr is the 4th octet in the second frame */
        taddr = OSS_FRAME_ADDR_T2(message_tvb, frameStart2 + 3, scm_udid[3], scm_udid[4]);
        sdn =  ( OSS_FRAME_ADDR_T(message_tvb, frameStart1) ^
                        ( OSS_FRAME_ADDR_T2(message_tvb, frameStart2, scm_udid[0], scm_udid[1]) ) );

        PACKET_SENDER_RECEIVER ( pinfo, taddr, frameStart2 + 3, OSS_FRAME_ADDR_T(message_tvb, frameStart1),
                                 frameStart1, frameStart2, sdn );
    }
    else if ( ! isResponse )
    {
        PACKET_SENDER(pinfo, OSS_FRAME_ADDR_T(message_tvb, frameStart1), frameStart1, frameStart2,
                      -1 * ( ( OSS_FRAME_ADDR_T(message_tvb, frameStart1) ) ^ ( OSS_FRAME_ADDR_T2(message_tvb, frameStart2, scm_udid[0], scm_udid[1]) ) ) );
    }
    else if ( isResponse )
    {
        PACKET_RECEIVER(pinfo, OSS_FRAME_ADDR_T(message_tvb, frameStart1), frameStart1, frameStart2,
                        -1 * ( ( OSS_FRAME_ADDR_T(message_tvb, frameStart1) ) ^ ( OSS_FRAME_ADDR_T2(message_tvb, frameStart2, scm_udid[0], scm_udid[1]) ) ) );
    }

    if ( ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_REQUEST ) ||
         ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) )
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

    if ( ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SSDO_SERVICE_RESPONSE ) ||
         ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SSDO_SLIM_SERVICE_RESPONSE ) )
        proto_tree_add_boolean(ssdo_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else
        proto_tree_add_boolean(ssdo_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    proto_tree_add_uint_format_value(ssdo_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                     OSS_FRAME_ID_T(message_tvb, frameStart1),
                                     "%s", val_to_str_const(OSS_FRAME_ID_T(message_tvb, frameStart1), message_type_values, "Unknown") );


    if ( isResponse )
    {
        if ( validSCMUDID )
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart1, 2, OSS_FRAME_ADDR_T(message_tvb, frameStart1));
            client = OSS_FRAME_ADDR_T(message_tvb, frameStart1);
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart2 + 3, 2, taddr);
            server = taddr;
        }
        else
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart1, 2, OSS_FRAME_ADDR_T(message_tvb, frameStart1));
            client = OSS_FRAME_ADDR_T(message_tvb, frameStart1);
        }
    }
    else if ( ! isResponse )
    {
        if ( validSCMUDID )
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart1, 2, OSS_FRAME_ADDR_T(message_tvb, frameStart1));
            server = OSS_FRAME_ADDR_T(message_tvb, frameStart1);
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_client, message_tvb, frameStart2 + 3, 2, taddr);
            client = taddr;
        }
        else
        {
            proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_server, message_tvb, frameStart1, 2, OSS_FRAME_ADDR_T(message_tvb, frameStart1));
            server = OSS_FRAME_ADDR_T(message_tvb, frameStart1);
        }
    }

    item = proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sacmd, message_tvb, db0Offset, 1, sacmd);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", SACMD: %s", val_to_str_const(sacmd, ssdo_sacmd_values, " "));

    ssdo_sacmd_tree = proto_item_add_subtree(item, ett_opensafety_ssdo_sacmd);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_block_transfer, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_end_segment,    message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_initiate,       message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_toggle,         message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_segmentation,   message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_abort_transfer, message_tvb, db0Offset, 1, db0);
    proto_tree_add_boolean(ssdo_sacmd_tree, hf_oss_ssdo_sacmd_access_type,    message_tvb, db0Offset, 1, db0);

    payloadOffset = db0Offset + 1;

    ct = tvb_get_guint8(message_tvb, frameStart1 + 3);
    if ( validSCMUDID )
        ct = (guint16)((tvb_get_guint8(message_tvb, frameStart2 + 2) ^ scm_udid[2]) << 8) + (tvb_get_guint8(message_tvb, frameStart1 + 3));

    proto_tree_add_uint(ssdo_tree, hf_oss_ssdo_sano, message_tvb, frameStart1 + 3, 1, ct );

    /* When the following clause is met, DB1,2 contain the SOD index, and DB3 the SOD subindex */
    if ( ( ( sacmd & OPENSAFETY_SSDO_SACMD_INI ) == OPENSAFETY_SSDO_SACMD_INI ) &&
            ( sacmd != OPENSAFETY_MSG_SSDO_ABORT )
    )
    {
        ssdoIndex = tvb_get_letohs(message_tvb, db0Offset + 1);
        ssdoSubIndex = tvb_get_guint8(message_tvb, db0Offset + 3);

        proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_sod_index, message_tvb, db0Offset + 1, 2,
                ssdoIndex, "0x%04X (%s)", ssdoIndex,
                val_to_str_const(((guint32) (ssdoIndex << 16)), sod_idx_names, "Unknown") );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s", val_to_str_const(((guint32) (ssdoIndex << 16)), sod_idx_names, "Unknown"));

        /* Some SOD downloads (0x101A for instance) don't have sub-indeces */
        if ( ssdoSubIndex != 0x0 )
        {
            proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_sod_subindex, message_tvb, db0Offset + 3, 1,
                ssdoSubIndex, "0x%02X (%s)", ssdoSubIndex,
                val_to_str_const(((guint32) (ssdoIndex << 16) + ssdoSubIndex), sod_idx_names, "Unknown") );
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                    val_to_str_const(((guint32) (ssdoIndex << 16) + ssdoSubIndex), sod_idx_names, "Unknown"));
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "]" );
        payloadOffset += 3;
    }

    if ( sacmd == OPENSAFETY_MSG_SSDO_ABORT )
    {
        abortcode = tvb_get_letohl(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 4);

        proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_abort_code, message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 4, 4, abortcode,
                "0x%04X %04X - %s", (guint16)(abortcode >> 16), (guint16)(abortcode),
                val_to_str_const(abortcode, abort_codes, "Unknown"));
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(abortcode, abort_codes, "Unknown"));


    } else {

        /* Either the SSDO msg is a response, then data is sent by the server and only in uploads,
         * or the message is a request, then data is coming from the client and payload data is
         * sent in downloads */
        if ( ( isResponse && (sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED ||
                    sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED ||
                    sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE ||
                    sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END ) )||
                    ( !isResponse && (sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED ||
                    sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED ||
                    sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE ||
                    sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END ) ) )
                {
                   decodePayload = TRUE;
                }

        if ( decodePayload )
        {
            saveFragmented = pinfo->fragmented;
            if ( server != 0 && client != 0 )
                fragmentId = (guint32)((((guint32)client) << 16 ) + server );

            isSegmented = ( ( db0 & OPENSAFETY_SSDO_SACMD_SEG ) == OPENSAFETY_SSDO_SACMD_SEG );

            /* If payload data has to be calculated, either a total size is given, or not */
            if ( ( sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED ) ||
                    ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED )
                )
            {

                payloadOffset += 4;

                /* reading real size */
                payloadSize = tvb_get_letohl(message_tvb, payloadOffset - 4);

                calcDataLength = dataLength - (payloadOffset - db0Offset);

                item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, payloadOffset - 4, 4,
                        payloadSize, "%d octets total (%d octets in this frame)", payloadSize, calcDataLength);

                if ( fragmentId != 0 && isSegmented )
                {
                    pinfo->fragmented = TRUE;
                    frag_msg = fragment_add_seq_check(&os_reassembly_table, message_tvb, payloadOffset, pinfo,
                                                      fragmentId, NULL, 0, calcDataLength, TRUE );
                    fragment_add_seq_offset ( &os_reassembly_table, pinfo, fragmentId, NULL, ct );

                    if ( frag_msg != NULL )
                    {
                        item = proto_tree_add_bytes_format_value(ssdo_tree, hf_oss_ssdo_payload, message_tvb, 0, 0, NULL, "Reassembled" );
                        PROTO_ITEM_SET_GENERATED(item);

                        ssdo_payload = proto_item_add_subtree(item, ett_opensafety_ssdo_payload);
                        process_reassembled_data(message_tvb, 0, pinfo, "Reassembled Message", frag_msg, &oss_frag_items, NULL, ssdo_payload );
                    }
                }

                if ( (gint) calcDataLength >= (gint) 0 )
                {
                    proto_tree_add_item(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset, calcDataLength, ENC_NA );
                } else {
                    expert_add_info_format(pinfo, item, &ei_payload_length_not_positive,
                                                "Calculation for payload length yielded non-positive result [%d]", (guint) calcDataLength );
                }
            }
            else
            {
                isEndSegment = FALSE;
                if ( ( sacmd == OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END ) || ( sacmd == OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END ) )
                    isEndSegment = TRUE;

                payloadSize = dataLength - (payloadOffset - db0Offset);

                if ( fragmentId != 0 && isSegmented )
                {
                    pinfo->fragmented = TRUE;

                    frag_msg = fragment_add_seq_check(&os_reassembly_table, message_tvb, payloadOffset, pinfo,
                                                      fragmentId, NULL, ct,
                                                      payloadSize, isEndSegment ? FALSE : TRUE );
                }

                if ( frag_msg )
                {
                    item = proto_tree_add_bytes_format_value(ssdo_tree, hf_oss_ssdo_payload, message_tvb,
                                                             0, 0, NULL, "Reassembled" );
                    PROTO_ITEM_SET_GENERATED(item);
                    ssdo_payload = proto_item_add_subtree(item, ett_opensafety_ssdo_payload);

                    new_tvb = process_reassembled_data(message_tvb, 0, pinfo, "Reassembled Message", frag_msg,
                                                       &oss_frag_items, NULL, ssdo_payload );
                    if ( isEndSegment && new_tvb )
                    {
                        item = proto_tree_add_uint_format_value(ssdo_payload, hf_oss_ssdo_payload_size, message_tvb, 0, 0,
                                                                payloadSize, "%d octets (over all fragments)", frag_msg->len);
                        PROTO_ITEM_SET_GENERATED(item);

                        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)" );
                        dissect_ssdo_payload ( pinfo, new_tvb, ssdo_payload, sacmd );
                    }
                }
                else
                {
                    item = proto_tree_add_uint_format_value(ssdo_tree, hf_oss_ssdo_payload_size, message_tvb, 0, 0, payloadSize,
                            "%d octets", payloadSize);
                    PROTO_ITEM_SET_GENERATED(item);

                    if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x06 )
                    {
                        entry = tvb_get_letohl ( message_tvb, payloadOffset );
                        proto_tree_add_uint_format_value ( ssdo_tree, hf_oss_sod_par_timestamp, message_tvb, payloadOffset,
                                    4, entry, "0x%08X", entry );
                        for ( n = 4; n < payloadSize; n+=4 )
                        {
                            entry = tvb_get_letohl ( message_tvb, payloadOffset + n );
                            proto_tree_add_uint_format_value ( ssdo_tree, hf_oss_sod_par_checksum, message_tvb, (payloadOffset + n ),
                                    4, entry, "[#%d] 0x%08X", ( n / 4 ), entry );
                        }
                    } else if ( ssdoIndex == OPENSAFETY_SOD_DVI && ssdoSubIndex == 0x07 ) {
                        entry = tvb_get_letohl ( message_tvb, payloadOffset );
                        proto_tree_add_uint_format_value ( ssdo_tree, hf_oss_sod_par_timestamp, message_tvb, payloadOffset,
                                    4, entry, "0x%08X", entry );
                    } else
                        proto_tree_add_item(ssdo_tree, hf_oss_ssdo_payload, message_tvb, payloadOffset, payloadSize, ENC_NA );
                }
            }

            pinfo->fragmented = saveFragmented;
        }
    }
}

static void
dissect_opensafety_snmt_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
        guint16 frameStart1, guint16 frameStart2 )
{
    proto_item *item;
    proto_tree *snmt_tree;
    guint32     entry = 0;
    guint16     addr, taddr, sdn;
    guint8      db0, byte, errcode;
    guint       dataLength;
    char       *tempString;

    dataLength = OSS_FRAME_LENGTH_T(message_tvb, frameStart1);

    /* addr is the first field, as well as the recipient of the message */
    addr = OSS_FRAME_ADDR_T(message_tvb, frameStart1);
    /* taddr is the 4th octet in the second frame */
    taddr = OSS_FRAME_ADDR_T(message_tvb, frameStart2 + 3);
    /* domain is xor'ed on the first field in the second frame. As this is also addr, it is easy to obtain */
    sdn = OSS_FRAME_ADDR_T(message_tvb, frameStart2) ^ addr;

    db0 = -1;
    if (dataLength > 0)
        db0 = tvb_get_guint8(message_tvb, frameStart1 + OSS_FRAME_POS_DATA);

    if ( ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE) == 0 ) &&
         ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 || (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 ) )
    {
        PACKET_RECEIVER( pinfo, addr, OSS_FRAME_POS_ADDR + frameStart1, frameStart2, sdn );
    }
    else
    {
        PACKET_SENDER_RECEIVER ( pinfo, taddr, frameStart2 + 3, addr, OSS_FRAME_POS_ADDR + frameStart1,
                             frameStart2, sdn );
    }

    item = proto_tree_add_uint_format_value(opensafety_tree, hf_oss_msg_category, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                            OPENSAFETY_SNMT_MESSAGE_TYPE,
                                            "%s", val_to_str_const(OPENSAFETY_SNMT_MESSAGE_TYPE, message_id_values, "Unknown") );
    PROTO_ITEM_SET_GENERATED(item);

    snmt_tree = proto_item_add_subtree(item, ett_opensafety_snmt);

    if ( ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SNMT_RESPONSE_UDID ) ||
         ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SNMT_SADR_ASSIGNED ) ||
         ( OSS_FRAME_ID_T(message_tvb, frameStart1) == OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE ) )
        proto_tree_add_boolean(snmt_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_RESPONSE);
    else
        proto_tree_add_boolean(snmt_tree, hf_oss_msg_direction, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1, OPENSAFETY_REQUEST);

    proto_tree_add_uint_format_value(snmt_tree, hf_oss_msg, message_tvb, OSS_FRAME_POS_ID + frameStart1, 1,
                                     OSS_FRAME_ID_T(message_tvb, frameStart1),
                                     "%s", val_to_str_const(OSS_FRAME_ID_T(message_tvb, frameStart1), message_type_values, "Unknown") );

    if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_SN_RESET_GUARDING_SCM) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_RESPONSE) == 0 )
    {
        byte = tvb_get_guint8(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1);

        if ( ! ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 && byte == OPENSAFETY_ERROR_GROUP_ADD_PARAMETER ) )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1, db0);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(db0, message_service_type, "Unknown"));
        }
        else
        {
            proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1,
                    db0, "%s [Request via SN Fail] (0x%02X)", val_to_str_const(byte, sn_fail_error_group, "Unknown"), db0);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(byte, sn_fail_error_group, "Unknown"));
        }

        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_FAIL) == 0 )
        {
            /* Handle a normal SN Fail */
            if ( byte != OPENSAFETY_ERROR_GROUP_ADD_PARAMETER )
            {
                proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_error_group, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 1,
                        byte, "%s", ( byte == 0 ? "Device" : val_to_str(byte, sn_fail_error_group, "Reserved [%d]" ) ) );

                errcode = tvb_get_guint8(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 2);
                proto_tree_add_uint_format_value(snmt_tree, hf_oss_snmt_error_code, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 2, 1,
                        errcode, "%s [%d]", ( errcode == 0 ? "Default" : "Vendor Specific" ), errcode );

                col_append_fstr(pinfo->cinfo, COL_INFO, " - Group: %s; Code: %s",
                    ( byte == 0 ? "Device" : val_to_str(byte, sn_fail_error_group, "Reserved [%d]" ) ),
                    ( errcode == 0 ? "Default" : "Vendor Specific" )
                );
            }
            else
            {
                errcode = tvb_get_guint8(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 2);

                /* Handle an additional parameter request */
                proto_tree_add_uint(snmt_tree, hf_oss_ssdo_extpar_parset, message_tvb,
                        OSS_FRAME_POS_DATA + frameStart1 + 2, 1, ( errcode & 0x0F ) + 1 );

                proto_tree_add_boolean(snmt_tree, hf_oss_snmt_param_type, message_tvb,
                        OSS_FRAME_POS_DATA + frameStart1 + 2, 1, ( ( errcode & 0xF0 ) != 0xF0 ) );
            }
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_UDID_SCM) == 0 )
        {
            item = proto_tree_add_item(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6, ENC_NA);

            if ( global_scm_udid_autoset == TRUE )
            {
                tempString = (char *)wmem_alloc0(wmem_packet_scope(), 128 * sizeof(char));
                g_snprintf ( tempString, 18, "%s", tvb_bytes_to_ep_str_punct(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6, ':' ) );
                if ( memcmp ( global_scm_udid, tempString, 17 ) != 0 )
                {
                    local_scm_udid = (char *)wmem_alloc0(wmem_file_scope(), 18 * sizeof(char));
                    g_snprintf(local_scm_udid, 18, "%s", tempString );
                    expert_add_info_format(pinfo, item, &ei_scmudid_autodetected, "Auto detected payload as SCM UDID [%s].", local_scm_udid);
                }
            }

        }
        else if ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGNED_ADDITIONAL_SADR) == 0 )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addsaddr, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 2,
                    OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 1));

            proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addtxspdo, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 3, 2,
                    OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 3));

            col_append_fstr(pinfo->cinfo, COL_INFO, " [0x%04X => 0x%04X]",
                    OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 1),
                    OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 3));
        }
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_SERVICE_REQUEST) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_service_id, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 1, db0);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(db0, message_service_type, "Unknown"));

        if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_STOP) == 0 || (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SCM_SET_TO_OP) == 0 )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_scm, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_tool, message_tvb, frameStart2 + 3, 2, taddr);
        }
        else if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_ASSIGN_UDID_SCM) == 0 )
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);
            item = proto_tree_add_item(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6, ENC_NA);

            if ( global_scm_udid_autoset == TRUE )
            {
                tempString = (char *)wmem_alloc0(wmem_packet_scope(), 18 * sizeof(char));
                g_snprintf ( tempString, 18, "%s", tvb_bytes_to_ep_str_punct(message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 6, ':' ) );
                if ( memcmp ( global_scm_udid, tempString, 17 ) != 0 )
                {
                    local_scm_udid = (char *)wmem_alloc0(wmem_file_scope(), 18 * sizeof(char));
                    g_snprintf(local_scm_udid, 18, "%s", tempString );
                    expert_add_info_format(pinfo, item, &ei_scmudid_autodetected, "Auto detected payload as SCM UDID [%s].", tempString);
                }
            }

        }
        else
        {
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);
            proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);

            if ( (db0 ^ OPENSAFETY_MSG_SNMT_EXT_SN_SET_TO_OP) == 0 )
            {
                entry = tvb_get_letohl ( message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 1 );
                proto_tree_add_uint_format_value ( snmt_tree, hf_oss_sod_par_timestamp, message_tvb,
                        OSS_FRAME_POS_DATA + frameStart1 + 1, 4, entry, "0x%08X", entry );
            }
            else if ( ( db0 ^ OPENSAFETY_MSG_SNMT_EXT_ASSIGN_ADDITIONAL_SADR) == 0 )
            {
                proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addsaddr, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 1, 2,
                        OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 1));

                proto_tree_add_uint(snmt_tree, hf_oss_snmt_ext_addtxspdo, message_tvb, OSS_FRAME_POS_DATA + frameStart1 + 3, 2,
                        OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 3));

                col_append_fstr(pinfo->cinfo, COL_INFO, " [0x%04X => 0x%04X]",
                        OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 1),
                        OSS_FRAME_ADDR_T(message_tvb, frameStart1 + OSS_FRAME_POS_DATA + 3));
            }

        }
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_SADR_ASSIGNED) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_item(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6, ENC_NA);
    }
    else if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_ASSIGN_SADR) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);

        if (dataLength > 0)
            proto_tree_add_item(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6, ENC_NA);

    }
    else if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_RESPONSE_UDID) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, frameStart2 + 3, 2, taddr);

        if (dataLength > 0)
            proto_tree_add_item(snmt_tree, hf_oss_snmt_udid, message_tvb, OSS_FRAME_POS_DATA + frameStart1, 6, ENC_NA);

    }
    else if ( (OSS_FRAME_ID_T(message_tvb, frameStart1) ^ OPENSAFETY_MSG_SNMT_REQUEST_UDID) == 0 )
    {
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_master, message_tvb, frameStart2 + 3, 2, taddr);
        proto_tree_add_uint(snmt_tree, hf_oss_snmt_slave, message_tvb, OSS_FRAME_POS_ADDR + frameStart1, 2, addr);
    }
}

static gboolean
dissect_opensafety_checksum(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *opensafety_tree,
                            guint8 type, guint16 frameStart1, guint16 frameStart2 )
{
    guint16     frame1_crc, frame2_crc;
    guint16     calc1_crc, calc2_crc;
    guint       dataLength, frame2Length;
    guint8     *bytes, ctr = 0, crcType = OPENSAFETY_CHECKSUM_CRC8;
    proto_item *item;
    proto_tree *checksum_tree;
    gint        start;
    gint        length;
    gboolean    isSlim = FALSE;
    gboolean    isSNMT = FALSE;
    GByteArray *scmUDID = NULL;

    dataLength = OSS_FRAME_LENGTH_T(message_tvb, frameStart1);
    start = OSS_FRAME_POS_DATA + dataLength + frameStart1;

    if (OSS_FRAME_LENGTH_T(message_tvb, frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
        frame1_crc = tvb_get_letohs(message_tvb, start);
    else
        frame1_crc = tvb_get_guint8(message_tvb, start);

    if ( type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
        isSlim = TRUE;
    if ( type == OPENSAFETY_SNMT_MESSAGE_TYPE )
        isSNMT = TRUE;

    frame2Length = (isSlim ? 0 : dataLength) + 5;

    length = (dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OPENSAFETY_CHECKSUM_CRC16 : OPENSAFETY_CHECKSUM_CRC8);
    item = proto_tree_add_uint_format(opensafety_tree, hf_oss_crc, message_tvb, start, length, frame1_crc,
                                      "CRC for subframe #1: 0x%04X", frame1_crc);

    checksum_tree = proto_item_add_subtree(item, ett_opensafety_checksum);

    bytes = (guint8*)tvb_memdup(wmem_packet_scope(), message_tvb, frameStart1, dataLength + 4);
    if ( dataLength > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
    {
        calc1_crc = crc16_0x755B(bytes, dataLength + 4, 0);
        if ( frame1_crc == calc1_crc )
            crcType = OPENSAFETY_CHECKSUM_CRC16;
        if ( frame1_crc != calc1_crc )
        {
            calc1_crc = crc16_0x5935(bytes, dataLength + 4, 0);
            if ( frame1_crc == calc1_crc )
            {
                crcType = OPENSAFETY_CHECKSUM_CRC16SLIM;
                if ( ! isSlim )
                    expert_add_info(pinfo, item, &ei_crc_slimssdo_instead_of_spdo );
            }
        }
    }
    else
        calc1_crc = crc8_0x2F(bytes, dataLength + 4, 0);

    item = proto_tree_add_boolean(checksum_tree, hf_oss_crc_valid, message_tvb,
            frameStart1, dataLength + 4, (frame1_crc == calc1_crc));
    PROTO_ITEM_SET_GENERATED(item);
    if ( frame1_crc != calc1_crc )
        expert_add_info(pinfo, item, &ei_crc_frame_1_invalid );

    /* using the defines, as the values can change */
    proto_tree_add_uint(checksum_tree, hf_oss_crc_type, message_tvb, start, length, crcType );

    start = frameStart2 + (isSlim ? 5 : dataLength + OSS_FRAME_POS_DATA + 1 );
    if (OSS_FRAME_LENGTH_T(message_tvb, frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8)
        frame2_crc = tvb_get_letohs(message_tvb, start);
    else
        frame2_crc = tvb_get_guint8(message_tvb, start);

    /* 0xFFFF is an invalid CRC16 value, therefore valid for initialization */
    calc2_crc = 0xFFFF;

    if ( global_calculate_crc2 )
    {
        bytes = (guint8*)tvb_memdup(wmem_packet_scope(), message_tvb, frameStart2, frame2Length + length);

        /* SLIM SSDO messages, do not contain a payload in frame2 */
        if ( isSlim == TRUE )
            dataLength = 0;

        scmUDID = g_byte_array_new();
        if ( isSNMT || ( hex_str_to_bytes((local_scm_udid != NULL ? local_scm_udid : global_scm_udid), scmUDID, TRUE) && scmUDID->len == 6 ) )
        {
            if ( !isSNMT )
            {
                for ( ctr = 0; ctr < 6; ctr++ )
                    bytes[ctr] = bytes[ctr] ^ (guint8)(scmUDID->data[ctr]);

                /*
                 * If the second frame is 6 or 7 (slim) bytes in length, we have to decode the found
                 * frame crc again. This must be done using the byte array, as the unxor operation
                 * had to take place.
                 */
                if ( dataLength == 0 )
                    frame2_crc = ( ( isSlim && length == 2 ) ? ( ( bytes[6] << 8 ) + bytes[5] ) : bytes[5] );
            }

            item = proto_tree_add_uint_format(opensafety_tree, hf_oss_crc, message_tvb, start, length, frame2_crc,
                    "CRC for subframe #2: 0x%04X", frame2_crc);

            checksum_tree = proto_item_add_subtree(item, ett_opensafety_checksum);

            if ( OSS_FRAME_LENGTH_T(message_tvb, frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 )
            {
                calc2_crc = crc16_0x755B(bytes, frame2Length, 0);
                if ( frame2_crc != calc2_crc )
                    calc2_crc = crc16_0x5935(bytes, frame2Length, 0);
            }
            else
                calc2_crc = crc8_0x2F(bytes, frame2Length, 0);

            item = proto_tree_add_boolean(checksum_tree, hf_oss_crc2_valid, message_tvb,
                    frameStart2, frame2Length, (frame2_crc == calc2_crc));
            PROTO_ITEM_SET_GENERATED(item);

            if ( frame2_crc != calc2_crc )
            {
                item = proto_tree_add_uint_format(checksum_tree, hf_oss_crc, message_tvb,
                        frameStart2, frame2Length, calc2_crc, "Calculated CRC: 0x%04X", calc2_crc);
                PROTO_ITEM_SET_GENERATED(item);
                expert_add_info(pinfo, item, &ei_crc_frame_2_invalid );
            }
        }
        else
            expert_add_info(pinfo, item, &ei_crc_frame_2_unknown_scm_udid );
    }

    /* For a correct calculation of the second crc we need to know the scm udid.
     * If the dissection of the second frame has been triggered, we integrate the
     * crc for frame2 into the result */
    return (gboolean) (frame1_crc == calc1_crc) && ( global_calculate_crc2 == TRUE ? (frame2_crc == calc2_crc) : TRUE);
}

static gboolean
dissect_opensafety_message(guint16 frameStart1, guint16 frameStart2, guint8 type,
                           tvbuff_t *message_tvb, packet_info *pinfo,
                           proto_item *opensafety_item, proto_tree *opensafety_tree, guint8 u_nrInPackage)
{
    guint8      b_ID, ctr;
    guint8      scm_udid[6];
    GByteArray *scmUDID = NULL;
    gboolean    validSCMUDID;
    proto_item *item;
    gboolean    messageTypeUnknown, crcValid;

    messageTypeUnknown = FALSE;

    for ( ctr = 0; ctr < 6; ctr++ )
        scm_udid[ctr] = 0;

    b_ID = OSS_FRAME_ID_T(message_tvb, frameStart1);
    /* Clearing connection valid bit */
    if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
        b_ID = b_ID & 0xF8;

    col_append_fstr(pinfo->cinfo, COL_INFO, (u_nrInPackage > 1 ? " | %s" : "%s" ),
            val_to_str(b_ID, message_type_values, "Unknown Message (0x%02X) "));

    {
        if ( type == OPENSAFETY_SNMT_MESSAGE_TYPE )
        {
            dissect_opensafety_snmt_message ( message_tvb, pinfo, opensafety_tree, frameStart1, frameStart2 );
        }
        else
        {
            validSCMUDID = FALSE;
            scmUDID = g_byte_array_new();

            if ( hex_str_to_bytes((local_scm_udid != NULL ? local_scm_udid : global_scm_udid), scmUDID, TRUE) && scmUDID->len == 6 )
            {
                validSCMUDID = TRUE;

                /* Now confirm, that the xor operation was successful. The ID fields of both frames have to be the same */
                b_ID = OSS_FRAME_ID_T(message_tvb, frameStart2) ^ (guint8)(scmUDID->data[OSS_FRAME_POS_ID]);

                if ( ( OSS_FRAME_ID_T(message_tvb, frameStart1) ^ b_ID ) != 0 )
                    validSCMUDID = FALSE;
                else
                    for ( ctr = 0; ctr < 6; ctr++ )
                        scm_udid[ctr] = scmUDID->data[ctr];
            }

            if ( strlen ( (local_scm_udid != NULL ? local_scm_udid : global_scm_udid) ) > 0  && scmUDID->len == 6 )
            {
                if ( local_scm_udid != NULL )
                {
                    item = proto_tree_add_string(opensafety_tree, hf_oss_scm_udid_auto, message_tvb, 0, 0, local_scm_udid);
                    if ( ! validSCMUDID )
                        expert_add_info(pinfo, item, &ei_message_id_field_mismatch );
                }
                else
                    item = proto_tree_add_string(opensafety_tree, hf_oss_scm_udid, message_tvb, 0, 0, global_scm_udid);
                PROTO_ITEM_SET_GENERATED(item);
            }

            item = proto_tree_add_boolean(opensafety_tree, hf_oss_scm_udid_valid, message_tvb, 0, 0, validSCMUDID);
            if ( scmUDID->len != 6 )
                expert_add_info(pinfo, item, &ei_scmudid_invalid_preference );
            PROTO_ITEM_SET_GENERATED(item);

            g_byte_array_free( scmUDID, TRUE);

            if ( type == OPENSAFETY_SSDO_MESSAGE_TYPE || type == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
            {
                dissect_opensafety_ssdo_message ( message_tvb, pinfo, opensafety_tree, frameStart1, frameStart2, validSCMUDID, scm_udid );
            }
            else if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                dissect_opensafety_spdo_message ( message_tvb, pinfo, opensafety_tree, frameStart1, frameStart2, validSCMUDID, scm_udid );
            }
            else
            {
                messageTypeUnknown = TRUE;
            }
        }

        crcValid = FALSE;
        item = proto_tree_add_uint(opensafety_tree, hf_oss_length,
                                   message_tvb, OSS_FRAME_POS_LEN + frameStart1, 1, OSS_FRAME_LENGTH_T(message_tvb, frameStart1));
        if ( messageTypeUnknown )
        {
            expert_add_info(pinfo, item, &ei_message_unknown_type );
        }
        else
        {
            crcValid = dissect_opensafety_checksum ( message_tvb, pinfo, opensafety_tree, type, frameStart1, frameStart2 );
        }

        /* with SNMT's we can check if the ID's for the frames match. Rare randomized packages do have
         * an issue, where an frame 1 can be valid. The id's for both frames must differ, as well as
         * the addresses, but addresses won't be checked yet, as there are issues with SDN xored on it. */
        if ( crcValid && type == OPENSAFETY_SNMT_MESSAGE_TYPE )
        {
            if ( OSS_FRAME_ID_T(message_tvb, frameStart1) != OSS_FRAME_ID_T(message_tvb, frameStart2) )
                expert_add_info(pinfo, opensafety_item, &ei_crc_frame_1_valid_frame2_invalid );
        }
    }

    return TRUE;
}

static gboolean
opensafety_package_dissector(const gchar *protocolName, const gchar *sub_diss_handle,
                             gboolean b_frame2First, gboolean do_byte_swap, guint8 force_nr_in_package,
                             tvbuff_t *given_tvb, packet_info *pinfo, proto_tree *tree, guint8 transporttype )
{
    tvbuff_t           *next_tvb = NULL, *gap_tvb = NULL, *message_tvb = NULL;
    guint               length, len, frameOffset, frameLength, nodeAddress, gapStart;
    guint8             *swbytes;
    gboolean            handled, dissectorCalled, call_sub_dissector, markAsMalformed;
    guint8              type, found, i, tempByte;
    guint16             frameStart1, frameStart2, byte_offset;
    gint                reported_len;
    dissector_handle_t  protocol_dissector = NULL;
    proto_item         *opensafety_item;
    proto_tree         *opensafety_tree;

    handled            = FALSE;
    dissectorCalled    = FALSE;
    call_sub_dissector = FALSE;
    markAsMalformed    = FALSE;

    /* registering frame end routine, to prevent a malformed dissection preventing
     * further dissector calls (see bug #6950) */
    register_frame_end_routine(pinfo, reset_dissector);

    length = tvb_reported_length(given_tvb);
    /* Minimum package length is 11 */
    if ( length < OSS_MINIMUM_LENGTH )
        return FALSE;

    /* Determine dissector handle for sub-dissection */
    if ( strlen( sub_diss_handle ) > 0 )
    {
        call_sub_dissector = TRUE;
        protocol_dissector = find_dissector ( sub_diss_handle );
        if ( protocol_dissector == NULL )
            protocol_dissector = data_dissector;
    }

    reported_len = tvb_reported_length_remaining(given_tvb, 0);

    /* This will swap the bytes according to MBTCP encoding */
    if ( do_byte_swap == TRUE && global_mbtcp_big_endian == TRUE )
    {
        /* Because of padding bytes at the end of the frame, tvb_memdup could lead
         * to a "openSAFETY truncated" message. By ensuring, that we have enough
         * bytes to copy, this will be prevented. */
        if ( ! tvb_bytes_exist ( given_tvb, 0, length ) )
            return FALSE;

        swbytes = (guint8 *) tvb_memdup( pinfo->pool, given_tvb, 0, length);

        /* Wordswapping for modbus detection */
        /* Only a even number of bytes can be swapped */
        len = (length / 2);
        for ( i = 0; i < len; i++ )
        {
            tempByte = swbytes [ 2 * i ]; swbytes [ 2 * i ] = swbytes [ 2 * i + 1 ]; swbytes [ 2 * i + 1 ] = tempByte;
        }

        message_tvb = tvb_new_real_data(swbytes, length, reported_len);
    } else {
        message_tvb = given_tvb;
    }

    frameOffset = 0;
    frameLength = 0;
    found = 0;

    /* Counter to determine gaps between openSAFETY packages */
    gapStart = 0;

    while ( frameOffset < length )
    {
        /* Reset the next_tvb buffer */
        next_tvb = NULL;

        /* Smallest possible frame size is 11 */
        if ( tvb_length_remaining(message_tvb, frameOffset ) < OSS_MINIMUM_LENGTH )
            break;

        /* Finding the start of the first possible safety frame */
        if ( findSafetyFrame(message_tvb, frameOffset, b_frame2First, &frameOffset, &frameLength) )
        {
            /* frameLength is calculated/read directly from the dissected data. If frameLenght and frameOffset together
             * are bigger than the reported length, the package is not really an openSAFETY package */
            if ( ( frameOffset + frameLength ) > (guint)reported_len )
                break;

            found++;

            byte_offset = ( b_frame2First ? 0 : frameOffset );
            /* We determine a possible position for frame 1 and frame 2 */
            if ( b_frame2First )
            {
                frameStart1 = findFrame1Position (message_tvb, byte_offset, frameLength, FALSE );
                frameStart2 = 0;
            }
            else
            {
                frameStart1 = 0;
                frameStart2 = ((OSS_FRAME_LENGTH_T(message_tvb, byte_offset + frameStart1) - 1) +
                        (OSS_FRAME_LENGTH_T(message_tvb, byte_offset + frameStart1) > OSS_PAYLOAD_MAXSIZE_FOR_CRC8 ? OSS_SLIM_FRAME2_WITH_CRC16 : OSS_SLIM_FRAME2_WITH_CRC8));
            }

            /* If both frame starts are equal, something went wrong. In which case, we retract the found entry, and
             * also increase the search offset, just doing a continue will result in an infinite loop. */
            if (frameStart1 == frameStart2)
            {
                found--;
                frameOffset += frameLength;
                continue;
            }

            /* We determine the possible type, and return false, if there could not be one */
            if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                type = OPENSAFETY_SSDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                type = OPENSAFETY_SPDO_MESSAGE_TYPE;
            else if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                type = OPENSAFETY_SNMT_MESSAGE_TYPE;
            else
            {
                /* This is an invalid openSAFETY package, but it could be an undetected slim ssdo message. This specific error
                 * will only occur, if findFrame1Position is in play. So we search once more, but this time calculating the CRC.
                 * The reason for the second run is, that calculating the CRC is time consuming.  */
                if ( b_frame2First )
                {
                    /* Now let's check again, but this time calculate the CRC */
                    frameStart1 = findFrame1Position(message_tvb, ( b_frame2First ? 0 : frameOffset ), frameLength, TRUE );
                    frameStart2 = 0;

                    if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE;
                    else if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SSDO_MESSAGE_TYPE ) == OPENSAFETY_SSDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SSDO_MESSAGE_TYPE;
                    else if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SPDO_MESSAGE_TYPE ) == OPENSAFETY_SPDO_MESSAGE_TYPE )
                        type = OPENSAFETY_SPDO_MESSAGE_TYPE;
                    else if ( ( OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) & OPENSAFETY_SNMT_MESSAGE_TYPE ) == OPENSAFETY_SNMT_MESSAGE_TYPE )
                        type = OPENSAFETY_SNMT_MESSAGE_TYPE;
                    else {
                        /* Skip this frame.  We cannot continue without
                           advancing frameOffset - just doing a continue
                           will result in an infinite loop. Advancing with 1 will
                           lead to infinite loop, advancing with frameLength might miss
                           some packages*/
                        frameOffset += 2;
                        found--;
                        continue;
                    }
                } else {
                    /* As stated above, you cannot just continue
                       without advancing frameOffset. Advancing with 1 will
                       lead to infinite loop, advancing with frameLength might miss
                       some packages*/
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* Sorting messages for transporttype */
            if ( global_classify_transport && transporttype != 0 )
            {
                /* Cyclic data is transported via SPDOs and acyclic is transported via SNMT, SSDO. Everything
                 * else is misclassification */
                if ( ( transporttype == OPENSAFETY_ACYCLIC_DATA && type == OPENSAFETY_SPDO_MESSAGE_TYPE ) ||
                        ( transporttype == OPENSAFETY_CYCLIC_DATA && type != OPENSAFETY_SPDO_MESSAGE_TYPE ) )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* Some faulty packages do indeed have a valid first frame, but the second is
             * invalid. These checks should prevent most faulty detections */
            if ( type != OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                /* Is the given type at least known? */
                gint idx = -1;
                try_val_to_str_idx(OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1), message_type_values, &idx );
                /* Unknown Frame Type */
                if ( idx < 0 )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
                /* Frame IDs do not match */
                else if ( type == OPENSAFETY_SNMT_MESSAGE_TYPE &&
                        (OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart1) != OSS_FRAME_ID_T(message_tvb, byte_offset + frameStart2)) )
                {
                    frameOffset += 2;
                    found--;
                    continue;
                }
            }

            /* If this package is not valid, the next step, which normally occurs in unxorFrame will lead to a
             * frameLength bigger than the maximum data size. This is an indicator, that the package in general
             * is fault, and therefore we return false. Increasing the frameOffset will lead to out-of-bounds
             * for tvb_* functions. And frameLength errors are misidentified packages most of the times anyway */
            if ( ( (gint)frameLength - (gint)( frameStart2 > frameStart1 ? frameStart2 : frameLength - frameStart1 ) ) < 0 )
                return FALSE;

            /* Some SPDO based sanity checks, still a lot of faulty SPDOs remain, because they
             * cannot be filtered, without throwing out too many positives. */
            if ( type == OPENSAFETY_SPDO_MESSAGE_TYPE )
            {
                /* Checking if there is a node address set, or the package is invalid. Some PRes
                 * messages in EPL may double as valid subframes 1. If the nodeAddress is out of
                 * range, the package is marked as malformed */
                nodeAddress = OSS_FRAME_ADDR_T(message_tvb, byte_offset + frameStart1);
                if ( nodeAddress == 0 || nodeAddress > 1024 ) {
                    markAsMalformed = TRUE;
                }
            }

            /* From here on, the package should be correct. Even if it is not correct, it will be dissected
             * anyway and marked as malformed. Therefore it can be assumed, that a gap will end here.
             */
            if ( global_display_intergap_data == TRUE && gapStart != frameOffset )
            {
                /* Storing the gap data in subset, and calling the data dissector to display it */
                gap_tvb = tvb_new_subset(message_tvb, gapStart, (frameOffset - gapStart), reported_len);
                call_dissector(data_dissector, gap_tvb, pinfo, tree);
            }
            /* Setting the gap to the next offset */
            gapStart = frameOffset + frameLength;

            /* Adding second data source */
            next_tvb = tvb_new_subset ( message_tvb, frameOffset, frameLength, reported_len );
            /* Adding a visual aid to the dissector tree */
            add_new_data_source(pinfo, next_tvb, "openSAFETY Frame");

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
                col_clear(pinfo->cinfo, COL_INFO);
            }

            /* if the tree is NULL, we are called for the overview, otherwise for the
               more detailed view of the package */
            if ( tree )
            {
                /* create the opensafety protocol tree */
                opensafety_item = proto_tree_add_item(tree, proto_opensafety, message_tvb, frameOffset, frameLength, ENC_NA);
                opensafety_tree = proto_item_add_subtree(opensafety_item, ett_opensafety);
            } else {
                opensafety_item = NULL;
                opensafety_tree = NULL;
            }

            if ( dissect_opensafety_message(frameStart1, frameStart2, type, next_tvb, pinfo, opensafety_item, opensafety_tree, found) != TRUE )
                markAsMalformed = TRUE;

            if ( tree && markAsMalformed )
            {
                if ( OSS_FRAME_ADDR_T(message_tvb, byte_offset + frameStart1) > 1024 )
                    expert_add_info(pinfo, opensafety_item, &ei_message_spdo_address_invalid );
            }

            /* Something is being displayed, therefore this dissector returns true */
            handled = TRUE;
        }
        else
            break;

        frameOffset += frameLength;
    }

    if ( handled == TRUE )
    {
        /* There might be some undissected data at the end of the frame (e.g. SercosIII) */
        if ( frameOffset < length && global_display_intergap_data == TRUE && gapStart != frameOffset )
        {
            /* Storing the gap data in subset, and calling the data dissector to display it */
            gap_tvb = tvb_new_subset(message_tvb, gapStart, (length - gapStart), reported_len);
            call_dissector(data_dissector, gap_tvb, pinfo, tree);
        }
    }

    return ( handled ? TRUE : FALSE );
}

static gboolean
dissect_opensafety_epl(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    gboolean        result     = FALSE;
    proto_tree      *epl_tree = NULL;
    guint8  epl_msgtype = 0;

    if ( ! global_enable_plk )
        return result;

    /* We will call the epl dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( bDissector_Called_Once_Before == FALSE )
    {
        bDissector_Called_Once_Before = TRUE;

        /* Set the tree up, until it is par with the top-level */
        epl_tree = tree;
        while ( epl_tree != NULL && epl_tree->parent != NULL )
            epl_tree = epl_tree->parent;

        /* Ordering message type to traffic types */
        if ( *((guint8*)data) == 0x03 || *((guint8*)data) == 0x04 )
            epl_msgtype = OPENSAFETY_CYCLIC_DATA;
        else
            epl_msgtype = OPENSAFETY_ACYCLIC_DATA;

        /* We check if we have a asynchronous message, or a synchronoues message. In case of
         * asynchronous messages, SPDO packages are not valid. */

        result = opensafety_package_dissector("openSAFETY/Powerlink", "",
                FALSE, FALSE, 0, message_tvb, pinfo, epl_tree, epl_msgtype );

        bDissector_Called_Once_Before = FALSE;
    }

    return result;
}


static gboolean
dissect_opensafety_siii(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gboolean        result     = FALSE;
    guint8          firstByte;

    if ( ! global_enable_siii )
        return result;

    if ( pinfo->ipproto == IP_PROTO_UDP )
    {
        return  opensafety_package_dissector("openSAFETY/SercosIII UDP", "", FALSE, FALSE, 0,
                message_tvb, pinfo, tree, OPENSAFETY_ACYCLIC_DATA );
    }

    /* We can assume to have a SercosIII package, as the SercosIII dissector won't detect
     * SercosIII-UDP packages, this is most likely SercosIII-over-ethernet */

    /* We will call the SercosIII dissector by using call_dissector(). The SercosIII dissector will
     * then call the heuristic openSAFETY dissector again. By setting this information, we prevent
     * a dissector loop. */
    if ( bDissector_Called_Once_Before == FALSE )
    {
        bDissector_Called_Once_Before = TRUE;
        /* No frames can be sent in AT messages, therefore those get filtered right away */
        firstByte = ( tvb_get_guint8(message_tvb, 0) << 1 );
        if ( ( firstByte & 0x40 ) == 0x40 )
        {
            result = opensafety_package_dissector("openSAFETY/SercosIII", "sercosiii",
                          FALSE, FALSE, 0, message_tvb, pinfo, tree, OPENSAFETY_CYCLIC_DATA );
        }
        bDissector_Called_Once_Before = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_pn_io(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gboolean        result     = FALSE;

    if ( ! global_enable_pnio )
        return result;

    /* We will call the pn_io dissector by using call_dissector(). The epl dissector will then call
     * the heuristic openSAFETY dissector again. By setting this information, we prevent a dissector
     * loop */
    if ( bDissector_Called_Once_Before == FALSE )
    {
        bDissector_Called_Once_Before = TRUE;
        result = opensafety_package_dissector("openSAFETY/Profinet IO", "pn_io",
                                              FALSE, FALSE, 0, message_tvb, pinfo, tree, 0);
        bDissector_Called_Once_Before = FALSE;
    }

    return result;
}

static gboolean
dissect_opensafety_mbtcp(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    if ( ! global_enable_mbtcp )
        return FALSE;

    /* When Modbus/TCP gets dissected, openSAFETY would be sorted as a child protocol. Although,
     * this behaviour is technically correct, it differs from other implemented IEM protocol handlers.
     * Therefore, the openSAFETY frame gets put one up, if the parent is not NULL */
    return opensafety_package_dissector("openSAFETY/Modbus TCP", "", FALSE, TRUE, 0,
                                        message_tvb, pinfo, ( ((tree != NULL) && (tree->parent != NULL)) ? tree->parent : tree ), 0);
}

static gboolean
dissect_opensafety_udpdata(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gboolean       result   = FALSE;
    static guint32 frameNum = 0;
    static guint32 frameIdx = 0;

    if ( ! global_enable_udp )
        return result;

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
                                          "", pinfo->destport == UDP_PORT_SIII ? global_siii_udp_frame2_first : global_udp_frame2_first,
                                          FALSE, frameIdx, message_tvb, pinfo, tree,
                                          pinfo->destport == UDP_PORT_SIII ? OPENSAFETY_ACYCLIC_DATA : 0 );

    if ( result )
        frameIdx++;

    return result;
}

static void
apply_prefs ( void )
{
    static gboolean opensafety_init = FALSE;
    static guint    opensafety_udp_port_number;
    static guint    opensafety_udp_siii_port_number;

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
        { &hf_oss_scm_udid,
          { "SCM UDID Configured",    "opensafety.scm_udid",
            FT_STRING,   BASE_NONE, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_scm_udid_auto,
          { "SCM UDID Auto Detect",    "opensafety.scm_udid.auto",
            FT_STRING,   BASE_NONE, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_scm_udid_valid,
          { "SCM UDID Valid",    "opensafety.scm_udid.valid",
            FT_BOOLEAN,   BASE_NONE, NULL,   0x0, NULL, HFILL } },

        { &hf_oss_msg,
          { "Message",    "opensafety.msg.id",
            FT_UINT8,   BASE_HEX, VALS(message_type_values),   0x0, NULL, HFILL } },
        { &hf_oss_msg_category,
          { "Type",  "opensafety.msg.type",
            FT_UINT16,   BASE_HEX, VALS(message_id_values),   0x0, NULL, HFILL } },
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
          { "SN send from",  "opensafety.msg.sender",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_msg_receiver,
          { "SN send to",  "opensafety.msg.receiver",
            FT_UINT16,   BASE_HEX, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_length,
          { "Length",    "opensafety.length",
            FT_UINT8,   BASE_DEC, NULL,     0x0, NULL, HFILL } },
        { &hf_oss_crc,
          { "CRC",       "opensafety.crc.data",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        { &hf_oss_crc_valid,
          { "Is Valid", "opensafety.crc.valid",
            FT_BOOLEAN, BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_crc_type,
          { "CRC Type",  "opensafety.crc.type",
            FT_UINT8,   BASE_DEC, VALS(message_crc_type),    0x0, NULL, HFILL } },
        { &hf_oss_crc2_valid,
          { "Is Valid", "opensafety.crc2.valid",
            FT_BOOLEAN, BASE_NONE, NULL,    0x0, NULL, HFILL } },

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
        { &hf_oss_snmt_service_id,
          { "Extended Service ID",   "opensafety.snmt.service_id",
            FT_UINT8,  BASE_HEX, VALS(message_service_type),    0x0, NULL, HFILL } },
        { &hf_oss_snmt_error_group,
          { "Error Group",   "opensafety.snmt.error_group",
            FT_UINT8,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_error_code,
          { "Error Code",   "opensafety.snmt.error_code",
            FT_UINT8,  BASE_DEC, NULL,   0x0, NULL, HFILL } },
        { &hf_oss_snmt_param_type,
          { "Parameter Request Type",   "opensafety.snmt.parameter_type",
            FT_BOOLEAN,  BASE_NONE, TFS(&opensafety_addparam_request),   0x0, NULL, HFILL } },
        { &hf_oss_snmt_ext_addsaddr,
          { "Additional SADDR",    "opensafety.snmt.additional.saddr",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_snmt_ext_addtxspdo,
          { "Additional TxSPDO",    "opensafety.snmt.additional.txspdo",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        /* SSDO Specific fields */
        { &hf_oss_ssdo_server,
          { "SSDO Server", "opensafety.ssdo.master",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_client,
          { "SSDO Client", "opensafety.ssdo.client",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sano,
          { "SOD Access Request Number", "opensafety.ssdo.sano",
            FT_UINT16,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sacmd,
          { "SOD Access Command", "opensafety.ssdo.sacmd",
            FT_UINT8,  BASE_HEX, VALS(ssdo_sacmd_values),    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sod_index,
          { "SOD Index", "opensafety.ssdo.sodentry.index",
            FT_UINT16,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sod_subindex,
          { "SOD Sub Index", "opensafety.ssdo.sodentry.subindex",
            FT_UINT8,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_payload,
          { "SOD Payload", "opensafety.ssdo.payload",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_payload_size,
          { "SOD Payload Size", "opensafety.ssdo.payloadsize",
            FT_UINT32,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sodentry_size,
          { "SOD Entry Size", "opensafety.ssdo.sodentry.size",
            FT_UINT32,  BASE_DEC, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sodentry_data,
          { "SOD Data", "opensafety.ssdo.sodentry.data",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL } },
        { &hf_oss_sod_par_timestamp,
          { "Parameter Timestamp", "opensafety.sod.parameter.timestamp",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_sod_par_checksum,
          { "Parameter Checksum", "opensafety.sod.parameter.checksum",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_oss_ssdo_sodmapping,
          { "Mapping entry", "opensafety.sod.mapping",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_sodmapping_bits,
          { "Mapping size", "opensafety.sod.mapping.bits",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_oss_ssdo_extpar_parset,
          { "Additional Parameter Set", "opensafety.ssdo.extpar.setnr",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_version,
          { "Parameter Set Version", "opensafety.ssdo.extpar.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_saddr,
          { "Parameter Set for SADDR", "opensafety.ssdo.extpar.saddr",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_length,
          { "Parameter Set Length", "opensafety.ssdo.extpar.length",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_crc,
          { "Parameter Set CRC", "opensafety.ssdo.extpar.crc",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_tstamp,
          { "Timestamp", "opensafety.ssdo.extpar.timestamp",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar_data,
          { "Ext. Parameter Data", "opensafety.ssdo.extpar.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_oss_ssdo_extpar,
          { "Ext. Parameter", "opensafety.ssdo.extpar",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        {&hf_oss_fragments,
         {"Message fragments", "opensafety.ssdo.fragments",
          FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment,
         {"Message fragment", "opensafety.ssdo.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_overlap,
         {"Message fragment overlap", "opensafety.ssdo.fragment.overlap",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "opensafety.ssdo.fragment.overlap.conflicts",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_multiple_tails,
         {"Message has multiple tail fragments", "opensafety.ssdo.fragment.multiple_tails",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_too_long_fragment,
         {"Message fragment too long", "opensafety.ssdo.fragment.too_long_fragment",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_error,
         {"Message defragmentation error", "opensafety.ssdo.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_fragment_count,
         {"Message fragment count", "opensafety.ssdo.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_reassembled_in,
         {"Reassembled in", "opensafety.ssdo.reassembled.in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_reassembled_length,
         {"Reassembled length", "opensafety.ssdo.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_oss_reassembled_data,
         {"Reassembled Data", "opensafety.ssdo.reassembled.data",
          FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

#if 0
        { &hf_oss_ssdo_inhibit_time,
          { "Inhibit Time", "opensafety.ssdo.inhibittime",
            FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },
#endif
        { &hf_oss_ssdo_abort_code,
          { "Abort Code", "opensafety.ssdo.abortcode",
            FT_UINT32,  BASE_HEX, NULL,    0x0, NULL, HFILL } },

        /* SSDO SACmd specific fields */
        { &hf_oss_ssdo_sacmd_access_type,
          { "Access Type", "opensafety.ssdo.sacmd.access",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_acc), OPENSAFETY_SSDO_SACMD_ACC, NULL, HFILL } },
#if 0
        { &hf_oss_ssdo_sacmd_reserved,
          { "Reserved", "opensafety.ssdo.sacmd.reserved",
            FT_BOOLEAN,  8, TFS(&opensafety_sacmd_res), OPENSAFETY_SSDO_SACMD_RES, NULL, HFILL } },
#endif
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
            FT_BOOLEAN,  BASE_NONE, TFS(&opensafety_set_notset),  0x0, NULL, HFILL } },
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
        &ett_opensafety_node,
        &ett_opensafety_checksum,
        &ett_opensafety_snmt,
        &ett_opensafety_ssdo,
        &ett_opensafety_ssdo_sacmd,
        &ett_opensafety_ssdo_fragment,
        &ett_opensafety_ssdo_fragments,
        &ett_opensafety_ssdo_payload,
        &ett_opensafety_ssdo_sodentry,
        &ett_opensafety_sod_mapping,
        &ett_opensafety_ssdo_extpar,
        &ett_opensafety_spdo,
    };

    static ei_register_info ei[] = {
        { &ei_crc_frame_1_invalid,
          { "opensafety.crc.error.frame1_invalid", PI_PROTOCOL, PI_ERROR,
            "Frame 1 CRC invalid, Possible error in package", EXPFILL } },
        { &ei_crc_frame_1_valid_frame2_invalid,
          { "opensafety.crc.error.frame1_valid_frame2_invalid", PI_PROTOCOL, PI_ERROR,
            "Frame 1 is valid, frame 2 id is invalid", EXPFILL } },
        { &ei_crc_slimssdo_instead_of_spdo,
          { "opensafety.crc.warning.wrong_crc_for_spdo", PI_PROTOCOL, PI_WARN,
            "Frame 1 SPDO CRC is Slim SSDO CRC16 0x5935", EXPFILL } },
        { &ei_crc_frame_2_invalid,
          { "opensafety.crc.error.frame2_invalid", PI_PROTOCOL, PI_ERROR,
            "Frame 2 CRC invalid, Possible error in package or crc calculation", EXPFILL } },
        { &ei_crc_frame_2_unknown_scm_udid,
          { "opensafety.crc.error.frame2_unknown_scmudid", PI_PROTOCOL, PI_WARN,
            "Frame 2 CRC invalid, SCM UDID was not auto-detected", EXPFILL } },

        { &ei_message_reassembly_size_differs_from_header,
          { "opensafety.msg.warning.reassembly_size_fail", PI_PROTOCOL, PI_WARN,
            "Reassembled message size differs from size in header", EXPFILL } },
        { &ei_message_unknown_type,
          { "opensafety.msg.error.unknown_type", PI_MALFORMED, PI_ERROR,
            "Unknown openSAFETY message type", EXPFILL } },
        { &ei_message_spdo_address_invalid,
          { "opensafety.msg.error.spdo_address_invalid", PI_MALFORMED, PI_ERROR,
            "SPDO address is invalid", EXPFILL } },
        { &ei_message_id_field_mismatch,
          { "opensafety.msg.error.id.mismatch", PI_PROTOCOL, PI_ERROR,
            "ID for frame 2 is not the same as for frame 1", EXPFILL } },

        { &ei_scmudid_autodetected,
          { "opensafety.scm_udid.note.autodetected", PI_PROTOCOL, PI_NOTE,
            "Auto detected payload as SCM UDID", EXPFILL } },
        { &ei_scmudid_invalid_preference,
          { "opensafety.scm_udid.note.invalid_preference", PI_PROTOCOL, PI_WARN,
            "openSAFETY protocol settings are invalid! SCM UDID first octet will be assumed to be 00", EXPFILL } },
        { &ei_scmudid_unknown,
          { "opensafety.scm_udid.warning.assuming_first_octet", PI_PROTOCOL, PI_WARN,
            "SCM UDID unknown, assuming 00 as first UDID octet", EXPFILL } },

        { &ei_payload_unknown_format,
          { "opensafety.msg.warning.unknown_format", PI_PROTOCOL, PI_WARN,
            "Unknown payload format detected", EXPFILL } },
        { &ei_payload_length_not_positive,
          { "opensafety.msg.warning.reassembly_length_not_positive", PI_PROTOCOL, PI_NOTE,
            "Calculation for payload length yielded non-positive result", EXPFILL } },
    };

    module_t *opensafety_module;
    expert_module_t *expert_opensafety;

    /* Register the protocol name and description */
    proto_opensafety = proto_register_protocol("openSAFETY", "openSAFETY",  "opensafety");
    opensafety_module = prefs_register_protocol(proto_opensafety, apply_prefs);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_opensafety, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_opensafety = expert_register_protocol ( proto_opensafety );
    expert_register_field_array ( expert_opensafety, ei, array_length (ei ) );

    /* register user preferences */
    prefs_register_string_preference(opensafety_module, "scm_udid",
                 "SCM UDID (xx:xx:xx:xx:xx:xx)",
                 "To be able to fully dissect SSDO and SPDO packages, a valid UDID for the SCM has to be provided",
                 &global_scm_udid);
    prefs_register_bool_preference(opensafety_module, "scm_udid_autoset",
                 "Set SCM UDID if detected in stream",
                 "Automatically assign a detected SCM UDID (by reading SNMT->SNTM_assign_UDID_SCM) and set it for the file",
                 &global_scm_udid_autoset);
    prefs_register_bool_preference(opensafety_module, "calculate_crc2",
                 "Enable CRC calculation in frame 2",
                 "Enable the calculation for the second CRC",
                 &global_calculate_crc2);

    prefs_register_uint_preference(opensafety_module, "network_udp_port",
                "Port used for Generic UDP",
                "Port used by any UDP demo implementation to transport data", 10,
                &global_network_udp_port);
    prefs_register_uint_preference(opensafety_module, "network_udp_port_sercosiii",
                "Port used for SercosIII/UDP",
                "UDP port used by SercosIII to transport data", 10,
                &global_network_udp_port_sercosiii);
    prefs_register_bool_preference(opensafety_module, "network_udp_frame_first_sercosiii",
                "openSAFETY frame 2 before frame 1 (SercosIII/UDP only)",
                "In an SercosIII/UDP transport stream, openSAFETY frame 2 will be expected before frame 1",
                &global_siii_udp_frame2_first );
    prefs_register_bool_preference(opensafety_module, "network_udp_frame_first",
                "openSAFETY frame 2 before frame 1 (UDP only)",
                "In the transport stream, openSAFETY frame 2 will be expected before frame 1",
                &global_udp_frame2_first );
    prefs_register_bool_preference(opensafety_module, "mbtcp_big_endian",
                "Big Endian Word Coding (Modbus/TCP only)",
                "Modbus/TCP words can be transcoded either big- or little endian. Default will be little endian",
                &global_mbtcp_big_endian);

    prefs_register_bool_preference(opensafety_module, "enable_plk",
                "Enable heuristic dissection for Ethernet POWERLINK", "Enable heuristic dissection for Ethernet POWERLINK",
                &global_enable_plk);
    prefs_register_bool_preference(opensafety_module, "enable_udp",
                "Enable heuristic dissection for openSAFETY over UDP encoded traffic", "Enable heuristic dissection for openSAFETY over UDP encoded traffic",
                &global_enable_udp);
    prefs_register_bool_preference(opensafety_module, "enable_genudp",
                "Enable heuristic dissection for generic UDP encoded traffic", "Enable heuristic dissection for generic UDP encoded traffic",
                &global_enable_genudp);
    prefs_register_bool_preference(opensafety_module, "enable_siii",
                "Enable heuristic dissection for SercosIII", "Enable heuristic dissection for SercosIII",
                &global_enable_siii);
    prefs_register_bool_preference(opensafety_module, "enable_pnio",
                "Enable heuristic dissection for Profinet IO", "Enable heuristic dissection for Profinet IO",
                &global_enable_pnio);
    prefs_register_bool_preference(opensafety_module, "enable_mbtcp",
                "Enable heuristic dissection for Modbus/TCP", "Enable heuristic dissection for Modbus/TCP",
                &global_enable_mbtcp);

    prefs_register_bool_preference(opensafety_module, "display_intergap_data",
                "Display the data between openSAFETY packets", "Display the data between openSAFETY packets",
                &global_display_intergap_data);
    prefs_register_bool_preference(opensafety_module, "classify_transport",
                "Dissect packet based on transport method (EPL + SercosIII only)",
                "SPDOs may only be found in cyclic data, SSDOs/SNMTS only in acyclic data",
                &global_classify_transport);

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
        /* Storing global data_dissector */
        if ( data_dissector == NULL )
            data_dissector = find_dissector ( "data" );

        /* EPL & SercosIII dissector registration */
        heur_dissector_add("epl_data", dissect_opensafety_epl, proto_opensafety);
        heur_dissector_add("sercosiii", dissect_opensafety_siii, proto_opensafety);

        /* If an openSAFETY UDP transport filter is present, add to its
         * heuristic filter list. Otherwise ignore the transport */
        if ( find_dissector("opensafety_udp") != NULL )
                heur_dissector_add("opensafety_udp", dissect_opensafety_udpdata, proto_opensafety);

        /* Modbus TCP dissector registration */
        dissector_add_string("modbus.data", "data", find_dissector("opensafety_mbtcp"));

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

        register_init_routine ( setup_dissector );

        /* registering frame end routine, to prevent a malformed dissection preventing
         * further dissector calls (see bug #6950) */
        /* register_frame_end_routine(reset_dissector); */
    }

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
