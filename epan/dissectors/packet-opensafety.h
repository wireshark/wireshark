/* packet-opensafety.h
 *
 *   openSAFETY is a machine-safety protocol, encapsulated in modern fieldbus
 *   and industrial ethernet solutions.
 *
 *   For more information see http://www.open-safety.org
 *
 *   This header contains commonly used headers, which may be used by programs
 *   utilizing the tap-interface of the dissector
 *
 * By Roland Knall <roland.knall@br-automation.com>
 * Copyright 2011-2015 Bernecker + Rainer Industrie-Elektronik Ges.m.b.H.
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

#ifndef _OPENSAFETY_HEADER_
#define _OPENSAFETY_HEADER_

#include <config.h>

#include <epan/packet.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* openSAFETY UDP Port */
#ifndef OPENSAFETY_UDP_PORT
#define OPENSAFETY_UDP_PORT   9877
#endif

/* SercosIII UDP Port */
#ifndef OPENSAFETY_UDP_PORT_SIII
#define OPENSAFETY_UDP_PORT_SIII         8755
#endif

#define OPENSAFETY_DEFAULT_DOMAIN       0x1

/* openSAFETY CRC types */
#define OPENSAFETY_CHECKSUM_CRC8        0x01
#define OPENSAFETY_CHECKSUM_CRC16       0x02
#define OPENSAFETY_CHECKSUM_CRC32       0x04
#define OPENSAFETY_CHECKSUM_CRC16SLIM   0x08
#define OPENSAFETY_CHECKSUM_INVALID     0xFF

static const value_string opensafety_frame_crc_type[] = {
    { OPENSAFETY_CHECKSUM_CRC8,         "CRC8" },
    { OPENSAFETY_CHECKSUM_CRC16,        "CRC16" },
    { OPENSAFETY_CHECKSUM_CRC32,        "CRC32" },
    { OPENSAFETY_CHECKSUM_CRC16SLIM,    "CRC16 Slim" },
    { 0, NULL }
};

/* openSAFETY Message Types */
#define OPENSAFETY_SNMT_MESSAGE_TYPE      0xA0
#define OPENSAFETY_SPDO_MESSAGE_TYPE      0xC0
#define OPENSAFETY_SSDO_MESSAGE_TYPE      0xE0
#define OPENSAFETY_SLIM_SSDO_MESSAGE_TYPE 0xE8

/* We shift the values by 5, otherwise they won't get picked up by the
 * hf_field value dissection */
static const value_string opensafety_msg_id_values[] = {
    { OPENSAFETY_SNMT_MESSAGE_TYPE >> 5,      "openSAFETY SNMT" },
    { OPENSAFETY_SPDO_MESSAGE_TYPE >> 5,      "openSAFETY SPDO" },
    { OPENSAFETY_SSDO_MESSAGE_TYPE >> 5,      "openSAFETY SSDO" },
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

static const value_string opensafety_message_type_values[] = {
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
#define OPENSAFETY_MSG_SNMT_EXT_ASSIGN_INIT_CT              0x10
#define OPENSAFETY_MSG_SNMT_EXT_ASSIGNED_INIT_CT            0x11

static const value_string opensafety_message_service_type[] = {
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
    { OPENSAFETY_MSG_SNMT_EXT_ASSIGN_INIT_CT,              "Assign initial CT for SN" },
    { OPENSAFETY_MSG_SNMT_EXT_ASSIGNED_INIT_CT,            "Acknowledge initial CT for SN" },
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

static const value_string opensafety_sn_fail_error_group[] = {
    { OPENSAFETY_ERROR_GROUP_APPLICATION,      "Application" },
    { OPENSAFETY_ERROR_GROUP_PARAMETER,        "Parameter" },
    { OPENSAFETY_ERROR_GROUP_VENDOR_SPECIFIC,  "Vendor specific" },
    { OPENSAFETY_ERROR_GROUP_OPENSAFETY_STACK, "openSAFETY Stack" },
    { OPENSAFETY_ERROR_GROUP_ADD_PARAMETER,    "Additional parameter needed" },
    { 0, NULL }
};

/* SSDO Access Command */

#define OPENSAFETY_SSDO_SACMD_ACC  0x01
#define OPENSAFETY_SSDO_SACMD_PRLD 0x02
#define OPENSAFETY_SSDO_SACMD_ABRT 0x04
#define OPENSAFETY_SSDO_SACMD_SEG  0x08
#define OPENSAFETY_SSDO_SACMD_TGL  0x10
#define OPENSAFETY_SSDO_SACMD_INI  0x20
#define OPENSAFETY_SSDO_SACMD_ENSG 0x40
#define OPENSAFETY_SSDO_SACMD_RES  0x80

#define OPENSAFETY_SSDO_UPLOAD     0x00
#define OPENSAFETY_SSDO_DOWNLOAD   0x01

#define OPENSAFETY_MSG_SSDO_ABORT                           ( OPENSAFETY_SSDO_SACMD_ABRT )
#define OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE           ( OPENSAFETY_SSDO_SACMD_SEG | OPENSAFETY_SSDO_UPLOAD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE         ( OPENSAFETY_SSDO_SACMD_SEG | OPENSAFETY_SSDO_DOWNLOAD )
#define OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MID_PRELOAD      ( OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE | OPENSAFETY_SSDO_SACMD_PRLD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MID_PRELOAD    ( OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE | OPENSAFETY_SSDO_SACMD_PRLD )
#define OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED       ( OPENSAFETY_SSDO_SACMD_INI | OPENSAFETY_SSDO_UPLOAD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED     ( OPENSAFETY_SSDO_SACMD_INI | OPENSAFETY_SSDO_DOWNLOAD )
#define OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXP_PRELOAD     ( OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED | OPENSAFETY_SSDO_SACMD_PRLD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXP_PRELOAD   ( OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED | OPENSAFETY_SSDO_SACMD_PRLD )
#define OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED       ( OPENSAFETY_SSDO_SACMD_INI | OPENSAFETY_SSDO_SACMD_SEG | OPENSAFETY_SSDO_UPLOAD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED     ( OPENSAFETY_SSDO_SACMD_INI | OPENSAFETY_SSDO_SACMD_SEG | OPENSAFETY_SSDO_DOWNLOAD )
#define OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEG_PRELOAD     ( OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED | OPENSAFETY_SSDO_SACMD_PRLD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEG_PRELOAD   ( OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED | OPENSAFETY_SSDO_SACMD_PRLD )
#define OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END              ( OPENSAFETY_SSDO_SACMD_ENSG | OPENSAFETY_SSDO_SACMD_SEG | OPENSAFETY_SSDO_UPLOAD )
#define OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END            ( OPENSAFETY_SSDO_SACMD_ENSG | OPENSAFETY_SSDO_SACMD_SEG | OPENSAFETY_SSDO_DOWNLOAD )

static const value_string opensafety_ssdo_sacmd_values[] = {
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_END,            "Download End Segment" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_END,              "Upload End Segment" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXPEDITED,     "Download Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEGMENTED,       "Upload Initiate Segmented" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEGMENTED,     "Download Initiate Segmented" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXPEDITED,       "Upload Expedited Initiate" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_EXP_PRELOAD,     "Upload Expedited Initiate w.Preload" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_EXP_PRELOAD,   "Download Initiate Segmented w.Preload" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_INITIATE_SEG_PRELOAD,     "Upload Initiate Segmented w. Preload" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_INITIATE_SEG_PRELOAD,   "Download Expedited Initiate w.Preload" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MIDDLE,         "Download Middle Segment" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MIDDLE,           "Upload Middle Segment" },
    { OPENSAFETY_MSG_SSDO_DOWNLOAD_SEGMENT_MID_PRELOAD,    "Download Middle Segment w. Preload" },
    { OPENSAFETY_MSG_SSDO_UPLOAD_SEGMENT_MID_PRELOAD,      "Upload Middle Segment w. Preload" },
    { OPENSAFETY_MSG_SSDO_ABORT,                           "Abort" },
    { 0, NULL }
};

static const true_false_string opensafety_sacmd_acc   = { "Download", "Upload" };
static const true_false_string opensafety_sacmd_abrt  = { "Abort Transfer", "Successful Transfer" };
static const true_false_string opensafety_sacmd_seg   = { "Segmented Access", "Expedited Access" };
static const true_false_string opensafety_sacmd_ini   = { "Initiate", "No Initiate" };
static const true_false_string opensafety_sacmd_ensg  = { "No more segments", "More segments" };

static const value_string opensafety_sod_idx_names[] = {
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
static value_string_ext opensafety_sod_idx_names_ext = VALUE_STRING_EXT_INIT(opensafety_sod_idx_names);

static const value_string opensafety_abort_codes[] = {

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
static value_string_ext opensafety_abort_codes_ext = VALUE_STRING_EXT_INIT(opensafety_abort_codes);

static const true_false_string opensafety_message_direction = { "Response", "Request" };
static const true_false_string opensafety_spdo_direction = { "Producer", "Consumer" };
static const true_false_string opensafety_addparam_request = { "Header only", "Header & Data" };

typedef struct _opensafety_packet_spdo
{
    guint16 timerequest;

    gboolean conn_valid;

    gboolean counter_40bit;

    union {
        guint16 b16;
        guint64 b40;
    } counter;

    struct {
        gboolean enabled40bit;
        gboolean requested40bit;
    } flags;

} opensafety_packet_spdo;

typedef struct _opensafety_packet_ssdo
{
    gboolean is_slim;

    struct {
        gboolean end_segment;
        gboolean initiate;
        gboolean toggle;
        gboolean segmented;
        gboolean abort_transfer;
        gboolean preload;
        gboolean read_access;
    } sacmd;
} opensafety_packet_ssdo;

typedef struct _opensafety_packet_snmt
{
    guint8 ext_msg_id;

    struct {
        gboolean exists;
        guint8 id;
        guint8 set;
        gboolean full;
    } add_param;

    struct {
        guint16 actual;
        guint16 additional;
    } add_saddr;

    guint64 init_ct;

    gchar * scm_udid;
    gchar * sn_udid;

    guint8 error_code;
} opensafety_packet_snmt;

typedef struct _opensafety_packet_frame
{
    gboolean malformed;

    guint16 subframe1;
    guint16 subframe2;

    guint length;

    guint16 byte_offset;

    tvbuff_t *frame_tvb;

} opensafety_packet_frame;

typedef struct _opensafety_packet_crc
{
    guint8  type;

    guint16 frame1;
    guint16 frame2;

    gboolean valid1;
    gboolean valid2;
} opensafety_packet_crc;

typedef struct _opensafety_packet_info
{
    opensafety_packet_frame frame;

    guint16 saddr;
    guint16 sdn;

    guint16 sender;
    guint16 receiver;

    gboolean is_request;

    guint8  msg_id;    /**< The exact transported message id */
    guint8  msg_type;  /**< Only represents the general type, e.g. SPDO, SSDO, Slim SSDO and SNMT */
    guint8  msg_len;
    guint   frame_len;

    guint8   scm_udid[6];
    gboolean scm_udid_valid;

    opensafety_packet_crc crc;

    union {
        opensafety_packet_snmt *snmt;
        opensafety_packet_ssdo *ssdo;
        opensafety_packet_spdo *spdo;
    } payload;

} opensafety_packet_info;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _OPENSAFETY_HEADER_ */

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
