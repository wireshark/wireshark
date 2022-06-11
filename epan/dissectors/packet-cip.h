/* packet-cip.h
 * Routines for CIP (Common Industrial Protocol) dissection
 * CIP Home: www.odva.org
 *
 * Copyright 2004
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
 *
 * Added support for Connection Configuration Object
 *   ryan wamsley * Copyright 2007
 *
 * Added support for PCCC Objects
 *   Jared Rittle - Cisco Talos
 *   Copyright 2017
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CIP_H
#define PACKET_CIP_H

/* CIP Service Codes */
#define SC_GET_ATT_ALL           0x01
#define SC_SET_ATT_ALL           0x02
#define SC_GET_ATT_LIST          0x03
#define SC_SET_ATT_LIST          0x04
#define SC_RESET                 0x05
#define SC_START                 0x06
#define SC_STOP                  0x07
#define SC_CREATE                0x08
#define SC_DELETE                0x09
#define SC_MULT_SERV_PACK        0x0A
#define SC_APPLY_ATTRIBUTES      0x0D
#define SC_GET_ATT_SINGLE        0x0E
#define SC_SET_ATT_SINGLE        0x10
#define SC_FIND_NEXT_OBJ_INST    0x11
#define SC_RESTOR                0x15
#define SC_SAVE                  0x16
#define SC_NO_OP                 0x17
#define SC_GET_MEMBER            0x18
#define SC_SET_MEMBER            0x19
#define SC_INSERT_MEMBER         0x1A
#define SC_REMOVE_MEMBER         0x1B
#define SC_GROUP_SYNC            0x1C

#define CIP_SC_MASK              0x7F
#define CIP_SC_RESPONSE_MASK     0x80

/* Classes that have class-specific dissectors */
#define CI_CLS_MR     0x02  /* Message Router */
#define CI_CLS_CM     0x06  /* Connection Manager */
#define CI_CLS_PCCC   0x67  /* PCCC Class */
#define CI_CLS_MOTION 0x42  /* Motion Device Axis Object */
#define CI_CLS_MB     0x44  /* Modbus Object */
#define CI_CLS_CCO    0xF3  /* Connection Configuration Object */

/* Class specific services */
/* Connection Manager */
#define SC_CM_FWD_CLOSE             0x4E
#define SC_CM_UNCON_SEND            0x52
#define SC_CM_FWD_OPEN              0x54
#define SC_CM_GET_CONN_DATA         0x56
#define SC_CM_SEARCH_CONN_DATA      0x57
#define SC_CM_LARGE_FWD_OPEN        0x5B
#define SC_CM_GET_CONN_OWNER        0x5A

/* PCCC Class */
#define SC_PCCC_EXECUTE_PCCC        0x4B

/* Modbus Object services */
#define SC_MB_READ_DISCRETE_INPUTS    0x4B
#define SC_MB_READ_COILS              0x4C
#define SC_MB_READ_INPUT_REGISTERS    0x4D
#define SC_MB_READ_HOLDING_REGISTERS  0x4E
#define SC_MB_WRITE_COILS             0x4F
#define SC_MB_WRITE_HOLDING_REGISTERS 0x50
#define SC_MB_PASSTHROUGH             0x51

/* Connection Configuration Object services */
#define SC_CCO_KICK_TIMER            0x4B
#define SC_CCO_OPEN_CONN             0x4C
#define SC_CCO_CLOSE_CONN            0x4D
#define SC_CCO_STOP_CONN             0x4E
#define SC_CCO_CHANGE_START          0x4F
#define SC_CCO_GET_STATUS            0x50
#define SC_CCO_CHANGE_COMPLETE       0x51
#define SC_CCO_AUDIT_CHANGE          0x52

/* CIP General status codes */
#define CI_GRC_SUCCESS              0x00
#define CI_GRC_FAILURE              0x01
#define CI_GRC_NO_RESOURCE          0x02
#define CI_GRC_BAD_DATA             0x03
#define CI_GRC_BAD_PATH             0x04
#define CI_GRC_BAD_CLASS_INSTANCE   0x05
#define CI_GRC_PARTIAL_DATA         0x06
#define CI_GRC_CONN_LOST            0x07
#define CI_GRC_BAD_SERVICE          0x08
#define CI_GRC_BAD_ATTR_DATA        0x09
#define CI_GRC_ATTR_LIST_ERROR      0x0A
#define CI_GRC_ALREADY_IN_MODE      0x0B
#define CI_GRC_BAD_OBJ_MODE         0x0C
#define CI_GRC_OBJ_ALREADY_EXISTS   0x0D
#define CI_GRC_ATTR_NOT_SETTABLE    0x0E
#define CI_GRC_PERMISSION_DENIED    0x0F
#define CI_GRC_DEV_IN_WRONG_STATE   0x10
#define CI_GRC_REPLY_DATA_TOO_LARGE 0x11
#define CI_GRC_FRAGMENT_PRIMITIVE   0x12
#define CI_GRC_CONFIG_TOO_SMALL     0x13
#define CI_GRC_UNDEFINED_ATTR       0x14
#define CI_GRC_CONFIG_TOO_BIG       0x15
#define CI_GRC_OBJ_DOES_NOT_EXIST   0x16
#define CI_GRC_NO_FRAGMENTATION     0x17
#define CI_GRC_DATA_NOT_SAVED       0x18
#define CI_GRC_DATA_WRITE_FAILURE   0x19
#define CI_GRC_REQUEST_TOO_LARGE    0x1A
#define CI_GRC_RESPONSE_TOO_LARGE   0x1B
#define CI_GRC_MISSING_LIST_DATA    0x1C
#define CI_GRC_INVALID_LIST_STATUS  0x1D
#define CI_GRC_SERVICE_ERROR        0x1E
#define CI_GRC_CONN_RELATED_FAILURE 0x1F
#define CI_GRC_INVALID_PARAMETER    0x20
#define CI_GRC_WRITE_ONCE_FAILURE   0x21
#define CI_GRC_INVALID_REPLY        0x22
#define CI_GRC_BUFFER_OVERFLOW      0x23
#define CI_GRC_MESSAGE_FORMAT       0x24
#define CI_GRC_BAD_KEY_IN_PATH      0x25
#define CI_GRC_BAD_PATH_SIZE        0x26
#define CI_GRC_UNEXPECTED_ATTR      0x27
#define CI_GRC_INVALID_MEMBER       0x28
#define CI_GRC_MEMBER_NOT_SETTABLE  0x29
#define CI_GRC_G2_SERVER_FAILURE    0x2A
#define CI_GRC_UNKNOWN_MB_ERROR     0x2B
#define CI_GRC_ATTRIBUTE_NOT_GET    0x2C

#define CI_GRC_STILL_PROCESSING     0xFF


/* PCCC Status Codes */
#define PCCC_GS_SUCCESS                    0x00
#define PCCC_GS_ILLEGAL_CMD                0x10
#define PCCC_GS_HOST_COMMS                 0x20
#define PCCC_GS_MISSING_REMOTE_NODE        0x30
#define PCCC_GS_HARDWARE_FAULT             0x40
#define PCCC_GS_ADDRESSING_ERROR           0x50
#define PCCC_GS_CMD_PROTECTION             0x60
#define PCCC_GS_PROGRAM_MODE               0x70
#define PCCC_GS_MISSING_COMPATABILITY_FILE 0x80
#define PCCC_GS_BUFFER_FULL_1              0x90
#define PCCC_GS_WAIT_ACK                   0xA0
#define PCCC_GS_REMOTE_DOWNLOAD_ERROR      0xB0
#define PCCC_GS_BUFFER_FULL_2              0xC0
#define PCCC_GS_NOT_USED_1                 0xD0
#define PCCC_GS_NOT_USED_2                 0xE0
#define PCCC_GS_USE_EXTSTS                 0xF0

/* PCCC Extended Status Codes */
#define PCCC_ES_ILLEGAL_VALUE         0x01
#define PCCC_ES_SHORT_ADDRESS         0x02
#define PCCC_ES_LONG_ADDRESS          0x03
#define PCCC_ES_NOT_FOUND             0x04
#define PCCC_ES_BAD_FORMAT            0x05
#define PCCC_ES_BAD_POINTER           0x06
#define PCCC_ES_BAD_SIZE              0x07
#define PCCC_ES_SITUATION_CHANGED     0x08
#define PCCC_ES_DATA_TOO_LARGE        0x09
#define PCCC_ES_TRANS_TOO_LARGE       0x0A
#define PCCC_ES_ACCESS_DENIED         0x0B
#define PCCC_ES_NOT_AVAILABLE         0x0C
#define PCCC_ES_ALREADY_EXISTS        0x0D
#define PCCC_ES_NO_EXECUTION          0x0E
#define PCCC_ES_HIST_OVERFLOW         0x0F
#define PCCC_ES_NO_ACCESS             0x10
#define PCCC_ES_ILLEGAL_DATA_TYPE     0x11
#define PCCC_ES_INVALID_DATA          0x12
#define PCCC_ES_BAD_REFERENCE         0x13
#define PCCC_ES_EXECUTION_FAILURE     0x14
#define PCCC_ES_CONVERSION_ERROR      0x15
#define PCCC_ES_NO_COMMS              0x16
#define PCCC_ES_TYPE_MISMATCH         0x17
#define PCCC_ES_BAD_RESPONSE          0x18
#define PCCC_ES_DUP_LABEL             0x19
#define PCCC_ES_FILE_ALREADY_OPEN     0x1A
#define PCCC_ES_PROGRAM_ALREADY_OWNED 0x1B
#define PCCC_ES_RESERVED_1            0x1C
#define PCCC_ES_RESERVED_2            0x1D
#define PCCC_ES_PROTECTION_VIOLATION  0x1E
#define PCCC_ES_TMP_INTERNAL_ERROR    0x1F
#define PCCC_ES_RACK_FAULT            0x22
#define PCCC_ES_TIMEOUT               0x23
#define PCCC_ES_UNKNOWN               0x24

/* PCCC Command Codes */
#define PCCC_CMD_00 0x00
#define PCCC_CMD_01 0x01
#define PCCC_CMD_02 0x02
#define PCCC_CMD_04 0x04
#define PCCC_CMD_05 0x05
#define PCCC_CMD_06 0x06
#define PCCC_CMD_07 0x07
#define PCCC_CMD_08 0x08
#define PCCC_CMD_0F 0x0F

/* PCCC Function Codes */
#define PCCC_FNC_06_00 0x00
#define PCCC_FNC_06_01 0x01
#define PCCC_FNC_06_02 0x02
#define PCCC_FNC_06_03 0x03
#define PCCC_FNC_06_04 0x04
#define PCCC_FNC_06_05 0x05
#define PCCC_FNC_06_06 0x06
#define PCCC_FNC_06_07 0x07
#define PCCC_FNC_06_08 0x08
#define PCCC_FNC_06_09 0x09
#define PCCC_FNC_06_0A 0x0A

#define PCCC_FNC_07_00 0x00
#define PCCC_FNC_07_01 0x01
#define PCCC_FNC_07_03 0x03
#define PCCC_FNC_07_04 0x04
#define PCCC_FNC_07_05 0x05
#define PCCC_FNC_07_06 0x06

#define PCCC_FNC_0F_00 0x00
#define PCCC_FNC_0F_01 0x01
#define PCCC_FNC_0F_02 0x02
#define PCCC_FNC_0F_03 0x03
#define PCCC_FNC_0F_04 0x04
#define PCCC_FNC_0F_05 0x05
#define PCCC_FNC_0F_06 0x06
#define PCCC_FNC_0F_07 0x07
#define PCCC_FNC_0F_08 0x08
#define PCCC_FNC_0F_09 0x09
#define PCCC_FNC_0F_0A 0x0A
#define PCCC_FNC_0F_11 0x11
#define PCCC_FNC_0F_12 0x12
#define PCCC_FNC_0F_17 0x17
#define PCCC_FNC_0F_18 0x18
#define PCCC_FNC_0F_26 0x26
#define PCCC_FNC_0F_29 0x29
#define PCCC_FNC_0F_3A 0x3A
#define PCCC_FNC_0F_41 0x41
#define PCCC_FNC_0F_50 0x50
#define PCCC_FNC_0F_52 0x52
#define PCCC_FNC_0F_53 0x53
#define PCCC_FNC_0F_55 0x55
#define PCCC_FNC_0F_57 0x57
#define PCCC_FNC_0F_5E 0x5E
#define PCCC_FNC_0F_67 0x67
#define PCCC_FNC_0F_68 0x68
#define PCCC_FNC_0F_79 0x79
#define PCCC_FNC_0F_80 0x80
#define PCCC_FNC_0F_81 0x81
#define PCCC_FNC_0F_82 0x82
#define PCCC_FNC_0F_88 0x88
#define PCCC_FNC_0F_8F 0x8F
#define PCCC_FNC_0F_A1 0xA1
#define PCCC_FNC_0F_A2 0xA2
#define PCCC_FNC_0F_A3 0xA3
#define PCCC_FNC_0F_A7 0xA7
#define PCCC_FNC_0F_A9 0xA9
#define PCCC_FNC_0F_AA 0xAA
#define PCCC_FNC_0F_AB 0xAB
#define PCCC_FNC_0F_AF 0xAF

/* PCCC File Types */
#define PCCC_FILE_TYPE_LOGIC            0x22
#define PCCC_FILE_TYPE_FUNCTION_CS0_CS2 0x48
#define PCCC_FILE_TYPE_CHANNEL_CONFIG   0x49
#define PCCC_FILE_TYPE_FUNCTION_ES1     0x4A
#define PCCC_FILE_TYPE_ONLINE_EDIT      0x65
#define PCCC_FILE_TYPE_FUNCTION_IOS     0x6A
#define PCCC_FILE_TYPE_DATA_OUTPUT      0x82
#define PCCC_FILE_TYPE_DATA_INPUT       0x83
#define PCCC_FILE_TYPE_DATA_STATUS      0x84
#define PCCC_FILE_TYPE_DATA_BINARY      0x85
#define PCCC_FILE_TYPE_DATA_TIMER       0x86
#define PCCC_FILE_TYPE_DATA_COUNTER     0x87
#define PCCC_FILE_TYPE_DATA_CONTROL     0x88
#define PCCC_FILE_TYPE_DATA_INTEGER     0x89
#define PCCC_FILE_TYPE_DATA_FLOAT       0x8A
#define PCCC_FILE_TYPE_FORCE_OUTPUT     0xA1
#define PCCC_FILE_TYPE_FORCE_INPUT      0xA2
#define PCCC_FILE_TYPE_FUNCTION_ES0     0xE0
#define PCCC_FILE_TYPE_FUNCTION_STI     0xE2
#define PCCC_FILE_TYPE_FUNCTION_EII     0xE3
#define PCCC_FILE_TYPE_FUNCTION_RTC     0xE4
#define PCCC_FILE_TYPE_FUNCTION_BHI     0xE5
#define PCCC_FILE_TYPE_FUNCTION_MMI     0xE6
#define PCCC_FILE_TYPE_FUNCTION_LCD     0xEC
#define PCCC_FILE_TYPE_FUNCTION_PTOX    0xED
#define PCCC_FILE_TYPE_FUNCTION_PWMX    0xEE

/* PCCC CPU Mode Codes */
#define PCCC_CPU_3A_PROGRAM     0x01
#define PCCC_CPU_3A_RUN         0x02

#define PCCC_CPU_80_PROGRAM     0x01
#define PCCC_CPU_80_RUN         0x06
#define PCCC_CPU_80_TEST_CONT   0x07
#define PCCC_CPU_80_TEST_SINGLE 0x08
#define PCCC_CPU_80_TEST_DEBUG  0x09



/* IOI Path types */
#define CI_SEGMENT_TYPE_MASK        0xE0

#define CI_PORT_SEGMENT             0x00
#define CI_LOGICAL_SEGMENT          0x20
#define CI_NETWORK_SEGMENT          0x40
#define CI_SYMBOLIC_SEGMENT         0x60
#define CI_DATA_SEGMENT             0x80

#define CI_PORT_SEG_EX_LINK_ADDRESS 0x10
#define CI_PORT_SEG_PORT_ID_MASK    0x0F

#define CI_LOGICAL_SEG_TYPE_MASK    0x1C
#define CI_LOGICAL_SEG_CLASS_ID     0x00
#define CI_LOGICAL_SEG_INST_ID      0x04
#define CI_LOGICAL_SEG_MBR_ID       0x08
#define CI_LOGICAL_SEG_CON_POINT    0x0C
#define CI_LOGICAL_SEG_ATTR_ID      0x10
#define CI_LOGICAL_SEG_SPECIAL      0x14
#define CI_LOGICAL_SEG_SERV_ID      0x18
#define CI_LOGICAL_SEG_EXT_LOGICAL  0x1C

#define CI_LOGICAL_SEG_FORMAT_MASK  0x03
#define CI_LOGICAL_SEG_8_BIT        0x00
#define CI_LOGICAL_SEG_16_BIT       0x01
#define CI_LOGICAL_SEG_32_BIT       0x02
#define CI_LOGICAL_SEG_RES_2        0x03
#define CI_LOGICAL_SEG_E_KEY        0x00

#define CI_E_KEY_FORMAT_VAL         0x04
#define CI_E_SERIAL_NUMBER_KEY_FORMAT_VAL 0x05

#define CI_DATA_SEG_TYPE_MASK       0x1F
#define CI_DATA_SEG_SIMPLE          0x00
#define CI_DATA_SEG_SYMBOL          0x11

#define CI_NETWORK_SEG_TYPE_MASK    0x1F
#define CI_NETWORK_SEG_SCHEDULE     0x01
#define CI_NETWORK_SEG_FIXED_TAG    0x02
#define CI_NETWORK_SEG_PROD_INHI    0x03
#define CI_NETWORK_SEG_SAFETY       0x10
#define CI_NETWORK_SEG_PROD_INHI_US 0x11
#define CI_NETWORK_SEG_EXTENDED     0x1F

#define CI_SYMBOL_SEG_FORMAT_MASK   0xE0
#define CI_SYMBOL_SEG_SIZE_MASK     0x1F
#define CI_SYMBOL_SEG_DOUBLE        0x20
#define CI_SYMBOL_SEG_TRIPLE        0x40
#define CI_SYMBOL_SEG_NUMERIC       0xC0

#define CI_SYMBOL_NUMERIC_USINT     6
#define CI_SYMBOL_NUMERIC_UINT      7
#define CI_SYMBOL_NUMERIC_UDINT     8

#define CI_TRANSPORT_CLASS_MASK     0x0F
#define CI_PRODUCTION_TRIGGER_MASK  0x70
#define CI_PRODUCTION_DIR_MASK      0x80

#define CONN_TYPE_NULL              0
#define CONN_TYPE_MULTICAST         1
#define CONN_TYPE_P2P               2
#define CONN_TYPE_RESERVED          3

#define ENIP_CIP_INTERFACE          0

/* Define common services */
#define GENERIC_SC_LIST \
   { SC_GET_ATT_ALL,          "Get Attributes All" }, \
   { SC_SET_ATT_ALL,          "Set Attributes All" }, \
   { SC_GET_ATT_LIST,         "Get Attribute List" }, \
   { SC_SET_ATT_LIST,         "Set Attribute List" }, \
   { SC_RESET,                "Reset" }, \
   { SC_START,                "Start" }, \
   { SC_STOP,                 "Stop" }, \
   { SC_CREATE,               "Create" }, \
   { SC_DELETE,               "Delete" }, \
   { SC_MULT_SERV_PACK,       "Multiple Service Packet" }, \
   { SC_APPLY_ATTRIBUTES,     "Apply Attributes" }, \
   { SC_GET_ATT_SINGLE,       "Get Attribute Single" }, \
   { SC_SET_ATT_SINGLE,       "Set Attribute Single" }, \
   { SC_FIND_NEXT_OBJ_INST,   "Find Next Object Instance" }, \
   { SC_RESTOR,               "Restore" }, \
   { SC_SAVE,                 "Save" }, \
   { SC_NO_OP,                "Nop" }, \
   { SC_GET_MEMBER,           "Get Member" }, \
   { SC_SET_MEMBER,           "Set Member" }, \
   { SC_INSERT_MEMBER,        "Insert Member" }, \
   { SC_REMOVE_MEMBER,        "Remove Member" }, \
   { SC_GROUP_SYNC,           "Group Sync" }, \

#define SEGMENT_VALUE_NOT_SET ((guint32)-1)
typedef struct cip_simple_request_info {
   // First Class ID
   guint32 iClassA;
   // Last Class ID
   guint32 iClass;

   // First Instance ID
   guint32 iInstanceA;
   // Last Instance ID
   guint32 iInstance;

   guint32 iAttribute;
   guint32 iMember;

   // First Connection Point
   guint32 iConnPointA;
   // Last Connection Point. The 2nd (last) Connection Point defines the Motion I/O Format.
   guint32 iConnPoint;
} cip_simple_request_info_t;

enum cip_datatype {
   cip_bool,
   cip_sint,
   cip_int,
   cip_dint,
   cip_lint,
   cip_usint,
   cip_usint_array,
   cip_uint,
   cip_uint_array,
   cip_udint,
   cip_ulint,
   cip_real,
   cip_lreal,
   cip_stime,
   cip_utime,
   cip_itime,
   cip_time,
   cip_ftime,
   cip_ltime,
   cip_ntime,
   cip_short_string,
   cip_string,
   cip_string2,
   cip_stringi,
   cip_byte,
   cip_word,
   cip_dword,
   cip_lword,
   cip_date,
   cip_time_of_day,
   cip_date_and_time,
   cip_dissector_func,

   /* Currently not supported */
   cip_stringN,
};

typedef int attribute_dissector_func(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len);

#define CIP_ATTR_CLASS (TRUE)
#define CIP_ATTR_INSTANCE (FALSE)
typedef struct attribute_info {
   guint                     class_id;
   gboolean                  class_instance;
   guint                     attribute;
   int                       gaa_index; /* Index of attribute in GetAttributeAll response (< 0 means not in GetAttrbuteAll */
   const char               *text;
   enum cip_datatype         datatype;
   int*                      phf;
   attribute_dissector_func *pdissect;
} attribute_info_t;

// This describes a one-way connection. Each CIP Connection includes 2 of these.
typedef struct cip_connID_info {
   // Connection ID from Forward Open Request. This may get updated in the Forward Open Response.
   guint32 connID;

   // From Common Packet Format, Sockaddr Info Item.
   address ipaddress;
   guint16 port;

   // Network Connection Parameters
   guint32 type;  // See: cip_con_type_vals

   // Requested Packet Interval in microseconds.
   guint32 rpi;

   // Actual Packet Interval in microseconds.
   guint32 api;
} cip_connID_info_t;

enum cip_safety_format_type {CIP_SAFETY_BASE_FORMAT, CIP_SAFETY_EXTENDED_FORMAT};

typedef struct cip_connection_triad {
   guint16 ConnSerialNumber;
   guint16 VendorID;
   guint32 DeviceSerialNumber;
} cip_connection_triad_t;

typedef struct cip_safety_epath_info {
   gboolean safety_seg;
   enum cip_safety_format_type format;

   // These 3x variables are only used during a first pass calculation.
   guint16 running_rollover_value;   /* Keep track of the rollover value over the course of the connection */
   guint16 running_timestamp_value;  /* Keep track of the timestamp value over the course of the connection */
   gboolean seen_non_zero_timestamp; /* True if we have seen a non-zero timestamp on this connection */

   // The Target CIP Connection Triad from the Forward Open Response, Safety Application Reply Data.
   cip_connection_triad_t target_triad;
} cip_safety_epath_info_t;

// Information for a given CIP Connection, for both directions (O->T and T->O)
typedef struct cip_conn_info {
   // Forward Open Data
   cip_connection_triad_t  triad;
   guint8                  TransportClass_trigger;
   guint32                 timeout_multiplier;
   cip_safety_epath_info_t safety;
   guint32                 ClassID;
   guint32                 ConnPoint;
   guint32                 FwdOpenPathLenBytes;
   void*                   pFwdOpenPathData;

   // Information about specific packet numbers.
   guint32 open_req_frame;
   guint32 open_reply_frame;
   guint32 close_frame;

   // Information about each direction of the overall connection.
   cip_connID_info_t O2T;
   cip_connID_info_t T2O;

   // Unique ID generated that links together the CIP Connections.
   //  - If the full connection information is available (eg: FwdOpen found), then it will link both
   //    connections (one for each direction)
   guint32 connid;
} cip_conn_info_t;

typedef struct cip_req_info {
   dissector_handle_t         dissector;

   // This is the CIP Service Code. It does not include the Response bit.
   guint8                     bService;

   // Number of 16-bit words in pIOI.
   guint                      IOILen;
   void                      *pIOI;

   guint                      RouteConnectionPathLen;
   void                      *pRouteConnectionPath;

   void                      *pData;
   cip_simple_request_info_t *ciaData;
   cip_conn_info_t*           connInfo;
} cip_req_info_t;

/*
** Exported functions
*/

/* Depending on if a Class or Symbol segment appears in Connection Path or
   a Request Path, display '-' before or after the actual name. */
#define NO_DISPLAY 0
#define DISPLAY_CONNECTION_PATH 1
#define DISPLAY_REQUEST_PATH 2
extern void dissect_epath( tvbuff_t *tvb, packet_info *pinfo, proto_tree *path_tree, proto_item *epath_item, int offset, int path_length,
                          gboolean generate, gboolean packed, cip_simple_request_info_t* req_data, cip_safety_epath_info_t* safety,
                          int display_type, proto_item *msp_item,
                          gboolean is_msp_item);

// Elementary Data Types.
enum cip_elem_data_types {
    CIP_STRING_TYPE = 0xD0,
    CIP_SHORT_STRING_TYPE = 0xDA,
    CIP_STRING2_TYPE = 0xD5
};

extern void add_cip_service_to_info_column(packet_info *pinfo, guint8 service, const value_string* service_vals);
extern attribute_info_t* cip_get_attribute(guint class_id, guint instance, guint attribute);
extern void cip_rpi_api_fmt(gchar *s, guint32 value);

extern int  dissect_cip_attribute(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb, attribute_info_t* attr, int offset, int total_len);
extern void dissect_cip_data(proto_tree *item_tree, tvbuff_t *tvb, int offset, packet_info *pinfo, cip_req_info_t *preq_info, proto_item* msp_item, gboolean is_msp_item);
extern void dissect_cip_date_and_time(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_datetime);
extern int dissect_cip_utime(proto_tree* tree, tvbuff_t* tvb, int offset, int hf_datetime);
extern int dissect_cip_generic_service_rsp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);
extern int  dissect_cip_get_attribute_list_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
   int offset, cip_simple_request_info_t* req_data);
extern int  dissect_cip_multiple_service_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item, int offset, gboolean request);
extern int  dissect_cip_response_status(proto_tree* tree, tvbuff_t* tvb, int offset, int hf_general_status, gboolean have_additional_status);
extern void dissect_cip_run_idle(tvbuff_t* tvb, int offset, proto_tree* item_tree);
extern int  dissect_cip_segment_single(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *path_tree, proto_item *epath_item,
   gboolean generate, gboolean packed, cip_simple_request_info_t* req_data, cip_safety_epath_info_t* safety,
   int display_type, proto_item *msp_item,
   gboolean is_msp_item);
extern int  dissect_cip_string_type(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset, int hf_type, int string_type);
extern int  dissect_cip_get_attribute_all_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, cip_simple_request_info_t* req_data);
extern int  dissect_cip_set_attribute_list_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
   int offset, cip_simple_request_info_t* req_data);
extern int  dissect_cip_set_attribute_list_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item * item,
   int offset, cip_simple_request_info_t* req_data);
extern void dissect_deviceid(tvbuff_t *tvb, int offset, proto_tree *tree,
   int hf_vendor, int hf_devtype, int hf_prodcode,
   int hf_compatibility, int hf_comp_bit, int hf_majrev, int hf_minrev,
   gboolean generate);
extern int dissect_electronic_key_format(tvbuff_t* tvb, int offset, proto_tree* tree, gboolean generate, guint8 key_format);
extern int  dissect_optional_attr_list(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int  dissect_optional_service_list(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int  dissect_padded_epath_len_usint(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int  dissect_padded_epath_len_uint(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);

extern void load_cip_request_data(packet_info *pinfo, cip_simple_request_info_t *req_data);
extern void reset_cip_request_info(cip_simple_request_info_t* req_data);
extern gboolean should_dissect_cip_response(tvbuff_t *tvb, int offset, guint8 gen_status);


/*
** Exported variables
*/
extern const value_string cip_sc_rr[];
extern const value_string cip_reset_type_vals[];
extern const value_string cip_con_prio_vals[];
extern const value_string cip_con_type_vals[];
extern const value_string cip_con_time_mult_vals[];
extern const value_string cip_class_names_vals[];
extern const value_string cip_port_number_vals[];
extern const value_string cip_id_state_vals[];
extern value_string_ext cip_gs_vals_ext;
extern value_string_ext cip_cm_ext_st_vals_ext;
extern value_string_ext cip_vendor_vals_ext;
extern value_string_ext cip_devtype_vals_ext;
extern value_string_ext cip_class_names_vals_ext;

/* Common class attributes and attribute dissection functions*/
extern int hf_attr_class_revision;
extern int hf_attr_class_max_instance;
extern int hf_attr_class_num_instance;
extern int hf_attr_class_opt_attr_num;
extern int hf_attr_class_attr_num;
extern int hf_attr_class_opt_service_num;
extern int hf_attr_class_service_code;
extern int hf_attr_class_num_class_attr;
extern int hf_attr_class_num_inst_attr;

#define CLASS_ATTRIBUTE_1_NAME  "Revision"
#define CLASS_ATTRIBUTE_2_NAME  "Max Instance"
#define CLASS_ATTRIBUTE_3_NAME  "Number of Instances"
#define CLASS_ATTRIBUTE_4_NAME  "Optional Attribute List"
#define CLASS_ATTRIBUTE_5_NAME  "Optional Service List"
#define CLASS_ATTRIBUTE_6_NAME  "Maximum ID Number Class Attributes"
#define CLASS_ATTRIBUTE_7_NAME  "Maximum ID Number Instance Attributes"

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */

#endif /* PACKET_CIP_H */
