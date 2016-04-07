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
#define CI_CLS_MR   0x02    /* Message Router */
#define CI_CLS_CM   0x06    /* Connection Manager */
#define CI_CLS_MB   0x44    /* Modbus Object */
#define CI_CLS_CCO  0xF3    /* Connection Configuration Object */

/* Class specific services */
/* Connection Manager */
#define SC_CM_FWD_CLOSE             0x4E
#define SC_CM_UNCON_SEND            0x52
#define SC_CM_FWD_OPEN              0x54
#define SC_CM_LARGE_FWD_OPEN        0x5B
#define SC_CM_GET_CONN_OWNER        0x5A

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

typedef struct cip_simple_request_info {
   guint32 iClass;
   guint32 iInstance;
   guint32 iAttribute;
   guint32 iMember;
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
   cip_itime,
   cip_time,
   cip_ftime,
   cip_ltime,
   cip_short_string,
   cip_string,
   cip_string2,
   cip_byte,
   cip_byte_array,
   cip_word,
   cip_dword,
   cip_lword,
   cip_date,
   cip_time_of_day,
   cip_date_and_time,
   cip_dissector_func,

   /* Currently not supported */
   cip_stringN,
   cip_stringi
};

typedef int attribute_dissector_func(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
                             int offset, int total_len);

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

typedef struct cip_connID_info {
   guint32 connID;
   address ipaddress;
   guint16 port;
   guint8  type;
} cip_connID_info_t;

enum cip_safety_format_type {CIP_SAFETY_BASE_FORMAT, CIP_SAFETY_EXTENDED_FORMAT};

typedef struct cip_safety_epath_info {
   gboolean safety_seg;
   enum cip_safety_format_type format;
} cip_safety_epath_info_t;

typedef struct cip_conn_info {
   guint16                 ConnSerialNumber;
   guint16                 VendorID;
   guint32                 DeviceSerialNumber;
   guint32                 forward_open_frame;
   cip_connID_info_t       O2T;
   cip_connID_info_t       T2O;
   guint8                  TransportClass_trigger;
   cip_safety_epath_info_t safety;
   gboolean                motion;
   guint32                 ClassID;
} cip_conn_info_t;

typedef struct cip_req_info {
   dissector_handle_t         dissector;
   guint8                     bService;
   guint                      IOILen;
   void                      *pIOI;
   void                      *pData;
   cip_simple_request_info_t *ciaData;
   cip_conn_info_t*           connInfo;
} cip_req_info_t;

/*
** Exported functions
*/

/* Depending on if a Class or Symbol segment appears in Connection Path or
   a Request Path, display '->' before or after the actual name. */
#define NO_DISPLAY 0
#define DISPLAY_CONNECTION_PATH 1
#define DISPLAY_REQUEST_PATH 2
extern void dissect_epath( tvbuff_t *tvb, packet_info *pinfo, proto_tree *path_tree, proto_item *epath_item, int offset, int path_length,
                          gboolean generate, gboolean packed, cip_simple_request_info_t* req_data, cip_safety_epath_info_t* safety,
                          int display_type, proto_item *msp_item,
                          gboolean is_msp_item);
extern void dissect_cip_date_and_time(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_datetime);
extern attribute_info_t* cip_get_attribute(guint class_id, guint instance, guint attribute);
extern void dissect_cip_get_attribute_all_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, cip_simple_request_info_t* req_data);

/*
** Exported variables
*/
extern const value_string cip_sc_rr[];
extern const value_string cip_reset_type_vals[];
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

extern void add_cip_service_to_info_column(packet_info *pinfo, guint8 service, const value_string* service_vals);

extern int dissect_optional_attr_list(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int dissect_optional_service_list(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);

extern int dissect_packed_epath(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int dissect_padded_epath(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int dissect_padded_epath_len_usint(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);
extern int dissect_padded_epath_len_uint(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
   int offset, int total_len);

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
