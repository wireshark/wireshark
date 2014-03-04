/* packet-zbee-zcl.h
 * Dissector routines for the ZigBee Cluster Library (ZCL)
 * By Fred Fierling <fff@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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

#ifndef PACKET_ZBEE_ZCL_H
#define PACKET_ZBEE_ZCL_H

/*  Structure to contain the ZCL frame information */
typedef struct{
    gboolean    mfr_spec;
    gboolean    direction;
    gboolean    disable_default_resp;

    guint8      frame_type;
    guint16     mfr_code;
    guint8      tran_seqno;
    guint8      cmd_id;
} zbee_zcl_packet;

/* ZCL Commands */
#define ZBEE_ZCL_CMD_READ_ATTR                  0x00
#define ZBEE_ZCL_CMD_READ_ATTR_RESP             0x01
#define ZBEE_ZCL_CMD_WRITE_ATTR                 0x02
#define ZBEE_ZCL_CMD_WRITE_ATTR_UNDIVIDED       0x03
#define ZBEE_ZCL_CMD_WRITE_ATTR_RESP            0x04
#define ZBEE_ZCL_CMD_WRITE_ATTR_NO_RESP         0x05
#define ZBEE_ZCL_CMD_CONFIG_REPORT              0x06
#define ZBEE_ZCL_CMD_CONFIG_REPORT_RESP         0x07
#define ZBEE_ZCL_CMD_READ_REPORT_CONFIG         0x08
#define ZBEE_ZCL_CMD_READ_REPORT_CONFIG_RESP    0x09
#define ZBEE_ZCL_CMD_REPORT_ATTR                0x0a
#define ZBEE_ZCL_CMD_DEFAULT_RESP               0x0b
#define ZBEE_ZCL_CMD_DISCOVER_ATTR              0x0c
#define ZBEE_ZCL_CMD_DISCOVER_ATTR_RESP         0x0d
#define ZBEE_ZCL_CMD_READ_ATTR_STRUCT           0x0e
#define ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT          0x0f
#define ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT_RESP     0x10
#define ZBEE_ZCL_CMD_DISCOVER_CMDS_REC          0x11
#define ZBEE_ZCL_CMD_DISCOVER_CMDS_REC_RESP     0x12

/* ZCL Data Types */
#define ZBEE_ZCL_NO_DATA            0x00

#define ZBEE_ZCL_8_BIT_DATA         0x08
#define ZBEE_ZCL_16_BIT_DATA        0x09
#define ZBEE_ZCL_24_BIT_DATA        0x0a
#define ZBEE_ZCL_32_BIT_DATA        0x0b
#define ZBEE_ZCL_40_BIT_DATA        0x0c
#define ZBEE_ZCL_48_BIT_DATA        0x0d
#define ZBEE_ZCL_56_BIT_DATA        0x0e
#define ZBEE_ZCL_64_BIT_DATA        0x0f

#define ZBEE_ZCL_BOOLEAN            0x10

#define ZBEE_ZCL_8_BIT_BITMAP       0x18
#define ZBEE_ZCL_16_BIT_BITMAP      0x19
#define ZBEE_ZCL_24_BIT_BITMAP      0x1a
#define ZBEE_ZCL_32_BIT_BITMAP      0x1b
#define ZBEE_ZCL_40_BIT_BITMAP      0x1c
#define ZBEE_ZCL_48_BIT_BITMAP      0x1d
#define ZBEE_ZCL_56_BIT_BITMAP      0x1e
#define ZBEE_ZCL_64_BIT_BITMAP      0x1f

#define ZBEE_ZCL_8_BIT_UINT         0x20
#define ZBEE_ZCL_16_BIT_UINT        0x21
#define ZBEE_ZCL_24_BIT_UINT        0x22
#define ZBEE_ZCL_32_BIT_UINT        0x23
#define ZBEE_ZCL_40_BIT_UINT        0x24
#define ZBEE_ZCL_48_BIT_UINT        0x25
#define ZBEE_ZCL_56_BIT_UINT        0x26
#define ZBEE_ZCL_64_BIT_UINT        0x27

#define ZBEE_ZCL_8_BIT_INT          0x28
#define ZBEE_ZCL_16_BIT_INT         0x29
#define ZBEE_ZCL_24_BIT_INT         0x2a
#define ZBEE_ZCL_32_BIT_INT         0x2b
#define ZBEE_ZCL_40_BIT_INT         0x2c
#define ZBEE_ZCL_48_BIT_INT         0x2d
#define ZBEE_ZCL_56_BIT_INT         0x2e
#define ZBEE_ZCL_64_BIT_INT         0x2f

#define ZBEE_ZCL_8_BIT_ENUM         0x30
#define ZBEE_ZCL_16_BIT_ENUM        0x31

#define ZBEE_ZCL_SEMI_FLOAT         0x38
#define ZBEE_ZCL_SINGLE_FLOAT       0x39
#define ZBEE_ZCL_DOUBLE_FLOAT       0x3a

#define ZBEE_ZCL_OCTET_STRING       0x41
#define ZBEE_ZCL_CHAR_STRING        0x42
#define ZBEE_ZCL_LONG_OCTET_STRING  0x43
#define ZBEE_ZCL_LONG_CHAR_STRING   0x44

#define ZBEE_ZCL_ARRAY              0x48
#define ZBEE_ZCL_STRUCT             0x4c

#define ZBEE_ZCL_SET                0x50
#define ZBEE_ZCL_BAG                0x51

#define ZBEE_ZCL_TIME               0xe0
#define ZBEE_ZCL_DATE               0xe1
#define ZBEE_ZCL_UTC                0xe2

#define ZBEE_ZCL_CLUSTER_ID         0xe8
#define ZBEE_ZCL_ATTR_ID            0xe9
#define ZBEE_ZCL_BACNET_OID         0xea

#define ZBEE_ZCL_IEEE_ADDR          0xf0
#define ZBEE_ZCL_SECURITY_KEY       0xf1

#define ZBEE_ZCL_UNKNOWN            0xff

/* ZCL Miscellaneous */
#define ZBEE_ZCL_INVALID_STR_LENGTH             0xff
#define ZBEE_ZCL_INVALID_LONG_STR_LENGTH        0xffff
#define ZBEE_ZCL_NUM_INDIVIDUAL_ETT             9
#define ZBEE_ZCL_NUM_ATTR_ETT                   64
#define ZBEE_ZCL_NUM_ARRAY_ELEM_ETT             16
#define ZBEE_ZCL_NUM_TOTAL_ETT                  (ZBEE_ZCL_NUM_INDIVIDUAL_ETT + ZBEE_ZCL_NUM_ATTR_ETT + ZBEE_ZCL_NUM_ARRAY_ELEM_ETT)
#define ZBEE_ZCL_DIR_REPORTED                   0
#define ZBEE_ZCL_DIR_RECEIVED                   1
/* seconds elapsed from year 1970 to 2000 */
#define ZBEE_ZCL_NSTIME_UTC_OFFSET              (((3*365 + 366)*7 + 2*365)*24*3600)
#define IS_ANALOG_SUBTYPE(x)    ( (x & 0xe0) == 0x20 || (x & 0xe0) == 0xe0 )

/* ZCL Status Enumerations */
#define ZBEE_ZCL_STAT_SUCCESS                       0x00
#define ZBEE_ZCL_STAT_FAILURE                       0x01

#define ZBEE_ZCL_STAT_NOT_AUTHORIZED                0x7e
#define ZBEE_ZCL_STAT_RESERVED_FIELD_NOT_ZERO       0x7f
#define ZBEE_ZCL_STAT_MALFORMED_CMD                 0x80
#define ZBEE_ZCL_STAT_UNSUP_CLUSTER_CMD             0x81
#define ZBEE_ZCL_STAT_UNSUP_GENERAL_CMD             0x82
#define ZBEE_ZCL_STAT_UNSUP_MFR_CLUSTER_CMD         0x83
#define ZBEE_ZCL_STAT_UNSUP_MFR_GENERAL_CMD         0x84
#define ZBEE_ZCL_STAT_INVALID_FIELD                 0x85
#define ZBEE_ZCL_STAT_UNSUPPORTED_ATTR              0x86
#define ZBEE_ZCL_STAT_INVALID_VALUE                 0x87
#define ZBEE_ZCL_STAT_READ_ONLY                     0x88
#define ZBEE_ZCL_STAT_INSUFFICIENT_SPACE            0x89
#define ZBEE_ZCL_STAT_DUPLICATE_EXISTS              0x8a
#define ZBEE_ZCL_STAT_NOT_FOUND                     0x8b
#define ZBEE_ZCL_STAT_UNREPORTABLE_ATTR             0x8c
#define ZBEE_ZCL_STAT_INVALID_DATA_TYPE             0x8d
#define ZBEE_ZCL_STAT_INVALID_SELECTOR              0x8e
#define ZBEE_ZCL_STAT_WRITE_ONLY                    0x8f
#define ZBEE_ZCL_STAT_INCONSISTENT_STARTUP_STATE    0x90
#define ZBEE_ZCL_STAT_DEFINED_OUT_OF_BAND           0x91
#define ZBEE_ZCL_STAT_OTA_ABORT                     0x95
#define ZBEE_ZCL_STAT_OTA_INVALID_IMAGE             0x96
#define ZBEE_ZCL_STAT_OTA_WAIT_FOR_DATA             0x97
#define ZBEE_ZCL_STAT_OTA_NO_IMAGE_AVAILABLE        0x98
#define ZBEE_ZCL_STAT_OTA_REQUIRE_MORE_IMAGE        0x99
#define ZBEE_ZCL_STAT_HARDWARE_FAILURE              0xc0
#define ZBEE_ZCL_STAT_SOFTWARE_FAILURE              0xc1
#define ZBEE_ZCL_STAT_CALIBRATION_ERROR             0xc2

/* Misc. */
#define INT24_SIGN_BITS                             0xffff8000
#define MONTHS_PER_YEAR                             12
#define YEAR_OFFSET                                 1900

typedef void (*zbee_zcl_fn_attr_id)      (proto_tree *tree, tvbuff_t *tvb, guint *offset);
typedef void (*zbee_zcl_fn_attr_data)    (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint16 attr_id, guint data_type);
typedef void (*zbee_zcl_fn_cmd_id)       (proto_tree *tree, tvbuff_t *tvb, guint *offset, guint8 dir);

typedef struct _zbee_zcl_cluster_desc {
    int         proto_id;
    protocol_t  *proto;
    const char  *name;
    int         ett;
    guint16     cluster_id;
    zbee_zcl_fn_attr_id fn_attr_id;
    zbee_zcl_fn_attr_data fn_attr_data;
	zbee_zcl_fn_cmd_id fn_cmd_id;
} zbee_zcl_cluster_desc;

extern const value_string zbee_zcl_short_data_type_names[];
extern const value_string zbee_mfr_code_names[];
extern const value_string zbee_zcl_status_names[];

/* Dissector functions */
extern void dissect_zcl_read_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
extern void dissect_zcl_write_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
extern void dissect_zcl_read_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);

/* Helper functions */
void decode_zcl_time_in_seconds (gchar *s, guint16 value);
void decode_zcl_time_in_minutes (gchar *s, guint16 value);
void dissect_zcl_attr_data (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint data_type);
void zbee_zcl_init_cluster(int proto, gint ett, guint16 cluster_id, zbee_zcl_fn_attr_id fn_attr_id, zbee_zcl_fn_attr_data fn_attr_data, zbee_zcl_fn_cmd_id fn_cmd_id);
zbee_zcl_cluster_desc *zbee_zcl_get_cluster_desc(guint16 cluster_id);

/* Cluster-specific commands and parameters */
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_NEP             0x02
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_NS              0x01
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_S               0x00
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_TMZ             0x03
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ZER                 0x00
#define ZBEE_ZCL_CSC_IAS_ZONE_S_ZER                 0x01
#define ZBEE_ZCL_CSC_IAS_ZONE_S_ZSCN                0x00
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_CIR             0x00
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_FPS             0x01
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_SLPI            0x02
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_SSPI            0x03
#define ZBEE_ZCL_CSC_POLL_CONTROL_S_CI              0x00
#define ZBEE_ZCL_CSC_THERMOSTAT_C_CWS               0x03
#define ZBEE_ZCL_CSC_THERMOSTAT_C_GWS               0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SRL               0x00
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS               0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_AV        0x80
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_FR        0x20
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_MO        0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SA        0x40
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SU        0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TH        0x10
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TU        0x04
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_WE        0x08
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_B          0x03
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_C          0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_H          0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_S_GWSR              0x00

#endif /* PACKET_ZBEE_ZCL_H*/
