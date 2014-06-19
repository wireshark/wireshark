/* packet-zbee-zcl.c
 * Dissector routines for the ZigBee Cluster Library (ZCL)
 * By Fred Fierling <fff@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Used Owen Kirby's packet-zbee-aps module as a template. Based
 * on ZigBee Cluster Library Specification document 075123r02ZB
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

/*  Include Files */
#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/*************************
 * Function Declarations *
 *************************
 */
void proto_register_zbee_zcl(void);
void proto_reg_handoff_zbee_zcl(void);

/* Command Dissector Helpers */
static void dissect_zcl_write_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
static void dissect_zcl_config_report (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
static void dissect_zcl_config_report_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
static void dissect_zcl_read_report_config (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
static void dissect_zcl_read_report_config_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);
static void dissect_zcl_default_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint8 dir);
static void dissect_zcl_discover_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_discover_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id);

/* Helper routines */
static void  dissect_zcl_attr_data_general(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 attr_id, guint data_type, guint16 cluster_id);
static void  dissect_zcl_attr_data_type_val (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 cmd_id, guint16 cluster_id);
static guint dissect_zcl_attr_uint8 (tvbuff_t *tvb, proto_tree *tree, guint *offset, int *length);
static void  dissect_zcl_attr_id (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 cluster_id);
static void  zcl_dump_data(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree);

static void dissect_zcl_array_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num);
static void dissect_zcl_set_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num);

/********************
 * Global Variables *
 ********************
 */
/* Header Field Indices. */
static int proto_zbee_zcl = -1;
static int hf_zbee_zcl_fcf_frame_type = -1;
static int hf_zbee_zcl_fcf_mfr_spec = -1;
static int hf_zbee_zcl_fcf_dir = -1;
static int hf_zbee_zcl_fcf_disable_default_resp = -1;
static int hf_zbee_zcl_mfr_code = -1;
static int hf_zbee_zcl_tran_seqno = -1;

static int hf_zbee_zcl_cmd_id = -1;
static int hf_zbee_zcl_cs_cmd_id = -1;
static int hf_zbee_zcl_attr_id = -1;
static int hf_zbee_zcl_attr_data_type = -1;
static int hf_zbee_zcl_attr_boolean = -1;
static int hf_zbee_zcl_attr_uint8 = -1;
static int hf_zbee_zcl_attr_uint16 = -1;
static int hf_zbee_zcl_attr_uint24 = -1;
static int hf_zbee_zcl_attr_uint32 = -1;
static int hf_zbee_zcl_attr_uint64 = -1;
static int hf_zbee_zcl_attr_int8 = -1;
static int hf_zbee_zcl_attr_int16 = -1;
static int hf_zbee_zcl_attr_int24 = -1;
static int hf_zbee_zcl_attr_int32 = -1;
static int hf_zbee_zcl_attr_int64 = -1;
/* static int hf_zbee_zcl_attr_semi = -1; */
static int hf_zbee_zcl_attr_float = -1;
static int hf_zbee_zcl_attr_double = -1;
static int hf_zbee_zcl_attr_bytes = -1;
static int hf_zbee_zcl_attr_minint = -1;
static int hf_zbee_zcl_attr_maxint = -1;
static int hf_zbee_zcl_attr_timeout = -1;
static int hf_zbee_zcl_attr_cid = -1;
static int hf_zbee_zcl_attr_hours = -1;
static int hf_zbee_zcl_attr_mins = -1;
static int hf_zbee_zcl_attr_secs = -1;
static int hf_zbee_zcl_attr_csecs = -1;
static int hf_zbee_zcl_attr_yy = -1;
static int hf_zbee_zcl_attr_mm = -1;
static int hf_zbee_zcl_attr_md = -1;
static int hf_zbee_zcl_attr_wd = -1;
static int hf_zbee_zcl_attr_utc = -1;
static int hf_zbee_zcl_attr_status = -1;
static int hf_zbee_zcl_attr_dir = -1;
static int hf_zbee_zcl_attr_dis = -1;
static int hf_zbee_zcl_attr_start = -1;
static int hf_zbee_zcl_attr_maxnum = -1;
static int hf_zbee_zcl_attr_str_len = -1;
static int hf_zbee_zcl_attr_str = -1;
static int hf_zbee_zcl_attr_ostr = -1;
static int hf_zbee_zcl_attr_array_elements_type = -1;
static int hf_zbee_zcl_attr_array_elements_num = -1;
static int hf_zbee_zcl_attr_set_elements_type = -1;
static int hf_zbee_zcl_attr_set_elements_num = -1;
static int hf_zbee_zcl_attr_bag_elements_type = -1;
static int hf_zbee_zcl_attr_bag_elements_num = -1;

static int hf_zbee_zcl_ias_zone_client_cmd_id = -1;
static int hf_zbee_zcl_ias_zone_client_zer_erc = -1;
static int hf_zbee_zcl_ias_zone_client_zer_zone_id = -1;
static int hf_zbee_zcl_ias_zone_server_cmd_id = -1;
static int hf_zbee_zcl_ias_zone_server_scn_ac_mains = -1;
static int hf_zbee_zcl_ias_zone_server_scn_alarm1 = -1;
static int hf_zbee_zcl_ias_zone_server_scn_alarm2 = -1;
static int hf_zbee_zcl_ias_zone_server_scn_battery = -1;
static int hf_zbee_zcl_ias_zone_server_scn_delay = -1;
static int hf_zbee_zcl_ias_zone_server_scn_ext_status = -1;
static int hf_zbee_zcl_ias_zone_server_scn_restore_reports = -1;
static int hf_zbee_zcl_ias_zone_server_scn_supervision_reports = -1;
static int hf_zbee_zcl_ias_zone_server_scn_tamper = -1;
static int hf_zbee_zcl_ias_zone_server_scn_trouble = -1;
static int hf_zbee_zcl_ias_zone_server_scn_zone_id = -1;
static int hf_zbee_zcl_ias_zone_server_scn_zone_status = -1;
static int hf_zbee_zcl_poll_control_client_cir_fpt = -1;
static int hf_zbee_zcl_poll_control_client_cir_sfp = -1;
static int hf_zbee_zcl_poll_control_client_cmd_id = -1;
static int hf_zbee_zcl_poll_control_client_slpi_nlpi = -1;
static int hf_zbee_zcl_poll_control_client_sspi_nspi = -1;
static int hf_zbee_zcl_poll_control_server_cmd_id = -1;
static int hf_zbee_zcl_thermostat_client_cmd_id = -1;
static int hf_zbee_zcl_thermostat_client_gws_days_to_return = -1;
static int hf_zbee_zcl_thermostat_client_gws_mtr = -1;
static int hf_zbee_zcl_thermostat_client_gws_mtr_cool = -1;
static int hf_zbee_zcl_thermostat_client_gws_mtr_heat = -1;
static int hf_zbee_zcl_thermostat_client_setpointrl_amount_field = -1;
static int hf_zbee_zcl_thermostat_client_setpointrl_modes = -1;
static int hf_zbee_zcl_thermostat_client_sws_dow = -1;
static int hf_zbee_zcl_thermostat_client_sws_mfs = -1;
static int hf_zbee_zcl_thermostat_client_sws_mfs_cool = -1;
static int hf_zbee_zcl_thermostat_client_sws_mfs_heat = -1;
static int hf_zbee_zcl_thermostat_client_sws_n_trans = -1;
static int hf_zbee_zcl_thermostat_server_cmd_id = -1;
static int hf_zbee_zcl_thermostat_server_gwsr_dow = -1;
static int hf_zbee_zcl_thermostat_server_gwsr_mfs = -1;
static int hf_zbee_zcl_thermostat_server_gwsr_mfs_cool = -1;
static int hf_zbee_zcl_thermostat_server_gwsr_mfs_heat = -1;
static int hf_zbee_zcl_thermostat_server_gwsr_n_trans = -1;

/* Subtree indices. */
static gint ett_zbee_zcl = -1;
static gint ett_zbee_zcl_fcf = -1;
static gint ett_zbee_zcl_attr[ZBEE_ZCL_NUM_ATTR_ETT];
static gint ett_zbee_zcl_array_elements[ZBEE_ZCL_NUM_ARRAY_ELEM_ETT];

static gint ett_zbee_zcl_ias_zone_server_scn_zone_status = -1;
static gint ett_zbee_zcl_thermostat_client_gws_days_to_return = -1;
static gint ett_zbee_zcl_thermostat_client_gws_mtr = -1;
static gint ett_zbee_zcl_thermostat_client_sws_dow_for_sequence = -1;
static gint ett_zbee_zcl_thermostat_client_sws_mfs = -1;
static gint ett_zbee_zcl_thermostat_server_gwsr_dow_for_sequence = -1;
static gint ett_zbee_zcl_thermostat_server_gwsr_mfs = -1;

/* Dissector Handles. */
static dissector_handle_t   data_handle;

/* Dissector List. */
static dissector_table_t    zbee_zcl_dissector_table;

/* Global variables */
static guint16 zcl_cluster_id = -1;

static GList *acluster_desc = NULL;

/********************/
/* Field Names      */
/********************/
/* Frame Type Names */
static const value_string zbee_zcl_frame_types[] = {
    { ZBEE_ZCL_FCF_PROFILE_WIDE,    "Profile-wide" },
    { ZBEE_ZCL_FCF_CLUSTER_SPEC,    "Cluster-specific" },
    { 0, NULL }
};

/* ZCL Command Names */
static const value_string zbee_zcl_cmd_names[] = {
    { ZBEE_ZCL_CMD_READ_ATTR,               "Read Attributes" },
    { ZBEE_ZCL_CMD_READ_ATTR_RESP,          "Read Attributes Response" },
    { ZBEE_ZCL_CMD_WRITE_ATTR,              "Write Attributes" },
    { ZBEE_ZCL_CMD_WRITE_ATTR_UNDIVIDED,    "Write Attributes Undivided" },
    { ZBEE_ZCL_CMD_WRITE_ATTR_RESP,         "Write Attributes Response" },
    { ZBEE_ZCL_CMD_WRITE_ATTR_NO_RESP,      "Write Attributes No Response" },
    { ZBEE_ZCL_CMD_CONFIG_REPORT,           "Configure Reporting" },
    { ZBEE_ZCL_CMD_CONFIG_REPORT_RESP,      "Configure Reporting Response" },
    { ZBEE_ZCL_CMD_READ_REPORT_CONFIG,      "Read Reporting Configuration" },
    { ZBEE_ZCL_CMD_READ_REPORT_CONFIG_RESP, "Read Reporting Configuration Response" },
    { ZBEE_ZCL_CMD_REPORT_ATTR,             "Report Attributes" },
    { ZBEE_ZCL_CMD_DEFAULT_RESP,            "Default Response" },
    { ZBEE_ZCL_CMD_DISCOVER_ATTR,           "Discover Attributes" },
    { ZBEE_ZCL_CMD_DISCOVER_ATTR_RESP,      "Discover Attributes Response" },
    { ZBEE_ZCL_CMD_READ_ATTR_STRUCT,        "Read Attributes Structured" },
    { ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT,       "Write Attributes Structured" },
    { ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT_RESP,  "Write Attributes Structured Response" },
    { ZBEE_ZCL_CMD_DISCOVER_CMDS_REC,       "Discover Commands Received" },
    { ZBEE_ZCL_CMD_DISCOVER_CMDS_REC_RESP,  "Discover Commands Received Response" },

    { 0, NULL }
};
static value_string_ext zbee_zcl_cmd_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_cmd_names);

/* ZCL Cluster-Specific Command Names */
static const value_string zbee_zcl_cs_cmd_names[] = {
    { 0, NULL }
};


/* ZigBee Manufacturer Name Table */
/* Per: 053298r19, December 2011 */
const value_string zbee_mfr_code_names[] = {

    { ZBEE_MFG_CODE_SAMSUNG,    ZBEE_MFG_SAMSUNG },
    { ZBEE_MFG_CODE_CIRRONET,   ZBEE_MFG_CIRRONET },
    { ZBEE_MFG_CODE_CHIPCON,    ZBEE_MFG_CHIPCON },
    { ZBEE_MFG_CODE_EMBER,      ZBEE_MFG_EMBER },
    { ZBEE_MFG_CODE_NTS,        ZBEE_MFG_NTS },
    { ZBEE_MFG_CODE_FREESCALE,  ZBEE_MFG_FREESCALE },
    { ZBEE_MFG_CODE_IPCOM,      ZBEE_MFG_IPCOM },
    { ZBEE_MFG_CODE_SAN_JUAN,   ZBEE_MFG_SAN_JUAN },
    { ZBEE_MFG_CODE_TUV,        ZBEE_MFG_TUV },
    { ZBEE_MFG_CODE_COMPXS,     ZBEE_MFG_COMPXS },
    { ZBEE_MFG_CODE_BM,         ZBEE_MFG_BM },
    { ZBEE_MFG_CODE_AWAREPOINT, ZBEE_MFG_AWAREPOINT },
    { ZBEE_MFG_CODE_PHILIPS,    ZBEE_MFG_PHILIPS },
    { ZBEE_MFG_CODE_LUXOFT,     ZBEE_MFG_LUXOFT },
    { ZBEE_MFG_CODE_KORWIN,     ZBEE_MFG_KORWIN },
    { ZBEE_MFG_CODE_1_RF,       ZBEE_MFG_1_RF },
    { ZBEE_MFG_CODE_STG,        ZBEE_MFG_STG },

    { ZBEE_MFG_CODE_TELEGESIS,  ZBEE_MFG_TELEGESIS },
    { ZBEE_MFG_CODE_VISIONIC,   ZBEE_MFG_VISIONIC },
    { ZBEE_MFG_CODE_INSTA,      ZBEE_MFG_INSTA },
    { ZBEE_MFG_CODE_ATALUM,     ZBEE_MFG_ATALUM },
    { ZBEE_MFG_CODE_ATMEL,      ZBEE_MFG_ATMEL },
    { ZBEE_MFG_CODE_DEVELCO,    ZBEE_MFG_DEVELCO },
    { ZBEE_MFG_CODE_HONEYWELL,  ZBEE_MFG_HONEYWELL },
    { 0x1017,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_RENESAS,    ZBEE_MFG_RENESAS },
    { ZBEE_MFG_CODE_XANADU,     ZBEE_MFG_XANADU },
    { ZBEE_MFG_CODE_NEC,        ZBEE_MFG_NEC },
    { ZBEE_MFG_CODE_YAMATAKE,   ZBEE_MFG_YAMATAKE },
    { ZBEE_MFG_CODE_TENDRIL,    ZBEE_MFG_TENDRIL },
    { ZBEE_MFG_CODE_ASSA,       ZBEE_MFG_ASSA },
    { ZBEE_MFG_CODE_MAXSTREAM,  ZBEE_MFG_MAXSTREAM },
    { ZBEE_MFG_CODE_NEUROCOM,   ZBEE_MFG_NEUROCOM },

    { ZBEE_MFG_CODE_III,        ZBEE_MFG_III },
    { ZBEE_MFG_CODE_VANTAGE,    ZBEE_MFG_VANTAGE },
    { ZBEE_MFG_CODE_ICONTROL,   ZBEE_MFG_ICONTROL },
    { ZBEE_MFG_CODE_RAYMARINE,  ZBEE_MFG_RAYMARINE },
    { ZBEE_MFG_CODE_LSR,        ZBEE_MFG_LSR },
    { ZBEE_MFG_CODE_ONITY,      ZBEE_MFG_ONITY },
    { ZBEE_MFG_CODE_MONO,       ZBEE_MFG_MONO },
    { ZBEE_MFG_CODE_RFT,        ZBEE_MFG_RFT },
    { ZBEE_MFG_CODE_ITRON,      ZBEE_MFG_ITRON },
    { ZBEE_MFG_CODE_TRITECH,    ZBEE_MFG_TRITECH },
    { ZBEE_MFG_CODE_EMBEDIT,    ZBEE_MFG_EMBEDIT },
    { ZBEE_MFG_CODE_S3C,        ZBEE_MFG_S3C },
    { ZBEE_MFG_CODE_SIEMENS,    ZBEE_MFG_SIEMENS },
    { ZBEE_MFG_CODE_MINDTECH,   ZBEE_MFG_MINDTECH },
    { ZBEE_MFG_CODE_LGE,        ZBEE_MFG_LGE },
    { ZBEE_MFG_CODE_MITSUBISHI, ZBEE_MFG_MITSUBISHI },

    { ZBEE_MFG_CODE_JOHNSON,    ZBEE_MFG_JOHNSON },
    { ZBEE_MFG_CODE_PRI,        ZBEE_MFG_PRI },
    { ZBEE_MFG_CODE_KNICK,      ZBEE_MFG_KNICK },
    { ZBEE_MFG_CODE_VICONICS,   ZBEE_MFG_VICONICS },
    { ZBEE_MFG_CODE_FLEXIPANEL, ZBEE_MFG_FLEXIPANEL },
    { 0x1035,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_TRANE,      ZBEE_MFG_TRANE },
    { ZBEE_MFG_CODE_JENNIC,     ZBEE_MFG_JENNIC },
    { ZBEE_MFG_CODE_LIG,        ZBEE_MFG_LIG },
    { ZBEE_MFG_CODE_ALERTME,    ZBEE_MFG_ALERTME },
    { ZBEE_MFG_CODE_DAINTREE,   ZBEE_MFG_DAINTREE },
    { ZBEE_MFG_CODE_AIJI,       ZBEE_MFG_AIJI },
    { ZBEE_MFG_CODE_TEL_ITALIA, ZBEE_MFG_TEL_ITALIA },
    { ZBEE_MFG_CODE_MIKROKRETS, ZBEE_MFG_MIKROKRETS },
    { ZBEE_MFG_CODE_OKI,        ZBEE_MFG_OKI },
    { ZBEE_MFG_CODE_NEWPORT,    ZBEE_MFG_NEWPORT },

    { ZBEE_MFG_CODE_C4,         ZBEE_MFG_C4 },
    { ZBEE_MFG_CODE_STM,        ZBEE_MFG_STM },
    { ZBEE_MFG_CODE_ASN,        ZBEE_MFG_ASN },
    { ZBEE_MFG_CODE_DCSI,       ZBEE_MFG_DCSI },
    { ZBEE_MFG_CODE_FRANCE_TEL, ZBEE_MFG_FRANCE_TEL },
    { ZBEE_MFG_CODE_MUNET,      ZBEE_MFG_MUNET },
    { ZBEE_MFG_CODE_AUTANI,     ZBEE_MFG_AUTANI },
    { ZBEE_MFG_CODE_COL_VNET,   ZBEE_MFG_COL_VNET },
    { ZBEE_MFG_CODE_AEROCOMM,   ZBEE_MFG_AEROCOMM },
    { ZBEE_MFG_CODE_SI_LABS,    ZBEE_MFG_SI_LABS },
    { ZBEE_MFG_CODE_INNCOM,     ZBEE_MFG_INNCOM },
    { ZBEE_MFG_CODE_CANNON,     ZBEE_MFG_CANNON },
    { ZBEE_MFG_CODE_SYNAPSE,    ZBEE_MFG_SYNAPSE },
    { ZBEE_MFG_CODE_FPS,        ZBEE_MFG_FPS },
    { ZBEE_MFG_CODE_CLS,        ZBEE_MFG_CLS },
    { ZBEE_MFG_CODE_CRANE,      ZBEE_MFG_CRANE },

    { ZBEE_MFG_CODE_MOBILARM,   ZBEE_MFG_MOBILARM },
    { ZBEE_MFG_CODE_IMONITOR,   ZBEE_MFG_IMONITOR },
    { ZBEE_MFG_CODE_BARTECH,    ZBEE_MFG_BARTECH },
    { ZBEE_MFG_CODE_MESHNETICS, ZBEE_MFG_MESHNETICS },
    { ZBEE_MFG_CODE_LS_IND,     ZBEE_MFG_LS_IND },
    { ZBEE_MFG_CODE_CASON,      ZBEE_MFG_CASON },
    { ZBEE_MFG_CODE_WLESS_GLUE, ZBEE_MFG_WLESS_GLUE },
    { ZBEE_MFG_CODE_ELSTER,     ZBEE_MFG_ELSTER },
    { ZBEE_MFG_CODE_SMS_TEC,    ZBEE_MFG_SMS_TEC },
    { ZBEE_MFG_CODE_ONSET,      ZBEE_MFG_ONSET },
    { ZBEE_MFG_CODE_RIGA,       ZBEE_MFG_RIGA },
    { ZBEE_MFG_CODE_ENERGATE,   ZBEE_MFG_ENERGATE },
    { ZBEE_MFG_CODE_CONMED,     ZBEE_MFG_CONMED },
    { ZBEE_MFG_CODE_POWERMAND,  ZBEE_MFG_POWERMAND },
    { ZBEE_MFG_CODE_SCHNEIDER,  ZBEE_MFG_SCHNEIDER },
    { ZBEE_MFG_CODE_EATON,      ZBEE_MFG_EATON },

    { ZBEE_MFG_CODE_TELULAR,    ZBEE_MFG_TELULAR },
    { ZBEE_MFG_CODE_DELPHI,     ZBEE_MFG_DELPHI },
    { ZBEE_MFG_CODE_EPISENSOR,  ZBEE_MFG_EPISENSOR },
    { ZBEE_MFG_CODE_LANDIS_GYR, ZBEE_MFG_LANDIS_GYR },
    { ZBEE_MFG_CODE_KABA,       ZBEE_MFG_KABA },
    { ZBEE_MFG_CODE_SHURE,      ZBEE_MFG_SHURE },
    { ZBEE_MFG_CODE_COMVERGE,   ZBEE_MFG_COMVERGE },
    { 0x1067,                   "Unknown" },             /**/
    { 0x1068,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_HIDALGO,    ZBEE_MFG_HIDALGO },
    { ZBEE_MFG_CODE_AIR2APP,    ZBEE_MFG_AIR2APP },
    { ZBEE_MFG_CODE_AMX,        ZBEE_MFG_AMX },
    { ZBEE_MFG_CODE_EDMI,       ZBEE_MFG_EDMI },
    { ZBEE_MFG_CODE_CYAN,       ZBEE_MFG_CYAN },
    { ZBEE_MFG_CODE_SYS_SPA,    ZBEE_MFG_SYS_SPA },
    { ZBEE_MFG_CODE_TELIT,      ZBEE_MFG_TELIT },

    { ZBEE_MFG_CODE_KAGA,       ZBEE_MFG_KAGA },
    { ZBEE_MFG_CODE_4_NOKS,     ZBEE_MFG_4_NOKS },
    { 0x1072,                   "Unknown" },             /**/
    { 0x1073,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_PROFILE_SYS,ZBEE_MFG_PROFILE_SYS },
    { 0x1075,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_FREESTYLE,  ZBEE_MFG_FREESTYLE },
    { 0x1077,                   "Unknown" },             /**/
    { 0x1078,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_REMOTE     ,ZBEE_MFG_REMOTE },
    { ZBEE_MFG_CODE_WAVECOM,    ZBEE_MFG_WAVECOM },
    { ZBEE_MFG_CODE_ENERGY_OPT, ZBEE_MFG_ENERGY_OPT },
    { ZBEE_MFG_CODE_GE,         ZBEE_MFG_GE },
    { 0x107d,                   "Unknown" },             /**/
    { 0x107e,                   "Unknown" },             /**/
    { 0x107f,                   "Unknown" },             /**/

    { 0x1080,                   "Unknown" },             /**/
    { 0x1081,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_MESHWORKS,  ZBEE_MFG_MESHWORKS },
    { ZBEE_MFG_CODE_ELLIPS,     ZBEE_MFG_ELLIPS },
    { 0x1084,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_CEDO,       ZBEE_MFG_CEDO },
    { 0x1086,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_DIGI,       ZBEE_MFG_DIGI },
    { 0x1088,                   "Unknown" },             /**/
    { 0x1089,                   "Unknown" },             /**/
    { 0x108a,                   "Unknown" },             /**/
    { 0x108b,                   "Unknown" },             /**/
    { 0x108c,                   "Unknown" },             /**/
    { 0x108d,                   "Unknown" },             /**/
    { 0x108e,                   "Unknown" },             /**/
    { 0x108f,                   "Unknown" },             /**/

    { 0x1090,                   "Unknown" },             /**/
    { 0x1091,                   "Unknown" },             /**/
    { 0x1092,                   "Unknown" },             /**/
    { 0x1093,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_A_D,        ZBEE_MFG_A_D },
    { 0x1095,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_CARRIER,    ZBEE_MFG_CARRIER },
    { ZBEE_MFG_CODE_SYCHIP,     ZBEE_MFG_SYCHIP },
    { 0x1098,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_PASSIVESYS, ZBEE_MFG_PASSIVESYS },
    { ZBEE_MFG_CODE_MMB,        ZBEE_MFG_MMB },
    { ZBEE_MFG_CODE_HOME_AUTO,  ZBEE_MFG_HOME_AUTO },
    { 0x109c,                   "Unknown" },             /**/
    { 0x109d,                   "Unknown" },             /**/
    { 0x109e,                   "Unknown" },             /**/
    { 0x109f,                   "Unknown" },             /**/

    { 0x10a0,                   "Unknown" },             /**/
    { 0x10a1,                   "Unknown" },             /**/
    { 0x10a2,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_SUNRISE,    ZBEE_MFG_SUNRISE },
    { ZBEE_MFG_CODE_MEMTEC,     ZBEE_MFG_MEMTEC },
    { 0x10a5,                   "Unknown" },             /**/
    { 0x10a6,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_BRITISH_GAS,ZBEE_MFG_BRITISH_GAS },
    { ZBEE_MFG_CODE_SENTEC,     ZBEE_MFG_SENTEC },
    { ZBEE_MFG_CODE_NAVETAS,    ZBEE_MFG_NAVETAS },
    { 0x10aa,                   "Unknown" },             /**/
    { 0x10ab,                   "Unknown" },             /**/
    { 0x10ac,                   "Unknown" },             /**/
    { 0x10ad,                   "Unknown" },             /**/
    { 0x10ae,                   "Unknown" },             /**/
    { 0x10af,                   "Unknown" },             /**/

    { 0x10b0,                   "Unknown" },             /**/
    { 0x10b1,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_ENERNOC,    ZBEE_MFG_ENERNOC },
    { ZBEE_MFG_CODE_ELTAV,      ZBEE_MFG_ELTAV },
    { 0x10b4,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_XSTREAMHD,  ZBEE_MFG_XSTREAMHD },
    { 0x10b6,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_GREEN,      ZBEE_MFG_GREEN },
    { 0x10b8,                   "Unknown" },             /**/
    { 0x10b9,                   "Unknown" },             /**/
    { 0x10ba,                   "Unknown" },             /**/
    { 0x10bb,                   "Unknown" },             /**/
    { 0x10bc,                   "Unknown" },             /**/
    { 0x10bd,                   "Unknown" },             /**/
    { 0x10be,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_OMRON,      ZBEE_MFG_OMRON },
    { 0x10c0,                   "Unknown" },             /**/
    { 0x10c1,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_PEEL,       ZBEE_MFG_PEEL },
    { 0x10c3,                   "Unknown" },             /**/
    { 0x10c4,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_NEC_TOKIN,  ZBEE_MFG_NEC_TOKIN },
    { ZBEE_MFG_CODE_G4S_JUSTICE,ZBEE_MFG_G4S_JUSTICE },
    { 0x10c7,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_ELECTROLUX, ZBEE_MFG_ELECTROLUX },
    { 0x10c9,                   "Unknown" },             /**/
    { 0x10ca,                   "Unknown" },             /**/
    { 0x10cb,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_MAINSTREAM, ZBEE_MFG_MAINSTREAM },
    { ZBEE_MFG_CODE_INDESIT_C,  ZBEE_MFG_INDESIT_C },
    { 0x10ce,                   "Unknown" },             /**/
    { 0x10cf,                   "Unknown" },             /**/
    { 0x10d0,                   "Unknown" },             /**/
    { 0x10d1,                   "Unknown" },             /**/
    { 0x10d2,                   "Unknown" },             /**/
    { 0x10d3,                   "Unknown" },             /**/
    { 0x10d4,                   "Unknown" },             /**/
    { 0x10d5,                   "Unknown" },             /**/
    { 0x10d6,                   "Unknown" },             /**/
    { 0x10d7,                   "Unknown" },             /**/
    { 0x10d8,                   "Unknown" },             /**/
    { 0x10d9,                   "Unknown" },             /**/
    { 0x10da,                   "Unknown" },             /**/
    { 0x10db,                   "Unknown" },             /**/
    { 0x10dc,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_RADIOCRAFTS,ZBEE_MFG_RADIOCRAFTS },
    { 0x10de,                   "Unknown" },             /**/
    { 0x10df,                   "Unknown" },             /**/
    { 0x10e0,                   "Unknown" },             /**/
    { 0x10e1,                   "Unknown" },             /**/
    { 0x10e2,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_HUAWEI_1,   ZBEE_MFG_HUAWEI },
    { ZBEE_MFG_CODE_HUAWEI_2,   ZBEE_MFG_HUAWEI },
    { 0x10e5,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_BGLOBAL,    ZBEE_MFG_BGLOBAL },
    { 0x10e7,                   "Unknown" },             /**/
    { 0x10e8,                   "Unknown" },             /**/
    { 0x10e9,                   "Unknown" },             /**/
    { 0x10ea,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_ABB,        ZBEE_MFG_ABB },
    { 0x10ec,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_GENUS,      ZBEE_MFG_GENUS },
    { 0x10ee,                   "Unknown" },             /**/
    { 0x10ef,                   "Unknown" },             /**/
    { 0x10f0,                   "Unknown" },             /**/
    { 0x10f1,                   "Unknown" },             /**/
    { 0x10f2,                   "Unknown" },             /**/
    { 0x10f3,                   "Unknown" },             /**/
    { 0x10f4,                   "Unknown" },             /**/
    { 0x10f5,                   "Unknown" },             /**/
    { 0x10f6,                   "Unknown" },             /**/
    { 0x10f7,                   "Unknown" },             /**/
    { 0x10f8,                   "Unknown" },             /**/
    { 0x10f9,                   "Unknown" },             /**/
    { 0x10fa,                   "Unknown" },             /**/
    { 0x10fb,                   "Unknown" },             /**/
    { 0x10fc,                   "Unknown" },             /**/
    { 0x10fd,                   "Unknown" },             /**/
    { 0x10fe,                   "Unknown" },             /**/
    { 0x10ff,                   "Unknown" },             /**/
    { ZBEE_MFG_CODE_RELOC,      ZBEE_MFG_RELOC },
    { 0, NULL }
};
static value_string_ext zbee_mfr_code_names_ext = VALUE_STRING_EXT_INIT(zbee_mfr_code_names);

/* ZCL Attribute Status Names */
const value_string zbee_zcl_status_names[] = {
    { ZBEE_ZCL_STAT_SUCCESS,                        "Success"},
    { ZBEE_ZCL_STAT_FAILURE,                        "Failure"},

    { ZBEE_ZCL_STAT_NOT_AUTHORIZED,                 "Not Authorized"},
    { ZBEE_ZCL_STAT_RESERVED_FIELD_NOT_ZERO,        "Reserved Field Not Zero"},
    { ZBEE_ZCL_STAT_MALFORMED_CMD,                  "Malformed Command"},
    { ZBEE_ZCL_STAT_UNSUP_CLUSTER_CMD,              "Unsupported Cluster Command"},
    { ZBEE_ZCL_STAT_UNSUP_GENERAL_CMD,              "Unsupported General Command"},
    { ZBEE_ZCL_STAT_UNSUP_MFR_CLUSTER_CMD,          "Unsupported Manufacturer Cluster Command"},
    { ZBEE_ZCL_STAT_UNSUP_MFR_GENERAL_CMD,          "Unsupported Manufacturer General Command"},
    { ZBEE_ZCL_STAT_INVALID_FIELD,                  "Invalid Field"},
    { ZBEE_ZCL_STAT_UNSUPPORTED_ATTR,               "Unsupported Attribute"},
    { ZBEE_ZCL_STAT_INVALID_VALUE,                  "Invalid Value"},
    { ZBEE_ZCL_STAT_READ_ONLY,                      "Read Only"},
    { ZBEE_ZCL_STAT_INSUFFICIENT_SPACE,             "Insufficient Space"},
    { ZBEE_ZCL_STAT_DUPLICATE_EXISTS,               "Duplicate Exists"},
    { ZBEE_ZCL_STAT_NOT_FOUND,                      "Not Found"},
    { ZBEE_ZCL_STAT_UNREPORTABLE_ATTR,              "Unreportable Attribute"},
    { ZBEE_ZCL_STAT_INVALID_DATA_TYPE,              "Invalid Data Type"},
    { ZBEE_ZCL_STAT_INVALID_SELECTOR,               "Invalid Selector"},
    { ZBEE_ZCL_STAT_WRITE_ONLY,                     "Write Only"},
    { ZBEE_ZCL_STAT_INCONSISTENT_STARTUP_STATE,     "Inconsistent Startup State"},
    { ZBEE_ZCL_STAT_DEFINED_OUT_OF_BAND,            "Defined Out of Band"},
    { ZBEE_ZCL_STAT_OTA_ABORT,                      "Ota Abort"},
    { ZBEE_ZCL_STAT_OTA_INVALID_IMAGE,              "Ota Invalid Image"},
    { ZBEE_ZCL_STAT_OTA_WAIT_FOR_DATA,              "Ota Wait For Data"},
    { ZBEE_ZCL_STAT_OTA_NO_IMAGE_AVAILABLE,         "Ota No Image Available"},
    { ZBEE_ZCL_STAT_OTA_REQUIRE_MORE_IMAGE,         "Ota Require More Image"},
    { ZBEE_ZCL_STAT_HARDWARE_FAILURE,               "Hardware Failure"},
    { ZBEE_ZCL_STAT_SOFTWARE_FAILURE,               "Software Failure"},
    { ZBEE_ZCL_STAT_CALIBRATION_ERROR,              "Calibration Error"},

    { 0, NULL }
};
static value_string_ext zbee_zcl_status_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_status_names);

/* ZCL Attribute Data Names */
static const value_string zbee_zcl_data_type_names[] = {
    { ZBEE_ZCL_NO_DATA,             "No Data" },
    { ZBEE_ZCL_8_BIT_DATA,          "8-Bit Data" },
    { ZBEE_ZCL_16_BIT_DATA,         "16-Bit Data" },
    { ZBEE_ZCL_24_BIT_DATA,         "24-Bit Data" },
    { ZBEE_ZCL_32_BIT_DATA,         "32-Bit Data" },
    { ZBEE_ZCL_40_BIT_DATA,         "40-Bit Data" },
    { ZBEE_ZCL_48_BIT_DATA,         "48-Bit Data" },
    { ZBEE_ZCL_56_BIT_DATA,         "56-Bit Data" },
    { ZBEE_ZCL_64_BIT_DATA,         "64-Bit Data" },

    { ZBEE_ZCL_BOOLEAN,             "Boolean" },

    { ZBEE_ZCL_8_BIT_BITMAP,        "8-Bit Bitmap" },
    { ZBEE_ZCL_16_BIT_BITMAP,       "16-Bit Bitmap" },
    { ZBEE_ZCL_24_BIT_BITMAP,       "24-Bit Bitmap" },
    { ZBEE_ZCL_32_BIT_BITMAP,       "32-Bit Bitmap" },
    { ZBEE_ZCL_40_BIT_BITMAP,       "40-Bit Bitmap" },
    { ZBEE_ZCL_48_BIT_BITMAP,       "48-Bit Bitmap" },
    { ZBEE_ZCL_56_BIT_BITMAP,       "56-Bit Bitmap" },
    { ZBEE_ZCL_64_BIT_BITMAP,       "64-Bit Bitmap" },

    { ZBEE_ZCL_8_BIT_UINT,          "8-Bit Unsigned Integer" },
    { ZBEE_ZCL_16_BIT_UINT,         "16-Bit Unsigned Integer" },
    { ZBEE_ZCL_24_BIT_UINT,         "24-Bit Unsigned Integer" },
    { ZBEE_ZCL_32_BIT_UINT,         "32-Bit Unsigned Integer" },
    { ZBEE_ZCL_40_BIT_UINT,         "40-Bit Unsigned Integer" },
    { ZBEE_ZCL_48_BIT_UINT,         "48-Bit Unsigned Integer" },
    { ZBEE_ZCL_56_BIT_UINT,         "56-Bit Unsigned Integer" },
    { ZBEE_ZCL_64_BIT_UINT,         "64-Bit Unsigned Integer" },

    { ZBEE_ZCL_8_BIT_INT,           "8-Bit Signed Integer" },
    { ZBEE_ZCL_16_BIT_INT,          "16-Bit Signed Integer" },
    { ZBEE_ZCL_24_BIT_INT,          "24-Bit Signed Integer" },
    { ZBEE_ZCL_32_BIT_INT,          "32-Bit Signed Integer" },
    { ZBEE_ZCL_40_BIT_INT,          "40-Bit Signed Integer" },
    { ZBEE_ZCL_48_BIT_INT,          "48-Bit Signed Integer" },
    { ZBEE_ZCL_56_BIT_INT,          "56-Bit Signed Integer" },
    { ZBEE_ZCL_64_BIT_INT,          "64-Bit Signed Integer" },

    { ZBEE_ZCL_8_BIT_ENUM,          "8-Bit Enumeration" },
    { ZBEE_ZCL_16_BIT_ENUM,         "16-Bit Enumeration" },

    { ZBEE_ZCL_SEMI_FLOAT,          "Semi-precision Floating Point" },
    { ZBEE_ZCL_SINGLE_FLOAT,        "Single Precision Floating Point" },
    { ZBEE_ZCL_DOUBLE_FLOAT,        "Double Precision Floating Point" },

    { ZBEE_ZCL_OCTET_STRING,        "Octet String" },
    { ZBEE_ZCL_CHAR_STRING,         "Character String" },
    { ZBEE_ZCL_LONG_OCTET_STRING,   "Long Octet String" },
    { ZBEE_ZCL_LONG_CHAR_STRING,    "Long Character String" },

    { ZBEE_ZCL_ARRAY,               "Array" },
    { ZBEE_ZCL_STRUCT,              "Structure" },

    { ZBEE_ZCL_SET,                 "Set Collection" },
    { ZBEE_ZCL_BAG,                 "Bag Collection" },

    { ZBEE_ZCL_TIME,                "Time of Day" },
    { ZBEE_ZCL_DATE,                "Date" },
    { ZBEE_ZCL_UTC,                 "UTC Time" },

    { ZBEE_ZCL_CLUSTER_ID,          "Cluster ID" },
    { ZBEE_ZCL_ATTR_ID,             "Attribute ID" },
    { ZBEE_ZCL_BACNET_OID,          "BACnet OID" },

    { ZBEE_ZCL_IEEE_ADDR,           "IEEE Address" },
    { ZBEE_ZCL_SECURITY_KEY,        "128-Bit Security Key" },

    { ZBEE_ZCL_UNKNOWN,             "Unknown" },

    { 0, NULL }
};
static value_string_ext zbee_zcl_data_type_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_data_type_names);

/* ZCL Attribute Short Data Names */
const value_string zbee_zcl_short_data_type_names[] = {
    { ZBEE_ZCL_NO_DATA,             "No Data" },
    { ZBEE_ZCL_8_BIT_DATA,          "Data8" },
    { ZBEE_ZCL_16_BIT_DATA,         "Data16" },
    { ZBEE_ZCL_24_BIT_DATA,         "Data24" },
    { ZBEE_ZCL_32_BIT_DATA,         "Data32" },
    { ZBEE_ZCL_40_BIT_DATA,         "Data40" },
    { ZBEE_ZCL_48_BIT_DATA,         "Data48" },
    { ZBEE_ZCL_56_BIT_DATA,         "Data56" },
    { ZBEE_ZCL_64_BIT_DATA,         "Data64" },

    { ZBEE_ZCL_BOOLEAN,             "Boolean" },

    { ZBEE_ZCL_8_BIT_BITMAP,        "Bit8" },
    { ZBEE_ZCL_16_BIT_BITMAP,       "Bit16" },
    { ZBEE_ZCL_24_BIT_BITMAP,       "Bit24" },
    { ZBEE_ZCL_32_BIT_BITMAP,       "Bit32" },
    { ZBEE_ZCL_40_BIT_BITMAP,       "Bit40" },
    { ZBEE_ZCL_48_BIT_BITMAP,       "Bit48" },
    { ZBEE_ZCL_56_BIT_BITMAP,       "Bit56" },
    { ZBEE_ZCL_64_BIT_BITMAP,       "Bit64" },

    { ZBEE_ZCL_8_BIT_UINT,          "Uint8" },
    { ZBEE_ZCL_16_BIT_UINT,         "Uint16" },
    { ZBEE_ZCL_24_BIT_UINT,         "Uint24" },
    { ZBEE_ZCL_32_BIT_UINT,         "Uint32" },
    { ZBEE_ZCL_40_BIT_UINT,         "Uint40" },
    { ZBEE_ZCL_48_BIT_UINT,         "Uint48" },
    { ZBEE_ZCL_56_BIT_UINT,         "Uint56" },
    { ZBEE_ZCL_64_BIT_UINT,         "Uint64" },

    { ZBEE_ZCL_8_BIT_INT,           "Int8" },
    { ZBEE_ZCL_16_BIT_INT,          "Int16" },
    { ZBEE_ZCL_24_BIT_INT,          "Int24" },
    { ZBEE_ZCL_32_BIT_INT,          "Int32" },
    { ZBEE_ZCL_40_BIT_INT,          "Int40" },
    { ZBEE_ZCL_48_BIT_INT,          "Int48" },
    { ZBEE_ZCL_56_BIT_INT,          "Int56" },
    { ZBEE_ZCL_64_BIT_INT,          "Int64" },

    { ZBEE_ZCL_8_BIT_ENUM,          "Enum8" },
    { ZBEE_ZCL_16_BIT_ENUM,         "Enum16" },

    { ZBEE_ZCL_SEMI_FLOAT,          "Semi Float" },
    { ZBEE_ZCL_SINGLE_FLOAT,        "Float" },
    { ZBEE_ZCL_DOUBLE_FLOAT,        "Double Float" },

    { ZBEE_ZCL_OCTET_STRING,        "Oct String" },
    { ZBEE_ZCL_CHAR_STRING,         "Char String" },
    { ZBEE_ZCL_LONG_OCTET_STRING,   "Long Oct String" },
    { ZBEE_ZCL_LONG_CHAR_STRING,    "Long Char String" },

    { ZBEE_ZCL_ARRAY,               "Array" },
    { ZBEE_ZCL_STRUCT,              "Structure" },

    { ZBEE_ZCL_SET,                 "Set" },
    { ZBEE_ZCL_BAG,                 "Bag" },

    { ZBEE_ZCL_TIME,                "Time" },
    { ZBEE_ZCL_DATE,                "Date" },
    { ZBEE_ZCL_UTC,                 "UTC" },

    { ZBEE_ZCL_CLUSTER_ID,          "Cluster" },
    { ZBEE_ZCL_ATTR_ID,             "Attribute" },
    { ZBEE_ZCL_BACNET_OID,          "BACnet" },

    { ZBEE_ZCL_IEEE_ADDR,           "EUI" },
    { ZBEE_ZCL_SECURITY_KEY,        "Key" },

    { ZBEE_ZCL_UNKNOWN,             "Unknown" },

    { 0, NULL }
};
static value_string_ext zbee_zcl_short_data_type_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_short_data_type_names);

/* ZCL Attribute English Weekday Names */
static const value_string zbee_zcl_wd_names[] = {
    { 1,    "Monday" },
    { 2,    "Tuesday" },
    { 3,    "Wednesday" },
    { 4,    "Thursday" },
    { 5,    "Friday" },
    { 6,    "Saturday" },
    { 7,    "Sunday" },

    { 0, NULL }
};
static value_string_ext zbee_zcl_wd_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_wd_names);

/* Attribute Direction Names */
static const value_string zbee_zcl_dir_names[] = {
    { ZBEE_ZCL_DIR_RECEIVED, "Received" },
    { ZBEE_ZCL_DIR_REPORTED, "Reported" },

    { 0, NULL }
};

/* Attribute Discovery Names */
static const value_string zbee_zcl_dis_names[] = {
    { 0,    "Incomplete" },
    { 1,    "Complete" },

    { 0, NULL }
};

/* ZCL IAS Zone Client Commands */
static const value_string zbee_zcl_ias_zone_client_cmd_names[] = {
    { ZBEE_ZCL_CSC_IAS_ZONE_C_ZER, "Zone Enroll Response" },

    { 0, NULL }
};

/* ZCL IAS Zone Client Enroll Response Code Commands */
static const value_string zbee_zcl_ias_zone_client_erc[] = {
    { ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_NEP, "No enroll permit" },
    { ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_NS, "Not supported" },
    { ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_S, "Success" },
    { ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_TMZ, "Too many zones" },

    { 0, NULL }
};

/* ZCL IAS Zone Server Commands */
static const value_string zbee_zcl_ias_zone_server_cmd_names[] = {
    { ZBEE_ZCL_CSC_IAS_ZONE_S_ZER, "Zone Enroll Request" },
    { ZBEE_ZCL_CSC_IAS_ZONE_S_ZSCN, "Zone Status Change Notification" },

    { 0, NULL }
};

/* ZCL Poll Control Client Commands */
static const value_string zbee_zcl_poll_control_client_cmd_names[] = {
    { ZBEE_ZCL_CSC_POLL_CONTROL_C_CIR, "Check-in Response" },
    { ZBEE_ZCL_CSC_POLL_CONTROL_C_FPS, "Fast Poll Stop" },
    { ZBEE_ZCL_CSC_POLL_CONTROL_C_SLPI, "Set Long Poll Interval" },
    { ZBEE_ZCL_CSC_POLL_CONTROL_C_SSPI, "Set Short Poll Interval" },

    { 0, NULL }
};

/* ZCL Poll Control Server Commands */
static const value_string zbee_zcl_poll_control_server_cmd_names[] = {
    { ZBEE_ZCL_CSC_POLL_CONTROL_S_CI, "Check-in" },

    { 0, NULL }
};

/* ZCL Thermostat Client Commands */
static const value_string zbee_zcl_thermostat_client_cmd_names[] = {
    { ZBEE_ZCL_CSC_THERMOSTAT_C_CWS, "Clear Weekly Schedule" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_GWS, "Get Weekly Schedule" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SRL, "Setpoint Raise/Lower" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS, "Set Weekly Schedule" },

    { 0, NULL }
};

/* ZCL Thermostat Client Setpoint Raise/Lower Mode Fields */
static const value_string zbee_zcl_thermostat_client_setpointrl_mf[] = {
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_B, "Both (adjust Heat Setpoint and Cool Setpoint)" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_C, "Cool (adjust Cool Setpoint)" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_H, "Heat (adjust Heat Setpoint)" },

    { 0, NULL }
};

/* ZCL Thermostat Client Weekly Schedule Day of Week for Sequence */
static const value_string zbee_zcl_thermostat_client_ws_dow[] = {
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_AV, "Away or Vacation" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_FR, "Friday" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_MO, "Monday" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SA, "Saturday" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SU, "Sunday" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TH, "Thursday" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TU, "Tuesday" },
    { ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_WE, "Wednesday" },

    { 0, NULL }
};

/* ZCL Thermostat Server Commands */
static const value_string zbee_zcl_thermostat_server_cmd_names[] = {
    { ZBEE_ZCL_CSC_THERMOSTAT_S_GWSR, "Get Weekly Schedule Response" },

    { 0, NULL }
};

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl
 *  DESCRIPTION
 *      ZigBee Cluster Library dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      void *data          - raw packet private data.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static int dissect_zbee_zcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tvbuff_t *payload_tvb;
    dissector_handle_t cluster_handle;

    proto_tree *zcl_tree = NULL;
    proto_tree *sub_tree = NULL;

    proto_item  *proto_root = NULL;
    proto_item  *ti;

    zbee_nwk_packet *nwk;
    zbee_zcl_packet packet;
    zbee_zcl_cluster_desc *desc;
    guint16 cluster_id;

    guint8  fcf;
    guint   offset = 0;
    guint   i;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    nwk = (zbee_nwk_packet *)data;

    /* Init. */
    memset(&packet, 0, sizeof(zbee_zcl_packet));

    /* Fill the zcl cluster id */
    cluster_id = zcl_cluster_id = nwk->cluster_id;
    cluster_handle = dissector_get_uint_handle(zbee_zcl_dissector_table, cluster_id);

    /* Create the protocol tree */
    if ( tree ) {
        proto_root = proto_tree_add_protocol_format(tree, proto_zbee_zcl, tvb, offset,
                                tvb_length(tvb), "ZigBee Cluster Library Frame");

        zcl_tree = proto_item_add_subtree(proto_root, ett_zbee_zcl);
    }

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Get the FCF */
    fcf = tvb_get_guint8(tvb, offset);
    packet.frame_type = zbee_get_bit_field(fcf, ZBEE_ZCL_FCF_FRAME_TYPE);
    packet.mfr_spec = zbee_get_bit_field(fcf, ZBEE_ZCL_FCF_MFR_SPEC);
    packet.direction = zbee_get_bit_field(fcf, ZBEE_ZCL_FCF_DIRECTION);
    packet.disable_default_resp = zbee_get_bit_field(fcf, ZBEE_ZCL_FCF_DISABLE_DEFAULT_RESP);

    /* Display the FCF */
    if ( tree ) {
        /* Create the subtree */
        ti = proto_tree_add_text(zcl_tree, tvb, offset, 1,
                    "Frame Control Field: %s (0x%02x)",
                    val_to_str_const(packet.frame_type, zbee_zcl_frame_types, "Unknown"), fcf);
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_fcf);

                /* Add the frame type */
        proto_tree_add_item(sub_tree, hf_zbee_zcl_fcf_frame_type, tvb, offset, 1, ENC_NA);

        /* Add the manufacturer specific, direction, and disable default response flags */
        proto_tree_add_item(sub_tree, hf_zbee_zcl_fcf_mfr_spec, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_zbee_zcl_fcf_dir, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_zbee_zcl_fcf_disable_default_resp, tvb, offset, 1, ENC_NA);
    }
    offset += 1;

    /* If the manufacturer code is present, get and display it. */
    if (packet.mfr_spec) {
        packet.mfr_code = tvb_get_letohs(tvb, offset);

        if ( tree ) {
            proto_tree_add_uint(zcl_tree, hf_zbee_zcl_mfr_code, tvb, offset, 2,
                            packet.mfr_code);

            proto_item_append_text(proto_root, ", Mfr: %s (0x%04x)",
                            val_to_str_ext_const(packet.mfr_code, &zbee_mfr_code_names_ext, "Unknown"),
                            packet.mfr_code);
        }
        offset += 2;
    }

    /* Add the transaction sequence number to the tree */
    packet.tran_seqno = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(zcl_tree, hf_zbee_zcl_tran_seqno, tvb, offset, 1, packet.tran_seqno);
    offset += 1;

    /* Display the command and sequence number on the proto root and info column. */
    packet.cmd_id = tvb_get_guint8(tvb, offset);

    desc = zbee_zcl_get_cluster_desc(cluster_id);
    if (desc != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s: ", desc->name);
    }

    /* Add command ID to the tree. */
    if ( packet.frame_type == ZBEE_ZCL_FCF_PROFILE_WIDE ) {
        if ( tree ) {
            proto_item_append_text(proto_root, ", Command: %s, Seq: %u",
                val_to_str_ext_const(packet.cmd_id, &zbee_zcl_cmd_names_ext, "Unknown Command"),
                packet.tran_seqno);
        }

        col_set_str(pinfo->cinfo, COL_INFO, "ZCL: ");
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_ext_const(packet.cmd_id, &zbee_zcl_cmd_names_ext, "Unknown Command"),
            packet.tran_seqno);

        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_cmd_id, tvb, offset, 1, packet.cmd_id);
        offset += 1;
    } else {
        /* Cluster-specific. */
        guint8 mode_for_sequence, number_of_transitions;

        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        if (cluster_handle != NULL) {
            /* Call the specific cluster dissector registered. */
            call_dissector_with_data(cluster_handle, payload_tvb, pinfo, zcl_tree, &packet);
            return tvb_length(tvb);
        }
        proto_item_append_text(proto_root, ", Cluster-specific Command: 0x%02x, Seq: %u", packet.cmd_id,
            packet.tran_seqno);
        switch (cluster_id) {
            case ZBEE_ZCL_CID_IAS_ZONE:
                if (packet.direction == ZBEE_ZCL_DIR_REPORTED) {
                    /* We have a client. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Client Command: %s, Seq: %u", val_to_str(packet.cmd_id,
                        zbee_zcl_ias_zone_client_cmd_names, "Unknown IAS Zone Client Command"), packet.tran_seqno);
                    if (zcl_tree) {
                        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_ias_zone_client_cmd_id, tvb, offset, 1,
                            packet.cmd_id);
                        offset += 1;
                        switch (packet.cmd_id) {
                            case ZBEE_ZCL_CSC_IAS_ZONE_C_ZER:
                                /* Zone Enroll Response. */
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_ias_zone_client_zer_erc, tvb, offset, 1,
                                    ENC_NA);
                                offset += 1;
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_ias_zone_client_zer_zone_id, tvb, offset, 1,
                                    ENC_NA);
                                offset += 1;
                                break;
                        }
                    }
                } else {
                    /* We have a server. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Server Command: %s, Seq: %u", val_to_str(packet.cmd_id,
                        zbee_zcl_ias_zone_server_cmd_names, "Unknown IAS Zone Server Command"), packet.tran_seqno);
                    if (zcl_tree) {
                        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_ias_zone_server_cmd_id, tvb, offset, 1,
                            packet.cmd_id);
                        offset += 1;
                        switch (packet.cmd_id) {
                            case ZBEE_ZCL_CSC_IAS_ZONE_S_ZSCN:
                                /* Zone Status Change Notification. */
                                ti = proto_tree_add_item(zcl_tree, hf_zbee_zcl_ias_zone_server_scn_zone_status, tvb,
                                    offset, 2, ENC_LITTLE_ENDIAN);
                                sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_ias_zone_server_scn_zone_status);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_alarm1, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_alarm2, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_tamper, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_battery, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_supervision_reports, tvb,
                                    offset, 2, ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_restore_reports, tvb,
                                    offset, 2, ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_trouble, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_ias_zone_server_scn_ac_mains, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                offset += 2;
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_ias_zone_server_scn_ext_status, tvb, offset,
                                    1, ENC_NA);
                                offset += 1;
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_ias_zone_server_scn_zone_id, tvb, offset, 1,
                                    ENC_NA);
                                offset += 1;
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_ias_zone_server_scn_delay, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                offset += 2;
                                break;
                        }
                    }
                }
                break;
            case ZBEE_ZCL_CID_POLL_CONTROL:
                if (packet.direction == ZBEE_ZCL_DIR_REPORTED) {
                    /* We have a client. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Client Command: %s, Seq: %u", val_to_str(packet.cmd_id,
                        zbee_zcl_poll_control_client_cmd_names, "Unknown Poll Control Client Command"),
                        packet.tran_seqno);
                    if (zcl_tree) {
                        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_poll_control_client_cmd_id, tvb, offset, 1,
                            packet.cmd_id);
                        offset += 1;
                        switch (packet.cmd_id) {
                            case ZBEE_ZCL_CSC_POLL_CONTROL_C_CIR:
                                /* Check-in Response. */
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_poll_control_client_cir_sfp, tvb, offset, 1,
                                    ENC_NA);
                                offset += 1;
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_poll_control_client_cir_fpt, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                offset += 2;
                                break;
                            case ZBEE_ZCL_CSC_POLL_CONTROL_C_SLPI:
                                /* Set Long Poll Interval. */
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_poll_control_client_slpi_nlpi, tvb, offset, 4,
                                    ENC_LITTLE_ENDIAN);
                                offset += 4;
                                break;
                            case ZBEE_ZCL_CSC_POLL_CONTROL_C_SSPI:
                                /* Set Short Poll Interval. */
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_poll_control_client_sspi_nspi, tvb, offset, 2,
                                    ENC_LITTLE_ENDIAN);
                                offset += 2;
                                break;
                          }
                    }
                } else {
                    /* We have a server. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Server Command: %s, Seq: %u", val_to_str(packet.cmd_id,
                        zbee_zcl_poll_control_server_cmd_names, "Unknown Poll Control Server Command"),
                        packet.tran_seqno);
                    proto_tree_add_uint(zcl_tree, hf_zbee_zcl_poll_control_server_cmd_id, tvb, offset, 1,
                            packet.cmd_id);
                    offset += 1;
                    /*  switch (packet.cmd_id) {
                        }
                     */
                }
                break;
            case ZBEE_ZCL_CID_THERMOSTAT:
                if (packet.direction == ZBEE_ZCL_DIR_REPORTED) {
                    /* We have a client. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Client Command: %s, Seq: %u", val_to_str(packet.cmd_id,
                        zbee_zcl_thermostat_client_cmd_names, "Unknown Thermostat Client Command"), packet.tran_seqno);
                    if (zcl_tree) {
                        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_thermostat_client_cmd_id, tvb, offset, 1,
                            packet.cmd_id);
                        offset += 1;
                        switch (packet.cmd_id) {
                            case ZBEE_ZCL_CSC_THERMOSTAT_C_GWS:
                                /* Get Weekly Schedule. */
                                ti = proto_tree_add_uint_format(zcl_tree,
                                    hf_zbee_zcl_thermostat_client_gws_days_to_return, tvb, offset, 1,
                                    tvb_get_guint8(tvb, offset), "Days To Return");
                                sub_tree = proto_item_add_subtree(ti,
                                    ett_zbee_zcl_thermostat_client_gws_days_to_return);
                                for (i = 0; i < 8; ++i) {
                                    if (tvb_get_guint8(tvb, offset) & (0x01 << i)) {
                                        proto_tree_add_uint(sub_tree, hf_zbee_zcl_thermostat_client_gws_days_to_return,
                                            tvb, offset, 1, tvb_get_guint8(tvb, offset) & (0x01 << i));
                                    }
                                }
                                offset += 1;
                                ti = proto_tree_add_uint_format(zcl_tree, hf_zbee_zcl_thermostat_client_gws_mtr, tvb,
                                    offset, 1, tvb_get_guint8(tvb, offset), "Mode To Return");
                                sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_thermostat_client_gws_mtr);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_thermostat_client_gws_mtr_heat, tvb, offset,
                                    1, ENC_NA);
                                proto_tree_add_item(sub_tree, hf_zbee_zcl_thermostat_client_gws_mtr_cool, tvb, offset,
                                    1, ENC_NA);
                                offset += 1;
                                break;
                            case ZBEE_ZCL_CSC_THERMOSTAT_C_SRL:
                                /* Setpoint Raise/Lower. */
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_thermostat_client_setpointrl_modes, tvb,
                                    offset, 1, ENC_NA);
                                offset += 1;
                                proto_tree_add_item(zcl_tree, hf_zbee_zcl_thermostat_client_setpointrl_amount_field,
                                    tvb, offset, 1, ENC_NA);
                                offset += 1;
                                break;
                            case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS:
                                /* Set Weekly Schedule. */
                                number_of_transitions = tvb_get_guint8(tvb, offset);
                                proto_tree_add_uint(zcl_tree, hf_zbee_zcl_thermostat_client_sws_n_trans, tvb, offset, 1,
                                    number_of_transitions);
                                offset += 1;
                                ti = proto_tree_add_uint_format(zcl_tree, hf_zbee_zcl_thermostat_client_sws_dow, tvb,
                                    offset, 1, tvb_get_guint8(tvb, offset), "Day of Week for Sequence");
                                sub_tree = proto_item_add_subtree(ti,
                                    ett_zbee_zcl_thermostat_client_sws_dow_for_sequence);
                                for (i = 0; i < 8; ++i) {
                                    if (tvb_get_guint8(tvb, offset) & (0x01 << i)) {
                                        proto_tree_add_uint(sub_tree, hf_zbee_zcl_thermostat_client_sws_dow, tvb,
                                            offset, 1, tvb_get_guint8(tvb, offset) & (0x01 << i));
                                    }
                                }
                                offset += 1;
                                mode_for_sequence = tvb_get_guint8(tvb, offset);
                                ti = proto_tree_add_uint_format(zcl_tree, hf_zbee_zcl_thermostat_client_sws_mfs, tvb,
                                    offset, 1, mode_for_sequence, "Mode for Sequence");
                                sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_thermostat_client_sws_mfs);
                                proto_tree_add_boolean(sub_tree, hf_zbee_zcl_thermostat_client_sws_mfs_heat, tvb,
                                    offset, 1, mode_for_sequence);
                                proto_tree_add_boolean(sub_tree, hf_zbee_zcl_thermostat_client_sws_mfs_cool, tvb,
                                    offset, 1, mode_for_sequence);
                                offset += 1;
                                for (i = 1; i <= number_of_transitions; ++i) {
                                    switch (mode_for_sequence) {
                                        case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_B:
                                            /* Both Cool Set Point and Heat Set Point. */
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Transition Time %d (minutes since midnight): %d", i,
                                                tvb_get_letohs(tvb, offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Heat Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Cool Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            break;
                                        case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_C:
                                            /* Cool Set Point. */
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Transition Time %d (minutes since midnight): %d", i,
                                                tvb_get_letohs(tvb, offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Cool Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            break;
                                        case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_H:
                                            /* Heat Set Point. */
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Transition Time %d (minutes since midnight): %d", i,
                                                tvb_get_letohs(tvb, offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Heat Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            break;
                                    }
                                }
                                break;
                        }
                    }
                } else {
                    /* We have a server. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Server Command: %s, Seq: %u", val_to_str(packet.cmd_id,
                        zbee_zcl_thermostat_server_cmd_names, "Unknown Thermostat Server Command"), packet.tran_seqno);
                    if (zcl_tree) {
                        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_thermostat_server_cmd_id, tvb, offset, 1,
                            packet.cmd_id);
                        offset += 1;
                        switch (packet.cmd_id) {
                            case ZBEE_ZCL_CSC_THERMOSTAT_S_GWSR:
                                /* Get Weekly Schedule Response. */
                                number_of_transitions = tvb_get_guint8(tvb, offset);
                                proto_tree_add_uint(zcl_tree, hf_zbee_zcl_thermostat_server_gwsr_n_trans, tvb, offset,
                                    1, number_of_transitions);
                                offset += 1;
                                ti = proto_tree_add_uint_format(zcl_tree, hf_zbee_zcl_thermostat_server_gwsr_dow, tvb,
                                    offset, 1, tvb_get_guint8(tvb, offset), "Day of Week for Sequence");
                                sub_tree = proto_item_add_subtree(ti,
                                    ett_zbee_zcl_thermostat_server_gwsr_dow_for_sequence);
                                for (i = 0; i < 8; ++i) {
                                    if (tvb_get_guint8(tvb, offset) & (0x01 << i)) {
                                        proto_tree_add_uint(sub_tree, hf_zbee_zcl_thermostat_server_gwsr_dow, tvb,
                                            offset, 1, tvb_get_guint8(tvb, offset) & (0x01 << i));
                                    }
                                }
                                offset += 1;
                                mode_for_sequence = tvb_get_guint8(tvb, offset);
                                ti = proto_tree_add_uint_format(zcl_tree, hf_zbee_zcl_thermostat_server_gwsr_mfs, tvb,
                                    offset, 1, mode_for_sequence, "Mode for Sequence");
                                sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_thermostat_server_gwsr_mfs);
                                proto_tree_add_boolean(sub_tree, hf_zbee_zcl_thermostat_server_gwsr_mfs_heat, tvb,
                                    offset, 1, mode_for_sequence);
                                proto_tree_add_boolean(sub_tree, hf_zbee_zcl_thermostat_server_gwsr_mfs_cool, tvb,
                                    offset, 1, mode_for_sequence);
                                offset += 1;
                                for (i = 1; i <= number_of_transitions; ++i) {
                                    switch (mode_for_sequence) {
                                        case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_B:
                                            /* Both Cool Set Point and Heat Set Point. */
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Transition Time %d (minutes since midnight): %d", i,
                                                tvb_get_letohs(tvb, offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Heat Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Cool Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            break;
                                        case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_C:
                                            /* Cool Set Point. */
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Transition Time %d (minutes since midnight): %d", i,
                                                tvb_get_letohs(tvb, offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Cool Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            break;
                                        case ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_H:
                                            /* Heat Set Point. */
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Transition Time %d (minutes since midnight): %d", i,
                                                tvb_get_letohs(tvb, offset));
                                            offset += 2;
                                            proto_tree_add_text(zcl_tree, tvb, offset, 2,
                                                "Heat Set Point %d (with 0.01 C resolution): %d", i, tvb_get_letohs(tvb,
                                                offset));
                                            offset += 2;
                                            break;
                                    }
                                }
                                break;
                        }
                    }
                }
                break;
            default:
                col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown Command: 0x%02x, Seq: %u", packet.cmd_id,
                    packet.tran_seqno);
                if (zcl_tree) {
                    proto_tree_add_uint(zcl_tree, hf_zbee_zcl_cs_cmd_id, tvb, offset, 1, packet.cmd_id);
                    offset += 1;
                }
                break;
        }
        /* Don't decode the tail. */
        zcl_dump_data(tvb, offset, pinfo, zcl_tree);
        return tvb_length(tvb);
    }

    if ( zcl_tree ) {
    /* Handle the contents of the command frame. */
        switch ( packet.cmd_id ) {
            case ZBEE_ZCL_CMD_READ_ATTR:
                dissect_zcl_read_attr(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_READ_ATTR_RESP:
                dissect_zcl_read_attr_resp(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR:
            case ZBEE_ZCL_CMD_WRITE_ATTR_UNDIVIDED:
            case ZBEE_ZCL_CMD_WRITE_ATTR_NO_RESP:
            case ZBEE_ZCL_CMD_REPORT_ATTR:
                dissect_zcl_write_attr(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR_RESP:
                dissect_zcl_write_attr_resp(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_CONFIG_REPORT:
                dissect_zcl_config_report(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_CONFIG_REPORT_RESP:
                dissect_zcl_config_report_resp(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_READ_REPORT_CONFIG:
                dissect_zcl_read_report_config(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_READ_REPORT_CONFIG_RESP:
                dissect_zcl_read_report_config_resp(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            case ZBEE_ZCL_CMD_DEFAULT_RESP:
                dissect_zcl_default_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.direction);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_ATTR:
                dissect_zcl_discover_attr(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_ATTR_RESP:
                dissect_zcl_discover_attr_resp(tvb, pinfo, zcl_tree, &offset, cluster_id);
                break;

            /* BUGBUG: don't dissect these for now */
            case ZBEE_ZCL_CMD_READ_ATTR_STRUCT:
            case ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT:
            case ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT_RESP:
                break;
        } /* switch */
    }
    zcl_dump_data(tvb, offset, pinfo, zcl_tree);
    return tvb_length(tvb);
} /* dissect_zbee_zcl */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_read_attr
 *  DESCRIPTION
 *      Helper dissector for ZCL Read Attributes and
 *      Write Attributes No Response commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
void dissect_zcl_read_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id)
{
    guint tvb_len;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len ) {
        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, tree, offset, cluster_id);
    }

    return;
} /* dissect_zcl_read_attr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_read_attr_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Read Attributes Response command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
void dissect_zcl_read_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    guint16 attr_id;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Status Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);

        /* Dissect the status and optionally the data type and value */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status)
            == ZBEE_ZCL_STAT_SUCCESS ) {

            /* Dissect the attribute data type and data */
            dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id);
        }
    }
} /* dissect_zcl_read_attr_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_write_attr
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
void dissect_zcl_write_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    guint16 attr_id;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Attribute Field");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);

        /* Dissect the attribute data type and data */
        dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id);
    }
} /* dissect_zcl_write_attr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_write_attr_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Write Attribute Response command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_write_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Status Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the status */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status) !=
            ZBEE_ZCL_STAT_SUCCESS ) {

            /* Dissect the failed attribute identifier */
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);
        }
    }

} /* dissect_zcl_write_attr_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_read_report_config_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *---------------------------------------------------------------
 */
static void dissect_zcl_read_report_config_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    guint data_type;
    guint attr_status;
    guint attr_dir;
    guint16 attr_id;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 3, "Reporting Configuration Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the status */
        attr_status = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status);

        /* Dissect the direction and any reported configuration */
        attr_dir = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir);

        /* Dissect the attribute id */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);

        if ( attr_status == ZBEE_ZCL_STAT_SUCCESS ) {
            if ( attr_dir == ZBEE_ZCL_DIR_REPORTED ) {

                /* Dissect the attribute data type */
                data_type = dissect_zcl_attr_uint8(tvb, sub_tree, offset,
                        &hf_zbee_zcl_attr_data_type);

                /* Dissect minimum reporting interval */
                proto_tree_add_item(tree, hf_zbee_zcl_attr_minint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                (*offset) += 2;

                /* Dissect maximum reporting interval */
                proto_tree_add_item(tree, hf_zbee_zcl_attr_maxint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                (*offset) += 2;

                if ( IS_ANALOG_SUBTYPE(data_type) ) {
                    /* Dissect reportable change */
                    dissect_zcl_attr_data_general(tvb, sub_tree, offset, attr_id, data_type, cluster_id);
                }

            } else {
                /* Dissect timeout period */
               proto_tree_add_item(tree, hf_zbee_zcl_attr_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
               (*offset) += 2;
            }
        }
    }

} /* dissect_zcl_read_report_config_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_config_report
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *---------------------------------------------------------------
 */
static void dissect_zcl_config_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    guint data_type;
    guint16 attr_id;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 3, "Reporting Configuration Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the direction and any reported configuration */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir)
                        == ZBEE_ZCL_DIR_REPORTED ) {

            /* Dissect the attribute id */
            attr_id = tvb_get_letohs(tvb, *offset);
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);

            /* Dissect the attribute data type */
            data_type = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_data_type);

            /* Dissect minimum reporting interval */
            proto_tree_add_item(tree, hf_zbee_zcl_attr_minint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            (*offset) += 2;

            /* Dissect maximum reporting interval */
            proto_tree_add_item(tree, hf_zbee_zcl_attr_maxint, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            (*offset) += 2;

            if ( IS_ANALOG_SUBTYPE(data_type) ) {
                /* Dissect reportable change */
                dissect_zcl_attr_data_general(tvb, sub_tree, offset, attr_id, data_type, cluster_id);
            }
        } else {

            /* Dissect the attribute id */
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);

            /* Dissect timeout period */
            proto_tree_add_item(tree, hf_zbee_zcl_attr_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            (*offset) += 2;
        }
    }

} /* dissect_zcl_config_report */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_config_report_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_config_report_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 3, "Attribute Status Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the status */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status) !=
            ZBEE_ZCL_STAT_SUCCESS ) {
                /* Dissect the direction on error */
                dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir);

                /* Dissect the attribute identifier on error */
                dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);
        }
    }
} /* dissect_zcl_config_report_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_read_report_config
 *  DESCRIPTION
 *      Helper dissector for ZCL Read Report Configuration command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_read_report_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 3, "Attribute Status Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the direction */
        dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir);

        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);
    }

} /* dissect_zcl_read_report_config */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_default_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Default Response command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *      dir                 - direction
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_default_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                     guint *offset, guint16 cluster_id, guint8 dir)
{
    zbee_zcl_cluster_desc *desc;

    /* Call the specific cluster function retrieves the command id */
    desc = zbee_zcl_get_cluster_desc(cluster_id);
    if ((desc != NULL) && (desc->fn_cmd_id != NULL)) {
        desc->fn_cmd_id(tree, tvb, offset, dir);
    }
    else {
        proto_tree_add_item(tree, hf_zbee_zcl_cmd_id, tvb, *offset, 1, ENC_NA);
    }
    *offset += 1;

    /* Dissect the status */
    dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_status);

    return;
} /* dissect_zcl_default_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_discover_attr
 *  DESCRIPTION
 *      Helper dissector for ZCL Discover Attributes command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_discover_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    /* Dissect the starting attribute identifier */
    proto_tree_add_item(tree, hf_zbee_zcl_attr_start, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    /* Dissect the number of maximum attribute identifiers */
    dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_maxnum);

    return;
} /* dissect_zcl_discover_attr */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_discover_attr_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Discover Attributes command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_discover_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;

    dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dis);

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 3, "Attribute Status Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id);

        /* Dissect the number of maximum attribute identifiers */
        dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_data_type);
    }

} /* dissect_zcl_discover_attr_resp */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_id
 *  DESCRIPTION
 *      Dissects Attribute ID field. This could be done with the
 *      dissect_zcl_attr_uint16 function, but we leave it separate
 *      so we can dissect the attr_id with a hash in the future.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_id(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 cluster_id)
{
    zbee_zcl_cluster_desc *desc;

    desc = zbee_zcl_get_cluster_desc(cluster_id);
    if ((desc != NULL) && (desc->fn_attr_id != NULL)) {
        desc->fn_attr_id(tree, tvb, offset);
    }
    else {
        /* Add the identifier */
        proto_tree_add_item(tree, hf_zbee_zcl_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    }

    *offset += 2;
} /* dissect_zcl_attr_id */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_data_type_val
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_data_type_val(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 attr_id, guint16 cluster_id)
{
    zbee_zcl_cluster_desc *desc;

    desc = zbee_zcl_get_cluster_desc(cluster_id);
    if ((desc != NULL) && (desc->fn_attr_data != NULL)) {
        desc->fn_attr_data(tree, tvb, offset, attr_id,
            dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_data_type));
    }
    else {
        dissect_zcl_attr_data(tvb, tree, offset,
            dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_data_type) );
    }

} /* dissect_zcl_attr_data_type_val */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_data_general
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      attr_id             - attribute identification
 *      data_type           - type of data
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_data_general(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 attr_id, guint data_type, guint16 cluster_id)
{
    zbee_zcl_cluster_desc *desc;

    desc = zbee_zcl_get_cluster_desc(cluster_id);
    if ((desc != NULL) && (desc->fn_attr_data != NULL)) {
        desc->fn_attr_data(tree, tvb, offset, attr_id, data_type);
    }
    else {
        dissect_zcl_attr_data(tvb, tree, offset, data_type);
    }

} /*dissect_zcl_attr_data_general*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_data
 *  DESCRIPTION
 *      Dissects the various types of ZCL attribute data.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      data_type           - the type of ZCL data in the packet buffer
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void dissect_zcl_attr_data(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint data_type)
{
    guint     attr_uint;
    gint      attr_int;
    guint8   *attr_string;
    guint8    attr_uint8[4];
    guint8    elements_type;
    guint16   elements_num;
    gfloat    attr_float;
    gdouble   attr_double;
    nstime_t  attr_time;

    /* Dissect attribute data type and data */
    switch ( data_type ) {
        case ZBEE_ZCL_NO_DATA:
            break;

        case ZBEE_ZCL_8_BIT_DATA:
        case ZBEE_ZCL_8_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;
            break;

        case ZBEE_ZCL_8_BIT_UINT:
        case ZBEE_ZCL_8_BIT_ENUM:

            /* Display 8 bit unsigned integer */
            attr_uint = tvb_get_guint8(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint8, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_8_BIT_INT:
            /* Display 8 bit integer */

            attr_int = (gint8)tvb_get_guint8(tvb, *offset);

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_int8, tvb, *offset, 1, ENC_NA);

            *offset += 1;
            break;

        case ZBEE_ZCL_BOOLEAN:

            attr_uint = tvb_get_guint8(tvb, *offset);

            proto_item_append_text(tree, ", %s: 0x%02x",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_boolean, tvb, *offset, 1, ENC_BIG_ENDIAN);

            *offset += 1;
            break;

        case ZBEE_ZCL_16_BIT_DATA:
        case ZBEE_ZCL_16_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 2, ENC_NA);
            (*offset) += 2;
            break;

        case ZBEE_ZCL_16_BIT_UINT:
        case ZBEE_ZCL_16_BIT_ENUM:
            /* Display 16 bit unsigned integer */

            attr_uint = tvb_get_letohs(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint16, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_16_BIT_INT:
            /* Display 16 bit integer */

            attr_int = (gint16)tvb_get_letohs(tvb, *offset);

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_int16, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

            *offset += 2;
            break;

        case ZBEE_ZCL_24_BIT_DATA:
        case ZBEE_ZCL_24_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 3, ENC_NA);
            (*offset) += 3;
            break;

        case ZBEE_ZCL_24_BIT_UINT:
            /* Display 24 bit unsigned integer */

            attr_uint = tvb_get_letoh24(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint24, tvb, *offset, 3, ENC_LITTLE_ENDIAN);

            *offset += 3;
            break;

        case ZBEE_ZCL_24_BIT_INT:
            /* Display 24 bit signed integer */

            attr_int = (gint)tvb_get_letoh24(tvb, *offset);
            /* sign extend into int32 */
            if (attr_int & INT24_SIGN_BITS) attr_int |= INT24_SIGN_BITS;

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_int24, tvb, *offset, 3, ENC_LITTLE_ENDIAN);

            *offset += 3;
            break;

        case ZBEE_ZCL_32_BIT_DATA:
        case ZBEE_ZCL_32_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 4, ENC_NA);
            (*offset) += 4;
            break;

        case ZBEE_ZCL_32_BIT_UINT:
            /* Display 32 bit unsigned integer */

            attr_uint = tvb_get_letohl(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint32, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

            *offset += 4;
            break;

        case ZBEE_ZCL_32_BIT_INT:
            /* Display 32 bit signed integer */

            attr_int = (gint)tvb_get_letohl(tvb, *offset);

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_int32, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
            break;

        case ZBEE_ZCL_40_BIT_DATA:
        case ZBEE_ZCL_40_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 5, ENC_NA);
            (*offset) += 5;
            break;

        case ZBEE_ZCL_40_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint64, tvb, *offset, 5, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" G_GINT64_MODIFIER "u", tvb_get_letoh40(tvb, *offset));
            (*offset) += 5;
            break;

        case ZBEE_ZCL_40_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 5, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" G_GINT64_MODIFIER "d", tvb_get_letohi40(tvb, *offset));
            (*offset) += 5;
            break;

        case ZBEE_ZCL_48_BIT_DATA:
        case ZBEE_ZCL_48_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 6, ENC_NA);
            (*offset) += 6;
            break;

        case ZBEE_ZCL_48_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint64, tvb, *offset, 6, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" G_GINT64_MODIFIER "u", tvb_get_letoh48(tvb, *offset));
            (*offset) += 6;
            break;

        case ZBEE_ZCL_48_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 6, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" G_GINT64_MODIFIER "d", tvb_get_letohi48(tvb, *offset));
            (*offset) += 6;
            break;

        case ZBEE_ZCL_56_BIT_DATA:
        case ZBEE_ZCL_56_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 7, ENC_NA);
            (*offset) += 7;
            break;

        case ZBEE_ZCL_56_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint64, tvb, *offset, 7, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" G_GINT64_MODIFIER "u", tvb_get_letoh56(tvb, *offset));
            (*offset) += 7;
            break;

        case ZBEE_ZCL_56_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 7, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" G_GINT64_MODIFIER "d", tvb_get_letohi56(tvb, *offset));
            (*offset) += 7;
            break;

        case ZBEE_ZCL_64_BIT_DATA:
        case ZBEE_ZCL_64_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 8, ENC_NA);
            (*offset) += 8;
            break;

        case ZBEE_ZCL_64_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" G_GINT64_MODIFIER "u", tvb_get_letoh64(tvb, *offset));
            (*offset) += 8;
            break;

        case ZBEE_ZCL_64_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" G_GINT64_MODIFIER "u", tvb_get_letoh64(tvb, *offset));
            (*offset) += 8;
            break;

        case ZBEE_ZCL_SEMI_FLOAT:
            /* BUGBUG */
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 2, ENC_NA);
            (*offset) += 2;
            break;

        case ZBEE_ZCL_SINGLE_FLOAT:
            attr_float = tvb_get_letohieee_float(tvb, *offset);


            proto_item_append_text(tree, ", %s: %g",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_float);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

            *offset += 4;
            break;

        case ZBEE_ZCL_DOUBLE_FLOAT:
            attr_double = tvb_get_letohieee_double(tvb, *offset);

            proto_item_append_text(tree, ", Double: %lg", attr_double);
            proto_tree_add_item(tree, hf_zbee_zcl_attr_double, tvb, *offset, 8, ENC_LITTLE_ENDIAN);

            *offset += 8;
            break;

        case ZBEE_ZCL_OCTET_STRING:

            /* Display octet string */
            attr_uint = tvb_get_guint8(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_STR_LENGTH) attr_uint = 0;

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, 1,
                        attr_uint);

            *offset += 1;

            attr_string = tvb_bytes_to_ep_str_punct(tvb, *offset, attr_uint, ':');
            proto_item_append_text(tree, ", Octets: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_ostr, tvb, *offset, attr_uint,
                            attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_CHAR_STRING:

            /* Display string */
            attr_uint = tvb_get_guint8(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_STR_LENGTH) attr_uint = 0;

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, 1, attr_uint);

            *offset += 1;

            attr_string = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, attr_uint, ENC_ASCII);

            proto_item_append_text(tree, ", String: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_str, tvb, *offset, attr_uint, attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_LONG_OCTET_STRING:

            /* Display long octet string */
            attr_uint = tvb_get_letohs(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_LONG_STR_LENGTH) attr_uint = 0;
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, 2, attr_uint);

            *offset += 2;

            attr_string = tvb_bytes_to_ep_str_punct(tvb, *offset, attr_uint, ':');
            proto_item_append_text(tree, ", Octets: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_ostr, tvb, *offset, attr_uint, attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_LONG_CHAR_STRING:

            /* Display long string */
            attr_uint = tvb_get_letohs(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_LONG_STR_LENGTH) attr_uint = 0;

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, 2, attr_uint);
            *offset += 2;

            attr_string = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, attr_uint, ENC_ASCII);
            proto_item_append_text(tree, ", String: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_str, tvb, *offset, attr_uint, attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_ARRAY:
            /* BYTE 0 - Elements type */
            elements_type = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_array_elements_type, tvb, *offset, 1, elements_type);
            *offset += 1;
            /* BYTE 1-2 - Element number */
            elements_num = tvb_get_letohs(tvb, *offset);
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_array_elements_num, tvb, *offset, 2, elements_num);
            *offset += 2;
            /* BYTE ... - Elements */
            dissect_zcl_array_type(tvb, tree, offset, elements_type, elements_num);
            break;

        case ZBEE_ZCL_SET:
            /* BYTE 0 - Elements type */
            elements_type = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_set_elements_type, tvb, *offset, 1, elements_type);
            *offset += 1;
            /* BYTE 1-2 - Element number */
            elements_num = tvb_get_letohs(tvb, *offset);
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_set_elements_num, tvb, *offset, 2, elements_num);
            *offset += 2;
            /* BYTE ... - Elements */
            dissect_zcl_set_type(tvb, tree, offset, elements_type, elements_num);
            break;

        case ZBEE_ZCL_BAG: /* Same as ZBEE_ZCL_SET, but using different filter fields */
            /* BYTE 0 - Elements type */
            elements_type = tvb_get_guint8(tvb, *offset);
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_bag_elements_type, tvb, *offset, 1, elements_type);
            *offset += 1;
            /* BYTE 1-2 - Element number */
            elements_num = tvb_get_letohs(tvb, *offset);
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_bag_elements_num, tvb, *offset, 2, elements_num);
            *offset += 2;
            /* BYTE ... - Elements */
            dissect_zcl_set_type(tvb, tree, offset, elements_type, elements_num);
            break;

        case ZBEE_ZCL_STRUCT:
            /* ToDo */
            break;

        case ZBEE_ZCL_TIME:
            /* Dissect Time of Day */
            attr_uint8[0] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_hours);
            attr_uint8[1] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_mins);
            attr_uint8[2] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_secs);
            attr_uint8[3] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_csecs);

            proto_item_append_text(tree, ", Time: %u:%u:%u.%u",
                attr_uint8[0], attr_uint8[1], attr_uint8[2], attr_uint8[3]);
            break;

        case ZBEE_ZCL_DATE:
            /* Dissect Date */
            attr_uint8[0] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_yy);
            attr_uint8[1] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_mm);
            attr_uint8[2] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_md);
            attr_uint8[3] = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_wd);

            proto_item_append_text(tree, ", Date: %u/%u/%u %s",
                attr_uint8[0]+1900, attr_uint8[1], attr_uint8[2],
                val_to_str_ext_const(attr_uint8[3], &zbee_zcl_wd_names_ext, "Invalid Weekday") );
            break;

        case ZBEE_ZCL_UTC:
            /* Display UTC */
            attr_time.secs = tvb_get_letohl(tvb, *offset);
            attr_time.secs += ZBEE_ZCL_NSTIME_UTC_OFFSET;
            attr_time.nsecs = 0;

            proto_item_append_text(tree, ", %s",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved") );
            proto_tree_add_time(tree, hf_zbee_zcl_attr_utc, tvb, *offset, 4, &attr_time);

            *offset += 4;
            break;

        case ZBEE_ZCL_CLUSTER_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_cid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            (*offset) += 2;
            break;

        case ZBEE_ZCL_ATTR_ID:
            dissect_zcl_attr_id(tvb, tree, offset, zcl_cluster_id);
            break;

        case ZBEE_ZCL_BACNET_OID:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 4, ENC_NA);
            (*offset) += 4;
            break;

        case ZBEE_ZCL_IEEE_ADDR:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 8, ENC_NA);
            (*offset) += 8;
            break;

        case ZBEE_ZCL_SECURITY_KEY:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 16, ENC_NA);
            (*offset) += 16;
            break;

        default:
            break;
        }

} /* dissect_zcl_attr_data */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_uint8
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      hf_zbee_zcl         - pointer to header field index
 *  RETURNS
 *      guint               - dissected data
 *---------------------------------------------------------------
 */
static guint dissect_zcl_attr_uint8(tvbuff_t *tvb, proto_tree *tree, guint *offset, int *hf_zbee_zcl)
{
    guint attr_uint;

    attr_uint = tvb_get_guint8(tvb, *offset);
    proto_tree_add_uint(tree, *hf_zbee_zcl, tvb, *offset, 1, attr_uint);
    (*offset)++;

    return attr_uint;
} /* dissect_zcl_attr_uint8 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_array_type
 *  DESCRIPTION
 *      Helper dissector for ZCL attribute array type.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      elements_type       - element type
 *      elements_num        - elements number
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_zcl_array_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 1;   /* First element has a 1-index value */

    tvb_len = tvb_captured_length(tvb);
    while ( (*offset < tvb_len) && (elements_num != 0) ) {
        /* Create subtree for array element field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Element #%d", i);

        /* Have "common" use case give individual tree control to all elements,
           but don't prevent dissection if list is large */
        if (i < ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1)
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_array_elements[i]);
        else
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_array_elements[ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1]);

        dissect_zcl_attr_data(tvb, sub_tree, offset, elements_type);
        elements_num--;
        i++;
    }
} /* dissect_zcl_array_type */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_set_type
 *  DESCRIPTION
 *      Helper dissector for ZCL attribute set and bag types.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      elements_type       - element type
 *      elements_num        - elements number
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
dissect_zcl_set_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num)
{
    proto_item *ti       = NULL;
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 1;   /* First element has a 1-index value */

    tvb_len = tvb_captured_length(tvb);
    while ( (*offset < tvb_len) && (elements_num != 0) ) {
        /* Create subtree for array element field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Element");

        /* Piggyback on array ett_ variables */
        /* Have "common" use case give individual tree control to all elements,
           but don't prevent dissection if list is large */
        if (i < ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1)
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_array_elements[i]);
        else
            sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_array_elements[ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1]);

        dissect_zcl_attr_data(tvb, sub_tree, offset, elements_type);
        elements_num--;
        i++;
    }
} /* dissect_zcl_set_type */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zcl_dump_data
 *  DESCRIPTION
 *      Helper functions dumps any remaining data into the data dissector.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      guint       offset  - offset after parsing last item.
 *      packet_info *pinfo  - packet information structure.
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void zcl_dump_data(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *root   = proto_tree_get_root(tree);
    guint       length = tvb_length_remaining(tvb, offset);
    tvbuff_t   *remainder;

    if (length > 0) {
        remainder = tvb_new_subset_remaining(tvb, offset);
        call_dissector(data_handle, remainder, pinfo, root);
    }

    return;
} /* zcl_dump_data */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *    decode_zcl_time_in_seconds
 *  DESCRIPTION
 *    this function decodes second time type variable
 *  PARAMETERS
 *  RETURNS
 *    none
 *---------------------------------------------------------------
 */
void decode_zcl_time_in_seconds(gchar *s, guint16 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", value);
    return;
} /* decode_zcl_time_in_seconds*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      decode_zcl_time_in_minutes
 *  DESCRIPTION
 *    this function decodes minute time type variable
 *  PARAMETERS
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void decode_zcl_time_in_minutes(gchar *s, guint16 value)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", value);
    return;
} /*decode_zcl_time_in_minutes*/

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zbee_zcl
 *  DESCRIPTION
 *      ZigBee ZCL protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zbee_zcl(void)
{
    guint i, j;

    static const true_false_string tfs_client_server = {
        "To Client",
        "To Server"
    };

    static const true_false_string tfs_ac_mains = {
        "AC/Mains fault",
        "AC/Mains OK"
    };

    static const true_false_string tfs_alarmed_or_not = {
        "Opened or alarmed",
        "Closed or not alarmed"
    };

    static const true_false_string tfs_battery = {
        "Low battery",
        "Battery OK"
    };

    static const true_false_string tfs_reports_or_not = {
        "Reports",
        "Does not report"
    };

    static const true_false_string tfs_reports_restore = {
        "Reports restore",
        "Does not report restore"
    };

    static const true_false_string tfs_tampered_or_not = {
        "Tampered",
        "Not tampered"
    };

    static const true_false_string tfs_trouble_failure = {
        "Trouble/Failure",
        "OK"
    };

    static hf_register_info hf[] = {
        { &hf_zbee_zcl_fcf_frame_type,
            { "Frame Type", "zbee_zcl.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_frame_types),
                ZBEE_ZCL_FCF_FRAME_TYPE, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_mfr_spec,
            { "Manufacturer Specific", "zbee_zcl.ms", FT_BOOLEAN, 8, NULL,
                ZBEE_ZCL_FCF_MFR_SPEC, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_dir,
            { "Direction", "zbee_zcl.dir", FT_BOOLEAN, 8, TFS(&tfs_client_server),
                ZBEE_ZCL_FCF_DIRECTION, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_disable_default_resp,
            { "Disable Default Response", "zbee_zcl.ddr", FT_BOOLEAN, 8, NULL,
                ZBEE_ZCL_FCF_DISABLE_DEFAULT_RESP, NULL, HFILL }},

        { &hf_zbee_zcl_mfr_code,
            { "Manufacturer Code", "zbee_zcl.cmd.mc", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
                    &zbee_mfr_code_names_ext, 0x0, "Assigned manufacturer code.", HFILL }},

        { &hf_zbee_zcl_tran_seqno,
            { "Sequence Number", "zbee_zcl.cmd.tsn", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_cmd_id,
            { "Command",    "zbee_zcl.cmd.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &zbee_zcl_cmd_names_ext,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_cs_cmd_id,
          { "Command",    "zbee_zcl.cs.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_cs_cmd_names) /*"Unknown"*/,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_id,
            { "Attribute",  "zbee_zcl.attr.id", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_data_type,
            { "Data Type",  "zbee_zcl.attr.data.type", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &zbee_zcl_data_type_names_ext, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_boolean,
            { "Boolean",    "zbee_zcl.attr.boolean", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0xff,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint8,
            { "Uint8",  "zbee_zcl.attr.uint8", FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint16,
            { "Uint16", "zbee_zcl.attr.uint16", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint24,
            { "Uint24", "zbee_zcl.attr.uint24", FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint32,
            { "Uint32", "zbee_zcl.attr.uint32", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint64,
            { "Uint64", "zbee_zcl.attr.uint64", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int8,
            { "Int8",   "zbee_zcl.attr.int8", FT_INT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int16,
            { "Int16",  "zbee_zcl.attr.int16", FT_INT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int24,
            { "Int24",  "zbee_zcl.attr.int24", FT_INT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int32,
            { "Int32",  "zbee_zcl.attr.int32", FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int64,
            { "Int64",  "zbee_zcl.attr.int64", FT_INT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_float,
            { "Float", "zbee_zcl.attr.float", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_double,
            { "Double Float", "zbee_zcl.attr.float", FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bytes,
            { "Bytes",  "zbee_zcl.attr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_minint,
            { "Minimum Interval", "zbee_zcl.attr.minint", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_maxint,
            { "Maximum Interval", "zbee_zcl.attr.maxint", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_timeout,
            { "Timeout", "zbee_zcl.attr.timeout", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_hours,
            { "Hours",  "zbee_zcl.attr.hours", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_mins,
            { "Minutes", "zbee_zcl.attr.mins", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_secs,
            { "Seconds", "zbee_zcl.attr.secs", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_csecs,
            { "Centiseconds", "zbee_zcl.attr.csecs", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_yy,
            { "Year", "zbee_zcl.attr.yy", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_mm,
            { "Month", "zbee_zcl.attr.mm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_md,
            { "Day of Month", "zbee_zcl.attr.md", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_wd,
            { "Day of Week", "zbee_zcl.attr.wd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_utc,
            { "UTC", "zbee_zcl.attr.utc", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_status,
            { "Status", "zbee_zcl.attr.status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &zbee_zcl_status_names_ext,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_dir,
            { "Direction", "zbee_zcl.attr.dir", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dir_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_dis,
            { "Discovery", "zbee_zcl.attr.dis", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dis_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_cid,
            { "Cluster", "zbee_zcl.attr.cid", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_start,
            { "Start Attribute", "zbee_zcl.attr.start", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_maxnum,
            { "Maxiumum Number", "zbee_zcl.attr.maxnum", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_str_len,
            { "Length", "zbee_zcl.attr.str.len", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_str,
            { "String", "zbee_zcl.attr.str", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_ostr,
            { "Octet String",   "zbee_zcl.attr.ostr", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_array_elements_type,
            { "Elements Type",   "zbee_zcl.attr.array.elements_type", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &zbee_zcl_data_type_names_ext, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_array_elements_num,
            { "Elements Number",   "zbee_zcl.attr.array.elements_num", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_set_elements_type,
            { "Elements Type",   "zbee_zcl.attr.set.elements_type", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &zbee_zcl_data_type_names_ext, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_set_elements_num,
            { "Elements Number",   "zbee_zcl.attr.set.elements_num", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bag_elements_type,
            { "Elements Type",   "zbee_zcl.attr.bag.elements_type", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &zbee_zcl_data_type_names_ext, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bag_elements_num,
            { "Elements Number",   "zbee_zcl.attr.bag.elements_num", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_client_cmd_id,
            { "Command", "zbee_zcl.ias_zone.client.cmd_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_ias_zone_client_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_client_zer_erc,
            { "Enroll response code", "zbee_zcl.ias_zone.client.zer.erc", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_ias_zone_client_erc), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_client_zer_zone_id,
            { "Zone ID", "zbee_zcl.ias_zone.client.zer.zone_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_server_cmd_id,
            { "Command", "zbee_zcl.ias_zone.server.cmd_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_ias_zone_server_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_ac_mains,
            { "AC (mains)", "zbee_zcl.ias_zone.server.scn.ac_mains", FT_BOOLEAN, 16, TFS(&tfs_ac_mains), 0x80, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_alarm1,
            { "Alarm 1", "zbee_zcl.ias_zone.server.scn.alarm_1", FT_BOOLEAN, 16, TFS(&tfs_alarmed_or_not), 0x01, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_alarm2,
            { "Alarm 2", "zbee_zcl.ias_zone.server.scn.alarm_2", FT_BOOLEAN, 16, TFS(&tfs_alarmed_or_not), 0x02, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_battery,
            { "Battery", "zbee_zcl.ias_zone.server.scn.battery", FT_BOOLEAN, 16, TFS(&tfs_battery), 0x08, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_delay,
            { "Delay (in quarterseconds)", "zbee_zcl.ias_zone.server.scn.delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_ext_status,
            { "Extended Status", "zbee_zcl.ias_zone.server.scn.ext_status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_restore_reports,
            { "Restore Reports", "zbee_zcl.ias_zone.server.scn.restore_reports", FT_BOOLEAN, 16,
                TFS(&tfs_reports_restore), 0x20, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_supervision_reports,
            { "Supervision Reports", "zbee_zcl.ias_zone.server.scn.supervision_reports", FT_BOOLEAN, 16,
                TFS(&tfs_reports_or_not), 0x10, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_tamper,
            { "Tamper", "zbee_zcl.ias_zone.server.scn.tamper", FT_BOOLEAN, 16, TFS(&tfs_tampered_or_not), 0x04, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_trouble,
            { "Trouble", "zbee_zcl.ias_zone.server.scn.trouble", FT_BOOLEAN, 16, TFS(&tfs_trouble_failure), 0x40, NULL,
                HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_zone_id,
            { "Zone ID", "zbee_zcl.ias_zone.server.scn.zone_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_ias_zone_server_scn_zone_status,
            { "Zone Status", "zbee_zcl.ias_zone.server.scn.zone_status", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_poll_control_client_cir_fpt,
            { "Fast Poll Timeout (quarterseconds)", "zbee_zcl.poll_control.client.cir.fpt", FT_UINT16, BASE_DEC, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_poll_control_client_cir_sfp,
            { "Start Fast Polling", "zbee_zcl.poll_control.client.cir.sfp", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_poll_control_client_cmd_id,
            { "Command", "zbee_zcl.poll_control.client.cmd_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_poll_control_client_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_poll_control_client_slpi_nlpi,
            { "New Long Poll Interval", "zbee_zcl.poll_control.client.slpi_nlpi", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_poll_control_client_sspi_nspi,
            { "New Short Poll Interval", "zbee_zcl.poll_control.client.sspi.nspi", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_zcl_poll_control_server_cmd_id,
            { "Command", "zbee_zcl.poll_control.server.cmd_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_poll_control_server_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_cmd_id,
            { "Command", "zbee_zcl.thermostat.client.cmd_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_client_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_gws_days_to_return,
            { "Days To Return", "zbee_zcl.thermostat.client.gws.days_to_return", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_client_ws_dow), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_gws_mtr,
            { "Mode to Return", "zbee_zcl.thermostat.client.gws.mtr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_gws_mtr_cool,
            { "Cool Setpoint Field Present in Payload", "zbee_zcl.thermostat.client.gws.mtr.cool", FT_BOOLEAN, 8, NULL,
                0x02, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_gws_mtr_heat,
            { "Heat Setpoint Field Present in Payload", "zbee_zcl.thermostat.client.gws.mtr.heat", FT_BOOLEAN, 8, NULL,
                0x01, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_setpointrl_amount_field,
            { "Amount Field: increased/decreased by (in steps of 0.1 C)",
                "zbee_zcl.thermostat.client.sprl.amount_field", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_setpointrl_modes,
            { "Mode Field", "zbee_zcl.thermostat.client.sprl.mode_field", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_client_setpointrl_mf), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_sws_dow,
            { "Day of Week for Sequence", "zbee_zcl.thermostat.client.sws.dow", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_client_ws_dow), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_sws_mfs,
            { "Mode for Sequence", "zbee_zcl.thermostat.client.sws.mfs", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_sws_mfs_cool,
            { "Cool Setpoint Field Present in Payload", "zbee_zcl.thermostat.client.sws.mfs.cool", FT_BOOLEAN, 8, NULL,
                0x02, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_sws_mfs_heat,
            { "Heat Setpoint Field Present in Payload", "zbee_zcl.thermostat.client.sws.mfs.heat", FT_BOOLEAN, 8, NULL,
                0x01, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_client_sws_n_trans,
            { "Number of Transitions for Sequence", "zbee_zcl.thermostat.client.sws.n_trans", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_server_cmd_id,
            { "Command", "zbee_zcl.thermostat.server.cmd_id", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_server_cmd_names), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_server_gwsr_dow,
            { "Day of Week for Sequence", "zbee_zcl.thermostat.server.gwsr.dow", FT_UINT8, BASE_HEX,
                VALS(zbee_zcl_thermostat_client_ws_dow), 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_server_gwsr_mfs,
            { "Mode for Sequence", "zbee_zcl.thermostat.server.gwsr.mfs", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_server_gwsr_mfs_cool,
            { "Cool Setpoint Field Present in Payload", "zbee_zcl.thermostat.server.gwsr.mfs_cool", FT_BOOLEAN, 8, NULL,
                0x02, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_server_gwsr_mfs_heat,
            { "Heat Setpoint Field Present in Payload", "zbee_zcl.thermostat.server.gwsr.mfs_heat", FT_BOOLEAN, 8, NULL,
                0x01, NULL, HFILL }},

        { &hf_zbee_zcl_thermostat_server_gwsr_n_trans,
            { "Number of Transitions for Sequence", "zbee_zcl.thermostat.server.gwsr.n_trans", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }}
    };

    /* ZCL subtrees */
    gint *ett[ZBEE_ZCL_NUM_TOTAL_ETT];

    ett[0] = &ett_zbee_zcl;
    ett[1] = &ett_zbee_zcl_fcf;
    ett[2] = &ett_zbee_zcl_ias_zone_server_scn_zone_status;
    ett[3] = &ett_zbee_zcl_thermostat_client_gws_days_to_return;
    ett[4] = &ett_zbee_zcl_thermostat_client_gws_mtr;
    ett[5] = &ett_zbee_zcl_thermostat_client_sws_dow_for_sequence;
    ett[6] = &ett_zbee_zcl_thermostat_client_sws_mfs;
    ett[7] = &ett_zbee_zcl_thermostat_server_gwsr_dow_for_sequence;
    ett[8] = &ett_zbee_zcl_thermostat_server_gwsr_mfs;

    j = ZBEE_ZCL_NUM_INDIVIDUAL_ETT;

    /* initialize attribute subtree types */
    for ( i = 0; i < ZBEE_ZCL_NUM_ATTR_ETT; i++, j++) {
        ett_zbee_zcl_attr[i] = -1;
        ett[j] = &ett_zbee_zcl_attr[i];
    }

    for ( i = 0; i < ZBEE_ZCL_NUM_ARRAY_ELEM_ETT; i++, j++ ) {
        ett_zbee_zcl_array_elements[i] = -1;
        ett[j] = &ett_zbee_zcl_array_elements[i];
    }

    /* Register ZigBee ZCL protocol with Wireshark. */
    proto_zbee_zcl = proto_register_protocol("ZigBee Cluster Library", "ZigBee ZCL", "zbee_zcl");
    proto_register_field_array(proto_zbee_zcl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZCL dissector and subdissector list. */
    zbee_zcl_dissector_table = register_dissector_table("zbee.zcl.cluster", "ZigBee ZCL Cluster ID", FT_UINT16, BASE_HEX);
    new_register_dissector(ZBEE_PROTOABBREV_ZCL, dissect_zbee_zcl, proto_zbee_zcl);

} /* proto_register_zbee_zcl */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zbee_zcl
 *  DESCRIPTION
 *      Finds the dissectors used in this module.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zbee_zcl(void)
{
    dissector_handle_t   zbee_zcl_handle;

    /* Find the dissectors we need. */
    data_handle = find_dissector("data");

    /* Register our dissector for the appropriate profiles. */
    zbee_zcl_handle = find_dissector(ZBEE_PROTOABBREV_ZCL);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_IPM,   zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_T1,    zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_HA,    zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_CBA,   zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_WSN,   zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_TA,    zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_HC,    zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_SE,    zbee_zcl_handle);

    dissector_add_uint("zbee.profile", ZBEE_PROFILE_C4_CL, zbee_zcl_handle);
} /* proto_reg_handoff_zbee_zcl */


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_zcl_init_cluster
 *  DESCRIPTION
 *      Register the specific cluster.
 *  PARAMETERS
 *      proto            - dissector proto
 *      ett              - ett proto (not used at the moment)
 *      cluster_id       - cluster id
 *      fn_attr_id       - specific cluster attribute id decode function
 *      fn_attr_data     - specific cluster attribute data decode function
 *      fn_cmd_id        - specific cluster command id decode function
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void
zbee_zcl_init_cluster(int proto, gint ett, guint16 cluster_id, zbee_zcl_fn_attr_id fn_attr_id, zbee_zcl_fn_attr_data fn_attr_data, zbee_zcl_fn_cmd_id fn_cmd_id)
{
    zbee_zcl_cluster_desc *cluster_desc;
    cluster_desc  = g_new(zbee_zcl_cluster_desc, 1);

    cluster_desc->proto = find_protocol_by_id(proto);
    cluster_desc->name = proto_get_protocol_short_name(cluster_desc->proto);
    cluster_desc->cluster_id = cluster_id;
    cluster_desc->fn_attr_id = fn_attr_id;
    cluster_desc->fn_attr_data = fn_attr_data;
    cluster_desc->fn_cmd_id = fn_cmd_id;
    acluster_desc = g_list_append(acluster_desc, cluster_desc);

    cluster_desc->proto_id = proto;
    cluster_desc->ett = ett;

    return;
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_zcl_get_cluster_desc
 *  DESCRIPTION
 *      Retrieves the registered specific cluster descriptor.
 *  PARAMETERS
 *      cluster_id       - cluster id
 *  RETURNS
 *      zbee_zcl_cluster_desc    - cluster descriptor pointer
 *---------------------------------------------------------------
 */
zbee_zcl_cluster_desc
*zbee_zcl_get_cluster_desc(guint16 cluster_id)
{
    GList *gl;
    gl = acluster_desc;

    while (gl) {
        zbee_zcl_cluster_desc *cluster_desc = (zbee_zcl_cluster_desc *)gl->data;
        if(cluster_desc->cluster_id == cluster_id) {
            return cluster_desc;
        }
        gl = gl->next;
    }

    return NULL;
}
