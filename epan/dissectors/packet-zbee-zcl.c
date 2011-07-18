/* packet-zbee-zcl.c
 * Dissector routines for the ZigBee Cluster Library (ZCL)
 * By Fred Fierling <fff@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*  Include Files */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVEHCONFIG_H */

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#include "packet-zbee.h"
#include "packet-zbee-zcl.h"

/*************************
 * Function Declarations *
 *************************
 */
/* Dissector Routines */
static void dissect_zbee_zcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Command Dissector Helpers */
static void dissect_zcl_read_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_read_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint *offset);
static void dissect_zcl_write_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_write_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint *offset);
static void dissect_zcl_config_report (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_config_report_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint *offset);
static void dissect_zcl_read_report_config (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint *offset);
static void dissect_zcl_read_report_config_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint *offset);
static void dissect_zcl_default_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_discover_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_discover_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint *offset);

/* Helper routines */
guint zbee_apf_transaction_len (tvbuff_t *tvb, guint offset, guint8 type);
static void  dissect_zcl_attr_data_type_val (tvbuff_t *tvb, proto_tree *tree, guint *offset);
#if 0
static guint dissect_zcl_attr_data_type (tvbuff_t *tvb, proto_tree *tree, guint *offset);
#endif
static void  dissect_zcl_attr_data (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint data_type);
static void  dissect_zcl_attr_bytes (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint length);
static guint dissect_zcl_attr_uint8 (tvbuff_t *tvb, proto_tree *tree, guint *offset, int *length);
static guint dissect_zcl_attr_uint16 (tvbuff_t *tvb, proto_tree *tree, guint *offset, int *length);
static void  dissect_zcl_attr_id (tvbuff_t *tvb, proto_tree *tree, guint *offset);
static void  dissect_zcl_big_int (tvbuff_t *tvb, proto_tree *tree, guint *offset, guint length,
                gboolean signed_flag);
static void  zcl_dump_data(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree);

static guint64 tvb_get_letohi (tvbuff_t *tvb, guint offset, guint length, gboolean signed_flag);

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
static int hf_zbee_zcl_attr_semi = -1;
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

/* Subtree indices. */
static gint ett_zbee_zcl = -1;
static gint ett_zbee_zcl_fcf = -1;
static gint ett_zbee_zcl_attr[ZBEE_ZCL_NUM_ATTR_ETT];

/* Dissector Handles. */
static dissector_handle_t   data_handle;

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

    { 0, NULL }
};
static value_string_ext zbee_zcl_cmd_names_ext = VALUE_STRING_EXT_INIT(zbee_zcl_cmd_names);

/* ZCL Cluster-Specific Command Names */
static const value_string zbee_zcl_cs_cmd_names[] = {
    { 0, NULL }
};


/* Manufacturer Name Table */
static const value_string zbee_mfr_code_names[] = {

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
    { ZBEE_MFG_CODE_DIGI,       ZBEE_MFG_DIGI },
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
    { 0x1087,                   "Unknown" },             /**/
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
#if 0
    { ZBEE_MFG_CODE_G4S_JUSTICE,ZBEE_MFG_G4S_JUSTICE },
    { ZBEE_MFG_CODE_MMB,        ZBEE_MFG_PASSIVESYS },
#endif
    { 0x109a,                   "Unknown" },             /**/
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

    { 0, NULL }
};
static value_string_ext zbee_mfr_code_names_ext = VALUE_STRING_EXT_INIT(zbee_mfr_code_names);

/* ZCL Attribute Status Names */
static const value_string zbee_zcl_status_names[] = {
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
    { ZBEE_ZCL_STAT_INSUFFICIENT_SPACE,             "Insufficient Space"},
    { ZBEE_ZCL_STAT_DUPLICATE_EXISTS,               "Duplicate Exists"},
    { ZBEE_ZCL_STAT_NOT_FOUND,                      "Not Found"},
    { ZBEE_ZCL_STAT_UNREPORTABLE_ATTR,              "Unreportable Attribute"},
    { ZBEE_ZCL_STAT_INVALID_DATA_TYPE,              "Invalid Data Type"},
    { ZBEE_ZCL_STAT_INVALID_SELECTOR,               "Invalid Selector"},
    { ZBEE_ZCL_STAT_WRITE_ONLY,                     "Write Only"},
    { ZBEE_ZCL_STAT_INCONSISTENT_STARTUP_STATE,     "Inconsistent Startup State"},
    { ZBEE_ZCL_STAT_DEFINED_OUT_OF_BAND,            "Defined Out of Band"},
    { ZBEE_ZCL_STAT_HARDWARE_FAILURE,               "Hardware Failure"},
    { ZBEE_ZCL_STAT_SOFTWARE_FAILURE,               "Software Failure"},

    { ZBEE_ZCL_STAT_CALIBRATION_ERROR,              "Calibration Error"},
    { ZBEE_ZCL_STAT_INVALID_VALUE,                  "Invalid Value"},
    { ZBEE_ZCL_STAT_READ_ONLY,                      "Read Only"},

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
static const value_string zbee_zcl_short_data_type_names[] = {
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
    { 0,    "Reported" },
    { 1,    "Received" },

    { 0, NULL }
};

/* Attribute Discovery Names */
static const value_string zbee_zcl_dis_names[] = {
    { 0,    "Incomplete" },
    { 1,    "Complete" },

    { 0, NULL }
};

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_zcl
 *  DESCRIPTION
 *      ZigBee Cluster Library dissector for wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_into *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zbee_zcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *zcl_tree = NULL;
    proto_tree  *sub_tree = NULL;

    proto_item  *proto_root = NULL;
    proto_item  *ti;

    zbee_zcl_packet packet;

    guint8  fcf;
    guint   offset = 0;

    /* Init. */
    memset(&packet, 0, sizeof(zbee_zcl_packet));

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
        ti = proto_tree_add_text(zcl_tree, tvb, offset, sizeof(guint8),
                    "Frame Control Field: %s (0x%02x)",
                    val_to_str_const(packet.frame_type, zbee_zcl_frame_types, "Unknown"), fcf);
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_fcf);

        /* Add the frame type */
        proto_tree_add_uint(sub_tree, hf_zbee_zcl_fcf_frame_type, tvb, offset, sizeof(guint8),
            fcf & ZBEE_ZCL_FCF_FRAME_TYPE);

        /* Add the manufacturer specific, direction, and disable default response flags */
        proto_tree_add_boolean(sub_tree, hf_zbee_zcl_fcf_mfr_spec, tvb, offset,
                        sizeof(guint8), fcf & ZBEE_ZCL_FCF_MFR_SPEC);

        proto_tree_add_boolean(sub_tree, hf_zbee_zcl_fcf_dir, tvb, offset, sizeof(guint8),
            fcf & ZBEE_ZCL_FCF_DIRECTION);

        proto_tree_add_boolean(sub_tree, hf_zbee_zcl_fcf_disable_default_resp, tvb, offset,
                        sizeof(guint8), fcf & ZBEE_ZCL_FCF_DISABLE_DEFAULT_RESP);
    }
    offset += sizeof(guint8);

    /* If the manufacturer code is present, get and display it. */
    if (packet.mfr_spec) {
        packet.mfr_code = tvb_get_letohs(tvb, offset);

        if ( tree ) {
            proto_tree_add_uint(zcl_tree, hf_zbee_zcl_mfr_code, tvb, offset, sizeof(guint16),
                            packet.mfr_code);

            proto_item_append_text(proto_root, ", Mfr: %s (0x%04x)",
                            val_to_str_ext_const(packet.mfr_code, &zbee_mfr_code_names_ext, "Unknown"),
                            packet.mfr_code);
        }
        offset += sizeof(guint16);
    }

    /* Add the transaction sequence number to the tree */
    packet.tran_seqno = tvb_get_guint8(tvb, offset);

    if ( zcl_tree ) {
        proto_tree_add_uint(zcl_tree, hf_zbee_zcl_tran_seqno, tvb, offset, sizeof(guint8),
                        packet.tran_seqno);
    }
    offset += sizeof(guint8);

    /* Display the command and sequence number on the proto root and info column. */
    packet.cmd_id = tvb_get_guint8(tvb, offset);

    /* Add command ID to the tree. */
    if ( packet.frame_type == ZBEE_ZCL_FCF_PROFILE_WIDE ) {
        if ( tree ) {
            proto_item_append_text(proto_root, ", Command: %s, Seq: %u",
                val_to_str_ext_const(packet.cmd_id, &zbee_zcl_cmd_names_ext, "Unknown Command"),
                packet.tran_seqno);
        }

        if ( check_col(pinfo->cinfo, COL_INFO) ) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
                val_to_str_ext_const(packet.cmd_id, &zbee_zcl_cmd_names_ext, "Unknown Command"),
                packet.tran_seqno);
        }

        if ( zcl_tree ) {
            proto_tree_add_uint(zcl_tree, hf_zbee_zcl_cmd_id, tvb, offset, sizeof(guint8),
                            packet.cmd_id);
        }
        offset += sizeof(guint8);
    } else {
        if ( tree ) {
            proto_item_append_text(proto_root, ", Cluster-specific Command: 0x%02x, Seq: %u",
                packet.cmd_id, packet.tran_seqno);
        }

        if ( check_col(pinfo->cinfo, COL_INFO) ) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Command: 0x%02x, Seq: %u",
                packet.cmd_id, packet.tran_seqno);
        }

        if ( zcl_tree ) {
            proto_tree_add_uint(zcl_tree, hf_zbee_zcl_cs_cmd_id, tvb, offset, sizeof(guint8),
                            packet.cmd_id);
        }
        offset += sizeof(guint8);

        /* Don't decode cluster-specific commands */
        zcl_dump_data(tvb, offset, pinfo, zcl_tree);
        return;
    }

    if ( zcl_tree ) {
    /* Handle the contents of the command frame. */
        switch ( packet.cmd_id ) {
            case ZBEE_ZCL_CMD_READ_ATTR:
                dissect_zcl_read_attr(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_READ_ATTR_RESP:
                dissect_zcl_read_attr_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR:
            case ZBEE_ZCL_CMD_WRITE_ATTR_UNDIVIDED:
            case ZBEE_ZCL_CMD_WRITE_ATTR_NO_RESP:
            case ZBEE_ZCL_CMD_REPORT_ATTR:
                dissect_zcl_write_attr(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR_RESP:
                dissect_zcl_write_attr_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_CONFIG_REPORT:
                dissect_zcl_config_report(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_CONFIG_REPORT_RESP:
                dissect_zcl_config_report_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_READ_REPORT_CONFIG:
                dissect_zcl_read_report_config(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_READ_REPORT_CONFIG_RESP:
                dissect_zcl_read_report_config_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_DEFAULT_RESP:
                dissect_zcl_default_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_ATTR:
                dissect_zcl_discover_attr(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_ATTR_RESP:
                dissect_zcl_discover_attr_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            /* BUGBUG: don't dissect these for now */
            case ZBEE_ZCL_CMD_READ_ATTR_STRUCT:
            case ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT:
            case ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT_RESP:
            default:
                zcl_dump_data(tvb, offset, pinfo, zcl_tree);
                break;
        } /* switch */
    }

    return;
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
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_read_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    guint tvb_len;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len ) {
        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, tree, offset);
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
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_read_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Status Record");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset);

        /* Dissect the status and optionally the data type and value */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status)
            == ZBEE_ZCL_STAT_SUCCESS ) {

            /* Dissect the attribute data type and data */
            dissect_zcl_attr_data_type_val(tvb, sub_tree, offset);
        }
    }

    return;
} /* dissect_zcl_read_attr_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_write_attr
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_write_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        ti = proto_tree_add_text(tree, tvb, *offset, 0, "Attribute Field");
        sub_tree = proto_item_add_subtree(ti, ett_zbee_zcl_attr[i]);
        i++;

        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset);

        /* Dissect the attribute data type and data */
        dissect_zcl_attr_data_type_val(tvb, sub_tree, offset);
    }

    return;
} /* dissect_zcl_write_attr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_write_attr_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Write Attribute Response command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_write_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

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
            dissect_zcl_attr_id(tvb, sub_tree, offset);
        }
    }

    return;
} /* dissect_zcl_write_attr_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_read_report_config_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *---------------------------------------------------------------
 */
static void dissect_zcl_read_report_config_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    guint data_type;
    guint attr_status;
    guint attr_dir;

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
        dissect_zcl_attr_id(tvb, sub_tree, offset);

        if ( attr_status == ZBEE_ZCL_STAT_SUCCESS ) {
            if ( attr_dir == ZBEE_ZCL_DIR_REPORTED ) {

                /* Dissect the attribute data type */
                data_type = dissect_zcl_attr_uint8(tvb, sub_tree, offset,
                        &hf_zbee_zcl_attr_data_type);

                /* Dissect minimum reporting interval */
                dissect_zcl_attr_uint16(tvb, sub_tree, offset, &hf_zbee_zcl_attr_minint);

                /* Dissect maximum reporting interval */
                dissect_zcl_attr_uint16(tvb, sub_tree, offset, &hf_zbee_zcl_attr_maxint);

                if ( IS_ANALOG_SUBTYPE(data_type) ) {
                    /* Dissect reportable change */
                    dissect_zcl_attr_data(tvb, sub_tree, offset, data_type);
                }

            } else {
                /* Dissect timeout period */
                dissect_zcl_attr_uint16(tvb, sub_tree, offset, &hf_zbee_zcl_attr_timeout);
            }
        }
    }

    return;
} /* dissect_zcl_read_report_config_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_config_report
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *---------------------------------------------------------------
 */
static void dissect_zcl_config_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    guint data_type;

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
            dissect_zcl_attr_id(tvb, sub_tree, offset);

            /* Dissect the attribute data type */
            data_type = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_data_type);

            /* Dissect minimum reporting interval */
            dissect_zcl_attr_uint16(tvb, sub_tree, offset, &hf_zbee_zcl_attr_minint);

            /* Dissect maximum reporting interval */
            dissect_zcl_attr_uint16(tvb, sub_tree, offset, &hf_zbee_zcl_attr_maxint);

            if ( IS_ANALOG_SUBTYPE(data_type) ) {
                /* Dissect reportable change */
                dissect_zcl_attr_data(tvb, sub_tree, offset, data_type);
            }
        } else {

            /* Dissect the attribute id */
            dissect_zcl_attr_id(tvb, sub_tree, offset);

            /* Dissect timeout period */
            dissect_zcl_attr_uint16(tvb, sub_tree, offset, &hf_zbee_zcl_attr_timeout);
        }
    }

    return;
} /* dissect_zcl_config_report */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_config_report_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Report Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_config_report_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

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
                dissect_zcl_attr_id(tvb, sub_tree, offset);
        }
    }

    return;
} /* dissect_zcl_config_report_resp */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_read_report_config
 *  DESCRIPTION
 *      Helper dissector for ZCL Read Report Configuration command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      guint               - offset after command dissection.
 *---------------------------------------------------------------
 */
static void dissect_zcl_read_report_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

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
        dissect_zcl_attr_id(tvb, sub_tree, offset);
    }

    return;
} /* dissect_zcl_read_report_config */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_default_resp
 *  DESCRIPTION
 *      Helper dissector for ZCL Default Response command.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_default_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    guint cmd_id;

    /* Dissect the command identifier */
    cmd_id = tvb_get_guint8(tvb, *offset);

    proto_tree_add_uint(tree, hf_zbee_zcl_cmd_id, tvb, *offset, sizeof(guint8), cmd_id);
    *offset += sizeof(guint8);

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
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_discover_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    /* Dissect the starting attribute identifier */
    dissect_zcl_attr_uint16(tvb, tree, offset, &hf_zbee_zcl_attr_start);

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
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - pointer to offset from caller
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_discover_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset)
{
    proto_item  *ti = NULL;
    proto_tree  *sub_tree = NULL;

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
        dissect_zcl_attr_id(tvb, sub_tree, offset);

        /* Dissect the number of maximum attribute identifiers */
        dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_data_type);
    }

    return;
} /* dissect_zcl_discover_attr_resp */

#if 0
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_data_type
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      guint               - attribute data type
 *---------------------------------------------------------------
 */
static guint dissect_zcl_attr_data_type(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint attr_data_type;

    /* Dissect attribute data type */
    attr_data_type = tvb_get_guint8(tvb, *offset);

    if ( tree ) {
        proto_tree_add_uint(tree, hf_zbee_zcl_attr_data_type, tvb, *offset, sizeof(guint8),
                    attr_data_type);
    }
    *offset += sizeof(guint8);

    return attr_data_type;
} /* dissect_zcl_attr_data_type */
#endif

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_id
 *  DESCRIPTION
 *      Dissects Attribute ID field. This could be done with the
 *      dissect_zcl_attr_uint16 function, but we leave it separate
 *      so we can dissect the attr_id with a hash in the future.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_id(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    guint16 attr_id;

    attr_id = tvb_get_letohs(tvb, *offset);

    /* Add the identifier */
    proto_tree_add_uint(tree, hf_zbee_zcl_attr_id, tvb, *offset, sizeof(guint16),
                       attr_id);
    *offset += sizeof(guint16);

    return;
} /* dissect_zcl_attr_id */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_data_type_val
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_data_type_val(tvbuff_t *tvb, proto_tree *tree, guint *offset)
{
    dissect_zcl_attr_data(tvb, tree, offset,
            dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_data_type) );

    return;
} /* dissect_zcl_attr_data_type_val */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_data
 *  DESCRIPTION
 *      Dissects the various types of ZCL attribute data.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      data_type           - the type of ZCL data in the packet buffer
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_data(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint data_type)
{
    guint attr_uint;
    gint attr_int;
    guint8 *attr_string;
    guint8 attr_uint8[4];
    gfloat attr_float;
    gdouble attr_double;
    nstime_t attr_time;

    attr_uint = 0;
    attr_int = 0;

    /* Dissect attribute data type and data */
    switch ( data_type ) {
        case ZBEE_ZCL_NO_DATA:
            break;

        case ZBEE_ZCL_8_BIT_DATA:
        case ZBEE_ZCL_8_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 1);
            break;

        case ZBEE_ZCL_8_BIT_UINT:
        case ZBEE_ZCL_8_BIT_ENUM:

            /* Display 8 bit unsigned integer */
            attr_uint = tvb_get_guint8(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_uint8, tvb, *offset, sizeof(guint8),
                        attr_uint);
            *offset += sizeof(guint8);
            break;

        case ZBEE_ZCL_8_BIT_INT:
            /* Display 8 bit integer */

            attr_int = (gint8)tvb_get_guint8(tvb, *offset);

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_int(tree, hf_zbee_zcl_attr_int8, tvb, *offset, sizeof(gint8),
                        (gint)attr_int);

            *offset += sizeof(gint8);
            break;

        case ZBEE_ZCL_BOOLEAN:

            attr_uint = tvb_get_guint8(tvb, *offset);

            proto_item_append_text(tree, ", %s: 0x%02x",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_boolean, tvb, *offset, 1, FALSE);

            *offset += sizeof(guint8);
            break;

        case ZBEE_ZCL_16_BIT_DATA:
        case ZBEE_ZCL_16_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 2);
            break;

        case ZBEE_ZCL_16_BIT_UINT:
        case ZBEE_ZCL_16_BIT_ENUM:
            /* Display 16 bit unsigned integer */

            attr_uint = tvb_get_letohs(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_uint16, tvb, *offset, sizeof(guint16),
                        attr_uint);

            *offset += sizeof(guint16);
            break;

        case ZBEE_ZCL_16_BIT_INT:
            /* Display 16 bit integer */

            attr_int = (gint16)tvb_get_letohs(tvb, *offset);

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_int(tree, hf_zbee_zcl_attr_int16, tvb, *offset, sizeof(gint16),
                        attr_int);

            *offset += sizeof(gint16);
            break;

        case ZBEE_ZCL_24_BIT_DATA:
        case ZBEE_ZCL_24_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 3);
            break;

        case ZBEE_ZCL_24_BIT_UINT:
            /* Display 24 bit unsigned integer */

            attr_uint = tvb_get_letoh24(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_uint24, tvb, *offset, 3,
                        attr_uint);

            *offset += 3;
            break;

        case ZBEE_ZCL_24_BIT_INT:
            /* Display 24 bit signed integer */

            attr_int = (gint)tvb_get_letoh24(tvb, *offset);
            /* sign extend into int32 */
            if (attr_int & INT24_SIGN_BITS) attr_int |= INT24_SIGN_BITS;

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_int(tree, hf_zbee_zcl_attr_int24, tvb, *offset, 3,
                        attr_int);

            *offset += 3;
            break;

        case ZBEE_ZCL_32_BIT_DATA:
        case ZBEE_ZCL_32_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 4);
            break;

        case ZBEE_ZCL_32_BIT_UINT:
            /* Display 32 bit unsigned integer */

            attr_uint = tvb_get_letohl(tvb, *offset);

            proto_item_append_text(tree, ", %s: %u",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_uint);

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_uint32, tvb, *offset, sizeof(guint),
                        attr_uint);

            *offset += sizeof(guint);
            break;

        case ZBEE_ZCL_32_BIT_INT:
            /* Display 32 bit signed integer */

            attr_int = (gint)tvb_get_letohl(tvb, *offset);

            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);

            proto_tree_add_int(tree, hf_zbee_zcl_attr_int32, tvb, *offset, sizeof(gint),
                        attr_int);

            *offset += sizeof(gint);
            break;

        case ZBEE_ZCL_40_BIT_DATA:
        case ZBEE_ZCL_40_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 5);
            break;

        case ZBEE_ZCL_40_BIT_UINT:
            dissect_zcl_big_int(tvb, tree, offset, 5, FALSE);
            break;

        case ZBEE_ZCL_40_BIT_INT:
            dissect_zcl_big_int(tvb, tree, offset, 5, TRUE);
            break;

        case ZBEE_ZCL_48_BIT_DATA:
        case ZBEE_ZCL_48_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 6);
            break;

        case ZBEE_ZCL_48_BIT_UINT:
            dissect_zcl_big_int(tvb, tree, offset, 6, FALSE);
            break;

        case ZBEE_ZCL_48_BIT_INT:
            dissect_zcl_big_int(tvb, tree, offset, 6, TRUE);
            break;

        case ZBEE_ZCL_56_BIT_DATA:
        case ZBEE_ZCL_56_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 7);
            break;

        case ZBEE_ZCL_56_BIT_UINT:
            dissect_zcl_big_int(tvb, tree, offset, 7, FALSE);
            break;

        case ZBEE_ZCL_56_BIT_INT:
            dissect_zcl_big_int(tvb, tree, offset, 7, TRUE);
            break;

        case ZBEE_ZCL_64_BIT_DATA:
        case ZBEE_ZCL_64_BIT_BITMAP:
            dissect_zcl_attr_bytes(tvb, tree, offset, 8);
            break;

        case ZBEE_ZCL_64_BIT_UINT:
            dissect_zcl_big_int(tvb, tree, offset, 8, FALSE);
            break;

        case ZBEE_ZCL_64_BIT_INT:
            dissect_zcl_big_int(tvb, tree, offset, 8, TRUE);
            break;

        case ZBEE_ZCL_SEMI_FLOAT:
            /* BUGBUG */
            dissect_zcl_attr_bytes(tvb, tree, offset, 2);
            break;

        case ZBEE_ZCL_SINGLE_FLOAT:
            attr_float = tvb_get_letohieee_float(tvb, *offset);


            proto_item_append_text(tree, ", %s: %g",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_float);

            proto_tree_add_item(tree, hf_zbee_zcl_attr_float, tvb, *offset, 4, TRUE);

            *offset += 4;
            break;

        case ZBEE_ZCL_DOUBLE_FLOAT:
            attr_double = tvb_get_letohieee_double(tvb, *offset);

            proto_item_append_text(tree, ", Double: %lg", attr_double);
            proto_tree_add_item(tree, hf_zbee_zcl_attr_double, tvb, *offset, 8, TRUE);

            *offset += 8;
            break;

        case ZBEE_ZCL_OCTET_STRING:

            /* Display octet string */
            attr_uint = tvb_get_guint8(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_STR_LENGTH) attr_uint = 0;

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, sizeof(guint8),
                        attr_uint);

            *offset += sizeof(guint8);

            attr_string = tvb_bytes_to_str_punct(tvb, *offset, attr_uint, ':');
            proto_item_append_text(tree, ", Octets: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_ostr, tvb, *offset, attr_uint,
                            attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_CHAR_STRING:

            /* Display string */
            attr_uint = tvb_get_guint8(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_STR_LENGTH) attr_uint = 0;

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, sizeof(guint8),
                        attr_uint);

            *offset += sizeof(guint8);

            attr_string = tvb_get_ephemeral_string(tvb, *offset, attr_uint);

            proto_item_append_text(tree, ", String: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_str, tvb, *offset, attr_uint, attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_LONG_OCTET_STRING:

            /* Display long octet string */
            attr_uint = tvb_get_letohs(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_LONG_STR_LENGTH) attr_uint = 0;
            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, sizeof(guint16), attr_uint);

            *offset += sizeof(guint16);

            attr_string = tvb_bytes_to_str_punct(tvb, *offset, attr_uint, ':');
            proto_item_append_text(tree, ", Octets: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_ostr, tvb, *offset, attr_uint, attr_string);

            *offset += attr_uint;
            break;

        case ZBEE_ZCL_LONG_CHAR_STRING:

            /* Display long string */
            attr_uint = tvb_get_letohs(tvb, *offset); /* string length */
            if (attr_uint == ZBEE_ZCL_INVALID_LONG_STR_LENGTH) attr_uint = 0;

            proto_tree_add_uint(tree, hf_zbee_zcl_attr_str_len, tvb, *offset, sizeof(guint16), attr_uint);

            *offset += sizeof(guint16);

            attr_string = tvb_get_ephemeral_string(tvb, *offset, attr_uint);
            proto_item_append_text(tree, ", String: %s", attr_string);
            proto_tree_add_string(tree, hf_zbee_zcl_attr_str, tvb, *offset, attr_uint, attr_string);

            *offset += attr_uint;
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
            attr_time.secs = (guint32)tvb_get_letohl(tvb, *offset);
            attr_time.secs += ZBEE_ZCL_NSTIME_UTC_OFFSET;
            attr_time.nsecs = 0;

            proto_item_append_text(tree, ", %s",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved") );
            proto_tree_add_time(tree, hf_zbee_zcl_attr_utc, tvb, *offset, sizeof(guint),
                            &attr_time);

            *offset += sizeof(guint32);
            break;

        case ZBEE_ZCL_CLUSTER_ID:
            dissect_zcl_attr_uint16(tvb, tree, offset, &hf_zbee_zcl_attr_cid);
            break;

        case ZBEE_ZCL_ATTR_ID:
            dissect_zcl_attr_id(tvb, tree, offset);
            break;

        case ZBEE_ZCL_BACNET_OID:
            dissect_zcl_attr_bytes(tvb, tree, offset, 4);
            break;

        case ZBEE_ZCL_IEEE_ADDR:
            dissect_zcl_attr_bytes(tvb, tree, offset, 8);
            break;

        case ZBEE_ZCL_SECURITY_KEY:
            dissect_zcl_attr_bytes(tvb, tree, offset, 16);
            break;

        default:
            break;
        }

    return;
} /* dissect_zcl_attr_data */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_big_int
 *  DESCRIPTION
 *      Dissects int or uint of up to 64 bits.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      signed_flag         - if TRUE, dissect a signed int
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_big_int(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint length,
                gboolean signed_flag)
{
    guint64 attr_uint64;

    attr_uint64 = tvb_get_letohi(tvb, *offset, length, signed_flag);

    /* add it to tree */

    if ( signed_flag ) {
        proto_item_append_text(tree, ", Int: %" G_GINT64_MODIFIER "d", (gint64)attr_uint64);

        proto_tree_add_int64(tree, hf_zbee_zcl_attr_int64, tvb, *offset, length,
                (gint64)attr_uint64);
    } else {
        proto_item_append_text(tree, ", Uint: %" G_GINT64_MODIFIER "u", attr_uint64);

        proto_tree_add_uint64(tree, hf_zbee_zcl_attr_uint64, tvb, *offset, length,
                attr_uint64);
    }

    *offset += length;

    return;
} /* dissect_zcl_big_int */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_uint8
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
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
        proto_tree_add_uint(tree, *hf_zbee_zcl, tvb, *offset, sizeof(guint8), attr_uint);
        (*offset)++;

        return attr_uint;
} /* dissect_zcl_attr_uint8 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_uint16
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      hf_zbee_zcl         - pointer to header field index
 *  RETURNS
 *      guint               - field value
 *---------------------------------------------------------------
 */
static guint dissect_zcl_attr_uint16(tvbuff_t *tvb, proto_tree *tree, guint *offset, int *hf_zbee_zcl)
{
        guint attr_uint;

        attr_uint = tvb_get_letohs(tvb, *offset);
        proto_tree_add_uint(tree, *hf_zbee_zcl, tvb, *offset, sizeof(guint16), attr_uint);
        *offset += sizeof(guint16);

        return attr_uint;
} /* dissect_zcl_attr_uint16 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zcl_attr_bytes
 *  DESCRIPTION
 *      Helper dissector for ZCL Attribute commands.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      proto_tree *tree    - pointer to data tree ethereal uses to display packet.
 *      offset              - offset into the tvb to begin dissection.
 *      length              - number of bytes to dissect
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void dissect_zcl_attr_bytes(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint length)
{
        proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, length, ENC_NA);
        *offset += length;

        return;
} /* dissect_dcl_attr_bytes */

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
    proto_tree  *root = proto_tree_get_root(tree);
    guint       length = tvb_length_remaining(tvb, offset);
    tvbuff_t    *remainder;

    if (length > 0) {
        remainder = tvb_new_subset(tvb, offset, length, length);
        call_dissector(data_handle, remainder, pinfo, root);
    }
} /* zcl_dump_data */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      tvb_get_letohi
 *  DESCRIPTION
 *      Gets little endian int or uint of up to 8 bytes from tvb buffer.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      offset              - offset into the tvb to begin dissection.
 *      length              - length of int or uint in bytes
 *      signed_flag         - if TRUE, get a signed int
 *  RETURNS
 *      guint64             - value retrieved from tvb buffer
 *---------------------------------------------------------------
 */
static guint64 tvb_get_letohi(tvbuff_t *tvb, guint offset, guint length, gboolean signed_flag)
{
        guint64 result;
        guint shift;

        DISSECTOR_ASSERT((length>=1) && (length<=8));

        result = 0;
        shift = 0;
        /* build big int of length bytes */
        while ( length-- ) {
            result += (guint64)tvb_get_guint8(tvb, offset) << shift;
            offset += sizeof(guint8);
            shift += 8;
        }

        if ( signed_flag && (result >> (shift - 1)) ) {
            /* sign extend remaining bytes */
            while ( shift < (sizeof(guint64) * 8) ) {
                result += (guint64)0xff << shift;
                shift += 8;
            }
        }

        return result;
} /* tvb_get_letohi */

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

    static hf_register_info hf[] = {
        { &hf_zbee_zcl_fcf_frame_type,
            { "Frame Type", "zbee.zcl.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_frame_types),
                ZBEE_ZCL_FCF_FRAME_TYPE, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_mfr_spec,
            { "Manufacturer Specific", "zbee.zcl.ms", FT_BOOLEAN, 8, NULL,
                ZBEE_ZCL_FCF_MFR_SPEC, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_dir,
            { "Direction", "zbee.zcl.dir", FT_BOOLEAN, 8, TFS(&tfs_client_server),
                ZBEE_ZCL_FCF_DIRECTION, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_disable_default_resp,
            { "Disable Default Response", "zbee.zcl.ddr", FT_BOOLEAN, 8, NULL,
                ZBEE_ZCL_FCF_DISABLE_DEFAULT_RESP, NULL, HFILL }},

        { &hf_zbee_zcl_mfr_code,
            { "Manufacturer Code", "zbee.zcl.cmd.mc", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
                    &zbee_mfr_code_names_ext, 0x0, "Assigned manufacturer code.", HFILL }},

        { &hf_zbee_zcl_tran_seqno,
            { "Sequence Number", "zbee.zcl.cmd.tsn", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_cmd_id,
            { "Command",    "zbee.zcl.cmd.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &zbee_zcl_cmd_names_ext,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_cs_cmd_id,
          { "Command",    "zbee.zcl.cs.cmd.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_cs_cmd_names) /*"Unknown"*/,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_id,
            { "Attribute",  "zbee.zcl.attr.id", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_data_type,
            { "Data Type",  "zbee.zcl.attr.data.type", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &zbee_zcl_data_type_names_ext, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_boolean,
            { "Boolean",    "zbee.zcl.attr.boolean", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0xff,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint8,
            { "Uint8",  "zbee.zcl.attr.uint8", FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint16,
            { "Uint16", "zbee.zcl.attr.uint16", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint24,
            { "Uint24", "zbee.zcl.attr.uint24", FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint32,
            { "Uint32", "zbee.zcl.attr.uint32", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint64,
            { "Uint64", "zbee.zcl.attr.uint64", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int8,
            { "Int8",   "zbee.zcl.attr.int8", FT_INT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int16,
            { "Int16",  "zbee.zcl.attr.int16", FT_INT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int24,
            { "Int24",  "zbee.zcl.attr.int24", FT_INT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int32,
            { "Int32",  "zbee.zcl.attr.int32", FT_INT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_int64,
            { "Int64",  "zbee.zcl.attr.int64", FT_INT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_semi,
            { "Semi Float", "zbee.zcl.attr.float", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_float,
            { "Float", "zbee.zcl.attr.float", FT_FLOAT, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_double,
            { "Double Float", "zbee.zcl.attr.float", FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bytes,
            { "Bytes",  "zbee.zcl.attr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_minint,
            { "Minimum Interval", "zbee.zcl.attr.minint", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_maxint,
            { "Maximum Interval", "zbee.zcl.attr.maxint", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_timeout,
            { "Timeout", "zbee.zcl.attr.timeout", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_hours,
            { "Hours",  "zbee.zcl.attr.hours", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_mins,
            { "Minutes", "zbee.zcl.attr.mins", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_secs,
            { "Seconds", "zbee.zcl.attr.secs", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_csecs,
            { "Centiseconds", "zbee.zcl.attr.csecs", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_yy,
            { "Year", "zbee.zcl.attr.yy", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_mm,
            { "Month", "zbee.zcl.attr.mm", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_md,
            { "Day of Month", "zbee.zcl.attr.md", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_wd,
            { "Day of Week", "zbee.zcl.attr.wd", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_utc,
            { "UTC", "zbee.zcl.attr.utc", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_status,
            { "Status", "zbee.zcl.attr.status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &zbee_zcl_status_names_ext,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_dir,
            { "Direction", "zbee.zcl.attr.dir", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dir_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_dis,
            { "Discovery", "zbee.zcl.attr.dis", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dis_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_attr_cid,
            { "Cluster", "zbee.zcl.attr.cid", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_start,
            { "Start Attribute", "zbee.zcl.attr.start", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_maxnum,
            { "Maxiumum Number", "zbee.zcl.attr.maxnum", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_str_len,
            { "Length", "zbee.zcl.attr.str.len", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_str,
            { "String", "zbee.zcl.attr.str", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_ostr,
            { "Octet String",   "zbee.zcl.attr.ostr", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }}
    };

    /* ZCL subtrees */
    gint *ett[ZBEE_ZCL_NUM_INDIVIDUAL_ETT + ZBEE_ZCL_NUM_ATTR_ETT];

    ett[0] = &ett_zbee_zcl;
    ett[1] = &ett_zbee_zcl_fcf;

    j = ZBEE_ZCL_NUM_INDIVIDUAL_ETT;

    /* initialize attribute subtree types */
    for ( i = 0; i < ZBEE_ZCL_NUM_ATTR_ETT; i++, j++) {
        ett_zbee_zcl_attr[i] = -1;
        ett[j] = &ett_zbee_zcl_attr[i];
    }

    /* Register ZigBee ZCL protocol with Wireshark. */
    proto_zbee_zcl = proto_register_protocol("ZigBee Cluster Library", "ZigBee ZCL", "zbee.zcl");
    proto_register_field_array(proto_zbee_zcl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZCL dissector and subdissector list. */
    register_dissector("zbee.zcl", dissect_zbee_zcl, proto_zbee_zcl);

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
    zbee_zcl_handle = find_dissector("zbee.zcl");
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
