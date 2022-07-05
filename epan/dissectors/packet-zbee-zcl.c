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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-zcl.h"

/*************************
 * Function Declarations *
 *************************
 */
void proto_register_zbee_zcl(void);
void proto_reg_handoff_zbee_zcl(void);

/* Command Dissector Helpers */
static void dissect_zcl_write_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_config_report (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_config_report_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_read_report_config (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_read_report_config_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_default_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_discover_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);
static void dissect_zcl_discover_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_read_attr_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_write_attr_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_write_attr_struct_resp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
static void dissect_zcl_discover_cmd_rec(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset);
static void dissect_zcl_discover_cmd_rec_resp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset);
//static void dissect_zcl_discover_attr_extended_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);

/* Helper routines */
static void  dissect_zcl_attr_data_general(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 attr_id, guint data_type, guint16 cluster_id, guint16 mfr_code, gboolean client_attr);
static void  zcl_dump_data(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree);

static void dissect_zcl_array_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num, gboolean client_attr);
static void dissect_zcl_set_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num, gboolean client_attr);

static zbee_zcl_cluster_desc *zbee_zcl_get_cluster_desc(guint16 cluster_id, guint16 mfr_code);
static void dissect_zcl_discover_cmd_attr_extended_resp(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, guint* offset, guint16 cluster_id, guint16 mfr_code, gboolean direction);
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
static int hf_zbee_zcl_cmd_id_rsp = -1;
static int hf_zbee_zcl_attr_id = -1;
static int hf_zbee_zcl_attr_data_type = -1;
static int hf_zbee_zcl_attr_access_ctrl = -1;
static int hf_zbee_zcl_indicator = -1;
static int hf_zbee_zcl_index = -1;
static int hf_zbee_zcl_cmd_start = -1;
static int hf_zbee_zcl_cmd_maxnum = -1;
static int hf_zbee_zcl_attr_boolean = -1;
static int hf_zbee_zcl_attr_bitmap8 = -1;
static int hf_zbee_zcl_attr_bitmap16 = -1;
static int hf_zbee_zcl_attr_bitmap24 = -1;
static int hf_zbee_zcl_attr_bitmap32 = -1;
static int hf_zbee_zcl_attr_bitmap40 = -1;
static int hf_zbee_zcl_attr_bitmap48 = -1;
static int hf_zbee_zcl_attr_bitmap56 = -1;
static int hf_zbee_zcl_attr_bitmap64 = -1;
static int hf_zbee_zcl_attr_uint8 = -1;
static int hf_zbee_zcl_attr_uint16 = -1;
static int hf_zbee_zcl_attr_uint24 = -1;
static int hf_zbee_zcl_attr_uint32 = -1;
static int hf_zbee_zcl_attr_uint40 = -1;
static int hf_zbee_zcl_attr_uint48 = -1;
static int hf_zbee_zcl_attr_uint56 = -1;
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
static int hf_zbee_zcl_attr_str = -1;
static int hf_zbee_zcl_attr_ostr = -1;
static int hf_zbee_zcl_attr_array_elements_type = -1;
static int hf_zbee_zcl_attr_array_elements_num = -1;
static int hf_zbee_zcl_attr_set_elements_type = -1;
static int hf_zbee_zcl_attr_set_elements_num = -1;
static int hf_zbee_zcl_attr_bag_elements_type = -1;
static int hf_zbee_zcl_attr_bag_elements_num = -1;

/* Subtree indices. */
static gint ett_zbee_zcl = -1;
static gint ett_zbee_zcl_fcf = -1;
static gint ett_zbee_zcl_attr[ZBEE_ZCL_NUM_ATTR_ETT];
static gint ett_zbee_zcl_sel[ZBEE_ZCL_NUM_IND_FIELD];
static gint ett_zbee_zcl_array_elements[ZBEE_ZCL_NUM_ARRAY_ELEM_ETT];

static expert_field ei_cfg_rpt_rsp_short_non_success = EI_INIT;
static expert_field ei_zbee_zero_length_element = EI_INIT;

/* Dissector List. */
static dissector_table_t    zbee_zcl_dissector_table;

/* Global variables */
static guint16 zcl_cluster_id = -1;
static guint16 zcl_mfr_code = -1;

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

/* ZigBee Manufacturer Code Table */
/* Per: 053874r74, June 2021 */
const value_string zbee_mfr_code_names[] = {
    { ZBEE_MFG_CODE_PANASONIC_RF4CE,   ZBEE_MFG_PANASONIC },
    { ZBEE_MFG_CODE_SONY_RF4CE,        ZBEE_MFG_SONY },
    { ZBEE_MFG_CODE_SAMSUNG_RF4CE,     ZBEE_MFG_SAMSUNG },
    { ZBEE_MFG_CODE_PHILIPS_RF4CE,     ZBEE_MFG_PHILIPS },
    { ZBEE_MFG_CODE_FREESCALE_RF4CE,   ZBEE_MFG_FREESCALE },
    { ZBEE_MFG_CODE_OKI_SEMI_RF4CE,    ZBEE_MFG_OKI_SEMI },
    { ZBEE_MFG_CODE_TI_RF4CE,          ZBEE_MFG_TI },
    { ZBEE_MFG_CODE_CIRRONET,          ZBEE_MFG_CIRRONET },
    { ZBEE_MFG_CODE_CHIPCON,           ZBEE_MFG_CHIPCON },
    { ZBEE_MFG_CODE_EMBER,             ZBEE_MFG_EMBER },
    { ZBEE_MFG_CODE_NTS,               ZBEE_MFG_NTS },
    { ZBEE_MFG_CODE_FREESCALE,         ZBEE_MFG_FREESCALE },
    { ZBEE_MFG_CODE_IPCOM,             ZBEE_MFG_IPCOM },
    { ZBEE_MFG_CODE_SAN_JUAN,          ZBEE_MFG_SAN_JUAN },
    { ZBEE_MFG_CODE_TUV,               ZBEE_MFG_TUV },
    { ZBEE_MFG_CODE_COMPXS,            ZBEE_MFG_COMPXS },
    { ZBEE_MFG_CODE_BM,                ZBEE_MFG_BM },
    { ZBEE_MFG_CODE_AWAREPOINT,        ZBEE_MFG_AWAREPOINT },
    { ZBEE_MFG_CODE_PHILIPS,           ZBEE_MFG_PHILIPS },
    { ZBEE_MFG_CODE_LUXOFT,            ZBEE_MFG_LUXOFT },
    { ZBEE_MFG_CODE_KORWIN,            ZBEE_MFG_KORWIN },
    { ZBEE_MFG_CODE_1_RF,              ZBEE_MFG_1_RF },
    { ZBEE_MFG_CODE_STG,               ZBEE_MFG_STG },
    { ZBEE_MFG_CODE_TELEGESIS,         ZBEE_MFG_TELEGESIS },
    { ZBEE_MFG_CODE_VISIONIC,          ZBEE_MFG_VISIONIC },
    { ZBEE_MFG_CODE_INSTA,             ZBEE_MFG_INSTA },
    { ZBEE_MFG_CODE_ATALUM,            ZBEE_MFG_ATALUM },
    { ZBEE_MFG_CODE_ATMEL,             ZBEE_MFG_ATMEL },
    { ZBEE_MFG_CODE_DEVELCO,           ZBEE_MFG_DEVELCO },
    { ZBEE_MFG_CODE_HONEYWELL1,        ZBEE_MFG_HONEYWELL },
    { ZBEE_MFG_CODE_RADIO_PULSE,       ZBEE_MFG_RADIO_PULSE },
    { ZBEE_MFG_CODE_RENESAS,           ZBEE_MFG_RENESAS },
    { ZBEE_MFG_CODE_XANADU,            ZBEE_MFG_XANADU },
    { ZBEE_MFG_CODE_NEC,               ZBEE_MFG_NEC },
    { ZBEE_MFG_CODE_YAMATAKE,          ZBEE_MFG_YAMATAKE },
    { ZBEE_MFG_CODE_TENDRIL,           ZBEE_MFG_TENDRIL },
    { ZBEE_MFG_CODE_ASSA,              ZBEE_MFG_ASSA },
    { ZBEE_MFG_CODE_MAXSTREAM,         ZBEE_MFG_MAXSTREAM },
    { ZBEE_MFG_CODE_NEUROCOM,          ZBEE_MFG_NEUROCOM },
    { ZBEE_MFG_CODE_III,               ZBEE_MFG_III },
    { ZBEE_MFG_CODE_VANTAGE,           ZBEE_MFG_VANTAGE },
    { ZBEE_MFG_CODE_ICONTROL,          ZBEE_MFG_ICONTROL },
    { ZBEE_MFG_CODE_RAYMARINE,         ZBEE_MFG_RAYMARINE },
    { ZBEE_MFG_CODE_LSR,               ZBEE_MFG_LSR },
    { ZBEE_MFG_CODE_ONITY,             ZBEE_MFG_ONITY },
    { ZBEE_MFG_CODE_MONO,              ZBEE_MFG_MONO },
    { ZBEE_MFG_CODE_RFT,               ZBEE_MFG_RFT },
    { ZBEE_MFG_CODE_ITRON,             ZBEE_MFG_ITRON },
    { ZBEE_MFG_CODE_TRITECH,           ZBEE_MFG_TRITECH },
    { ZBEE_MFG_CODE_EMBEDIT,           ZBEE_MFG_EMBEDIT },
    { ZBEE_MFG_CODE_S3C,               ZBEE_MFG_S3C },
    { ZBEE_MFG_CODE_SIEMENS,           ZBEE_MFG_SIEMENS },
    { ZBEE_MFG_CODE_MINDTECH,          ZBEE_MFG_MINDTECH },
    { ZBEE_MFG_CODE_LGE,               ZBEE_MFG_LGE },
    { ZBEE_MFG_CODE_MITSUBISHI,        ZBEE_MFG_MITSUBISHI },
    { ZBEE_MFG_CODE_JOHNSON,           ZBEE_MFG_JOHNSON },
    { ZBEE_MFG_CODE_PRI,               ZBEE_MFG_PRI },
    { ZBEE_MFG_CODE_KNICK,             ZBEE_MFG_KNICK },
    { ZBEE_MFG_CODE_VICONICS,          ZBEE_MFG_VICONICS },
    { ZBEE_MFG_CODE_FLEXIPANEL,        ZBEE_MFG_FLEXIPANEL },
    { ZBEE_MFG_CODE_PIASIM,            ZBEE_MFG_PIASIM },
    { ZBEE_MFG_CODE_TRANE,             ZBEE_MFG_TRANE },
    { ZBEE_MFG_CODE_JENNIC,            ZBEE_MFG_JENNIC },
    { ZBEE_MFG_CODE_LIG,               ZBEE_MFG_LIG },
    { ZBEE_MFG_CODE_ALERTME,           ZBEE_MFG_ALERTME },
    { ZBEE_MFG_CODE_DAINTREE,          ZBEE_MFG_DAINTREE },
    { ZBEE_MFG_CODE_AIJI,              ZBEE_MFG_AIJI },
    { ZBEE_MFG_CODE_TEL_ITALIA,        ZBEE_MFG_TEL_ITALIA },
    { ZBEE_MFG_CODE_MIKROKRETS,        ZBEE_MFG_MIKROKRETS },
    { ZBEE_MFG_CODE_OKI_SEMI,          ZBEE_MFG_OKI_SEMI },
    { ZBEE_MFG_CODE_NEWPORT,           ZBEE_MFG_NEWPORT },
    { ZBEE_MFG_CODE_C4,                ZBEE_MFG_C4 },
    { ZBEE_MFG_CODE_STM,               ZBEE_MFG_STM },
    { ZBEE_MFG_CODE_ASN,               ZBEE_MFG_ASN },
    { ZBEE_MFG_CODE_DCSI,              ZBEE_MFG_DCSI },
    { ZBEE_MFG_CODE_FRANCE_TEL,        ZBEE_MFG_FRANCE_TEL },
    { ZBEE_MFG_CODE_MUNET,             ZBEE_MFG_MUNET },
    { ZBEE_MFG_CODE_AUTANI,            ZBEE_MFG_AUTANI },
    { ZBEE_MFG_CODE_COL_VNET,          ZBEE_MFG_COL_VNET },
    { ZBEE_MFG_CODE_AEROCOMM,          ZBEE_MFG_AEROCOMM },
    { ZBEE_MFG_CODE_SI_LABS,           ZBEE_MFG_SI_LABS },
    { ZBEE_MFG_CODE_INNCOM,            ZBEE_MFG_INNCOM },
    { ZBEE_MFG_CODE_CANNON,            ZBEE_MFG_CANNON },
    { ZBEE_MFG_CODE_SYNAPSE,           ZBEE_MFG_SYNAPSE },
    { ZBEE_MFG_CODE_FPS,               ZBEE_MFG_FPS },
    { ZBEE_MFG_CODE_CLS,               ZBEE_MFG_CLS },
    { ZBEE_MFG_CODE_CRANE,             ZBEE_MFG_CRANE },
    { ZBEE_MFG_CODE_MOBILARM,          ZBEE_MFG_MOBILARM },
    { ZBEE_MFG_CODE_IMONITOR,          ZBEE_MFG_IMONITOR },
    { ZBEE_MFG_CODE_BARTECH,           ZBEE_MFG_BARTECH },
    { ZBEE_MFG_CODE_MESHNETICS,        ZBEE_MFG_MESHNETICS },
    { ZBEE_MFG_CODE_LS_IND,            ZBEE_MFG_LS_IND },
    { ZBEE_MFG_CODE_CASON,             ZBEE_MFG_CASON },
    { ZBEE_MFG_CODE_WLESS_GLUE,        ZBEE_MFG_WLESS_GLUE },
    { ZBEE_MFG_CODE_ELSTER,            ZBEE_MFG_ELSTER },
    { ZBEE_MFG_CODE_SMS_TEC,           ZBEE_MFG_SMS_TEC },
    { ZBEE_MFG_CODE_ONSET,             ZBEE_MFG_ONSET },
    { ZBEE_MFG_CODE_RIGA,              ZBEE_MFG_RIGA },
    { ZBEE_MFG_CODE_ENERGATE,          ZBEE_MFG_ENERGATE },
    { ZBEE_MFG_CODE_CONMED,            ZBEE_MFG_CONMED },
    { ZBEE_MFG_CODE_POWERMAND,         ZBEE_MFG_POWERMAND },
    { ZBEE_MFG_CODE_SCHNEIDER,         ZBEE_MFG_SCHNEIDER },
    { ZBEE_MFG_CODE_EATON,             ZBEE_MFG_EATON },
    { ZBEE_MFG_CODE_TELULAR,           ZBEE_MFG_TELULAR },
    { ZBEE_MFG_CODE_DELPHI,            ZBEE_MFG_DELPHI },
    { ZBEE_MFG_CODE_EPISENSOR,         ZBEE_MFG_EPISENSOR },
    { ZBEE_MFG_CODE_LANDIS_GYR,        ZBEE_MFG_LANDIS_GYR },
    { ZBEE_MFG_CODE_KABA,              ZBEE_MFG_KABA },
    { ZBEE_MFG_CODE_SHURE,             ZBEE_MFG_SHURE },
    { ZBEE_MFG_CODE_COMVERGE,          ZBEE_MFG_COMVERGE },
    { ZBEE_MFG_CODE_DBS_LODGING,       ZBEE_MFG_DBS_LODGING },
    { ZBEE_MFG_CODE_ENERGY_AWARE,      ZBEE_MFG_ENERGY_AWARE },
    { ZBEE_MFG_CODE_HIDALGO,           ZBEE_MFG_HIDALGO },
    { ZBEE_MFG_CODE_AIR2APP,           ZBEE_MFG_AIR2APP },
    { ZBEE_MFG_CODE_AMX,               ZBEE_MFG_AMX },
    { ZBEE_MFG_CODE_EDMI,              ZBEE_MFG_EDMI },
    { ZBEE_MFG_CODE_CYAN,              ZBEE_MFG_CYAN },
    { ZBEE_MFG_CODE_SYS_SPA,           ZBEE_MFG_SYS_SPA },
    { ZBEE_MFG_CODE_TELIT,             ZBEE_MFG_TELIT },
    { ZBEE_MFG_CODE_KAGA,              ZBEE_MFG_KAGA },
    { ZBEE_MFG_CODE_4_NOKS,            ZBEE_MFG_4_NOKS },
    { ZBEE_MFG_CODE_CERTICOM,          ZBEE_MFG_CERTICOM },
    { ZBEE_MFG_CODE_GRIDPOINT,         ZBEE_MFG_GRIDPOINT },
    { ZBEE_MFG_CODE_PROFILE_SYS,       ZBEE_MFG_PROFILE_SYS },
    { ZBEE_MFG_CODE_COMPACTA,          ZBEE_MFG_COMPACTA },
    { ZBEE_MFG_CODE_FREESTYLE,         ZBEE_MFG_FREESTYLE },
    { ZBEE_MFG_CODE_ALEKTRONA,         ZBEE_MFG_ALEKTRONA },
    { ZBEE_MFG_CODE_COMPUTIME,         ZBEE_MFG_COMPUTIME },
    { ZBEE_MFG_CODE_REMOTE_TECH,       ZBEE_MFG_REMOTE_TECH },
    { ZBEE_MFG_CODE_WAVECOM,           ZBEE_MFG_WAVECOM },
    { ZBEE_MFG_CODE_ENERGY,            ZBEE_MFG_ENERGY },
    { ZBEE_MFG_CODE_GE,                ZBEE_MFG_GE },
    { ZBEE_MFG_CODE_JETLUN,            ZBEE_MFG_JETLUN },
    { ZBEE_MFG_CODE_CIPHER,            ZBEE_MFG_CIPHER },
    { ZBEE_MFG_CODE_CORPORATE,         ZBEE_MFG_CORPORATE },
    { ZBEE_MFG_CODE_ECOBEE,            ZBEE_MFG_ECOBEE },
    { ZBEE_MFG_CODE_SMK,               ZBEE_MFG_SMK },
    { ZBEE_MFG_CODE_MESHWORKS,         ZBEE_MFG_MESHWORKS },
    { ZBEE_MFG_CODE_ELLIPS,            ZBEE_MFG_ELLIPS },
    { ZBEE_MFG_CODE_SECURE,            ZBEE_MFG_SECURE },
    { ZBEE_MFG_CODE_CEDO,              ZBEE_MFG_CEDO },
    { ZBEE_MFG_CODE_TOSHIBA,           ZBEE_MFG_TOSHIBA },
    { ZBEE_MFG_CODE_DIGI,              ZBEE_MFG_DIGI },
    { ZBEE_MFG_CODE_UBILOGIX,          ZBEE_MFG_UBILOGIX },
    { ZBEE_MFG_CODE_ECHELON,           ZBEE_MFG_ECHELON },
    { ZBEE_MFG_CODE_GREEN_ENERGY,      ZBEE_MFG_GREEN_ENERGY },
    { ZBEE_MFG_CODE_SILVER_SPRING,     ZBEE_MFG_SILVER_SPRING },
    { ZBEE_MFG_CODE_BLACK,             ZBEE_MFG_BLACK },
    { ZBEE_MFG_CODE_AZTECH_ASSOC,      ZBEE_MFG_AZTECH_ASSOC },
    { ZBEE_MFG_CODE_A_AND_D,           ZBEE_MFG_A_AND_D },
    { ZBEE_MFG_CODE_RAINFOREST,        ZBEE_MFG_RAINFOREST },
    { ZBEE_MFG_CODE_CARRIER,           ZBEE_MFG_CARRIER },
    { ZBEE_MFG_CODE_SYCHIP,            ZBEE_MFG_SYCHIP },
    { ZBEE_MFG_CODE_OPEN_PEAK,         ZBEE_MFG_OPEN_PEAK },
    { ZBEE_MFG_CODE_PASSIVE,           ZBEE_MFG_PASSIVE },
    { ZBEE_MFG_CODE_MMB,               ZBEE_MFG_MMB },
    { ZBEE_MFG_CODE_LEVITON,           ZBEE_MFG_LEVITON },
    { ZBEE_MFG_CODE_KOREA_ELEC,        ZBEE_MFG_KOREA_ELEC },
    { ZBEE_MFG_CODE_COMCAST1,          ZBEE_MFG_COMCAST },
    { ZBEE_MFG_CODE_NEC_ELEC,          ZBEE_MFG_NEC_ELEC },
    { ZBEE_MFG_CODE_NETVOX,            ZBEE_MFG_NETVOX },
    { ZBEE_MFG_CODE_UCONTROL,          ZBEE_MFG_UCONTROL },
    { ZBEE_MFG_CODE_EMBEDIA,           ZBEE_MFG_EMBEDIA },
    { ZBEE_MFG_CODE_SENSUS,            ZBEE_MFG_SENSUS },
    { ZBEE_MFG_CODE_SUNRISE,           ZBEE_MFG_SUNRISE },
    { ZBEE_MFG_CODE_MEMTECH,           ZBEE_MFG_MEMTECH },
    { ZBEE_MFG_CODE_FREEBOX,           ZBEE_MFG_FREEBOX },
    { ZBEE_MFG_CODE_M2_LABS,           ZBEE_MFG_M2_LABS },
    { ZBEE_MFG_CODE_BRITISH_GAS,       ZBEE_MFG_BRITISH_GAS },
    { ZBEE_MFG_CODE_SENTEC,            ZBEE_MFG_SENTEC },
    { ZBEE_MFG_CODE_NAVETAS,           ZBEE_MFG_NAVETAS },
    { ZBEE_MFG_CODE_LIGHTSPEED,        ZBEE_MFG_LIGHTSPEED },
    { ZBEE_MFG_CODE_OKI,               ZBEE_MFG_OKI },
    { ZBEE_MFG_CODE_SISTEMAS,          ZBEE_MFG_SISTEMAS },
    { ZBEE_MFG_CODE_DOMETIC,           ZBEE_MFG_DOMETIC },
    { ZBEE_MFG_CODE_APLS,              ZBEE_MFG_APLS },
    { ZBEE_MFG_CODE_ENERGY_HUB,        ZBEE_MFG_ENERGY_HUB },
    { ZBEE_MFG_CODE_KAMSTRUP,          ZBEE_MFG_KAMSTRUP },
    { ZBEE_MFG_CODE_ECHOSTAR,          ZBEE_MFG_ECHOSTAR },
    { ZBEE_MFG_CODE_ENERNOC,           ZBEE_MFG_ENERNOC },
    { ZBEE_MFG_CODE_ELTAV,             ZBEE_MFG_ELTAV },
    { ZBEE_MFG_CODE_BELKIN,            ZBEE_MFG_BELKIN },
    { ZBEE_MFG_CODE_XSTREAMHD,         ZBEE_MFG_XSTREAMHD },
    { ZBEE_MFG_CODE_SATURN_SOUTH,      ZBEE_MFG_SATURN_SOUTH },
    { ZBEE_MFG_CODE_GREENTRAP,         ZBEE_MFG_GREENTRAP },
    { ZBEE_MFG_CODE_SMARTSYNCH,        ZBEE_MFG_SMARTSYNCH },
    { ZBEE_MFG_CODE_NYCE,              ZBEE_MFG_NYCE },
    { ZBEE_MFG_CODE_ICM_CONTROLS,      ZBEE_MFG_ICM_CONTROLS },
    { ZBEE_MFG_CODE_MILLENNIUM,        ZBEE_MFG_MILLENNIUM },
    { ZBEE_MFG_CODE_MOTOROLA,          ZBEE_MFG_MOTOROLA },
    { ZBEE_MFG_CODE_EMERSON,           ZBEE_MFG_EMERSON },
    { ZBEE_MFG_CODE_RADIO_THERMOSTAT,  ZBEE_MFG_RADIO_THERMOSTAT },
    { ZBEE_MFG_CODE_OMRON,             ZBEE_MFG_OMRON },
    { ZBEE_MFG_CODE_GIINII,            ZBEE_MFG_GIINII },
    { ZBEE_MFG_CODE_FUJITSU,           ZBEE_MFG_FUJITSU },
    { ZBEE_MFG_CODE_PEEL,              ZBEE_MFG_PEEL },
    { ZBEE_MFG_CODE_ACCENT,            ZBEE_MFG_ACCENT },
    { ZBEE_MFG_CODE_BYTESNAP,          ZBEE_MFG_BYTESNAP },
    { ZBEE_MFG_CODE_NEC_TOKIN,         ZBEE_MFG_NEC_TOKIN },
    { ZBEE_MFG_CODE_G4S_JUSTICE,       ZBEE_MFG_G4S_JUSTICE },
    { ZBEE_MFG_CODE_TRILLIANT,         ZBEE_MFG_TRILLIANT },
    { ZBEE_MFG_CODE_ELECTROLUX,        ZBEE_MFG_ELECTROLUX },
    { ZBEE_MFG_CODE_ONZO,              ZBEE_MFG_ONZO },
    { ZBEE_MFG_CODE_ENTEK,             ZBEE_MFG_ENTEK },
    { ZBEE_MFG_CODE_PHILIPS2,          ZBEE_MFG_PHILIPS },
    { ZBEE_MFG_CODE_MAINSTREAM,        ZBEE_MFG_MAINSTREAM },
    { ZBEE_MFG_CODE_INDESIT,           ZBEE_MFG_INDESIT },
    { ZBEE_MFG_CODE_THINKECO,          ZBEE_MFG_THINKECO },
    { ZBEE_MFG_CODE_2D2C,              ZBEE_MFG_2D2C },
    { ZBEE_MFG_CODE_GREENPEAK,         ZBEE_MFG_GREENPEAK },
    { ZBEE_MFG_CODE_INTERCEL,          ZBEE_MFG_INTERCEL },
    { ZBEE_MFG_CODE_LG,                ZBEE_MFG_LG },
    { ZBEE_MFG_CODE_MITSUMI1,          ZBEE_MFG_MITSUMI1 },
    { ZBEE_MFG_CODE_MITSUMI2,          ZBEE_MFG_MITSUMI2 },
    { ZBEE_MFG_CODE_ZENTRUM,           ZBEE_MFG_ZENTRUM },
    { ZBEE_MFG_CODE_NEST,              ZBEE_MFG_NEST },
    { ZBEE_MFG_CODE_EXEGIN,            ZBEE_MFG_EXEGIN },
    { ZBEE_MFG_CODE_HONEYWELL2,        ZBEE_MFG_HONEYWELL },
    { ZBEE_MFG_CODE_TAKAHATA,          ZBEE_MFG_TAKAHATA },
    { ZBEE_MFG_CODE_SUMITOMO,          ZBEE_MFG_SUMITOMO },
    { ZBEE_MFG_CODE_GE_ENERGY,         ZBEE_MFG_GE_ENERGY },
    { ZBEE_MFG_CODE_GE_APPLIANCES,     ZBEE_MFG_GE_APPLIANCES },
    { ZBEE_MFG_CODE_RADIOCRAFTS,       ZBEE_MFG_RADIOCRAFTS },
    { ZBEE_MFG_CODE_CEIVA,             ZBEE_MFG_CEIVA },
    { ZBEE_MFG_CODE_TEC_CO,            ZBEE_MFG_TEC_CO },
    { ZBEE_MFG_CODE_CHAMELEON,         ZBEE_MFG_CHAMELEON },
    { ZBEE_MFG_CODE_SAMSUNG,           ZBEE_MFG_SAMSUNG },
    { ZBEE_MFG_CODE_RUWIDO,            ZBEE_MFG_RUWIDO },
    { ZBEE_MFG_CODE_HUAWEI_1,          ZBEE_MFG_HUAWEI },
    { ZBEE_MFG_CODE_HUAWEI_2,          ZBEE_MFG_HUAWEI },
    { ZBEE_MFG_CODE_GREENWAVE,         ZBEE_MFG_GREENWAVE },
    { ZBEE_MFG_CODE_BGLOBAL,           ZBEE_MFG_BGLOBAL },
    { ZBEE_MFG_CODE_MINDTECK,          ZBEE_MFG_MINDTECK },
    { ZBEE_MFG_CODE_INGERSOLL_RAND,    ZBEE_MFG_INGERSOLL_RAND },
    { ZBEE_MFG_CODE_DIUS,              ZBEE_MFG_DIUS },
    { ZBEE_MFG_CODE_EMBEDDED,          ZBEE_MFG_EMBEDDED },
    { ZBEE_MFG_CODE_ABB,               ZBEE_MFG_ABB },
    { ZBEE_MFG_CODE_SONY,              ZBEE_MFG_SONY },
    { ZBEE_MFG_CODE_GENUS,             ZBEE_MFG_GENUS },
    { ZBEE_MFG_CODE_UNIVERSAL1,        ZBEE_MFG_UNIVERSAL },
    { ZBEE_MFG_CODE_UNIVERSAL2,        ZBEE_MFG_UNIVERSAL },
    { ZBEE_MFG_CODE_METRUM,            ZBEE_MFG_METRUM },
    { ZBEE_MFG_CODE_CISCO,             ZBEE_MFG_CISCO },
    { ZBEE_MFG_CODE_UBISYS,            ZBEE_MFG_UBISYS },
    { ZBEE_MFG_CODE_CONSERT,           ZBEE_MFG_CONSERT },
    { ZBEE_MFG_CODE_CRESTRON,          ZBEE_MFG_CRESTRON },
    { ZBEE_MFG_CODE_ENPHASE,           ZBEE_MFG_ENPHASE },
    { ZBEE_MFG_CODE_INVENSYS,          ZBEE_MFG_INVENSYS },
    { ZBEE_MFG_CODE_MUELLER,           ZBEE_MFG_MUELLER },
    { ZBEE_MFG_CODE_AAC_TECH,          ZBEE_MFG_AAC_TECH },
    { ZBEE_MFG_CODE_U_NEXT,            ZBEE_MFG_U_NEXT },
    { ZBEE_MFG_CODE_STEELCASE,         ZBEE_MFG_STEELCASE },
    { ZBEE_MFG_CODE_TELEMATICS,        ZBEE_MFG_TELEMATICS },
    { ZBEE_MFG_CODE_SAMIL,             ZBEE_MFG_SAMIL },
    { ZBEE_MFG_CODE_PACE,              ZBEE_MFG_PACE },
    { ZBEE_MFG_CODE_OSBORNE,           ZBEE_MFG_OSBORNE },
    { ZBEE_MFG_CODE_POWERWATCH,        ZBEE_MFG_POWERWATCH },
    { ZBEE_MFG_CODE_CANDELED,          ZBEE_MFG_CANDELED },
    { ZBEE_MFG_CODE_FLEXGRID,          ZBEE_MFG_FLEXGRID },
    { ZBEE_MFG_CODE_HUMAX,             ZBEE_MFG_HUMAX },
    { ZBEE_MFG_CODE_UNIVERSAL,         ZBEE_MFG_UNIVERSAL },
    { ZBEE_MFG_CODE_ADVANCED_ENERGY,   ZBEE_MFG_ADVANCED_ENERGY },
    { ZBEE_MFG_CODE_BEGA,              ZBEE_MFG_BEGA },
    { ZBEE_MFG_CODE_BRUNEL,            ZBEE_MFG_BRUNEL },
    { ZBEE_MFG_CODE_PANASONIC,         ZBEE_MFG_PANASONIC },
    { ZBEE_MFG_CODE_ESYSTEMS,          ZBEE_MFG_ESYSTEMS },
    { ZBEE_MFG_CODE_PANAMAX,           ZBEE_MFG_PANAMAX },
    { ZBEE_MFG_CODE_PHYSICAL,          ZBEE_MFG_PHYSICAL },
    { ZBEE_MFG_CODE_EM_LITE,           ZBEE_MFG_EM_LITE },
    { ZBEE_MFG_CODE_OSRAM,             ZBEE_MFG_OSRAM },
    { ZBEE_MFG_CODE_2_SAVE,            ZBEE_MFG_2_SAVE },
    { ZBEE_MFG_CODE_PLANET,            ZBEE_MFG_PLANET },
    { ZBEE_MFG_CODE_AMBIENT,           ZBEE_MFG_AMBIENT },
    { ZBEE_MFG_CODE_PROFALUX,          ZBEE_MFG_PROFALUX },
    { ZBEE_MFG_CODE_BILLION,           ZBEE_MFG_BILLION },
    { ZBEE_MFG_CODE_EMBERTEC,          ZBEE_MFG_EMBERTEC },
    { ZBEE_MFG_CODE_IT_WATCHDOGS,      ZBEE_MFG_IT_WATCHDOGS },
    { ZBEE_MFG_CODE_RELOC,             ZBEE_MFG_RELOC },
    { ZBEE_MFG_CODE_INTEL,             ZBEE_MFG_INTEL },
    { ZBEE_MFG_CODE_TREND,             ZBEE_MFG_TREND },
    { ZBEE_MFG_CODE_MOXA,              ZBEE_MFG_MOXA },
    { ZBEE_MFG_CODE_QEES,              ZBEE_MFG_QEES },
    { ZBEE_MFG_CODE_SAYME,             ZBEE_MFG_SAYME },
    { ZBEE_MFG_CODE_PENTAIR,           ZBEE_MFG_PENTAIR },
    { ZBEE_MFG_CODE_ORBIT,             ZBEE_MFG_ORBIT },
    { ZBEE_MFG_CODE_CALIFORNIA,        ZBEE_MFG_CALIFORNIA },
    { ZBEE_MFG_CODE_COMCAST2,          ZBEE_MFG_COMCAST },
    { ZBEE_MFG_CODE_IDT,               ZBEE_MFG_IDT },
    { ZBEE_MFG_CODE_PIXELA,            ZBEE_MFG_PIXELA },
    { ZBEE_MFG_CODE_TIVO,              ZBEE_MFG_TIVO },
    { ZBEE_MFG_CODE_FIDURE,            ZBEE_MFG_FIDURE },
    { ZBEE_MFG_CODE_MARVELL,           ZBEE_MFG_MARVELL },
    { ZBEE_MFG_CODE_WASION,            ZBEE_MFG_WASION },
    { ZBEE_MFG_CODE_JASCO,             ZBEE_MFG_JASCO },
    { ZBEE_MFG_CODE_SHENZHEN,          ZBEE_MFG_SHENZHEN },
    { ZBEE_MFG_CODE_NETCOMM,           ZBEE_MFG_NETCOMM },
    { ZBEE_MFG_CODE_DEFINE,            ZBEE_MFG_DEFINE },
    { ZBEE_MFG_CODE_IN_HOME_DISP,      ZBEE_MFG_IN_HOME_DISP },
    { ZBEE_MFG_CODE_MIELE,             ZBEE_MFG_MIELE },
    { ZBEE_MFG_CODE_TELEVES,           ZBEE_MFG_TELEVES },
    { ZBEE_MFG_CODE_LABELEC,           ZBEE_MFG_LABELEC },
    { ZBEE_MFG_CODE_CHINA_ELEC,        ZBEE_MFG_CHINA_ELEC },
    { ZBEE_MFG_CODE_VECTORFORM,        ZBEE_MFG_VECTORFORM },
    { ZBEE_MFG_CODE_BUSCH_JAEGER,      ZBEE_MFG_BUSCH_JAEGER },
    { ZBEE_MFG_CODE_REDPINE,           ZBEE_MFG_REDPINE },
    { ZBEE_MFG_CODE_BRIDGES,           ZBEE_MFG_BRIDGES },
    { ZBEE_MFG_CODE_SERCOMM,           ZBEE_MFG_SERCOMM },
    { ZBEE_MFG_CODE_WSH,               ZBEE_MFG_WSH },
    { ZBEE_MFG_CODE_BOSCH,             ZBEE_MFG_BOSCH },
    { ZBEE_MFG_CODE_EZEX,              ZBEE_MFG_EZEX },
    { ZBEE_MFG_CODE_DRESDEN,           ZBEE_MFG_DRESDEN },
    { ZBEE_MFG_CODE_MEAZON,            ZBEE_MFG_MEAZON },
    { ZBEE_MFG_CODE_CROW,              ZBEE_MFG_CROW },
    { ZBEE_MFG_CODE_HARVARD,           ZBEE_MFG_HARVARD },
    { ZBEE_MFG_CODE_ANDSON,            ZBEE_MFG_ANDSON },
    { ZBEE_MFG_CODE_ADHOCO,            ZBEE_MFG_ADHOCO },
    { ZBEE_MFG_CODE_WAXMAN,            ZBEE_MFG_WAXMAN },
    { ZBEE_MFG_CODE_OWON,              ZBEE_MFG_OWON },
    { ZBEE_MFG_CODE_HITRON,            ZBEE_MFG_HITRON },
    { ZBEE_MFG_CODE_SCEMTEC,           ZBEE_MFG_SCEMTEC },
    { ZBEE_MFG_CODE_WEBEE,             ZBEE_MFG_WEBEE },
    { ZBEE_MFG_CODE_GRID2HOME,         ZBEE_MFG_GRID2HOME },
    { ZBEE_MFG_CODE_TELINK,            ZBEE_MFG_TELINK },
    { ZBEE_MFG_CODE_JASMINE,           ZBEE_MFG_JASMINE },
    { ZBEE_MFG_CODE_BIDGELY,           ZBEE_MFG_BIDGELY },
    { ZBEE_MFG_CODE_LUTRON,            ZBEE_MFG_LUTRON },
    { ZBEE_MFG_CODE_IJENKO,            ZBEE_MFG_IJENKO },
    { ZBEE_MFG_CODE_STARFIELD,         ZBEE_MFG_STARFIELD },
    { ZBEE_MFG_CODE_TCP,               ZBEE_MFG_TCP },
    { ZBEE_MFG_CODE_ROGERS,            ZBEE_MFG_ROGERS },
    { ZBEE_MFG_CODE_CREE,              ZBEE_MFG_CREE },
    { ZBEE_MFG_CODE_ROBERT_BOSCH_LLC,  ZBEE_MFG_ROBERT_BOSCH_LLC },
    { ZBEE_MFG_CODE_IBIS,              ZBEE_MFG_IBIS },
    { ZBEE_MFG_CODE_QUIRKY,            ZBEE_MFG_QUIRKY },
    { ZBEE_MFG_CODE_EFERGY,            ZBEE_MFG_EFERGY },
    { ZBEE_MFG_CODE_SMARTLABS,         ZBEE_MFG_SMARTLABS },
    { ZBEE_MFG_CODE_EVERSPRING,        ZBEE_MFG_EVERSPRING },
    { ZBEE_MFG_CODE_SWANN,             ZBEE_MFG_SWANN },
    { ZBEE_MFG_CODE_SONETER,           ZBEE_MFG_SONETER },
    { ZBEE_MFG_CODE_SAMSUNG_SDS,       ZBEE_MFG_SAMSUNG_SDS },
    { ZBEE_MFG_CODE_UNIBAND_ELECTRO,   ZBEE_MFG_UNIBAND_ELECTRO },
    { ZBEE_MFG_CODE_ACCTON_TECHNOLOGY, ZBEE_MFG_ACCTON_TECHNOLOGY },
    { ZBEE_MFG_CODE_BOSCH_THERMOTECH,  ZBEE_MFG_BOSCH_THERMOTECH },
    { ZBEE_MFG_CODE_WINCOR_NIXDORF,    ZBEE_MFG_WINCOR_NIXDORF },
    { ZBEE_MFG_CODE_OHSUNG_ELECTRO,    ZBEE_MFG_OHSUNG_ELECTRO },
    { ZBEE_MFG_CODE_ZEN_WITHIN,        ZBEE_MFG_ZEN_WITHIN },
    { ZBEE_MFG_CODE_TECH_4_HOME,       ZBEE_MFG_TECH_4_HOME },
    { ZBEE_MFG_CODE_NANOLEAF,          ZBEE_MFG_NANOLEAF },
    { ZBEE_MFG_CODE_KEEN_HOME,         ZBEE_MFG_KEEN_HOME },
    { ZBEE_MFG_CODE_POLY_CONTROL,      ZBEE_MFG_POLY_CONTROL },
    { ZBEE_MFG_CODE_EASTFIELD_LIGHT,   ZBEE_MFG_EASTFIELD_LIGHT },
    { ZBEE_MFG_CODE_IP_DATATEL,        ZBEE_MFG_IP_DATATEL },
    { ZBEE_MFG_CODE_LUMI_UNITED_TECH,  ZBEE_MFG_LUMI_UNITED_TECH },
    { ZBEE_MFG_CODE_SENGLED_OPTOELEC,  ZBEE_MFG_SENGLED_OPTOELEC },
    { ZBEE_MFG_CODE_REMOTE_SOLUTION,   ZBEE_MFG_REMOTE_SOLUTION },
    { ZBEE_MFG_CODE_ABB_GENWAY_XIAMEN, ZBEE_MFG_ABB_GENWAY_XIAMEN },
    { ZBEE_MFG_CODE_ZHEJIANG_REXENSE,  ZBEE_MFG_ZHEJIANG_REXENSE },
    { ZBEE_MFG_CODE_FOREE_TECHNOLOGY,  ZBEE_MFG_FOREE_TECHNOLOGY },
    { ZBEE_MFG_CODE_OPEN_ACCESS_TECH,  ZBEE_MFG_OPEN_ACCESS_TECH },
    { ZBEE_MFG_CODE_INNR_LIGHTNING,    ZBEE_MFG_INNR_LIGHTNING },
    { ZBEE_MFG_CODE_TECHWORLD,         ZBEE_MFG_TECHWORLD },
    { ZBEE_MFG_CODE_LEEDARSON_LIGHT,   ZBEE_MFG_LEEDARSON_LIGHT },
    { ZBEE_MFG_CODE_ARZEL_ZONING,      ZBEE_MFG_ARZEL_ZONING },
    { ZBEE_MFG_CODE_HOLLEY_TECH,       ZBEE_MFG_HOLLEY_TECH },
    { ZBEE_MFG_CODE_BELDON_TECH,       ZBEE_MFG_BELDON_TECH },
    { ZBEE_MFG_CODE_FLEXTRONICS,       ZBEE_MFG_FLEXTRONICS },
    { ZBEE_MFG_CODE_SHENZHEN_MEIAN,    ZBEE_MFG_SHENZHEN_MEIAN },
    { ZBEE_MFG_CODE_LOWES,             ZBEE_MFG_LOWES },
    { ZBEE_MFG_CODE_SIGMA_CONNECT,     ZBEE_MFG_SIGMA_CONNECT },
    { ZBEE_MFG_CODE_WULIAN,            ZBEE_MFG_WULIAN },
    { ZBEE_MFG_CODE_PLUGWISE_BV,       ZBEE_MFG_PLUGWISE_BV },
    { ZBEE_MFG_CODE_TITAN_PRODUCTS,    ZBEE_MFG_TITAN_PRODUCTS },
    { ZBEE_MFG_CODE_ECOSPECTRAL,       ZBEE_MFG_ECOSPECTRAL },
    { ZBEE_MFG_CODE_D_LINK,            ZBEE_MFG_D_LINK },
    { ZBEE_MFG_CODE_TECHNICOLOR_HOME,  ZBEE_MFG_TECHNICOLOR_HOME },
    { ZBEE_MFG_CODE_OPPLE_LIGHTING,    ZBEE_MFG_OPPLE_LIGHTING },
    { ZBEE_MFG_CODE_WISTRON_NEWEB,     ZBEE_MFG_WISTRON_NEWEB },
    { ZBEE_MFG_CODE_QMOTION_SHADES,    ZBEE_MFG_QMOTION_SHADES },
    { ZBEE_MFG_CODE_INSTA_ELEKTRO,     ZBEE_MFG_INSTA_ELEKTRO },
    { ZBEE_MFG_CODE_SHANGHAI_VANCOUNT, ZBEE_MFG_SHANGHAI_VANCOUNT },
    { ZBEE_MFG_CODE_IKEA_OF_SWEDEN,    ZBEE_MFG_IKEA_OF_SWEDEN },
    { ZBEE_MFG_CODE_RT_RK,             ZBEE_MFG_RT_RK },
    { ZBEE_MFG_CODE_SHENZHEN_FEIBIT,   ZBEE_MFG_SHENZHEN_FEIBIT },
    { ZBEE_MFG_CODE_EU_CONTROLS,       ZBEE_MFG_EU_CONTROLS },
    { ZBEE_MFG_CODE_TELKONET,          ZBEE_MFG_TELKONET },
    { ZBEE_MFG_CODE_THERMAL_SOLUTION,  ZBEE_MFG_THERMAL_SOLUTION },
    { ZBEE_MFG_CODE_POM_CUBE,          ZBEE_MFG_POM_CUBE },
    { ZBEE_MFG_CODE_EI_ELECTRONICS,    ZBEE_MFG_EI_ELECTRONICS },
    { ZBEE_MFG_CODE_OPTOGA,            ZBEE_MFG_OPTOGA },
    { ZBEE_MFG_CODE_STELPRO,           ZBEE_MFG_STELPRO },
    { ZBEE_MFG_CODE_LYNXUS_TECH,       ZBEE_MFG_LYNXUS_TECH },
    { ZBEE_MFG_CODE_SEMICONDUCTOR_COM, ZBEE_MFG_SEMICONDUCTOR_COM },
    { ZBEE_MFG_CODE_TP_LINK,           ZBEE_MFG_TP_LINK },
    { ZBEE_MFG_CODE_LEDVANCE_LLC,      ZBEE_MFG_LEDVANCE_LLC },
    { ZBEE_MFG_CODE_NORTEK,            ZBEE_MFG_NORTEK },
    { ZBEE_MFG_CODE_IREVO_ASSA_ABBLOY, ZBEE_MFG_IREVO_ASSA_ABBLOY },
    { ZBEE_MFG_CODE_MIDEA,             ZBEE_MFG_MIDEA },
    { ZBEE_MFG_CODE_ZF_FRIEDRICHSHAF,  ZBEE_MFG_ZF_FRIEDRICHSHAF },
    { ZBEE_MFG_CODE_CHECKIT,           ZBEE_MFG_CHECKIT },
    { ZBEE_MFG_CODE_ACLARA,            ZBEE_MFG_ACLARA },
    { ZBEE_MFG_CODE_NOKIA,             ZBEE_MFG_NOKIA },
    { ZBEE_MFG_CODE_GOLDCARD_HIGHTECH, ZBEE_MFG_GOLDCARD_HIGHTECH },
    { ZBEE_MFG_CODE_GEORGE_WILSON,     ZBEE_MFG_GEORGE_WILSON },
    { ZBEE_MFG_CODE_EASY_SAVER_CO,     ZBEE_MFG_EASY_SAVER_CO },
    { ZBEE_MFG_CODE_ZTE_CORPORATION,   ZBEE_MFG_ZTE_CORPORATION },
    { ZBEE_MFG_CODE_ARRIS,             ZBEE_MFG_ARRIS },
    { ZBEE_MFG_CODE_RELIANCE_BIG_TV,   ZBEE_MFG_RELIANCE_BIG_TV },
    { ZBEE_MFG_CODE_INSIGHT_ENERGY,    ZBEE_MFG_INSIGHT_ENERGY },
    { ZBEE_MFG_CODE_THOMAS_RESEARCH,   ZBEE_MFG_THOMAS_RESEARCH },
    { ZBEE_MFG_CODE_LI_SENG_TECH,      ZBEE_MFG_LI_SENG_TECH },
    { ZBEE_MFG_CODE_SYSTEM_LEVEL_SOLU, ZBEE_MFG_SYSTEM_LEVEL_SOLU },
    { ZBEE_MFG_CODE_MATRIX_LABS,       ZBEE_MFG_MATRIX_LABS },
    { ZBEE_MFG_CODE_SINOPE_TECH,       ZBEE_MFG_SINOPE_TECH },
    { ZBEE_MFG_CODE_JIUZHOU_GREEBLE,   ZBEE_MFG_JIUZHOU_GREEBLE },
    { ZBEE_MFG_CODE_GUANGZHOU_LANVEE,  ZBEE_MFG_GUANGZHOU_LANVEE },
    { ZBEE_MFG_CODE_VENSTAR,           ZBEE_MFG_VENSTAR },
    { ZBEE_MFG_CODE_SLV,               ZBEE_MFG_SLV },
    { ZBEE_MFG_CODE_HALO_SMART_LABS,   ZBEE_MFG_HALO_SMART_LABS },
    { ZBEE_MFG_CODE_SCOUT_SECURITY,    ZBEE_MFG_SCOUT_SECURITY },
    { ZBEE_MFG_CODE_ALIBABA_CHINA,     ZBEE_MFG_ALIBABA_CHINA },
    { ZBEE_MFG_CODE_RESOLUTION_PROD,   ZBEE_MFG_RESOLUTION_PROD },
    { ZBEE_MFG_CODE_SMARTLOK_INC,      ZBEE_MFG_SMARTLOK_INC },
    { ZBEE_MFG_CODE_LUX_PRODUCTS_CORP, ZBEE_MFG_LUX_PRODUCTS_CORP },
    { ZBEE_MFG_CODE_VIMAR_SPA,         ZBEE_MFG_VIMAR_SPA },
    { ZBEE_MFG_CODE_UNIVERSAL_LIGHT,   ZBEE_MFG_UNIVERSAL_LIGHT },
    { ZBEE_MFG_CODE_ROBERT_BOSCH_GMBH, ZBEE_MFG_ROBERT_BOSCH_GMBH },
    { ZBEE_MFG_CODE_ACCENTURE,         ZBEE_MFG_ACCENTURE },
    { ZBEE_MFG_CODE_HEIMAN_TECHNOLOGY, ZBEE_MFG_HEIMAN_TECHNOLOGY },
    { ZBEE_MFG_CODE_SHENZHEN_HOMA,     ZBEE_MFG_SHENZHEN_HOMA },
    { ZBEE_MFG_CODE_VISION_ELECTRO,    ZBEE_MFG_VISION_ELECTRO },
    { ZBEE_MFG_CODE_LENOVO,            ZBEE_MFG_LENOVO },
    { ZBEE_MFG_CODE_PRESCIENSE_RD,     ZBEE_MFG_PRESCIENSE_RD },
    { ZBEE_MFG_CODE_SHENZHEN_SEASTAR,  ZBEE_MFG_SHENZHEN_SEASTAR },
    { ZBEE_MFG_CODE_SENSATIVE_AB,      ZBEE_MFG_SENSATIVE_AB },
    { ZBEE_MFG_CODE_SOLAREDGE,         ZBEE_MFG_SOLAREDGE },
    { ZBEE_MFG_CODE_ZIPATO,            ZBEE_MFG_ZIPATO },
    { ZBEE_MFG_CODE_CHINA_FIRE_SEC,    ZBEE_MFG_CHINA_FIRE_SEC },
    { ZBEE_MFG_CODE_QUBY_BV,           ZBEE_MFG_QUBY_BV },
    { ZBEE_MFG_CODE_HANGZHOU_ROOMBANK, ZBEE_MFG_HANGZHOU_ROOMBANK },
    { ZBEE_MFG_CODE_AMAZON_LAB126,     ZBEE_MFG_AMAZON_LAB126 },
    { ZBEE_MFG_CODE_PAULMANN_LICHT,    ZBEE_MFG_PAULMANN_LICHT },
    { ZBEE_MFG_CODE_SHENZHEN_ORVIBO,   ZBEE_MFG_SHENZHEN_ORVIBO },
    { ZBEE_MFG_CODE_TCI_TELECOMM,      ZBEE_MFG_TCI_TELECOMM },
    { ZBEE_MFG_CODE_MUELLER_LICHT_INT, ZBEE_MFG_MUELLER_LICHT_INT },
    { ZBEE_MFG_CODE_AURORA_LIMITED,    ZBEE_MFG_AURORA_LIMITED },
    { ZBEE_MFG_CODE_SMART_DCC,         ZBEE_MFG_SMART_DCC },
    { ZBEE_MFG_CODE_SHANGHAI_UMEINFO,  ZBEE_MFG_SHANGHAI_UMEINFO },
    { ZBEE_MFG_CODE_CARBON_TRACK,      ZBEE_MFG_CARBON_TRACK },
    { ZBEE_MFG_CODE_SOMFY,             ZBEE_MFG_SOMFY },
    { ZBEE_MFG_CODE_VIESSMAN_ELEKTRO,  ZBEE_MFG_VIESSMAN_ELEKTRO },
    { ZBEE_MFG_CODE_HILDEBRAND_TECH,   ZBEE_MFG_HILDEBRAND_TECH },
    { ZBEE_MFG_CODE_ONKYO_TECH,        ZBEE_MFG_ONKYO_TECH },
    { ZBEE_MFG_CODE_SHENZHEN_SUNRICH,  ZBEE_MFG_SHENZHEN_SUNRICH },
    { ZBEE_MFG_CODE_XIU_XIU_TECH,      ZBEE_MFG_XIU_XIU_TECH },
    { ZBEE_MFG_CODE_ZUMTOBEL_GROUP,    ZBEE_MFG_ZUMTOBEL_GROUP },
    { ZBEE_MFG_CODE_SHENZHEN_KAADAS,   ZBEE_MFG_SHENZHEN_KAADAS },
    { ZBEE_MFG_CODE_SHANGHAI_XIAOYAN,  ZBEE_MFG_SHANGHAI_XIAOYAN },
    { ZBEE_MFG_CODE_CYPRESS_SEMICOND,  ZBEE_MFG_CYPRESS_SEMICOND },
    { ZBEE_MFG_CODE_XAL_GMBH,          ZBEE_MFG_XAL_GMBH },
    { ZBEE_MFG_CODE_INERGY_SYSTEMS,    ZBEE_MFG_INERGY_SYSTEMS },
    { ZBEE_MFG_CODE_ALFRED_KARCHER,    ZBEE_MFG_ALFRED_KARCHER },
    { ZBEE_MFG_CODE_ADUROLIGHT_MANU,   ZBEE_MFG_ADUROLIGHT_MANU },
    { ZBEE_MFG_CODE_GROUPE_MULLER,     ZBEE_MFG_GROUPE_MULLER },
    { ZBEE_MFG_CODE_V_MARK_ENTERPRI,   ZBEE_MFG_V_MARK_ENTERPRI },
    { ZBEE_MFG_CODE_LEAD_ENERGY_AG,    ZBEE_MFG_LEAD_ENERGY_AG },
    { ZBEE_MFG_CODE_UIOT_GROUP,        ZBEE_MFG_UIOT_GROUP },
    { ZBEE_MFG_CODE_AXXESS_INDUSTRIES, ZBEE_MFG_AXXESS_INDUSTRIES },
    { ZBEE_MFG_CODE_THIRD_REALITY_INC, ZBEE_MFG_THIRD_REALITY_INC },
    { ZBEE_MFG_CODE_DSR_CORPORATION,   ZBEE_MFG_DSR_CORPORATION },
    { ZBEE_MFG_CODE_GUANGZHOU_VENSI,   ZBEE_MFG_GUANGZHOU_VENSI },
    { ZBEE_MFG_CODE_SCHLAGE_LOCK_ALL,  ZBEE_MFG_SCHLAGE_LOCK_ALL },
    { ZBEE_MFG_CODE_NET2GRID,          ZBEE_MFG_NET2GRID },
    { ZBEE_MFG_CODE_AIRAM_ELECTRIC,    ZBEE_MFG_AIRAM_ELECTRIC },
    { ZBEE_MFG_CODE_IMMAX_WPB_CZ,      ZBEE_MFG_IMMAX_WPB_CZ },
    { ZBEE_MFG_CODE_ZIV_AUTOMATION,    ZBEE_MFG_ZIV_AUTOMATION },
    { ZBEE_MFG_CODE_HANGZHOU_IMAGIC,   ZBEE_MFG_HANGZHOU_IMAGIC },
    { ZBEE_MFG_CODE_XIAMEN_LEELEN,     ZBEE_MFG_XIAMEN_LEELEN },
    { ZBEE_MFG_CODE_OVERKIZ_SAS,       ZBEE_MFG_OVERKIZ_SAS },
    { ZBEE_MFG_CODE_FLONIDAN,          ZBEE_MFG_FLONIDAN },
    { ZBEE_MFG_CODE_HDL_AUTOATION,     ZBEE_MFG_HDL_AUTOATION },
    { ZBEE_MFG_CODE_ARDOMUS_NETWORKS,  ZBEE_MFG_ARDOMUS_NETWORKS},
    { ZBEE_MFG_CODE_SAMJIN_CO,         ZBEE_MFG_SAMJIN_CO},
    { ZBEE_MFG_CODE_SPRUE_AEGIS_PLC,   ZBEE_MFG_SPRUE_AEGIS_PLC },
    { ZBEE_MFG_CODE_INDRA_SISTEMAS,    ZBEE_MFG_INDRA_SISTEMAS },
    { ZBEE_MFG_CODE_JBT_SMART_LIGHT,   ZBEE_MFG_JBT_SMART_LIGHT },
    { ZBEE_MFG_CODE_GE_LIGHTING_CURRE, ZBEE_MFG_GE_LIGHTING_CURRE },
    { ZBEE_MFG_CODE_DANFOSS,           ZBEE_MFG_DANFOSS },
    { ZBEE_MFG_CODE_NIVISS_PHP_SP,     ZBEE_MFG_NIVISS_PHP_SP },
    { ZBEE_MFG_CODE_FENGLIYUAN_ENERGY, ZBEE_MFG_FENGLIYUAN_ENERGY },
    { ZBEE_MFG_CODE_NEXELEC,           ZBEE_MFG_NEXELEC },
    { ZBEE_MFG_CODE_SICHUAN_BEHOME_PR, ZBEE_MFG_SICHUAN_BEHOME_PR },
    { ZBEE_MFG_CODE_FUJIAN_STARNET,    ZBEE_MFG_FUJIAN_STARNET },
    { ZBEE_MFG_CODE_TOSHIBA_VISUAL_SO, ZBEE_MFG_TOSHIBA_VISUAL_SO },
    { ZBEE_MFG_CODE_LATCHABLE_INC,     ZBEE_MFG_LATCHABLE_INC },
    { ZBEE_MFG_CODE_LS_DEUTSCHLAND,    ZBEE_MFG_LS_DEUTSCHLAND },
    { ZBEE_MFG_CODE_GLEDOPTO_CO_LTD,   ZBEE_MFG_GLEDOPTO_CO_LTD },
    { ZBEE_MFG_CODE_THE_HOME_DEPOT,    ZBEE_MFG_THE_HOME_DEPOT },
    { ZBEE_MFG_CODE_NEONLITE_INTERNAT, ZBEE_MFG_NEONLITE_INTERNAT },
    { ZBEE_MFG_CODE_ARLO_TECHNOLOGIES, ZBEE_MFG_ARLO_TECHNOLOGIES },
    { ZBEE_MFG_CODE_XINGLUO_TECH,      ZBEE_MFG_XINGLUO_TECH },
    { ZBEE_MFG_CODE_SIMON_ELECTRIC_CH, ZBEE_MFG_SIMON_ELECTRIC_CH },
    { ZBEE_MFG_CODE_HANGZHOU_GREATSTA, ZBEE_MFG_HANGZHOU_GREATSTA },
    { ZBEE_MFG_CODE_SEQUENTRIC_ENERGY, ZBEE_MFG_SEQUENTRIC_ENERGY },
    { ZBEE_MFG_CODE_SOLUM_CO_LTD,      ZBEE_MFG_SOLUM_CO_LTD },
    { ZBEE_MFG_CODE_EAGLERISE_ELEC,    ZBEE_MFG_EAGLERISE_ELEC },
    { ZBEE_MFG_CODE_FANTEM_TECH,       ZBEE_MFG_FANTEM_TECH },
    { ZBEE_MFG_CODE_YUNDING_NETWORK,   ZBEE_MFG_YUNDING_NETWORK },
    { ZBEE_MFG_CODE_ATLANTIC_GROUP,    ZBEE_MFG_ATLANTIC_GROUP },
    { ZBEE_MFG_CODE_XIAMEN_INTRETECH,  ZBEE_MFG_XIAMEN_INTRETECH },
    { ZBEE_MFG_CODE_TUYA_GLOBAL_INC,   ZBEE_MFG_TUYA_GLOBAL_INC },
    { ZBEE_MFG_CODE_XIAMEN_DNAKE_INTE, ZBEE_MFG_XIAMEN_DNAKE_INTE },
    { ZBEE_MFG_CODE_NIKO_NV,           ZBEE_MFG_NIKO_NV },
    { ZBEE_MFG_CODE_EMPORIA_ENERGY,    ZBEE_MFG_EMPORIA_ENERGY },
    { ZBEE_MFG_CODE_SIKOM_AS,          ZBEE_MFG_SIKOM_AS },
    { ZBEE_MFG_CODE_AXIS_LABS_INC,     ZBEE_MFG_AXIS_LABS_INC },
    { ZBEE_MFG_CODE_CURRENT_PRODUCTS,  ZBEE_MFG_CURRENT_PRODUCTS },
    { ZBEE_MFG_CODE_METERSIT_SRL,      ZBEE_MFG_METERSIT_SRL },
    { ZBEE_MFG_CODE_HORNBACH_BAUMARKT, ZBEE_MFG_HORNBACH_BAUMARKT },
    { ZBEE_MFG_CODE_DICEWORLD_SRL_A,   ZBEE_MFG_DICEWORLD_SRL_A },
    { ZBEE_MFG_CODE_ARC_TECHNOLOGY,    ZBEE_MFG_ARC_TECHNOLOGY },
    { ZBEE_MFG_CODE_KONKE_INFORMATION, ZBEE_MFG_KONKE_INFORMATION },
    { ZBEE_MFG_CODE_SALTO_SYSTEMS_SL,  ZBEE_MFG_SALTO_SYSTEMS_SL },
    { ZBEE_MFG_CODE_SHYUGJ_TECHNOLOGY, ZBEE_MFG_SHYUGJ_TECHNOLOGY },
    { ZBEE_MFG_CODE_BRAYDEN_AUTOMA,    ZBEE_MFG_BRAYDEN_AUTOMA },
    { ZBEE_MFG_CODE_ENVIRONEXUS_PTY,   ZBEE_MFG_ENVIRONEXUS_PTY },
    { ZBEE_MFG_CODE_ELTRA_NV_SA,       ZBEE_MFG_ELTRA_NV_SA },
    { ZBEE_MFG_CODE_XIAMOMI_COMMUNI,   ZBEE_MFG_XIAMOMI_COMMUNI },
    { ZBEE_MFG_CODE_SHUNCOM_ELECTRON,  ZBEE_MFG_SHUNCOM_ELECTRON },
    { ZBEE_MFG_CODE_VOLTALIS_SA,       ZBEE_MFG_VOLTALIS_SA },
    { ZBEE_MFG_CODE_FEELUX_CO_LTD,     ZBEE_MFG_FEELUX_CO_LTD },
    { ZBEE_MFG_CODE_SMARTPLUS_INC,     ZBEE_MFG_SMARTPLUS_INC },
    { ZBEE_MFG_CODE_HALEMEIER_GMBH,    ZBEE_MFG_HALEMEIER_GMBH },
    { ZBEE_MFG_CODE_TRUST_INTL,        ZBEE_MFG_TRUST_INTL },
    { ZBEE_MFG_CODE_DUKE_ENERGY,       ZBEE_MFG_DUKE_ENERGY },
    { ZBEE_MFG_CODE_CALIX,             ZBEE_MFG_CALIX },
    { ZBEE_MFG_CODE_ADEO,              ZBEE_MFG_ADEO },
    { ZBEE_MFG_CODE_CONNECTED_RESP,    ZBEE_MFG_CONNECTED_RESP },
    { ZBEE_MFG_CODE_STROYENERGOKOM,    ZBEE_MFG_STROYENERGOKOM },
    { ZBEE_MFG_CODE_LUMITECH_LIGHT,    ZBEE_MFG_LUMITECH_LIGHT },
    { ZBEE_MFG_CODE_VERDANT_ENVIRO ,   ZBEE_MFG_VERDANT_ENVIRO },
    { ZBEE_MFG_CODE_ALFRED_INTL,       ZBEE_MFG_ALFRED_INTL },
    { ZBEE_MFG_CODE_SANSI_LED_LIGHT,   ZBEE_MFG_SANSI_LED_LIGHT },
    { ZBEE_MFG_CODE_MINDTREE,          ZBEE_MFG_MINDTREE },
    { ZBEE_MFG_CODE_NORDIC_SEMI,       ZBEE_MFG_NORDIC_SEMI },
    { ZBEE_MFG_CODE_SITERWELL_ELEC,    ZBEE_MFG_SITERWELL_ELEC },
    { ZBEE_MFG_CODE_BRILONER_LEUCHTEN, ZBEE_MFG_BRILONER_LEUCHTEN },
    { ZBEE_MFG_CODE_SHENZHEN_SEI_TECH, ZBEE_MFG_SHENZHEN_SEI_TECH },
    { ZBEE_MFG_CODE_COPPER_LABS,       ZBEE_MFG_COPPER_LABS },
    { ZBEE_MFG_CODE_DELTA_DORE,        ZBEE_MFG_DELTA_DORE },
    { ZBEE_MFG_CODE_HAGER_GROUP,       ZBEE_MFG_HAGER_GROUP },
    { ZBEE_MFG_CODE_SHENZHEN_COOLKIT,  ZBEE_MFG_SHENZHEN_COOLKIT },
    { ZBEE_MFG_CODE_HANGZHOU_SKY_LIGHT,ZBEE_MFG_HANGZHOU_SKY_LIGHT },
    { ZBEE_MFG_CODE_E_ON_SE,           ZBEE_MFG_E_ON_SE },
    { ZBEE_MFG_CODE_LIDL_STIFTUNG,     ZBEE_MFG_LIDL_STIFTUNG },
    { ZBEE_MFG_CODE_SICHUAN_CHANGHONG, ZBEE_MFG_SICHUAN_CHANGHONG },
    { ZBEE_MFG_CODE_NODON,             ZBEE_MFG_NODON },
    { ZBEE_MFG_CODE_JIANGXI_INNOTECH,  ZBEE_MFG_JIANGXI_INNOTECH },
    { ZBEE_MFG_CODE_MERCATOR_PTY,      ZBEE_MFG_MERCATOR_PTY },
    { ZBEE_MFG_CODE_BEIJING_RUYING,    ZBEE_MFG_BEIJING_RUYING },
    { ZBEE_MFG_CODE_EGLO_LEUCHTEN,     ZBEE_MFG_EGLO_LEUCHTEN },
    { ZBEE_MFG_CODE_PIETRO_FIORENTINI, ZBEE_MFG_PIETRO_FIORENTINI },
    { ZBEE_MFG_CODE_ZEHNDER_GROUP,     ZBEE_MFG_ZEHNDER_GROUP },
    { ZBEE_MFG_CODE_BRK_BRANDS,        ZBEE_MFG_BRK_BRANDS },
    { ZBEE_MFG_CODE_ASKEY_COMPUTER,    ZBEE_MFG_ASKEY_COMPUTER },
    { ZBEE_MFG_CODE_PASSIVEBOLT,       ZBEE_MFG_PASSIVEBOLT },
    { ZBEE_MFG_CODE_AVM_AUDIOVISUELLE, ZBEE_MFG_AVM_AUDIOVISUELLE },
    { ZBEE_MFG_CODE_NINGBO_SUNTECH,    ZBEE_MFG_NINGBO_SUNTECH },
    { ZBEE_MFG_CODE_SOCIETE_EN_COMMAND,ZBEE_MFG_SOCIETE_EN_COMMAND },
    { ZBEE_MFG_CODE_VIVINT_SMART_HOME, ZBEE_MFG_VIVINT_SMART_HOME },
    { ZBEE_MFG_CODE_NAMRON,            ZBEE_MFG_NAMRON },
    { ZBEE_MFG_CODE_RADEMACHER_GERA,   ZBEE_MFG_RADEMACHER_GERA },
    { ZBEE_MFG_CODE_OMO_SYSTEMS,       ZBEE_MFG_OMO_SYSTEMS },
    { ZBEE_MFG_CODE_SIGLIS,            ZBEE_MFG_SIGLIS },
    { ZBEE_MFG_CODE_IMHOTEP_CREATION,  ZBEE_MFG_IMHOTEP_CREATION },
    { ZBEE_MFG_CODE_ICASA,             ZBEE_MFG_ICASA },
    { ZBEE_MFG_CODE_LEVEL_HOME,        ZBEE_MFG_LEVEL_HOME },
    { ZBEE_MFG_CODE_TIS_CONTROL,       ZBEE_MFG_TIS_CONTROL },
    { ZBEE_MFG_CODE_RADISYS_INDIA,     ZBEE_MFG_RADISYS_INDIA },
    { ZBEE_MFG_CODE_VEEA,              ZBEE_MFG_VEEA },
    { ZBEE_MFG_CODE_FELL_TECHNOLOGY,   ZBEE_MFG_FELL_TECHNOLOGY },
    { ZBEE_MFG_CODE_SOWILO_DESIGN,     ZBEE_MFG_SOWILO_DESIGN },
    { ZBEE_MFG_CODE_LEXI_DEVICES,      ZBEE_MFG_LEXI_DEVICES },
    { ZBEE_MFG_CODE_LIFI_LABS,         ZBEE_MFG_LIFI_LABS },
    { ZBEE_MFG_CODE_GRUNDFOS_HOLDING,  ZBEE_MFG_GRUNDFOS_HOLDING },
    { ZBEE_MFG_CODE_SOURCING_CREATION, ZBEE_MFG_SOURCING_CREATION },
    { ZBEE_MFG_CODE_KRAKEN_TECH,       ZBEE_MFG_KRAKEN_TECHNOLOGIES },
    { ZBEE_MFG_CODE_EVE_SYSTEMS,       ZBEE_MFG_EVE_SYSTEMS },
    { ZBEE_MFG_CODE_LITE_ON_TECH,      ZBEE_MFG_LITE_ON_TECHNOLOGY },
    { ZBEE_MFG_CODE_FOCALCREST,        ZBEE_MFG_FOCALCREST },
    { ZBEE_MFG_CODE_BOUFFALO_LAB,      ZBEE_MFG_BOUFFALO_LAB },
    { ZBEE_MFG_CODE_WYZE_LABS,         ZBEE_MFG_WYZE_LABS },

    { ZBEE_MFG_CODE_DATEK_WIRLESS,     ZBEE_MFG_DATEK_WIRLESS },
    { ZBEE_MFG_CODE_GEWISS_SPA,        ZBEE_MFG_GEWISS_SPA },
    { ZBEE_MFG_CODE_CLIMAX_TECH,       ZBEE_MFG_CLIMAX_TECH },
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
    { ZBEE_ZCL_STAT_INCONSISTENT,                   "Inconsistent Value"},
    { ZBEE_ZCL_STAT_ACTION_DENIED,                  "Action Denied"},
    { ZBEE_ZCL_STAT_TIMEOUT,                        "Timeout"},
    { ZBEE_ZCL_STAT_OTA_ABORT,                      "Ota Abort"},
    { ZBEE_ZCL_STAT_OTA_INVALID_IMAGE,              "Ota Invalid Image"},
    { ZBEE_ZCL_STAT_OTA_WAIT_FOR_DATA,              "Ota Wait For Data"},
    { ZBEE_ZCL_STAT_OTA_NO_IMAGE_AVAILABLE,         "Ota No Image Available"},
    { ZBEE_ZCL_STAT_OTA_REQUIRE_MORE_IMAGE,         "Ota Require More Image"},
    { ZBEE_ZCL_STAT_OTA_NOTIFICATION_PENDING,       "Ota Notification Pending"},
    { ZBEE_ZCL_STAT_HARDWARE_FAILURE,               "Hardware Failure"},
    { ZBEE_ZCL_STAT_SOFTWARE_FAILURE,               "Software Failure"},
    { ZBEE_ZCL_STAT_CALIBRATION_ERROR,              "Calibration Error"},
    { ZBEE_ZCL_STAT_UNSUPPORTED_CLUSTER,            "Unsupported Cluster"},
    { ZBEE_ZCL_STAT_LIMIT_REACHED,                  "Limit Reached"},
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

/**
 *ZigBee Cluster Library dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param data raw packet private data.
*/
static int dissect_zbee_zcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tvbuff_t *payload_tvb;
    dissector_handle_t cluster_handle;

    proto_tree *zcl_tree;
    proto_tree *sub_tree = NULL;

    proto_item  *proto_root;

    zbee_nwk_packet *nwk;
    zbee_zcl_packet packet;
    zbee_zcl_cluster_desc *desc;
    guint16 cluster_id;

    guint8  fcf;
    guint   offset = 0;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    nwk = (zbee_nwk_packet *)data;

    /* Init. */
    memset(&packet, 0, sizeof(zbee_zcl_packet));

    /* Fill the zcl cluster id */
    cluster_id = zcl_cluster_id = nwk->cluster_id;

    /* Create the protocol tree */
    proto_root = proto_tree_add_protocol_format(tree, proto_zbee_zcl, tvb, offset,
                            -1, "ZigBee Cluster Library Frame");

    zcl_tree = proto_item_add_subtree(proto_root, ett_zbee_zcl);

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
        sub_tree = proto_tree_add_subtree_format(zcl_tree, tvb, offset, 1,
                    ett_zbee_zcl_fcf, NULL, "Frame Control Field: %s (0x%02x)",
                    val_to_str_const(packet.frame_type, zbee_zcl_frame_types, "Unknown"), fcf);

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

    /* Fill the zcl mfr code id */
    zcl_mfr_code = packet.mfr_code;

    /* Add the transaction sequence number to the tree */
    packet.tran_seqno = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(zcl_tree, hf_zbee_zcl_tran_seqno, tvb, offset, 1, packet.tran_seqno);
    offset += 1;

    /* Display the command and sequence number on the proto root and info column. */
    packet.cmd_id = tvb_get_guint8(tvb, offset);

    /* Get the manufacturer specific cluster handle */
    cluster_handle = dissector_get_uint_handle(zbee_zcl_dissector_table, ZCL_CLUSTER_MFR_KEY(cluster_id, packet.mfr_code));

    desc = zbee_zcl_get_cluster_desc(cluster_id, packet.mfr_code);
    if (desc != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s: ", desc->name);
    }

    /* Add command ID to the tree. */
    if ( packet.frame_type == ZBEE_ZCL_FCF_PROFILE_WIDE ) {
        /* Profile-wide commands. */
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
        /* Cluster-specific commands. */
        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        if (cluster_handle != NULL) {
            /* Call the specific cluster dissector registered. */
            call_dissector_with_data(cluster_handle, payload_tvb, pinfo, zcl_tree, &packet);
            return tvb_captured_length(tvb);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown Command: 0x%02x, Seq: %u", packet.cmd_id,
                packet.tran_seqno);

            proto_tree_add_uint(zcl_tree, hf_zbee_zcl_cs_cmd_id, tvb, offset, 1, packet.cmd_id);
            offset += 1;
        }
        /* Don't decode the tail. */
        zcl_dump_data(tvb, offset, pinfo, zcl_tree);
        return tvb_captured_length(tvb);
    }

    if ( zcl_tree ) {
    /* Handle the contents of the command frame. */
        switch ( packet.cmd_id ) {
            case ZBEE_ZCL_CMD_READ_ATTR:
                dissect_zcl_read_attr(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_READ_ATTR_RESP:
                dissect_zcl_read_attr_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR:
            case ZBEE_ZCL_CMD_WRITE_ATTR_UNDIVIDED:
            case ZBEE_ZCL_CMD_WRITE_ATTR_NO_RESP:
                dissect_zcl_write_attr(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_REPORT_ATTR:
                dissect_zcl_report_attr(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR_RESP:
                dissect_zcl_write_attr_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_CONFIG_REPORT:
                dissect_zcl_config_report(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_CONFIG_REPORT_RESP:
                dissect_zcl_config_report_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_READ_REPORT_CONFIG:
                dissect_zcl_read_report_config(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_READ_REPORT_CONFIG_RESP:
                dissect_zcl_read_report_config_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_DEFAULT_RESP:
                dissect_zcl_default_resp(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_ATTR:
            case ZBEE_ZCL_CMD_DISCOVER_ATTR_EXTENDED:
                dissect_zcl_discover_attr(tvb, pinfo, zcl_tree, &offset);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_ATTR_RESP:
                dissect_zcl_discover_attr_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            /* BUGBUG: don't dissect these for now*/
            case ZBEE_ZCL_CMD_READ_ATTR_STRUCT:
                dissect_zcl_read_attr_struct(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT:
                dissect_zcl_write_attr_struct(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT_RESP:
                dissect_zcl_write_attr_struct_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                break;

            case ZBEE_ZCL_CMD_DISCOVER_CMDS_REC:
            case ZBEE_ZCL_CMD_DISCOVER_CMDS_GEN:
                 dissect_zcl_discover_cmd_rec(tvb, pinfo, zcl_tree, &offset);
                 break;

            case ZBEE_ZCL_CMD_DISCOVER_CMDS_REC_RESP:
            case ZBEE_ZCL_CMD_DISCOVER_CMDS_GEN_RESP:
                 dissect_zcl_discover_cmd_rec_resp(tvb, pinfo, zcl_tree, &offset);
                 break;

           /* case ZBEE_ZCL_CMD_DISCOVER_CMDS_GEN_RESP:
                 dissect_zcl_discover_cmd_gen_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                 break;*/

            case ZBEE_ZCL_CMD_DISCOVER_ATTR_EXTENDED_RESP:
                 dissect_zcl_discover_cmd_attr_extended_resp(tvb, pinfo, zcl_tree, &offset, cluster_id, packet.mfr_code, packet.direction);
                 break;

        } /* switch */
    }
    zcl_dump_data(tvb, offset, pinfo, zcl_tree);
    return tvb_captured_length(tvb);
} /* dissect_zbee_zcl */

/**
 *Helper dissector for ZCL Read Attributes and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer from caller.
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
void dissect_zcl_read_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    guint tvb_len;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_CLIENT;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len ) {
        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, tree, offset, cluster_id, mfr_code, client_attr);
    }

    return;
} /* dissect_zcl_read_attr */

/**
 *Helper dissector for ZCL Read Attributes Response command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
void dissect_zcl_read_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;
    guint16 attr_id;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_SERVER;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Status Record");
        i++;

        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);

        /* Dissect the status and optionally the data type and value */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status)
            == ZBEE_ZCL_STAT_SUCCESS ) {

            /* Dissect the attribute data type and data */
            dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id, mfr_code, client_attr);
        }

        /* Set end for subtree */
        proto_item_set_end(proto_tree_get_parent(sub_tree), tvb, *offset);
    }
} /* dissect_zcl_read_attr_resp */

/**
 *Helper dissector for ZCL Report Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
void dissect_zcl_write_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;
    guint16 attr_id;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_CLIENT;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Attribute Field");
        i++;

        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);

        /* Dissect the attribute data type and data */
        dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id, mfr_code, client_attr);

        /* Set end for subtree */
        proto_item_set_end(proto_tree_get_parent(sub_tree), tvb, *offset);
    }
} /* dissect_zcl_write_attr */

/**
 *Helper dissector for ZCL Report Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
void dissect_zcl_report_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;
    guint16 attr_id;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_SERVER;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Attribute Field");
        i++;

        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);

        /* Dissect the attribute data type and data */
        dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id, mfr_code, client_attr);

        /* Set end for subtree */
        proto_item_set_end(proto_tree_get_parent(sub_tree), tvb, *offset);
    }
} /* dissect_zcl_report_attr */

/**
 *Helper dissector for ZCL Write Attribute Response command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
static void dissect_zcl_write_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_SERVER;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Status Record");
        i++;

        /* Dissect the status */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status) !=
            ZBEE_ZCL_STAT_SUCCESS ) {

            /* Dissect the failed attribute identifier */
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);
        }

        /* Set end for subtree */
        proto_item_set_end(proto_tree_get_parent(sub_tree), tvb, *offset);
    }

} /* dissect_zcl_write_attr_resp */

/**
 *Helper dissector for ZCL Report Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster identification
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
 */
static void dissect_zcl_read_report_config_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;
    guint data_type;
    guint attr_status;
    guint attr_dir;
    guint16 attr_id;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 3, ett_zbee_zcl_attr[i], NULL, "Reporting Configuration Record");
        i++;

        /* Dissect the status */
        attr_status = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status);

        /* Dissect the direction and any reported configuration */
        attr_dir = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir);

        /* Dissect the attribute id */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, (direction == ZBEE_ZCL_FCF_TO_SERVER && attr_dir == ZBEE_ZCL_DIR_REPORTED) ||
                (direction == ZBEE_ZCL_FCF_TO_CLIENT && attr_dir == ZBEE_ZCL_DIR_RECEIVED));

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
                    dissect_zcl_attr_data_general(tvb, sub_tree, offset, attr_id, data_type, cluster_id, mfr_code, direction == ZBEE_ZCL_FCF_TO_SERVER);
                }

            } else {
                /* Dissect timeout period */
               proto_tree_add_item(tree, hf_zbee_zcl_attr_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
               (*offset) += 2;
            }
        }
    }

} /* dissect_zcl_read_report_config_resp */

/**
 *Helper dissector for ZCL Config Report Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
static void dissect_zcl_config_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;
    guint data_type;
    guint16 attr_id;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 3, ett_zbee_zcl_attr[i], NULL, "Reporting Configuration Record");
        i++;

        /* Dissect the direction and any reported configuration */
        if ( dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir)
                        == ZBEE_ZCL_DIR_REPORTED ) {

            /* Dissect the attribute id */
            attr_id = tvb_get_letohs(tvb, *offset);
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, direction == ZBEE_ZCL_FCF_TO_CLIENT);

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
                dissect_zcl_attr_data_general(tvb, sub_tree, offset, attr_id, data_type, cluster_id, mfr_code, direction == ZBEE_ZCL_FCF_TO_CLIENT);
            }
        } else {

            /* Dissect the attribute id */
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, direction == ZBEE_ZCL_FCF_TO_SERVER);

            /* Dissect timeout period */
            proto_tree_add_item(tree, hf_zbee_zcl_attr_timeout, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            (*offset) += 2;
        }
    }

} /* dissect_zcl_config_report */

/**
 *Helper dissector for ZCL Config Report Attribute Response commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
static void dissect_zcl_config_report_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_captured_length(tvb);

    /* Special case when all attributes configured successfully */
    if ( *offset == tvb_len - 1 ) {
        /* Dissect the status */
        if ( dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_status) !=
            ZBEE_ZCL_STAT_SUCCESS ) {
            expert_add_info(pinfo, tree->last_child, &ei_cfg_rpt_rsp_short_non_success);
        }
    }

    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {
        guint8 attr_dir;

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 3, ett_zbee_zcl_attr[i], NULL, "Attribute Status Record");
        i++;

        /* Dissect the status */
        dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status);
        /* Dissect the direction */
        attr_dir = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir);
        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, (direction == ZBEE_ZCL_FCF_TO_SERVER && attr_dir == ZBEE_ZCL_DIR_REPORTED) ||
                (direction == ZBEE_ZCL_FCF_TO_CLIENT && attr_dir == ZBEE_ZCL_DIR_RECEIVED));
    }
} /* dissect_zcl_config_report_resp */

/**
 *Helper dissector for ZCL Read Report Configuration command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
static void dissect_zcl_read_report_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 0;

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {
        guint8 attr_dir;

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 3, ett_zbee_zcl_attr[i], NULL, "Attribute Status Record");
        i++;

        /* Dissect the direction */
        attr_dir = dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dir);

        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, (direction == ZBEE_ZCL_FCF_TO_SERVER && attr_dir == ZBEE_ZCL_DIR_RECEIVED) ||
                (direction == ZBEE_ZCL_FCF_TO_CLIENT && attr_dir == ZBEE_ZCL_DIR_REPORTED));
    }

} /* dissect_zcl_read_report_config */

/**
 *Helper dissector for ZCL Default Response command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller.
*/
static void dissect_zcl_default_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    /* The only way to tell if this is a profile-wide or cluster specific command */
    /* is the frame control of the original message to which this is the response. */
    /* So, display the originating command id and do not attempt to interpret */
    proto_tree_add_item(tree, hf_zbee_zcl_cmd_id_rsp, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Dissect the status */
    dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_status);
} /* dissect_zcl_default_resp */

/**
 *Helper dissector for ZCL Discover Attributes command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
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


/**
 *Helper dissector for ZCL Discover Attributes command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset pointer to offset from caller
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param direction ZCL direction
*/
static void dissect_zcl_discover_attr_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree = NULL;

    guint tvb_len;
    guint i = 0;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_SERVER;

    /* XXX - tree is never available!!!*/
    dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_dis);

    tvb_len = tvb_captured_length(tvb);
    while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ) {

        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 3, ett_zbee_zcl_attr[i], NULL, "Attribute Status Record");
        i++;

        /* Dissect the attribute identifier */
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);

        /* Dissect the number of maximum attribute identifiers */
        dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_data_type);
    }

} /* dissect_zcl_discover_attr_resp */


static void dissect_zcl_read_attr_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, guint* offset,
    guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree = NULL;
    guint tvb_len;
    guint i = 0, j=0;
//    guint16 attr_id;
    guint8 indicator;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_CLIENT;
    tvb_len = tvb_captured_length(tvb);
    while (*offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT) {
        /* Create subtree for aelector field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_sel[i], NULL, "Selector");
        i++;
        /* Dissect the attribute identifier */
//        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, tree, offset, cluster_id, mfr_code, client_attr);
        proto_tree_add_item(sub_tree, hf_zbee_zcl_indicator, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
        indicator = tvb_get_guint8(tvb, *offset);
        *offset += 1;
        j=0;
        while (j < indicator) {
            proto_tree_add_item(sub_tree, hf_zbee_zcl_index, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            //index = tvb_get_letohs(tvb, offset);
            /*index = dissect_zcl_array_type();*/
            j++;
            *offset += 2;
        }
    }

}/*dissect_zcl_read_attr_struct*/

static void dissect_zcl_write_attr_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, guint* offset,
    guint16 cluster_id, guint16 mfr_code, gboolean direction)
{
    proto_tree *sub_tree = NULL;
    proto_tree *sub_tree_1 = NULL;
    guint tvb_len, indicator;
    guint i = 0, j=0;
    guint16 attr_id;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_CLIENT;
    tvb_len = tvb_captured_length(tvb);
    while(*offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT){
        /* Create subtree for aelector field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Attribute Record");
        sub_tree_1 = proto_tree_add_subtree(sub_tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Selector");
        i++;
        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, *offset);
        dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);
        if(sub_tree_1){
            proto_tree_add_item(sub_tree, hf_zbee_zcl_indicator, tvb, 0, 1, ENC_LITTLE_ENDIAN);
            indicator = tvb_get_guint8(tvb, *offset);
            (* offset) += 1;
            j=0;
            while (j < indicator) {
                proto_tree_add_item(sub_tree, hf_zbee_zcl_index, tvb, 0, 2, ENC_LITTLE_ENDIAN);
                j++;
                (* offset) += 2;
            }
        }
        /* Dissect the attribute data type and data */
        dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id, mfr_code, client_attr);
    }
    /* Set end for subtree */
    proto_item_set_end(proto_tree_get_parent(sub_tree_1), tvb, *offset);
}

static void dissect_zcl_write_attr_struct_resp(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, guint* offset,    guint16 cluster_id, guint16 mfr_code, gboolean direction){

    proto_tree *sub_tree;
    proto_tree *sub_tree_1;
    guint tvb_len, indicator;
    guint i = 0,j = 0;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_SERVER;
    tvb_len = tvb_captured_length(tvb);
    while (*offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT) {
        /* Create subtree for attribute status field */
        sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Write Attribute Record");
        sub_tree_1 = proto_tree_add_subtree(sub_tree, tvb, *offset, 0, ett_zbee_zcl_attr[i], NULL, "Selector");
        i++;
        /* Dissect the status */
        if (dissect_zcl_attr_uint8(tvb, sub_tree, offset, &hf_zbee_zcl_attr_status) !=
            ZBEE_ZCL_STAT_SUCCESS) {
            /* Dissect the failed attribute identifier */
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);
            if (sub_tree_1) {
                proto_tree_add_item(sub_tree, hf_zbee_zcl_indicator, tvb, 0, 1, ENC_LITTLE_ENDIAN);
                indicator = tvb_get_guint8(tvb, *offset);
                *offset += 1;
                j = 0;
                while (j < indicator) {
                    proto_tree_add_item(sub_tree, hf_zbee_zcl_index, tvb, 0, 2, ENC_LITTLE_ENDIAN);
                    //index = tvb_get_letohs(tvb, offset);
                    /*index = dissect_zcl_array_type();*/
                    j++;
                    *offset += 2;
                }
            }
        }
    }
        /* Set end for subtree */
//        proto_item_set_end(proto_tree_get_parent(sub_tree_1), tvb, *offset);
}
static void dissect_zcl_discover_cmd_rec(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_cmd_start);
    /* Dissect the number of maximum attribute identifiers */
    dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_cmd_maxnum);
    return;
}
static void dissect_zcl_discover_cmd_rec_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset)
{
    guint tvb_len;
    guint i = 0;
    gint discovery_complete = -1;
    discovery_complete = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_dis);
    if(discovery_complete == 0){
        tvb_len = tvb_captured_length(tvb);
        while ( *offset < tvb_len && i < (tvb_len-1) ) {
            /* Dissect the command identifiers */
            dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_cs_cmd_id);
            i++;
        }
    }
}

static void dissect_zcl_discover_cmd_attr_extended_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean direction){
    proto_tree* sub_tree = NULL;
    guint tvb_len;
    guint i = 0;
    gint discovery_complete = -1;
    guint16 attr_id = 0;
    gboolean client_attr = direction == ZBEE_ZCL_FCF_TO_SERVER;
    discovery_complete = dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_dis);
    if(discovery_complete == 0){
        tvb_len = tvb_captured_length(tvb);
        while ( *offset < tvb_len && i < ZBEE_ZCL_NUM_ATTR_ETT ){
            sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 4, ett_zbee_zcl_attr[i], NULL, "Extended Attribute Information");
            i++;
            attr_id = tvb_get_letohs(tvb, *offset);
            dissect_zcl_attr_id(tvb, sub_tree, offset, cluster_id, mfr_code, client_attr);
            dissect_zcl_attr_data_type_val(tvb, sub_tree, offset, attr_id, cluster_id, mfr_code, client_attr);
            proto_tree_add_item(sub_tree, hf_zbee_zcl_attr_access_ctrl, tvb, 0, 1, ENC_LITTLE_ENDIAN);
            *offset += 1;
        }
    }
}

/**
 *Dissects Attribute ID field. This could be done with the
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param client_attr ZCL client
*/
void dissect_zcl_attr_id(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 cluster_id, guint16 mfr_code, gboolean client_attr)
{
    zbee_zcl_cluster_desc *desc;
    int hf_attr_id = hf_zbee_zcl_attr_id;

    /* Check if a cluster-specific attribute ID definition exists. */
    desc = zbee_zcl_get_cluster_desc(cluster_id, mfr_code);

    if (desc) {
        if (client_attr) {
            if (desc->hf_attr_client_id >= 0) {
                hf_attr_id = desc->hf_attr_client_id;
            }
        }
        else {
            if (desc->hf_attr_server_id >= 0) {
                hf_attr_id = desc->hf_attr_server_id;
            }
        }
    }

    /* Add the identifier. */
    proto_tree_add_item(tree, hf_attr_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
} /* dissect_zcl_attr_id */

/**
 *Helper dissector for ZCL Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset into the tvb to begin dissection.
 *@param attr_id attribute id
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param client_attr ZCL client
*/
void dissect_zcl_attr_data_type_val(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 attr_id, guint16 cluster_id, guint16 mfr_code, gboolean client_attr)
{
    zbee_zcl_cluster_desc *desc;

    desc = zbee_zcl_get_cluster_desc(cluster_id, mfr_code);
    if ((desc != NULL) && (desc->fn_attr_data != NULL)) {
        desc->fn_attr_data(tree, tvb, offset, attr_id,
            dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_data_type), client_attr);
    }
    else {
        dissect_zcl_attr_data(tvb, tree, offset,
            dissect_zcl_attr_uint8(tvb, tree, offset, &hf_zbee_zcl_attr_data_type), client_attr);
    }

} /* dissect_zcl_attr_data_type_val */


/**
 *Helper dissector for ZCL Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset into the tvb to begin dissection.
 *@param attr_id attribute identification
 *@param data_type type of data
 *@param cluster_id cluster id
 *@param mfr_code manufacturer code.
 *@param client_attr ZCL client
*/
static void dissect_zcl_attr_data_general(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint16 attr_id, guint data_type, guint16 cluster_id, guint16 mfr_code, gboolean client_attr)
{
    zbee_zcl_cluster_desc *desc;

    desc = zbee_zcl_get_cluster_desc(cluster_id, mfr_code);
    if ((desc != NULL) && (desc->fn_attr_data != NULL)) {
        desc->fn_attr_data(tree, tvb, offset, attr_id, data_type, client_attr);
    }
    else {
        dissect_zcl_attr_data(tvb, tree, offset, data_type, client_attr);
    }

} /*dissect_zcl_attr_data_general*/

/**
 *Dissects the various types of ZCL attribute data.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset into the tvb to begin dissection.
 *@param client_attr ZCL client
*/
void dissect_zcl_attr_data(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint data_type, gboolean client_attr)
{
    guint     attr_uint;
    gint      attr_int;
    const guint8   *attr_string;
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
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;
            break;

        case ZBEE_ZCL_8_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap8, tvb, *offset, 1, ENC_NA);
            proto_item_append_text(tree, ", Bitmap: %02x", tvb_get_guint8(tvb, *offset));
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
            attr_int = tvb_get_gint8(tvb, *offset);
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
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 2, ENC_NA);
            (*offset) += 2;
            break;

        case ZBEE_ZCL_16_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap16, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %04" PRIx16, tvb_get_letohs(tvb, *offset));
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
            attr_int = tvb_get_letohis(tvb, *offset);
            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int16, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_24_BIT_DATA:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 3, ENC_NA);
            (*offset) += 3;
            break;

        case ZBEE_ZCL_24_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap24, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %06" PRIx32, tvb_get_letoh24(tvb, *offset));
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
            attr_int = tvb_get_letohi24(tvb, *offset);
            /* sign extend into int32 */
            if (attr_int & INT24_SIGN_BITS) attr_int |= INT24_SIGN_BITS;
            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int24, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
            *offset += 3;
            break;

        case ZBEE_ZCL_32_BIT_DATA:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 4, ENC_NA);
            (*offset) += 4;
            break;

        case ZBEE_ZCL_32_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap32, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %08" PRIx32, tvb_get_letohl(tvb, *offset));
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
            attr_int = tvb_get_letohil(tvb, *offset);
            proto_item_append_text(tree, ", %s: %-d",
                val_to_str_ext_const(data_type, &zbee_zcl_short_data_type_names_ext, "Reserved"), attr_int);
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int32, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
            break;

        case ZBEE_ZCL_40_BIT_DATA:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 5, ENC_NA);
            (*offset) += 5;
            break;

        case ZBEE_ZCL_40_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap40, tvb, *offset, 5, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %010" PRIx64, tvb_get_letoh40(tvb, *offset));
            (*offset) += 5;
            break;

        case ZBEE_ZCL_40_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint40, tvb, *offset, 5, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" PRIu64, tvb_get_letoh40(tvb, *offset));
            (*offset) += 5;
            break;

        case ZBEE_ZCL_40_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 5, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" PRId64, tvb_get_letohi40(tvb, *offset));
            (*offset) += 5;
            break;

        case ZBEE_ZCL_48_BIT_DATA:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 6, ENC_NA);
            (*offset) += 6;
            break;

        case ZBEE_ZCL_48_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap48, tvb, *offset, 6, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %012" PRIx64, tvb_get_letoh48(tvb, *offset));
            (*offset) += 6;
            break;

        case ZBEE_ZCL_48_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint48, tvb, *offset, 6, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" PRIu64, tvb_get_letoh48(tvb, *offset));
            (*offset) += 6;
            break;

        case ZBEE_ZCL_48_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 6, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" PRId64, tvb_get_letohi48(tvb, *offset));
            (*offset) += 6;
            break;

        case ZBEE_ZCL_56_BIT_DATA:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 7, ENC_NA);
            (*offset) += 7;
            break;

        case ZBEE_ZCL_56_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap56, tvb, *offset, 7, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %014" PRIx64, tvb_get_letoh56(tvb, *offset));
            (*offset) += 7;
            break;

        case ZBEE_ZCL_56_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint56, tvb, *offset, 7, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" PRIu64, tvb_get_letoh56(tvb, *offset));
            (*offset) += 7;
            break;

        case ZBEE_ZCL_56_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 7, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" PRId64, tvb_get_letohi56(tvb, *offset));
            (*offset) += 7;
            break;

        case ZBEE_ZCL_64_BIT_DATA:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bytes, tvb, *offset, 8, ENC_NA);
            (*offset) += 8;
            break;

        case ZBEE_ZCL_64_BIT_BITMAP:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_bitmap64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Bitmap: %016" PRIx64, tvb_get_letoh64(tvb, *offset));
            (*offset) += 8;
            break;

        case ZBEE_ZCL_64_BIT_UINT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_uint64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Uint: %" PRIu64, tvb_get_letoh64(tvb, *offset));
            (*offset) += 8;
            break;

        case ZBEE_ZCL_64_BIT_INT:
            proto_tree_add_item(tree, hf_zbee_zcl_attr_int64, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            proto_item_append_text(tree, ", Int: %" PRIu64, tvb_get_letoh64(tvb, *offset));
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
            proto_item_append_text(tree, ", Double: %g", attr_double);
            proto_tree_add_item(tree, hf_zbee_zcl_attr_double, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
            *offset += 8;
            break;

        case ZBEE_ZCL_OCTET_STRING:
            /* Display octet string */
            proto_tree_add_item_ret_length(tree, hf_zbee_zcl_attr_ostr, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, &attr_int);
            if (attr_int > 1)
                proto_item_append_text(tree, ", Octets: %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, (*offset)+1, attr_int-1, ':'));
            *offset += attr_int;
            break;

        case ZBEE_ZCL_CHAR_STRING:
            /* Display string */
            proto_tree_add_item_ret_string_and_length(tree, hf_zbee_zcl_attr_str, tvb, *offset, 1, ENC_NA|ENC_ZIGBEE, wmem_packet_scope(), &attr_string, &attr_int);
            proto_item_append_text(tree, ", String: %s", attr_string);
            *offset += attr_int;
            break;

        case ZBEE_ZCL_LONG_OCTET_STRING:
            /* Display long octet string */
            proto_tree_add_item_ret_length(tree, hf_zbee_zcl_attr_ostr, tvb, *offset, 2, ENC_LITTLE_ENDIAN|ENC_ZIGBEE, &attr_int);
            if (attr_int > 2)
                proto_item_append_text(tree, ", Octets: %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, (*offset)+2, attr_int-2, ':'));
            *offset += attr_int;
            break;

        case ZBEE_ZCL_LONG_CHAR_STRING:
            /* Display long string */
            proto_tree_add_item_ret_string_and_length(tree, hf_zbee_zcl_attr_str, tvb, *offset, 2, ENC_LITTLE_ENDIAN|ENC_ZIGBEE, wmem_packet_scope(), &attr_string, &attr_int);
            proto_item_append_text(tree, ", String: %s", attr_string);
            *offset += attr_int;
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
            dissect_zcl_array_type(tvb, tree, offset, elements_type, elements_num, client_attr);
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
            dissect_zcl_set_type(tvb, tree, offset, elements_type, elements_num, client_attr);
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
            dissect_zcl_set_type(tvb, tree, offset, elements_type, elements_num, client_attr);
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
            dissect_zcl_attr_id(tvb, tree, offset, zcl_cluster_id, zcl_mfr_code, client_attr);
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

/**
 *Helper dissector for ZCL Attribute commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset into the tvb to begin dissection.
 *@param hf_zbee_zcl pointer to header field index
 *@return dissected data
*/
guint dissect_zcl_attr_uint8(tvbuff_t *tvb, proto_tree *tree, guint *offset, int *hf_zbee_zcl)
{
    guint attr_uint;

    attr_uint = tvb_get_guint8(tvb, *offset);
    proto_tree_add_uint(tree, *hf_zbee_zcl, tvb, *offset, 1, attr_uint);
    (*offset)++;

    return attr_uint;
} /* dissect_zcl_attr_uint8 */

/**
 *Helper dissector for ZCL attribute array type.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset into the tvb to begin dissection.
 *@param elements_type element type
 *@param elements_num elements number
 *@param client_attr ZCL client
*/
static void
dissect_zcl_array_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num, gboolean client_attr)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 1;   /* First element has a 1-index value */

    tvb_len = tvb_captured_length(tvb);
    while ( (*offset < tvb_len) && (elements_num != 0) ) {

        /* Have "common" use case give individual tree control to all elements,
           but don't prevent dissection if list is large */
        if (i < ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1)
            sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0,
                        ett_zbee_zcl_array_elements[i], NULL, "Element #%d", i);
        else
            sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0,
                        ett_zbee_zcl_array_elements[ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1], NULL, "Element #%d", i);

        guint old_offset = *offset;
        dissect_zcl_attr_data(tvb, sub_tree, offset, elements_type, client_attr);
        if (old_offset >= *offset) {
            proto_tree_add_expert(sub_tree, NULL, &ei_zbee_zero_length_element, tvb, old_offset, -1);
            break;
        }
        elements_num--;
        i++;
    }
} /* dissect_zcl_array_type */

/**
 *Helper dissector for ZCL attribute set and bag types.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree wireshark uses to display packet.
 *@param offset into the tvb to begin dissection.
 *@param elements_type element type
 *@param elements_num elements number
 *@param client_attr ZCL client
*/
static void
dissect_zcl_set_type(tvbuff_t *tvb, proto_tree *tree, guint *offset, guint8 elements_type, guint16 elements_num, gboolean client_attr)
{
    proto_tree *sub_tree;

    guint tvb_len;
    guint i = 1;   /* First element has a 1-index value */

    tvb_len = tvb_captured_length(tvb);
    while ( (*offset < tvb_len) && (elements_num != 0) ) {
        /* Piggyback on array ett_ variables */
        /* Have "common" use case give individual tree control to all elements,
           but don't prevent dissection if list is large */
        if (i < ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1)
            sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0,
                            ett_zbee_zcl_array_elements[i], NULL, "Element");
        else
            sub_tree = proto_tree_add_subtree(tree, tvb, *offset, 0,
                        ett_zbee_zcl_array_elements[ZBEE_ZCL_NUM_ARRAY_ELEM_ETT-1], NULL, "Element");

        guint old_offset = *offset;
        dissect_zcl_attr_data(tvb, sub_tree, offset, elements_type, client_attr);
        if (old_offset >= *offset) {
            proto_tree_add_expert(sub_tree, NULL, &ei_zbee_zero_length_element, tvb, old_offset, -1);
            break;
        }
        elements_num--;
        i++;
    }
} /* dissect_zcl_set_type */

/**
 *Helper functions dumps any remaining data into the data dissector.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param offset offset after parsing last item.
 *@param pinfo packet information structure.
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static void zcl_dump_data(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *root   = proto_tree_get_root(tree);
    guint       length = tvb_captured_length_remaining(tvb, offset);
    tvbuff_t   *remainder;

    if (length > 0) {
        remainder = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(remainder, pinfo, root);
    }

    return;
} /* zcl_dump_data */

/**
 *This function decodes tenth of second time type variable
 *
*/
void decode_zcl_time_in_100ms(gchar *s, guint16 value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d.%d seconds", value/10, value%10);
    return;
} /* decode_zcl_time_in_100ms*/

  /**
  *This function decodes second time type variable
  *
  */
void decode_zcl_time_in_seconds(gchar *s, guint16 value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", value);
    return;
} /* decode_zcl_time_in_seconds*/

/**
 *This function decodes minute time type variable
 *
*/
void decode_zcl_time_in_minutes(gchar *s, guint16 value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", value);
    return;
} /*decode_zcl_time_in_minutes*/

static void
cluster_desc_free(gpointer p, gpointer user_data _U_)
{
    g_free(p);
}

static void
zbee_shutdown(void)
{
    g_list_foreach(acluster_desc, cluster_desc_free, NULL);
    g_list_free(acluster_desc);
}

/**
 *ZigBee ZCL protocol registration routine.
 *
*/
void proto_register_zbee_zcl(void)
{
    guint i, j;

    static hf_register_info hf[] = {
        { &hf_zbee_zcl_fcf_frame_type,
            { "Frame Type", "zbee_zcl.type", FT_UINT8, BASE_HEX, VALS(zbee_zcl_frame_types),
                ZBEE_ZCL_FCF_FRAME_TYPE, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_mfr_spec,
            { "Manufacturer Specific", "zbee_zcl.ms", FT_BOOLEAN, 8, NULL,
                ZBEE_ZCL_FCF_MFR_SPEC, NULL, HFILL }},

        { &hf_zbee_zcl_fcf_dir,
            { "Direction", "zbee_zcl.dir", FT_BOOLEAN, 8, TFS(&tfs_s2c_c2s),
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

        { &hf_zbee_zcl_cmd_id_rsp,
          { "Response to Command", "zbee_zcl.cmd.id.rsp", FT_UINT8, BASE_HEX, NULL,
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

        { &hf_zbee_zcl_attr_bitmap8,
            { "Bitmap8",  "zbee_zcl.attr.bitmap8", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap16,
            { "Bitmap16", "zbee_zcl.attr.bitmap16", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap24,
            { "Bitmap24", "zbee_zcl.attr.bitmap24", FT_UINT24, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap32,
            { "Bitmap32", "zbee_zcl.attr.bitmap32", FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap40,
            { "Bitmap40", "zbee_zcl.attr.bitmap40", FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap48,
            { "Bitmap48", "zbee_zcl.attr.bitmap48", FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap56,
            { "Bitmap56", "zbee_zcl.attr.bitmap56", FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_bitmap64,
            { "Bitmap64", "zbee_zcl.attr.bitmap64", FT_UINT64, BASE_HEX, NULL, 0x0,
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

        { &hf_zbee_zcl_attr_uint40,
            { "Uint40", "zbee_zcl.attr.uint40", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint48,
            { "Uint48", "zbee_zcl.attr.uint48", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_uint56,
            { "Uint56", "zbee_zcl.attr.uint56", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
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

        { &hf_zbee_zcl_indicator,
            { "Indicator", "zbee_zcl.attr.ind", FT_UINT8, BASE_DEC, NULL,
                0X0, NULL, HFILL}},

        { &hf_zbee_zcl_index,
            { "Indicator", "zbee_zcl.attr.index", FT_UINT16, BASE_DEC, NULL, 0X0, NULL, HFILL}},

        { &hf_zbee_zcl_attr_access_ctrl,
            { "Attribute Access Control", "zbee_zcl.attr.access.ctrl", FT_UINT8, BASE_HEX, NULL, 0X0, NULL, HFILL}},

        { &hf_zbee_zcl_attr_dis,
            { "Discovery", "zbee_zcl.attr.dis", FT_UINT8, BASE_HEX, VALS(zbee_zcl_dis_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_cmd_start,
            {"Start Command", "zbee_zcl.cmd.start", FT_UINT8, BASE_HEX, NULL,
                0X0, NULL, HFILL}},

        { &hf_zbee_zcl_cmd_maxnum,
            {"Maximum Number", "zbee_zcl.cmd.maxnum", FT_UINT8, BASE_HEX, NULL, 0X0, NULL, HFILL}},

        { &hf_zbee_zcl_attr_cid,
            { "Cluster", "zbee_zcl.attr.cid", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_start,
            { "Start Attribute", "zbee_zcl.attr.start", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_maxnum,
            { "Maximum Number", "zbee_zcl.attr.maxnum", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_str,
            { "String", "zbee_zcl.attr.str", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_zcl_attr_ostr,
            { "Octet String",   "zbee_zcl.attr.ostr", FT_UINT_BYTES, SEP_COLON, NULL, 0x0,
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
                NULL, HFILL }}
    };

    /* ZCL subtrees */
    gint *ett[ZBEE_ZCL_NUM_TOTAL_ETT];

    ett[0] = &ett_zbee_zcl;
    ett[1] = &ett_zbee_zcl_fcf;
    j = ZBEE_ZCL_NUM_INDIVIDUAL_ETT;

    /* initialize attribute subtree types */
    for ( i = 0; i < ZBEE_ZCL_NUM_ATTR_ETT; i++, j++) {
        ett_zbee_zcl_attr[i] = -1;
        ett[j] = &ett_zbee_zcl_attr[i];
    }


    for(i=0; i<ZBEE_ZCL_NUM_IND_FIELD; i++){
        ett_zbee_zcl_sel[i] = -1;
    }

    for ( i = 0; i < ZBEE_ZCL_NUM_ARRAY_ELEM_ETT; i++, j++ ) {
        ett_zbee_zcl_array_elements[i] = -1;
        ett[j] = &ett_zbee_zcl_array_elements[i];
    }

    static ei_register_info ei[] = {
        { &ei_cfg_rpt_rsp_short_non_success,
          { "zbee_zcl.cfg_rpt_rsp_short_non_success", PI_PROTOCOL, PI_WARN,
            "Non-success response without full status records", EXPFILL }},
        { &ei_zbee_zero_length_element,
          { "zbee_zcl.zero_length_element", PI_PROTOCOL, PI_ERROR,
            "Element has zero length", EXPFILL }},
    };

    expert_module_t *expert_zbee_zcl;

    /* Register ZigBee ZCL protocol with Wireshark. */
    proto_zbee_zcl = proto_register_protocol("ZigBee Cluster Library", "ZigBee ZCL", "zbee_zcl");
    proto_register_field_array(proto_zbee_zcl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_zbee_zcl = expert_register_protocol(proto_zbee_zcl);
    expert_register_field_array(expert_zbee_zcl, ei, array_length(ei));

    /* Register the ZCL dissector and subdissector list. */
    zbee_zcl_dissector_table = register_dissector_table("zbee.zcl.cluster", "ZigBee ZCL Cluster ID", proto_zbee_zcl, FT_UINT16, BASE_HEX);
    register_dissector(ZBEE_PROTOABBREV_ZCL, dissect_zbee_zcl, proto_zbee_zcl);

    register_shutdown_routine(zbee_shutdown);
} /* proto_register_zbee_zcl */

/**
 *Finds the dissectors used in this module.
 *
*/
void proto_reg_handoff_zbee_zcl(void)
{
    dissector_handle_t   zbee_zcl_handle;

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
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_RS,    zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_GP,    zbee_zcl_handle);
    dissector_add_uint("zbee.profile", ZBEE_PROFILE_ZLL,   zbee_zcl_handle);

    dissector_add_uint("zbee.profile", ZBEE_PROFILE_C4_CL, zbee_zcl_handle);
} /* proto_reg_handoff_zbee_zcl */

/**
 *Register the specific cluster.
 *
 *@param  proto_abbrev Protocol abbreviation
 *@param  proto dissector
 *@param  ett proto (not used at the moment)
 *@param  cluster_id cluster identification
 *@param  mfr_code manufacturer code.
 *@param  hf_attr_server_id cluster-specific server attribute ID field.
 *@param  hf_attr_client_id cluster-specific client attribute ID field.
 *@param  hf_cmd_rx_id cluster-specific client-to-server command ID field, or -1.
 *@param  hf_cmd_tx_id cluster-specific server-to-client command ID field, or -1.
 *@param  fn_attr_data specific cluster attribute data decode function
*/
void
zbee_zcl_init_cluster(const char *proto_abbrev, int proto, gint ett, guint16 cluster_id, guint16 mfr_code, int hf_attr_server_id, int hf_attr_client_id, int hf_cmd_rx_id, int hf_cmd_tx_id, zbee_zcl_fn_attr_data fn_attr_data)
{
    zbee_zcl_cluster_desc *cluster_desc;
    dissector_handle_t dissector_handle;

    /* Register the dissector with the ZigBee application dissectors. */
    dissector_handle = find_dissector(proto_abbrev);
    dissector_add_uint("zbee.zcl.cluster", ZCL_CLUSTER_MFR_KEY(cluster_id, mfr_code), dissector_handle);

    /* Allocate a cluster descriptor */
    cluster_desc = g_new(zbee_zcl_cluster_desc, 1);

    /* Initialize the cluster descriptor */
    cluster_desc->proto_id = proto;
    cluster_desc->proto = find_protocol_by_id(proto);
    cluster_desc->name = proto_get_protocol_short_name(cluster_desc->proto);
    cluster_desc->ett = ett;
    cluster_desc->cluster_id = cluster_id;
    cluster_desc->mfr_code = mfr_code;
    cluster_desc->hf_attr_server_id = hf_attr_server_id;
    cluster_desc->hf_attr_client_id = hf_attr_client_id;
    cluster_desc->hf_cmd_rx_id = hf_cmd_rx_id;
    cluster_desc->hf_cmd_tx_id = hf_cmd_tx_id;
    cluster_desc->fn_attr_data = fn_attr_data;

    /* Add the cluster descriptor to the list */
    acluster_desc = g_list_append(acluster_desc, cluster_desc);
}

/**
 *Retrieves the registered specific cluster manufacturer descriptor.
 *
 *@param  cluster_id cluster identification
 *@param  mfr_code manufacturer code
 *@return cluster descriptor pointer
*/
static zbee_zcl_cluster_desc
*zbee_zcl_get_cluster_desc(guint16 cluster_id, guint16 mfr_code)
{
    GList *gl;
    gl = acluster_desc;

    while (gl) {
        zbee_zcl_cluster_desc *cluster_desc = (zbee_zcl_cluster_desc *)gl->data;
        if((cluster_desc->cluster_id == cluster_id) && (cluster_desc->mfr_code == mfr_code)) {
            return cluster_desc;
        }
        gl = gl->next;
    }

    return NULL;
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
