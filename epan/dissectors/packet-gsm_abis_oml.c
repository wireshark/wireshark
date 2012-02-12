/* packet-abis_oml.c
 * Routines for packet dissection of GSM A-bis OML (3GPP TS 12.21)
 * Copyright 2009-2011 by Harald Welte <laforge@gnumonks.org>
 * Copyright 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * based on A-bis OML code in OpenBSC
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/lapd_sapi.h>
#include <epan/prefs.h>

#include "packet-gsm_a_common.h"

#include <sys/types.h>

/* From openbsc/include/openbsc/abis_nm.h */

#define ABIS_OM_MDISC_FOM		0x80
#define ABIS_OM_MDISC_MMI		0x40
#define ABIS_OM_MDISC_TRAU		0x20
#define ABIS_OM_MDISC_MANUF		0x10
#define ABIS_OM_PLACEMENT_ONLY		0x80
#define ABIS_OM_PLACEMENT_FIRST 	0x40
#define ABIS_OM_PLACEMENT_MIDDLE	0x20
#define ABIS_OM_PLACEMENT_LAST		0x10

/* Section 9.1: Message Types */
enum abis_nm_msgtype {
	/* SW Download Management Messages */
	NM_MT_LOAD_INIT			= 0x01,
	NM_MT_LOAD_INIT_ACK,
	NM_MT_LOAD_INIT_NACK,
	NM_MT_LOAD_SEG,
	NM_MT_LOAD_SEG_ACK,
	NM_MT_LOAD_ABORT,
	NM_MT_LOAD_END,
	NM_MT_LOAD_END_ACK,
	NM_MT_LOAD_END_NACK,
	NM_MT_SW_ACT_REQ,		/* BTS->BSC */
	NM_MT_SW_ACT_REQ_ACK,
	NM_MT_SW_ACT_REQ_NACK,
	NM_MT_ACTIVATE_SW,		/* BSC->BTS */
	NM_MT_ACTIVATE_SW_ACK,
	NM_MT_ACTIVATE_SW_NACK,
	NM_MT_SW_ACTIVATED_REP,		/* 0x10 */
	/* A-bis Interface Management Messages */
	NM_MT_ESTABLISH_TEI		= 0x21,
	NM_MT_ESTABLISH_TEI_ACK,
	NM_MT_ESTABLISH_TEI_NACK,
	NM_MT_CONN_TERR_SIGN,
	NM_MT_CONN_TERR_SIGN_ACK,
	NM_MT_CONN_TERR_SIGN_NACK,
	NM_MT_DISC_TERR_SIGN,
	NM_MT_DISC_TERR_SIGN_ACK,
	NM_MT_DISC_TERR_SIGN_NACK,
	NM_MT_CONN_TERR_TRAF,
	NM_MT_CONN_TERR_TRAF_ACK,
	NM_MT_CONN_TERR_TRAF_NACK,
	NM_MT_DISC_TERR_TRAF,
	NM_MT_DISC_TERR_TRAF_ACK,
	NM_MT_DISC_TERR_TRAF_NACK,
	/* Transmission Management Messages */
	NM_MT_CONN_MDROP_LINK		= 0x31,
	NM_MT_CONN_MDROP_LINK_ACK,
	NM_MT_CONN_MDROP_LINK_NACK,
	NM_MT_DISC_MDROP_LINK,
	NM_MT_DISC_MDROP_LINK_ACK,
	NM_MT_DISC_MDROP_LINK_NACK,
	/* Air Interface Management Messages */
	NM_MT_SET_BTS_ATTR		= 0x41,
	NM_MT_SET_BTS_ATTR_ACK,
	NM_MT_SET_BTS_ATTR_NACK,
	NM_MT_SET_RADIO_ATTR,
	NM_MT_SET_RADIO_ATTR_ACK,
	NM_MT_SET_RADIO_ATTR_NACK,
	NM_MT_SET_CHAN_ATTR,
	NM_MT_SET_CHAN_ATTR_ACK,
	NM_MT_SET_CHAN_ATTR_NACK,
	/* Test Management Messages */
	NM_MT_PERF_TEST			= 0x51,
	NM_MT_PERF_TEST_ACK,
	NM_MT_PERF_TEST_NACK,
	NM_MT_TEST_REP,
	NM_MT_SEND_TEST_REP,
	NM_MT_SEND_TEST_REP_ACK,
	NM_MT_SEND_TEST_REP_NACK,
	NM_MT_STOP_TEST,
	NM_MT_STOP_TEST_ACK,
	NM_MT_STOP_TEST_NACK,
	/* State Management and Event Report Messages */
	NM_MT_STATECHG_EVENT_REP	= 0x61,
	NM_MT_FAILURE_EVENT_REP,
	NM_MT_STOP_EVENT_REP,
	NM_MT_STOP_EVENT_REP_ACK,
	NM_MT_STOP_EVENT_REP_NACK,
	NM_MT_REST_EVENT_REP,
	NM_MT_REST_EVENT_REP_ACK,
	NM_MT_REST_EVENT_REP_NACK,
	NM_MT_CHG_ADM_STATE,
	NM_MT_CHG_ADM_STATE_ACK,
	NM_MT_CHG_ADM_STATE_NACK,
	NM_MT_CHG_ADM_STATE_REQ,
	NM_MT_CHG_ADM_STATE_REQ_ACK,
	NM_MT_CHG_ADM_STATE_REQ_NACK,
	NM_MT_REP_OUTST_ALARMS		= 0x93,
	NM_MT_REP_OUTST_ALARMS_ACK,
	NM_MT_REP_OUTST_ALARMS_NACK,
	/* Equipment Management Messages */
	NM_MT_CHANGEOVER		= 0x71,
	NM_MT_CHANGEOVER_ACK,
	NM_MT_CHANGEOVER_NACK,
	NM_MT_OPSTART,
	NM_MT_OPSTART_ACK,
	NM_MT_OPSTART_NACK,
	NM_MT_REINIT,
	NM_MT_REINIT_ACK,
	NM_MT_REINIT_NACK,
	NM_MT_SET_SITE_OUT,		/* BS11: get alarm ?!? */
	NM_MT_SET_SITE_OUT_ACK,
	NM_MT_SET_SITE_OUT_NACK,
	NM_MT_CHG_HW_CONF		= 0x90,
	NM_MT_CHG_HW_CONF_ACK,
	NM_MT_CHG_HW_CONF_NACK,
	/* Measurement Management Messages */
	NM_MT_MEAS_RES_REQ		= 0x8a,
	NM_MT_MEAS_RES_RESP,
	NM_MT_STOP_MEAS,
	NM_MT_START_MEAS,
	/* Other Messages */
	NM_MT_GET_ATTR			= 0x81,
	NM_MT_GET_ATTR_RESP,
	NM_MT_GET_ATTR_NACK,
	NM_MT_SET_ALARM_THRES,
	NM_MT_SET_ALARM_THRES_ACK,
	NM_MT_SET_ALARM_THRES_NACK,

	NM_MT_IPACC_RESTART		= 0x87,
	NM_MT_IPACC_RESTART_ACK,
};

enum abis_nm_msgtype_bs11 {
	NM_MT_BS11_RESET_RESOURCE	= 0x74,

	NM_MT_BS11_BEGIN_DB_TX		= 0xa3,
	NM_MT_BS11_BEGIN_DB_TX_ACK,
	NM_MT_BS11_BEGIN_DB_TX_NACK,
	NM_MT_BS11_END_DB_TX		= 0xa6,
	NM_MT_BS11_END_DB_TX_ACK,
	NM_MT_BS11_END_DB_TX_NACK,
	NM_MT_BS11_CREATE_OBJ		= 0xa9,
	NM_MT_BS11_CREATE_OBJ_ACK,
	NM_MT_BS11_CREATE_OBJ_NACK,
	NM_MT_BS11_DELETE_OBJ		= 0xac,
	NM_MT_BS11_DELETE_OBJ_ACK,
	NM_MT_BS11_DELETE_OBJ_NACK,

	NM_MT_BS11_SET_ATTR		= 0xd0,
	NM_MT_BS11_SET_ATTR_ACK,
	NM_MT_BS11_SET_ATTR_NACK,
	NM_MT_BS11_LMT_SESSION		= 0xdc,

	NM_MT_BS11_GET_STATE		= 0xe3,
	NM_MT_BS11_GET_STATE_ACK,
	NM_MT_BS11_LMT_LOGON		= 0xe5,
	NM_MT_BS11_LMT_LOGON_ACK,
	NM_MT_BS11_RESTART		= 0xe7,
	NM_MT_BS11_RESTART_ACK,
	NM_MT_BS11_DISCONNECT		= 0xe9,
	NM_MT_BS11_DISCONNECT_ACK,
	NM_MT_BS11_LMT_LOGOFF		= 0xec,
	NM_MT_BS11_LMT_LOGOFF_ACK,
	NM_MT_BS11_RECONNECT		= 0xf1,
	NM_MT_BS11_RECONNECT_ACK,
};

enum abis_nm_msgtype_ipacc {
	NM_MT_IPACC_RSL_CONNECT		= 0xe0,
	NM_MT_IPACC_RSL_CONNECT_ACK,
	NM_MT_IPACC_RSL_CONNECT_NACK,
	NM_MT_IPACC_RSL_DISCONNECT	= 0xe3,
	NM_MT_IPACC_RSL_DISCONNECT_ACK,
	NM_MT_IPACC_RSL_DISCONNECT_NACK,
	NM_MT_IPACC_CONN_TRAF		= 0xe6,
	NM_MT_IPACC_CONN_TRAF_ACK,
	NM_MT_IPACC_CONN_TRAF_NACK,
	NM_MT_IPACC_DISC_TRAF		= 0xe9,
	NM_MT_IPACC_DISC_TRAF_ACK,
	NM_MT_IPACC_DISC_TRAF_NACK,
	NM_MT_IPACC_DEF_BOOT_SW		= 0xec,
	NM_MT_IPACC_DEF_BOOT_SW_ACK,
	NM_MT_IPACC_DEF_BOOT_SW_NACK,
	NM_MT_IPACC_SET_NVATTR		= 0xef,
	NM_MT_IPACC_SET_NVATTR_ACK,
	NM_MT_IPACC_SET_NVATTR_NACK,
	NM_MT_IPACC_GET_NVATTR		= 0xf2,
	NM_MT_IPACC_GET_NVATTR_ACK,
	NM_MT_IPACC_GET_NVATTR_NACK,
	NM_MT_IPACC_SET_ATTR		= 0xf5,
	NM_MT_IPACC_SET_ATTR_ACK,
	NM_MT_IPACC_SET_ATTR_NACK,
	NM_MT_IPACC_ATTR_CHG_EVT	= 0xf8,
	NM_MT_IPACC_SW_DEACT		= 0xf9,
	NM_MT_IPACC_SW_DEACT_ACK,
	NM_MT_IPACC_SW_DEACT_NACK,
	NM_MT_IPACC_MEAS_RES_REQ_NACK	= 0xfc,
	NM_MT_IPACC_START_MEAS_NACK,
	NM_MT_IPACC_STOP_MEAS_NACK,
};

enum abis_nm_bs11_cell_alloc {
	NM_BS11_CANR_GSM	= 0x00,
	NM_BS11_CANR_DCS1800	= 0x01,
};

/* Section 9.2: Object Class */
enum abis_nm_obj_class {
	NM_OC_SITE_MANAGER		= 0x00,
	NM_OC_BTS,
	NM_OC_RADIO_CARRIER,
	NM_OC_CHANNEL,
	NM_OC_BASEB_TRANSC,
	/* RFU: 05-FE */
	NM_OC_BS11_ADJC			= 0xa0,
	NM_OC_BS11_HANDOVER		= 0xa1,
	NM_OC_BS11_PWR_CTRL		= 0xa2,
	NM_OC_BS11_BTSE			= 0xa3,		/* LMT? */
	NM_OC_BS11_RACK			= 0xa4,
	NM_OC_BS11			= 0xa5,		/* 01: ALCO */
	NM_OC_BS11_TEST			= 0xa6,
	NM_OC_BS11_ENVABTSE		= 0xa8,
	NM_OC_BS11_BPORT		= 0xa9,

	NM_OC_GPRS_NSE			= 0xf0,
	NM_OC_GPRS_CELL			= 0xf1,
	NM_OC_GPRS_NSVC0		= 0xf2,
	NM_OC_GPRS_NSVC1		= 0xf3,

	NM_OC_NULL			= 0xff,
};

/* Section 9.4: Attributes */
enum abis_nm_attr {
	NM_ATT_ABIS_CHANNEL	= 0x01,
	NM_ATT_ADD_INFO,
	NM_ATT_ADD_TEXT,
	NM_ATT_ADM_STATE,
	NM_ATT_ARFCN_LIST,
	NM_ATT_AUTON_REPORT,
	NM_ATT_AVAIL_STATUS,
	NM_ATT_BCCH_ARFCN,
	NM_ATT_BSIC,
	NM_ATT_BTS_AIR_TIMER,
	NM_ATT_CCCH_L_I_P,
	NM_ATT_CCCH_L_T,
	NM_ATT_CHAN_COMB,
	NM_ATT_CONN_FAIL_CRIT,
	NM_ATT_DEST,
	/* res */
	NM_ATT_EVENT_TYPE	= 0x11, /* BS11: file data ?!? */
	NM_ATT_FILE_ID,
	NM_ATT_FILE_VERSION,
	NM_ATT_GSM_TIME,
	NM_ATT_HSN,
	NM_ATT_HW_CONFIG,
	NM_ATT_HW_DESC,
	NM_ATT_INTAVE_PARAM,
	NM_ATT_INTERF_BOUND,
	NM_ATT_LIST_REQ_ATTR,
	NM_ATT_MAIO,
	NM_ATT_MANUF_STATE,
	NM_ATT_MANUF_THRESH,
	NM_ATT_MANUF_ID,
	NM_ATT_MAX_TA,
	NM_ATT_MDROP_LINK,	/* 0x20 */
	NM_ATT_MDROP_NEXT,
	NM_ATT_NACK_CAUSES,
	NM_ATT_NY1,
	NM_ATT_OPER_STATE,
	NM_ATT_OVERL_PERIOD,
	NM_ATT_PHYS_CONF,
	NM_ATT_POWER_CLASS,
	NM_ATT_POWER_THRESH,
	NM_ATT_PROB_CAUSE,
	NM_ATT_RACH_B_THRESH,
	NM_ATT_LDAVG_SLOTS,
	NM_ATT_RAD_SUBC,
	NM_ATT_RF_MAXPOWR_R,
	NM_ATT_SITE_INPUTS,
	NM_ATT_SITE_OUTPUTS,
	NM_ATT_SOURCE,		/* 0x30 */
	NM_ATT_SPEC_PROB,
	NM_ATT_START_TIME,
	NM_ATT_T200,
	NM_ATT_TEI,
	NM_ATT_TEST_DUR,
	NM_ATT_TEST_NO,
	NM_ATT_TEST_REPORT,
	NM_ATT_VSWR_THRESH,
	NM_ATT_WINDOW_SIZE,
	/* Res  */
	NM_ATT_BS11_RSSI_OFFS	= 0x3d,
	NM_ATT_BS11_TXPWR	= 0x3e,
	NM_ATT_BS11_DIVERSITY	= 0x3f,
	/* Res  */
	NM_ATT_TSC		= 0x40,
	NM_ATT_SW_CONFIG,
	NM_ATT_SW_DESCR,
	NM_ATT_SEVERITY,
	NM_ATT_GET_ARI,
	NM_ATT_HW_CONF_CHG,
	NM_ATT_OUTST_ALARM,
	NM_ATT_FILE_DATA,
	NM_ATT_MEAS_RES,
	NM_ATT_MEAS_TYPE,
};

enum abis_nm_attr_bs11 {
	NM_ATT_BS11_OM_LAPD_REL_TIMER	= 0x02,
	NM_ATT_BS11_EMERG_TIMER1	= 0x42,
	NM_ATT_BS11_EMERG_TIMER2	= 0x44,
	NM_ATT_BS11_ESN_FW_CODE_NO	= 0x4c,
	NM_ATT_BS11_ESN_HW_CODE_NO	= 0x4f,

	NM_ATT_BS11_FILE_DATA		= NM_ATT_EVENT_TYPE,

	NM_ATT_BS11_ESN_PCB_SERIAL	= 0x55,
	NM_ATT_BS11_EXCESSIVE_DISTANCE	= 0x58,

	NM_ATT_BS11_ALL_TEST_CATG	= 0x60,
	NM_ATT_BS11_BTSLS_HOPPING,
	NM_ATT_BS11_CELL_ALLOC_NR,
	NM_ATT_BS11_CELL_GLOBAL_ID,
	NM_ATT_BS11_ENA_INTERF_CLASS	= 0x66,
	NM_ATT_BS11_ENA_INT_INTEC_HANDO	= 0x67,
	NM_ATT_BS11_ENA_INT_INTRC_HANDO	= 0x68,
	NM_ATT_BS11_ENA_MS_PWR_CTRL	= 0x69,
	NM_ATT_BS11_ENA_PWR_BDGT_HO	= 0x6a,
	NM_ATT_BS11_ENA_PWR_CTRL_RLFW	= 0x6b,
	NM_ATT_BS11_ENA_RXLEV_HO	= 0x6c,
	NM_ATT_BS11_ENA_RXQUAL_HO	= 0x6d,
	NM_ATT_BS11_FACCH_QUAL		= 0x6e,

	NM_ATT_BS11_RF_RES_IND_PER	= 0x8f,

	NM_ATT_BS11_RX_LEV_MIN_CELL	= 0x90,
	NM_ATT_BS11_ABIS_EXT_TIME	= 0x91,
	NM_ATT_BS11_TIMER_HO_REQUEST	= 0x92,
	NM_ATT_BS11_TIMER_NCELL		= 0x93,
	NM_ATT_BS11_TSYNC		= 0x94,
	NM_ATT_BS11_TTRAU		= 0x95,
	NM_ATT_BS11_EMRG_CFG_MEMBER	= 0x9b,
	NM_ATT_BS11_TRX_AREA		= 0x9f,

	NM_ATT_BS11_BCCH_RECONF		= 0xd7,
	NM_ATT_BS11_BIT_ERR_THESH	= 0xa0,
	NM_ATT_BS11_BOOT_SW_VERS	= 0xa1,
	NM_ATT_BS11_CCLK_ACCURACY	= 0xa3,
	NM_ATT_BS11_CCLK_TYPE		= 0xa4,
	NM_ATT_BS11_INP_IMPEDANCE	= 0xaa,
	NM_ATT_BS11_L1_PROT_TYPE	= 0xab,
	NM_ATT_BS11_LINE_CFG		= 0xac,
	NM_ATT_BS11_LI_PORT_1		= 0xad,
	NM_ATT_BS11_LI_PORT_2		= 0xae,

	NM_ATT_BS11_L1_REM_ALM_TYPE	= 0xb0,
	NM_ATT_BS11_SW_LOAD_INTENDED	= 0xbb,
	NM_ATT_BS11_SW_LOAD_SAFETY	= 0xbc,
	NM_ATT_BS11_SW_LOAD_STORED	= 0xbd,

	NM_ATT_BS11_VENDOR_NAME		= 0xc1,
	NM_ATT_BS11_HOPPING_MODE	= 0xc5,
	NM_ATT_BS11_LMT_LOGON_SESSION	= 0xc6,
	NM_ATT_BS11_LMT_LOGIN_TIME	= 0xc7,
	NM_ATT_BS11_LMT_USER_ACC_LEV	= 0xc8,
	NM_ATT_BS11_LMT_USER_NAME	= 0xc9,

	NM_ATT_BS11_L1_CONTROL_TS	= 0xd8,
	NM_ATT_BS11_RADIO_MEAS_GRAN	= 0xdc,	/* in SACCH multiframes */
	NM_ATT_BS11_RADIO_MEAS_REP	= 0xdd,

	NM_ATT_BS11_SH_LAPD_INT_TIMER	= 0xe8,

	NM_ATT_BS11_BTS_STATE		= 0xf0,
	NM_ATT_BS11_E1_STATE		= 0xf1,
	NM_ATT_BS11_PLL			= 0xf2,
	NM_ATT_BS11_RX_OFFSET		= 0xf3,
	NM_ATT_BS11_ANT_TYPE		= 0xf4,
	NM_ATT_BS11_PLL_MODE		= 0xfc,
	NM_ATT_BS11_PASSWORD		= 0xfd,
};

enum abis_nm_attr_ipa {
	NM_ATT_IPACC_DST_IP		= 0x80,
	NM_ATT_IPACC_DST_IP_PORT	= 0x81,
	NM_ATT_IPACC_SSRC		= 0x82,		/* RTP Sync Source */
	NM_ATT_IPACC_RTP_PAYLD_TYPE	= 0x83,
	NM_ATT_IPACC_BASEB_ID		= 0x84,
	NM_ATT_IPACC_STREAM_ID		= 0x85,
	NM_ATT_IPACC_NV_FLAGS		= 0x86,
	NM_ATT_IPACC_FREQ_CTRL		= 0x87,
	NM_ATT_IPACC_PRIM_OML_CFG	= 0x88,
	NM_ATT_IPACC_SEC_OML_CFG	= 0x89,
	NM_ATT_IPACC_IP_IF_CFG		= 0x8a,		/* IP interface */
	NM_ATT_IPACC_IP_GW_CFG		= 0x8b,		/* IP gateway */
	NM_ATT_IPACC_IN_SERV_TIME	= 0x8c,
	NM_ATT_IPACC_TRX_BTS_ASS	= 0x8d,
	NM_ATT_IPACC_LOCATION		= 0x8e,		/* string describing location */
	NM_ATT_IPACC_PAGING_CFG		= 0x8f,
	NM_ATT_IPACC_FILE_DATA		= 0x90,
	NM_ATT_IPACC_UNIT_ID		= 0x91,		/* Site/BTS/TRX */
	NM_ATT_IPACC_PARENT_UNIT_ID	= 0x92,
	NM_ATT_IPACC_UNIT_NAME		= 0x93,		/* default: nbts-<mac-as-string> */
	NM_ATT_IPACC_SNMP_CFG		= 0x94,
	NM_ATT_IPACC_PRIM_OML_CFG_LIST	= 0x95,
	NM_ATT_IPACC_PRIM_OML_FB_TOUT	= 0x96,		/* fallback timeout */
	NM_ATT_IPACC_CUR_SW_CFG		= 0x97,
	NM_ATT_IPACC_TIMING_BUS		= 0x98,
	NM_ATT_IPACC_CGI		= 0x99,		/* Cell Global ID */
	NM_ATT_IPACC_RAC		= 0x9a,
	NM_ATT_IPACC_OBJ_VERSION	= 0x9b,
	NM_ATT_IPACC_GPRS_PAGING_CFG	= 0x9c,
	NM_ATT_IPACC_NSEI		= 0x9d,
	NM_ATT_IPACC_BVCI		= 0x9e,
	NM_ATT_IPACC_NSVCI		= 0x9f,
	NM_ATT_IPACC_NS_CFG		= 0xa0,
	NM_ATT_IPACC_BSSGP_CFG		= 0xa1,
	NM_ATT_IPACC_NS_LINK_CFG	= 0xa2,
	NM_ATT_IPACC_RLC_CFG		= 0xa3,
	NM_ATT_IPACC_ALM_THRESH_LIST	= 0xa4,
	NM_ATT_IPACC_MONIT_VAL_LIST	= 0xa5,
	NM_ATT_IPACC_TIB_CONTROL	= 0xa6,
	NM_ATT_IPACC_SUPP_FEATURES	= 0xa7,
	NM_ATT_IPACC_CODING_SCHEMES	= 0xa8,
	NM_ATT_IPACC_RLC_CFG_2		= 0xa9,
	NM_ATT_IPACC_HEARTB_TOUT	= 0xaa,
	NM_ATT_IPACC_UPTIME		= 0xab,
	NM_ATT_IPACC_RLC_CFG_3		= 0xac,
	NM_ATT_IPACC_SSL_CFG		= 0xad,
	NM_ATT_IPACC_SEC_POSSIBLE	= 0xae,
	NM_ATT_IPACC_IML_SSL_STATE	= 0xaf,
	NM_ATT_IPACC_REVOC_DATE		= 0xb0,
};

/* Section 9.4.4: Administrative State */
enum abis_nm_adm_state {
	NM_STATE_LOCKED		= 0x01,
	NM_STATE_UNLOCKED	= 0x02,
	NM_STATE_SHUTDOWN	= 0x03,
	NM_STATE_NULL		= 0xff,
};

/* Section 9.4.13: Channel Combination */
enum abis_nm_chan_comb {
	NM_CHANC_TCHFull	= 0x00,
	NM_CHANC_TCHHalf	= 0x01,
	NM_CHANC_TCHHalf2	= 0x02,
	NM_CHANC_SDCCH		= 0x03,
	NM_CHANC_mainBCCH	= 0x04,
	NM_CHANC_BCCHComb	= 0x05,
	NM_CHANC_BCCH		= 0x06,
	NM_CHANC_BCCH_CBCH	= 0x07,
	NM_CHANC_SDCCH_CBCH	= 0x08,
};

/* Section 9.4.16: Event Type */
enum abis_nm_event_type {
	NM_EVT_COMM_FAIL	= 0x00,
	NM_EVT_QOS_FAIL		= 0x01,
	NM_EVT_PROC_FAIL	= 0x02,
	NM_EVT_EQUIP_FAIL	= 0x03,
	NM_EVT_ENV_FAIL		= 0x04,
};

/* Section: 9.4.63: Perceived Severity */
enum abis_nm_severity {
	NM_SEVER_CEASED		= 0x00,
	NM_SEVER_CRITICAL	= 0x01,
	NM_SEVER_MAJOR		= 0x02,
	NM_SEVER_MINOR		= 0x03,
	NM_SEVER_WARNING	= 0x04,
	NM_SEVER_INDETERMINATE	= 0x05,
};

/* Section 9.4.43: Probable Cause Type */
enum abis_nm_pcause_type {
	NM_PCAUSE_T_X721	= 0x01,
	NM_PCAUSE_T_GSM		= 0x02,
	NM_PCAUSE_T_MANUF	= 0x03,
};

/* Section 9.4.36: NACK Causes */
enum abis_nm_nack_cause {
	/* General Nack Causes */
	NM_NACK_INCORR_STRUCT		= 0x01,
	NM_NACK_MSGTYPE_INVAL		= 0x02,
	NM_NACK_OBJCLASS_INVAL		= 0x05,
	NM_NACK_OBJCLASS_NOTSUPP	= 0x06,
	NM_NACK_BTSNR_UNKN		= 0x07,
	NM_NACK_TRXNR_UNKN		= 0x08,
	NM_NACK_OBJINST_UNKN		= 0x09,
	NM_NACK_ATTRID_INVAL		= 0x0c,
	NM_NACK_ATTRID_NOTSUPP		= 0x0d,
	NM_NACK_PARAM_RANGE		= 0x0e,
	NM_NACK_ATTRLIST_INCONSISTENT	= 0x0f,
	NM_NACK_SPEC_IMPL_NOTSUPP	= 0x10,
	NM_NACK_CANT_PERFORM		= 0x11,
	/* Specific Nack Causes */
	NM_NACK_RES_NOTIMPL		= 0x19,
	NM_NACK_RES_NOTAVAIL		= 0x1a,
	NM_NACK_FREQ_NOTAVAIL		= 0x1b,
	NM_NACK_TEST_NOTSUPP		= 0x1c,
	NM_NACK_CAPACITY_RESTR		= 0x1d,
	NM_NACK_PHYSCFG_NOTPERFORM	= 0x1e,
	NM_NACK_TEST_NOTINIT		= 0x1f,
	NM_NACK_PHYSCFG_NOTRESTORE	= 0x20,
	NM_NACK_TEST_NOSUCH		= 0x21,
	NM_NACK_TEST_NOSTOP		= 0x22,
	NM_NACK_MSGINCONSIST_PHYSCFG	= 0x23,
	NM_NACK_FILE_INCOMPLETE		= 0x25,
	NM_NACK_FILE_NOTAVAIL		= 0x26,
	NM_NACK_FILE_NOTACTIVATE	= 0x27,
	NM_NACK_REQ_NOT_GRANT		= 0x28,
	NM_NACK_WAIT			= 0x29,
	NM_NACK_NOTH_REPORT_EXIST	= 0x2a,
	NM_NACK_MEAS_NOTSUPP		= 0x2b,
	NM_NACK_MEAS_NOTSTART		= 0x2c,
};

/* Section 9.4.1 */
struct abis_nm_channel {
	guint8	attrib;
	guint8	bts_port;
	guint8	timeslot;
	guint8	subslot;
};

/* Siemens BS-11 specific objects in the SienemsHW (0xA5) object class */
enum abis_bs11_objtype {
	BS11_OBJ_ALCO		= 0x01,
	BS11_OBJ_BBSIG		= 0x02,	/* obj_class: 0,1 */
	BS11_OBJ_TRX1		= 0x03,	/* only DEACTIVATE TRX1 */
	BS11_OBJ_CCLK		= 0x04,
	BS11_OBJ_GPSU		= 0x06,
	BS11_OBJ_LI			= 0x07,
	BS11_OBJ_PA			= 0x09,	/* obj_class: 0, 1*/
};

enum abis_bs11_trx_power {
	BS11_TRX_POWER_GSM_2W	= 0x06,
	BS11_TRX_POWER_GSM_250mW= 0x07,
	BS11_TRX_POWER_GSM_80mW	= 0x08,
	BS11_TRX_POWER_GSM_30mW	= 0x09,
	BS11_TRX_POWER_DCS_3W	= 0x0a,
	BS11_TRX_POWER_DCS_1W6	= 0x0b,
	BS11_TRX_POWER_DCS_500mW= 0x0c,
	BS11_TRX_POWER_DCS_160mW= 0x0d,
};

enum abis_bs11_li_pll_mode {
	BS11_LI_PLL_LOCKED	= 2,
	BS11_LI_PLL_STANDALONE	= 3,
};

enum abis_bs11_phase {
	BS11_STATE_SOFTWARE_RQD		= 0x01,
	BS11_STATE_LOAD_SMU_INTENDED	= 0x11,
	BS11_STATE_LOAD_SMU_SAFETY	= 0x21,
	BS11_STATE_LOAD_FAILED		= 0x31,
	BS11_STATE_LOAD_DIAGNOSTIC	= 0x41,
	BS11_STATE_WARM_UP		= 0x51,
	BS11_STATE_WARM_UP_2		= 0x52,
	BS11_STATE_WAIT_MIN_CFG		= 0x62,
	BS11_STATE_MAINTENANCE		= 0x72,
	BS11_STATE_LOAD_MBCCU		= 0x92,
	BS11_STATE_WAIT_MIN_CFG_2	= 0xA2,
	BS11_STATE_NORMAL		= 0x03,
	BS11_STATE_ABIS_LOAD		= 0x13,
};

/* From openbsc/include/openbsc/tlv.h */
enum tlv_type {
	TLV_TYPE_UNKNOWN,
	TLV_TYPE_FIXED,
	TLV_TYPE_T,
	TLV_TYPE_TV,
	TLV_TYPE_TLV,
	TLV_TYPE_TL16V,
	TLV_TYPE_TLV16,
};

struct tlv_def {
	enum tlv_type type;
	guint8 fixed_len;
};

struct tlv_definition {
	struct tlv_def def[0xff];
};

enum abis_nm_ipacc_test_no {
	NM_IPACC_TESTNO_RLOOP_ANT	= 0x01,
	NM_IPACC_TESTNO_RLOOP_XCVR	= 0x02,
	NM_IPACC_TESTNO_FUNC_OBJ	= 0x03,
	NM_IPACC_TESTNO_CHAN_USAGE	= 0x40,
	NM_IPACC_TESTNO_BCCH_CHAN_USAGE	= 0x41,
	NM_IPACC_TESTNO_FREQ_SYNC	= 0x42,
	NM_IPACC_TESTNO_BCCH_INFO	= 0x43,
	NM_IPACC_TESTNO_TX_BEACON	= 0x44,
	NM_IPACC_TESTNO_SYSINFO_MONITOR	= 0x45,
	NM_IPACC_TESTNO_BCCCH_MONITOR	= 0x46,
};

/* first byte after length inside NM_ATT_TEST_REPORT */
enum abis_nm_ipacc_test_res {
	NM_IPACC_TESTRES_SUCCESS	= 0,
	NM_IPACC_TESTRES_TIMEOUT	= 1,
	NM_IPACC_TESTRES_NO_CHANS	= 2,
	NM_IPACC_TESTRES_PARTIAL	= 3,
	NM_IPACC_TESTRES_STOPPED	= 4,
};

/* internal IE inside NM_ATT_TEST_REPORT */
enum abis_nm_ipacc_testres_ie {
	NM_IPACC_TR_IE_FREQ_ERR_LIST	= 3,
	NM_IPACC_TR_IE_CHAN_USAGE	= 4,
	NM_IPACC_TR_IE_BCCH_INFO	= 6,
	NM_IPACC_TR_IE_RESULT_DETAILS	= 8,
	NM_IPACC_TR_IE_FREQ_ERR		= 18,
};

/* initialize the protocol and registered fields */
static int proto_abis_oml = -1;

/* OML header */
static int hf_oml_msg_disc = -1;
static int hf_oml_placement = -1;
static int hf_oml_sequence = -1;
static int hf_oml_length = -1;
/* FOM header */
static int hf_oml_fom_msgtype = -1;
static int hf_oml_fom_objclass = -1;
static int hf_oml_fom_inst_bts = -1;
static int hf_oml_fom_inst_trx = -1;
static int hf_oml_fom_inst_ts = -1;
static int hf_oml_fom_attr_tag = -1;
static int hf_oml_fom_attr_len = -1;
static int hf_oml_fom_attr_val = -1;
/* FOM attributes */
static int hf_attr_adm_state = -1;
static int hf_attr_arfcn = -1;
static int hf_attr_oper_state = -1;
static int hf_attr_avail_state = -1;
static int hf_attr_event_type = -1;
static int hf_attr_severity = -1;
static int hf_attr_bcch_arfcn = -1;
static int hf_attr_bsic = -1;
static int hf_attr_test_no = -1;
static int hf_attr_tsc = -1;
static int hf_attr_tei = -1;
static int hf_attr_ach_btsp = -1;
static int hf_attr_ach_tslot = -1;
static int hf_attr_ach_sslot = -1;
static int hf_attr_gsm_time = -1;
static int hf_attr_chan_comb = -1;
static int hf_attr_hsn = -1;
static int hf_attr_maio = -1;
/* Ipaccess */
static int hf_oml_ipa_tres_attr_tag = -1;
static int hf_oml_ipa_tres_attr_len = -1;
static int hf_attr_ipa_test_res = -1;
static int hf_attr_ipa_tr_rxlev = -1;
static int hf_attr_ipa_tr_b_rxlev = -1;
static int hf_attr_ipa_tr_arfcn = -1;
static int hf_attr_ipa_tr_f_qual = -1;
static int hf_attr_ipa_tr_f_err = -1;
static int hf_attr_ipa_tr_rxqual = -1;
static int hf_attr_ipa_tr_frame_offs = -1;
static int hf_attr_ipa_tr_framenr_offs = -1;
static int hf_attr_ipa_tr_bsic = -1;
static int hf_attr_ipa_tr_cell_id = -1;
static int hf_attr_ipa_tr_si2 = -1;
static int hf_attr_ipa_tr_si2bis = -1;
static int hf_attr_ipa_tr_si2ter = -1;
static int hf_attr_ipa_tr_chan_desc = -1;
static int hf_attr_ipa_rsl_ip = -1;
static int hf_attr_ipa_rsl_port = -1;
static int hf_attr_ipa_prim_oml_ip = -1;
static int hf_attr_ipa_prim_oml_port = -1;
static int hf_attr_ipa_location_name = -1;
static int hf_attr_ipa_unit_id = -1;
static int hf_attr_ipa_unit_name = -1;
static int hf_attr_ipa_nv_flags = -1;
static int hf_attr_ipa_nv_mask = -1;
static int hf_attr_ipa_nsl_sport = -1;
static int hf_attr_ipa_nsl_daddr = -1;
static int hf_attr_ipa_nsl_dport = -1;
static int hf_attr_ipa_nsei = -1;
static int hf_attr_ipa_nsvci = -1;
static int hf_attr_ipa_bvci = -1;
static int hf_attr_ipa_rac = -1;

/* initialize the subtree pointers */
static int ett_oml = -1;
static int ett_oml_fom = -1;
static int ett_oml_fom_att = -1;

enum {
	OML_DIALECT_ETSI,
	OML_DIALECT_SIEMENS,
	OML_DIALECT_IPA,
};

/* which A-bis OML dialect to use (prefrence) */
static gint global_oml_dialect = OML_DIALECT_ETSI;

static proto_tree *top_tree;

/* TS 12.21 Chapter 8.1 / TS 08.59 */
static const value_string oml_msg_disc_vals[] = {
	{ ABIS_OM_MDISC_FOM,	"Formatted O&M" },
	{ ABIS_OM_MDISC_MMI,	"MMI Transfer" },
	{ ABIS_OM_MDISC_TRAU,	"TRAU O&M" },
	{ ABIS_OM_MDISC_MANUF,	"Manufacturer specific" },
	{ 0, NULL },
};

/* TS 12.21 Chapter 8.1.1 */
static const value_string oml_placement_vals[] = {
	{ ABIS_OM_PLACEMENT_ONLY,	"Only" },
	{ ABIS_OM_PLACEMENT_FIRST,	"First" },
	{ ABIS_OM_PLACEMENT_MIDDLE,	"Middle" },
	{ ABIS_OM_PLACEMENT_LAST,	"Last" },
	{ 0, NULL },
};

/* Standard Message Types as per TS 12.21 Chapter 9.2 */
static const value_string oml_fom_msgtype_vals[] = {
	{ NM_MT_LOAD_INIT,		"Software Load Init" },
	{ NM_MT_LOAD_INIT_ACK,		"Software Load Init ACK" },
	{ NM_MT_LOAD_INIT_NACK,		"Software Load Init NACK" },
	{ NM_MT_LOAD_SEG,		"Software Load Segment" },
	{ NM_MT_LOAD_SEG_ACK,		"Software Load Segment ACK" },
	{ NM_MT_LOAD_END,		"Software Load End" },
	{ NM_MT_LOAD_END_ACK,		"Software Load End ACK" },
	{ NM_MT_LOAD_END_NACK,		"Software Load End NACK" },
	{ NM_MT_SW_ACT_REQ,		"Software Activate Request" },
	{ NM_MT_SW_ACT_REQ_ACK,		"Software Activate Request ACK" },
	{ NM_MT_SW_ACT_REQ_NACK,	"Software Activate Request NACK" },
	{ NM_MT_ACTIVATE_SW,		"Activate Software" },
	{ NM_MT_ACTIVATE_SW_ACK,	"Activate Software ACK" },
	{ NM_MT_ACTIVATE_SW_NACK,	"Activate Software NACK" },
	{ NM_MT_SW_ACTIVATED_REP,	"Software Activated Report" },
	{ NM_MT_ESTABLISH_TEI,		"Establish TEI" },
	{ NM_MT_ESTABLISH_TEI_ACK,	"Establish TEI ACK" },
	{ NM_MT_ESTABLISH_TEI_NACK,	"Establish TEI NACK" },
	{ NM_MT_CONN_TERR_SIGN,		"Connect Terrestrial Signalling" },
	{ NM_MT_CONN_TERR_SIGN_ACK,	"Connect Terrestrial Signalling ACK" },
	{ NM_MT_CONN_TERR_SIGN_NACK,	"Connect Terrestrial Signalling NACK" },
	{ NM_MT_DISC_TERR_SIGN,		"Disconnect Terrestrial Signalling" },
	{ NM_MT_DISC_TERR_SIGN_ACK,	"Disconnect Terrestrial Signalling ACK" },
	{ NM_MT_DISC_TERR_SIGN_NACK,	"Disconnect Terrestrial Signalling NACK" },
	{ NM_MT_CONN_TERR_TRAF,		"Connect Terrestrial Traffic" },
	{ NM_MT_CONN_TERR_TRAF_ACK,	"Connect Terrestrial Traffic ACK" },
	{ NM_MT_CONN_TERR_TRAF_NACK,	"Connect Terrestrial Traffic NACK" },
	{ NM_MT_DISC_TERR_TRAF,		"Disconnect Terrestrial Traffic" },
	{ NM_MT_DISC_TERR_TRAF_ACK,	"Disconnect Terrestrial Traffic ACK" },
	{ NM_MT_DISC_TERR_TRAF_NACK,	"Disconnect Terrestrial Traffic NACK" },
	{ NM_MT_CONN_MDROP_LINK,	"Connect Multi-Drop Link" },
	{ NM_MT_CONN_MDROP_LINK_ACK,	"Connect Multi-Drop Link ACK" },
	{ NM_MT_CONN_MDROP_LINK_NACK,	"Connect Multi-Drop Link NACK" },
	{ NM_MT_DISC_MDROP_LINK,	"Disconnect Multi-Drop Link" },
	{ NM_MT_DISC_MDROP_LINK_ACK,	"Disconnect Multi-Drop Link ACK" },
	{ NM_MT_DISC_MDROP_LINK_NACK,	"Disconnect Multi-Drop Link NACK" },
	{ NM_MT_SET_BTS_ATTR,		"Set BTS Attributes" },
	{ NM_MT_SET_BTS_ATTR_ACK,	"Set BTS Attributes ACK" },
	{ NM_MT_SET_BTS_ATTR_NACK,	"Set BTS Attributes NACK" },
	{ NM_MT_SET_RADIO_ATTR,		"Set Radio Carrier Attributes" },
	{ NM_MT_SET_RADIO_ATTR_ACK,	"Set Radio Carrier Attributes ACK" },
	{ NM_MT_SET_RADIO_ATTR_NACK,	"Set Radio Carrier Attributes NACK" },
	{ NM_MT_SET_CHAN_ATTR,		"Set Channel Attributes" },
	{ NM_MT_SET_CHAN_ATTR_ACK,	"Set Channel Attributes ACK" },
	{ NM_MT_SET_CHAN_ATTR_NACK,	"Set Channel Attributes NACK" },
	{ NM_MT_PERF_TEST,		"Perform Test" },
	{ NM_MT_PERF_TEST_ACK,		"Perform Test ACK" },
	{ NM_MT_PERF_TEST_NACK,		"Perform Test NACK" },
	{ NM_MT_TEST_REP,		"Test Report" },
	{ NM_MT_SEND_TEST_REP,		"Send Test Report" },
	{ NM_MT_SEND_TEST_REP_ACK,	"Send Test Report ACK" },
	{ NM_MT_SEND_TEST_REP_NACK,	"Send Test Report NACK" },
	{ NM_MT_STOP_TEST,		"Stop Test" },
	{ NM_MT_STOP_TEST_ACK,		"Stop Test ACK" },
	{ NM_MT_STOP_TEST_NACK,		"Stop Test NACK" },
	{ NM_MT_STATECHG_EVENT_REP,	"State Changed Event Report" },
	{ NM_MT_FAILURE_EVENT_REP,	"Failure Event Report" },
	{ NM_MT_STOP_EVENT_REP,		"Stop Sending Event Reports" },
	{ NM_MT_STOP_EVENT_REP_ACK,	"Stop Sending Event Reports ACK" },
	{ NM_MT_STOP_EVENT_REP_NACK,	"Stop Sending Event Reports NACK" },
	{ NM_MT_REST_EVENT_REP,		"Restart Sending Event Reports" },
	{ NM_MT_REST_EVENT_REP_ACK,	"Restart Sending Event Reports ACK" },
	{ NM_MT_REST_EVENT_REP_NACK,	"Restart Sending Event Reports NACK" },
	{ NM_MT_CHG_ADM_STATE,		"Change Administrative State" },
	{ NM_MT_CHG_ADM_STATE_ACK,	"Change Administrative State ACK" },
	{ NM_MT_CHG_ADM_STATE_NACK,	"Change Administrative State NACK" },
	{ NM_MT_CHG_ADM_STATE_REQ,	"Change Administrative State Request" },
	{ NM_MT_CHG_ADM_STATE_REQ_ACK,	"Change Administrative State Request ACK" },
	{ NM_MT_CHG_ADM_STATE_REQ_NACK,	"Change Administrative State Request NACK" },
	{ NM_MT_REP_OUTST_ALARMS,	"Report Outstanding Alarms" },
	{ NM_MT_REP_OUTST_ALARMS_ACK,	"Report Outstanding Alarms ACK" },
	{ NM_MT_REP_OUTST_ALARMS_NACK,	"Report Outstanding Alarms NACK" },
	{ NM_MT_CHANGEOVER,		"Changeover" },
	{ NM_MT_CHANGEOVER_ACK,		"Changeover ACK" },
	{ NM_MT_CHANGEOVER_NACK,	"Changeover NACK" },
	{ NM_MT_OPSTART,		"Opstart" },
	{ NM_MT_OPSTART_ACK,		"Opstart ACK" },
	{ NM_MT_OPSTART_NACK,		"Opstart NACK" },
	{ NM_MT_REINIT,			"Reinitialize" },
	{ NM_MT_REINIT_ACK,		"Reinitialize ACK" },
	{ NM_MT_REINIT_NACK,		"Reinitialize NACK" },
	{ NM_MT_SET_SITE_OUT,		"Set Site Outputs" },
	{ NM_MT_SET_SITE_OUT_ACK,	"Set Site Outputs ACK" },
	{ NM_MT_SET_SITE_OUT_NACK,	"Set Site Outputs NACK" },
	{ NM_MT_CHG_HW_CONF,		"Change HW Configuration" },
	{ NM_MT_CHG_HW_CONF_ACK,	"Change HW Configuration ACK" },
	{ NM_MT_CHG_HW_CONF_NACK,	"Change HW Configuration NACK" },
	{ NM_MT_MEAS_RES_REQ,		"Measurement Result Request" },
	{ NM_MT_MEAS_RES_RESP,		"Measurement Result Response" },
	{ NM_MT_STOP_MEAS,		"Stop Measurement" },
	{ NM_MT_START_MEAS,		"Start Measurement" },
	{ NM_MT_GET_ATTR,		"Get Attributes" },
	{ NM_MT_GET_ATTR_RESP,		"Get Attributes Response" },
	{ NM_MT_GET_ATTR_NACK,		"Get Attributes NACK" },
	{ NM_MT_SET_ALARM_THRES,	"Set Alarm Threshold" },
	{ NM_MT_SET_ALARM_THRES_ACK,	"Set Alarm Threshold ACK" },
	{ NM_MT_SET_ALARM_THRES_NACK,	"Set Alarm Threshold NACK" },
	{ 0, NULL }
};

/* proprietary ip.access message types, not in the standard */
static const value_string oml_fom_msgtype_vals_ipa[] = {
	{ NM_MT_IPACC_RESTART,		"IPA Restart" },
	{ NM_MT_IPACC_RESTART_ACK,	"IPA Restart ACK" },
	{ NM_MT_IPACC_RSL_CONNECT,	"IPA RSL Connect" },
	{ NM_MT_IPACC_RSL_CONNECT_ACK,	"IPA RSL Connect ACK" },
	{ NM_MT_IPACC_RSL_CONNECT_NACK,	"IPA RSL Connect NACK" },
	{ NM_MT_IPACC_RSL_DISCONNECT,	"IPA RSL Disconnect" },
	{ NM_MT_IPACC_RSL_DISCONNECT_ACK, "IPA RSL Disconnect ACK" },
	{ NM_MT_IPACC_RSL_DISCONNECT_NACK, "IPA RSL Disconnect NACK" },
	{ NM_MT_IPACC_CONN_TRAF,	"IPA Connect Traffic" },
	{ NM_MT_IPACC_CONN_TRAF_ACK,	"IPA Connect Traffic ACK" },
	{ NM_MT_IPACC_CONN_TRAF_NACK,	"IPA Connect Traffic NACK" },
	{ NM_MT_IPACC_DISC_TRAF,	"IPA Disconnect Traffic" },
	{ NM_MT_IPACC_DISC_TRAF_ACK,	"IPA Disconnect Traffic ACK" },
	{ NM_MT_IPACC_DISC_TRAF_NACK,	"IPA Disconnect Traffic NACK" },
	{ NM_MT_IPACC_DEF_BOOT_SW,	"IPA Default Boot Software" },
	{ NM_MT_IPACC_DEF_BOOT_SW_ACK,	"IPA Default Boot Software ACK" },
	{ NM_MT_IPACC_DEF_BOOT_SW_NACK,	"IPA Default Boot Software NACK" },
	{ NM_MT_IPACC_SET_NVATTR,	"IPA Set NVRAM Attributes" },
	{ NM_MT_IPACC_SET_NVATTR_ACK,	"IPA Set NVRAM Attributes ACK" },
	{ NM_MT_IPACC_SET_NVATTR_NACK,	"IPA Set NVRAM Attributes NACK" },
	{ NM_MT_IPACC_GET_NVATTR,	"IPA Get NVRAM Attributes" },
	{ NM_MT_IPACC_GET_NVATTR_ACK,	"IPA Get NVRAM Attributes ACK" },
	{ NM_MT_IPACC_GET_NVATTR_NACK,	"IPA Get NVRAM Attributes NACK" },
	{ NM_MT_IPACC_SET_ATTR,		"IPA Set Attributes" },
	{ NM_MT_IPACC_SET_ATTR_ACK,	"IPA Set Attributes ACK" },
	{ NM_MT_IPACC_SET_ATTR_NACK,	"IPA Set Attributes NACK" },
	{ NM_MT_IPACC_ATTR_CHG_EVT,	"IPA Attribute Change Event" },
	{ NM_MT_IPACC_SW_DEACT,		"IPA Software Deactivate" },
	{ NM_MT_IPACC_SW_DEACT_ACK,	"IPA Software Deactivate ACK" },
	{ NM_MT_IPACC_SW_DEACT_NACK,	"IPA Software Deactivate NACK" },
	{ NM_MT_IPACC_MEAS_RES_REQ_NACK,"IPA Measurement Result Request NACK" },
	{ NM_MT_IPACC_START_MEAS_NACK,	"IPA Start Measurement NACK" },
	{ NM_MT_IPACC_STOP_MEAS_NACK,	"IPA Stop Measurement NACK" },
	{ 0, NULL }
};

/* proprietary Siemens message types, not in the standard */
static const value_string oml_fom_msgtype_vals_bs11[] = {
	{ NM_MT_BS11_RESET_RESOURCE,	"SIE Reset Resource" },
	{ NM_MT_BS11_BEGIN_DB_TX,	"SIE Begin Database Transmission" },
	{ NM_MT_BS11_BEGIN_DB_TX_ACK,	"SIE Begin Database Transmission ACK" },
	{ NM_MT_BS11_BEGIN_DB_TX_NACK,	"SIE Begin Database Transmission NACK" },
	{ NM_MT_BS11_END_DB_TX,		"SIE End Database Transmission" },
	{ NM_MT_BS11_END_DB_TX_ACK,	"SIE End Database Transmission ACK" },
	{ NM_MT_BS11_END_DB_TX_NACK,	"SIE End Database Transmission NACK" },
	{ NM_MT_BS11_CREATE_OBJ,	"SIE Create Object" },
	{ NM_MT_BS11_CREATE_OBJ_ACK,	"SIE Create Object ACK" },
	{ NM_MT_BS11_CREATE_OBJ_NACK,	"SIE Create Object NACK" },
	{ NM_MT_BS11_DELETE_OBJ,	"SIE Delete Object" },
	{ NM_MT_BS11_DELETE_OBJ_ACK,	"SIE Delete Object ACK" },
	{ NM_MT_BS11_DELETE_OBJ_NACK,	"SIE Delete Object NACK" },
	{ NM_MT_BS11_SET_ATTR,		"SIE Set Attribute" },
	{ NM_MT_BS11_SET_ATTR_ACK,	"SIE Set Attribute ACK" },
	{ NM_MT_BS11_SET_ATTR_NACK,	"SIE Set Attribute NACK" },
	{ NM_MT_BS11_GET_STATE,		"SIE Get State" },
	{ NM_MT_BS11_GET_STATE_ACK,	"SIE Get State ACK" },
	{ NM_MT_BS11_LMT_LOGON,		"SIE LMT Logon" },
	{ NM_MT_BS11_LMT_LOGON_ACK,	"SIE LMT Logon ACK" },
	{ NM_MT_BS11_RESTART,		"SIE Restart" },
	{ NM_MT_BS11_RESTART_ACK,	"SIE Restart ACK" },
	{ NM_MT_BS11_DISCONNECT,	"SIE Disconnect BTS" },
	{ NM_MT_BS11_DISCONNECT_ACK,	"SIE Disconnect BTS ACK" },
	{ NM_MT_BS11_LMT_LOGOFF,	"SIE LMT Logoff" },
	{ NM_MT_BS11_LMT_LOGOFF_ACK,	"SIE LMT Logoff ACK" },
	{ NM_MT_BS11_RECONNECT,		"SIE Reconnect BTS" },
	{ NM_MT_BS11_RECONNECT_ACK,	"SIE Reconnect BTS ACK" },
	{ 0, NULL }
};

/* TS 12.21 Section 9.2: Object Class */
static const value_string oml_fom_objclass_vals[] = {
	{ NM_OC_SITE_MANAGER,		"BTS Site Manager" },
	{ NM_OC_BTS,			"BTS" },
	{ NM_OC_RADIO_CARRIER,		"Radio Carrier" },
	{ NM_OC_CHANNEL,		"Radio Channel" },
	{ NM_OC_BASEB_TRANSC,		"Baseband Transceiver" },

	/* proprietary, vendor specific */
	{ NM_OC_BS11_ADJC,		"SIE Adjacend Channel" },
	{ NM_OC_BS11_HANDOVER,		"SIE Handover" },
	{ NM_OC_BS11_PWR_CTRL,		"SIE Power Control" },
	{ NM_OC_BS11_BTSE,		"SIE BTSE" },
	{ NM_OC_BS11_RACK,		"SIE Rack" },
	{ NM_OC_BS11,			"SIE SiemensHW" },
	{ NM_OC_BS11_TEST,		"SIE Test" },
	{ NM_OC_BS11_ENVABTSE,		"SIE EnvaBTSE" },
	{ NM_OC_BS11_BPORT,		"SIE BPort" },

	{ NM_OC_GPRS_NSE,		"GPRS NSE" },
	{ NM_OC_GPRS_CELL,		"GPRS Cell" },
	{ NM_OC_GPRS_NSVC0,		"GPRS NSVC0" },
	{ NM_OC_GPRS_NSVC1,		"GPRS NSVC1" },

	{ NM_OC_NULL,			"NULL" },
	{ 0, NULL }
};

/* TS 12.21 Section 9.4: Attributes */
static const value_string oml_fom_attr_vals[] = {
	{ NM_ATT_ABIS_CHANNEL,		"A-bis Channel" },
	{ NM_ATT_ADD_INFO,		"Additional Information" },
	{ NM_ATT_ADD_TEXT,		"Additional Text" },
	{ NM_ATT_ADM_STATE,		"Administrative State" },
	{ NM_ATT_ARFCN_LIST,		"ARFCN List" },
	{ NM_ATT_AUTON_REPORT,		"Autonomously Report" },
	{ NM_ATT_AVAIL_STATUS,		"Availability Status" },
	{ NM_ATT_BCCH_ARFCN,		"BCCH ARFCN" },
	{ NM_ATT_BSIC,			"BSIC" },
	{ NM_ATT_BTS_AIR_TIMER,		"BTS Air Timer" },
	{ NM_ATT_CCCH_L_I_P,		"CCCH Load Indication Period" },
	{ NM_ATT_CCCH_L_T,		"CCCH Load Threshold" },
	{ NM_ATT_CHAN_COMB,		"Channel Combination" },
	{ NM_ATT_CONN_FAIL_CRIT,	"Connection Fail Criterion" },
	{ NM_ATT_DEST,			"Destination" },
	{ NM_ATT_EVENT_TYPE,		"Event Type" },
	{ NM_ATT_FILE_ID,		"File ID" },
	{ NM_ATT_FILE_VERSION,		"File Version" },
	{ NM_ATT_GSM_TIME,		"GSM Time" },
	{ NM_ATT_HSN,			"HSN" },
	{ NM_ATT_HW_CONFIG,		"HW Configuration" },
	{ NM_ATT_HW_DESC,		"HW Description" },
	{ NM_ATT_INTAVE_PARAM,		"Intave Parameter" },
	{ NM_ATT_INTERF_BOUND,		"Interference Boundaries" },
	{ NM_ATT_LIST_REQ_ATTR,		"List of required Attributes" },
	{ NM_ATT_MAIO,			"MAIO" },
	{ NM_ATT_MANUF_STATE,		"Manufacturer Dependent State" },
	{ NM_ATT_MANUF_THRESH,		"Manufacturer Dependent Thresholds" },
	{ NM_ATT_MANUF_ID,		"Manufacturer Id" },
	{ NM_ATT_MAX_TA,		"Maximum Timing Advance" },
	{ NM_ATT_MDROP_LINK,		"Multi-drop BSC Link" },
	{ NM_ATT_MDROP_NEXT,		"Multi-drop next BTS Link" },
	{ NM_ATT_NACK_CAUSES,		"NACK Causes" },
	{ NM_ATT_NY1,			"Ny1" },
	{ NM_ATT_OPER_STATE,		"Operational State" },
	{ NM_ATT_OVERL_PERIOD,		"Overload Period" },
	{ NM_ATT_PHYS_CONF,		"Physical Config" },
	{ NM_ATT_POWER_CLASS,		"Power Class" },
	{ NM_ATT_POWER_THRESH,		"Power Output Thresholds" },
	{ NM_ATT_PROB_CAUSE,		"Probable Cause" },
	{ NM_ATT_RACH_B_THRESH,		"RACH Busy Threshold" },
	{ NM_ATT_LDAVG_SLOTS,		"RACH Load Averaging Slots" },
	{ NM_ATT_RAD_SUBC,		"Radio Sub Channel" },
	{ NM_ATT_RF_MAXPOWR_R,		"RF Max Power Reduction" },
	{ NM_ATT_SITE_INPUTS,		"Site Inputs" },
	{ NM_ATT_SITE_OUTPUTS,		"Site Outputs" },
	{ NM_ATT_SOURCE,		"Source" },
	{ NM_ATT_SPEC_PROB,		"Specific Problems" },
	{ NM_ATT_START_TIME,		"Starting Time" },
	{ NM_ATT_T200,			"T200" },
	{ NM_ATT_TEI,			"TEI" },
	{ NM_ATT_TEST_DUR,		"Test Duration" },
	{ NM_ATT_TEST_NO,		"Test No" },
	{ NM_ATT_TEST_REPORT,		"Test Report Info" },
	{ NM_ATT_VSWR_THRESH,		"VSWR Thresholds " },
	{ NM_ATT_WINDOW_SIZE,		"Window Size" },
	{ NM_ATT_BS11_RSSI_OFFS,	"SIE RSSI Offset" },
	{ NM_ATT_BS11_TXPWR,		"SIE TX Power" },
	{ NM_ATT_BS11_DIVERSITY,	"SIE Diversity" },
	{ NM_ATT_TSC,			"Training Sequence Code" },
	{ NM_ATT_SW_CONFIG,		"SW Configuration" },
	{ NM_ATT_SW_DESCR,		"SW Description" },
	{ NM_ATT_SEVERITY,		"Perceived Severity" },
	{ NM_ATT_GET_ARI,		"Get ARI" },
	{ NM_ATT_HW_CONF_CHG,		"HW Configuration Change" },
	{ NM_ATT_OUTST_ALARM,		"Outstanding Alarm" },
	{ NM_ATT_FILE_DATA,		"File Data" },
	{ NM_ATT_MEAS_RES,		"Measurement Result" },
	{ NM_ATT_MEAS_TYPE,		"Measurement Type" },
	{ 0, NULL }
};

/* proprietary Siemens attributes, not in the standard */
static const value_string oml_fom_attr_vals_bs11[] = {
	{ NM_ATT_BS11_OM_LAPD_REL_TIMER,"SIE OML LAPD Release Timer" },
	{ NM_ATT_BS11_RF_RES_IND_PER,	"SIE RF Resource Indication Period" },
	{ NM_ATT_BS11_RX_LEV_MIN_CELL,	"SIE RxLevel Min Cell" },
	{ NM_ATT_BS11_ABIS_EXT_TIME,	"SIE A-bis external time" },
	{ NM_ATT_BS11_TIMER_HO_REQUEST,	"SIE Timer Handover Request" },
	{ NM_ATT_BS11_TIMER_NCELL,	"SIE Timer nCell" },
	{ NM_ATT_BS11_TSYNC,		"SIE Timer Tsync" },
	{ NM_ATT_BS11_TTRAU,		"SIE Timer Ttrau" },
	{ NM_ATT_BS11_EMRG_CFG_MEMBER,	"SIE Emergency Config Member" },
	{ NM_ATT_BS11_TRX_AREA,		"SIE TRX Area" },
	{ NM_ATT_BS11_BCCH_RECONF,	"SIE BCCH Reconfiguration" },
	{ NM_ATT_BS11_BIT_ERR_THESH,	"SIE Bit Error Threshold" },
	{ NM_ATT_BS11_BOOT_SW_VERS,	"SIE Boot Software Version" },
	{ NM_ATT_BS11_CCLK_ACCURACY,	"SIE CCLK Accuracy" },
	{ NM_ATT_BS11_CCLK_TYPE,	"SIE CCLK Type" },
	{ NM_ATT_BS11_INP_IMPEDANCE,	"SIE Input Impedance" },
	{ NM_ATT_BS11_L1_PROT_TYPE,	"SIE L1 Protocol Type" },
	{ NM_ATT_BS11_LINE_CFG,		"SIE Line Configuration" },
	{ NM_ATT_BS11_LI_PORT_1,	"SIE Line Interface Port 1" },
	{ NM_ATT_BS11_LI_PORT_2,	"SIE Line Interface Port 2" },
	{ NM_ATT_BS11_L1_REM_ALM_TYPE,	"SIE L1 Remote Alarm Type" },
	{ NM_ATT_BS11_SW_LOAD_INTENDED,	"SIE Software Load Intended" },
	{ NM_ATT_BS11_SW_LOAD_SAFETY,	"SIE Software Load Safety" },
	{ NM_ATT_BS11_SW_LOAD_STORED,	"SIE Software Load Stored" },
	{ NM_ATT_BS11_VENDOR_NAME,	"SIE Vendor Name" },
	{ NM_ATT_BS11_HOPPING_MODE,	"SIE Hopping Mode" },
	{ NM_ATT_BS11_LMT_LOGON_SESSION,"SIE LMT Logon Session" },
	{ NM_ATT_BS11_LMT_LOGIN_TIME,	"SIE LMT Login Time" },
	{ NM_ATT_BS11_LMT_USER_ACC_LEV,	"SIE LMT User Account Level" },
	{ NM_ATT_BS11_LMT_USER_NAME,	"SIE LMT User Account Name" },
	{ NM_ATT_BS11_L1_CONTROL_TS,	"SIE L1 Control TS" },
	{ NM_ATT_BS11_RADIO_MEAS_GRAN,	"SIE Radio Measurement Granularity" },
	{ NM_ATT_BS11_RADIO_MEAS_REP,	"SIE Rdadio Measurement Report" },
	{ NM_ATT_BS11_SH_LAPD_INT_TIMER,"SIE LAPD Internal Timer" },
	{ NM_ATT_BS11_BTS_STATE,	"SIE BTS State" },
	{ NM_ATT_BS11_E1_STATE,		"SIE E1 State" },
	{ NM_ATT_BS11_PLL,		"SIE PLL" },
	{ NM_ATT_BS11_RX_OFFSET,	"SIE Rx Offset" },
	{ NM_ATT_BS11_ANT_TYPE,		"SIE Antenna Type" },
	{ NM_ATT_BS11_PLL_MODE,		"SIE PLL Mode" },
	{ NM_ATT_BS11_PASSWORD,		"SIE Password" },
	{ NM_ATT_BS11_ESN_FW_CODE_NO,	"SIE ESN FW Code Number" },
	{ NM_ATT_BS11_ESN_HW_CODE_NO,	"SIE ESN HW Code Number" },
	{ NM_ATT_BS11_ESN_PCB_SERIAL,	"SIE ESN PCB Serial Number" },
	{ NM_ATT_BS11_EXCESSIVE_DISTANCE, "SIE Excessive Distance" },
	{ NM_ATT_BS11_ALL_TEST_CATG,	"SIE All Test Categories" },
	{ NM_ATT_BS11_BTSLS_HOPPING,	"SIE BTS LS Hopping" },
	{ NM_ATT_BS11_CELL_ALLOC_NR,	"SIE Cell Allocation Number" },
	{ NM_ATT_BS11_CELL_GLOBAL_ID,	"SIE Cell Global ID" },
	{ NM_ATT_BS11_ENA_INTERF_CLASS,	"SIE Enable Interference Class" },
	{ NM_ATT_BS11_ENA_INT_INTEC_HANDO, "SIE Enable Int Intec Handover" },
	{ NM_ATT_BS11_ENA_INT_INTRC_HANDO, "SIE Enable Int Intrc Handover" },
	{ NM_ATT_BS11_ENA_MS_PWR_CTRL,	"SIE Enable MS Power Control" },
	{ NM_ATT_BS11_ENA_PWR_BDGT_HO,	"SIE Enable Power Budget HO" },
	{ NM_ATT_BS11_ENA_RXLEV_HO,	"SIE Enable RxLevel HO" },
	{ NM_ATT_BS11_ENA_RXQUAL_HO,	"SIE Enable RxQual HO" },
	{ NM_ATT_BS11_FACCH_QUAL,	"SIE FACCH Quality" },
	{ 0, NULL }
};

/* proprietary ip.access attributes, not in the standard */
static const value_string oml_fom_attr_vals_ipa[] = {
	{ NM_ATT_IPACC_DST_IP,		"IPA Destination IP Address" },
	{ NM_ATT_IPACC_DST_IP_PORT,	"IPA Destionation IP Port" },
	{ NM_ATT_IPACC_SSRC,		"IPA RTP SSRC" },
	{ NM_ATT_IPACC_RTP_PAYLD_TYPE,	"IPA RTP Payload Type" },
	{ NM_ATT_IPACC_BASEB_ID,	"IPA Baseband Identifier" },
	{ NM_ATT_IPACC_STREAM_ID,	"IPA Stream Identifier" },
	{ NM_ATT_IPACC_NV_FLAGS,	"IPA NVRAM Flags" },
	{ NM_ATT_IPACC_FREQ_CTRL,	"IPA Frequency Control" },
	{ NM_ATT_IPACC_PRIM_OML_CFG,	"IPA Primary OML Config" },
	{ NM_ATT_IPACC_SEC_OML_CFG,	"IPA Secondary OML Config" },
	{ NM_ATT_IPACC_IP_IF_CFG,	"IPA IP Interface Config" },
	{ NM_ATT_IPACC_IP_GW_CFG,	"IPA IP Gateway Config" },
	{ NM_ATT_IPACC_IN_SERV_TIME,	"IPA In Service Time" },
	{ NM_ATT_IPACC_TRX_BTS_ASS,	"IPA TRX BTS Assignment" },
	{ NM_ATT_IPACC_LOCATION,	"IPA BTS Location Name" },
	{ NM_ATT_IPACC_PAGING_CFG,	"IPA Paging Configuration" },
	{ NM_ATT_IPACC_FILE_DATA,	"IPA File Data" },
	{ NM_ATT_IPACC_UNIT_ID,		"IPA Unit ID" },
	{ NM_ATT_IPACC_PARENT_UNIT_ID,	"IPA Parent Unit ID" },
	{ NM_ATT_IPACC_UNIT_NAME,	"IPA Unit Name" },
	{ NM_ATT_IPACC_SNMP_CFG,	"IPA SNMP Config" },
	{ NM_ATT_IPACC_PRIM_OML_CFG_LIST, "IPA Primary OML Config List" },
	{ NM_ATT_IPACC_PRIM_OML_FB_TOUT,"IPA Primary OML Fallback Timeout" },
	{ NM_ATT_IPACC_CUR_SW_CFG,	"IPA Current Software Config" },
	{ NM_ATT_IPACC_TIMING_BUS,	"IPA Timing Bus" },
	{ NM_ATT_IPACC_CGI,		"IPA CGI" },
	{ NM_ATT_IPACC_RAC,		"IPA RAC" },
	{ NM_ATT_IPACC_OBJ_VERSION,	"IPA Object Version" },
	{ NM_ATT_IPACC_GPRS_PAGING_CFG,	"IPA GPRS Paging Configuration" },
	{ NM_ATT_IPACC_NSEI,		"IPA NSEI" },
	{ NM_ATT_IPACC_BVCI,		"IPA BVCI" },
	{ NM_ATT_IPACC_NSVCI,		"IPA NSVCI" },
	{ NM_ATT_IPACC_NS_CFG,		"IPA NS Configuration" },
	{ NM_ATT_IPACC_BSSGP_CFG,	"IPA BSSGP Configuration" },
	{ NM_ATT_IPACC_NS_LINK_CFG,	"IPA NS Link Configuration" },
	{ NM_ATT_IPACC_RLC_CFG,		"IPA RLC Configuration" },
	{ NM_ATT_IPACC_ALM_THRESH_LIST,	"IPA Alarm Threshold List" },
	{ NM_ATT_IPACC_MONIT_VAL_LIST,	"IPA Monitored Value List" },
	{ NM_ATT_IPACC_TIB_CONTROL,	"IPA Timing Interface Bus Control" },
	{ NM_ATT_IPACC_SUPP_FEATURES,	"IPA Supported Features" },
	{ NM_ATT_IPACC_CODING_SCHEMES,	"IPA Coding Schemes" },
	{ NM_ATT_IPACC_RLC_CFG_2,	"IPA RLC Configuration 2" },
	{ NM_ATT_IPACC_HEARTB_TOUT,	"IPA Heartbeat Timeout" },
	{ NM_ATT_IPACC_UPTIME,		"IPA Uptime" },
	{ NM_ATT_IPACC_RLC_CFG_3,	"IPA RLC Configuration 3" },
	{ NM_ATT_IPACC_SSL_CFG,		"IPA SSL Configuration" },
	{ NM_ATT_IPACC_SEC_POSSIBLE,	"IPA Security Possible" },
	{ NM_ATT_IPACC_IML_SSL_STATE,	"IPA IML SSL State" },
	{ NM_ATT_IPACC_REVOC_DATE,	"IPA Revocation Date" },
	{ 0, NULL }
};

static const enum_val_t oml_dialect_enumvals[] = {
	{ "etsi",	"ETSI/3GPP TS 12.21",	OML_DIALECT_ETSI },
	{ "siemens",	"Siemens",		OML_DIALECT_SIEMENS },
	{ "ipaccess",	"ip.access",		OML_DIALECT_IPA },
	{ NULL, NULL, 0 }
};

static void format_custom_msgtype(gchar *out, guint32 in)
{
	const gchar *tmp = NULL;

	switch (global_oml_dialect) {
	case OML_DIALECT_SIEMENS:
		tmp = match_strval(in, oml_fom_msgtype_vals_bs11);
		break;
	case OML_DIALECT_IPA:
		tmp = match_strval(in, oml_fom_msgtype_vals_ipa);
		break;
	case OML_DIALECT_ETSI:
	default:
		g_snprintf(out, ITEM_LABEL_LENGTH, "%s",
			   val_to_str(in, oml_fom_msgtype_vals, "Unknown 0x%02x"));
		return;
	}

	if (tmp)
		g_snprintf(out, ITEM_LABEL_LENGTH, "%s", tmp);
	else
		g_snprintf(out, ITEM_LABEL_LENGTH, "%s",
			   val_to_str(in, oml_fom_msgtype_vals, "Unknown 0x%02x"));
}

static void format_custom_attr(gchar *out, guint32 in)
{
	const gchar *tmp = NULL;

	switch (global_oml_dialect) {
	case OML_DIALECT_SIEMENS:
		tmp = match_strval(in, oml_fom_attr_vals_bs11);
		break;
	case OML_DIALECT_IPA:
		tmp = match_strval(in, oml_fom_attr_vals_ipa);
		break;
	case OML_DIALECT_ETSI:
	default:
		g_snprintf(out, ITEM_LABEL_LENGTH, "%s",
			   val_to_str(in, oml_fom_attr_vals, "Unknown 0x%02x"));
		return;
	}

	if (tmp)
		g_snprintf(out, ITEM_LABEL_LENGTH, "%s", tmp);
	else
		g_snprintf(out, ITEM_LABEL_LENGTH, "%s",
			   val_to_str(in, oml_fom_attr_vals, "Unknown 0x%02x"));
}

/* Section 9.4.4: Administrative State */
static const value_string oml_adm_state_vals[] = {
	{ NM_STATE_LOCKED,		"Locked" },
	{ NM_STATE_UNLOCKED,		"Unlocked" },
	{ NM_STATE_SHUTDOWN,		"Shutdown" },
	{ NM_STATE_NULL,		"Null" },
	{ 0, NULL }
};

static const value_string oml_oper_state_vals[] = {
	{ 1,	"Disabled" },
	{ 2,	"Enabled" },
	{ 0xff,	"NULL" },
	{ 0, NULL }
};

/* Section 9.4.7 Availability Status */
static const value_string oml_avail_state_vals[] = {
	{ 0,	"In test" },
	{ 1,	"Failed" },
	{ 2,	"Power off" },
	{ 3,	"Off line" },
	{ 5,	"Dependency" },
	{ 6,	"Degraded" },
	{ 7, 	"Not installed" },
	{ 0xff,	"OK" },
	{ 0, NULL }
};

/* Section 9.4.13: Channel Combination */
static const value_string oml_chan_comb_vals[] = {
	{ NM_CHANC_TCHFull,		"TCH/F" },
	{ NM_CHANC_TCHHalf,		"TCH/H" },
	{ NM_CHANC_TCHHalf2,		"TCH/H 2" },
	{ NM_CHANC_SDCCH,		"SDCCH" },
	{ NM_CHANC_mainBCCH,		"Main BCCH" },
	{ NM_CHANC_BCCHComb,		"Combined BCCH" },
	{ NM_CHANC_BCCH,		"BCCH" },
	{ NM_CHANC_BCCH_CBCH,		"BCCH+CBCH" },
	{ NM_CHANC_SDCCH_CBCH,		"SDCCH+CBCH" },
	{ 0, NULL }
};

/* Section 9.4.16: Event Type */
static const value_string oml_event_type_vals[] = {
	{ NM_EVT_COMM_FAIL,		"Communication Failure" },
	{ NM_EVT_QOS_FAIL,		"QoS Failure" },
	{ NM_EVT_PROC_FAIL,		"Processor Failure" },
	{ NM_EVT_EQUIP_FAIL,		"Equipment Failure" },
	{ NM_EVT_ENV_FAIL,		"Environment Failure" },
	{ 0, NULL }
};

/* Section 9.4.63: Perceived Severity */
static const value_string oml_severity_vals[] = {
	{ NM_SEVER_CEASED,		"Ceased" },
	{ NM_SEVER_CRITICAL,		"Critical" },
	{ NM_SEVER_MAJOR,		"Major" },
	{ NM_SEVER_MINOR,		"Minor" },
	{ NM_SEVER_WARNING,		"Warning" },
	{ NM_SEVER_INDETERMINATE,	"Indeterminate" },
	{ 0, NULL }
};

/* Section 9.4.36: NACK Causes */
static const value_string oml_nack_cause[] = {
	{ NM_NACK_INCORR_STRUCT,	"Incorrect message structure" },
	{ NM_NACK_MSGTYPE_INVAL,	"Invalid message type value" },
	{ NM_NACK_OBJCLASS_INVAL,	"Invalid Object class value" },
	{ NM_NACK_OBJCLASS_NOTSUPP,	"Object Class not supported" },
	{ NM_NACK_BTSNR_UNKN,		"BTS Number unknown" },
	{ NM_NACK_TRXNR_UNKN,		"TRX Number unknown" },
	{ NM_NACK_OBJINST_UNKN,		"Object Instance unknown" },
	{ NM_NACK_ATTRID_INVAL,		"Invalid Attribute ID value" },
	{ NM_NACK_ATTRID_NOTSUPP,	"Attribute ID not supported" },
	{ NM_NACK_PARAM_RANGE,		"Parameter value out of range" },
	{ NM_NACK_ATTRLIST_INCONSISTENT, "Inconsistency in Attribute list" },
	{ NM_NACK_SPEC_IMPL_NOTSUPP,	"Specified Implementation not supported" },
	{ NM_NACK_CANT_PERFORM,		"Message cannot be performed" },
	{ NM_NACK_RES_NOTIMPL,		"Resource not implemented" },
	{ NM_NACK_RES_NOTAVAIL,		"Resource not available" },
	{ NM_NACK_FREQ_NOTAVAIL,	"Frequency not available" },
	{ NM_NACK_TEST_NOTSUPP,		"Test not supported" },
	{ NM_NACK_CAPACITY_RESTR,	"Capacity restrictions" },
	{ NM_NACK_PHYSCFG_NOTPERFORM,	"Phys config cannot be performed" },
	{ NM_NACK_TEST_NOTINIT,		"Test not initiated" },
	{ NM_NACK_PHYSCFG_NOTRESTORE,	"Phys config cannot be restored" },
	{ NM_NACK_TEST_NOSUCH,		"No such Test" },
	{ NM_NACK_TEST_NOSTOP,		"Test cannot be stopped" },
	{ NM_NACK_MSGINCONSIST_PHYSCFG,	"Message inconsisten with physical config" },
	{ NM_NACK_FILE_INCOMPLETE,	"Complete file not received" },
	{ NM_NACK_FILE_NOTAVAIL,	"File not available at destination" },
	{ NM_NACK_FILE_NOTACTIVATE,	"File cannot be activated" },
	{ NM_NACK_REQ_NOT_GRANT,	"Request not granted" },
	{ NM_NACK_WAIT,			"Wait" },
	{ NM_NACK_NOTH_REPORT_EXIST,	"Nothing reportable existing" },
	{ NM_NACK_MEAS_NOTSUPP,		"Measurement not supported" },
	{ NM_NACK_MEAS_NOTSTART,	"Measurement not started" },
	{ 0xff,				"NULL" },
	{ 0, NULL }
};

static const value_string oml_test_no_vals[] = {
	{ NM_IPACC_TESTNO_RLOOP_ANT,	"Radio Loop test via antenna" },
	{ NM_IPACC_TESTNO_RLOOP_XCVR,	"Radio Loop test via transceiver" },
	{ NM_IPACC_TESTNO_FUNC_OBJ,	"BTS Functional object self test" },
	{ NM_IPACC_TESTNO_CHAN_USAGE,	"Channel Usage" },
	{ NM_IPACC_TESTNO_BCCH_CHAN_USAGE, "BCCH Channel Usage" },
	{ NM_IPACC_TESTNO_FREQ_SYNC,	"Frequency Synchronization" },
	{ NM_IPACC_TESTNO_BCCH_INFO,	"BCCH Information" },
	{ NM_IPACC_TESTNO_TX_BEACON,	"Transmit Beacon" },
	{ NM_IPACC_TESTNO_SYSINFO_MONITOR, "SysInfo Monitor" },
	{ NM_IPACC_TESTNO_BCCCH_MONITOR, "BCCH & CCCH Monitor" },
	{ 0, NULL }
};

static const value_string ipacc_test_res_vals[] = {
	{ NM_IPACC_TESTRES_SUCCESS,	"Success" },
	{ NM_IPACC_TESTRES_TIMEOUT,	"Timeout" },
	{ NM_IPACC_TESTRES_NO_CHANS,	"No suitable channels available" },
	{ NM_IPACC_TESTRES_PARTIAL,	"Partial" },
	{ NM_IPACC_TESTRES_STOPPED,	"Stopped" },
	{ 0, NULL }
};

static const value_string ipacc_testres_ie_vals[] = {
	{ NM_IPACC_TR_IE_FREQ_ERR_LIST,	"Frequency Error List" },
	{ NM_IPACC_TR_IE_CHAN_USAGE,	"Channel Usage" },
	{ NM_IPACC_TR_IE_BCCH_INFO,	"BCCH Information" },
	{ NM_IPACC_TR_IE_RESULT_DETAILS,"Result Details" },
	{ NM_IPACC_TR_IE_FREQ_ERR,	"Frequency Error" },
	{ 0, NULL }
};

/* ANSI C does not allow selective initialization of arrays, for that reason,
 * we initialize these three TLV definitions in proto_register_abis_oml(). */
static struct tlv_definition nm_att_tlvdef_base;
static struct tlv_definition nm_att_tlvdev_bs11;
static struct tlv_definition nm_att_tlvdef_ipa;

static const struct tlv_def *
find_tlv_tag(guint8 tag)
{
	const struct tlv_def *specific;

	switch (global_oml_dialect) {
	case OML_DIALECT_IPA:
		specific = &nm_att_tlvdef_ipa.def[tag];
		break;
	case OML_DIALECT_SIEMENS:
		specific = &nm_att_tlvdev_bs11.def[tag];
		break;
	case OML_DIALECT_ETSI:
	default:
		specific = NULL;
		break;
	}

	if (specific && specific->type != TLV_TYPE_UNKNOWN)
		return specific;

	return &nm_att_tlvdef_base.def[tag];
}

/* Parse the ip.access specific BCCH Information IE embedded into the Test
 * Report IE */
static gint
ipacc_tr_ie_bcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *att_tree,
		 int offset)
{
	guint16 binfo_type;

	binfo_type = tvb_get_ntohs(tvb, offset);
	offset += 2;

	/* FIXME: there are still some bugs remaining here */
	proto_tree_add_item(att_tree, hf_attr_ipa_tr_arfcn,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_f_qual,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_b_rxlev,
			    tvb, offset++, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_rxqual,
			    tvb, offset++, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_f_err,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_frame_offs,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(att_tree, hf_attr_ipa_tr_framenr_offs,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_bsic,
			    tvb, offset++, 1, ENC_LITTLE_ENDIAN);

	de_lai(tvb, att_tree, pinfo, offset, 5, NULL, 0);
	offset += 5;

	proto_tree_add_item(att_tree, hf_attr_ipa_tr_cell_id,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (binfo_type & 0x8000) {
		/* System Information 2 */
		/* FIXME: Parse 04.18 Neighbour Cell Description */
		proto_tree_add_item(att_tree, hf_attr_ipa_tr_si2,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	if (binfo_type & 0x0001) {
		/* System Information 2bis */
		/* FIXME: Parse 04.18 Neighbour Cell Description */
		proto_tree_add_item(att_tree, hf_attr_ipa_tr_si2bis,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	if (binfo_type & 0x0002) {
		/* System Information 2ter */
		/* FIXME: Parse 04.18 Neighbour Cell Description */
		proto_tree_add_item(att_tree, hf_attr_ipa_tr_si2ter,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	if (binfo_type & 0x0004) {
		/* FIXME: Parse 04.18 Cell Channel Description */
		proto_tree_add_item(att_tree, hf_attr_ipa_tr_chan_desc,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}

	return offset;
}

/* Parse the ip.access specific Channel Usage IE embedded into the Test
 * Report IE */
static gint
ipacc_tr_ie_chan_usage(tvbuff_t *tvb, proto_tree *att_tree, int offset)
{
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		guint16 result;

		result = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(att_tree, hf_attr_ipa_tr_arfcn,
				    tvb, offset, 2, result);
		proto_tree_add_uint(att_tree, hf_attr_ipa_tr_rxlev,
				    tvb, offset, 2, result);
		offset += 2;
	}
	return offset;
}

/* Parse the ip.access specific format of the standard test report IE */
static gint
dissect_ipacc_test_rep(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{
	gint offset = 0;

	proto_tree_add_item(tree, hf_attr_ipa_test_res, tvb, offset++,
			    1, ENC_BIG_ENDIAN);

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		guint8 ie;
		guint16 len;
		proto_item *ti;
		proto_tree *att_tree;

		ie = tvb_get_guint8(tvb, offset);
		len = tvb_get_ntohs(tvb, offset+1);
		ti = proto_tree_add_item(tree, hf_oml_ipa_tres_attr_tag, tvb,
					 offset++, 1, ENC_BIG_ENDIAN);
		att_tree = proto_item_add_subtree(ti, ett_oml_fom_att);
		proto_tree_add_uint(att_tree, hf_oml_ipa_tres_attr_len, tvb,
				    offset, 2, len);
		offset += 2;

		switch (ie) {
		case NM_IPACC_TR_IE_CHAN_USAGE:
			offset = ipacc_tr_ie_chan_usage(tvb,
						 	att_tree, offset);
			break;
		case NM_IPACC_TR_IE_BCCH_INFO:
			offset = ipacc_tr_ie_bcch(tvb, pinfo,
						  att_tree, offset);
			break;
		default:
			break;
		}
	}
	return offset;
}

/* Dissect OML FOM Attributes after OML + FOM header */
static gint
dissect_oml_attrs(tvbuff_t *tvb, int base_offs, packet_info *pinfo,
		  proto_tree *tree)
{
	int offset = base_offs;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		guint i;
		guint8 tag, val8;
		guint16 val16;
		guint32 val32;
		unsigned int len, len_len, hlen;
		const struct tlv_def *tdef;
		proto_item *ti;
		proto_tree *att_tree;
		tvbuff_t *sub_tvb;

		tag = tvb_get_guint8(tvb, offset);
		tdef = find_tlv_tag(tag);

		switch (tdef->type) {
		case TLV_TYPE_FIXED:
			hlen = 1;
			len_len = 0;
			len = tdef->fixed_len;
			break;
		case TLV_TYPE_T:
			hlen = 1;
			len_len = 0;
			len = 0;
			break;
		case TLV_TYPE_TV:
			hlen = 1;
			len_len = 0;
			len = 1;
			break;
		case TLV_TYPE_TLV:
			hlen = 2;
			len_len = 1;
			len = tvb_get_guint8(tvb, offset+1);
			break;
		case TLV_TYPE_TL16V:
			hlen = 3;
			len_len = 2;
			len = tvb_get_guint8(tvb, offset+1) << 8 |
						tvb_get_guint8(tvb, offset+2);
			break;
		case TLV_TYPE_TLV16:
			hlen = 2;
			len_len = 1;
			len = tvb_get_guint8(tvb, offset+1) * 2;
			break;
		case TLV_TYPE_UNKNOWN: /* fall through */
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
		}

		ti = proto_tree_add_item(tree, hf_oml_fom_attr_tag, tvb,
					 offset, 1, ENC_BIG_ENDIAN);
		att_tree = proto_item_add_subtree(ti, ett_oml_fom_att);
		proto_tree_add_uint(att_tree, hf_oml_fom_attr_len, tvb,
				    offset+1, len_len, len);
		offset += hlen;

		sub_tvb = tvb_new_subset(tvb, offset, len, len);

		switch (tag) {
		/* parse only the most common IE for now */
		case NM_ATT_ABIS_CHANNEL:
			proto_tree_add_item(att_tree, hf_attr_ach_btsp, tvb,
					    offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(att_tree, hf_attr_ach_tslot, tvb,
					    offset+1, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(att_tree, hf_attr_ach_sslot, tvb,
					    offset+2, 1, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_ADM_STATE:
			proto_tree_add_item(att_tree, hf_attr_adm_state, tvb,
					    offset, len, ENC_BIG_ENDIAN);
			val8 = tvb_get_guint8(tvb, offset);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					val_to_str(val8, oml_adm_state_vals,
						   "%02x"));
			break;
		case NM_ATT_ARFCN_LIST:
			for (i = 0; i < len; i += 2) {
				val16 = tvb_get_ntohs(tvb, offset + i);
				proto_tree_add_uint(att_tree, hf_attr_arfcn,
						    tvb, offset + i, 2, val16);
			}
			break;
		case NM_ATT_AVAIL_STATUS:
			/* Availability status can have length 0 */
			if (len) {
				val8 = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(att_tree,
						    hf_attr_avail_state, tvb,
					    	    offset, len, ENC_BIG_ENDIAN);
			} else
				val8 = 0xff;
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					val_to_str(val8, oml_avail_state_vals,
						   "%02x"));
			break;
		case NM_ATT_BCCH_ARFCN:
			proto_tree_add_item(att_tree, hf_attr_bcch_arfcn, tvb,
					    offset, len, ENC_BIG_ENDIAN);
			break;
		case NM_ATT_BSIC:
			proto_tree_add_item(att_tree, hf_attr_bsic, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_CHAN_COMB:
			proto_tree_add_item(att_tree, hf_attr_chan_comb, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_EVENT_TYPE:
			proto_tree_add_item(att_tree, hf_attr_event_type, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_GSM_TIME:
			proto_tree_add_item(att_tree, hf_attr_gsm_time, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_OPER_STATE:
			proto_tree_add_item(att_tree, hf_attr_oper_state, tvb,
					    offset, len, ENC_BIG_ENDIAN);
			val8 = tvb_get_guint8(tvb, offset);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					val_to_str(val8, oml_oper_state_vals,
						   "%02x"));
			break;
		case NM_ATT_TEI:
			proto_tree_add_item(att_tree, hf_attr_tei, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_TSC:
			proto_tree_add_item(att_tree, hf_attr_tsc, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_SEVERITY:
			proto_tree_add_item(att_tree, hf_attr_severity, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_TEST_REPORT:
			dissect_ipacc_test_rep(att_tree, pinfo, sub_tvb);
			break;
		case NM_ATT_TEST_NO:
			proto_tree_add_item(att_tree, hf_attr_test_no, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			val8 = tvb_get_guint8(tvb, offset);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
					val_to_str(val8, oml_test_no_vals,
						   "%02x"));
			break;
		case NM_ATT_HSN:
			proto_tree_add_item(att_tree, hf_attr_hsn, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_MAIO:
			proto_tree_add_item(att_tree, hf_attr_maio, tvb,
					    offset, len, ENC_LITTLE_ENDIAN);
			break;
		default:
			proto_tree_add_item(att_tree, hf_oml_fom_attr_val, tvb,
					    offset, len, ENC_NA);
		}

		if (global_oml_dialect == OML_DIALECT_IPA) switch (tag) {
		/* proprietary ip.access extensions */
		case NM_ATT_IPACC_DST_IP:
			val32 = tvb_get_ntohl(tvb, offset);
			proto_tree_add_ipv4(att_tree, hf_attr_ipa_rsl_ip, tvb,
					    offset, len, val32);
			break;
		case NM_ATT_IPACC_DST_IP_PORT:
			val16 = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(att_tree, hf_attr_ipa_rsl_port, tvb,
					    offset, len, val16);
			break;
		case NM_ATT_IPACC_LOCATION:
			proto_tree_add_item(att_tree, hf_attr_ipa_location_name,
					    tvb, offset, len, ENC_ASCII|ENC_NA);
			break;
		case NM_ATT_IPACC_UNIT_ID:
			proto_tree_add_item(att_tree, hf_attr_ipa_unit_id,
					    tvb, offset, len, ENC_ASCII|ENC_NA);
			break;
		case NM_ATT_IPACC_UNIT_NAME:
			proto_tree_add_item(att_tree, hf_attr_ipa_unit_name,
					    tvb, offset, len, ENC_ASCII|ENC_NA);
			break;
		case NM_ATT_IPACC_PRIM_OML_CFG_LIST:
			proto_tree_add_item(att_tree, hf_attr_ipa_prim_oml_ip,
					    tvb, offset+1, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(att_tree, hf_attr_ipa_prim_oml_port,
					    tvb, offset+1+4, 2, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_IPACC_NV_FLAGS:
			{
				guint flags, mask;
				flags = tvb_get_guint8(tvb, offset);
				mask = tvb_get_guint8(tvb, offset+1);
				flags |= tvb_get_guint8(tvb, offset+2) << 8;
				mask |= tvb_get_guint8(tvb, offset+3) << 8;
				proto_tree_add_uint(att_tree, hf_attr_ipa_nv_flags,
						    tvb, offset, 3, flags);
				proto_tree_add_uint(att_tree, hf_attr_ipa_nv_mask,
						    tvb, offset+1, 3, mask);
			}
			break;
		case NM_ATT_IPACC_RAC:
			proto_tree_add_item(att_tree, hf_attr_ipa_rac,
					    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			break;
		case NM_ATT_IPACC_NSEI:
			val16 = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(att_tree, hf_attr_ipa_nsei,
					   tvb, offset, 2, val16);
			break;
		case NM_ATT_IPACC_NSVCI:
			val16 = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(att_tree, hf_attr_ipa_nsvci,
					   tvb, offset, 2, val16);
			break;
		case NM_ATT_IPACC_BVCI:
			val16 = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(att_tree, hf_attr_ipa_bvci,
					   tvb, offset, 2, val16);
			break;
		case NM_ATT_IPACC_NS_LINK_CFG:
			val16 = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(att_tree, hf_attr_ipa_nsl_sport,
					   tvb, offset, 2, val16);
			val32 = tvb_get_ipv4(tvb, offset+2);
			proto_tree_add_ipv4(att_tree, hf_attr_ipa_nsl_daddr,
					   tvb, offset+2, 4, val32);
			val16 = tvb_get_ntohs(tvb, offset+6);
			proto_tree_add_uint(att_tree, hf_attr_ipa_nsl_dport,
					   tvb, offset+6, 2, val16);
			break;
		}
		offset += len;
	}
	return offset;
}

static int
dissect_oml_fom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		int offset, proto_item *top_ti)
{
	guint8 msg_type, obj_class, bts_nr, trx_nr, ts_nr;
	proto_item *ti;
	proto_tree *fom_tree;
	gchar formatted[ITEM_LABEL_LENGTH];

	msg_type = tvb_get_guint8(tvb, offset);
	obj_class = tvb_get_guint8(tvb, offset+1);
	bts_nr = tvb_get_guint8(tvb, offset+2);
	trx_nr = tvb_get_guint8(tvb, offset+3);
	ts_nr = tvb_get_guint8(tvb, offset+4);
	format_custom_msgtype(formatted, msg_type);
	proto_item_append_text(top_ti, ", %s(%02x,%02x,%02x) %s ",
			val_to_str(obj_class, oml_fom_objclass_vals, "%02x"),
			bts_nr, trx_nr, ts_nr, formatted);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%02x,%02x,%02x) %s ",
			val_to_str(obj_class, oml_fom_objclass_vals, "%02x"),
			bts_nr, trx_nr, ts_nr, formatted);
	ti = proto_tree_add_item(tree, hf_oml_fom_msgtype, tvb, offset++, 1, ENC_BIG_ENDIAN);
	fom_tree = proto_item_add_subtree(ti, ett_oml_fom);
	proto_tree_add_item(fom_tree, hf_oml_fom_objclass, tvb, offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(fom_tree, hf_oml_fom_inst_bts, tvb, offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(fom_tree, hf_oml_fom_inst_trx, tvb, offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(fom_tree, hf_oml_fom_inst_ts, tvb, offset++, 1, ENC_BIG_ENDIAN);


	/* dissect the TLV objects in the message body */
	offset = dissect_oml_attrs(tvb, offset, pinfo, fom_tree);

	return offset;
}

static const guint8 ipaccess_magic[] = "com.ipaccess";

static int
dissect_oml_manuf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  int offset, proto_item *top_ti)
{
	if (tvb_get_guint8(tvb, offset) != 0x0d ||
	    tvb_memeql(tvb, offset+1, ipaccess_magic, sizeof(ipaccess_magic)))
		return offset;

	offset += sizeof(ipaccess_magic) + 1;

	return dissect_oml_fom(tvb, pinfo, tree, offset, top_ti);
}

static int
dissect_abis_oml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *oml_tree;

	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OML");

	top_tree = tree;
	if (tree) {
		guint8 msg_disc = tvb_get_guint8(tvb, offset);

		ti = proto_tree_add_item(tree, proto_abis_oml, tvb, 0, -1, ENC_NA);
		oml_tree = proto_item_add_subtree(ti, ett_oml);

		proto_tree_add_item(oml_tree, hf_oml_msg_disc, tvb, offset++,
				    1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(oml_tree, hf_oml_placement, tvb, offset++,
				    1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(oml_tree, hf_oml_sequence, tvb, offset++,
				    1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(oml_tree, hf_oml_length, tvb, offset++,
				    1, ENC_LITTLE_ENDIAN);

		switch (msg_disc) {
		case ABIS_OM_MDISC_FOM:
			offset = dissect_oml_fom(tvb, pinfo, oml_tree,
						 offset, ti);
			break;
		case ABIS_OM_MDISC_MANUF:
			offset = dissect_oml_manuf(tvb, pinfo, oml_tree,							       offset, ti);
			break;
		case ABIS_OM_MDISC_MMI:
		case ABIS_OM_MDISC_TRAU:
		default:
			break;
		}
	}

	return offset;
}

void
proto_reg_handoff_abis_oml(void);

void
proto_register_abis_oml(void)
{
	static hf_register_info hf[] = {
		{ &hf_oml_msg_disc,
			{ "Message Discriminator", "oml.msg_dsc",
			  FT_UINT8, BASE_HEX, VALS(oml_msg_disc_vals), 0,
			  "GSM 12.21 Message Discriminator", HFILL }
		},
		{ &hf_oml_placement,
			{ "Placement Indicator", "oml.placement",
			  FT_UINT8, BASE_HEX, VALS(oml_placement_vals), 0,
			  "GSM 12.21 Placement Indicator", HFILL }
		},
		{ &hf_oml_sequence,
			{ "Sequence Number", "oml.sequence",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  "Sequence Number (if multi-part msg)", HFILL }
		},
		{ &hf_oml_length,
			{ "Length Indicator", "oml.length",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Total length of payload", HFILL }
		},
		{ &hf_oml_fom_msgtype,
			{ "FOM Message Type", "oml.fom.msg_type",
			  FT_UINT8, BASE_CUSTOM, &format_custom_msgtype, 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_objclass,
			{ "FOM Object Class", "oml.fom.obj_class",
			  FT_UINT8, BASE_HEX, VALS(oml_fom_objclass_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_inst_bts,
			{ "FOM Object Instance BTS", "oml.fom.obj_inst.bts",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_inst_trx,
			{ "FOM Object Instance TRX", "oml.fom.obj_inst.trx",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_inst_ts,
			{ "FOM Object Instance TS", "oml.fom.obj_inst.ts",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_attr_tag,
			{ "FOM Attribute ID", "oml.fom.attr_id",
			  FT_UINT8, BASE_CUSTOM, &format_custom_attr, 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_attr_len,
			{ "FOM Attribute Length", "oml.fom.attr_len",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_oml_fom_attr_val,
			{ "FOM Attribute Value", "oml.fom.attr_val",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},



		/* OML Attributes */
		{ &hf_attr_adm_state,
			{ "Administrative State", "oml.fom.attr.adm_state",
			  FT_UINT8, BASE_HEX, VALS(oml_adm_state_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_arfcn,
			{ "ARFCN", "oml.fom.attr.arfcn",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_oper_state,
			{ "Operational State", "oml.fom.attr.oper_state",
			  FT_UINT8, BASE_HEX, VALS(oml_oper_state_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_avail_state,
			{ "Availability Status", "oml.fom.attr.avail_state",
			  FT_UINT8, BASE_HEX, VALS(oml_avail_state_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_event_type,
			{ "Event Type", "oml.fom.attr.event_type",
			  FT_UINT8, BASE_HEX, VALS(oml_event_type_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_severity,
			{ "Severity", "oml.fom.attr.severity",
			  FT_UINT8, BASE_HEX, VALS(oml_severity_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_bcch_arfcn,
			{ "BCCH ARFCN", "oml.fom.attr.bcch_arfcn",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  "ARFCN of the BCCH", HFILL }
		},
		{ &hf_attr_bsic,
			{ "BSIC", "oml.fom.attr.bsic",
			  FT_UINT16, BASE_HEX, NULL, 0,
			  "Base Station Identity Cdoe", HFILL }
		},
		{ &hf_attr_test_no,
			{ "Test Number", "oml.fom.attr.test_no",
			  FT_UINT8, BASE_HEX, VALS(oml_test_no_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_tsc,
			{ "TSC", "oml.fom.attr.tsc",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  "Training Sequence Code", HFILL }
		},
		{ &hf_attr_tei,
			{ "TEI", "oml.fom.attr.tei",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_attr_ach_btsp,
			{ "BTS E1 Port", "oml.fom.attr.abis_ch.bts_port",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_attr_ach_tslot,
			{ "E1 Timeslot", "oml.fom.attr.abis_ch.timeslot",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_attr_ach_sslot,
			{ "E1 Subslot", "oml.fom.attr.abis_ch.subslot",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_attr_gsm_time,
			{ "GSM Time", "oml.fom.attr.gsm_time",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_attr_chan_comb,
			{ "Channel Combination", "oml.fom.attr.chan_comb",
			  FT_UINT8, BASE_HEX, VALS(oml_chan_comb_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_hsn,
			{ "HSN", "oml.fom.attr.hsn",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Hopping Sequence Number", HFILL }
		},
		{ &hf_attr_maio,
			{ "MAIO", "oml.fom.attr.maio",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Mobile Allocation Index Offset", HFILL }
		},

		/* IP Access */
		{ &hf_oml_ipa_tres_attr_tag,
			{ "IPA Test Result Embedded IE",
						"oml.fom.testrep.ipa_tag",
			  FT_UINT8, BASE_HEX, VALS(ipacc_testres_ie_vals), 0,
			  "Information Element embedded into the Test Result "
			  "of ip.access BTS", HFILL },
		},
		{ &hf_oml_ipa_tres_attr_len,
			{ "IPA Test Result Embedded IE Length",
						"oml.fom.testrep.ipa_len",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  "Length of ip.access Test Result Embedded IE", HFILL }
		},
		{ &hf_attr_ipa_test_res,
			{ "IPA Test Result", "oml.fom.testrep.result",
			  FT_UINT8, BASE_DEC, VALS(ipacc_test_res_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_rxlev,
			{ "Rx Level", "oml.fom.testrep.ipa_rxlev",
			  FT_UINT16, BASE_DEC, NULL, 0xfc00, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_b_rxlev,
			{ "Rx Level", "oml.fom.testrep.ipa_rxlev_b",
			  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_arfcn,
			{ "ARFCN", "oml.fom.testrep.ipa_arfcn",
			  FT_UINT16, BASE_DEC, NULL, 0x03ff, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_f_qual,
			{ "Frequency Quality", "oml.fom.testrep.ipa.freq_qual",
			  FT_UINT8, BASE_DEC, NULL, 0xfc, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_f_err,
			{ "Frequency Error", "oml.fom.testrep.ipa.freq_err",
			  FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_rxqual,
			{ "Rx Quality", "oml.fom.testrep.ipa.rx_qual",
			  FT_UINT8, BASE_DEC, NULL, 0x7, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_frame_offs,
			{ "Frame Offset", "oml.fom.testrep.ipa.frame_offset",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_framenr_offs,
			{ "Frame Number Offset",
					"oml.fom.testrep.ipa.framenr_offset",
			  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_bsic,
			{ "BSIC", "oml.fom.testrep.ipa.bsic",
			  FT_UINT8, BASE_DEC, NULL, 0x3f,
			  "Base Station Identity Code", HFILL }
		},
		{ &hf_attr_ipa_tr_cell_id,
			{ "Cell ID", "oml.fom.testrep.ipa.cell_id",
			  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_rsl_ip,
			{ "BSC RSL IP Address", "oml.fom.attr.ipa.rsl_ip",
			  FT_IPv4, BASE_NONE, NULL, 0,
			  "IP Address to which the BTS establishes "
			  "the RSL link", HFILL }
		},
		{ &hf_attr_ipa_rsl_port,
			{ "BSC RSL TCP Port", "oml.fom.attr.ipa.rsl_port",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  "Port number to which the BST establishes "
			  "the RSL link", HFILL }
		},
		{ &hf_attr_ipa_prim_oml_ip,
			{ "Primary OML IP Address",
					"oml.fom.attr.ipa.prim_oml_ip",
			  FT_IPv4, BASE_NONE, NULL, 0,
			  "IP Address of the BSC for the primary OML link",
			  HFILL }
		},
		{ &hf_attr_ipa_prim_oml_port,
			{ "Primary OML TCP Port",
					"oml.fom.attr.ipa.prim_oml_port",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  "TCP Port of the BSC for the primarly OML link",
			  HFILL }
		},
		{ &hf_attr_ipa_location_name,
			{ "Location Name", "oml.fom.attr.ipa.loc_name",
			  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_unit_name,
			{ "Unit Name", "oml.fom.attr.ipa.unit_name",
			  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_unit_id,
			{ "Unit ID", "oml.fom.attr.ipa.unit_id",
			  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_nv_flags,
			{ "NVRAM Config Flags", "oml.fom.attr.ipa.nv_flags",
			  FT_UINT16, BASE_HEX, NULL, 0xffff, NULL, HFILL }
		},
		{ &hf_attr_ipa_nv_mask,
			{ "NVRAM Config Mask", "oml.fom.attr.ipa.nv_mask",
			  FT_UINT16, BASE_HEX, NULL, 0xffff, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_si2,
			{ "System Information 2", "oml.fom.attr.ipa.si2",
			  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_si2bis,
			{ "System Information 2bis", "oml.fom.attr.ipa.si2bis",
			  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_si2ter,
			{ "System Information 2ter", "oml.fom.attr.ipa.si2ter",
			  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_tr_chan_desc,
			{ "Cell Channel Description",
						"oml.fom.attr.ipa.chan_desc",
			  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_nsl_sport,
			{ "NS Link IP Source Port",
						"oml.fom.attr.ipa.nsl_sport",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_nsl_daddr,
			{ "NS Link IP Destination Addr",
						"oml.fom.attr.ipa.nsl_daddr",
			  FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_nsl_dport,
			{ "NS Link IP Destination Port",
						"oml.fom.attr.ipa.nsl_dport",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_nsei,
			{ "NSEI", "oml.fom.attr.ipa.nsei",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_nsvci,
			{ "NSVCI", "oml.fom.attr.ipa.nsvci",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_bvci,
			{ "BVCI", "oml.fom.attr.ipa.bvci",
			  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_attr_ipa_rac,
			{ "RAC", "oml.fom.attr.ipa.rac",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  "Routing Area Code", HFILL }
		},
	};
	static gint *ett[] = {
		&ett_oml,
		&ett_oml_fom,
		&ett_oml_fom_att,
	};

	module_t *oml_module;

#define NM_ATT_TLVDEF_BASE(_attr, _type, _fixed_len)			\
	nm_att_tlvdef_base.def[_attr].type = _type;			\
	nm_att_tlvdef_base.def[_attr].fixed_len = _fixed_len;		\

	/* From openbsc/src/abis_nm.c, converted to support ANSI C. */
	NM_ATT_TLVDEF_BASE(NM_ATT_ABIS_CHANNEL,		TLV_TYPE_FIXED,	3);
	NM_ATT_TLVDEF_BASE(NM_ATT_ADD_INFO,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_ADD_TEXT,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_ADM_STATE,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_ARFCN_LIST,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_AUTON_REPORT,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_AVAIL_STATUS,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_BCCH_ARFCN,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_BSIC,			TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_BTS_AIR_TIMER,	TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_CCCH_L_I_P,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_CCCH_L_T,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_CHAN_COMB,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_CONN_FAIL_CRIT,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_DEST,			TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_BASE(NM_ATT_EVENT_TYPE,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_FILE_ID,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_FILE_VERSION,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_GSM_TIME,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_HSN,			TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_HW_CONFIG,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_HW_DESC,		TLV_TYPE_TLV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_INTAVE_PARAM,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_INTERF_BOUND,		TLV_TYPE_FIXED,	6);
	NM_ATT_TLVDEF_BASE(NM_ATT_LIST_REQ_ATTR,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MAIO,			TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MANUF_STATE,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MANUF_THRESH,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MANUF_ID,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MAX_TA,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MDROP_LINK,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_MDROP_NEXT,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_NACK_CAUSES,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_NY1,			TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_OPER_STATE,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_OVERL_PERIOD,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_PHYS_CONF,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_POWER_CLASS,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_POWER_THRESH,		TLV_TYPE_FIXED,	3);
	NM_ATT_TLVDEF_BASE(NM_ATT_PROB_CAUSE,		TLV_TYPE_FIXED,	3);
	NM_ATT_TLVDEF_BASE(NM_ATT_RACH_B_THRESH,	TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_LDAVG_SLOTS,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_RAD_SUBC,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_RF_MAXPOWR_R,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_SITE_INPUTS,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_SITE_OUTPUTS,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_SOURCE,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_SPEC_PROB,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_START_TIME,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_T200,			TLV_TYPE_FIXED,	7);
	NM_ATT_TLVDEF_BASE(NM_ATT_TEI,			TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_TEST_DUR,		TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_BASE(NM_ATT_TEST_NO,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_TEST_REPORT,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_VSWR_THRESH,		TLV_TYPE_FIXED, 2);
	NM_ATT_TLVDEF_BASE(NM_ATT_WINDOW_SIZE,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_TSC,			TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_SW_CONFIG,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_SEVERITY,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_GET_ARI,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_HW_CONF_CHG,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_OUTST_ALARM,		TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_FILE_DATA,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_BASE(NM_ATT_MEAS_RES,		TLV_TYPE_TL16V,	0);

	/* BS 11 specifics */
#define NM_ATT_TLVDEV_BS11(_attr, _type, _fixed_len)		\
	nm_att_tlvdev_bs11.def[_attr].type = _type;		\
	nm_att_tlvdev_bs11.def[_attr].fixed_len = _fixed_len;	\

	/* different stndard IEs */
	NM_ATT_TLVDEV_BS11(NM_ATT_OUTST_ALARM,		TLV_TYPE_TLV,	0);
	NM_ATT_TLVDEV_BS11(NM_ATT_HW_DESC,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEV_BS11(NM_ATT_ARFCN_LIST,		TLV_TYPE_TLV16,	0);

	/* proprietary IEs */
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_ABIS_EXT_TIME,     TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_OM_LAPD_REL_TIMER, TLV_TYPE_FIXED, 2);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_SH_LAPD_INT_TIMER, TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_EMERG_TIMER1,      TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_EMERG_TIMER2,      TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_BTSLS_HOPPING,     TLV_TYPE_FIXED, 1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_CELL_ALLOC_NR,     TLV_TYPE_FIXED, 1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_ENA_INTERF_CLASS,  TLV_TYPE_FIXED, 1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_FACCH_QUAL,        TLV_TYPE_FIXED, 1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_TSYNC,             TLV_TYPE_FIXED, 2);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_TTRAU,             TLV_TYPE_FIXED, 2);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_EXCESSIVE_DISTANCE,TLV_TYPE_TLV,   1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_HOPPING_MODE,      TLV_TYPE_TLV,   1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_RF_RES_IND_PER,    TLV_TYPE_FIXED, 1);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_RADIO_MEAS_GRAN,   TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_RADIO_MEAS_REP,    TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_EMRG_CFG_MEMBER,   TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_TRX_AREA,          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_ESN_FW_CODE_NO,    TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_ESN_HW_CODE_NO,    TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_ESN_PCB_SERIAL,    TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_BOOT_SW_VERS,      TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(0x59,                          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(0xd5,                          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(0xa8,                          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_PASSWORD,          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_TXPWR,             TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_RSSI_OFFS,         TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_LINE_CFG,          TLV_TYPE_TV,    0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_L1_PROT_TYPE,      TLV_TYPE_TV,    0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_BIT_ERR_THESH,     TLV_TYPE_FIXED, 2);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_DIVERSITY,         TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_LMT_LOGON_SESSION, TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_LMT_LOGIN_TIME,    TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_LMT_USER_ACC_LEV,  TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_LMT_USER_NAME,     TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_BTS_STATE,         TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_E1_STATE,          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_PLL_MODE,          TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_PLL,               TLV_TYPE_TLV,   0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_CCLK_ACCURACY,     TLV_TYPE_TV,    0);
	NM_ATT_TLVDEV_BS11(NM_ATT_BS11_CCLK_TYPE,         TLV_TYPE_TV,    0);

	/* ip.access specifics */
#define NM_ATT_TLVDEF_IPA(_attr, _type, _fixed_len)		\
	nm_att_tlvdef_ipa.def[_attr].type = _type;		\
	nm_att_tlvdef_ipa.def[_attr].fixed_len = _fixed_len;	\

	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_DST_IP,		TLV_TYPE_FIXED,	4);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_DST_IP_PORT,	TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_PRIM_OML_CFG,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_NV_FLAGS,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_FREQ_CTRL,	TLV_TYPE_FIXED,	2);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_SEC_OML_CFG,	TLV_TYPE_FIXED,	6);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_IP_IF_CFG,	TLV_TYPE_FIXED,	8);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_IP_GW_CFG,	TLV_TYPE_FIXED,	12);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_LOCATION,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_UNIT_ID,		TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_UNIT_NAME,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_SNMP_CFG,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_ALM_THRESH_LIST,	TLV_TYPE_TL16V,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_CUR_SW_CFG,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_STREAM_ID,	TLV_TYPE_TV,	0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_RAC,		TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_OBJ_VERSION,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_GPRS_PAGING_CFG,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_NSEI,		TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_BVCI,		TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_NSVCI,		TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_NS_CFG,		TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_BSSGP_CFG,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_NS_LINK_CFG,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_RLC_CFG,		TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_SUPP_FEATURES,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_CODING_SCHEMES,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_RLC_CFG_2,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_RLC_CFG_3,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_PAGING_CFG,	TLV_TYPE_FIXED, 2);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_FILE_DATA,	TLV_TYPE_TL16V, 0);
	NM_ATT_TLVDEF_IPA(NM_ATT_IPACC_CGI,		TLV_TYPE_TL16V, 0);

	/* assign our custom match functions */
	proto_abis_oml = proto_register_protocol("GSM A-bis OML", "A-bis OML",
						 "gsm_abis_oml");

	proto_register_field_array(proto_abis_oml, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	new_register_dissector("gsm_abis_oml", dissect_abis_oml, proto_abis_oml);

	oml_module = prefs_register_protocol(proto_abis_oml, proto_reg_handoff_abis_oml);
	prefs_register_enum_preference(oml_module, "oml_dialect",
		    "A-bis OML dialect to be used",
		    "Use ipaccess nanoBTS specific definitions for OML",
		    &global_oml_dialect, oml_dialect_enumvals, TRUE);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_abis_oml(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		dissector_handle_t abis_oml_handle;

		abis_oml_handle = new_create_dissector_handle(dissect_abis_oml,
							  proto_abis_oml);
		dissector_add_uint("lapd.gsm.sapi", LAPD_GSM_SAPI_OM_PROC,
				   abis_oml_handle);

	} else {
		/* preferences have been changed */
	}
}
