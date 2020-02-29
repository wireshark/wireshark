/* packet-gsmtap.c
 * Routines for GSMTAP captures
 *
 * (C) 2008-2013 by Harald Welte <laforge@gnumonks.org>
 * (C) 2011 by Holger Hans Peter Freyther
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* GSMTAP is a generic header format for GSM protocol captures,
 * it uses the IANA-assigned UDP port number 4729 and carries
 * payload in various formats of GSM interfaces such as Um MAC
 * blocks or Um bursts.
 *
 * It is defined by the gsmtap.h libosmocore header, in
 *
 * http://cgit.osmocom.org/libosmocore/tree/include/osmocom/core/gsmtap.h
 *
 * Example programs generating GSMTAP data are airprobe
 * (http://airprobe.org/) or OsmocomBB (http://bb.osmocom.org/)
 *
 * It has also been used for Tetra by the OsmocomTETRA project.
 * (http://tetra.osmocom.org/)
 *
 * GSMTAP also carries payload in various formats of WiMAX interfaces.
 * It uses the wimax plugin to decode the WiMAX bursts.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-gsmtap.h"
#include "packet-lapdm.h"
#include "packet-tetra.h"

void proto_register_gsmtap(void);
void proto_reg_handoff_gsmtap(void);

static int proto_gsmtap = -1;

static int hf_gsmtap_version = -1;
static int hf_gsmtap_hdrlen = -1;
static int hf_gsmtap_type = -1;
static int hf_gsmtap_timeslot = -1;
static int hf_gsmtap_subslot = -1;
static int hf_gsmtap_arfcn = -1;
static int hf_gsmtap_uplink = -1;
static int hf_gsmtap_pcs = -1;
static int hf_gsmtap_signal_dbm = -1;
static int hf_gsmtap_snr_db = -1;
static int hf_gsmtap_frame_nr = -1;
static int hf_gsmtap_burst_type = -1;
static int hf_gsmtap_channel_type = -1;
static int hf_gsmtap_tetra_channel_type = -1;
static int hf_gsmtap_gmr1_channel_type = -1;
static int hf_gsmtap_rrc_sub_type = -1;
static int hf_gsmtap_antenna = -1;

static int hf_sacch_l1h_power_lev = -1;
static int hf_sacch_l1h_fpc = -1;
static int hf_sacch_l1h_ta = -1;

static int hf_ptcch_spare = -1;
static int hf_ptcch_ta_idx = -1;
static int hf_ptcch_ta_val = -1;
static int hf_ptcch_padding = -1;

static gint ett_gsmtap = -1;

enum {
	GSMTAP_SUB_DATA = 0,
	GSMTAP_SUB_UM,
	GSMTAP_SUB_UM_LAPDM,
	GSMTAP_SUB_UM_RLC_MAC_UL,
	GSMTAP_SUB_UM_RLC_MAC_DL,
	GSMTAP_SUB_LLC,
	GSMTAP_SUB_SNDCP,
	GSMTAP_SUB_ABIS,
	/* WiMAX sub handles */
	GSMTAP_SUB_CDMA_CODE,
	GSMTAP_SUB_FCH,
	GSMTAP_SUB_FFB,
	GSMTAP_SUB_PDU,
	GSMTAP_SUB_HACK,
	GSMTAP_SUB_PHY_ATTRIBUTES,
	GSMTAP_SUB_CBCH,
	GSMTAP_SUB_SIM,
	/* GMR-1 sub handles */
	GSMTAP_SUB_GMR1_BCCH,
	GSMTAP_SUB_GMR1_CCCH,
	GSMTAP_SUB_GMR1_LAPSAT,
	GSMTAP_SUB_GMR1_RACH,
	/* UMTS */
	GSMTAP_SUB_UMTS_RLC_MAC,
	GSMTAP_SUB_UMTS_RRC,
	/* LTE*/
	GSMTAP_SUB_LTE_RRC,
	GSMTAP_SUB_LTE_NAS,

	GSMTAP_SUB_MAX
};

enum {
	GSMTAP_RRC_SUB_DL_DCCH_Message = 0,
	GSMTAP_RRC_SUB_UL_DCCH_Message,
	GSMTAP_RRC_SUB_DL_CCCH_Message,
	GSMTAP_RRC_SUB_UL_CCCH_Message,
	GSMTAP_RRC_SUB_PCCH_Message,
	GSMTAP_RRC_SUB_DL_SHCCH_Message,
	GSMTAP_RRC_SUB_UL_SHCCH_Message,
	GSMTAP_RRC_SUB_BCCH_FACH_Message,
	GSMTAP_RRC_SUB_BCCH_BCH_Message,
	GSMTAP_RRC_SUB_MCCH_Message,
	GSMTAP_RRC_SUB_MSCH_Message,
	GSMTAP_RRC_SUB_HandoverToUTRANCommand,
	GSMTAP_RRC_SUB_InterRATHandoverInfo,
	GSMTAP_RRC_SUB_SystemInformation_BCH,
	GSMTAP_RRC_SUB_System_Information_Container,
	GSMTAP_RRC_SUB_UE_RadioAccessCapabilityInfo,
	GSMTAP_RRC_SUB_MasterInformationBlock,
	GSMTAP_RRC_SUB_SysInfoType1,
	GSMTAP_RRC_SUB_SysInfoType2,
	GSMTAP_RRC_SUB_SysInfoType3,
	GSMTAP_RRC_SUB_SysInfoType4,
	GSMTAP_RRC_SUB_SysInfoType5,
	GSMTAP_RRC_SUB_SysInfoType5bis,
	GSMTAP_RRC_SUB_SysInfoType6,
	GSMTAP_RRC_SUB_SysInfoType7,
	GSMTAP_RRC_SUB_SysInfoType8,
	GSMTAP_RRC_SUB_SysInfoType9,
	GSMTAP_RRC_SUB_SysInfoType10,
	GSMTAP_RRC_SUB_SysInfoType11,
	GSMTAP_RRC_SUB_SysInfoType11bis,
	GSMTAP_RRC_SUB_SysInfoType12,
	GSMTAP_RRC_SUB_SysInfoType13,
	GSMTAP_RRC_SUB_SysInfoType13_1,
	GSMTAP_RRC_SUB_SysInfoType13_2,
	GSMTAP_RRC_SUB_SysInfoType13_3,
	GSMTAP_RRC_SUB_SysInfoType13_4,
	GSMTAP_RRC_SUB_SysInfoType14,
	GSMTAP_RRC_SUB_SysInfoType15,
	GSMTAP_RRC_SUB_SysInfoType15bis,
	GSMTAP_RRC_SUB_SysInfoType15_1,
	GSMTAP_RRC_SUB_SysInfoType15_1bis,
	GSMTAP_RRC_SUB_SysInfoType15_2,
	GSMTAP_RRC_SUB_SysInfoType15_2bis,
	GSMTAP_RRC_SUB_SysInfoType15_2ter,
	GSMTAP_RRC_SUB_SysInfoType15_3,
	GSMTAP_RRC_SUB_SysInfoType15_3bis,
	GSMTAP_RRC_SUB_SysInfoType15_4,
	GSMTAP_RRC_SUB_SysInfoType15_5,
	GSMTAP_RRC_SUB_SysInfoType15_6,
	GSMTAP_RRC_SUB_SysInfoType15_7,
	GSMTAP_RRC_SUB_SysInfoType15_8,
	GSMTAP_RRC_SUB_SysInfoType16,
	GSMTAP_RRC_SUB_SysInfoType17,
	GSMTAP_RRC_SUB_SysInfoType18,
	GSMTAP_RRC_SUB_SysInfoType19,
	GSMTAP_RRC_SUB_SysInfoType20,
	GSMTAP_RRC_SUB_SysInfoType21,
	GSMTAP_RRC_SUB_SysInfoType22,
	GSMTAP_RRC_SUB_SysInfoTypeSB1,
	GSMTAP_RRC_SUB_SysInfoTypeSB2,
	GSMTAP_RRC_SUB_ToTargetRNC_Container,
	GSMTAP_RRC_SUB_TargetRNC_ToSourceRNC_Container,

	GSMTAP_RRC_SUB_MAX
};

static const value_string rrc_sub_types[] = {
	{ GSMTAP_RRC_SUB_DL_DCCH_Message,					"RRC DL-DCCH" },
	{ GSMTAP_RRC_SUB_UL_DCCH_Message,					"RRC UL-DCCH" },
	{ GSMTAP_RRC_SUB_DL_CCCH_Message,					"RRC DL-CCCH" },
	{ GSMTAP_RRC_SUB_UL_CCCH_Message,					"RRC UL-CCCH" },
	{ GSMTAP_RRC_SUB_PCCH_Message,						"RRC PCCH" },
	{ GSMTAP_RRC_SUB_DL_SHCCH_Message,					"RRC DL-SHCCH" },
	{ GSMTAP_RRC_SUB_UL_SHCCH_Message,					"RRC UL-SHCCH" },
	{ GSMTAP_RRC_SUB_BCCH_FACH_Message,					"RRC BCCH-FACH" },
	{ GSMTAP_RRC_SUB_BCCH_BCH_Message,					"RRC BCCH-BCH" },
	{ GSMTAP_RRC_SUB_MCCH_Message,						"RRC MCCH" },
	{ GSMTAP_RRC_SUB_MSCH_Message,						"RRC MSCH" },
	{ GSMTAP_RRC_SUB_HandoverToUTRANCommand,			"RRC Handover To UTRAN Command" },
	{ GSMTAP_RRC_SUB_InterRATHandoverInfo,				"RRC Inter RAT Handover Info" },
	{ GSMTAP_RRC_SUB_SystemInformation_BCH,				"RRC System Information - BCH" },
	{ GSMTAP_RRC_SUB_System_Information_Container,		"RRC System Information Container" },
	{ GSMTAP_RRC_SUB_UE_RadioAccessCapabilityInfo,		"RRC UE Radio Access Capability Info" },
	{ GSMTAP_RRC_SUB_MasterInformationBlock,			"RRC Master Information Block" },
	{ GSMTAP_RRC_SUB_SysInfoType1,						"RRC System Information Type 1" },
	{ GSMTAP_RRC_SUB_SysInfoType2,						"RRC System Information Type 2" },
	{ GSMTAP_RRC_SUB_SysInfoType3,						"RRC System Information Type 3" },
	{ GSMTAP_RRC_SUB_SysInfoType4,						"RRC System Information Type 4" },
	{ GSMTAP_RRC_SUB_SysInfoType5,						"RRC System Information Type 5" },
	{ GSMTAP_RRC_SUB_SysInfoType5bis,					"RRC System Information Type 5bis" },
	{ GSMTAP_RRC_SUB_SysInfoType6,						"RRC System Information Type 6" },
	{ GSMTAP_RRC_SUB_SysInfoType7,						"RRC System Information Type 7" },
	{ GSMTAP_RRC_SUB_SysInfoType8,						"RRC System Information Type 8" },
	{ GSMTAP_RRC_SUB_SysInfoType9,						"RRC System Information Type 9" },
	{ GSMTAP_RRC_SUB_SysInfoType10,						"RRC System Information Type 10" },
	{ GSMTAP_RRC_SUB_SysInfoType11,						"RRC System Information Type 11" },
	{ GSMTAP_RRC_SUB_SysInfoType11bis,					"RRC System Information Type 11bis" },
	{ GSMTAP_RRC_SUB_SysInfoType12,						"RRC System Information Type 12" },
	{ GSMTAP_RRC_SUB_SysInfoType13,						"RRC System Information Type 13" },
	{ GSMTAP_RRC_SUB_SysInfoType13_1,					"RRC System Information Type 13.1" },
	{ GSMTAP_RRC_SUB_SysInfoType13_2,					"RRC System Information Type 13.2" },
	{ GSMTAP_RRC_SUB_SysInfoType13_3,					"RRC System Information Type 13.3" },
	{ GSMTAP_RRC_SUB_SysInfoType13_4,					"RRC System Information Type 13.4" },
	{ GSMTAP_RRC_SUB_SysInfoType14,						"RRC System Information Type 14" },
	{ GSMTAP_RRC_SUB_SysInfoType15,						"RRC System Information Type 15" },
	{ GSMTAP_RRC_SUB_SysInfoType15bis,					"RRC System Information Type 15bis" },
	{ GSMTAP_RRC_SUB_SysInfoType15_1,					"RRC System Information Type 15.1" },
	{ GSMTAP_RRC_SUB_SysInfoType15_1bis,				"RRC System Information Type 15.1bis" },
	{ GSMTAP_RRC_SUB_SysInfoType15_2,					"RRC System Information Type 15.1" },
	{ GSMTAP_RRC_SUB_SysInfoType15_2bis,				"RRC System Information Type 15.2bis" },
	{ GSMTAP_RRC_SUB_SysInfoType15_2ter,				"RRC System Information Type 15.2ter" },
	{ GSMTAP_RRC_SUB_SysInfoType15_3,					"RRC System Information Type 15.3" },
	{ GSMTAP_RRC_SUB_SysInfoType15_3bis,				"RRC System Information Type 15.3bis" },
	{ GSMTAP_RRC_SUB_SysInfoType15_4,					"RRC System Information Type 15.4" },
	{ GSMTAP_RRC_SUB_SysInfoType15_5,					"RRC System Information Type 15.5" },
	{ GSMTAP_RRC_SUB_SysInfoType15_6,					"RRC System Information Type 15.6" },
	{ GSMTAP_RRC_SUB_SysInfoType15_7,					"RRC System Information Type 15.7 "},
	{ GSMTAP_RRC_SUB_SysInfoType15_8,					"RRC System Information Type 15.8" },
	{ GSMTAP_RRC_SUB_SysInfoType16,						"RRC System Information Type 16" },
	{ GSMTAP_RRC_SUB_SysInfoType17,						"RRC System Information Type 17" },
	{ GSMTAP_RRC_SUB_SysInfoType18,						"RRC System Information Type 18" },
	{ GSMTAP_RRC_SUB_SysInfoType19,						"RRC System Information Type 19" },
	{ GSMTAP_RRC_SUB_SysInfoType20,						"RRC System Information Type 20" },
	{ GSMTAP_RRC_SUB_SysInfoType21,						"RRC System Information Type 21" },
	{ GSMTAP_RRC_SUB_SysInfoType22,						"RRC System Information Type 22" },
	{ GSMTAP_RRC_SUB_SysInfoTypeSB1,					"RRC System Information Type SB 1" },
	{ GSMTAP_RRC_SUB_SysInfoTypeSB2,					"RRC System Information Type SB 2" },
	{ GSMTAP_RRC_SUB_ToTargetRNC_Container,				"RRC To Target RNC Container" },
	{ GSMTAP_RRC_SUB_TargetRNC_ToSourceRNC_Container,	"RRC Target RNC To Source RNC Container" },
	{ 0,												NULL }
};

/* LTE RRC message types */
enum {
	GSMTAP_LTE_RRC_SUB_DL_CCCH_Message = 0,
	GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
	GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
	GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
	GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
	GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
	GSMTAP_LTE_RRC_SUB_PCCH_Message,
	GSMTAP_LTE_RRC_SUB_MCCH_Message,
	GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_MBMS,
	GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_BR,
	GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_MBMS,
	GSMTAP_LTE_RRC_SUB_SC_MCCH_Message,
	GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_Message,
	GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_Message_V2X,
	GSMTAP_LTE_RRC_SUB_DL_CCCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_DL_DCCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_TDD_NB,
	GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_PCCH_Message_NB,
	GSMTAP_LTE_RRC_SUB_SC_MCCH_Message_NB,

	GSMTAP_LTE_RRC_SUB_MAX
};

/* LTE NAS message types */
enum {
	GSMTAP_LTE_NAS_PLAIN = 0,
	GSMTAP_LTE_NAS_SEC_HEADER,

	GSMTAP_LTE_NAS_SUB_MAX
};


static dissector_handle_t sub_handles[GSMTAP_SUB_MAX];
static dissector_handle_t rrc_sub_handles[GSMTAP_RRC_SUB_MAX];
static dissector_handle_t lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_MAX];
static dissector_handle_t lte_nas_sub_handles[GSMTAP_LTE_NAS_SUB_MAX];

static dissector_table_t gsmtap_dissector_table;

static const value_string gsmtap_bursts[] = {
	{ GSMTAP_BURST_UNKNOWN,		"UNKNOWN" },
	{ GSMTAP_BURST_FCCH,		"FCCH" },
	{ GSMTAP_BURST_PARTIAL_SCH,	"PARTIAL SCH" },
	{ GSMTAP_BURST_SCH,			"SCH" },
	{ GSMTAP_BURST_CTS_SCH,		"CTS SCH" },
	{ GSMTAP_BURST_COMPACT_SCH,	"COMPACT SCH" },
	{ GSMTAP_BURST_NORMAL,		"NORMAL" },
	{ GSMTAP_BURST_DUMMY,		"DUMMY" },
	{ GSMTAP_BURST_ACCESS,		"RACH" },
	/* WiMAX bursts */
	{ GSMTAP_BURST_CDMA_CODE,       "CDMA Code"  },
	{ GSMTAP_BURST_FCH,             "FCH"  },
	{ GSMTAP_BURST_FFB,             "Fast Feedback" },
	{ GSMTAP_BURST_PDU,             "PDU" },
	{ GSMTAP_BURST_HACK,            "HACK" },
	{ GSMTAP_BURST_PHY_ATTRIBUTES,  "PHY Attributes" },
	{ 0,				NULL },
};

static const value_string gsmtap_channels[] = {
	{ GSMTAP_CHANNEL_UNKNOWN,	"UNKNOWN" },
	{ GSMTAP_CHANNEL_BCCH,		"BCCH" },
	{ GSMTAP_CHANNEL_CCCH,		"CCCH" },
	{ GSMTAP_CHANNEL_RACH,		"RACH" },
	{ GSMTAP_CHANNEL_AGCH,		"AGCH" },
	{ GSMTAP_CHANNEL_PCH,		"PCH" },
	{ GSMTAP_CHANNEL_SDCCH,		"SDCCH" },
	{ GSMTAP_CHANNEL_SDCCH4,	"SDCCH/4" },
	{ GSMTAP_CHANNEL_SDCCH8,	"SDCCH/8" },
	{ GSMTAP_CHANNEL_TCH_F,		"FACCH/F" },
	{ GSMTAP_CHANNEL_TCH_H,		"FACCH/H" },
	{ GSMTAP_CHANNEL_PACCH,		"PACCH" },
	{ GSMTAP_CHANNEL_CBCH52,	"CBCH" },
	{ GSMTAP_CHANNEL_PDTCH,		"PDTCH" },
	{ GSMTAP_CHANNEL_PTCCH,		"PTTCH" },
	{ GSMTAP_CHANNEL_CBCH51,	"CBCH" },

	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_SDCCH,		"LSACCH" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_SDCCH4,	"SACCH/4" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_SDCCH8,	"SACCH/8" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_TCH_F,		"SACCH/F" },
	{ GSMTAP_CHANNEL_ACCH|
	  GSMTAP_CHANNEL_TCH_H,		"SACCH/H" },
	{ 0,				NULL },
};

static const value_string gsmtap_tetra_channels[] = {
	{ GSMTAP_TETRA_BSCH,		"BSCH"   },
	{ GSMTAP_TETRA_AACH,		"AACH"   },
	{ GSMTAP_TETRA_SCH_HU,		"SCH/HU" },
	{ GSMTAP_TETRA_SCH_HD,		"SCH/HD" },
	{ GSMTAP_TETRA_SCH_F,		"SCH/F"	 },
	{ GSMTAP_TETRA_BNCH,		"BNCH"   },
	{ GSMTAP_TETRA_STCH,		"STCH"   },
	{ GSMTAP_TETRA_TCH_F,		"AACH"   },
	{ 0,				NULL     },
};

static const value_string gsmtap_gmr1_channels[] = {
	{ GSMTAP_GMR1_BCCH,		"BCCH" },
	{ GSMTAP_GMR1_CCCH,		"CCCH" },
	{ GSMTAP_GMR1_PCH,		"PCH" },
	{ GSMTAP_GMR1_AGCH,		"AGCH" },
	{ GSMTAP_GMR1_BACH,		"BACH" },
	{ GSMTAP_GMR1_RACH,		"RACH" },
	{ GSMTAP_GMR1_CBCH,		"CBCH" },
	{ GSMTAP_GMR1_SDCCH,		"SDCCH" },
	{ GSMTAP_GMR1_TACCH,		"TACCH" },
	{ GSMTAP_GMR1_GBCH,		"GBCH" },
	{ GSMTAP_GMR1_TCH3,		"TCH3" },
	{ GSMTAP_GMR1_TCH3|
	  GSMTAP_GMR1_FACCH,		"FACCH3" },
	{ GSMTAP_GMR1_TCH3|
	  GSMTAP_GMR1_DKAB,		"DKAB" },
	{ GSMTAP_GMR1_TCH6,		"TCH6" },
	{ GSMTAP_GMR1_TCH6|
	  GSMTAP_GMR1_FACCH,		"FACCH6" },
	{ GSMTAP_GMR1_TCH6|
	  GSMTAP_GMR1_SACCH,		"SACCH6" },
	{ GSMTAP_GMR1_TCH9,		"TCH9" },
	{ GSMTAP_GMR1_TCH9|
	  GSMTAP_GMR1_FACCH,		"FACCH9" },
	{ GSMTAP_GMR1_TCH9|
	  GSMTAP_GMR1_SACCH,		"SACCH9" },
	{ 0,				NULL },
};

/* the mapping is not complete */
static const int gsmtap_to_tetra[9] = {
	0,
	TETRA_CHAN_BSCH,
	TETRA_CHAN_AACH,
	TETRA_CHAN_SCH_HU,
	0,
	TETRA_CHAN_SCH_F,
	TETRA_CHAN_BNCH,
	TETRA_CHAN_STCH,
	0
};

static const value_string gsmtap_types[] = {
	{ GSMTAP_TYPE_UM,	"GSM Um (MS<->BTS)" },
	{ GSMTAP_TYPE_ABIS,	"GSM Abis (BTS<->BSC)" },
	{ GSMTAP_TYPE_UM_BURST,	"GSM Um burst (MS<->BTS)" },
	{ GSMTAP_TYPE_SIM,	"SIM" },
	{ GSMTAP_TYPE_TETRA_I1, "TETRA V+D"},
	{ GSMTAP_TTPE_TETRA_I1_BURST, "TETRA V+D burst"},
	{ GSMTAP_TYPE_WMX_BURST,"WiMAX burst" },
	{ GSMTAP_TYPE_GMR1_UM, "GMR-1 air interface (MES-MS<->GTS)" },
	{ GSMTAP_TYPE_UMTS_RLC_MAC,	"UMTS RLC/MAC" },
	{ GSMTAP_TYPE_UMTS_RRC,		"UMTS RRC" },
	{ GSMTAP_TYPE_LTE_RRC,		"LTE RRC" },
	{ GSMTAP_TYPE_LTE_MAC,		"LTE MAC" },
	{ GSMTAP_TYPE_LTE_MAC_FRAMED,	"LTE MAC framed" },
	{ GSMTAP_TYPE_OSMOCORE_LOG,	"libosmocore logging" },
	{ GSMTAP_TYPE_QC_DIAG,		"Qualcomm DIAG" },
	{ GSMTAP_TYPE_LTE_NAS,		"LTE NAS" },
	{ 0,			NULL },
};

/* dissect a SACCH L1 header which is included in the first 2 bytes
 * of every SACCH frame (according to TS 04.04) */
static void
dissect_sacch_l1h(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *l1h_tree = NULL;

	if (!tree)
		return;

	ti = proto_tree_add_protocol_format(tree, proto_gsmtap, tvb, 0, 2,
			"SACCH L1 Header, Power Level: %u, Timing Advance: %u",
			tvb_get_guint8(tvb, 0) & 0x1f,
			tvb_get_guint8(tvb, 1));
	l1h_tree = proto_item_add_subtree(ti, ett_gsmtap);
	/* Power Level */
	proto_tree_add_item(l1h_tree, hf_sacch_l1h_power_lev, tvb, 0, 1, ENC_BIG_ENDIAN);
	/* Fast Power Control */
	proto_tree_add_item(l1h_tree, hf_sacch_l1h_fpc, tvb, 0, 1, ENC_BIG_ENDIAN);
	/* Acutal Timing Advance */
	proto_tree_add_item(l1h_tree, hf_sacch_l1h_ta, tvb, 1, 1, ENC_BIG_ENDIAN);
}

/* Dissect a PTCCH/D (Packet Timing Advance Control Channel) message.
 * See 3GPP TS 45.010, section 5.6.2 and 3GPP TS 45.002, section 3.3.4.2.
 *
 *   +--------------+--------------+-----+---------------+------------------+
 *   |    Octet 1   |    Octet 2   |     |    Octet 16   |  Octet 17 .. 23  |
 *   +---+----------+---+----------+-----+---+-----------+------------------+
 *   | 0 | TA TAI=0 | 0 | TA TAI=1 | ... | 0 | TA TAI=15 | Padding 00101011 |
 *   +---+----------+---+----------+-----+---+-----------+------------------+
 */
static void
dissect_ptcch_dl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sub_tree;
	proto_item *ti, *gi;
	int offset;

	col_set_str(pinfo->cinfo, COL_INFO, "Packet Timing Advance Control");

	if (!tree)
		return;

	ti = proto_tree_add_protocol_format(tree, proto_gsmtap, tvb, 0, 23,
		"PTCCH (Packet Timing Advance Control Channel) on Downlink");
	sub_tree = proto_item_add_subtree(ti, ett_gsmtap);

	for (offset = 0; offset < 16; offset++) {
		/* Meta info: Timing Advance Index */
		gi = proto_tree_add_uint(sub_tree, hf_ptcch_ta_idx, tvb, 0, 0, offset);
		proto_item_set_generated(gi);

		proto_tree_add_item(sub_tree, hf_ptcch_spare, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(sub_tree, hf_ptcch_ta_val, tvb, offset, 1, ENC_NA);
	}

	/* Spare padding */
	proto_tree_add_item(sub_tree, hf_ptcch_padding, tvb, offset, -1, ENC_NA);
}

static void
handle_lapdm(guint8 sub_type, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	lapdm_data_t ld;

	ld.hdr_type = LAPDM_HDR_FMT_B;
	/* only downlink SACCH frames use B4 header format */
	if (sub_type & GSMTAP_CHANNEL_ACCH && pinfo->p2p_dir == P2P_DIR_RECV)
		ld.hdr_type = LAPDM_HDR_FMT_B4;
	call_dissector_with_data(sub_handles[GSMTAP_SUB_UM_LAPDM], tvb, pinfo, tree, &ld);
}

static void
handle_tetra(int channel, tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree)
{
	int tetra_chan;
	if (channel < 0 || channel > GSMTAP_TETRA_TCH_F)
		return;

	tetra_chan = gsmtap_to_tetra[channel];
	if (tetra_chan <= 0)
		return;

	tetra_dissect_pdu(tetra_chan, TETRA_DOWNLINK, payload_tvb, tree, pinfo);
}

/* dissect a GSMTAP header and hand payload off to respective dissector */
static int
dissect_gsmtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int sub_handle, sub_handle_idx = 0, len, offset = 0;
	proto_item *ti;
	proto_tree *gsmtap_tree = NULL;
	tvbuff_t *payload_tvb, *l1h_tvb = NULL;
	guint8 hdr_len, type, sub_type, timeslot, subslot;
	guint16 arfcn;

	len = tvb_reported_length(tvb);

	hdr_len = tvb_get_guint8(tvb, offset + 1) <<2;
	type = tvb_get_guint8(tvb, offset + 2);
	timeslot = tvb_get_guint8(tvb, offset + 3);
	arfcn = tvb_get_ntohs(tvb, offset + 4);
	sub_type = tvb_get_guint8(tvb, offset + 12);
	subslot = tvb_get_guint8(tvb, offset + 14);

	/* In case of a SACCH, there is a two-byte L1 header in front
	 * of the packet (see TS 04.04) */
	if (type == GSMTAP_TYPE_UM &&
	    sub_type & GSMTAP_CHANNEL_ACCH) {
		l1h_tvb = tvb_new_subset_length(tvb, hdr_len, 2);
		payload_tvb = tvb_new_subset_length(tvb, hdr_len+2, len-(hdr_len+2));
	} else {
		payload_tvb = tvb_new_subset_length(tvb, hdr_len, len-hdr_len);
	}

	/* We don't want any UDP related info left in the INFO field, as the
	 * gsm_a_dtap dissector will not clear but only append */
	col_clear(pinfo->cinfo, COL_INFO);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSMTAP");

	/* Some GSMTAP types are completely unrelated to the Um air interface */
	if (dissector_try_uint(gsmtap_dissector_table, type, payload_tvb,
			       pinfo, tree))
		return tvb_captured_length(tvb);

	if (arfcn & GSMTAP_ARFCN_F_UPLINK) {
		col_set_str(pinfo->cinfo, COL_RES_NET_SRC, "MS");
		col_set_str(pinfo->cinfo, COL_RES_NET_DST, "BTS");
		/* p2p_dir is used by the LAPDm dissector */
		pinfo->p2p_dir = P2P_DIR_SENT;
	} else {
		col_set_str(pinfo->cinfo, COL_RES_NET_SRC, "BTS");
		switch (sub_type & ~GSMTAP_CHANNEL_ACCH) {
		case GSMTAP_CHANNEL_BCCH:
		case GSMTAP_CHANNEL_CCCH:
		case GSMTAP_CHANNEL_PCH:
		case GSMTAP_CHANNEL_AGCH:
		case GSMTAP_CHANNEL_CBCH51:
		case GSMTAP_CHANNEL_CBCH52:
		case GSMTAP_CHANNEL_PTCCH:
			col_set_str(pinfo->cinfo, COL_RES_NET_DST, "Broadcast");
			break;
		default:
			col_set_str(pinfo->cinfo, COL_RES_NET_DST, "MS");
			break;
		}
		/* p2p_dir is used by the LAPDm dissector */
		pinfo->p2p_dir = P2P_DIR_RECV;
	}

	/* Try to build an identifier of different 'streams' */
	/* (AFCN _cant_ be used because of hopping */
	conversation_create_endpoint_by_id(pinfo, ENDPOINT_GSMTAP, (timeslot << 3) | subslot, 0);

	if (tree) {
		guint8 channel;
		const char *channel_str;
		channel = tvb_get_guint8(tvb, offset+12);
		if (type == GSMTAP_TYPE_TETRA_I1)
			channel_str = val_to_str(channel, gsmtap_tetra_channels, "Unknown: %d");
		else if (type == GSMTAP_TYPE_GMR1_UM)
			channel_str = val_to_str(channel, gsmtap_gmr1_channels, "Unknown: %d");
		else
			channel_str = val_to_str(channel, gsmtap_channels, "Unknown: %d");

		ti = proto_tree_add_protocol_format(tree, proto_gsmtap, tvb, 0, hdr_len,
			"GSM TAP Header, ARFCN: %u (%s), TS: %u, Channel: %s (%u)",
			arfcn & GSMTAP_ARFCN_MASK,
			arfcn & GSMTAP_ARFCN_F_UPLINK ? "Uplink" : "Downlink",
			tvb_get_guint8(tvb, offset+3),
			channel_str,
			tvb_get_guint8(tvb, offset+14));
		gsmtap_tree = proto_item_add_subtree(ti, ett_gsmtap);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_version,
				    tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(gsmtap_tree, hf_gsmtap_hdrlen,
				    tvb, offset+1, 1, hdr_len);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_type,
				    tvb, offset+2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_timeslot,
				    tvb, offset+3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_arfcn,
				    tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_uplink,
				    tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_pcs,
				    tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_signal_dbm,
				    tvb, offset+6, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_snr_db,
				    tvb, offset+7, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_frame_nr,
				    tvb, offset+8, 4, ENC_BIG_ENDIAN);
		if (type == GSMTAP_TYPE_UM_BURST)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_burst_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_UM)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_channel_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_TETRA_I1)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_tetra_channel_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_WMX_BURST)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_burst_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_GMR1_UM)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_gmr1_channel_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		else if (type == GSMTAP_TYPE_UMTS_RRC)
			proto_tree_add_item(gsmtap_tree, hf_gsmtap_rrc_sub_type,
					    tvb, offset+12, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_antenna,
				    tvb, offset+13, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(gsmtap_tree, hf_gsmtap_subslot,
				    tvb, offset+14, 1, ENC_BIG_ENDIAN);
	}

	switch (type) {
	case GSMTAP_TYPE_UMTS_RRC:
		sub_handle = GSMTAP_SUB_UMTS_RRC;
		sub_handle_idx = sub_type;
		if (sub_handle_idx >= GSMTAP_RRC_SUB_MAX) {
			sub_handle = GSMTAP_SUB_DATA;
		}
		/* make entry in the Protocol column on summary display.
		 * Normally, the RRC dissector would be doing this, but
		 * we are bypassing dissect_rrc() and directly call a
		 * sub-dissector */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RRC");
		break;
	case GSMTAP_TYPE_LTE_RRC:
		sub_handle = GSMTAP_SUB_LTE_RRC;
		sub_handle_idx = sub_type;
		if (sub_handle_idx >= GSMTAP_LTE_RRC_SUB_MAX) {
			sub_handle = GSMTAP_SUB_DATA;
		}
		/*Directly call the respective lte rrc message dissector */
		break;
	case GSMTAP_TYPE_LTE_NAS:
		sub_handle = GSMTAP_SUB_LTE_NAS;
		sub_handle_idx = sub_type;
		if (sub_handle_idx >= GSMTAP_LTE_NAS_SUB_MAX) {
			sub_handle = GSMTAP_SUB_DATA;
		}
		break;

	case GSMTAP_TYPE_UM:
		if (l1h_tvb)
			dissect_sacch_l1h(l1h_tvb, tree);
		switch (sub_type & ~GSMTAP_CHANNEL_ACCH) {
		case GSMTAP_CHANNEL_BCCH:
		case GSMTAP_CHANNEL_CCCH:
		case GSMTAP_CHANNEL_PCH:
		case GSMTAP_CHANNEL_AGCH:
			/* FIXME: we might want to skip idle frames */
			sub_handle = GSMTAP_SUB_UM;
			break;
		case GSMTAP_CHANNEL_SDCCH:
		case GSMTAP_CHANNEL_SDCCH4:
		case GSMTAP_CHANNEL_SDCCH8:
		case GSMTAP_CHANNEL_TCH_F:
		case GSMTAP_CHANNEL_TCH_H:
			handle_lapdm(sub_type, payload_tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		case GSMTAP_CHANNEL_PACCH:
		case GSMTAP_CHANNEL_PDTCH:
			if (pinfo->p2p_dir == P2P_DIR_SENT) {
				sub_handle = GSMTAP_SUB_UM_RLC_MAC_UL;
			}
			else
			{
				sub_handle = GSMTAP_SUB_UM_RLC_MAC_DL;
			}
			break;
		/* See 3GPP TS 45.003, section 5.2 "Packet control channels" */
		case GSMTAP_CHANNEL_PTCCH:
			/* PTCCH/D carries Timing Advance updates encoded with CS-1 */
			if (pinfo->p2p_dir == P2P_DIR_RECV) {
				dissect_ptcch_dl(payload_tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			/* PTCCH/U carries Access Bursts for Timing Advance estimation */
			sub_handle = GSMTAP_SUB_DATA;
			break;

	        case GSMTAP_CHANNEL_CBCH51:
		case GSMTAP_CHANNEL_CBCH52:
			sub_handle = GSMTAP_SUB_CBCH;
			break;

		case GSMTAP_CHANNEL_RACH:
		default:
			sub_handle = GSMTAP_SUB_DATA;
			break;
		}
		break;
	case GSMTAP_TYPE_ABIS:
		sub_handle = GSMTAP_SUB_ABIS;
		break;
	case GSMTAP_TYPE_GB_LLC:
		sub_handle = GSMTAP_SUB_LLC;
		break;
	case GSMTAP_TYPE_GB_SNDCP:
		sub_handle = GSMTAP_SUB_SNDCP;
		break;
	case GSMTAP_TYPE_TETRA_I1:
		handle_tetra(tvb_get_guint8(tvb, offset+12), payload_tvb, pinfo, tree);
		return tvb_captured_length(tvb);
	case GSMTAP_TYPE_WMX_BURST:
		switch (sub_type) {
	        case GSMTAP_BURST_CDMA_CODE:
			sub_handle = GSMTAP_SUB_CDMA_CODE;
			break;
	        case GSMTAP_BURST_FCH:
			sub_handle = GSMTAP_SUB_FCH;
			break;
	        case GSMTAP_BURST_FFB:
			sub_handle = GSMTAP_SUB_FFB;
			break;
	        case GSMTAP_BURST_PDU:
			sub_handle = GSMTAP_SUB_PDU;
			break;
	        case GSMTAP_BURST_HACK:
			sub_handle = GSMTAP_SUB_HACK;
			break;
	        case GSMTAP_BURST_PHY_ATTRIBUTES:
			sub_handle = GSMTAP_SUB_PHY_ATTRIBUTES;
			break;
	        default:
	                sub_handle = GSMTAP_SUB_DATA;
	                break;
	        }
 		break;
	case GSMTAP_TYPE_GMR1_UM:
		switch (sub_type) {
		case GSMTAP_GMR1_BCCH:
			sub_handle = GSMTAP_SUB_GMR1_BCCH;
			break;
		case GSMTAP_GMR1_CCCH:
		case GSMTAP_GMR1_AGCH:
		case GSMTAP_GMR1_PCH:
			sub_handle = GSMTAP_SUB_GMR1_CCCH;
			break;
		case GSMTAP_GMR1_SDCCH:
		case GSMTAP_GMR1_TCH3 | GSMTAP_GMR1_FACCH:
		case GSMTAP_GMR1_TCH6 | GSMTAP_GMR1_FACCH:
		case GSMTAP_GMR1_TCH9 | GSMTAP_GMR1_FACCH:
			sub_handle = GSMTAP_SUB_GMR1_LAPSAT;
			break;
		case GSMTAP_GMR1_RACH:
			sub_handle = GSMTAP_SUB_GMR1_RACH;
			break;
		default:
			sub_handle = GSMTAP_SUB_DATA;
			break;
		}
		break;
	case GSMTAP_TYPE_UM_BURST:
	default:
		sub_handle = GSMTAP_SUB_DATA;
		break;
	}
	switch (sub_handle){
	case GSMTAP_SUB_UMTS_RRC:
		call_dissector(rrc_sub_handles[sub_handle_idx], payload_tvb,
			       pinfo, tree);
		break;
	case GSMTAP_SUB_LTE_RRC:
		call_dissector(lte_rrc_sub_handles[sub_handle_idx], payload_tvb,
			       pinfo, tree);
		break;
	case GSMTAP_SUB_LTE_NAS:
		call_dissector(lte_nas_sub_handles[sub_handle_idx], payload_tvb,
			       pinfo, tree);
		break;
	default:
		if (sub_handles[sub_handle] != NULL)
			call_dissector(sub_handles[sub_handle], payload_tvb, pinfo, tree);
		break;
	}
	/* TODO: warn user that the WiMAX plugin must be enabled for some types */
	return tvb_captured_length(tvb);
}

static const true_false_string sacch_l1h_fpc_mode_vals = {
	"In use",
	"Not in use"
};

void
proto_register_gsmtap(void)
{
	static hf_register_info hf[] = {
		{ &hf_gsmtap_version, { "Version", "gsmtap.version",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_hdrlen, { "Header Length", "gsmtap.hdr_len",
		  FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0, NULL, HFILL } },
		{ &hf_gsmtap_type, { "Payload Type", "gsmtap.type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_types), 0, NULL, HFILL } },
		{ &hf_gsmtap_timeslot, { "Time Slot", "gsmtap.ts",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_arfcn, { "ARFCN", "gsmtap.arfcn",
		  FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_MASK, NULL, HFILL } },
		{ &hf_gsmtap_uplink, { "Uplink", "gsmtap.uplink",
		  FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_F_UPLINK, NULL, HFILL } },
		{ &hf_gsmtap_pcs, { "PCS band indicator", "gsmtap.pcs_band",
		  FT_UINT16, BASE_DEC, NULL, GSMTAP_ARFCN_F_PCS, NULL, HFILL } },
		{ &hf_gsmtap_signal_dbm, { "Signal Level (dBm)", "gsmtap.signal_dbm",
		  FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_snr_db, { "Signal/Noise Ratio (dB)", "gsmtap.snr_db",
		  FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_frame_nr, { "GSM Frame Number", "gsmtap.frame_nr",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_burst_type, { "Burst Type", "gsmtap.burst_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_bursts), 0, NULL, HFILL }},
		{ &hf_gsmtap_channel_type, { "Channel Type", "gsmtap.chan_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_channels), 0, NULL, HFILL }},
		{ &hf_gsmtap_tetra_channel_type, { "Channel Type", "gsmtap.tetra_chan_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_tetra_channels), 0, NULL, HFILL }},
		{ &hf_gsmtap_gmr1_channel_type, { "Channel Type", "gsmtap.gmr1_chan_type",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_gmr1_channels), 0, NULL, HFILL }},
		{ &hf_gsmtap_rrc_sub_type, { "Message Type", "gsmtap.rrc_sub_type",
		  FT_UINT8, BASE_DEC, VALS(rrc_sub_types), 0, NULL, HFILL }},
		{ &hf_gsmtap_antenna, { "Antenna Number", "gsmtap.antenna",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_gsmtap_subslot, { "Sub-Slot", "gsmtap.sub_slot",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

		{ &hf_sacch_l1h_power_lev, { "MS power level", "gsmtap.sacch_l1.power_lev",
		  FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
		{ &hf_sacch_l1h_fpc, { "FPC", "gsmtap.sacch_l1.fpc",
		  FT_BOOLEAN, 8, TFS(&sacch_l1h_fpc_mode_vals), 0x20,
		  NULL, HFILL } },
		{ &hf_sacch_l1h_ta, { "Actual Timing Advance", "gsmtap.sacch_l1.ta",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

		/* PTCCH (Packet Timing Advance Control Channel) on Downlink */
		{ &hf_ptcch_spare, { "Spare Bit", "gsmtap.ptcch.spare",
		  FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
		{ &hf_ptcch_ta_idx, { "Timing Advance Index", "gsmtap.ptcch.ta_idx",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_ptcch_ta_val, { "Timing Advance Value", "gsmtap.ptcch.ta_val",
		  FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL } },
		{ &hf_ptcch_padding, { "Spare Padding", "gsmtap.ptcch.padding",
		  FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_gsmtap
	};

	proto_gsmtap = proto_register_protocol("GSM Radiotap", "GSMTAP", "gsmtap");
	proto_register_field_array(proto_gsmtap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	gsmtap_dissector_table = register_dissector_table("gsmtap.type",
						"GSMTAP type", proto_gsmtap, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_gsmtap(void)
{
	dissector_handle_t gsmtap_handle;

	/* TODO: some dissectors may be NULL if not loaded */
	sub_handles[GSMTAP_SUB_DATA] = find_dissector("data");
	sub_handles[GSMTAP_SUB_UM] = find_dissector_add_dependency("gsm_a_ccch", proto_gsmtap);
	sub_handles[GSMTAP_SUB_UM_LAPDM] = find_dissector_add_dependency("lapdm", proto_gsmtap);
	sub_handles[GSMTAP_SUB_UM_RLC_MAC_UL] = find_dissector_add_dependency("gsm_rlcmac_ul", proto_gsmtap);
	sub_handles[GSMTAP_SUB_UM_RLC_MAC_DL] = find_dissector_add_dependency("gsm_rlcmac_dl", proto_gsmtap);
	sub_handles[GSMTAP_SUB_LLC] = find_dissector_add_dependency("llcgprs", proto_gsmtap);
	sub_handles[GSMTAP_SUB_SNDCP] = find_dissector_add_dependency("sndcp", proto_gsmtap);
	sub_handles[GSMTAP_SUB_ABIS] = find_dissector_add_dependency("gsm_a_dtap", proto_gsmtap);
	sub_handles[GSMTAP_SUB_CDMA_CODE] = find_dissector_add_dependency("wimax_cdma_code_burst_handler", proto_gsmtap);
	sub_handles[GSMTAP_SUB_FCH] = find_dissector_add_dependency("wimax_fch_burst_handler", proto_gsmtap);
	sub_handles[GSMTAP_SUB_FFB] = find_dissector_add_dependency("wimax_ffb_burst_handler", proto_gsmtap);
	sub_handles[GSMTAP_SUB_PDU] = find_dissector_add_dependency("wimax_pdu_burst_handler", proto_gsmtap);
	sub_handles[GSMTAP_SUB_HACK] = find_dissector_add_dependency("wimax_hack_burst_handler", proto_gsmtap);
	sub_handles[GSMTAP_SUB_PHY_ATTRIBUTES] = find_dissector_add_dependency("wimax_phy_attributes_burst_handler", proto_gsmtap);
	sub_handles[GSMTAP_SUB_CBCH] = find_dissector_add_dependency("gsm_cbch", proto_gsmtap);
	sub_handles[GSMTAP_SUB_GMR1_BCCH] = find_dissector_add_dependency("gmr1_bcch", proto_gsmtap);
	sub_handles[GSMTAP_SUB_GMR1_CCCH] = find_dissector_add_dependency("gmr1_ccch", proto_gsmtap);
	sub_handles[GSMTAP_SUB_GMR1_LAPSAT] = find_dissector_add_dependency("lapsat", proto_gsmtap);
	sub_handles[GSMTAP_SUB_GMR1_RACH] = find_dissector_add_dependency("gmr1_rach", proto_gsmtap);
	sub_handles[GSMTAP_SUB_UMTS_RRC] = find_dissector_add_dependency("rrc", proto_gsmtap);

	rrc_sub_handles[GSMTAP_RRC_SUB_DL_DCCH_Message] = find_dissector_add_dependency("rrc.dl.dcch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_UL_DCCH_Message] = find_dissector_add_dependency("rrc.ul.dcch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_DL_CCCH_Message] = find_dissector_add_dependency("rrc.dl.ccch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_UL_CCCH_Message] = find_dissector_add_dependency("rrc.ul.ccch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_PCCH_Message] = find_dissector_add_dependency("rrc.pcch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_DL_SHCCH_Message] = find_dissector_add_dependency("rrc.dl.shcch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_UL_SHCCH_Message] = find_dissector_add_dependency("rrc.ul.shcch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_BCCH_FACH_Message] = find_dissector_add_dependency("rrc.bcch.fach", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_BCCH_BCH_Message] = find_dissector_add_dependency("rrc.bcch.bch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_MCCH_Message] = find_dissector_add_dependency("rrc.mcch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_MSCH_Message] = find_dissector_add_dependency("rrc.msch", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_HandoverToUTRANCommand] = find_dissector_add_dependency("rrc.irat.ho_to_utran_cmd", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_InterRATHandoverInfo] = find_dissector_add_dependency("rrc.irat.irat_ho_info", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SystemInformation_BCH] = find_dissector_add_dependency("rrc.sysinfo", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_System_Information_Container] = find_dissector_add_dependency("rrc.sysinfo.cont", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_UE_RadioAccessCapabilityInfo] = find_dissector_add_dependency("rrc.ue_radio_access_cap_info", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_MasterInformationBlock] = find_dissector_add_dependency("rrc.si.mib", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType1] = find_dissector_add_dependency("rrc.si.sib1", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType2] = find_dissector_add_dependency("rrc.si.sib2", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType3] = find_dissector_add_dependency("rrc.si.sib3", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType4] = find_dissector_add_dependency("rrc.si.sib4", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType5] = find_dissector_add_dependency("rrc.si.sib5", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType5bis] = find_dissector_add_dependency("rrc.si.sib5bis", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType6] = find_dissector_add_dependency("rrc.si.sib6", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType7] = find_dissector_add_dependency("rrc.si.sib7", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType8] = find_dissector_add_dependency("rrc.si.sib8", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType9] = find_dissector_add_dependency("rrc.si.sib9", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType10] = find_dissector_add_dependency("rrc.si.sib10", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType11] = find_dissector_add_dependency("rrc.si.sib11", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType11bis] = find_dissector_add_dependency("rrc.si.sib11bis", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType12] = find_dissector_add_dependency("rrc.si.sib12", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType13] = find_dissector_add_dependency("rrc.si.sib13", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType13_1] = find_dissector_add_dependency("rrc.si.sib13-1", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType13_2] = find_dissector_add_dependency("rrc.si.sib13-2", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType13_3] = find_dissector_add_dependency("rrc.si.sib13-3", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType13_4] = find_dissector_add_dependency("rrc.si.sib13-4", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType14] = find_dissector_add_dependency("rrc.si.sib14", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15] = find_dissector_add_dependency("rrc.si.sib15", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15bis] = find_dissector_add_dependency("rrc.si.sib15bis", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_1] = find_dissector_add_dependency("rrc.si.sib15-1", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_1bis] = find_dissector_add_dependency("rrc.si.sib15-1bis", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_2] = find_dissector_add_dependency("rrc.si.sib15-2", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_2bis] = find_dissector_add_dependency("rrc.si.sib15-2bis", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_2ter] = find_dissector_add_dependency("rrc.si.sib15-2ter", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_3] = find_dissector_add_dependency("rrc.si.sib15-3", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_3bis] = find_dissector_add_dependency("rrc.si.sib15-3bis", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_4] = find_dissector_add_dependency("rrc.si.sib15-4", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_5] = find_dissector_add_dependency("rrc.si.sib15-5", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_6] = find_dissector_add_dependency("rrc.si.sib15-6", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_7] = find_dissector_add_dependency("rrc.si.sib15-7", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType15_8] = find_dissector_add_dependency("rrc.si.sib15-8", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType16] = find_dissector_add_dependency("rrc.si.sib16", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType17] = find_dissector_add_dependency("rrc.si.sib17", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType18] = find_dissector_add_dependency("rrc.si.sib18", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType19] = find_dissector_add_dependency("rrc.si.sib19", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType20] = find_dissector_add_dependency("rrc.si.sib20", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType21] = find_dissector_add_dependency("rrc.si.sib21", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoType22] = find_dissector_add_dependency("rrc.si.sib22", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoTypeSB1] = find_dissector_add_dependency("rrc.si.sb1", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_SysInfoTypeSB2] = find_dissector_add_dependency("rrc.si.sb2", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_ToTargetRNC_Container] = find_dissector_add_dependency("rrc.s_to_trnc_cont", proto_gsmtap);
	rrc_sub_handles[GSMTAP_RRC_SUB_TargetRNC_ToSourceRNC_Container] = find_dissector_add_dependency("rrc.t_to_srnc_cont", proto_gsmtap);

	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_DL_CCCH_Message] = find_dissector_add_dependency("lte_rrc.dl_ccch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_DL_DCCH_Message] = find_dissector_add_dependency("lte_rrc.dl_dcch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_UL_CCCH_Message] = find_dissector_add_dependency("lte_rrc.ul_ccch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_UL_DCCH_Message] = find_dissector_add_dependency("lte_rrc.ul_dcch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message] = find_dissector_add_dependency("lte_rrc.bcch_bch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message] = find_dissector_add_dependency("lte_rrc.bcch_dl_sch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_PCCH_Message] = find_dissector_add_dependency("lte_rrc.pcch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_MCCH_Message] = find_dissector_add_dependency("lte_rrc.mcch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_MBMS] = find_dissector_add_dependency("lte_rrc.bcch_bch.mbms", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_BR] = find_dissector_add_dependency("lte_rrc.bcch_dl_sch_br", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_MBMS] = find_dissector_add_dependency("lte_rrc.bcch_dl_sch.mbms", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_SC_MCCH_Message] = find_dissector_add_dependency("lte_rrc.sc_mcch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_Message] = find_dissector_add_dependency("lte_rrc.sbcch_sl_bch", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_Message_V2X] = find_dissector_add_dependency("lte_rrc.sbcch_sl_bch.v2x", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_DL_CCCH_Message_NB] = find_dissector_add_dependency("lte_rrc.dl_ccch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_DL_DCCH_Message_NB] = find_dissector_add_dependency("lte_rrc.dl_dcch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB] = find_dissector_add_dependency("lte_rrc.ul_ccch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB] = find_dissector_add_dependency("lte_rrc.ul_dcch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_NB] = find_dissector_add_dependency("lte_rrc.bcch_bch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_TDD_NB] = find_dissector_add_dependency("lte_rrc.bcch_bch.nb.tdd", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_NB] = find_dissector_add_dependency("lte_rrc.bcch_dl_sch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_PCCH_Message_NB] = find_dissector_add_dependency("lte_rrc.pcch.nb", proto_gsmtap);
	lte_rrc_sub_handles[GSMTAP_LTE_RRC_SUB_SC_MCCH_Message_NB] = find_dissector_add_dependency("lte_rrc.sc_mcch.nb", proto_gsmtap);

	lte_nas_sub_handles[GSMTAP_LTE_NAS_PLAIN] = find_dissector_add_dependency("nas-eps_plain", proto_gsmtap);
	lte_nas_sub_handles[GSMTAP_LTE_NAS_SEC_HEADER] = find_dissector_add_dependency("nas-eps", proto_gsmtap);

	gsmtap_handle = create_dissector_handle(dissect_gsmtap, proto_gsmtap);
	dissector_add_uint_with_preference("udp.port", GSMTAP_UDP_PORT, gsmtap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
