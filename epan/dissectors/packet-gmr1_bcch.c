/* packet-gmr1_bcch.c
 *
 * Routines for GMR-1 BCCH dissection in wireshark.
 * Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
 *
 * References:
 *  [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
 *  [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
 *  [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
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
#include <epan/wmem/wmem.h>

#include "packet-csn1.h"

void proto_register_gmr1_bcch(void);

/* GMR-1 BCCH proto */
static int proto_gmr1_bcch = -1;

/* GMR-1 BCCH sub tree */
static gint ett_gmr1_bcch = -1;


/* ------------------------------------------------------------------------ */
/* CSN1 fields                                                              */
/* ------------------------------------------------------------------------ */

/* Segment 1A fields - [3] 11.5.2.66 */
static int hf_seg1a_class_2_version = -1;
static int hf_seg1a_class_3_version = -1;

static int hf_seg1a_syncinfo_sb_frame_ts_offset = -1;
static int hf_seg1a_syncinfo_sb_symbol_offset = -1;
static int hf_seg1a_syncinfo_sa_freq_offset = -1;

static int hf_seg1a_rachctrl_max_retrans = -1;
static int hf_seg1a_rachctrl_acc[16] = { -1, -1, -1, -1, -1, -1, -1, -1,
                                         -1, -1, -1, -1, -1, -1, -1, -1 };
static int hf_seg1a_rachctrl_cell_bar_access = -1;

static int hf_seg1a_miscinfo_sb_reselection_hysteresis = -1;
static int hf_seg1a_miscinfo_spare = -1;
static int hf_seg1a_miscinfo_priority_access_ind = -1;

static int hf_seg1a_gbch_present = -1;
static int hf_seg1a_test_gs = -1;
static int hf_seg1a_test_gs2 = -1;
static int hf_seg1a_spare1 = -1;
static int hf_seg1a_cell_bar_access_extension2 = -1;
static int hf_seg1a_spare2 = -1;
static int hf_seg1a_cell_bar_access_extension = -1;

/* Segment 2A & 2Abis fields - [3] 11.5.2.67 / 11.5.2.68 */
static int hf_seg2a_class_4_version = -1;

static int hf_seg2a_syncinfo_sa_sirfn_delay = -1;
static int hf_seg2a_syncinfo_sa_bcch_stn = -1;
static int hf_seg2a_syncinfo_superframe_num = -1;
static int hf_seg2a_syncinfo_multiframe_num = -1;
static int hf_seg2a_syncinfo_mffn_high_bit = -1;

static int hf_seg2a_selcrit_rxlev_select_min = -1;

static int hf_seg2a_miscinfo_sb_selection_power = -1;

static int hf_seg2a_lainfo_sa_pch_config = -1;
static int hf_seg2a_lainfo_sa_bach_config = -1;
static int hf_seg2a_lainfo_rach_ts_offset = -1;
static int hf_seg2a_lainfo_n_page_occurrences = -1;
static int hf_seg2a_lainfo_imsi_attach_detach_ind = -1;
static int hf_seg2a_lainfo_ecsc_indication = -1;
static int hf_seg2a_lainfo_si_update_ind = -1;

/* Segment 2B fields */
/* Segment 2Bbis fields */

/* Segment 3A fields - [1] 11.5.2.71 */
static int hf_seg3a_lai_mcc = -1;
static int hf_seg3a_lai_mnc = -1;
static int hf_seg3a_lai_lac = -1;
static int hf_seg3a_lai_msc_id = -1;
static int hf_seg3a_lai_spot_beam_id = -1;

static int hf_seg3a_system_sat_id = -1;
static int hf_seg3a_system_sys_id = -1;

static int hf_seg3a_satpos_latitude = -1;
static int hf_seg3a_satpos_longitude = -1;
static int hf_seg3a_satpos_radius = -1;

static int hf_seg3a_beam_latitude = -1;
static int hf_seg3a_beam_longitude = -1;

static int hf_seg3a_miscinfo_sb_reselection_timer = -1;

static int hf_seg3a_spare = -1;

/* Segment 3B fields */
/* Segment 3Bbis fields */
/* Segment 3C fields */
/* Segment 3D fields */
/* Segment 3E fields */
/* Segment 3Ebis fields */
/* Segment 3F fields */
/* Segment 3G fields */
/* Segment 3Gbis fields */
/* Segment 3H fields */
/* Segment 3I fields */
/* Segment 3J fields */
/* Segment 3Jbis fields */
/* Segment 3Kbis fields */
/* Segment 3L fields */
/* Segment 3M fields */
/* Segment 4A fields */
/* Segment 4B fields */
/* Segment 4C fields */
/* Segment 4D fields */
/* Segment 4E fields */
/* Segment 4F fields */
/* Segment 4G fields */
/* Segment 4H fields */
/* Segment 4I fields */
/* Segment 4J fields */
/* Segment 4K fields */

/* System Information fields [1] 10.1.31 & 10.1.32 */
static int hf_si_protocol_version = -1;
static int hf_si_block_type = -1;
static int hf_si_spare = -1;

static int hf_si1_randomization_period = -1;


/* ------------------------------------------------------------------------ */
/* CSN1 parsing structure                                                   */
/* ------------------------------------------------------------------------ */

/* Segments structures */

	/* Segment 1A - [3] 11.5.2.66 */
typedef struct {
	guint8	SB_FRAME_TS_OFFSET;
	gint8	SB_SYMBOL_OFFSET;
	gint8	SA_FREQ_OFFSET;
} Seg1A_SyncInfo_t;

typedef struct {
	guint8	AC15;
	guint8	AC14;
	guint8	AC13;
	guint8	AC12;
	guint8	AC11;
	guint8	EC10;
	guint8	AC9;
	guint8	AC8;
	guint8	AC7;
	guint8	AC6;
	guint8	AC5;
	guint8	AC4;
	guint8	AC3;
	guint8	AC2;
	guint8	AC1;
	guint8	AC0;
} Seg1A_AccessClasses_t;

typedef struct {
	guint8	Max_Retrans;
	Seg1A_AccessClasses_t AccessClasses;
	guint8	CELL_BAR_ACCESS;
} Seg1A_RACHCtrlParams_t;

typedef struct {
	guint8	SB_RESELECTION_HYSTERESIS;
	guint8	Spare;
	guint8	PriorityAccessInd;
} Seg1A_MiscInfo_t;

typedef struct {
	guint8	Class_2_version;
	guint8	Class_3_version;
	Seg1A_SyncInfo_t SyncInfo;
	Seg1A_RACHCtrlParams_t RACHCtrlParams;
	Seg1A_MiscInfo_t MiscInfo;
	guint8	GBCH_Present;
	guint8	Test_GS;
	guint8	Test_GS2;
	guint8	Spare1;
	guint8	CELL_BAR_ACCESS_EXTENSION2;
	guint8	Spare2;
	guint8	CELL_BAR_ACCESS_EXTENSION;
} Segment1A_t;

	/* Segment 2A & 2Abis - [3] 11.5.2.67 / 11.5.2.68 */
typedef struct {
	guint8	SA_SIRFN_DELAY;
	guint8	SA_BCCH_STN;
	guint16	SuperframeNum;
	guint8	MultiframeNum;
	guint8	MFFN_HighBit;
} Seg2A_SyncInfo_t;

typedef struct {
	guint8	RXLEV_SELECT_MIN;
} Seg2A_SelectionCriterion_t;

typedef struct {
	guint8	SB_SELECTION_POWER;
} Seg2A_MiscInfo_t;

typedef struct {
	guint8	SA_PCH_CONFIG;
	guint8	SA_BACH_CONFIG;
	guint8	RACH_TS_OFFSET;
	guint8	N_Page_Occurrences;
	guint8	IMSI_attach_detach_ind;
	guint8	ECSC_ind;
	guint8	SI_update_ind;
} Seg2A_LAInfo_t;

typedef struct {
	guint8	Class_4_version;
	Seg2A_SyncInfo_t SyncInfo;
	Seg2A_SelectionCriterion_t SelectionCriterion;
	Seg2A_MiscInfo_t MiscInfo;
	Seg2A_LAInfo_t LAInfo;
} Segment2A_t;

typedef struct {
	guint8	Class_4_version;
	Seg2A_SyncInfo_t SyncInfo;
	Seg2A_SelectionCriterion_t SelectionCriterion;
	Seg2A_MiscInfo_t MiscInfo;
	Seg2A_LAInfo_t LAInfo;
} Segment2Abis_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment2B_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment2Bbis_t;

	/* Segment 3A - [1] 11.5.2.71 */
typedef struct {
	guint16 MCC;
	guint16 MNC;
	guint16 LAC;
	guint8 MSC_ID;		/* splitted version of LAC */
	guint16 Spot_Beam_ID;	/* splitted version of LAC */
} Seg3A_LAI_t;

typedef struct {
	guint8 Satellite_ID;
	guint8 System_ID;
} Seg3A_System_t;

typedef struct {
	gint8   Latitude;
	guint16 Longitude;
	gint16  Radius;
} Seg3A_SatellitePosition_t;

typedef struct {
	gint16  Latitude;
	guint16 Longitude;
} Seg3A_BeamPosition_t;

typedef struct {
	guint8 SB_RESELECTION_TIMER;
} Seg3A_MiscInfo_t;

typedef struct {
	Seg3A_LAI_t LAI;
	Seg3A_System_t System;
	Seg3A_SatellitePosition_t SatellitePosition;
	Seg3A_BeamPosition_t BeamPosition;
	Seg3A_MiscInfo_t MiscInfo;
	guint8 Spare;
} Segment3A_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3B_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3Bbis_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3C_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3D_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3E_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3Ebis_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3F_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3G_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3Gbis_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3H_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3I_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3J_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3Jbis_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3Kbis_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3L_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment3M_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4A_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4B_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4C_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4D_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4E_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4F_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4G_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4H_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4I_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4J_t;

typedef struct {
	guint8 _dummy; /* Remove when dissection is written */
} Segment4K_t;

/* System informations structures */

	/* System Information type 1 - [1] 10.1.31 */
typedef struct {
	guint8		Protocol_Version;
	guint8		Block_Type;
	guint8		Randomization_Period;
	guint8		Spare;
} SI1_Block_Header_t;

typedef struct {
	SI1_Block_Header_t	Block_Header;
	Segment1A_t		Segment1A;
	guint8			SegmentType;
	union {
		Segment2Abis_t		Segment2Abis;
		Segment2Bbis_t		Segment2Bbis;
		Segment3A_t		Segment3A;
		Segment3Bbis_t		Segment3Bbis;
		Segment3C_t		Segment3C;
		Segment3D_t		Segment3D;
		Segment3Ebis_t		Segment3Ebis;
		Segment3F_t		Segment3F;
		Segment3Gbis_t		Segment3Gbis;
		Segment3H_t		Segment3H;
		Segment3I_t		Segment3I;
		Segment3Jbis_t		Segment3Jbis;
		Segment3Kbis_t		Segment3Kbis;
		Segment4A_t		Segment4A;
		Segment4B_t		Segment4B;
		Segment4C_t		Segment4C;
		Segment4D_t		Segment4D;
		Segment4E_t		Segment4E;
		Segment4F_t		Segment4F;
		Segment4G_t		Segment4G;
		Segment4H_t		Segment4H;
		Segment4I_t		Segment4I;
		Segment4J_t		Segment4J;
		Segment4K_t		Segment4K;
	} u;
} SystemInformation1_t;

	/* System Information type 2 - [1] 10.1.32 */
typedef struct {
	guint8		Protocol_Version;
	guint8		Block_Type;
	guint8		Spare;
} SI2_Block_Header_t;

typedef struct {
	SI2_Block_Header_t	Block_Header;
	guint8			SegmentType;
	union {
		Segment2A_t		Segment2A;
		Segment2B_t		Segment2B;
		Segment3B_t		Segment3B;
		Segment3E_t		Segment3E;
		Segment3G_t		Segment3G;
		Segment3J_t		Segment3J;
	} u;
} SystemInformation2_t;


/* ------------------------------------------------------------------------ */
/* CSN1 parsing definitions                                                 */
/* ------------------------------------------------------------------------ */

/* Segments */

	/* Segment 1A - [3] 11.5.2.66 */
static const
CSN_DESCR_BEGIN(Seg1A_SyncInfo_t)
  M_UINT       (Seg1A_SyncInfo_t, SB_FRAME_TS_OFFSET, 5, &hf_seg1a_syncinfo_sb_frame_ts_offset),
  M_UINT       (Seg1A_SyncInfo_t, SB_SYMBOL_OFFSET, 6, &hf_seg1a_syncinfo_sb_symbol_offset),
  M_UINT       (Seg1A_SyncInfo_t, SA_FREQ_OFFSET, 8, &hf_seg1a_syncinfo_sa_freq_offset),
CSN_DESCR_END  (Seg1A_SyncInfo_t)

static const
CSN_DESCR_BEGIN(Seg1A_AccessClasses_t)
 M_UINT        (Seg1A_AccessClasses_t, AC15, 1, &hf_seg1a_rachctrl_acc[15]),
 M_UINT        (Seg1A_AccessClasses_t, AC14, 1, &hf_seg1a_rachctrl_acc[14]),
 M_UINT        (Seg1A_AccessClasses_t, AC13, 1, &hf_seg1a_rachctrl_acc[13]),
 M_UINT        (Seg1A_AccessClasses_t, AC12, 1, &hf_seg1a_rachctrl_acc[12]),
 M_UINT        (Seg1A_AccessClasses_t, AC11, 1, &hf_seg1a_rachctrl_acc[11]),
 M_UINT        (Seg1A_AccessClasses_t, EC10, 1, &hf_seg1a_rachctrl_acc[10]),
 M_UINT        (Seg1A_AccessClasses_t, AC9,  1, &hf_seg1a_rachctrl_acc[9]),
 M_UINT        (Seg1A_AccessClasses_t, AC8,  1, &hf_seg1a_rachctrl_acc[8]),
 M_UINT        (Seg1A_AccessClasses_t, AC7,  1, &hf_seg1a_rachctrl_acc[7]),
 M_UINT        (Seg1A_AccessClasses_t, AC6,  1, &hf_seg1a_rachctrl_acc[6]),
 M_UINT        (Seg1A_AccessClasses_t, AC5,  1, &hf_seg1a_rachctrl_acc[5]),
 M_UINT        (Seg1A_AccessClasses_t, AC4,  1, &hf_seg1a_rachctrl_acc[4]),
 M_UINT        (Seg1A_AccessClasses_t, AC3,  1, &hf_seg1a_rachctrl_acc[3]),
 M_UINT        (Seg1A_AccessClasses_t, AC2,  1, &hf_seg1a_rachctrl_acc[2]),
 M_UINT        (Seg1A_AccessClasses_t, AC1,  1, &hf_seg1a_rachctrl_acc[1]),
 M_UINT        (Seg1A_AccessClasses_t, AC0,  1, &hf_seg1a_rachctrl_acc[0]),
CSN_DESCR_END  (Seg1A_AccessClasses_t)

static const
CSN_DESCR_BEGIN(Seg1A_RACHCtrlParams_t)
 M_UINT        (Seg1A_RACHCtrlParams_t, Max_Retrans, 2, &hf_seg1a_rachctrl_max_retrans),
 M_TYPE_LABEL  (Seg1A_RACHCtrlParams_t, AccessClasses, Seg1A_AccessClasses_t, "Access Classes"),
 M_UINT        (Seg1A_RACHCtrlParams_t, CELL_BAR_ACCESS, 1, &hf_seg1a_rachctrl_cell_bar_access),
CSN_DESCR_END  (Seg1A_RACHCtrlParams_t)

static const
CSN_DESCR_BEGIN(Seg1A_MiscInfo_t)
  M_UINT       (Seg1A_MiscInfo_t, SB_RESELECTION_HYSTERESIS, 4, &hf_seg1a_miscinfo_sb_reselection_hysteresis),
  M_UINT       (Seg1A_MiscInfo_t, Spare, 1, &hf_seg1a_miscinfo_spare),
  M_UINT       (Seg1A_MiscInfo_t, PriorityAccessInd, 1, &hf_seg1a_miscinfo_priority_access_ind),
CSN_DESCR_END  (Seg1A_MiscInfo_t)

static const
CSN_DESCR_BEGIN(Segment1A_t)
  M_UINT       (Segment1A_t, Class_2_version, 3, &hf_seg1a_class_2_version),
  M_UINT       (Segment1A_t, Class_3_version, 4, &hf_seg1a_class_3_version),
  M_TYPE_LABEL (Segment1A_t, SyncInfo, Seg1A_SyncInfo_t, "Synchronization Info Class 1"),
  M_TYPE_LABEL (Segment1A_t, RACHCtrlParams, Seg1A_RACHCtrlParams_t, "RACH Control Parameters"),
  M_TYPE_LABEL (Segment1A_t, MiscInfo, Seg1A_MiscInfo_t, "Misc Info Class 1"),
  M_UINT       (Segment1A_t, GBCH_Present, 1, &hf_seg1a_gbch_present),
  M_UINT       (Segment1A_t, Test_GS, 1, &hf_seg1a_test_gs),
  M_UINT       (Segment1A_t, Test_GS2, 1, &hf_seg1a_test_gs2),
  M_UINT       (Segment1A_t, Spare1, 3, &hf_seg1a_spare1),
  M_UINT       (Segment1A_t, CELL_BAR_ACCESS_EXTENSION2, 1, &hf_seg1a_cell_bar_access_extension2),
  M_UINT       (Segment1A_t, Spare2, 5, &hf_seg1a_spare2),
  M_UINT       (Segment1A_t, CELL_BAR_ACCESS_EXTENSION, 1, &hf_seg1a_cell_bar_access_extension),
CSN_DESCR_END  (Segment1A_t)

	/* Segment 2A & 2Abis - [1] 11.5.2.67 / 11.5.2.68 */
static const
CSN_DESCR_BEGIN(Seg2A_SyncInfo_t)
  M_UINT       (Seg2A_SyncInfo_t, SA_SIRFN_DELAY, 4, &hf_seg2a_syncinfo_sa_sirfn_delay),
  M_UINT       (Seg2A_SyncInfo_t, SA_BCCH_STN, 5, &hf_seg2a_syncinfo_sa_bcch_stn),
  M_UINT       (Seg2A_SyncInfo_t, SuperframeNum, 13, &hf_seg2a_syncinfo_superframe_num),
  M_UINT       (Seg2A_SyncInfo_t, MultiframeNum, 2, &hf_seg2a_syncinfo_multiframe_num),
  M_UINT       (Seg2A_SyncInfo_t, MFFN_HighBit, 1, &hf_seg2a_syncinfo_mffn_high_bit),
CSN_DESCR_END  (Seg2A_SyncInfo_t)

static const
CSN_DESCR_BEGIN(Seg2A_SelectionCriterion_t)
  M_UINT       (Seg2A_SelectionCriterion_t, RXLEV_SELECT_MIN, 5, &hf_seg2a_selcrit_rxlev_select_min),
CSN_DESCR_END  (Seg2A_SelectionCriterion_t)

static const
CSN_DESCR_BEGIN(Seg2A_MiscInfo_t)
  M_UINT       (Seg2A_MiscInfo_t, SB_SELECTION_POWER, 4, &hf_seg2a_miscinfo_sb_selection_power),
CSN_DESCR_END  (Seg2A_MiscInfo_t)

static const
CSN_DESCR_BEGIN(Seg2A_LAInfo_t)
  M_UINT       (Seg2A_LAInfo_t, SA_PCH_CONFIG, 2, &hf_seg2a_lainfo_sa_pch_config),
  M_UINT       (Seg2A_LAInfo_t, SA_BACH_CONFIG, 8, &hf_seg2a_lainfo_sa_bach_config),
  M_UINT       (Seg2A_LAInfo_t, RACH_TS_OFFSET, 5, &hf_seg2a_lainfo_rach_ts_offset),
  M_UINT       (Seg2A_LAInfo_t, N_Page_Occurrences, 2, &hf_seg2a_lainfo_n_page_occurrences),
  M_UINT       (Seg2A_LAInfo_t, IMSI_attach_detach_ind, 1, &hf_seg2a_lainfo_imsi_attach_detach_ind),
  M_UINT       (Seg2A_LAInfo_t, ECSC_ind, 1, &hf_seg2a_lainfo_ecsc_indication),
  M_UINT       (Seg2A_LAInfo_t, SI_update_ind, 1, &hf_seg2a_lainfo_si_update_ind),
CSN_DESCR_END  (Seg2A_LAInfo_t)

static const
CSN_DESCR_BEGIN(Segment2A_t)
  M_FIXED_LABEL(Segment2A_t, 2, 0x2, "= Class type: 2"),
  M_FIXED_LABEL(Segment2A_t, 4, 0x0, "= Segment type: A"),
  M_UINT       (Segment2A_t, Class_4_version, 3, &hf_seg2a_class_4_version),
  M_TYPE_LABEL (Segment2A_t, SyncInfo, Seg2A_SyncInfo_t, "Synchronization Info Class 2"),
  M_TYPE_LABEL (Segment2A_t, SelectionCriterion, Seg2A_SelectionCriterion_t, "Selection Criterion"),
  M_TYPE_LABEL (Segment2A_t, MiscInfo, Seg2A_MiscInfo_t, "Misc Info Class 2"),
  M_TYPE_LABEL (Segment2A_t, LAInfo, Seg2A_LAInfo_t, "LA Info Class 2"),
CSN_DESCR_END  (Segment2A_t)

static const
CSN_DESCR_BEGIN(Segment2Abis_t)
  M_FIXED_LABEL(Segment2Abis_t, 2, 0x2, "= Class type: 2"),
  M_FIXED_LABEL(Segment2Abis_t, 4, 0x0, "= Segment type: Abis"),
  M_UINT       (Segment2Abis_t, Class_4_version, 3, &hf_seg2a_class_4_version),
  M_TYPE_LABEL (Segment2Abis_t, SyncInfo, Seg2A_SyncInfo_t, "Synchronization Info Class 2"),
  M_TYPE_LABEL (Segment2Abis_t, SelectionCriterion, Seg2A_SelectionCriterion_t, "Selection Criterion"),
  M_TYPE_LABEL (Segment2Abis_t, MiscInfo, Seg2A_MiscInfo_t, "Misc Info Class 2"),
  M_TYPE_LABEL (Segment2Abis_t, LAInfo, Seg2A_LAInfo_t, "LA Info Class 2"),
CSN_DESCR_END  (Segment2Abis_t)

static const
CSN_DESCR_BEGIN(Segment2B_t)
  M_FIXED_LABEL(Segment2B_t, 2, 0x2, "= Class type: 2"),
  M_FIXED_LABEL(Segment2B_t, 4, 0x1, "= Segment type: B"),
CSN_DESCR_END  (Segment2B_t)

static const
CSN_DESCR_BEGIN(Segment2Bbis_t)
  M_FIXED_LABEL(Segment2Bbis_t, 2, 0x2, "= Class type: 2"),
  M_FIXED_LABEL(Segment2Bbis_t, 4, 0x1, "= Segment type: B bis"),
CSN_DESCR_END  (Segment2Bbis_t)

	/* Segment 3A - [1] 11.5.2.71 */
static gint16
Seg3A_LAI_Dissector(proto_tree *tree _U_, csnStream_t* ar, tvbuff_t *tvb, void* data, int ett_csn1)
{
	Seg3A_LAI_t *LAI = (Seg3A_LAI_t *)data;
	proto_item *lac_item;
	proto_tree *lac_tree;
	guint8 c[5];
	int i;

	if (ar->remaining_bits_len < 5*8)
		return -1;

	for (i=0; i<5; i++)
		c[i] = tvb_get_bits8(tvb, ar->bit_offset + (i<<3), 8);

	LAI->MCC = (c[0] & 0xf) * 100 + ((c[0] & 0xf0) >> 4) * 10 + (c[1] & 0xf);
	LAI->MNC = (c[2] & 0xf) *  10 + ((c[2] & 0xf0) >> 4);

	LAI->LAC = (c[3] << 8) | c[4];
	LAI->MSC_ID = (LAI->LAC >> 10) & 0x3f;
	LAI->Spot_Beam_ID = LAI->LAC & 0x03ff;

	proto_tree_add_uint_bits_format_value(tree, hf_seg3a_lai_mcc, tvb, ar->bit_offset, 16, (guint32)LAI->MCC, "%d", LAI->MCC);
	proto_tree_add_uint_bits_format_value(tree, hf_seg3a_lai_mnc, tvb, ar->bit_offset+16, 8, (guint32)LAI->MNC, "%d", LAI->MNC);

	lac_item = proto_tree_add_uint_bits_format_value(tree, hf_seg3a_lai_lac, tvb, ar->bit_offset+24, 16, (guint32)LAI->LAC, "0x%04x", LAI->LAC);
	lac_tree = proto_item_add_subtree(lac_item, ett_csn1);

	proto_tree_add_uint_bits_format_value(lac_tree, hf_seg3a_lai_msc_id, tvb, ar->bit_offset+24, 6, (guint32)LAI->MSC_ID, "%d", LAI->MSC_ID);
	proto_tree_add_uint_bits_format_value(lac_tree, hf_seg3a_lai_spot_beam_id, tvb, ar->bit_offset+30, 10, (guint32)LAI->Spot_Beam_ID, "%d", LAI->Spot_Beam_ID);

	ar->remaining_bits_len -= 5*8;
	ar->bit_offset += 5*8;

	return 0;
}

static const
CSN_DESCR_BEGIN(Seg3A_System_t)
  M_UINT       (Seg3A_System_t, Satellite_ID, 2, &hf_seg3a_system_sat_id),
  M_UINT       (Seg3A_System_t, System_ID, 4, &hf_seg3a_system_sys_id),
CSN_DESCR_END  (Seg3A_System_t)

static const
CSN_DESCR_BEGIN(Seg3A_SatellitePosition_t)
  M_UINT       (Seg3A_SatellitePosition_t, Latitude, 8, &hf_seg3a_satpos_latitude),
  M_UINT       (Seg3A_SatellitePosition_t, Longitude, 12, &hf_seg3a_satpos_longitude),
  M_UINT       (Seg3A_SatellitePosition_t, Radius, 16, &hf_seg3a_satpos_radius),
CSN_DESCR_END  (Seg3A_SatellitePosition_t)

static const
CSN_DESCR_BEGIN(Seg3A_BeamPosition_t)
  M_UINT       (Seg3A_BeamPosition_t, Latitude, 11, &hf_seg3a_beam_latitude),
  M_UINT       (Seg3A_BeamPosition_t, Longitude, 12, &hf_seg3a_beam_longitude),
CSN_DESCR_END  (Seg3A_BeamPosition_t)

static const
CSN_DESCR_BEGIN(Seg3A_MiscInfo_t)
  M_UINT       (Seg3A_MiscInfo_t, SB_RESELECTION_TIMER, 6, &hf_seg3a_miscinfo_sb_reselection_timer),
CSN_DESCR_END  (Seg3A_MiscInfo_t)

static const
CSN_DESCR_BEGIN(Segment3A_t)
  M_FIXED_LABEL(Segment3A_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3A_t, 4, 0x0, "= Segment type: A"),
  M_SERIALIZE  (Segment3A_t, LAI, 0, Seg3A_LAI_Dissector),
  M_TYPE_LABEL (Segment3A_t, System, Seg3A_System_t, "System"),
  M_TYPE_LABEL (Segment3A_t, SatellitePosition, Seg3A_SatellitePosition_t, "Satellite Position"),
  M_TYPE_LABEL (Segment3A_t, BeamPosition, Seg3A_BeamPosition_t, "Beam Center Position"),
  M_TYPE_LABEL (Segment3A_t, MiscInfo, Seg3A_MiscInfo_t, "Misc Info Class 3"),
  M_UINT       (Segment3A_t, Spare, 4, &hf_seg3a_spare),
CSN_DESCR_END  (Segment3A_t)

static const
CSN_DESCR_BEGIN(Segment3B_t)
  M_FIXED_LABEL(Segment3B_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3B_t, 4, 0x1, "= Segment type: B"),
CSN_DESCR_END  (Segment3B_t)

static const
CSN_DESCR_BEGIN(Segment3Bbis_t)
  M_FIXED_LABEL(Segment3Bbis_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3Bbis_t, 4, 0x1, "= Segment type: B bis"),
CSN_DESCR_END  (Segment3Bbis_t)

static const
CSN_DESCR_BEGIN(Segment3C_t)
  M_FIXED_LABEL(Segment3C_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3C_t, 4, 0x2, "= Segment type: C"),
CSN_DESCR_END  (Segment3C_t)

static const
CSN_DESCR_BEGIN(Segment3D_t)
  M_FIXED_LABEL(Segment3D_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3D_t, 4, 0x3, "= Segment type: D"),
CSN_DESCR_END  (Segment3D_t)

static const
CSN_DESCR_BEGIN(Segment3E_t)
  M_FIXED_LABEL(Segment3E_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3E_t, 4, 0x4, "= Segment type: E"),
CSN_DESCR_END  (Segment3E_t)

static const
CSN_DESCR_BEGIN(Segment3Ebis_t)
  M_FIXED_LABEL(Segment3Ebis_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3Ebis_t, 4, 0x4, "= Segment type: E bis"),
CSN_DESCR_END  (Segment3Ebis_t)

static const
CSN_DESCR_BEGIN(Segment3F_t)
  M_FIXED_LABEL(Segment3F_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3F_t, 4, 0x5, "= Segment type: F"),
CSN_DESCR_END  (Segment3F_t)

static const
CSN_DESCR_BEGIN(Segment3G_t)
  M_FIXED_LABEL(Segment3G_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3G_t, 4, 0x6, "= Segment type: G"),
CSN_DESCR_END  (Segment3G_t)

static const
CSN_DESCR_BEGIN(Segment3Gbis_t)
  M_FIXED_LABEL(Segment3Gbis_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3Gbis_t, 4, 0x6, "= Segment type: G bis"),
CSN_DESCR_END  (Segment3Gbis_t)

static const
CSN_DESCR_BEGIN(Segment3H_t)
  M_FIXED_LABEL(Segment3H_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3H_t, 4, 0x7, "= Segment type: H"),
CSN_DESCR_END  (Segment3H_t)

static const
CSN_DESCR_BEGIN(Segment3I_t)
  M_FIXED_LABEL(Segment3I_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3I_t, 4, 0x9, "= Segment type: I"),
CSN_DESCR_END  (Segment3I_t)

static const
CSN_DESCR_BEGIN(Segment3J_t)
  M_FIXED_LABEL(Segment3J_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3J_t, 4, 0xa, "= Segment type: J"),
CSN_DESCR_END  (Segment3J_t)

static const
CSN_DESCR_BEGIN(Segment3Jbis_t)
  M_FIXED_LABEL(Segment3Jbis_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3Jbis_t, 4, 0xa, "= Segment type: J bis"),
CSN_DESCR_END  (Segment3Jbis_t)

static const
CSN_DESCR_BEGIN(Segment3Kbis_t)
  M_FIXED_LABEL(Segment3Kbis_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3Kbis_t, 4, 0xb, "= Segment type: K bis"),
CSN_DESCR_END  (Segment3Kbis_t)

#if 0
static const
CSN_DESCR_BEGIN(Segment3L_t)
  M_FIXED_LABEL(Segment3L_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3L_t, 4, 0xc, "= Segment type: L"),
CSN_DESCR_END  (Segment3L_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(Segment3M_t)
  M_FIXED_LABEL(Segment3M_t, 1, 0x0, "= Class type: 3"),
  M_FIXED_LABEL(Segment3M_t, 4, 0xd, "= Segment type: M"),
CSN_DESCR_END  (Segment3M_t)
#endif

static const
CSN_DESCR_BEGIN(Segment4A_t)
  M_FIXED_LABEL(Segment4A_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4A_t, 4, 0x0, "= Segment type: A"),
CSN_DESCR_END  (Segment4A_t)

static const
CSN_DESCR_BEGIN(Segment4B_t)
  M_FIXED_LABEL(Segment4B_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4B_t, 4, 0x1, "= Segment type: B"),
CSN_DESCR_END  (Segment4B_t)

static const
CSN_DESCR_BEGIN(Segment4C_t)
  M_FIXED_LABEL(Segment4C_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4C_t, 4, 0x2, "= Segment type: C"),
CSN_DESCR_END  (Segment4C_t)

static const
CSN_DESCR_BEGIN(Segment4D_t)
  M_FIXED_LABEL(Segment4D_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4D_t, 4, 0x3, "= Segment type: D"),
CSN_DESCR_END  (Segment4D_t)

static const
CSN_DESCR_BEGIN(Segment4E_t)
  M_FIXED_LABEL(Segment4E_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4E_t, 4, 0x4, "= Segment type: E"),
CSN_DESCR_END  (Segment4E_t)

static const
CSN_DESCR_BEGIN(Segment4F_t)
  M_FIXED_LABEL(Segment4F_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4F_t, 4, 0x5, "= Segment type: F"),
CSN_DESCR_END  (Segment4F_t)

static const
CSN_DESCR_BEGIN(Segment4G_t)
  M_FIXED_LABEL(Segment4G_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4G_t, 4, 0x6, "= Segment type: G"),
CSN_DESCR_END  (Segment4G_t)

static const
CSN_DESCR_BEGIN(Segment4H_t)
  M_FIXED_LABEL(Segment4H_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4H_t, 4, 0x7, "= Segment type: H"),
CSN_DESCR_END  (Segment4H_t)

static const
CSN_DESCR_BEGIN(Segment4I_t)
  M_FIXED_LABEL(Segment4I_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4I_t, 4, 0x8, "= Segment type: I"),
CSN_DESCR_END  (Segment4I_t)

static const
CSN_DESCR_BEGIN(Segment4J_t)
  M_FIXED_LABEL(Segment4J_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4J_t, 4, 0x9, "= Segment type: J"),
CSN_DESCR_END  (Segment4J_t)

static const
CSN_DESCR_BEGIN(Segment4K_t)
  M_FIXED_LABEL(Segment4K_t, 3, 0x6, "= Class type: 4"),
  M_FIXED_LABEL(Segment4K_t, 4, 0xa, "= Segment type: K"),
CSN_DESCR_END  (Segment4K_t)


/* System information */

	/* System Information type 1 - [1] 10.1.31 */

static const
CSN_DESCR_BEGIN(SI1_Block_Header_t)
  M_UINT       (SI1_Block_Header_t, Protocol_Version, 4, &hf_si_protocol_version),
  M_UINT       (SI1_Block_Header_t, Block_Type, 1, &hf_si_block_type),
  M_UINT       (SI1_Block_Header_t, Randomization_Period, 2, &hf_si1_randomization_period),
  M_UINT       (SI1_Block_Header_t, Spare, 1, &hf_si_spare),
CSN_DESCR_END  (SI1_Block_Header_t)

static const
CSN_ChoiceElement_t SI1_SegmentChoice[] =
{
  {6, 0x20, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment2Abis, Segment2Abis_t, "Segment 2A bis")},
  {6, 0x21, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment2Bbis, Segment2Bbis_t, "Segment 2B bis")},
  {5, 0x00, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3A,    Segment3A_t,    "Segment 3A")},
  {5, 0x01, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3Bbis, Segment3Bbis_t, "Segment 3B bis")},
  {5, 0x02, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3C,    Segment3C_t,    "Segment 3C")},
  {5, 0x03, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3D,    Segment3D_t,    "Segment 3D")},
  {5, 0x04, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3Ebis, Segment3Ebis_t, "Segment 3E bis")},
  {5, 0x05, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3F,    Segment3F_t,    "Segment 3F")},
  {5, 0x06, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3Gbis, Segment3Gbis_t, "Segment 3G bis")},
  {5, 0x07, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3H,    Segment3H_t,    "Segment 3H")},
  {5, 0x09, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3I,    Segment3I_t,    "Segment 3I")},
  {5, 0x0a, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3Jbis, Segment3Jbis_t, "Segment 3J bis")},
  {5, 0x0b, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment3Kbis, Segment3Kbis_t, "Segment 3K bis")},
  {7, 0x60, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4A,    Segment4A_t,    "Segment 4A")},
  {7, 0x61, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4B,    Segment4B_t,    "Segment 4B")},
  {7, 0x62, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4C,    Segment4C_t,    "Segment 4C")},
  {7, 0x63, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4D,    Segment4D_t,    "Segment 4D")},
  {7, 0x64, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4E,    Segment4E_t,    "Segment 4E")},
  {7, 0x65, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4F,    Segment4F_t,    "Segment 4F")},
  {7, 0x66, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4G,    Segment4G_t,    "Segment 4G")},
  {7, 0x67, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4H,    Segment4H_t,    "Segment 4H")},
  {7, 0x68, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4I,    Segment4I_t,    "Segment 4I")},
  {7, 0x69, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4J,    Segment4J_t,    "Segment 4J")},
  {7, 0x6a, 1, M_TYPE_LABEL(SystemInformation1_t, u.Segment4K,    Segment4K_t,    "Segment 4K")},
  {0, 0x00, 1, CSN_ERROR(SystemInformation1_t, "Unknown segment !", -1)},
};

static const
CSN_DESCR_BEGIN(SystemInformation1_t)
  M_TYPE_LABEL (SystemInformation1_t, Block_Header, SI1_Block_Header_t, "Block Header"),
  M_TYPE_LABEL (SystemInformation1_t, Segment1A, Segment1A_t, "Segment 1A"),
  M_CHOICE_IL  (SystemInformation1_t, SegmentType, SI1_SegmentChoice, ElementsOf(SI1_SegmentChoice)),
CSN_DESCR_END  (SystemInformation1_t)

	/* System Information type 2 - [1] 10.1.32 */

CSN_DESCR_BEGIN(SI2_Block_Header_t)
  M_UINT       (SI2_Block_Header_t, Protocol_Version, 4, &hf_si_protocol_version),
  M_UINT       (SI2_Block_Header_t, Block_Type, 1, &hf_si_block_type),
  M_UINT       (SI2_Block_Header_t, Spare, 3, &hf_si_spare),
CSN_DESCR_END  (SI2_Block_Header_t)

static const
CSN_ChoiceElement_t SI2_SegmentChoice[] =
{
  {6, 0x20, 1, M_TYPE_LABEL(SystemInformation2_t, u.Segment2A, Segment2A_t, "Segment 2A")},
  {6, 0x21, 1, M_TYPE_LABEL(SystemInformation2_t, u.Segment2B, Segment2B_t, "Segment 2B")},
  {5, 0x01, 1, M_TYPE_LABEL(SystemInformation2_t, u.Segment3B, Segment3B_t, "Segment 3B")},
  {5, 0x04, 1, M_TYPE_LABEL(SystemInformation2_t, u.Segment3E, Segment3E_t, "Segment 3E")},
  {5, 0x06, 1, M_TYPE_LABEL(SystemInformation2_t, u.Segment3G, Segment3G_t, "Segment 3G")},
  {5, 0x0a, 1, M_TYPE_LABEL(SystemInformation2_t, u.Segment3J, Segment3J_t, "Segment 3J")},
  {0, 0x00, 1, CSN_ERROR(SystemInformation2_t, "Unknown segment !", -1)},
};

static const
CSN_DESCR_BEGIN(SystemInformation2_t)
  M_TYPE_LABEL (SystemInformation2_t, Block_Header, SI2_Block_Header_t, "Block Header"),
  M_CHOICE_IL  (SystemInformation2_t, SegmentType, SI2_SegmentChoice, ElementsOf(SI2_SegmentChoice)),
CSN_DESCR_END  (SystemInformation2_t)


/* ------------------------------------------------------------------------ */
/* Fields values                                                            */
/* ------------------------------------------------------------------------ */

/* Common stuff */
static void
segx_half_db_value_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%2.1f dB (%u)", v * 0.5f, v);
}

/* Segment 1A - [3] 11.5.2.66 */
static void
seg1a_syncinfo_sa_freq_offset_fmt(gchar *s, guint32 v)
{
	gint32 sv = (gint32)v;
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d Hz (%d)", sv * 5, sv);
}

static const value_string seg1a_rachctrl_acc_vals[] = {
	{  0, "not barred (allowed)"},
	{  1, "barred (not allowed)"},
	{  0, NULL }
};

static const value_string seg1a_rachctrl_cell_bar_access_vals[] = {
	{  0, "The cell is not barred"},
	{  1, "The cell is barred"},
	{  0, NULL }
};

/* Segment 2A & 2Abis - [1] 11.5.2.67 & 11.5.2.68 */
static const value_string seg2a_lainfo_imsi_attach_detach_ind_vals[] = {
	{  0, "MESs shall NOT apply IMSI attach and detach procedure for this LA"},
	{  1, "MESs shall apply IMSI attach and detach procedure for this LA"},
	{  0, NULL }
};

static const value_string seg2a_lainfo_ecsc_indication_vals[] = {
	{  0, "Early sending is explicitly prohibited"},
	{  1, "Early sending is explicitly accepted"},
	{  0, NULL }
};

/* Segment 3A - [1] 11.5.2.71 */
static void
seg3a_latitude_fmt(gchar *s, guint32 v)
{
	gint32 sv = (gint32)v;
	char c;

	if (sv < 0) {
		c = 'S';
		sv = -sv;
	} else
		c = 'N';

	g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f %c (%d)", sv / 10.0f, c, sv);
}

static void
seg3a_longitude_fmt(gchar *s, guint32 v)
{
	gint32 sv;
	char c;

	if (v < 1800) {
		c = 'W';
		sv = v;
	} else {
		c = 'E';
		sv = 3600 - v;
	}

	g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f %c (%u)", sv / 10.0f, c, v);
}

static void
seg3a_satpos_radius_fmt(gchar *s, guint32 v)
{
	gint32 sv = (gint32)v;
	gint32 a = (42162 * 1000) + (sv * 5);
	g_snprintf(s, ITEM_LABEL_LENGTH, "%.3lf km (%u)", a / 1000.0, sv);
}

static void
seg3a_miscinfo_sb_reselection_timer_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes (%u)", v*4, v);
}

/* System Information 1 - [1] 10.3.31 */
static const value_string si1_randomization_period_vals[] = {
	{ 0, "7 frames after this SI block" },
	{ 1, "15 frames after this SI block" },
	{ 2, "23 frames after this SI block" },
	{ 3, "31 frames after this SI block" },
	{ 0, NULL }
};


/* ------------------------------------------------------------------------ */
/* Dissector code                                                           */
/* ------------------------------------------------------------------------ */

static void
dissect_gmr1_bcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item  *bcch_item = NULL;
	proto_tree  *bcch_tree = NULL;
	csnStream_t  ar;
	gboolean     is_si1;

	col_append_str(pinfo->cinfo, COL_INFO, "(BCCH) ");

	is_si1 = tvb_get_bits8(tvb, 0, 5) & 1;

	bcch_item =  proto_tree_add_protocol_format(
		tree, proto_gmr1_bcch, tvb, 0, -1,
		"GMR-1 BCCH - System Information type %d", is_si1 ? 1 : 2
	);
	bcch_tree = proto_item_add_subtree(bcch_item, ett_gmr1_bcch);

	csnStreamInit(&ar, 0, tvb_length(tvb)*8);

	/* SI1 or SI2 */
	if (is_si1) {
		SystemInformation1_t *data;
		data = wmem_new(wmem_packet_scope(), SystemInformation1_t);
		/* Initialize the type to the last element, which is an
		 * "Unknown", in case the dissector bails before getting this
		 * far. */
		data->SegmentType = array_length(SI1_SegmentChoice) - 1;
		csnStreamDissector(bcch_tree, &ar, CSNDESCR(SystemInformation1_t), tvb, data, ett_gmr1_bcch);
		col_append_fstr(
			pinfo->cinfo, COL_INFO,
			"System Information 1: Segment 1A, %s",
			SI1_SegmentChoice[data->SegmentType].descr.sz
		);
	} else {
		SystemInformation2_t *data;
		data = wmem_new(wmem_packet_scope(), SystemInformation2_t);
		/* Initialize the type to the last element, which is an
		 * "Unknown", in case the dissector bails before getting this
		 * far. */
		data->SegmentType = array_length(SI2_SegmentChoice) - 1;
		csnStreamDissector(bcch_tree, &ar, CSNDESCR(SystemInformation2_t), tvb, data, ett_gmr1_bcch);
		col_append_fstr(
			pinfo->cinfo, COL_INFO,
			"System Information 2: %s",
			SI2_SegmentChoice[data->SegmentType].descr.sz
		);
	}
}

void
proto_register_gmr1_bcch(void)
{
	static hf_register_info hf[] = {
		/* Segment 1A - [3] 11.5.2.66 */
		{ &hf_seg1a_class_2_version,
		  { "Class 2 version", "gmr1.bcch.seg1a.class_2_version",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Version number for current Class 2 information", HFILL }
		},
		{ &hf_seg1a_class_3_version,
		  { "Class 3 version", "gmr1.bcch.seg1a.class_3_version",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Version number for current Class 3 information", HFILL }
		},
		{ &hf_seg1a_syncinfo_sb_frame_ts_offset,
		  { "SB_FRAME_TS_OFFSET", "gmr1.bcch.seg1a.syncinfo.sb_frame_ts_offset",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_syncinfo_sb_symbol_offset,
		  { "SB_SYMBOL_OFFSET", "gmr1.bcch.seg1a.syncinfo.sb_symbol_offset",
		    FT_INT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_syncinfo_sa_freq_offset,
		  { "SA_FREQ_OFFSET", "gmr1.bcch.seg1a.syncinfo.sa_freq_offset",
		    FT_UINT8, BASE_CUSTOM, seg1a_syncinfo_sa_freq_offset_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_rachctrl_max_retrans,
		  { "Max Retrans", "gmr1.bcch.seg1a.rachctrl.max_retrans",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[15],
		  { "AC15", "gmr1.bcch.seg1a.rachctrl.ac15",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 15 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[14],
		  { "AC14", "gmr1.bcch.seg1a.rachctrl.ac14",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 14 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[13],
		  { "AC13", "gmr1.bcch.seg1a.rachctrl.ac13",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 13 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[12],
		  { "AC12", "gmr1.bcch.seg1a.rachctrl.ac12",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 12 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[11],
		  { "AC11", "gmr1.bcch.seg1a.rachctrl.ac11",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 11 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[10],
		  { "EC10", "gmr1.bcch.seg1a.rachctrl.ac10",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Emergency Class 10 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[9],
		  { "AC9", "gmr1.bcch.seg1a.rachctrl.ac9",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 9 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[8],
		  { "AC8", "gmr1.bcch.seg1a.rachctrl.ac8",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 8 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[7],
		  { "AC7", "gmr1.bcch.seg1a.rachctrl.ac7",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 7 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[6],
		  { "AC6", "gmr1.bcch.seg1a.rachctrl.ac6",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 6 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[5],
		  { "AC5", "gmr1.bcch.seg1a.rachctrl.ac5",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 5 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[4],
		  { "AC4", "gmr1.bcch.seg1a.rachctrl.ac4",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 4 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[3],
		  { "AC3", "gmr1.bcch.seg1a.rachctrl.ac3",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 3 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[2],
		  { "AC2", "gmr1.bcch.seg1a.rachctrl.ac2",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 2 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[1],
		  { "AC1", "gmr1.bcch.seg1a.rachctrl.ac1",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 1 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_acc[0],
		  { "AC0", "gmr1.bcch.seg1a.rachctrl.ac0",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_acc_vals), 0x00,
		    "Access Class 0 barred", HFILL }
		},
		{ &hf_seg1a_rachctrl_cell_bar_access,
		  { "CELL_BAR_ACCESS", "gmr1.bcch.seg1a.rachctrl.cell_bar_access",
		    FT_UINT8, BASE_DEC, VALS(seg1a_rachctrl_cell_bar_access_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_miscinfo_sb_reselection_hysteresis,
		  { "SB_RESELECTION_HYSTERESIS", "gmr1.bcch.seg1a.miscinfo.sb_reselection_hysteresis",
		    FT_UINT8, BASE_CUSTOM, segx_half_db_value_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_miscinfo_spare,
		  { "Spare", "gmr1.bcch.seg1a.miscinfo.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_miscinfo_priority_access_ind,
		  { "Priority Access Ind", "gmr1.bcch.seg1a.miscinfo.priority_access_ind",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Reserved for future use", HFILL }
		},
		{ &hf_seg1a_gbch_present,
		  { "GBCH Present", "gmr1.bcch.seg1a.gbch_present",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_test_gs,
		  { "Test GS", "gmr1.bcch.seg1a.test_gs",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_test_gs2,
		  { "Test GS2", "gmr1.bcch.seg1a.test_gs2",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_spare1,
		  { "Spare", "gmr1.bcch.seg1a.spare1",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_cell_bar_access_extension2,
		  { "CELL_BAR_ACCESS_EXTENSION2", "gmr1.bcch.seg1a.cell_bar_access_extension2",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_spare2,
		  { "Spare", "gmr1.bcch.seg1a.spare2",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg1a_cell_bar_access_extension,
		  { "CELL_BAR_ACCESS_EXTENSION", "gmr1.bcch.seg1a.cell_bar_access_extension",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},

		/* Segment 2A - [1] 11.5.2.67 */
		{ &hf_seg2a_class_4_version,
		  { "Class 4 version", "gmr1.bcch.seg2a.class_4_version",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Version number for current Class 4 information", HFILL }
		},
		{ &hf_seg2a_syncinfo_sa_sirfn_delay,
		  { "SA_SIRFN_DELAY", "gmr1.bcch.seg2a.syncinfo.sa_sirfn_delay",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Delay of system information relative to superframe", HFILL }
		},
		{ &hf_seg2a_syncinfo_sa_bcch_stn,
		  { "SA_BCCH_STN", "gmr1.bcch.seg2a.syncinfo.sa_bcch_stn",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Starting timeslot number", HFILL }
		},
		{ &hf_seg2a_syncinfo_superframe_num,
		  { "Superframe Number", "gmr1.bcch.seg2a.syncinfo.superframe_num",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg2a_syncinfo_multiframe_num,
		  { "Multiframe Number", "gmr1.bcch.seg2a.syncinfo.multiframe_num",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Multiframe number in a superframe", HFILL }
		},
		{ &hf_seg2a_syncinfo_mffn_high_bit,
		  { "MFFN high bit", "gmr1.bcch.seg2a.syncinfo.mffn_high_bit",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "High bit of the TDMA FN in a multiframe", HFILL }
		},
		{ &hf_seg2a_selcrit_rxlev_select_min,
		  { "RXLEV_SELECT_MIN", "gmr1.bcch.seg2a.selcrit.rxlev_select_min",
		    FT_UINT8, BASE_CUSTOM, segx_half_db_value_fmt, 0x00,
		    "Adjustment to threshold to camp-on system", HFILL }
		},
		{ &hf_seg2a_miscinfo_sb_selection_power,
		  { "SB_SELECTION_POWER", "gmr1.bcch.seg2a.miscinfo.sb_selection_power",
		    FT_UINT8, BASE_CUSTOM, segx_half_db_value_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg2a_lainfo_sa_pch_config,
		  { "SA_PCH_CONFIG", "gmr1.bcch.seg2a.lainfo.sa_pch_config",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Paging group configuration information", HFILL }
		},
		{ &hf_seg2a_lainfo_sa_bach_config,
		  { "SA_BACH_CONFIG", "gmr1.bcch.seg2a.lainfo.sa_bach_config",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Alerting group configuration information", HFILL }
		},
		{ &hf_seg2a_lainfo_rach_ts_offset,
		  { "RACH_TS_OFFSET", "gmr1.bcch.seg2a.lainfo.rach_ts_offset",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Start of RACH window with respect to BCCH", HFILL }
		},
		{ &hf_seg2a_lainfo_n_page_occurrences,
		  { "N Page Occurrences", "gmr1.bcch.seg2a.lainfo.n_page_occurrences",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Number of times a page shall be retransmitted after the initial transmission", HFILL }
		},
		{ &hf_seg2a_lainfo_imsi_attach_detach_ind,
		  { "IMSI attach-detach ind", "gmr1.bcch.seg2a.lainfo.imsi_attach_detach_ind",
		    FT_UINT8, BASE_DEC, VALS(seg2a_lainfo_imsi_attach_detach_ind_vals), 0x00,
		    "Should MESs apply IMSI attach and detach procedure for this LA", HFILL }
		},
		{ &hf_seg2a_lainfo_ecsc_indication,
		  { "ECSC indication", "gmr1.bcch.seg2a.lainfo.ecsc_indication",
		    FT_UINT8, BASE_DEC, VALS(seg2a_lainfo_ecsc_indication_vals), 0x00,
		    "Early Classmark Sending Control", HFILL }
		},
		{ &hf_seg2a_lainfo_si_update_ind,
		  { "SI update ind", "gmr1.bcch.seg2a.lainfo.si_update_ind",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Flag for BACH reorganization. Value changes after each reorganization", HFILL }
		},

		/* Segment 3A - [1] 11.5.2.71 */
		{ &hf_seg3a_lai_mcc,
		  { "Mobile Country Code (MCC)", "gmr1.bcch.seg3a.lai.mcc",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_lai_mnc,
		  { "Mobile Network Code (MNC)", "gmr1.bcch.seg3a.lai.mnc",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_lai_lac,
		  { "Location Area Code (LAC)", "gmr1.bcch.seg3a.lai.lac",
		    FT_UINT16, BASE_HEX, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_lai_msc_id,
		  { "MSC ID", "gmr1.bcch.seg3a.lai.msc_id",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_lai_spot_beam_id,
		  { "Spot Beam ID", "gmr1.bcch.seg3a.lai.spot_beam_id",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_system_sat_id,
		  { "Satellite ID", "gmr1.bcch.seg3a.system.sat_id",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_system_sys_id,
		  { "System ID", "gmr1.bcch.seg3a.system.sys_id",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_satpos_latitude,
		  { "Latitude", "gmr1.bcch.seg3a.satpos.latitude",
		    FT_INT8, BASE_CUSTOM, seg3a_latitude_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_satpos_longitude,
		  { "Longitude", "gmr1.bcch.seg3a.satpos.longitude",
		    FT_UINT16, BASE_CUSTOM, seg3a_longitude_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_satpos_radius,
		  { "Radius", "gmr1.bcch.seg3a.satpos.radius",
		    FT_INT16, BASE_CUSTOM, seg3a_satpos_radius_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_beam_latitude,
		  { "Latitude", "gmr1.bcch.seg3a.beam.latitude",
		    FT_INT16, BASE_CUSTOM, seg3a_latitude_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_beam_longitude,
		  { "Longitude", "gmr1.bcch.seg3a.beam.longitude",
		    FT_UINT16, BASE_CUSTOM, seg3a_longitude_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_miscinfo_sb_reselection_timer,
		  { "SB_RESELECTION_TIMER", "gmr1.bcch.seg3a.sb_reselection_timer",
		    FT_UINT8, BASE_CUSTOM, seg3a_miscinfo_sb_reselection_timer_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_seg3a_spare,
		  { "Spare", "gmr1.bcch.seg3a.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},

		/* System Information fields - [1] 10.1.31 & 10.1.32 */
		{ &hf_si_protocol_version,
		  { "Protocol version", "gmr1.bcch.si.protocol_version",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_si_block_type,
		  { "Block Type", "gmr1.bcch.si.block_type",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_si_spare,
		  { "Spare", "gmr1.bcch.si.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_si1_randomization_period,
		  { "Randomization Period", "gmr1.bcch.si.randomization_period",
		    FT_UINT8, BASE_DEC, VALS(si1_randomization_period_vals), 0x00,
		    NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_gmr1_bcch,
	};

	proto_gmr1_bcch = proto_register_protocol("GEO-Mobile Radio (1) BCCH", "GMR-1 BCCH", "gmr1.bcch");

	proto_register_field_array(proto_gmr1_bcch, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gmr1_bcch", dissect_gmr1_bcch, proto_gmr1_bcch);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
