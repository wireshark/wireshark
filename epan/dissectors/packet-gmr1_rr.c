/* packet-gmr1_rr.c
 *
 * Routines for GMR-1 Radio Resource dissection in wireshark.
 * Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
 *
 * References:
 *  [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
 *  [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
 *  [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
 *  [4] ETSI TS 100 940 V7.21.0 - GSM 04.08
 *  [5] ETSI TS 101 376-4-12 V3.2.1 - GMR-1 3G 44.060
 *  [6] ETSI TS 101 376-5-6 V1.3.1 - GMR-1 05.008
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include "packet-gmr1_common.h"


/* GMR-1 CCCH proto */
static int proto_gmr1_ccch = -1;

/* Fallback CCCH sub tree */
static gint ett_msg_ccch = -1;

static gint ett_rr_pd = -1;

/* Handoffs */
static dissector_handle_t data_handle;



/* ------------------------------------------------------------------------ */
/* RR Information Elements                                                  */
/* ------------------------------------------------------------------------ */

enum gmr1_ie_rr_idx {
	GMR1_IE_RR_CHAN_DESC = 0,		/* [1] 11.5.2.5   */
	GMR1_IE_RR_CHAN_MODE,			/* [1] 11.5.2.6   */
	GMR1_IE_RR_CIPH_MODE_SETTING,		/* [4] 10.5.2.9   */
	GMR1_IE_RR_CIPH_RESP,			/* [4] 10.5.2.10  */
	GMR1_IE_RR_L2_PSEUDO_LEN,		/* [1] 11.5.2.19  */
	GMR1_IE_RR_PAGE_MODE,			/* [1] 11.5.2.26  */
	GMR1_IE_RR_REQ_REF,			/* [1] 11.5.2.30  */
	GMR1_IE_RR_CAUSE,			/* [1] 11.5.2.31  */
	GMR1_IE_RR_TIMING_OFS,			/* [1] 11.5.2.40  */
	GMR1_IE_RR_TMSI_PTMSI,			/* [4] 10.5.2.42  */
	GMR1_IE_RR_WAIT_IND,			/* [4] 10.5.2.43  */
	GMR1_IE_RR_MES_INFO_FLG,		/* [1] 11.5.2.44  */
	GMR1_IE_RR_FREQ_OFS,			/* [1] 11.5.2.49  */
	GMR1_IE_RR_PAGE_INFO,			/* [1] 11.5.2.51  */
	GMR1_IE_RR_POS_DISPLAY,			/* [1] 11.5.2.52  */
	GMR1_IE_RR_POS_UPD_INFO,		/* [1] 11.5.2.54  */
	GMR1_IE_RR_BCCH_CARRIER,		/* [1] 11.5.2.55  */
	GMR1_IE_RR_REJECT_CAUSE,		/* [1] 11.5.2.56  */
	GMR1_IE_RR_GPS_TIMESTAMP,		/* [1] 11.5.2.57  */
	GMR1_IE_RR_TMSI_AVAIL_MSK,		/* [1] 11.5.2.62  */
	GMR1_IE_RR_GPS_ALMANAC,			/* [1] 11.5.2.63  */
	GMR1_IE_RR_MSC_ID,			/* [1] 11.5.2.100 */
	GMR1_IE_RR_GPS_DISCR,			/* [1] 11.5.2.101 */
	GMR1_IE_RR_PKT_IMM_ASS_3_PRM,		/* [3] 11.5.2.105 */
	GMR1_IE_RR_PKT_FREQ_PRM,		/* [3] 11.5.2.106 */
	GMR1_IE_RR_PKT_IMM_ASS_2_PRM,		/* [3] 11.5.2.107 */
	GMR1_IE_RR_USF,				/* [3] 11.5.2.110 */
	GMR1_IE_RR_TIMING_ADV_IDX,		/* [3] 10.1.18.3.4 */
	GMR1_IE_RR_TLLI,			/* [5] 12.16      */
	GMR1_IE_RR_PKT_PWR_CTRL_PRM,		/* [3] 10.1.18.3.3 */
	GMR1_IE_RR_PERSISTENCE_LVL,		/* [3] 10.1.18.4.2 */
	NUM_GMR1_IE_RR	/* Terminator */
};

const value_string gmr1_ie_rr_strings[] = {
	{ 0, "Channel Description" },		/* [1] 11.5.2.5   */
	{ 0, "Channel Mode" },			/* [1] 11.5.2.6   */
	{ 0, "Cipher Mode Setting" },		/* [4] 10.5.2.9   */
	{ 0, "Cipher Response" },		/* [4] 10.5.2.10  */
	{ 0, "L2 Pseudo Length" },		/* [1] 11.5.2.19  */
	{ 0, "Page Mode" },			/* [1] 11.5.2.26  */
	{ 0, "Request Reference" },		/* [1] 11.5.2.30  */
	{ 0, "RR Cause" },			/* [1] 11.5.2.31  */
	{ 0, "Timing Offset" },			/* [1] 11.5.2.40  */
	{ 0, "TMSI/P-TMSI" },			/* [4] 10.5.2.42  */
	{ 0, "Wait Indication" },		/* [4] 10.5.2.43  */
	{ 0, "MES Information Flag" },		/* [1] 11.5.2.44  */
	{ 0, "Frequency Offset" },		/* [1] 11.5.2.49  */
	{ 0, "Paging Information" },		/* [1] 11.5.2.51  */
	{ 0, "Position Display" },		/* [1] 11.5.2.52  */
	{ 0, "Position Update Information" },	/* [1] 11.5.2.54  */
	{ 0, "BCCH Carrier Specification"},	/* [1] 11.5.2.55  */
	{ 0, "Reject Cause" },			/* [1] 11.5.2.56  */
	{ 0, "GPS timestamp" },			/* [1] 11.5.2.57  */
	{ 0, "TMSI Availability Mask" },	/* [1] 11.5.2.62  */
	{ 0, "GPS Almanac Data" },		/* [1] 11.5.2.63  */
	{ 0, "MSC ID" },			/* [1] 11.5.2.100 */
	{ 0, "GPS Discriminator" },		/* [1] 11.5.2.101 */
	{ 0, "Packet Imm. Ass. Type 3 Params" },/* [3] 11.5.2.105 */
	{ 0, "Packet Frequency Parameters" },	/* [3] 11.5.2.106 */
	{ 0, "Packet Imm. Ass. Type 2 Params" },/* [3] 11.5.2.107 */
	{ 0, "USF" },				/* [3] 11.5.2.110 */
	{ 0, "Timing Advance Index" },		/* [3] 10.1.18.3.4 */
	{ 0, "TLLI" },				/* [5] 12.16      */
	{ 0, "Packet Power Control Params" },	/* [3] 10.1.18.3.3 */
	{ 0, "Persistence Level" },		/* [3] 10.1.18.4.2 */
	{ 0, NULL },
};

gint ett_gmr1_ie_rr[NUM_GMR1_IE_RR];


/* Fields */
static int hf_rr_msg_type = -1;
static int hf_rr_chan_desc_kab_loc = -1;
static int hf_rr_chan_desc_rx_tn = -1;
static int hf_rr_chan_desc_arfcn = -1;
static int hf_rr_chan_desc_tx_tn = -1;
static int hf_rr_chan_desc_chan_type = -1;
static int hf_rr_chan_mode = -1;
static int hf_rr_ciph_mode_setting_sc = -1;
static int hf_rr_ciph_mode_setting_algo = -1;
static int hf_rr_ciph_resp_cr = -1;
static int hf_rr_ciph_resp_spare = -1;
static int hf_rr_l2_pseudo_len = -1;
static int hf_rr_page_mode = -1;
static int hf_rr_page_mode_spare = -1;
static int hf_rr_req_ref_est_cause = -1;
static int hf_rr_req_ref_ra = -1;
static int hf_rr_req_ref_fn = -1;
static int hf_rr_cause = -1;
static int hf_rr_timing_ofs_ti = -1;
static int hf_rr_timing_ofs_value = -1;
static int hf_rr_tmsi_ptmsi = -1;
static int hf_rr_wait_ind_timeout = -1;
static int hf_rr_mif_mes1_ab = -1;
static int hf_rr_mif_mes1_i = -1;
static int hf_rr_mif_mes1_d = -1;
static int hf_rr_mif_mes2 = -1;
static int hf_rr_mif_mes3 = -1;
static int hf_rr_mif_mes4 = -1;
static int hf_rr_mif_pv = -1;
static int hf_rr_freq_ofs_fi = -1;
static int hf_rr_freq_ofs_value = -1;
static int hf_rr_freq_ofs_spare = -1;
static int hf_rr_page_info_msc_id = -1;
static int hf_rr_page_info_chan_needed = -1;
static int hf_rr_pos_display_flag = -1;
static int hf_rr_pos_display_text = -1;
static int hf_rr_pos_upd_info_v = -1;
static int hf_rr_pos_upd_info_dist = -1;
static int hf_rr_pos_upd_info_time = -1;
static int hf_rr_bcch_carrier_arfcn = -1;
static int hf_rr_bcch_carrier_si = -1;
static int hf_rr_bcch_carrier_ri = -1;
static int hf_rr_bcch_carrier_spare = -1;
static int hf_rr_reject_cause = -1;
static int hf_rr_reject_cause_b = -1;
static int hf_rr_gps_timestamp = -1;
static int hf_rr_tmsi_avail_msk_tmsi[4] = { -1, -1, -1, -1 };
static int hf_rr_gps_almanac_pn = -1;
static int hf_rr_gps_almanac_wn = -1;
static int hf_rr_gps_almanac_word = -1;
static int hf_rr_gps_almanac_sfn = -1;
static int hf_rr_gps_almanac_co = -1;
static int hf_rr_gps_almanac_spare = -1;
static int hf_rr_msc_id = -1;
static int hf_rr_msc_id_spare = -1;
static int hf_rr_gps_discr = -1;
static int hf_rr_pkt_imm_ass_3_prm_rlc_mode = -1;
static int hf_rr_pkt_imm_ass_3_prm_spare = -1;
static int hf_rr_pkt_imm_ass_3_prm_dl_tfi = -1;
static int hf_rr_pkt_imm_ass_3_prm_start_fn = -1;
static int hf_rr_pkt_imm_ass_3_prm_mac_slot_alloc = -1;
static int hf_rr_pkt_freq_prm_arfcn = -1;
static int hf_rr_pkt_freq_prm_dl_freq_plan_id = -1;
static int hf_rr_pkt_freq_prm_dl_bw = -1;
static int hf_rr_pkt_freq_prm_ul_freq_dist = -1;
static int hf_rr_pkt_freq_prm_ul_bw = -1;
static int hf_rr_pkt_freq_prm_spare = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_spare1 = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_final_alloc = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_usf_granularity = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_dl_ctl_mac_slot = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_mac_mode = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_start_fn = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_rlc_dblk_gnt = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_mcs = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_tfi = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_spare2 = -1;
static int hf_rr_pkt_imm_ass_2_prm_ac_mac_slot_alloc = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_chan_mcs_cmd = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_chan_mcs_cmd_pnb512 = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_spare1 = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_rlc_dblk_gnt = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_spare2 = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_tfi = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_usf_granularity = -1;
static int hf_rr_pkt_imm_ass_2_prm_d_mac_slot_alloc = -1;
static int hf_rr_usf_value = -1;
static int hf_rr_usf_spare = -1;
static int hf_rr_timing_adv_idx_value = -1;
static int hf_rr_timing_adv_idx_spare = -1;
static int hf_rr_tlli = -1;
static int hf_rr_pkt_pwr_ctrl_prm_par = -1;
static int hf_rr_pkt_pwr_ctrl_prm_spare = -1;
static int hf_rr_persistence_lvl[4] = { -1, -1, -1, -1 };


/* Generic display vals/func */
static const value_string rr_gen_ie_presence_vals[] = {
	{ 0, "IE is absent" },
	{ 1, "IE is present" },
	{ 0, NULL }
};

static void
rr_gen_ie_seconds_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%u seconds", v);
}



/* [1] 11.5.2.5 - Channel Description */
static const value_string rr_chan_desc_chan_type_vals[] = {
	{  1, "TCH3 No offset" },
	{  3, "TCH3 1/2 symbol offset" },
	{  6, "TCH6 No offset" },
	{  7, "TCH6 1/2 symbol offset" },
	{  4, "TCH9 No offset" },
	{  5, "TCH9 1/2 symbol offset" },
	{ 13, "Reserved for SDCCH frames xx00" },
	{ 14, "Reserved for SDCCH frames xx01" },
	{ 15, "Reserved for SDCCH frames xx10" },
	{ 16, "Reserved for SDCCH frames xx11" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_chan_desc)
{
	gint bit_offset;

	bit_offset = offset << 3;

	/* KAB Location (6 bits)*/
	proto_tree_add_bits_item(tree, hf_rr_chan_desc_kab_loc, tvb,
	                         bit_offset, 6, ENC_BIG_ENDIAN);
	bit_offset += 6;

	/* RX Timeslot (5 bits) */
	proto_tree_add_bits_item(tree, hf_rr_chan_desc_rx_tn, tvb,
	                         bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset += 5;

	/* ARFCN (11 bits) */
	proto_tree_add_bits_item(tree, hf_rr_chan_desc_arfcn, tvb,
	                         bit_offset, 11, ENC_BIG_ENDIAN);
	bit_offset += 11;

	/* TX Timeslot (5 bits) */
	proto_tree_add_bits_item(tree, hf_rr_chan_desc_tx_tn, tvb,
	                         bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset += 5;

	/* Channel Type (5 bits) */
	proto_tree_add_bits_item(tree, hf_rr_chan_desc_chan_type, tvb,
	                         bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset += 5;

	return 4;
}

/* [1] 11.5.2.6 - Channel Mode */
static const value_string rr_chan_mode_vals[] = {
	{ 0x00, "Signalling only" },
	{ 0x01, "Speech" },
	{ 0x03, "Data, 12,0 kbit/s radio I/F rate" },
	{ 0x0b, "Data, 6,0 kbit/s radio I/F rate" },
	{ 0x13, "Data, 3,6 kbit/s radio I/F rate" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_chan_mode)
{
	/* Channel Mode */
	proto_tree_add_item(tree, hf_rr_chan_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [4] 10.5.2.9 - Cipher Mode Setting */
static const value_string rr_ciph_mode_setting_sc_vals[] = {
	{ 0, "No ciphering"},
	{ 1, "Start ciphering"},
	{ 0, NULL }
};

static const value_string rr_ciph_mode_setting_algo_vals[] = {
	{ 0, "A5/1" },
	{ 1, "A5/2" },
	{ 2, "A5/3" },
	{ 3, "A5/4" },
	{ 4, "A5/5" },
	{ 5, "A5/6" },
	{ 6, "A5/7" },
	{ 7, "Reverved" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_ciph_mode_setting)
{
	/* SC */
	proto_tree_add_item(tree, hf_rr_ciph_mode_setting_sc, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Algo */
	proto_tree_add_item(tree, hf_rr_ciph_mode_setting_algo, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [4] 10.5.2.10 - Cipher Response */
static const value_string rr_ciph_resp_cr_vals[] = {
	{ 0, "IMEISV shall not be included"},
	{ 1, "IMEISV shall be included"},
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_ciph_resp)
{
	/* CR */
	proto_tree_add_item(tree, hf_rr_ciph_resp_cr, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(tree, hf_rr_ciph_resp_spare, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.19 - L2 Pseudo Length */
GMR1_IE_FUNC(gmr1_ie_rr_l2_pseudo_len)
{
	/* L2 Pseudo Length value */
	proto_tree_add_item(tree, hf_rr_l2_pseudo_len, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.26 - Page Mode */
static const value_string rr_page_mode_vals[] = {
	{ 0, "Normal Paging" },
	{ 1, "Reserved (Changed from Extended Paging in GSM)" },
	{ 2, "Paging Reorganization" },
	{ 3, "Same as before" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_page_mode)
{
	/* Page mode */
	proto_tree_add_item(tree, hf_rr_page_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(tree, hf_rr_page_mode_spare, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.30 - Request Reference */
static const value_string rr_req_ref_est_cause_vals[] = {
	{ 0, "MO call" },
	{ 1, "In response to paging/alerting" },
	{ 2, "Location update/IMSI detach" },
	{ 3, "Emergency call" },
	{ 4, "Supplementary/short message service" },
	{ 5, "Position verification" },
	{ 6, "Any other valid cause" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_req_ref)
{
	/* Establishement Cause + RA */
	proto_tree_add_item(tree, hf_rr_req_ref_est_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_rr_req_ref_ra, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Frame number % 256 */
	proto_tree_add_item(tree, hf_rr_req_ref_fn, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 2;
}

/* [1] 11.5.2.31 - RR Cause */
static const value_string rr_cause_vals[] = {
	{ 0x00, "Normal event" },
	{ 0x01, "Abnormal release, unspecified" },
	{ 0x02, "Abnormal release, channel unacceptable" },
	{ 0x03, "Abnormal release, timer expired" },
	{ 0x04, "Abnormal release, no activity on the radio path" },
	{ 0x05, "Preemptive release" },
	{ 0x09, "Channel mode unacceptable" },
	{ 0x0a, "Frequency not implemented" },
	{ 0x0b, "Position unacceptable" },
	{ 0x41, "Call already cleared" },
	{ 0x5f, "Semantically incorrect message" },
	{ 0x60, "Invalid mandatory information" },
	{ 0x61, "Message type nonexistent or not implemented" },
	{ 0x62, "Message type not compatible with protocol state" },
	{ 0x6f, "Protocol error unspecified" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_cause)
{
	/* RR Cause */
	proto_tree_add_item(tree, hf_rr_cause, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.40 - Timing Offset */
static const value_string rr_timing_ofs_ti_vals[] = {
	{ 0, "The timing offset parameter in this IE to be ignored" },
	{ 1, "The timing offset parameter has a valid value" },
	{ 0, NULL }
};

static void
rr_timing_ofs_value_fmt(gchar *s, guint32 v)
{
	gint32 sv = (signed)v;

	g_snprintf(s, ITEM_LABEL_LENGTH, "%.3f symbols ( ~ %.3f ms )",
		sv / 40.0f, (sv / 40.0f) * (10.0f / 234.0f));
}

GMR1_IE_FUNC(gmr1_ie_rr_timing_ofs)
{
	gint bit_offset;

	bit_offset = offset << 3;

	/* TI */
	proto_tree_add_bits_item(tree, hf_rr_timing_ofs_ti, tvb,
	                         bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;

	/* Value */
	proto_tree_add_bits_item(tree, hf_rr_timing_ofs_value, tvb,
	                         bit_offset, 15, ENC_BIG_ENDIAN);
	bit_offset += 15;

	return 2;
}

/* [4] 10.5.2.42 - TMSI/P-TMSI */
GMR1_IE_FUNC(gmr1_ie_rr_tmsi_ptmsi)
{
	/* TMSI/P-TMSI value as hex */
	proto_tree_add_item(tree, hf_rr_tmsi_ptmsi, tvb, offset, 4, ENC_BIG_ENDIAN);

	return 4;
}

/* [4] 10.5.2.43 - Wait Indication */
GMR1_IE_FUNC(gmr1_ie_rr_wait_ind)
{
	/* Timeout value */
	proto_tree_add_item(tree, hf_rr_wait_ind_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.44 - MES Information Flag */
static const value_string rr_mif_mes1_ab_vals[] = {
	{ 0, "Chan. Assigned: MES1 registered at selected GS" },
	{ 1, "Chan. Assigned: MES1 requires registration at selected GS" },
	{ 2, "Chan. Assigned; MES 1 Extended Channel Req. Reqd" },
	{ 3, "Pause Timer Indication" },
	{ 0, NULL }
};

static const value_string rr_mif_mes234_vals[] = {
	{ 0, "MES doesn't exists" },
	{ 1, "Pause Timer Ind for this MES" },
	{ 0, NULL }
};

static const value_string rr_mif_pv_vals[] = {
	{ 0, "Position Verification not requested" },
	{ 1, "MES1 shall send a Channel Request for Position Verification following the completion of the upcoming call" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_mes_info_flg)
{
	proto_tree_add_item(tree, hf_rr_mif_mes1_ab,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_rr_mif_mes1_i,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_rr_mif_mes1_d,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_rr_mif_mes2,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_rr_mif_mes3,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_rr_mif_mes4,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_rr_mif_pv,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.49 - Frequency Offset */
static const value_string rr_freq_ofs_fi_vals[] = {
	{ 0, "The frequency offset parameter in this IE to be ignored" },
	{ 1, "The frequency offset parameter has a valid value" },
	{ 0, NULL }
};

static void
rr_freq_ofs_value_fmt(gchar *s, guint32 v)
{
	gint32 sv = (signed)v;

	g_snprintf(s, ITEM_LABEL_LENGTH, "%d Hz", sv);
}

GMR1_IE_FUNC(gmr1_ie_rr_freq_ofs)
{
	gint bit_offset;

	bit_offset = offset << 3;

	/* FI */
	proto_tree_add_bits_item(tree, hf_rr_freq_ofs_fi, tvb,
	                         bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;

	/* Value */
	proto_tree_add_bits_item(tree, hf_rr_freq_ofs_value, tvb,
	                         bit_offset, 12, ENC_BIG_ENDIAN);
	bit_offset += 12;

	/* Spare */
	proto_tree_add_bits_item(tree, hf_rr_freq_ofs_spare, tvb,
	                         bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;

	return 2;
}

/* [1] 11.5.2.51 - Paging Information */
static const value_string rr_page_info_chan_needed_vals[] = {
	{ 0, "Any" },
	{ 1, "SDCCH" },
	{ 2, "TCH3" },
	{ 3, "PDCCH" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_page_info)
{
	/* MSC ID & Channe needed */
	proto_tree_add_item(tree, hf_rr_page_info_msc_id,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_rr_page_info_chan_needed,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.52 - Position Display */
static const value_string rr_pos_display_flag_vals[] = {
	{ 0, "Position not available" },
	{ 1, "No position display service" },
	{ 2, "Use default 7-bit alphabet (GSM 03.38)" },
	{ 0, NULL }
};

extern int
gsm_sms_char_7bit_unpack(
	unsigned int offset, unsigned int in_length, unsigned int out_length,
	const guint8 *input, unsigned char *output);

extern gchar *
gsm_sms_chars_to_utf8(const unsigned char* src, int len);

GMR1_IE_FUNC(gmr1_ie_rr_pos_display)
{
	const unsigned char *txt_raw;
	unsigned char txt_packed[11], txt_unpacked[12];
	int out_len, i;

	/* Flag */
	proto_tree_add_item(tree, hf_rr_pos_display_flag,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Unpack text */
	txt_raw = tvb_get_ptr(tvb, offset, 11);

	for (i=0; i<10; i++)
		txt_packed[i] = (txt_raw[i] << 4) | (txt_raw[i+1] >> 4);
	txt_packed[10] = txt_raw[10];

	out_len = gsm_sms_char_7bit_unpack(0, 11, 12, txt_packed, txt_unpacked);

	/* Display it */
	proto_tree_add_string(tree, hf_rr_pos_display_text,
	                      tvb, offset, 11, gsm_sms_chars_to_utf8(txt_unpacked, out_len));

	return 11;
}

/* [1] 11.5.2.54 - Position Update Information */
static const value_string rr_pos_upd_info_v_vals[] = {
	{ 0, "Information in this IE is Invalid and should be ignored" },
	{ 1, "Information in this IE is Valid" },
	{ 0, NULL }
};

static void
rr_pos_upd_info_dist_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d km", v);
}

static void
rr_pos_upd_info_time_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", v);
}

GMR1_IE_FUNC(gmr1_ie_rr_pos_upd_info)
{
	gint curr_offset = offset;

	/* Valid & GPS Update Distance */
	proto_tree_add_item(tree, hf_rr_pos_upd_info_v,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_rr_pos_upd_info_dist,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	/* GPS Update Timer */
	proto_tree_add_item(tree, hf_rr_pos_upd_info_time,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return 2;
}

/* [1] 11.5.2.55 - BCCH Carrier */
static const value_string rr_bcch_carrier_si_vals[] = {
	{ 0, "BCCH carrier is on the same satellite" },
	{ 1, "BCCH carrier is on a different satellite" },
	{ 0, NULL }
};

static const value_string rr_bcch_carrier_ri_vals[] = {
	{ 0, "Spot beam reselection not needed; use the spot beam with given BCCH" },
	{ 1, "Spot beam reselection needed; use the BCCH for spot beam reselection" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_bcch_carrier)
{
	gint bit_offset;

	bit_offset = offset << 3;

	/* ARFCN */
	proto_tree_add_bits_item(tree, hf_rr_bcch_carrier_arfcn,
	                         tvb, bit_offset, 11, ENC_BIG_ENDIAN);
	bit_offset += 11;

	/* Sat ind */
	proto_tree_add_bits_item(tree, hf_rr_bcch_carrier_si,
	                         tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;

	/* Resel ind */
	proto_tree_add_bits_item(tree, hf_rr_bcch_carrier_ri,
	                         tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;

	/* Spare */
	proto_tree_add_bits_item(tree, hf_rr_bcch_carrier_spare,
	                         tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;

	return 2;
}

/* [1] 11.5.2.56 - Reject Cause */
static const value_string rr_reject_cause_vals[] = {
	{ 0x00, "Lack of resources (default)" },
	{ 0x11, "Invalid position for selected LAI" },
	{ 0x12, "Invalid position for selected spot beam" },
	{ 0x13, "Invalid position" },
	{ 0x15, "Position too old" },
	{ 0x16, "Invalid position for service provider" },
	{ 0x17, "Redirect to new satellite" },
	{ 0x3f, "Reported position acceptable" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_rr_reject_cause)
{
	/* Cause */
	proto_tree_add_item(tree, hf_rr_reject_cause,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* BCCH carrier */
	proto_tree_add_item(tree, hf_rr_reject_cause_b,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.57 - GPS timestamp */
static void
rr_gps_timestamp_fmt(gchar *s, guint32 v)
{
	if (v == 0xffff)
		g_snprintf(s, ITEM_LABEL_LENGTH, "> 65535 minutes or N/A");
	else
		g_snprintf(s, ITEM_LABEL_LENGTH, "%d minutes", v);
}

GMR1_IE_FUNC(gmr1_ie_rr_gps_timestamp)
{
	/* GPS timestamp */
	proto_tree_add_item(tree, hf_rr_gps_timestamp,
	                    tvb, offset, 2, ENC_BIG_ENDIAN);

	return 2;
}

/* [1] 11.5.2.62 - Availability Mask */
GMR1_IE_FUNC(gmr1_ie_rr_tmsi_avail_msk)
{
	int i;

	for (i=0; i<4; i++)
		proto_tree_add_item(tree, hf_rr_tmsi_avail_msk_tmsi[i],
				    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.63 - GPS Almanac Data */
static void
rr_gps_almanac_pn_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d", v+1);
}

static const value_string rr_gps_almanac_sfn_vals[] = {
	{ 0, "Frame 4" },
	{ 1, "Frame 5" },
	{ 0, NULL }
};


GMR1_IE_FUNC(gmr1_ie_rr_gps_almanac)
{
	gint curr_offset = offset;

	/* Page Number & Word Number */
	proto_tree_add_item(tree, hf_rr_gps_almanac_pn,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_rr_gps_almanac_wn,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	/* Almanac Data */
	proto_tree_add_item(tree, hf_rr_gps_almanac_word,
	                    tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	curr_offset += 3;

	/* SubFrame Number & CO & Spare */
	proto_tree_add_item(tree, hf_rr_gps_almanac_sfn,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_rr_gps_almanac_co,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_rr_gps_almanac_spare,
	                    tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return 5;
}

/* [1] 11.5.2.100 - MSC ID */
GMR1_IE_FUNC(gmr1_ie_rr_msc_id)
{
	/* MSC ID */
	proto_tree_add_item(tree, hf_rr_msc_id,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare bits */
	proto_tree_add_item(tree, hf_rr_msc_id_spare,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [1] 11.5.2.101 - GPS Discriminator */
GMR1_IE_FUNC(gmr1_ie_rr_gps_discr)
{
	/* GPS Position CRC value */
	proto_tree_add_item(tree, hf_rr_gps_discr, tvb, offset, 2, ENC_BIG_ENDIAN);

	return 2;
}

/* [3] 11.5.2.105 - Packet Imm. Ass. Type 3 Params */
static const value_string rr_pkt_imm_ass_3_prm_rlc_mode_vals[] = {
	{ 0, "RLC acknowledged mode" },
	{ 1, "RLC unacknowledged mode" },
	{ 0, NULL }
};

static const crumb_spec_t rr_pkt_imm_ass_3_prm_dl_tfi_crumbs[] = {
	{  0, 3 },
	{ 12, 4 },
	{  0, 0 }
};

GMR1_IE_FUNC(gmr1_ie_rr_pkt_imm_ass_3_prm)
{
	/* RLC Mode */
	proto_tree_add_item(tree, hf_rr_pkt_imm_ass_3_prm_rlc_mode,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(tree, hf_rr_pkt_imm_ass_3_prm_spare,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Downlink Tempory Flow Identifier (TFI) */
	proto_tree_add_split_bits_item_ret_val(
		tree, hf_rr_pkt_imm_ass_3_prm_dl_tfi,
		tvb, offset << 3,
		rr_pkt_imm_ass_3_prm_dl_tfi_crumbs,
		NULL);

	/* Starting Frame Number */
	proto_tree_add_item(tree, hf_rr_pkt_imm_ass_3_prm_start_fn,
	                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

	/* MAC Slot allocation */
	proto_tree_add_item(tree, hf_rr_pkt_imm_ass_3_prm_mac_slot_alloc,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	return 3;
}

/* [3] 11.5.2.106 - Packet Frequency Parameters */
static const value_string rr_pkt_freq_prm_dl_freq_plan_id_vals[] = {
	{ 0, "S-Band" },	/* Pretty much a guess ... */
	{ 1, "L-Band" },	/* didn't find exact value in specs */
	{ 0, NULL }
};

static const crumb_spec_t rr_pkt_freq_prm_arfcn_crumbs[] = {
	{  0, 8 },
	{ 13, 3 },
	{  0, 0 }
};

static const crumb_spec_t rr_pkt_freq_prm_ul_freq_dist_crumbs[] = {
	{  0, 1 },
	{ 12, 4 },
	{  0, 0 }
};

static void
rr_pkt_freq_prm_xx_bw_fmt(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d * 31.25 kHz = %.2f kHz (%d)", v, 31.25f*v, v);
}

GMR1_IE_FUNC(gmr1_ie_rr_pkt_freq_prm)
{
	/* ARFCN */
	proto_tree_add_split_bits_item_ret_val(
		tree, hf_rr_pkt_freq_prm_arfcn,
		tvb, offset << 3,
		rr_pkt_freq_prm_arfcn_crumbs,
		NULL);

	/* DL Freq plan ID */
	proto_tree_add_item(tree, hf_rr_pkt_freq_prm_dl_freq_plan_id,
	                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

	/* DL bandwidth */
	proto_tree_add_item(tree, hf_rr_pkt_freq_prm_dl_bw,
	                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

	/* UL Freq distance */
	proto_tree_add_split_bits_item_ret_val(
		tree, hf_rr_pkt_freq_prm_ul_freq_dist,
		tvb, (offset+1) << 3,
		rr_pkt_freq_prm_ul_freq_dist_crumbs,
		NULL);

	/* UL bandwidth */
	proto_tree_add_item(tree, hf_rr_pkt_freq_prm_ul_bw,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(tree, hf_rr_pkt_freq_prm_spare,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	return 3;
}

/* [3] 11.5.2.107 - Packet Imm. Ass. Type 2 Params */
static const value_string rr_pkt_imm_ass_2_prm_ac_mac_mode_vals[] = {
	{ 0, "Dynamic allocation" },
	{ 1, "Reverved" },
	{ 2, "Reverved" },
	{ 3, "Reverved" },
	{ 0, NULL }
};

static const crumb_spec_t rr_pkt_imm_ass_2_prm_ac_rlc_dblk_gnt_crumbs[] = {
	{  0, 4 },
	{ 13, 3 },
	{  0, 0 }
};

GMR1_IE_FUNC(gmr1_ie_rr_pkt_imm_ass_2_prm)
{
	proto_tree *subtree_ac, *subtree_d;
	proto_item *item_ac, *item_d;


	/* Terminal AC */
	/* ----------- */

	item_ac = proto_tree_add_text(tree, tvb, offset, 5, "GMPRS Terminal type A or C");
	subtree_ac = proto_item_add_subtree(item_ac, ett_gmr1_ie_rr[GMR1_IE_RR_PKT_IMM_ASS_2_PRM]);

	/* Spare */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_spare1,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Final Allocation */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_final_alloc,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* USF Granularity */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_usf_granularity,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Downlink Control MAC slot */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_dl_ctl_mac_slot,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* MAC Mode */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_mac_mode,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Starting Frame Number */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_start_fn,
	                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

	/* RLC Data Blocks Granted */
	proto_tree_add_split_bits_item_ret_val(
		tree, hf_rr_pkt_imm_ass_2_prm_ac_rlc_dblk_gnt,
		tvb, (offset+1) << 3,
		rr_pkt_imm_ass_2_prm_ac_rlc_dblk_gnt_crumbs,
		NULL);

	/* MCS */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_mcs,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	/* TFI */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_tfi,
	                    tvb, offset+3, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_spare2,
	                    tvb, offset+3, 1, ENC_BIG_ENDIAN);

	/* MAC Slot allocation */
	proto_tree_add_item(subtree_ac, hf_rr_pkt_imm_ass_2_prm_ac_mac_slot_alloc,
	                    tvb, offset+4, 1, ENC_BIG_ENDIAN);

	/* Terminal D */
	/* ---------- */

	item_d = proto_tree_add_text(tree, tvb, offset, 5, "GMPRS Terminal type D");
	subtree_d = proto_item_add_subtree(item_d, ett_gmr1_ie_rr[GMR1_IE_RR_PKT_IMM_ASS_2_PRM]);

	/* Channel MCS command */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_chan_mcs_cmd,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Channel MCS command PNB(5,12) */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_chan_mcs_cmd_pnb512,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_spare1,
	                    tvb, offset+1, 1, ENC_BIG_ENDIAN);

	/* RLC Data Blocks Granted */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_rlc_dblk_gnt,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_spare2,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	/* TFI */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_tfi,
	                    tvb, offset+3, 1, ENC_BIG_ENDIAN);

	/* USF Granularity */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_usf_granularity,
	                    tvb, offset+3, 1, ENC_BIG_ENDIAN);

	/* MAC Slot allocation */
	proto_tree_add_item(subtree_d, hf_rr_pkt_imm_ass_2_prm_d_mac_slot_alloc,
	                    tvb, offset+4, 1, ENC_BIG_ENDIAN);


	return 5;
}

/* [3] 11.5.2.110 - USF */
GMR1_IE_FUNC(gmr1_ie_rr_usf)
{
	/* Spare */
	proto_tree_add_item(tree, hf_rr_usf_spare,
	                    tvb, offset, 3, ENC_BIG_ENDIAN);

	/* USF */
	proto_tree_add_item(tree, hf_rr_usf_value,
	                    tvb, offset+2, 1, ENC_BIG_ENDIAN);

	return 3;
}

/* [3] 10.1.18.3.4 & [5] 12.29 - Timing Advance Index */
GMR1_IE_FUNC(gmr1_ie_rr_timing_adv_idx)
{
	/* TAI */
	proto_tree_add_item(tree, hf_rr_timing_adv_idx_value,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(tree, hf_rr_timing_adv_idx_spare,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [5] 12.16 - TLLI */
GMR1_IE_FUNC(gmr1_ie_rr_tlli)
{
	/* TLLI value as hex */
	proto_tree_add_item(tree, hf_rr_tlli, tvb, offset, 4, ENC_BIG_ENDIAN);

	return 4;
}

/* [3] 10.1.18.3.3 & [5] 10.4.10a & [6] 5.3.3 - Packet Power Control Params */
static void
rr_pkt_pwr_ctrl_prm_par_fmt(gchar *s, guint32 v)
{
	if (v >= 61) {
		g_snprintf(s, ITEM_LABEL_LENGTH, "Escape %d (%d)", v-60, v);
		return;
	}

	g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f dB (%d)", v*0.4f, v);
}

GMR1_IE_FUNC(gmr1_ie_rr_pkt_pwr_ctrl_prm)
{
	/* Power Attenuation Request (PAR) */
	proto_tree_add_item(tree, hf_rr_pkt_pwr_ctrl_prm_par,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	/* Spare */
	proto_tree_add_item(tree, hf_rr_pkt_pwr_ctrl_prm_spare,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

/* [3] 10.1.18.4.2 & [5] 12.14 - Persistence Level */
GMR1_IE_FUNC(gmr1_ie_rr_persistence_lvl)
{
	int i;

	for (i=0; i<4; i++)
		proto_tree_add_item(tree, hf_rr_persistence_lvl[i],
				    tvb, offset + (i>>1), 1, ENC_BIG_ENDIAN);

	return 2;
}


elem_fcn gmr1_ie_rr_func[NUM_GMR1_IE_RR] = {
	gmr1_ie_rr_chan_desc,		/* Channel Description */
	gmr1_ie_rr_chan_mode,		/* Channel Mode */
	gmr1_ie_rr_ciph_mode_setting,	/* Cipher Mode Setting */
	gmr1_ie_rr_ciph_resp,		/* Cipher Response */
	gmr1_ie_rr_l2_pseudo_len,	/* L2 Pseudo Length */
	gmr1_ie_rr_page_mode,		/* Page Mode */
	gmr1_ie_rr_req_ref,		/* Request Reference */
	gmr1_ie_rr_cause,		/* RR Cause */
	gmr1_ie_rr_timing_ofs,		/* Timing Offset */
	gmr1_ie_rr_tmsi_ptmsi,		/* TMSI/P-TMSI */
	gmr1_ie_rr_wait_ind,		/* Wait Indication */
	gmr1_ie_rr_mes_info_flg,	/* MES Information Flag */
	gmr1_ie_rr_freq_ofs,		/* Frequency Offset */
	gmr1_ie_rr_page_info,		/* Paging Information */
	gmr1_ie_rr_pos_display,		/* Position Display */
	gmr1_ie_rr_pos_upd_info,	/* Position Update Information */
	gmr1_ie_rr_bcch_carrier,	/* BCCH Carrier */
	gmr1_ie_rr_reject_cause,	/* Reject Cause */
	gmr1_ie_rr_gps_timestamp,	/* GPS timestamp */
	gmr1_ie_rr_tmsi_avail_msk,	/* TMSI Availability Mask */
	gmr1_ie_rr_gps_almanac,		/* GPS Almanac Data */
	gmr1_ie_rr_msc_id,		/* MSC ID */
	gmr1_ie_rr_gps_discr,		/* GPS Discriminator */
	gmr1_ie_rr_pkt_imm_ass_3_prm,	/* Packet Imm. Ass. Type 3 Params */
	gmr1_ie_rr_pkt_freq_prm,	/* Packet Frequency Parameters */
	gmr1_ie_rr_pkt_imm_ass_2_prm,	/* Packet Imm. Ass. Type 2 Params */
	gmr1_ie_rr_usf,			/* USF */
	gmr1_ie_rr_timing_adv_idx,	/* Timing Advance Index */
	gmr1_ie_rr_tlli,		/* TLLI */
	gmr1_ie_rr_pkt_pwr_ctrl_prm,	/* Packet Power Control Params */
	gmr1_ie_rr_persistence_lvl,	/* Persistence Level */
};


/* ------------------------------------------------------------------------ */
/* RR Messages                                                              */
/* ------------------------------------------------------------------------ */

/* [1] 10.1.18 - Immediate Assignment */
GMR1_MSG_FUNC(gmr1_rr_msg_imm_ass)
{
	guint8 mif;

	GMR1_MSG_FUNC_BEGIN

	/* MES Information Flag			[1] 11.5.2.44	- M V 1 */
	mif = tvb_get_guint8(tvb, curr_offset);

	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_MES_INFO_FLG, NULL);

	/* Request Reference 1 (MES1)		[1] 11.5.2.30	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES1");

	/* GPS Discriminator			[1] 11.5.2.101	- C V 2 */
	if ((mif & 0x03) != 0x02) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_DISCR, " - MES1");
	}

	/* Channel Description			[1] 11.5.2.5	- C V 4 */
	if ((mif & 0x03) != 0x03) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_CHAN_DESC, " - MES1");
	}

	/* Timing Offset			[1] 11.5.2.40	- C V 2 */
	if ((mif & 0x03) != 0x03) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TIMING_OFS, " - MES1");
	}

	/* Frequency Offset			[1] 11.5.2.49	- C V 2 */
	if ((mif & 0x03) != 0x03) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_FREQ_OFS, " - MES1");
	}

	/* Idle Mode Pos. Upd. Info.		[1] 11.5.2.54	- C V 2 */
	if (mif & 0x04) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_POS_UPD_INFO, " - Idle Mode");
	}

	/* Ded. Mode Pos. Upd. Info.		[1] 11.5.2.54	- C V 2 */
	if (mif & 0x08) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_POS_UPD_INFO, " - Dedicated Mode");
	}

	/* Request Reference 2 (MES2)		[1] 11.5.2.30	- C V 2 */
	if (mif & 0x10) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES2");
	}

	/* Request Reference 3 (MES3)		[1] 11.5.2.30	- C V 2 */
	if (mif & 0x20) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES3");
	}

	/* Request Reference 4 (MES4)		[1] 11.5.2.30	- C V 2 */
	if (mif & 0x40) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES4");
	}

	/* IA Rest Octets			[1] 11.5.2.16	- M V 0..18 */
		/* FIXME */

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.20.1 - Immediate Assignment Reject Type 1 */
GMR1_MSG_FUNC(gmr1_rr_msg_imm_ass_rej_1)
{
	guint8 rej_cause;

	GMR1_MSG_FUNC_BEGIN

	/* Request Reference 1 (MES1) 		[1] 11.5.2.30	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES1");

	/* GPS Discriminator			[1] 11.5.2.101	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_DISCR, NULL);

	/* Reject Cause				[1] 11.5.2.56	- M V 1 */
	rej_cause = tvb_get_guint8(tvb, curr_offset);

	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REJECT_CAUSE, NULL);

	/* Wait Indication 1 (MES1)		[4] 10.5.2.43	- C V 1 */
	if ((rej_cause & 0xfc) == 0x00) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_WAIT_IND, " - MES1");
	}

	/* Request Reference 2 (MES2) 		[1] 11.5.2.30	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES2");

	/* Wait Indication 2 (MES2)		[4] 10.5.2.43	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_WAIT_IND, " - MES2");

	/* Request Reference 3 (MES3)		[1] 11.5.2.30	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES3");

	/* Wait Indication 3 (MES3)		[4] 10.5.2.43	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_WAIT_IND, " - MES3");

	/* Request Reference 4 (MES4)		[1] 11.5.2.30	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, " - MES4");

	/* Wait Indication 4 (MES4)		[4] 10.5.2.43	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_WAIT_IND, " - MES4");

	/* Idle Mode Position Update Info.	[1] 11.5.2.54	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_POS_UPD_INFO, " - Idle Mode");

	/* BCCH Carrier Specification		[1] 11.5.2.55	- C V 2 */
	if (rej_cause & 1) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_BCCH_CARRIER, NULL);
	}

	/* MSC ID				[1] 11.5.2.100	- C V 1 */
	if ((rej_cause & 0xfc) == 0x5c) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_MSC_ID, NULL);
	}

	/* IAR Rest Octets			[1] 11.5.2.17	- M V 1..4 */
		/* FIXME */

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.20.4 - Position Verification Notify */
GMR1_MSG_FUNC(gmr1_rr_msg_pos_verif_notify)
{
	GMR1_MSG_FUNC_BEGIN

	/* Request Reference 			[1] 11.5.2.30	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_REQ_REF, NULL);

	/* GPS Discriminator			[1] 11.5.2.101	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_DISCR, NULL);

	/* Position Display 			[1] 11.5.2.52	- M V 11 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_POS_DISPLAY, NULL);

	/* 78 Idle Mode Position Update Info.	[1] 11.5.2.54	- O TV 3 */
	ELEM_OPT_TV(0x78, GMR1_IE_RR, GMR1_IE_RR_POS_UPD_INFO, NULL);

	/* IAR Rest Octets			[1] 11.5.2.17	- M V 3..6 */
		/* FIXME */

	GMR1_MSG_FUNC_END
}

/* [3] 10.1.18.3 - Immediate Assignment Type 2 */
GMR1_MSG_FUNC(gmr1_rr_msg_imm_ass_2)
{
	GMR1_MSG_FUNC_BEGIN

	/* USF					[3] 11.5.2.110	- M V 3 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_USF, NULL);

	/* Timing Advance Index			[3] 10.1.18.3.4	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TIMING_ADV_IDX, NULL);

	/* TLLI					[5] 12.16	- M V 4 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TLLI, NULL);

	/* Timing Offset			[1] 11.5.2.40	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TIMING_OFS, NULL);

	/* Frequency Offset			[1] 11.5.2.49	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_FREQ_OFS, NULL);

	/* Packet Imm. Ass. Type 2 Params.	[3] 11.5.2.107	- M V 5 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PKT_IMM_ASS_2_PRM, NULL);

	/* Packet Frequency Parameters		[3] 11.5.2.106	- M V 3 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PKT_FREQ_PRM, NULL);

	/* Packet Power Control Parameters	[3] 10.1.18.3.3	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PKT_PWR_CTRL_PRM, NULL);

	GMR1_MSG_FUNC_END
}

/* [3] 10.1.18.4 - Immediate Assignment Type 3 */
GMR1_MSG_FUNC(gmr1_rr_msg_imm_ass_3)
{
	GMR1_MSG_FUNC_BEGIN

	/* Page Mode				[1] 11.5.2.26	- M V 1/2 */
	/* Spare Half Octet			[1] 11.5.1.8	- M V 1/2 */
	ELEM_MAND_VV_SHORT(GMR1_IE_RR, GMR1_IE_RR_PAGE_MODE,
	                   GMR1_IE_COMMON, GMR1_IE_COM_SPARE_NIBBLE);

	/* Persistence Level			[3] 10.1.18.4.2	- M V 2 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PERSISTENCE_LVL, NULL);

	/* Timing Advance Index			[3] 10.1.18.3.4	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TIMING_ADV_IDX, NULL);

	/* TLLI					[5] 12.16	- M V 4 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TLLI, NULL);

	/* Packet Imm. Ass. Type 3 Params	[3] 11.5.2.105	- M V 3 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PKT_IMM_ASS_3_PRM, NULL);

	/* Packet Frequency Parameters		[3] 11.5.2.106	- M V 3 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PKT_FREQ_PRM, NULL);

	/* Packet Power Control Parameters	[3] 10.1.18.3.3	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PKT_PWR_CTRL_PRM, NULL);

	/* P1 Rest Octets			[1] 11.5.2.23	- M V 6 */
		/* FIXME */

	GMR1_MSG_FUNC_END
}

/* [3] 10.1.9 - Ciphering Mode Command */
GMR1_MSG_FUNC(gmr1_rr_msg_ciph_mode_cmd)
{
	GMR1_MSG_FUNC_BEGIN

	/* Cipher Mode Setting			[4] 10.5.2.9	- M V 1/2 */
	/* Cipher Response			[4] 10.5.2.10	- M V 1/2 */
	ELEM_MAND_VV_SHORT(GMR1_IE_RR, GMR1_IE_RR_CIPH_MODE_SETTING,
	                   GMR1_IE_RR, GMR1_IE_RR_CIPH_RESP);

	/* 75  Position Display			[1] 11.5.2.52	- O TV 12 */
	ELEM_OPT_TV(0x75, GMR1_IE_RR, GMR1_IE_RR_POS_DISPLAY, NULL);

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.10 - Ciphering Mode Complete */
GMR1_MSG_FUNC(gmr1_rr_msg_ciph_mode_complete)
{
	GMR1_MSG_FUNC_BEGIN

	/* 17  Mobile Identity			[1] 11.5.1.4	- O TLV 3-11 */
	ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

	/* 76  GPS Timestamp			[1] 11.5.2.57	- O TV 3 */
	ELEM_OPT_TV(0x76, GMR1_IE_RR, GMR1_IE_RR_GPS_TIMESTAMP, NULL);

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.7 - Channel Release */
GMR1_MSG_FUNC(gmr1_rr_msg_chan_release)
{
	GMR1_MSG_FUNC_BEGIN

	/* RR Cause				[1] 11.5.2.31	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_CAUSE, NULL);

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.24 - Paging Request Type 3 */
GMR1_MSG_FUNC(gmr1_rr_msg_pag_req_3)
{
	guint8 tam;

	GMR1_MSG_FUNC_BEGIN

	/* Page Mode				[1] 11.5.2.26	- M V 1/2 */
	/* TMSI Availability Mask		[1] 11.5.2.62	- M V 1/2 */
	tam = (tvb_get_guint8(tvb, curr_offset) & 0xf0) >> 4;

	ELEM_MAND_VV_SHORT(GMR1_IE_RR, GMR1_IE_RR_PAGE_MODE,
	                   GMR1_IE_RR, GMR1_IE_RR_TMSI_AVAIL_MSK);

	/* Mobile Identity 1 (TMSI)		[4] 10.5.2.42	- C V 4 */
	if (tam & 0x01) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TMSI_PTMSI, " - 1");
	}

	/* GPS Almanac Data 1			[1] 11.5.2.63	- C V 5 */
	if (!(tam & 0x01)) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_ALMANAC, " - 1");
	}

	/* Mobile Identity 2 (TMSI)		[4] 10.5.2.42	- C V 4 */
	if (tam & 0x02) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TMSI_PTMSI, " - 2");
	}

	/* GPS Almanac Data 2			[1] 11.5.2.63	- C V 5 */
	if (!(tam & 0x02)) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_ALMANAC, " - 2");
	}

	/* Mobile Identity 3 (TMSI)		[4] 10.5.2.42	- C V 4 */
	if (tam & 0x04) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TMSI_PTMSI, " - 3");
	}

	/* GPS Almanac Data 3			[1] 11.5.2.63	- C V 5 */
	if (!(tam & 0x04)) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_ALMANAC, " - 3");
	}

	/* Mobile Identity 4 (TMSI)		[4] 10.5.2.42	- C V 4 */
	if (tam & 0x08) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_TMSI_PTMSI, " - 4");
	}

	/* GPS Almanac Data 4			[1] 11.5.2.63	- C V 5 */
	if (!(tam & 0x08)) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_GPS_ALMANAC, " - 4");
	}

	/* Paging Information 1			[1] 11.5.2.51	- C V 1 */
	if (tam & 0x01) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PAGE_INFO, " - 1");
	}

	/* Paging Information 2			[1] 11.5.2.51	- C V 1 */
	if (tam & 0x02) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PAGE_INFO, " - 2");
	}

	/* Paging Information 3			[1] 11.5.2.51	- C V 1 */
	if (tam & 0x04) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PAGE_INFO, " - 3");
	}

	/* Paging Information 4			[1] 11.5.2.51	- C V 1 */
	if (tam & 0x08) {
		ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_PAGE_INFO, " - 4");
	}

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.25 - Paging Response */
GMR1_MSG_FUNC(gmr1_rr_msg_pag_resp)
{
	GMR1_MSG_FUNC_BEGIN

	/* Ciphering Key Sequence Number	[4] 10.5.1.2	- M V 1/2 */
	/* Spare Half Octet			[1] 11.5.1.8	- M V 1/2 */
	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM,
	                   GMR1_IE_COMMON, GMR1_IE_COM_SPARE_NIBBLE);

	/* Mobile Earth Station Classmark 2	[1] 11.5.1.6	- M L V 4 */
	ELEM_MAND_LV(GMR1_IE_COMMON, GMR1_IE_COM_CM2, NULL);

	/* Mobile Identity			[4] 10.5.1.4	- M L V 2-9 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.5 - Channel Mode Modify */
GMR1_MSG_FUNC(gmr1_rr_msg_chan_mode_modify)
{
	GMR1_MSG_FUNC_BEGIN

	/* Channel Description			[1] 11.5.2.5	- M V 4 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_CHAN_DESC, NULL);

	/* Channel Mode				[1] 11.5.2.6	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_CHAN_MODE, NULL);

	GMR1_MSG_FUNC_END
}

/* [1] 10.1.6 - Channel Mode Modify Acknowledge */
GMR1_MSG_FUNC(gmr1_rr_msg_chan_mode_mod_ack)
{
	GMR1_MSG_FUNC_BEGIN

	/* Channel Description			[1] 11.5.2.5	- M V 4 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_CHAN_DESC, NULL);

	/* Channel Mode				[1] 11.5.2.6	- M V 1 */
	ELEM_MAND_V(GMR1_IE_RR, GMR1_IE_RR_CHAN_MODE, NULL);

	GMR1_MSG_FUNC_END
}


/* See [3] 11.4.1 - Table 11.1 */
static const value_string gmr1_msg_rr_strings[] = {
	/* Channel establishment messages */
	{ 0x3f, "Immediate Assignment" },
	{ 0x3a, "Immediate Assignment Reject Type 1" },
	{ 0x3b, "Immediate Assignment Reject Type 2" },
	{ 0x13e, "Extended Immediate Assignment" },	/* Conflict ... add 0x100 */
	{ 0x13b, "Extended Imm. Assignment Reject" },	/* Conflict ... add 0x100 */
	{ 0x39, "Position Verification Notify" },
	{ 0x3c, "Immediate Assignment Reject Type 3" },
	{ 0x3e, "Immediate Assignment Type 2" },
	{ 0x3d, "Immediate Assignment Type 3" },

	/* Ciphering messages */
	{ 0x35, "Ciphering Mode Command" },
	{ 0x32, "Ciphering Mode Complete" },

	/* Channel assignment/handover messages */
	{ 0x2e, "Assignment Command 1" },
	{ 0x2a, "Assignment Command 2" },
	{ 0x29, "Assignment Complete" },
	{ 0x2f, "Assignment Failure" },
	{ 0x2b, "Handover Command" },
	{ 0x2c, "Handover Complete" },

	/* Channel release messages */
	{ 0x0d, "Channel Release" },
	{ 0x0e, "TtT Signalling Link Failure" },

	/* Paging messages */
	{ 0x21, "Paging Request Type 1" },
	{ 0x22, "Paging Request Type 2" },
	{ 0x24, "Paging Request Type 3" },
	{ 0x27, "Paging Response" },

	/* Miscellaneous messages */
	{ 0x10, "Channel Mode Modify" },
	{ 0x12, "RR Status" },
	{ 0x17, "Channel Mode Modify Acknowledge" },
	{ 0x16, "Classmark Change" },
	{ 0x13, "Classmark Enquiry" },
	{ 0x14, "Position Update Request" },
	{ 0x15, "Position Update Accept" },
	{ 0x11, "Link Correction Message" },

	{ 0x01, "Power Control Parameters Update" },
	{ 0x02, "Guard Time Violation" },
	{ 0x04, "Extended Channel Request" },

	/* Status and Diagnostic Messages */
	{ 0x40, "Information Request" },
	{ 0x41, "Information Response Position" },
	{ 0x42, "Information Response Version" },
	{ 0x43, "Information Response Spot Beam Selection" },
	{ 0x44, "Information Response Power Control" },
	{ 0x45, "Information Response Vendor Specific" },
	{ 0x46, "Information Response Current Beam" },
	{ 0x4f, "Information Response Error" },

	/* End */
	{ 0, NULL }
};


#define NUM_GMR1_MSG_RR (sizeof(gmr1_msg_rr_strings) / sizeof(value_string))
static gint ett_msg_rr[NUM_GMR1_MSG_RR];

	/* same order as gmr1_msg_rr_strings */
static const gmr1_msg_func_t gmr1_msg_rr_func[NUM_GMR1_MSG_RR] = {
	/* Channel establishment messages */
	gmr1_rr_msg_imm_ass,		/* Imm. Ass.*/
	gmr1_rr_msg_imm_ass_rej_1,	/* Imm. Ass. Reject Type 1 */
	NULL,				/* Imm. Ass. Reject Type 2 */
	NULL,				/* Extended Imm. Ass. */
	NULL,				/* Extended Imm. Ass. Reject */
	gmr1_rr_msg_pos_verif_notify,	/* Position Verification Notify */
	NULL,				/* Imm. Ass. Reject Type 3 */
	gmr1_rr_msg_imm_ass_2,		/* Imm. Ass. Type 2 */
	gmr1_rr_msg_imm_ass_3,		/* Imm. Ass. Type 3 */

	/* Ciphering messages */
	gmr1_rr_msg_ciph_mode_cmd,	/* Ciphering Mode Command */
	gmr1_rr_msg_ciph_mode_complete,	/* Ciphering Mode Complete */

	/* Channel assignment/handover messages */
	NULL,				/* Assignment Command 1 */
	NULL,				/* Assignment Command 2 */
	NULL,				/* Assignment Complete */
	NULL,				/* Assignment Failure */
	NULL,				/* Handover Command */
	NULL,				/* Handover Complete */

	/* Channel release messages */
	gmr1_rr_msg_chan_release,	/* Channel Release */
	NULL,				/* TtT Signalling Link Failure */

	/* Paging messages */
	NULL,				/* Paging Request Type 1 */
	NULL,				/* Paging Request Type 2 */
	gmr1_rr_msg_pag_req_3,		/* Paging Request Type 3 */
	gmr1_rr_msg_pag_resp,		/* Paging Response */

	/* Miscellaneous messages */
	gmr1_rr_msg_chan_mode_modify,	/* Channel Mode Modify */
	NULL,				/* RR Status */
	gmr1_rr_msg_chan_mode_mod_ack,	/* Channel Mode Modify Acknowledge */
	NULL,				/* Classmark Change */
	NULL,				/* Classmark Enquiry */
	NULL,				/* Position Update Request */
	NULL,				/* Position Update Accept */
	NULL,				/* Link Correction Message */

	NULL,				/* Power Control Parameters Update */
	NULL,				/* Guard Time Violation */
	NULL,				/* Extended Channel Request */

	/* Status and Diagnostic Messages */
	NULL,				/* Info. Req. */
	NULL,				/* Info. Resp. Position */
	NULL,				/* Info. Resp. Version */
	NULL,				/* Info. Resp. Spot Beam Selection */
	NULL,				/* Info. Resp. Power Control */
	NULL,				/* Info. Resp. Vendor Specific */
	NULL,				/* Info. Resp. Current Beam */
	NULL,				/* Info. Resp. Error */

	NULL,
};


void
gmr1_get_msg_rr_params(guint8 oct, int dcch, const gchar **msg_str,
                       int *ett_tree, int *hf_idx, gmr1_msg_func_t *msg_func_p)
{
	const gchar *m = NULL;
	gint idx;

	if (dcch)
		m = match_strval_idx((guint32)oct | 0x100, gmr1_msg_rr_strings, &idx);

	if (!m)
		m = match_strval_idx((guint32)oct, gmr1_msg_rr_strings, &idx);

	*msg_str = m;
	*hf_idx = hf_rr_msg_type;
	if (m != NULL) {
		*ett_tree  = ett_msg_rr[idx];
		*msg_func_p = gmr1_msg_rr_func[idx];
	} else {
		*ett_tree = -1;
		*msg_func_p = NULL;
	}
}


/* ------------------------------------------------------------------------ */
/* Dissector code                                                           */
/* ------------------------------------------------------------------------ */

static void
dissect_gmr1_ccch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 len, offset;
	gmr1_msg_func_t msg_func;
	const gchar *msg_str;
	gint ett_tree;
	int hf_idx;
	proto_item *ccch_item = NULL, *pd_item = NULL;
	proto_tree *ccch_tree = NULL, *pd_tree = NULL;
	guint32 oct[3];
	guint8 pd;
	gint ti = -1;

	/* Scan init */
	len = tvb_length(tvb);
	offset = 0;

	/* Safety */
	if (len < 3) {
		/* Can't be a CCCH */
		goto err;
	}

	col_append_str(pinfo->cinfo, COL_INFO, "(CCCH) ");

	/* First octed with pseudo len */
	oct[0] = tvb_get_guint8(tvb, offset++);

	/* Check protocol descriptor */
	oct[1] = tvb_get_guint8(tvb, offset++);

	if ((oct[1] & GMR1_PD_EXT_MSK) == GMR1_PD_EXT_VAL)
		pd = oct[1] & 0xff;
	else
		pd = oct[1] & 0x0f;

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",
		val_to_str(pd, gmr1_pd_short_vals, "Unknown (%u)"));

	if (pd != GMR1_PD_RR)
		goto err;	/* CCCH is only RR */

	/* Get message parameters */
	oct[2] = tvb_get_guint8(tvb, offset);

	gmr1_get_msg_rr_params(oct[2], 0, &msg_str, &ett_tree, &hf_idx, &msg_func);

	/* Create protocol tree */
	if (msg_str == NULL)
	{
		ccch_item = proto_tree_add_protocol_format(
			tree, proto_gmr1_ccch, tvb, 0, len,
			"GMR-1 CCCH - Message Type (0x%02x)", oct[2]);
		ccch_tree = proto_item_add_subtree(ccch_item, ett_msg_ccch);

		col_append_fstr(pinfo->cinfo, COL_INFO, "Message Type (0x%02x) ", oct[2]);
	}
	else
	{
		ccch_item = proto_tree_add_protocol_format(
			tree, proto_gmr1_ccch, tvb, 0, -1,
			"GMR-1 CCCH - %s", msg_str);
		ccch_tree = proto_item_add_subtree(ccch_item, ett_tree);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
	}

	/* Start over */
	offset = 0;

	/* L2 Pseudo Length - [1] 11.5.2.19 */
	offset += elem_v(tvb, ccch_tree, pinfo, GMR1_IE_RR, GMR1_IE_RR_L2_PSEUDO_LEN, offset, NULL);

	/* Protocol discriminator item */
	pd_item = proto_tree_add_text(
		ccch_tree, tvb, 1, 1,
		"Protocol Discriminator: %s",
		val_to_str(pd, gmr1_pd_vals, "Unknown (%u)")
	);

	pd_tree = proto_item_add_subtree(pd_item, ett_rr_pd);

		/* Skip indicator / Transaction indicator */
	if (ti == -1) {
		proto_tree_add_item(pd_tree, hf_gmr1_skip_ind, tvb, 1, 1, ENC_BIG_ENDIAN);
	} else {
		/* FIXME !!! */
	}

		/* Protocol discriminator value */
	proto_tree_add_item(pd_tree, hf_gmr1_l3_pd, tvb, 1, 1, ENC_BIG_ENDIAN);


		/* Move on */
	offset++;

	/* Message type - [1] 11.4 */
	proto_tree_add_uint_format(
		ccch_tree, hf_idx, tvb, offset, 1, oct[2],
		"Message Type: %s", msg_str ? msg_str : "(Unknown)"
	);

	offset++;

	/* Decode elements */
	if (msg_func) {
		(*msg_func)(tvb, ccch_tree, pinfo, offset, len - offset);
	} else {
		proto_tree_add_text(ccch_tree, tvb, offset, len - offset,
		                    "Message Elements");
	}

	/* Done ! */
	return;

	/* Error handling */
err:
	call_dissector(data_handle, tvb, pinfo, tree);
}

void
proto_register_gmr1_rr(void)
{
	static hf_register_info hf[] = {
		{ &hf_rr_msg_type,
		  { "Radio Resources Management Message Type", "gmr1.rr.msg_type",
		    FT_UINT8, BASE_HEX, VALS(gmr1_msg_rr_strings), 0x00,
		    NULL, HFILL }	/* FIXME handle CCCH/DCCH conflicts */
		},
		{ &hf_rr_chan_desc_kab_loc,
		  { "KAB Location", "gmr1.rr.chan_desc.kab_loc",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_chan_desc_rx_tn,
		  { "RX Timeslot", "gmr1.rr.chan_desc.rx_tn",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_chan_desc_arfcn,
		  { "ARFCN", "gmr1.rr.chan_desc.arfcn",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_chan_desc_tx_tn,
		  { "TX Timeslot", "gmr1.rr.chan_desc.tx_tn",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_chan_desc_chan_type,
		  { "Channel Type", "gmr1.rr.chan_desc.chan_type",
		    FT_UINT8, BASE_DEC, VALS(rr_chan_desc_chan_type_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_chan_mode,
		  { "Channel Mode", "gmr1.rr.chan_mode",
		    FT_UINT8, BASE_DEC, VALS(rr_chan_mode_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_ciph_mode_setting_sc,
		  { "SC", "gmr1.rr.ciph_mode_setting.sc",
		    FT_UINT8, BASE_DEC, VALS(rr_ciph_mode_setting_sc_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_rr_ciph_mode_setting_algo,
		  { "Algorithm", "gmr1.rr.ciph_mode_setting.algo",
		    FT_UINT8, BASE_DEC, VALS(rr_ciph_mode_setting_algo_vals), 0x0e,
		    NULL, HFILL }
		},
		{ &hf_rr_ciph_resp_cr,
		  { "CR", "gmr1.rr.ciph_resp.cr",
		    FT_UINT8, BASE_DEC, VALS(rr_ciph_resp_cr_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_rr_ciph_resp_spare,
		  { "Spare", "gmr1.rr.ciph_resp.spare",
		    FT_UINT8, BASE_DEC, NULL, 0xe0,
		    NULL, HFILL }
		},
		{ &hf_rr_l2_pseudo_len,
		  { "L2 Pseudo Length value", "gmr1.rr.l2_pseudo_len",
		    FT_UINT8, BASE_DEC, NULL, 0xfc,
		    NULL, HFILL }
		},
		{ &hf_rr_page_mode,
		  { "Page Mode", "gmr1.rr.page_mode.mode",
		    FT_UINT8, BASE_DEC, VALS(rr_page_mode_vals), 0x03,
		    NULL, HFILL }
		},
		{ &hf_rr_page_mode_spare,
		  { "Spare", "gmr1.rr.page_mode.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x0c,
		    NULL, HFILL }
		},
		{ &hf_rr_req_ref_est_cause,
		  { "Establishment cause group ID", "gmr1.rr.req_ref.est_cause",
		    FT_UINT8, BASE_DEC, VALS(rr_req_ref_est_cause_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_rr_req_ref_ra,
		  { "Random Access Information", "gmr1.rr.req_ref.ra",
		    FT_UINT8, BASE_HEX, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_rr_req_ref_fn,
		  { "Frame Number mod 256", "gmr1.rr.req_ref.fn",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_cause,
		  { "RR Cause", "gmr1.rr.cause",
		    FT_UINT8, BASE_DEC, VALS(rr_cause_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_timing_ofs_ti,
		  { "TI", "gmr1.rr.timing_offset.ti",
		    FT_UINT8, BASE_DEC, VALS(rr_timing_ofs_ti_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_timing_ofs_value,
		  { "Timing Offset value", "gmr1.rr.timing_offset.value",
		    FT_INT16, BASE_CUSTOM, rr_timing_ofs_value_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_tmsi_ptmsi,
		  { "TMSI/P-TMSI Value","gmr1.rr.tmsi_ptmsi",
		    FT_UINT32,BASE_HEX,  NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_wait_ind_timeout,
		  { "T3122/T3142 timeout", "gmr1.rr.wait_ind.timeout",
		    FT_UINT8, BASE_CUSTOM, rr_gen_ie_seconds_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_mes1_ab,
		  { "MES1 - Assignment Type", "gmr1.rr.mes_info_flag.1.ab",
		    FT_UINT8, BASE_DEC, VALS(rr_mif_mes1_ab_vals), 0x03,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_mes1_i,
		  { "MES1 - Idle mode position update", "gmr1.rr.mes_info_flag.1.i",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x04,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_mes1_d,
		  { "MES1 - Dedicated mode position update", "gmr1.rr.mes_info_flag.1.d",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_mes2,
		  { "MES2", "gmr1.rr.mes_info_flag.2",
		    FT_UINT8, BASE_DEC, VALS(rr_mif_mes234_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_mes3,
		  { "MES3", "gmr1.rr.mes_info_flag.3",
		    FT_UINT8, BASE_DEC, VALS(rr_mif_mes234_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_mes4,
		  { "MES4", "gmr1.rr.mes_info_flag.4",
		    FT_UINT8, BASE_DEC, VALS(rr_mif_mes234_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_rr_mif_pv,
		  { "Position Verification indicator", "gmr1.rr.mes_info_flag.pv",
		    FT_UINT8, BASE_DEC, VALS(rr_mif_pv_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_freq_ofs_fi,
		  { "FI", "gmr1.rr.frequency_offset.fi",
		    FT_UINT8, BASE_DEC, VALS(rr_freq_ofs_fi_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_freq_ofs_value,
		  { "Frequency Offset value", "gmr1.rr.frequency_offset.value",
		    FT_INT16, BASE_CUSTOM, rr_freq_ofs_value_fmt, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_freq_ofs_spare,
		  { "Spare", "gmr1.rr.frequency_offset.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_page_info_msc_id,
		  { "MSC ID", "gmr1.rr.paging_info.msc_id",
		    FT_UINT8, BASE_DEC, NULL, 0xfc,
		    NULL, HFILL }
		},
		{ &hf_rr_page_info_chan_needed,
		  { "Channel Needed", "gmr1.rr.paging_info.chan_needed",
		    FT_UINT8, BASE_DEC, VALS(rr_page_info_chan_needed_vals), 0x03,
		    NULL, HFILL }
		},
		{ &hf_rr_pos_display_flag,
		  { "Display Information Flag", "gmr1.rr.pos_display.flag",
		    FT_UINT8, BASE_DEC, VALS(rr_pos_display_flag_vals), 0xf0,
		    NULL, HFILL }
		},
		{ &hf_rr_pos_display_text,
		  { "Country and Region name", "gmr1.rr.pos_display.text",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_pos_upd_info_v,
		  { "Valid", "gmr1.rr.pos_upd_info.valid",
		    FT_UINT8, BASE_DEC, VALS(rr_pos_upd_info_v_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_rr_pos_upd_info_dist,
		  { "GPS Update Distance", "gmr1.rr.pos_upd_info.distance",
		    FT_UINT8, BASE_CUSTOM, rr_pos_upd_info_dist_fmt, 0xfe,
		    NULL, HFILL }
		},
		{ &hf_rr_pos_upd_info_time,
		  { "GPS Update Timer", "gmr1.rr.pos_upd_info.time",
		    FT_UINT8, BASE_CUSTOM, rr_pos_upd_info_time_fmt, 0xff,
		    NULL, HFILL }
		},
		{ &hf_rr_bcch_carrier_arfcn,
		  { "ARFCN", "gmr1.rr.bcch_carrier.arfcn",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_bcch_carrier_si,
		  { "Satellite Indication", "gmr1.rr.bcch_carrier.si",
		    FT_UINT8, BASE_DEC, VALS(rr_bcch_carrier_si_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_bcch_carrier_ri,
		  { "Reselection Indication", "gmr1.rr.bcch_carrier.ri",
		    FT_UINT8, BASE_DEC, VALS(rr_bcch_carrier_ri_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_bcch_carrier_spare,
		  { "Spare", "gmr1.rr.bcch_carrier.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_reject_cause,
		  { "Cause", "gmr1.rr.reject_cause.cause",
		    FT_UINT8, BASE_DEC, VALS(rr_reject_cause_vals), 0xfc,
		    NULL, HFILL }
		},
		{ &hf_rr_reject_cause_b,
		  { "BCCH Carrier IE presence", "gmr1.rr.reject_cause.b",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_rr_gps_timestamp,
		  { "GPS timestamp", "gmr1.rr.gps_timestamp",
		    FT_UINT16, BASE_CUSTOM, rr_gps_timestamp_fmt, 0xffff,
		    NULL, HFILL }
		},
		{ &hf_rr_tmsi_avail_msk_tmsi[0],
		  { "TMSI 1 Presence", "gmr1.rr.tmsi_avail_msk.tmsi1",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_rr_tmsi_avail_msk_tmsi[1],
		  { "TMSI 2 Presence", "gmr1.rr.tmsi_avail_msk.tmsi2",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_rr_tmsi_avail_msk_tmsi[2],
		  { "TMSI 3 Presence", "gmr1.rr.tmsi_avail_msk.tmsi3",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_rr_tmsi_avail_msk_tmsi[3],
		  { "TMSI 4 Presence", "gmr1.rr.tmsi_avail_msk.tmsi4",
		    FT_UINT8, BASE_DEC, VALS(rr_gen_ie_presence_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_gps_almanac_pn,
		  { "Page Number", "gmr1.rr.gps_almanac.pn",
		    FT_UINT8, BASE_CUSTOM, rr_gps_almanac_pn_fmt, 0xf8,
		    "See ICD-GPS-200", HFILL }
		},
		{ &hf_rr_gps_almanac_wn,
		  { "Word Number", "gmr1.rr.gps_almanac.wn",
		    FT_UINT8, BASE_DEC, NULL, 0x07,
		    "See ICD-GPS-200", HFILL }
		},
		{ &hf_rr_gps_almanac_word,
		  { "GPS Almanac Word", "gmr1.rr.gps_almanac.word",
		    FT_UINT24, BASE_HEX, NULL, 0x00,
		    "See ICD-GPS-200", HFILL }
		},
		{ &hf_rr_gps_almanac_sfn,
		  { "Sub Frame Number", "gmr1.rr.gps_almanac.sfn",
		    FT_UINT8, BASE_DEC, VALS(rr_gps_almanac_sfn_vals), 0x80,
		    "See ICD-GPS-200", HFILL }
		},
		{ &hf_rr_gps_almanac_co,
		  { "CO", "gmr1.rr.gps_almanac.co",
		    FT_UINT8, BASE_DEC, NULL, 0x40,
		    NULL, HFILL }
		},
		{ &hf_rr_gps_almanac_spare,
		  { "Spare", "gmr1.rr.gps_almanac.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x3f,
		    NULL, HFILL }
		},
		{ &hf_rr_msc_id,
		  { "MSC ID", "gmr1.rr.msc_id",
		    FT_UINT8, BASE_DEC, NULL, 0xfc,
		    NULL, HFILL }
		},
		{ &hf_rr_msc_id_spare,
		  { "Spare", "gmr1.rr.msc_id.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x03,
		    NULL, HFILL }
		},
		{ &hf_rr_gps_discr,
		  { "GPS Position field CRC-16", "gmr1.rr.gps_discriminator",
		    FT_UINT16, BASE_HEX, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_3_prm_rlc_mode,
		  { "RLC Mode", "gmr1.rr._pkt_imm_ass_3_prm.",
		    FT_UINT8, BASE_DEC, VALS(rr_pkt_imm_ass_3_prm_rlc_mode_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_3_prm_spare,
		  { "Spare", "gmr1.rr._pkt_imm_ass_3_prm.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x1e,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_3_prm_dl_tfi,
		  { "Downlink TFI", "gmr1.rr._pkt_imm_ass_3_prm.tfi",
		    FT_UINT8, BASE_HEX, NULL, 0x00,
		    "Temporary Flow Identifier", HFILL }
		},
		{ &hf_rr_pkt_imm_ass_3_prm_start_fn,
		  { "Start Framenumber", "gmr1.rr._pkt_imm_ass_3_prm.start_fn",
		    FT_UINT8, BASE_DEC, NULL, 0xf0,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_3_prm_mac_slot_alloc,
		  { "MAC-slot Allocation", "gmr1.rr._pkt_imm_ass_3_prm.mac_slot_alloc",
		    FT_UINT8, BASE_HEX, NULL, 0xff,
		    "LSB=slot 0, MSB=slot 7", HFILL }
		},
		{ &hf_rr_pkt_freq_prm_arfcn,
		  { "ARFCN", "gmr1.rr.pkt_freq_prm.arfcn",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_freq_prm_dl_freq_plan_id,
		  { "Downlink Freq. Plan ID", "gmr1.rr.pkt_freq_prm.dl_freq_plan_id",
		    FT_UINT8, BASE_DEC, VALS(rr_pkt_freq_prm_dl_freq_plan_id_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_freq_prm_dl_bw,
		  { "Downlink Bandwidth", "gmr1.rr.pkt_freq_prm.dl_bw",
		    FT_UINT8, BASE_CUSTOM, rr_pkt_freq_prm_xx_bw_fmt, 0x70,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_freq_prm_ul_freq_dist,
		  { "Uplink Freq. Distance", "gmr1.rr.pkt_freq_prm.ul_freq_dist",
		    FT_INT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_freq_prm_ul_bw,
		  { "Uplink Bandwidth", "gmr1.rr.pkt_freq_prm.ul_bw",
		    FT_UINT8, BASE_CUSTOM, rr_pkt_freq_prm_xx_bw_fmt, 0x70,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_freq_prm_spare,
		  { "Spare", "gmr1.rr.pkt_freq_prm.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_spare1,
		  { "Spare", "gmr1.rr._pkt_imm_ass_2_prm.ac.spare1",
		    FT_UINT8, BASE_DEC, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_final_alloc,
		  { "Final Allocation", "gmr1.rr._pkt_imm_ass_2_prm.ac.final_alloc",
		    FT_UINT8, BASE_DEC, NULL, 0x02,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_usf_granularity,
		  { "USF Granularity", "gmr1.rr._pkt_imm_ass_2_prm.ac.usf_granularity",
		    FT_UINT8, BASE_DEC, NULL, 0x04,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_dl_ctl_mac_slot,
		  { "Downlink Control MAC-slot", "gmr1.rr._pkt_imm_ass_2_prm.ac.dl_ctl_mac_slot",
		    FT_UINT8, BASE_DEC, NULL, 0x38,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_mac_mode,
		  { "MAC mode", "gmr1.rr._pkt_imm_ass_2_prm.ac.mac_mode",
		    FT_UINT8, BASE_DEC, VALS(rr_pkt_imm_ass_2_prm_ac_mac_mode_vals), 0xc0,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_start_fn,
		  { "Starting Frame Number", "gmr1.rr._pkt_imm_ass_2_prm.ac.start_fn",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_rlc_dblk_gnt,
		  { "RLC Data Blocks Granted", "gmr1.rr._pkt_imm_ass_2_prm.ac.rlc_dblk_gnt",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_mcs,
		  { "MCS", "gmr1.rr._pkt_imm_ass_2_prm.ac.mcs",
		    FT_UINT8, BASE_DEC, NULL, 0xf8,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_tfi,
		  { "TFI", "gmr1.rr._pkt_imm_ass_2_prm.ac.tfi",
		    FT_UINT8, BASE_HEX, NULL, 0x7f,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_spare2,
		  { "Spare", "gmr1.rr._pkt_imm_ass_2_prm.ac.spare2",
		    FT_UINT8, BASE_HEX, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_ac_mac_slot_alloc,
		  { "MAC-slot Allocation", "gmr1.rr._pkt_imm_ass_2_prm.ac.mac_slot_alloc",
		    FT_UINT8, BASE_HEX, NULL, 0xff,
		    "LSB=slot 0, MSB=slot 7", HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_chan_mcs_cmd,
		  { "Channel MCS Command", "gmr1.rr._pkt_imm_ass_2_prm.d.chan_mcs_cmd",
		    FT_UINT8, BASE_HEX, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_chan_mcs_cmd_pnb512,
		  { "Channel MCS Command PNB 5,12", "gmr1.rr._pkt_imm_ass_2_prm.d.chan_mcs_cmd_pnb512",
		    FT_UINT8, BASE_HEX, NULL, 0xf0,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_spare1,
		  { "Spare", "gmr1.rr._pkt_imm_ass_2_prm.d.spare1",
		    FT_UINT8, BASE_HEX, NULL, 0xff,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_rlc_dblk_gnt,
		  { "RLC Data Blocks Granted", "gmr1.rr._pkt_imm_ass_2_prm.d.rlc_dblk_gnt",
		    FT_UINT8, BASE_DEC, NULL, 0x7f,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_spare2,
		  { "Spare", "gmr1.rr._pkt_imm_ass_2_prm.d.spare2",
		    FT_UINT8, BASE_HEX, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_tfi,
		  { "TFI", "gmr1.rr._pkt_imm_ass_2_prm.d.tfi",
		    FT_UINT8, BASE_HEX, NULL, 0x7f,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_usf_granularity,
		  { "USF Granularity", "gmr1.rr._pkt_imm_ass_2_prm.ac.usf_granularity",
		    FT_UINT8, BASE_DEC, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_imm_ass_2_prm_d_mac_slot_alloc,
		  { "MAC-slot Allocation", "gmr1.rr._pkt_imm_ass_2_prm.d.mac_slot_alloc",
		    FT_UINT8, BASE_HEX, NULL, 0xff,
		    "LSB=slot 0, MSB=slot 7", HFILL }
		},
		{ &hf_rr_usf_value,
		  { "Uplink state flag (USF)", "gmr1.rr.usf.value",
		    FT_UINT8, BASE_HEX, NULL, 0x3f,
		    NULL, HFILL }
		},
		{ &hf_rr_usf_spare,
		  { "Spare", "gmr1.rr.usf.spare",
		    FT_UINT24, BASE_DEC, NULL, 0xffffc0,
		    NULL, HFILL }
		},
		{ &hf_rr_timing_adv_idx_value,
		  { "TAI Value", "gmr1.rr.timing_adv_idx.tai",
		    FT_UINT8, BASE_DEC, NULL, 0x7f,
		    NULL, HFILL }
		},
		{ &hf_rr_timing_adv_idx_spare,
		  { "Spare", "gmr1.rr.timing_adv_idx.spare",
		    FT_UINT8, BASE_DEC, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_rr_tlli,
		  { "TLLI", "gmr1.rr.tlli",
		    FT_UINT32, BASE_HEX,  NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_pwr_ctrl_prm_par,
		  { "Power Attenuation Request (PAR)", "gmr1.rr.pkt_pwr_ctrl_prm.par",
		    FT_UINT8, BASE_CUSTOM, rr_pkt_pwr_ctrl_prm_par_fmt, 0x3f,
		    NULL, HFILL }
		},
		{ &hf_rr_pkt_pwr_ctrl_prm_spare,
		  { "Spare", "gmr1.rr.pkt_pwr_ctrl_prm.spare",
		    FT_UINT8, BASE_DEC, NULL, 0xc0,
		    NULL, HFILL }
		},
		{ &hf_rr_persistence_lvl[0],
		  { "for Radio priority 1", "gmr1.rr.persistence_lvl.p1",
		    FT_UINT8, BASE_DEC, NULL, 0xf0,
		    NULL, HFILL }
		},
		{ &hf_rr_persistence_lvl[1],
		  { "for Radio priority 2", "gmr1.rr.persistence_lvl.p2",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_rr_persistence_lvl[2],
		  { "for Radio priority 3", "gmr1.rr.persistence_lvl.p3",
		    FT_UINT8, BASE_DEC, NULL, 0xf0,
		    NULL, HFILL }
		},
		{ &hf_rr_persistence_lvl[3],
		  { "for Radio priority 4", "gmr1.rr.persistence_lvl.p4",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
	};

#define NUM_INDIVIDUAL_ELEMS 2
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
	                 NUM_GMR1_IE_RR +
	                 NUM_GMR1_MSG_RR];

	unsigned int last_offset, i;

	/* Setup protocol subtree array */
	ett[0] = &ett_msg_ccch;
	ett[1] = &ett_rr_pd;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i<NUM_GMR1_IE_RR; i++,last_offset++) {
		ett_gmr1_ie_rr[i] = -1;
		ett[last_offset] = &ett_gmr1_ie_rr[i];
	}

	for (i=0; i<NUM_GMR1_MSG_RR; i++,last_offset++) {
		ett_msg_rr[i] = -1;
		ett[last_offset] = &ett_msg_rr[i];
	}

	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol name and field description */
	proto_gmr1_ccch = proto_register_protocol("GEO-Mobile Radio (1) CCCH", "GMR-1 CCCH", "gmr1_ccch");

	proto_register_field_array(proto_gmr1_ccch, hf, array_length(hf));

	/* Register dissector */
	register_dissector("gmr1_ccch", dissect_gmr1_ccch, proto_gmr1_ccch);
}

void
proto_reg_handoff_gmr1_rr(void)
{
	data_handle = find_dissector("data");
}
