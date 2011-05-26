/* packet-homeplug-av.c
 * Routines for HomePlug AV dissection
 *
 * Copyright 2011, Florian Fainelli <florian[AT]openwrt.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
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

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/ptvcursor.h>

static int proto_homeplug_av			= -1;

static int hf_homeplug_av_mmhdr			= -1;
static int hf_homeplug_av_mmhdr_mmver		= -1;
static int hf_homeplug_av_mmhdr_mmtype		= -1;
static int hf_homeplug_av_mmhdr_mmtype_lsb 	= -1;
static int hf_homeplug_av_mmhdr_mmtype_msb 	= -1;
static int hf_homeplug_av_vendor		= -1;
static int hf_homeplug_av_vendor_oui		= -1;
static int hf_homeplug_av_reserved		= -1;

/* Beacon */
static int hf_homeplug_av_bcn			= -1;
static int hf_homeplug_av_bcn_bts		= -1;
static int hf_homeplug_av_bcn_bto_0		= -1;
static int hf_homeplug_av_bcn_bto_1		= -1;
static int hf_homeplug_av_bcn_bto_2		= -1;
static int hf_homeplug_av_bcn_bto_3		= -1;

/* Frame Control */
static int hf_homeplug_av_fc			= -1;
static int hf_homeplug_av_fc_stei		= -1;
static int hf_homeplug_av_fc_dtei		= -1;
static int hf_homeplug_av_fc_lid		= -1;
static int hf_homeplug_av_fc_cfs		= -1;
static int hf_homeplug_av_fc_bdf		= -1;
static int hf_homeplug_av_fc_hp10df		= -1;
static int hf_homeplug_av_fc_hp11df		= -1;
static int hf_homeplug_av_fc_ppb		= -1;
static int hf_homeplug_av_fc_ble		= -1;
static int hf_homeplug_av_fc_pbsz		= -1;
static int hf_homeplug_av_fc_num_sym		= -1;
static int hf_homeplug_av_fc_tmi_av		= -1;
static int hf_homeplug_av_fc_fl_av		= -1;
static int hf_homeplug_av_fc_mpdu_cnt		= -1;
static int hf_homeplug_av_fc_burst_cnt		= -1;
static int hf_homeplug_av_fc_clst		= -1;
static int hf_homeplug_av_fc_rg_len		= -1;
static int hf_homeplug_av_fc_mfs_cmd_mgmt	= -1;
static int hf_homeplug_av_fc_mfs_cmd_data	= -1;
static int hf_homeplug_av_fc_rsr		= -1;
static int hf_homeplug_av_fc_mcf		= -1;
static int hf_homeplug_av_fc_dccpcf		= -1;
static int hf_homeplug_av_fc_mnbf		= -1;


/* Public MMEs */
static int hf_homeplug_av_public		= -1;
static int hf_homeplug_av_public_frag_count	= -1;
static int hf_homeplug_av_public_frag_index	= -1;
static int hf_homeplug_av_public_frag_seqnum	= -1;

static int hf_homeplug_av_cc_disc_list_cnf	= -1;

static int hf_homeplug_av_cc_disc_list_sta_cnt	= -1;
static int hf_homeplug_av_cc_sta_info		= -1;
static int hf_homeplug_av_cc_sta_info_mac	= -1;
static int hf_homeplug_av_cc_sta_info_tei	= -1;
static int hf_homeplug_av_cc_sta_info_same_net	= -1;
static int hf_homeplug_av_cc_sta_info_sig_level	= -1;
static int hf_homeplug_av_cc_sta_info_avg_ble	= -1;

static int hf_homeplug_av_cc_disc_list_net_cnt	= -1;
static int hf_homeplug_av_cc_net_info		= -1;
static int hf_homeplug_av_cc_net_info_hyb_mode	= -1;
static int hf_homeplug_av_cc_net_info_bcn_slots	= -1;
static int hf_homeplug_av_cc_net_info_cco_sts	= -1;
static int hf_homeplug_av_cc_net_info_bcn_ofs	= -1;

static int hf_homeplug_av_brg_infos_cnf		= -1;
static int hf_homeplug_av_brg_infos_cnf_brd	= -1;
static int hf_homeplug_av_brg_infos_cnf_btei	= -1;
static int hf_homeplug_av_brg_infos_cnf_num_stas= -1;
static int hf_homeplug_av_brg_infos_cnf_mac	= -1;

static int hf_homeplug_av_cm_nw_infos_cnf	= -1;

static int hf_homeplug_av_nw_stats_cnf		= -1;

/* Shared network informations fields */
static int hf_homeplug_av_nw_info_del_type	= -1;
static int hf_homeplug_av_nw_info_fccs_av	= -1;
static int hf_homeplug_av_nw_info_peks		= -1;
static int hf_homeplug_av_nw_info_pid		= -1;
static int hf_homeplug_av_nw_info_prn		= -1;
static int hf_homeplug_av_nw_info_pmn		= -1;
static int hf_homeplug_av_nw_info_my_nonce	= -1;
static int hf_homeplug_av_nw_info_your_nonce	= -1;
static int hf_homeplug_av_nw_info_key_type	= -1;
static int hf_homeplug_av_nw_info_cco_cap	= -1;
static int hf_homeplug_av_nw_info_num_avlns	= -1;
static int hf_homeplug_av_nw_info_nid		= -1;
static int hf_homeplug_av_nw_info_snid		= -1;
static int hf_homeplug_av_nw_info_tei		= -1;
static int hf_homeplug_av_nw_info_sta_role	= -1;
static int hf_homeplug_av_nw_info_cco_mac	= -1;
static int hf_homeplug_av_nw_info_cco_tei	= -1;
static int hf_homeplug_av_nw_info_num_stas	= -1;
static int hf_homeplug_av_nw_info_access	= -1;
static int hf_homeplug_av_nw_info_num_coord	= -1;


static int hf_homeplug_av_cm_enc_pld_ind	= -1;
static int hf_homeplug_av_cm_enc_pld_ind_avlns	= -1;
static int hf_homeplug_av_cm_enc_pld_ind_iv	= -1;
static int hf_homeplug_av_cm_enc_pld_ind_uuid	= -1;
static int hf_homeplug_av_cm_enc_pld_ind_len	= -1;
static int hf_homeplug_av_cm_enc_pld_ind_pld	= -1;

static int hf_homeplug_av_cm_enc_pld_rsp	= -1;
static int hf_homeplug_av_cm_enc_pld_rsp_result	= -1;

static int hf_homeplug_av_cm_set_key_req	= -1;
static int hf_homeplug_av_cm_set_key_req_nw_key	= -1;

static int hf_homeplug_av_cm_set_key_cnf	= -1;
static int hf_homeplug_av_cm_set_key_cnf_result	= -1;

static int hf_homeplug_av_cm_get_key_req	= -1;
static int hf_homeplug_av_cm_get_key_req_type	= -1;
static int hf_homeplug_av_cm_get_key_req_has_key= -1;

static int hf_homeplug_av_cm_get_key_cnf	= -1;
static int hf_homeplug_av_cm_get_key_cnf_result	= -1;
static int hf_homeplug_av_cm_get_key_cnf_rtype	= -1;
static int hf_homeplug_av_cm_get_key_cnf_key	= -1;


/* Intellon specific vendor MMEs */
static int hf_homeplug_av_get_sw_cnf		= -1;
static int hf_homeplug_av_get_sw_cnf_status	= -1;
static int hf_homeplug_av_get_sw_cnf_dev_id	= -1;
static int hf_homeplug_av_get_sw_cnf_ver_len	= -1;
static int hf_homeplug_av_get_sw_cnf_ver_str	= -1;
static int hf_homeplug_av_get_sw_cnf_upg	= -1;

/* Shared memory related fields */
static int hf_homeplug_av_mem_len_16bits	= -1;
static int hf_homeplug_av_mem_len_32bits	= -1;
static int hf_homeplug_av_mem_offset		= -1;
static int hf_homeplug_av_mem_checksum		= -1;
static int hf_homeplug_av_mem_data		= -1;
static int hf_homeplug_av_mem_addr		= -1;
static int hf_homeplug_av_mem_status		= -1;

static int hf_homeplug_av_wr_mem_req		= -1;
static int hf_homeplug_av_wr_mem_cnf		= -1;

static int hf_homeplug_av_rd_mem_req		= -1;
static int hf_homeplug_av_rd_mem_cnf		= -1;

static int hf_homeplug_av_mac_module_id		= -1;

static int hf_homeplug_av_st_mac_req		= -1;
static int hf_homeplug_av_st_mac_req_img_load	= -1;
static int hf_homeplug_av_st_mac_req_img_len	= -1;
static int hf_homeplug_av_st_mac_req_img_chksum	= -1;
static int hf_homeplug_av_st_mac_req_img_start	= -1;

static int hf_homeplug_av_st_mac_cnf		= -1;
static int hf_homeplug_av_st_mac_cnf_status	= -1;

static int hf_homeplug_av_get_nvm_cnf		= -1;
static int hf_homeplug_av_get_nvm_cnf_status	= -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_type	= -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_page	= -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_block	= -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_size	= -1;

static int hf_homeplug_av_rs_dev_cnf		= -1;
static int hf_homeplug_av_rs_dev_cnf_status	= -1;

static int hf_homeplug_av_wr_mod_req		= -1;

static int hf_homeplug_av_wr_mod_cnf		= -1;
static int hf_homeplug_av_wr_mod_cnf_status	= -1;

static int hf_homeplug_av_wr_mod_ind		= -1;
static int hf_homeplug_av_wr_mod_ind_status	= -1;

static int hf_homeplug_av_rd_mod_req		= -1;

static int hf_homeplug_av_rd_mod_cnf		= -1;
static int hf_homeplug_av_rd_mod_cnf_status	= -1;

static int hf_homeplug_av_mod_nvm_req		= -1;

static int hf_homeplug_av_mod_nvm_cnf		= -1;
static int hf_homeplug_av_mod_nvm_cnf_status	= -1;

static int hf_homeplug_av_wd_rpt_req		= -1;
static int hf_homeplug_av_wd_rpt_req_session_id	= -1;
static int hf_homeplug_av_wd_rpt_req_clr	= -1;

static int hf_homeplug_av_wd_rpt_ind		= -1;
static int hf_homeplug_av_wd_rpt_ind_status	= -1;
static int hf_homeplug_av_wd_rpt_ind_session_id	= -1;
static int hf_homeplug_av_wd_rpt_ind_num_parts	= -1;
static int hf_homeplug_av_wd_rpt_ind_curr_part	= -1;
static int hf_homeplug_av_wd_rpt_ind_rdata_len	= -1;
static int hf_homeplug_av_wd_rpt_ind_rdata_ofs	= -1;
static int hf_homeplug_av_wd_rpt_ind_rdata	= -1;

static int hf_homeplug_av_lnk_stats_req		= -1;
static int hf_homeplug_av_lnk_stats_req_mcontrol= -1;
static int hf_homeplug_av_lnk_stats_req_dir	= -1;
static int hf_homeplug_av_lnk_stats_req_lid	= -1;
static int hf_homeplug_av_lnk_stats_req_macaddr	= -1;

static int hf_homeplug_av_lnk_stats_cnf		= -1;
static int hf_homeplug_av_lnk_stats_cnf_status	= -1;
static int hf_homeplug_av_lnk_stats_cnf_dir	= -1;
static int hf_homeplug_av_lnk_stats_cnf_lid	= -1;
static int hf_homeplug_av_lnk_stats_cnf_tei	= -1;
static int hf_homeplug_av_lnk_stats_cnf_lstats	= -1;

static int hf_homeplug_av_lnk_stats_tx		= -1;
static int hf_homeplug_av_lnk_stats_tx_mpdu_ack	= -1;
static int hf_homeplug_av_lnk_stats_tx_mpdu_col	= -1;
static int hf_homeplug_av_lnk_stats_tx_mpdu_fai = -1;
static int hf_homeplug_av_lnk_stats_tx_pbs_pass	= -1;
static int hf_homeplug_av_lnk_stats_tx_pbs_fail = -1;

static int hf_homeplug_av_lnk_stats_rx		= -1;
static int hf_homeplug_av_lnk_stats_rx_mpdu_ack	= -1;
static int hf_homeplug_av_lnk_stats_rx_mpdu_fai = -1;
static int hf_homeplug_av_lnk_stats_rx_pbs_pass	= -1;
static int hf_homeplug_av_lnk_stats_rx_pbs_fail = -1;
static int hf_homeplug_av_lnk_stats_rx_tb_pass 	= -1;
static int hf_homeplug_av_lnk_stats_rx_tb_fail 	= -1;
static int hf_homeplug_av_lnk_stats_rx_num_int 	= -1;

static int hf_homeplug_av_rx_inv_stats		= -1;
static int hf_homeplug_av_rx_inv_phy_rate	= -1;
static int hf_homeplug_av_rx_inv_pbs_pass	= -1;
static int hf_homeplug_av_rx_inv_pbs_fail	= -1;
static int hf_homeplug_av_rx_inv_tb_pass	= -1;
static int hf_homeplug_av_rx_inv_tb_fail	= -1;

static int hf_homeplug_av_sniffer_req		= -1;
static int hf_homeplug_av_sniffer_req_ctrl	= -1;

static int hf_homeplug_av_sniffer_cnf		= -1;
static int hf_homeplug_av_sniffer_cnf_status	= -1;
static int hf_homeplug_av_sniffer_cnf_state	= -1;
static int hf_homeplug_av_sniffer_cnf_da	= -1;

static int hf_homeplug_av_sniffer_ind		= -1;
static int hf_homeplug_av_sniffer_ind_type	= -1;
static int hf_homeplug_av_sniffer_ind_data	= -1;
static int hf_homeplug_av_sniffer_data_dir	= -1;
static int hf_homeplug_av_sniffer_data_systime	= -1;
static int hf_homeplug_av_sniffer_data_bc_time	= -1;

static int hf_homeplug_av_nw_info_cnf		= -1;

static int hf_homeplug_av_nw_info_sta_info	= -1;
static int hf_homeplug_av_nw_info_net_info	= -1;

static int hf_homeplug_av_nw_info_sta_da	= -1;
static int hf_homeplug_av_nw_info_sta_tei	= -1;
static int hf_homeplug_av_nw_info_sta_bda	= -1;
static int hf_homeplug_av_nw_info_sta_phy_dr_tx	= -1;
static int hf_homeplug_av_nw_info_sta_phy_dr_rx	= -1;

static int hf_homeplug_av_cp_rpt_req		= -1;
static int hf_homeplug_av_cp_rpt_req_session_id	= -1;
static int hf_homeplug_av_cp_rpt_req_clr	= -1;

static int hf_homeplug_av_cp_rpt_ind		= -1;
static int hf_homeplug_av_cp_rpt_ind_status	= -1;
static int hf_homeplug_av_cp_rpt_ind_major_ver	= -1;
static int hf_homeplug_av_cp_rpt_ind_minor_ver	= -1;
static int hf_homeplug_av_cp_rpt_ind_session_id	= -1;
static int hf_homeplug_av_cp_rpt_ind_total_size	= -1;
static int hf_homeplug_av_cp_rpt_ind_blk_offset	= -1;
static int hf_homeplug_av_cp_rpt_ind_byte_index	= -1;
static int hf_homeplug_av_cp_rpt_ind_num_parts	= -1;
static int hf_homeplug_av_cp_rpt_ind_curr_part	= -1;
static int hf_homeplug_av_cp_rpt_ind_data_len	= -1;
static int hf_homeplug_av_cp_rpt_ind_data_ofs	= -1;
static int hf_homeplug_av_cp_rpt_ind_data	= -1;

static int hf_homeplug_av_fr_lbk_duration	= -1;
static int hf_homeplug_av_fr_lbk_len		= -1;

static int hf_homeplug_av_fr_lbk_req		= -1;
static int hf_homeplug_av_fr_lbk_req_data	= -1;

static int hf_homeplug_av_fr_lbk_cnf		= -1;
static int hf_homeplug_av_fr_lbk_cnf_status	= -1;

static int hf_homeplug_av_lbk_stat_cnf		= -1;
static int hf_homeplug_av_lbk_stat_cnf_status	= -1;
static int hf_homeplug_av_lbk_stat_cnf_lbk_stat	= -1;

static int hf_homeplug_av_set_key_req		= -1;
static int hf_homeplug_av_set_key_req_eks	= -1;
static int hf_homeplug_av_set_key_req_nmk	= -1;
static int hf_homeplug_av_set_key_req_rda	= -1;
static int hf_homeplug_av_set_key_req_dak	= -1;

static int hf_homeplug_av_set_key_cnf		= -1;
static int hf_homeplug_av_set_key_cnf_status	= -1;

static int hf_homeplug_av_mfg_string_cnf	= -1;
static int hf_homeplug_av_mfg_string_cnf_status	= -1;
static int hf_homeplug_av_mfg_string_cnf_len	= -1;
static int hf_homeplug_av_mfg_string_cnf_string	= -1;

static int hf_homeplug_av_rd_cblock_cnf		= -1;
static int hf_homeplug_av_rd_cblock_cnf_status	= -1;
static int hf_homeplug_av_rd_cblock_cnf_len	= -1;

static int hf_homeplug_av_cblock_hdr		= -1;
static int hf_homeplug_av_cblock_hdr_ver	= -1;
static int hf_homeplug_av_cblock_img_rom_addr	= -1;
static int hf_homeplug_av_cblock_img_addr	= -1;
static int hf_homeplug_av_cblock_img_len	= -1;
static int hf_homeplug_av_cblock_img_chksum	= -1;
static int hf_homeplug_av_cblock_entry_point	= -1;
static int hf_homeplug_av_cblock_next_hdr	= -1;
static int hf_homeplug_av_cblock_hdr_chksum	= -1;

static int hf_homeplug_av_cblock		= -1;
static int hf_homeplug_av_cblock_sdram_size	= -1;
static int hf_homeplug_av_cblock_sdram_conf	= -1;
static int hf_homeplug_av_cblock_sdram_tim0	= -1;
static int hf_homeplug_av_cblock_sdram_tim1	= -1;
static int hf_homeplug_av_cblock_sdram_cntrl	= -1;
static int hf_homeplug_av_cblock_sdram_refresh	= -1;
static int hf_homeplug_av_cblock_mac_clock	= -1;

static int hf_homeplug_av_set_sdram_req		= -1;
static int hf_homeplug_av_set_sdram_req_chksum	= -1;

static int hf_homeplug_av_set_sdram_cnf		= -1;
static int hf_homeplug_av_set_sdram_cnf_status	= -1;

static int hf_homeplug_av_host_action_ind	= -1;
static int hf_homeplug_av_host_action_ind_act	= -1;

static int hf_homeplug_av_host_action_rsp	= -1;
static int hf_homeplug_av_host_action_rsp_sts	= -1;

static int hf_homeplug_av_op_attr_cookie	= -1;
static int hf_homeplug_av_op_attr_rep_type	= -1;

static int hf_homeplug_av_op_attr_req		= -1;

static int hf_homeplug_av_op_attr_cnf		= -1;
static int hf_homeplug_av_op_attr_cnf_status	= -1;
static int hf_homeplug_av_op_attr_cnf_size	= -1;
static int hf_homeplug_av_op_attr_cnf_data	= -1;

static int hf_homeplug_av_op_attr_data_hw	= -1;
static int hf_homeplug_av_op_attr_data_sw	= -1;
static int hf_homeplug_av_op_attr_data_sw_major	= -1;
static int hf_homeplug_av_op_attr_data_sw_minor	= -1;
static int hf_homeplug_av_op_attr_data_sw_sub	= -1;
static int hf_homeplug_av_op_attr_data_sw_num	= -1;
static int hf_homeplug_av_op_attr_data_sw_date	= -1;
static int hf_homeplug_av_op_attr_data_sw_rel	= -1;

static int hf_homeplug_av_enet_phy_req		= -1;
static int hf_homeplug_av_enet_phy_req_mcontrol	= -1;
static int hf_homeplug_av_enet_phy_req_addcaps	= -1;

static int hf_homeplug_av_enet_phy_cnf		= -1;
static int hf_homeplug_av_enet_phy_cnf_status	= -1;
static int hf_homeplug_av_enet_phy_cnf_speed	= -1;
static int hf_homeplug_av_enet_phy_cnf_duplex	= -1;

static int hf_homeplug_av_tone_map_req		= -1;
static int hf_homeplug_av_tone_map_req_mac	= -1;
static int hf_homeplug_av_tone_map_req_slot	= -1;

static int hf_homeplug_av_tone_map_cnf		= -1;
static int hf_homeplug_av_tone_map_cnf_status	= -1;
static int hf_homeplug_av_tone_map_cnf_slot	= -1;
static int hf_homeplug_av_tone_map_cnf_num_tms	= -1;
static int hf_homeplug_av_tone_map_cnf_num_act	= -1;

static int hf_homeplug_av_tone_map_carrier	= -1;
static int hf_homeplug_av_tone_map_carrier_lo	= -1;
static int hf_homeplug_av_tone_map_carrier_hi	= -1;

static gint ett_homeplug_av			= -1;
static gint ett_homeplug_av_mmhdr		= -1;
static gint ett_homeplug_av_mmtype		= -1;
static gint ett_homeplug_av_vendor		= -1;
static gint ett_homeplug_av_public		= -1;

static gint ett_homeplug_av_fc			= -1;
static gint ett_homeplug_av_bcn			= -1;
static gint ett_homeplug_av_cc_disc_list_cnf	= -1;
static gint ett_homeplug_av_cc_sta_info		= -1;
static gint ett_homeplug_av_cc_net_info		= -1;
static gint ett_homeplug_av_cm_enc_pld_ind	= -1;
static gint ett_homeplug_av_cm_enc_pld_rsp	= -1;
static gint ett_homeplug_av_cm_set_key_req	= -1;
static gint ett_homeplug_av_cm_set_key_cnf	= -1;
static gint ett_homeplug_av_cm_get_key_req	= -1;
static gint ett_homeplug_av_cm_get_key_cnf	= -1;
static gint ett_homeplug_av_brg_infos_cnf	= -1;
static gint ett_homeplug_av_cm_nw_infos_cnf	= -1;
static gint ett_homeplug_av_nw_stats_cnf	= -1;

static gint ett_homeplug_av_get_sw_cnf		= -1;
static gint ett_homeplug_av_wr_mem_req		= -1;
static gint ett_homeplug_av_wr_mem_cnf		= -1;
static gint ett_homeplug_av_rd_mem_req		= -1;
static gint ett_homeplug_av_st_mac_req		= -1;
static gint ett_homeplug_av_st_mac_cnf		= -1;
static gint ett_homeplug_av_rd_mem_cnf		= -1;
static gint ett_homeplug_av_get_nvm_cnf		= -1;
static gint ett_homeplug_av_rs_dev_cnf		= -1;
static gint ett_homeplug_av_wr_mod_req		= -1;
static gint ett_homeplug_av_wr_mod_cnf		= -1;
static gint ett_homeplug_av_wr_mod_ind		= -1;
static gint ett_homeplug_av_rd_mod_req		= -1;
static gint ett_homeplug_av_rd_mod_cnf		= -1;
static gint ett_homeplug_av_mod_nvm_req		= -1;
static gint ett_homeplug_av_mod_nvm_cnf		= -1;
static gint ett_homeplug_av_wd_rpt_req		= -1;
static gint ett_homeplug_av_wd_rpt_ind		= -1;
static gint ett_homeplug_av_lnk_stats_req	= -1;
static gint ett_homeplug_av_lnk_stats_cnf	= -1;
static gint ett_homeplug_av_lnk_stats_tx	= -1;
static gint ett_homeplug_av_lnk_stats_rx	= -1;
static gint ett_homeplug_av_lnk_stats_rx_inv	= -1;
static gint ett_homeplug_av_sniffer_req		= -1;
static gint ett_homeplug_av_sniffer_cnf		= -1;
static gint ett_homeplug_av_sniffer_ind		= -1;
static gint ett_homeplug_av_sniffer_ind_data	= -1;
static gint ett_homeplug_av_nw_info_cnf		= -1;
static gint ett_homeplug_av_nw_info_sta_info	= -1;
static gint ett_homeplug_av_nw_info_net_info	= -1;
static gint ett_homeplug_av_cp_rpt_req		= -1;
static gint ett_homeplug_av_cp_rpt_ind		= -1;
static gint ett_homeplug_av_fr_lbk_req		= -1;
static gint ett_homeplug_av_fr_lbk_cnf		= -1;
static gint ett_homeplug_av_lbk_stat_cnf	= -1;
static gint ett_homeplug_av_set_key_req		= -1;
static gint ett_homeplug_av_set_key_cnf		= -1;
static gint ett_homeplug_av_mfg_string_cnf	= -1;
static gint ett_homeplug_av_rd_cblock_cnf	= -1;
static gint ett_homeplug_av_cblock_hdr		= -1;
static gint ett_homeplug_av_cblock		= -1;
static gint ett_homeplug_av_set_sdram_req	= -1;
static gint ett_homeplug_av_set_sdram_cnf	= -1;
static gint ett_homeplug_av_host_action_ind	= -1;
static gint ett_homeplug_av_host_action_rsp	= -1;
static gint ett_homeplug_av_op_attr_req		= -1;
static gint ett_homeplug_av_op_attr_cnf		= -1;
static gint ett_homeplug_av_op_attr_data	= -1;
static gint ett_homeplug_av_enet_phy_req	= -1;
static gint ett_homeplug_av_enet_phy_cnf	= -1;
static gint ett_homeplug_av_tone_map_req	= -1;
static gint ett_homeplug_av_tone_map_cnf	= -1;
static gint ett_homeplug_av_tone_map_carrier	= -1;

#define HOMEPLUG_AV_MIN_FRAME_SIZE		46	/* 60 - Ethernet SADDR + DADDR + Ethertype */
#define HOMEPLUG_AV_MMHDR_LEN			3	/* MM version (1) + MM type (2) */

#define HOMEPLUG_AV_PUBLIC_FRAG_COUNT_MASK	0x0F
#define HOMEPLUG_AV_PUBLIC_FRAG_INDEX_MASK	0xF0

#define HOMEPLUG_AV_MMTYPE_CC_DISC_LIST_REQ	0x0014
#define HOMEPLUG_AV_MMTYPE_CC_DISC_LIST_CNF	0x0015
#define HOMEPLUG_AV_MMTYPE_CM_ENC_PLD_IND	0x6004
#define HOMEPLUG_AV_MMTYPE_CM_ENC_PLD_RSP	0x6005
#define HOMEPLUG_AV_MMTYPE_CM_SET_KEY_REQ	0x6008
#define HOMEPLUG_AV_MMTYPE_CM_SET_KEY_CNF	0x6009
#define HOMEPLUG_AV_MMTYPE_CM_GET_KEY_REQ	0x600C
#define HOMEPLUG_AV_MMTYPE_CM_GET_KEY_CNF	0x600D
#define HOMEPLUG_AV_MMTYPE_CM_BRG_INFO_REQ	0x6020
#define HOMEPLUG_AV_MMTYPE_CM_BRG_INFO_CNF	0x6021
#define HOMEPLUG_AV_MMTYPE_CM_NW_INFO_REQ	0x6038
#define HOMEPLUG_AV_MMTYPE_CM_NW_INFO_CNF	0x6039
#define HOMEPLUG_AV_MMTYPE_CM_NW_STATS_REQ	0x6048
#define HOMEPLUG_AV_MMTYPE_CM_NW_STATS_CNF	0x6049
#define HOMEPLUG_AV_MMTYPE_GET_SW_REQ		0xA000
#define HOMEPLUG_AV_MMTYPE_GET_SW_CNF		0xA001
#define HOMEPLUG_AV_MMTYPE_WR_MEM_REQ		0xA004
#define HOMEPLUG_AV_MMTYPE_WR_MEM_CNF		0xA005
#define HOMEPLUG_AV_MMTYPE_RD_MEM_REQ		0xA008
#define HOMEPLUG_AV_MMTYPE_RD_MEM_CNF		0xA009
#define HOMEPLUG_AV_MMTYPE_ST_MAC_REQ		0xA00C
#define HOMEPLUG_AV_MMTYPE_ST_MAC_CNF		0xA00D
#define HOMEPLUG_AV_MMTYPE_GET_NVM_REQ		0xA010
#define HOMEPLUG_AV_MMTYPE_GET_NVM_CNF		0xA011
#define HOMEPLUG_AV_MMTYPE_RS_DEV_REQ		0xA01C
#define HOMEPLUG_AV_MMTYPE_RS_DEV_CNF		0xA01D
#define HOMEPLUG_AV_MMTYPE_WR_MOD_REQ		0xA020
#define HOMEPLUG_AV_MMTYPE_WR_MOD_CNF		0xA021
#define HOMEPLUG_AV_MMTYPE_WR_MOD_IND		0xA022
#define HOMEPLUG_AV_MMTYPE_RD_MOD_REQ		0xA024
#define HOMEPLUG_AV_MMTYPE_RD_MOD_CNF		0xA025
#define HOMEPLUG_AV_MMTYPE_NVM_MOD_REQ		0xA028
#define HOMEPLUG_AV_MMTYPE_NVM_MOD_CNF		0xA029
#define HOMEPLUG_AV_MMTYPE_WD_RPT_REQ		0xA02C
#define HOMEPLUG_AV_MMTYPE_WD_RPT_IND		0xA02E
#define HOMEPLUG_AV_MMTYPE_LNK_STATS_REQ	0xA030
#define HOMEPLUG_AV_MMTYPE_LNK_STATS_CNF	0xA031
#define HOMEPLUG_AV_MMTYPE_SNIFFER_REQ		0xA034
#define HOMEPLUG_AV_MMTYPE_SNIFFER_CNF		0xA035
#define HOMEPLUG_AV_MMTYPE_SNIFFER_IND		0xA036
#define HOMEPLUG_AV_MMTYPE_NW_INFO_REQ		0xA038
#define HOMEPLUG_AV_MMTYPE_NW_INFO_CNF		0xA039
#define HOMEPLUG_AV_MMTYPE_CP_RPT_REQ		0xA040
#define HOMEPLUG_AV_MMTYPE_CP_RPT_IND		0xA042
#define HOMEPLUG_AV_MMTYPE_FR_LBK_REQ		0xA048
#define HOMEPLUG_AV_MMTYPE_FR_LBK_CNF		0xA049
#define HOMEPLUG_AV_MMTYPE_LBK_STAT_REQ		0xA04C
#define HOMEPLUG_AV_MMTYPE_LBK_STAT_CNF		0xA04D
#define HOMEPLUG_AV_MMTYPE_SET_KEY_REQ		0xA050
#define HOMEPLUG_AV_MMTYPE_SET_KEY_CNF		0xA051
#define HOMEPLUG_AV_MMTYPE_MFG_STRING_REQ	0xA054
#define HOMEPLUG_AV_MMTYPE_MFG_STRING_CNF	0xA055
#define HOMEPLUG_AV_MMTYPE_RD_CBLOCK_REQ	0xA058
#define HOMEPLUG_AV_MMTYPE_RD_CBLOCK_CNF	0xA059
#define HOMEPLUG_AV_MMTYPE_SET_SDRAM_REQ	0xA05C
#define HOMEPLUG_AV_MMTYPE_SET_SDRAM_CNF	0xA05D
#define HOMEPLUG_AV_MMTYPE_HOST_ACTION_IND	0xA062
#define HOMEPLUG_AV_MMTYPE_HOST_ACTION_RSP	0xA063
#define HOMEPLUG_AV_MMTYPE_OP_ATTR_REQ		0xA068
#define HOMEPLUG_AV_MMTYPE_OP_ATTR_CNF		0xA069
#define HOMEPLUG_AV_MMTYPE_GET_ENET_PHY_REQ	0xA06C
#define HOMEPLUG_AV_MMTYPE_GET_ENET_PHY_CNF	0xA06D
#define HOMEPLUG_AV_MMTYPE_TONE_MAP_REQ		0xA070
#define HOMEPLUG_AV_MMTYPE_TONE_MAP_CNF		0xA071

static const value_string homeplug_av_mmtype_vals[] = {
    /* Public MMEs */
    { HOMEPLUG_AV_MMTYPE_CC_DISC_LIST_REQ,	"Central Coordination Discovery List Request" },
    { HOMEPLUG_AV_MMTYPE_CC_DISC_LIST_CNF,	"Central Coordination Discovery List Confirmation" },
    { HOMEPLUG_AV_MMTYPE_CM_ENC_PLD_IND,	"Encrypted Payload Indicate" },
    { HOMEPLUG_AV_MMTYPE_CM_ENC_PLD_RSP,	"Encrypted Payload Respons" },
    { HOMEPLUG_AV_MMTYPE_CM_SET_KEY_REQ,	"Set Key Request" },
    { HOMEPLUG_AV_MMTYPE_CM_SET_KEY_CNF,	"Set Key Confirmation" },
    { HOMEPLUG_AV_MMTYPE_CM_GET_KEY_REQ,	"Get Key Request" },
    { HOMEPLUG_AV_MMTYPE_CM_GET_KEY_CNF,	"Get Key Confirmation" },
    { HOMEPLUG_AV_MMTYPE_CM_BRG_INFO_REQ,	"Get Bridge Informations Request" },
    { HOMEPLUG_AV_MMTYPE_CM_BRG_INFO_CNF,	"Get Bridge Informations Confirmation" },
    { HOMEPLUG_AV_MMTYPE_CM_NW_INFO_REQ,	"Get Network Informations Request" },
    { HOMEPLUG_AV_MMTYPE_CM_NW_INFO_CNF,	"Get Network Informations Confirmation" },
    { HOMEPLUG_AV_MMTYPE_CM_NW_STATS_REQ,	"Get Network Statistics Request" },
    { HOMEPLUG_AV_MMTYPE_CM_NW_STATS_CNF,	"Get Network Statistics Confirmation" },

    /* Intellon vendor-specific MMEs */
    { HOMEPLUG_AV_MMTYPE_GET_SW_REQ, 		"Get Device/SW Version Request" },
    { HOMEPLUG_AV_MMTYPE_GET_SW_CNF, 		"Get Device/SW Version Confirmation" },
    { HOMEPLUG_AV_MMTYPE_WR_MEM_REQ,		"Write MAC Memory Request" },
    { HOMEPLUG_AV_MMTYPE_WR_MEM_CNF,		"Write MAC Memory Confirmation" },
    { HOMEPLUG_AV_MMTYPE_RD_MEM_REQ,		"Read MAC Memory Request" },
    { HOMEPLUG_AV_MMTYPE_RD_MEM_CNF,		"Read MAC Memory Confirmation" },
    { HOMEPLUG_AV_MMTYPE_ST_MAC_REQ,		"Start MAC Request" },
    { HOMEPLUG_AV_MMTYPE_ST_MAC_CNF,		"Start MAC Confirmation" },
    { HOMEPLUG_AV_MMTYPE_GET_NVM_REQ,		"Get NVM Parameters Request" },
    { HOMEPLUG_AV_MMTYPE_GET_NVM_CNF,		"Get NVM Parameters Confirmation" },
    { HOMEPLUG_AV_MMTYPE_RS_DEV_REQ,		"Reset Device Request" },
    { HOMEPLUG_AV_MMTYPE_RS_DEV_CNF,		"Reset Device Confirmation" },
    { HOMEPLUG_AV_MMTYPE_WR_MOD_REQ,		"Write Module Data Request" },
    { HOMEPLUG_AV_MMTYPE_WR_MOD_CNF,		"Write Module Data Confirmation" },
    { HOMEPLUG_AV_MMTYPE_WR_MOD_IND,		"Write Module Data Indicate" },
    { HOMEPLUG_AV_MMTYPE_RD_MOD_REQ,		"Read Module Data Request" },
    { HOMEPLUG_AV_MMTYPE_RD_MOD_CNF,		"Read Module Data Confirmation" },
    { HOMEPLUG_AV_MMTYPE_NVM_MOD_REQ,		"Write Module Data to NVM Request" },
    { HOMEPLUG_AV_MMTYPE_NVM_MOD_CNF,		"Write Module Data to NVM Confirmation" },
    { HOMEPLUG_AV_MMTYPE_WD_RPT_REQ,		"Get Watchdog Report Request" },
    { HOMEPLUG_AV_MMTYPE_WD_RPT_IND,		"Get Watchdog Report Indicate" },
    { HOMEPLUG_AV_MMTYPE_LNK_STATS_REQ,		"Link Statistics Request" },
    { HOMEPLUG_AV_MMTYPE_LNK_STATS_CNF,		"Link Statistics Confirmation" },
    { HOMEPLUG_AV_MMTYPE_SNIFFER_REQ,		"Sniffer Request" },
    { HOMEPLUG_AV_MMTYPE_SNIFFER_CNF,		"Sniffer Confirmation" },
    { HOMEPLUG_AV_MMTYPE_SNIFFER_IND,		"Sniffer Indicate" },
    { HOMEPLUG_AV_MMTYPE_NW_INFO_REQ,		"Network Info Request" },
    { HOMEPLUG_AV_MMTYPE_NW_INFO_CNF,		"Network Info Confirmation" },
    { HOMEPLUG_AV_MMTYPE_CP_RPT_REQ,		"Check Points Request" },
    { HOMEPLUG_AV_MMTYPE_CP_RPT_IND,		"Check Points Indicate" },
    { HOMEPLUG_AV_MMTYPE_FR_LBK_REQ,		"Loopback Request" },
    { HOMEPLUG_AV_MMTYPE_FR_LBK_CNF,		"Loopback Confirmation" },
    { HOMEPLUG_AV_MMTYPE_LBK_STAT_REQ,		"Loopback Status Request" },
    { HOMEPLUG_AV_MMTYPE_LBK_STAT_CNF,		"Loopback Status Confirmation" },
    { HOMEPLUG_AV_MMTYPE_SET_KEY_REQ,		"Set Encryption Key Request" },
    { HOMEPLUG_AV_MMTYPE_SET_KEY_CNF,		"Set Encryption Key Confirmation" },
    { HOMEPLUG_AV_MMTYPE_MFG_STRING_REQ,	"Get Manufacturer String Request" },
    { HOMEPLUG_AV_MMTYPE_MFG_STRING_CNF,	"Get Manufacturer String Confirmation" },
    { HOMEPLUG_AV_MMTYPE_RD_CBLOCK_REQ,		"Read Configuration Block Request" },
    { HOMEPLUG_AV_MMTYPE_RD_CBLOCK_CNF,		"Read Configuration Block Confirmation" },
    { HOMEPLUG_AV_MMTYPE_SET_SDRAM_REQ,		"Set SDRAM Configuration Request" },
    { HOMEPLUG_AV_MMTYPE_SET_SDRAM_CNF,		"Set SDRAM Configuration Confirmation" },
    { HOMEPLUG_AV_MMTYPE_HOST_ACTION_IND,	"Embedded Host Action Required Indication" },
    { HOMEPLUG_AV_MMTYPE_HOST_ACTION_RSP,	"Embedded Host Action Required Respons" },
    { HOMEPLUG_AV_MMTYPE_OP_ATTR_REQ,		"Get Device Attributes Request" },
    { HOMEPLUG_AV_MMTYPE_OP_ATTR_CNF,		"Get Device Attributes Confirmation" },
    { HOMEPLUG_AV_MMTYPE_GET_ENET_PHY_REQ,	"Get Ethernet PHY Settings Request" },
    { HOMEPLUG_AV_MMTYPE_GET_ENET_PHY_CNF,	"Get Ethernet PHY Settings Confirmation" },
    { HOMEPLUG_AV_MMTYPE_TONE_MAP_REQ,		"Tone Map Characteristics Request" },
    { HOMEPLUG_AV_MMTYPE_TONE_MAP_CNF,		"Tone Map Characteristics Confirmation" },
    { 0, NULL }
};

/* Versions */
#define HOMEPLUG_AV_MMVER_MASK			0x01

static const value_string homeplug_av_mmver_vals[] = {
    { 0x00, "1.0" },
    { 0x01, "1.1" },
    { 0, NULL }
};

/* MMTYPE LSB Values */
#define HOMEPLUG_AV_MMTYPE_LSB_MASK		0x03

static const value_string homeplug_av_mmtype_lsb_vals[] = {
    { 0x00, "Request" },
    { 0x01, "Confirm" },
    { 0x02, "Indication" },
    { 0x03, "Response" },
    { 0, NULL }
};

/* MMTYPE MSB Values */
#define HOMEPLUG_AV_MMTYPE_MSB_STA_CCO		0x00
#define HOMEPLUG_AV_MMTYPE_MSB_PROXY		0x01
#define HOMEPLUG_AV_MMTYPE_MSB_CCO_CCO		0x02
#define HOMEPLUG_AV_MMTYPE_MSB_STA_STA		0x03
#define HOMEPLUG_AV_MMTYPE_MSB_MANUF		0x04
#define HOMEPLUG_AV_MMTYPE_MSB_VENDOR		0x05
#define HOMEPLUG_AV_MMTYPE_MSB_RSV		0x06
#define HOMEPLUG_AV_MMTYPE_MSB_MASK		0x06
#define HOMEPLUG_AV_MMTYPE_MSB_SHIFT		(5)

static const value_string homeplug_av_mmtype_msb_vals[] = {
   { HOMEPLUG_AV_MMTYPE_MSB_STA_CCO, "STA - Central Coordinator" },
   { HOMEPLUG_AV_MMTYPE_MSB_PROXY,   "Proxy Coordinator" },
   { HOMEPLUG_AV_MMTYPE_MSB_CCO_CCO, "Central Coordinator - Central Coordinator" },
   { HOMEPLUG_AV_MMTYPE_MSB_STA_STA, "STA - STA" },
   { HOMEPLUG_AV_MMTYPE_MSB_MANUF,   "Manufacturer Specific" },
   { HOMEPLUG_AV_MMTYPE_MSB_VENDOR,  "Vendor Specific" },
   { 0, NULL }
};

#define HOMEPLUG_AV_CC_STA_NET_MASK	0x01

static const value_string homeplug_av_cc_sta_net_type_vals[] = {
   { 0x00, "Different network" },
   { 0x01, "Same network" },
   { 0, NULL }
};

static const value_string homeplug_av_sig_level_vals[] = {
   { 0x00,	"N/A" },
   { 0x01,	"> - 10 dB, but <= 0 dB" },
   { 0x02,	"> - 15 dB, but <= -10 dB" },
   { 0x03,	"> - 20 dB, but <= -15 dB" },
   { 0x04,	"> - 25 dB, but <= -20 dB" },
   { 0x05,	"> - 30 dB, but <= -25 dB" },
   { 0x06,	"> - 35 dB, but <= -30 dB" },
   { 0x07,	"> - 40 dB, but <= -35 dB" },
   { 0x08,	"> - 45 dB, but <= -40 dB" },
   { 0x09,	"> - 50 dB, but <= -45 dB" },
   { 0x0A,	"> - 55 dB, but <= -50 dB" },
   { 0x0B,	"> - 60 dB, but <= -55 dB" },
   { 0x0C,	"> - 65 dB, but <= -60 dB" },
   { 0x0D,	"> - 70 dB, but <= -65 dB" },
   { 0x0E,	"> - 75 dB, but <= -70 dB" },
   { 0x0F,	"<= -75 dB" },
   { 0, NULL }
};

#define HOMEPLUG_AV_CCO_STATUS_MASK		0x07

static const value_string homeplug_av_cco_status_vals[] = {
   { 0x00, "Unknown" },
   { 0x01, "Non-coordinating Network" },
   { 0x02, "Coordinating, group status unknown" },
   { 0x03, "Coordinating network in the same group" },
   { 0x04, "Coordinating network not in the same group" },
   { 0, NULL }
};

#define HOMEPLUG_AV_NW_INFO_ROLE_MASK	0x03

static const value_string homeplug_av_nw_info_role_vals[] = {
   { 0x00, "Station" },
   { 0x01, "Proxy coordinator" },
   { 0x02, "Central coordinator" },
   { 0, NULL }
};

#define HOMEPLUG_AV_NW_INFO_NID_MASK	0x01

static const value_string homeplug_nw_info_access_vals[] = {
   { 0x00, "In-home" },
   { 0x01, "Access" },
   { 0, NULL }
};

#define HOMEPLUG_AV_PEKS_MASK		0x0F

static const value_string homeplug_av_peks_vals[] = {
   { 0x00, "Destination STA's DAK" },
   { 0x01, "NMK known to STA" },
   { 0x02, "TEK Index 0" },
   { 0x03, "TEK Index 1" },
   { 0x04, "TEK Index 2" },
   { 0x05, "TEK Index 3" },
   { 0x06, "TEK Index 4" },
   { 0x07, "TEK Index 5" },
   { 0x08, "TEK Index 6" },
   { 0x09, "TEK Index 7" },
   { 0x0A, "TEK Index 8" },
   { 0x0B, "TEK Index 9" },
   { 0x0C, "TEK Index 10" },
   { 0x0D, "TEK Index 11" },
   { 0x0E, "TEK Index 12" },
   { 0x0F, "No key" },
   { 0, NULL }
};

#define HOMEPLUG_AV_AVLN_STATUS_MASK	0x0F

static const value_string homeplug_av_avln_status_vals[] = {
   { 0x00, "Unassociated and Level-0 CCo capable" },
   { 0x01, "Unassociated and Level-1 CCo capable" },
   { 0x02, "Unassociated and Level-2 CCo capable" },
   { 0x03, "Unassociated and Level-3 CCo capable" },
   { 0x04, "Associated but not PCo capable" },
   { 0x05, "Associated but and PCo capable" },
   { 0x06, "Reserved" },
   { 0x07, "Reserved" },
   { 0x08, "CCo of an AV Logical Network" },
   { 0, NULL }
};

#define HOMEPLUG_AV_PID_AUTH_STA	0x00
#define HOMEPLUG_AV_PID_PROV_AUTH_NEK	0x01
#define HOMEPLUG_AV_PID_PROV_AUTH_DAK	0x02
#define HOMEPLUG_AV_PID_PROV_AUTH_UKE	0x03
#define HOMEPLUG_AV_PID_HLE		0x04
#define HOMEPLUG_AV_PID_MASK		0x07

static const value_string homeplug_av_pid_vals[] = {
   { HOMEPLUG_AV_PID_AUTH_STA,		"Authentication request by new STA" },
   { HOMEPLUG_AV_PID_PROV_AUTH_NEK,	"Provision authenticated STA with new NEK by CCo" },
   { HOMEPLUG_AV_PID_PROV_AUTH_DAK,	"Provision STA with NMK using DAK" },
   { HOMEPLUG_AV_PID_PROV_AUTH_UKE,	"Provision STA with NMK using UKE" },
   { HOMEPLUG_AV_PID_HLE,		"HLE" },
   { 0, NULL }
};

#define HOMEPLUG_AV_KEY_TYPE_DAK	0x00
#define HOMEPLUG_AV_KEY_TYPE_NMK	0x01
#define HOMEPLUG_AV_KEY_TYPE_NEK	0x02
#define HOMEPLUG_AV_KEY_TYPE_TEK	0x03
#define HOMEPLUG_AV_KEY_TYPE_HASH	0x04
#define HOMEPLUG_AV_KEY_TYPE_NONE	0x05
#define HOMEPLUG_AV_KEY_TYPE_MASK	0x07

static const value_string homeplug_av_key_type_vals[] = {
   { HOMEPLUG_AV_KEY_TYPE_DAK,	"DAK" },
   { HOMEPLUG_AV_KEY_TYPE_NMK,	"NMK" },
   { HOMEPLUG_AV_KEY_TYPE_NEK,	"NEK" },
   { HOMEPLUG_AV_KEY_TYPE_TEK,	"TEK" },
   { HOMEPLUG_AV_KEY_TYPE_HASH,	"Hash Key" },
   { HOMEPLUG_AV_KEY_TYPE_NONE,	"Nonce only (no key)" },
   { 0, NULL }
};

#define HOMEPLUG_AV_REQ_TYPE_MASK	0x01

static const value_string homeplug_av_req_type_vals[] = {
   { 0x00, "Direct" },
   { 0x01, "Relayed" },
   { 0, NULL }
};

#define HOMEPLUG_AV_KEY_RESULT_MASK	0x03

static const value_string homeplug_av_key_result_vals[] = {
   { 0x00, "Key granted" },
   { 0x01, "Request refused" },
   { 0x02, "Unsupported method/key type" },
   { 0, NULL }
};

#define HOMEPLUG_AV_ENET_PHY_SPEED_MASK	0x03

static const value_string homeplug_av_enet_phy_speed_vals[] = {
   { 0x00, "10 Mbits/sec" },
   { 0x01, "100 Mbits/sec" },
   { 0x02, "1 Gbits/sec" },
   { 0, NULL }
};

#define HOMEPLUG_AV_ENET_PHY_DUPLEX_MASK 0x01

static const value_string homeplug_av_enet_phy_duplex_vals[] = {
   { 0x00, "Half" },
   { 0x01, "Full" },
   { 0, NULL }
};

#define HOMEPLUG_AV_ENET_PHY_MCONTROL_MASK	0x01

static const value_string homeplug_av_enet_phy_mcontrol_vals[] = {
   { 0x00, "Read" },
   { 0x01, "Write" },
   { 0, NULL }
};

static const value_string homeplug_av_wr_rd_mem_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "Invalid Address" },
   { 0x14, "Invalid Length" },
   { 0, NULL }
};

static const value_string homeplug_av_mac_module_id_vals[] = {
   { 0x00, "MAC Soft-Loader Image" },
   { 0x01, "MAC Software Image" },
   { 0x02, "PIB" },
   { 0x10, "Write Alternate Flash Location" },
   { 0, NULL }
};

static const value_string homeplug_av_st_mac_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "Invalid Module ID" },
   { 0x14, "Invalid Command" },
   { 0, NULL }
};

static const value_string homeplug_av_get_nvm_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "NVM Not Present" },
   { 0, NULL }
};

static const value_string homeplug_av_rs_dev_status_vals[] = {
   { 0x00, "Success" },
   { 0x01, "NVM Not Present" },
   { 0, NULL }
};

static const value_string homeplug_av_wr_rd_mod_cnf_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "Invalid Module ID" },
   { 0x12, "Invalid Length" },
   { 0x14, "Invalid Checksum" },
   { 0x18, "Bad Header Checksum" },
   { 0x1C, "Invalid Length" },
   { 0x20, "Unexpected Offset" },
   { 0, NULL }
};

static const value_string homeplug_av_wr_mod_ind_status_vals[] = {
   { 0x00, "Successful module update" },
   { 0x10, "Update occured but not successful" },
   { 0, NULL }
};

static const value_string homeplug_av_mod_nvm_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "Invalid Module ID" },
   { 0x14, "NVM Module Not Present" },
   { 0x18, "NVM Too Small" },
   { 0x1C, "Invalid Header Checksum" },
   { 0x20, "Invalid Section Mismatch" },
   { 0, NULL }
};

#define HOMEPLUG_AV_RPT_CLR_MASK		0x01

static const value_string homeplug_av_rpt_clr_vals[] = {
   { 0x00, "Get Report" },
   { 0x01, "Get Report and Clear" },
   { 0, NULL }
};

#define HOMEPLUG_AV_GEN_STATUS_MASK		0x03

static const value_string homeplug_av_generic_status_vals[] = {
   { 0x00, "Success" },
   { 0x01, "Failure" },
   { 0x02, "Not supported" },
   { 0, NULL }
};

#define HOMEPLUG_AV_LNK_STATS_MCTL_MASK		0x01

static const value_string homeplug_av_lnk_stats_mctrl_vals[] = {
   { 0x00, "Read" },
   { 0x01, "Clear" },
   { 0, NULL }
};

#define HOMEPLUG_AV_LNK_STATS_DIR_TX		0x00
#define HOMEPLUG_AV_LNK_STATS_DIR_RX		0x01
#define HOMEPLUG_AV_LNK_STATS_DIR_TX_RX		0x02
#define HOMEPLUG_AV_LNK_STATS_DIR_MASK		0x03

static const value_string homeplug_av_lnk_stats_dir_vals[] = {
   { HOMEPLUG_AV_LNK_STATS_DIR_TX, "Tx" },
   { HOMEPLUG_AV_LNK_STATS_DIR_RX, "Rx" },
   { HOMEPLUG_AV_LNK_STATS_DIR_TX_RX, "Tx/Rx" },
   { 0, NULL }
};

static const value_string homeplug_av_lnk_stats_lid_vals[] = {
   { 0x00, "CSMA Channel Access Priority 0" },
   { 0x01, "CSMA Channel Access Priority 1" },
   { 0x02, "CSMA Channel Access Priority 2" },
   { 0x03, "CSMA Channel Access Priority 3" },
   { 0xF8, "Sum of all CSMA stats for Peer Node" },
   { 0xFB, "Reserved" },
   { 0xFC, "Sum of all CSMA stats" },
   { 0, NULL }
};

#define HOMEPLUG_AV_LNK_STATS_STATUS_SUCCESS	0x00
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_CTRL	0x01
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_DIR	0x02
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_LID	0x10
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_MAC	0x20

static const value_string homeplug_av_lnk_status_vals[] = {
   { HOMEPLUG_AV_LNK_STATS_STATUS_SUCCESS,	"Success" },
   { HOMEPLUG_AV_LNK_STATS_STATUS_INV_CTRL,	"Invalid Control" },
   { HOMEPLUG_AV_LNK_STATS_STATUS_INV_DIR,	"Invalid Direction" },
   { HOMEPLUG_AV_LNK_STATS_STATUS_INV_LID,	"Invalid Link ID" },
   { HOMEPLUG_AV_LNK_STATS_STATUS_INV_MAC,	"Invalid MAC Address" },
   { 0, NULL }
};

#define HOMEPLUG_AV_SNIFFER_CTRL_MASK		0x03

static const value_string homeplug_av_sniffer_ctrl_vals[] = {
   { 0x00, "Disable" },
   { 0x01, "Enable" },
   { 0x02, "No change" },
   { 0, NULL }
};

static const value_string homeplug_av_sniffer_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "Invalid Control" },
   { 0, NULL }
};

static const value_string homeplug_av_sniffer_type_vals[] = {
   { 0x00, "Regular" },
   { 0, NULL }
};

#define HOMEPLUG_AV_LBK_STATUS_MASK		0x01

static const value_string homeplug_av_lbk_status_vals[] = {
   { 0x00, "Done" },
   { 0x01, "Looping frame" },
   { 0, NULL }
};

static const value_string homeplug_av_set_key_peks_vals[] = {
   { 0x00, "Remote" },
   { 0x0F, "Local" },
   { 0, NULL }
};

static const value_string homeplug_av_set_key_status_vals[] = {
   { 0x00, "Success" },
   { 0x10, "Invalid EKS" },
   { 0x11, "Invalid PKS" },
   { 0, NULL }
};

static const value_string homeplug_av_cblock_status_vals[] = {
   { 0x00, "Success" },
   { 0x01, "Failure" },
   { 0x10, "No Flash" },
   { 0x30, "Invalid Checksum" },
   { 0x34, "BIST Failed" },
   { 0, NULL }
};

#define HOMEPLUG_AV_HOST_ACTION_SOFT_LDR	0x00
#define HOMEPLUG_AV_HOST_ACTION_FW_UPG_RDY	0x01
#define HOMEPLUG_AV_HOST_ACTION_PIB_UP_RDY	0x02
#define HOMEPLUG_AV_HOST_ACTION_FW_PIB_UP_RDY	0x03
#define HOMEPLUG_AV_HOST_ACTION_BOOT_LDR	0x04

static const value_string homeplug_av_host_action_vals[] = {
   { HOMEPLUG_AV_HOST_ACTION_SOFT_LDR,		"Loader (Soft/Bootloader)" },
   { HOMEPLUG_AV_HOST_ACTION_FW_UPG_RDY,	"Firmware Upgrade Ready" },
   { HOMEPLUG_AV_HOST_ACTION_PIB_UP_RDY,	"PIB Update Ready" },
   { HOMEPLUG_AV_HOST_ACTION_FW_PIB_UP_RDY,	"Firmware Upgrade and PIB Update Ready" },
   { HOMEPLUG_AV_HOST_ACTION_BOOT_LDR,		"Loader (Bootloader)" },
   { 0, NULL }
};

static const value_string homeplug_av_op_attr_report_vals[] = {
   { 0x00, "Binary" },
   { 0x01, "XML" },
   { 0, NULL }
};

#define HOMEPLUG_AV_TONE_MAP_MASK		0x07

static const value_string homeplug_av_tone_map_vals[] = {
   { 0x00, "No modulation" },
   { 0x01, "BPSK" },
   { 0x02, "QPSK" },
   { 0x03, "8-QAM" },
   { 0x04, "16-QAM" },
   { 0x05, "64-QAM" },
   { 0x06, "256-QAM" },
   { 0x07, "1024-QAM" },
   { 0, NULL }
};

#define HOMEPLUG_AV_TONE_MAP_STATUS_MASK	0x03

static const value_string homeplug_av_tone_map_status_vals[] = {
   { 0x00, "Success" },
   { 0x01, "Uknown MAC address" },
   { 0x02, "Unknown Tone Map slot" },
   { 0, NULL }
};

#define	HOMEPLUG_AV_MAX_CARRIERS	(1156 / 2)

#define TVB_LEN_GREATEST  1
#define TVB_LEN_UNDEF     0
#define TVB_LEN_SHORTEST -1
static int check_tvb_length(ptvcursor_t *cursor, const gint length)
{
  if (!cursor)
    return TVB_LEN_UNDEF;

  if (tvb_reported_length_remaining(ptvcursor_tvbuff(cursor),
				    ptvcursor_current_offset(cursor)) < length)
    return TVB_LEN_SHORTEST;

  return TVB_LEN_GREATEST;
}

static inline unsigned int homeplug_av_mmtype_msb_is_vendor(guint8 msb)
{
 return ((msb & (HOMEPLUG_AV_MMTYPE_MSB_VENDOR << HOMEPLUG_AV_MMTYPE_MSB_SHIFT)) ==
	 (HOMEPLUG_AV_MMTYPE_MSB_VENDOR << HOMEPLUG_AV_MMTYPE_MSB_SHIFT));
}

/* Dissection of MMHDR */
static guint16
dissect_homeplug_av_mmhdr(ptvcursor_t *cursor)
{
  proto_item *ti = NULL;
  proto_tree *ti_mmtype = NULL;
  proto_tree *ti_vendor = NULL;
  proto_tree *ti_public = NULL;
  guint8 lsb, msb;
  guint16 homeplug_av_mmtype;

  ti = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr, 3, FALSE);

  lsb = tvb_get_guint8(ptvcursor_tvbuff(cursor),
	ptvcursor_current_offset(cursor) + 1);
  msb = tvb_get_guint8(ptvcursor_tvbuff(cursor),
	ptvcursor_current_offset(cursor) + 2);

  homeplug_av_mmtype = (msb << 8) | lsb;

  if (!ptvcursor_tree(cursor))
    return homeplug_av_mmtype;

  ptvcursor_push_subtree(cursor, ti, ett_homeplug_av_mmhdr);
  {
     ptvcursor_add(cursor, hf_homeplug_av_mmhdr_mmver, 1, FALSE);
     ti_mmtype = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr_mmtype, 2, TRUE);

     ptvcursor_push_subtree(cursor, ti_mmtype, ett_homeplug_av_mmtype);
     {
	ptvcursor_add(cursor, hf_homeplug_av_mmhdr_mmtype_lsb, 1, FALSE);
	ptvcursor_add(cursor, hf_homeplug_av_mmhdr_mmtype_msb, 1, FALSE);
     }
     ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_pop_subtree(cursor);

  if (homeplug_av_mmtype_msb_is_vendor(msb))
  {
     ti_vendor = ptvcursor_add_no_advance(cursor, hf_homeplug_av_vendor, -1, FALSE);

     ptvcursor_push_subtree(cursor, ti_vendor, ett_homeplug_av_vendor);
     {
	ptvcursor_add(cursor, hf_homeplug_av_vendor_oui, 3, TRUE);
     }
     ptvcursor_pop_subtree(cursor);
  }
  else
  {
     ti_public = ptvcursor_add_no_advance(cursor, hf_homeplug_av_public, -1, FALSE);

     ptvcursor_push_subtree(cursor, ti_public, ett_homeplug_av_public);
     {
	ptvcursor_add_no_advance(cursor, hf_homeplug_av_public_frag_count, 1, FALSE);
	ptvcursor_add(cursor, hf_homeplug_av_public_frag_index, 1, FALSE);
	ptvcursor_add(cursor, hf_homeplug_av_public_frag_seqnum, 1, FALSE);
     }
     ptvcursor_pop_subtree(cursor);
  }

  return homeplug_av_mmtype;
}

/* Beacon body */
static void
dissect_homeplug_av_beacon(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_bcn, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_bcn);
   {
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_del_type, 1, FALSE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_access, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_bcn_bts, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_0, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_1, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_2, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_3, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_fccs_av, 3, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

/* Frame control */
static void
dissect_homeplug_av_frame_control(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_fc);
   {
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_del_type, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_access, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_stei, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_dtei, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_lid, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_cfs, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_bdf, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_hp10df, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_hp11df, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_ppb, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_ble, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_pbsz, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_num_sym, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_tmi_av, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_mpdu_cnt, 2, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_burst_cnt, 2, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_fl_av, 2, TRUE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_clst, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_rg_len, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_mfs_cmd_mgmt, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_mfs_cmd_data, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_fc_rsr, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_mcf, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_dccpcf, 1, FALSE);
     ptvcursor_add_no_advance(cursor, hf_homeplug_av_fc_mnbf, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_fccs_av, 3, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_info_sta(ptvcursor_t *cursor, gboolean vendor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_sta_info, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_info_sta_info);
   {
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_da, 6, FALSE);
      if (vendor) {
	ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_tei, 1, FALSE);
	ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_bda, 6, FALSE);
      }
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_phy_dr_tx, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_phy_dr_rx, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_info_net(ptvcursor_t *cursor, gboolean vendor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_net_info, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_info_net_info);
   {
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_tei, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_role, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_mac, 6, FALSE);
     if (vendor) {
       ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_tei, 1, FALSE);
     }
     else
     {
       ptvcursor_add(cursor, hf_homeplug_av_nw_info_access, 1, FALSE);
       ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_coord, 1, FALSE);
     }
   }
   ptvcursor_pop_subtree(cursor);
}

/* Public MMEs */
static void
dissect_homeplug_av_cc_sta_info(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cc_sta_info, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cc_sta_info);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_mac, 6, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_tei, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_same_net, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_cap, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_sig_level, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_avg_ble, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cc_net_info(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cc_net_info, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cc_net_info);
   {
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_hyb_mode, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_bcn_slots, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_cco_sts, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_bcn_ofs, 2, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cc_disc_list_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 num_stas;
   guint8 sta;
   guint8 num_nets;
   guint8 net;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cc_disc_list_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cc_disc_list_cnf);
   {
      num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
      		ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_cc_disc_list_sta_cnt, 1, FALSE);

      for (sta = 0; sta < num_stas; sta++) {
	dissect_homeplug_av_cc_sta_info(cursor);
      }

      num_nets = tvb_get_guint8(ptvcursor_tvbuff(cursor),
				ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_cc_disc_list_net_cnt, 1, FALSE);

      for (net = 0; net < num_nets; net++) {
	dissect_homeplug_av_cc_net_info(cursor);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_enc_pld_ind(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 pid;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_enc_pld_ind, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_enc_pld_ind);
   {
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_avlns, 1, FALSE);
      pid = tvb_get_guint8(ptvcursor_tvbuff(cursor),
		ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, FALSE);
      if (pid == HOMEPLUG_AV_PID_HLE) {
	ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_iv, 16, TRUE);
      } else {
	ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_uuid, 16, TRUE);
      }
      ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_len, 2, TRUE);

      /* Encrypted payload follows */
      if (pid != HOMEPLUG_AV_PID_HLE) {
	ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_pld, -1, FALSE);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_enc_pld_rsp(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_enc_pld_rsp, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_enc_pld_rsp);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_rsp_result, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_set_key_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_set_key_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_set_key_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_key_type, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_your_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_cap, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cm_set_key_req_nw_key, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_set_key_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_set_key_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_set_key_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cm_set_key_cnf_result, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_your_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_cap, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_get_key_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 key_type;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_get_key_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_get_key_req);
   {

      ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_req_type, 1, FALSE);
      key_type = tvb_get_guint8(ptvcursor_tvbuff(cursor),
				ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_key_type, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, FALSE);
      if (key_type == HOMEPLUG_AV_KEY_TYPE_HASH) {
	ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_req_has_key, -1, FALSE);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_get_key_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_get_key_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_get_key_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_cnf_result, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_cnf_rtype, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_your_nonce, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_cnf_key, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_brg_infos_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 bridging;
   guint8 num_stas;
   guint8 sta;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_brg_infos_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_brg_infos_cnf);
   {
      bridging = tvb_get_guint8(ptvcursor_tvbuff(cursor),
		ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_brd, 1, FALSE);

      if (bridging) {
	ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_btei, 1, FALSE);

	num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
				  ptvcursor_current_offset(cursor));
	ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_num_stas, 1, FALSE);

	for (sta = 0; sta < num_stas; sta++) {
	  ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_mac, 6, FALSE);
	}
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_infos_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 num_avlns;
   guint8 net;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_nw_infos_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_nw_infos_cnf);
   {
      num_avlns = tvb_get_guint8(ptvcursor_tvbuff(cursor),
		ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_avlns, 1, FALSE);

      for (net = 0; net < num_avlns; net++) {
	dissect_homeplug_av_nw_info_net(cursor, FALSE);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_stats_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 num_stas;
   guint8 sta;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_stats_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_stats_cnf);
   {
      num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
		ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_stas, 1, FALSE);

      for (sta = 0; sta < num_stas; sta++) {
	dissect_homeplug_av_nw_info_sta(cursor, FALSE);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

/* Intellon specific vendor MMEs */
static void
dissect_homeplug_av_get_sw_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_get_sw_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_get_sw_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_dev_id, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_ver_len, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_ver_str, 64, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_upg, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wr_mem_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mem_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mem_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, TRUE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wr_mem_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mem_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mem_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mem_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mem_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mem_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mem_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mem_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mem_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mem_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mem_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, TRUE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_st_mac_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_mac_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_mac_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_load, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_len, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_chksum, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_start, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}


static void
dissect_homeplug_av_st_mac_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_mac_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_mac_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_st_mac_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_nvm_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_get_nvm_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_get_nvm_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_type, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_page, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_block, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_size, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rs_dev_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rs_dev_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rs_dev_cnf);
   {
     ptvcursor_add(cursor, hf_homeplug_av_rs_dev_cnf_status, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void dissect_homeplug_av_wr_mod_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mod_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mod_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_checksum, 4, TRUE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void dissect_homeplug_av_wr_mod_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mod_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mod_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_wr_mod_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void dissect_homeplug_av_wr_mod_ind(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mod_ind, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mod_ind);
   {
      ptvcursor_add(cursor, hf_homeplug_av_wr_mod_ind_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mod_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mod_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mod_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mod_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mod_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mod_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_rd_mod_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_mem_checksum, 4, TRUE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mod_nvm_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mod_nvm_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_mod_nvm_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mod_nvm_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mod_nvm_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_mod_nvm_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mod_nvm_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wd_rpt_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wd_rpt_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wd_rpt_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_req_session_id, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_req_clr, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wd_rpt_ind(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wd_rpt_ind, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wd_rpt_ind);
   {
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_session_id, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_num_parts, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_curr_part, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_rdata_len, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_rdata_ofs, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_rdata, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_mcontrol, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_dir, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_lid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_macaddr, 6, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_tx(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_tx, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_tx);
   {
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_mpdu_ack, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_mpdu_col, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_mpdu_fai, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_pbs_pass, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_pbs_fail, 8, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_rx_interval(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rx_inv_stats, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_rx_inv);
   {
      ptvcursor_add(cursor, hf_homeplug_av_rx_inv_phy_rate, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_rx_inv_pbs_pass, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_rx_inv_pbs_fail, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_rx_inv_tb_pass, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_rx_inv_tb_fail, 8, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_rx(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 num_rx_interval;
   guint8 interval;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_rx, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_rx);
   {
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_mpdu_ack, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_mpdu_fai, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_pbs_pass, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_pbs_fail, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_tb_pass, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_tb_fail, 8, TRUE);
      num_rx_interval = tvb_get_guint8(ptvcursor_tvbuff(cursor),
					ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_num_int, 1, FALSE);

      for (interval = 0; interval < num_rx_interval; interval++) {
	dissect_homeplug_av_lnk_stats_rx_interval(cursor);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint8 status;
   guint8 direction;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_cnf);
   {
      status = tvb_get_guint8(ptvcursor_tvbuff(cursor),
					ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_status, 1, FALSE);

      direction = tvb_get_guint8(ptvcursor_tvbuff(cursor),
					ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_dir, 1, FALSE);

      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_lid, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_tei, 1, FALSE);

      ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_cnf_lstats, -1, FALSE);

      if (status == HOMEPLUG_AV_LNK_STATS_STATUS_SUCCESS)
      {
	switch (direction) {
	case HOMEPLUG_AV_LNK_STATS_DIR_TX:
	   dissect_homeplug_av_lnk_stats_tx(cursor);
	   break;
	case HOMEPLUG_AV_LNK_STATS_DIR_RX:
	   dissect_homeplug_av_lnk_stats_rx(cursor);
	   break;
	case HOMEPLUG_AV_LNK_STATS_DIR_TX_RX:
	   dissect_homeplug_av_lnk_stats_tx(cursor);
	   dissect_homeplug_av_lnk_stats_rx(cursor);
	   break;
	}
     }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_sniffer_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sniffer_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_sniffer_req_ctrl, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_sniffer_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sniffer_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_sniffer_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_sniffer_cnf_state, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_sniffer_cnf_da, 6, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_sniffer_ind(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   proto_item * it_data = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_ind, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sniffer_ind);
   {
      ptvcursor_add(cursor, hf_homeplug_av_sniffer_ind_type, 1, FALSE);

      it_data = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_ind_data, -1, FALSE);

      ptvcursor_push_subtree(cursor, it_data, ett_homeplug_av_sniffer_ind_data);
      {
	ptvcursor_add(cursor, hf_homeplug_av_sniffer_data_dir, 1, FALSE);
	ptvcursor_add(cursor, hf_homeplug_av_sniffer_data_systime, 8, TRUE);
	ptvcursor_add(cursor, hf_homeplug_av_sniffer_data_bc_time, 4, TRUE);
	dissect_homeplug_av_frame_control(cursor);
	 dissect_homeplug_av_beacon(cursor);
      }
      ptvcursor_pop_subtree(cursor);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_info_cnf(ptvcursor_t *cursor)
{
    proto_item * it = NULL;
    guint8 num_avlns;
    guint8 num_stas;
    guint8 sta;

    if (!ptvcursor_tree(cursor))
      return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_cnf, -1, FALSE);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_info_cnf);
    {
       num_avlns = tvb_get_guint8(ptvcursor_tvbuff(cursor),
					ptvcursor_current_offset(cursor));
       ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_avlns, 1, FALSE);

       if (num_avlns) {
	   dissect_homeplug_av_nw_info_net(cursor, TRUE);
	   num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
					    ptvcursor_current_offset(cursor));
	   ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_stas, 1, FALSE);

	   for (sta = 0; sta < num_stas; sta++) {
	      dissect_homeplug_av_nw_info_sta(cursor, TRUE);
	   }
	   }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cp_rpt_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cp_rpt_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cp_rpt_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_req_session_id, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_req_clr, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cp_rpt_ind(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cp_rpt_ind, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cp_rpt_ind);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_status, 1, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_major_ver, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_minor_ver, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 14, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_session_id, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_total_size, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_blk_offset, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_byte_index, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_num_parts, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_curr_part, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_data_len, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_data_ofs, 1, TRUE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_cp_rpt_ind_data, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_fr_lbk_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_fr_lbk_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_fr_lbk_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_duration, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_len, 2, FALSE);
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_fr_lbk_req_data, -1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_fr_lbk_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_fr_lbk_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_fr_lbk_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_duration, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_len, 2, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lbk_stat_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lbk_stat_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lbk_stat_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_lbk_stat_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_lbk_stat_cnf_lbk_stat, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_key_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_key_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_key_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_set_key_req_eks, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_set_key_req_nmk, 16, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_set_key_req_rda, 6, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_set_key_req_dak, 16, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_key_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_key_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_key_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_set_key_cnf_status, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mfg_string_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mfg_string_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_mfg_string_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_mfg_string_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mfg_string_cnf_len, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_mfg_string_cnf_string, 64, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cblock_hdr(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cblock_hdr, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cblock_hdr);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_ver, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_img_rom_addr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_img_addr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_img_len, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_img_chksum, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_entry_point, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 12, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_next_hdr, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_chksum, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cblock(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cblock, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cblock);
   {
      ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_size, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_conf, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_tim0, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_tim1, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_cntrl, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_refresh, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_cblock_mac_clock, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_cblock_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_cblock_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_cblock_cnf);
   {
     ptvcursor_add(cursor, hf_homeplug_av_rd_cblock_cnf_status, 1, FALSE);
     ptvcursor_add(cursor, hf_homeplug_av_rd_cblock_cnf_len, 1, FALSE);
     dissect_homeplug_av_cblock_hdr(cursor);
     dissect_homeplug_av_cblock(cursor);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_sdram_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_sdram_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_sdram_req);
   {
      dissect_homeplug_av_cblock(cursor);
      ptvcursor_add(cursor, hf_homeplug_av_set_sdram_req_chksum, 4, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_sdram_cnf(ptvcursor_t *cursor)
{
    proto_item * it = NULL;

    if (!ptvcursor_tree(cursor))
      return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_sdram_cnf, -1, FALSE);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_sdram_cnf);
    {
       ptvcursor_add(cursor, hf_homeplug_av_set_sdram_cnf_status, 1, FALSE);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_host_action_ind(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_host_action_ind, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_host_action_ind);
   {
      ptvcursor_add(cursor, hf_homeplug_av_host_action_ind_act, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_host_action_rsp(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_host_action_rsp, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_host_action_rsp);
   {
      ptvcursor_add(cursor, hf_homeplug_av_host_action_rsp_sts, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_op_attr_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_op_attr_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_cookie, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_rep_type, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_op_attr_bin_report(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_cnf_data, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_op_attr_data);
   {
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_hw, 16, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw, 16, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_major, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_minor, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_sub, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_num, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 8, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_date, 8, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_rel, 12, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_op_attr_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_op_attr_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_cnf_status, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_cookie, 4, TRUE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_rep_type, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_op_attr_cnf_size, 2, TRUE);
      dissect_homeplug_av_op_attr_bin_report(cursor);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_enet_phy_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_enet_phy_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_enet_phy_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_enet_phy_req_mcontrol, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_enet_phy_req_addcaps, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, TRUE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_enet_phy_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
      return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_enet_phy_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_enet_phy_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_enet_phy_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_enet_phy_cnf_speed, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_enet_phy_cnf_duplex, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_req(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_req, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_req);
   {
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_req_mac, 6, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_req_slot, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_carrier(ptvcursor_t *cursor)
{
   proto_item * it = NULL;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_carrier, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_carrier);
   {
      ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_carrier_lo, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_carrier_hi, 1, FALSE);
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_cnf(ptvcursor_t *cursor)
{
   proto_item * it = NULL;
   guint16 i;

   if (!ptvcursor_tree(cursor))
     return;

   it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_cnf, -1, FALSE);

   ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_cnf);
   {
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_cnf_status, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_cnf_slot, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_cnf_num_tms, 1, FALSE);
      ptvcursor_add(cursor, hf_homeplug_av_tone_map_cnf_num_act, 2, TRUE);

      for (i = 0; i < HOMEPLUG_AV_MAX_CARRIERS; i++) {
	dissect_homeplug_av_tone_map_carrier(cursor);
      }
   }
   ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mme(ptvcursor_t *cursor, guint16 homeplug_av_mmtype)
{

  switch (homeplug_av_mmtype) {
  /* Public MMEs */
  case HOMEPLUG_AV_MMTYPE_CC_DISC_LIST_CNF:
     dissect_homeplug_av_cc_disc_list_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_ENC_PLD_IND:
     dissect_homeplug_av_cm_enc_pld_ind(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_ENC_PLD_RSP:
     dissect_homeplug_av_cm_enc_pld_rsp(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_SET_KEY_REQ:
     dissect_homeplug_av_cm_set_key_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_SET_KEY_CNF:
     dissect_homeplug_av_cm_set_key_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_GET_KEY_REQ:
     dissect_homeplug_av_cm_get_key_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_GET_KEY_CNF:
     dissect_homeplug_av_cm_get_key_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_BRG_INFO_CNF:
     dissect_homeplug_av_get_brg_infos_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_NW_INFO_CNF:
     dissect_homeplug_av_nw_infos_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CM_NW_STATS_CNF:
     dissect_homeplug_av_nw_stats_cnf(cursor);
     break;

  /* Intellon Vendor-specific MMEs */
  case HOMEPLUG_AV_MMTYPE_GET_SW_CNF:
     dissect_homeplug_av_get_sw_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WR_MEM_REQ:
     dissect_homeplug_av_wr_mem_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WR_MEM_CNF:
     dissect_homeplug_av_wr_mem_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_RD_MEM_REQ:
     dissect_homeplug_av_rd_mem_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_RD_MEM_CNF:
     dissect_homeplug_av_rd_mem_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_ST_MAC_REQ:
     dissect_homeplug_av_st_mac_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_ST_MAC_CNF:
     dissect_homeplug_av_st_mac_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_GET_NVM_CNF:
     dissect_homeplug_av_get_nvm_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_RS_DEV_CNF:
     dissect_homeplug_av_rs_dev_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WR_MOD_REQ:
     dissect_homeplug_av_wr_mod_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WR_MOD_CNF:
     dissect_homeplug_av_wr_mod_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WR_MOD_IND:
     dissect_homeplug_av_wr_mod_ind(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_RD_MOD_REQ:
     dissect_homeplug_av_rd_mod_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_RD_MOD_CNF:
     dissect_homeplug_av_rd_mod_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_NVM_MOD_REQ:
     dissect_homeplug_av_mod_nvm_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_NVM_MOD_CNF:
     dissect_homeplug_av_mod_nvm_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WD_RPT_REQ:
     dissect_homeplug_av_wd_rpt_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_WD_RPT_IND:
     dissect_homeplug_av_wd_rpt_ind(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_LNK_STATS_REQ:
     dissect_homeplug_av_lnk_stats_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_LNK_STATS_CNF:
     dissect_homeplug_av_lnk_stats_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SNIFFER_REQ:
     dissect_homeplug_av_sniffer_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SNIFFER_CNF:
     dissect_homeplug_av_sniffer_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SNIFFER_IND:
     dissect_homeplug_av_sniffer_ind(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_NW_INFO_CNF:
     dissect_homeplug_av_nw_info_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CP_RPT_REQ:
     dissect_homeplug_av_cp_rpt_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_CP_RPT_IND:
     dissect_homeplug_av_cp_rpt_ind(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_FR_LBK_REQ:
     dissect_homeplug_av_fr_lbk_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_FR_LBK_CNF:
     dissect_homeplug_av_fr_lbk_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_LBK_STAT_CNF:
     dissect_homeplug_av_lbk_stat_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SET_KEY_REQ:
     dissect_homeplug_av_set_key_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SET_KEY_CNF:
     dissect_homeplug_av_set_key_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_MFG_STRING_CNF:
     dissect_homeplug_av_mfg_string_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_RD_CBLOCK_CNF:
     dissect_homeplug_av_rd_cblock_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SET_SDRAM_REQ:
     dissect_homeplug_av_set_sdram_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_SET_SDRAM_CNF:
     dissect_homeplug_av_set_sdram_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_HOST_ACTION_IND:
     dissect_homeplug_av_host_action_ind(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_HOST_ACTION_RSP:
     dissect_homeplug_av_host_action_rsp(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_OP_ATTR_REQ:
     dissect_homeplug_av_op_attr_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_OP_ATTR_CNF:
     dissect_homeplug_av_op_attr_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_GET_ENET_PHY_REQ:
     dissect_homeplug_av_get_enet_phy_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_GET_ENET_PHY_CNF:
     dissect_homeplug_av_get_enet_phy_cnf(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_TONE_MAP_REQ:
     dissect_homeplug_av_tone_map_req(cursor);
     break;
  case HOMEPLUG_AV_MMTYPE_TONE_MAP_CNF:
     dissect_homeplug_av_tone_map_cnf(cursor);
     break;
  default:
     break;
  }

  return;
}

static void
dissect_homeplug_av(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *ti = NULL;
  proto_tree *homeplug_av_tree = NULL;
  ptvcursor_t *cursor = NULL;
  guint16 homeplug_av_mmtype;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HomePlug AV");
  col_set_str(pinfo->cinfo, COL_INFO, "MAC Management");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_homeplug_av, tvb, 0, -1, FALSE);
    homeplug_av_tree = proto_item_add_subtree(ti, ett_homeplug_av);
  }

  cursor = ptvcursor_new(homeplug_av_tree, tvb, 0);

  /* Check if we have enough data to process a complete frame */
  if (check_tvb_length(cursor, HOMEPLUG_AV_MIN_FRAME_SIZE) != TVB_LEN_SHORTEST &&
      /* Check if we have enough data to process the header */
      check_tvb_length(cursor, HOMEPLUG_AV_MMHDR_LEN) != TVB_LEN_SHORTEST) {

      homeplug_av_mmtype = dissect_homeplug_av_mmhdr(cursor);

      if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
	  val_to_str(homeplug_av_mmtype, homeplug_av_mmtype_vals, "Unknown 0x%x"));
      }

      dissect_homeplug_av_mme(cursor, homeplug_av_mmtype);
  }

  ptvcursor_free(cursor);
}


void
proto_reg_handoff_homeplug_av(void)
{
  dissector_handle_t homeplug_av_handle;

  homeplug_av_handle = create_dissector_handle(dissect_homeplug_av, proto_homeplug_av);
  dissector_add_uint("ethertype", ETHERTYPE_HOMEPLUG_AV, homeplug_av_handle);
}

void
proto_register_homeplug_av(void)
{
   static hf_register_info hf[] = {
	{ &hf_homeplug_av_reserved,
	  { "Reserved", "homeplug_av.reserved",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* MM Header */
	{ &hf_homeplug_av_mmhdr,
	  { "MAC Management Header", "homeplug_av.mmhdr",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mmhdr_mmver,
	  { "Version", "homeplug_av.mmhdr.mmver",
	  FT_UINT8, BASE_DEC, VALS(homeplug_av_mmver_vals), HOMEPLUG_AV_MMVER_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_mmhdr_mmtype,
	  { "Type", "homeplug_av.mmhdr.mmtype",
	  FT_UINT16, BASE_HEX, VALS(homeplug_av_mmtype_vals), 0x0000, NULL, HFILL }
	},
	{ &hf_homeplug_av_mmhdr_mmtype_lsb,
	  { "LSB", "homeplug_av.mmhdr.mmtype.lsb",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_mmtype_lsb_vals), HOMEPLUG_AV_MMTYPE_LSB_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_mmhdr_mmtype_msb,
	  { "MSB", "homeplug_av.mmhdr.mmtype.msb",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_mmtype_msb_vals), HOMEPLUG_AV_MMTYPE_MSB_MASK, "Reserved", HFILL },
	},
	/* Public MME */
	{ &hf_homeplug_av_public,
	  { "Public MME", "homeplug_av.public",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_public_frag_count,
	  { "Fragment count", "homeplug_av.public.frag_count",
	  FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_PUBLIC_FRAG_COUNT_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_public_frag_index,
	  { "Fragment index", "homeplug_av.public.frag_index",
	  FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_PUBLIC_FRAG_INDEX_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_public_frag_seqnum,
	  { "Fragment Sequence number", "homeplug_av.public.frag_seqnum",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Frame Control */
	{ &hf_homeplug_av_fc,
	  { "Frame control", "homeplug_av.fc",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_stei,
	  { "Source Terminal Equipment Identifier", "homeplug_av.fc.snei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_dtei,
	  { "Destination Terminal Equipment Identifier", "homeplug_av.fc.dtei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_lid,
	  { "Link ID", "homeplug_av.fc.lid",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_cfs,
	  { "Contention free session", "homeplug_av.fc.cfs",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x01, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_bdf,
	  { "Beacon detect flag", "homeplug_av.fc.bdf",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x02, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_hp10df,
	  { "Homeplug AV version 1.0", "homeplug_av.fc.hp10df",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x04, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_hp11df,
	  { "Homeplug AV version 1.1", "homeplug_av.fc.hp11df",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x08, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_ppb,
	  { "Pending PHY blocks", "homeplug_av.fc.ppb",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_ble,
	  { "Bit loading estimate", "homeplug_av.fc.ble",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_pbsz,
	  { "PHY block size", "homeplug_av.fc.pbsz",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x01, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_num_sym,
	  { "Number of symbols", "homeplug_av.fc.num_sym",
	  FT_UINT8, BASE_DEC, NULL, 0x06, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_tmi_av,
	  { "Tonemap index", "homeplug_av.fc.tmi_av",
	  FT_UINT8, BASE_DEC, NULL, 0xF8, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_fl_av,
	  { "Frame length", "homeplug_av.fc.fl_av",
	  FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_mpdu_cnt,
	  { "MPDU count", "homeplug_av.fc.mpdu_cnt",
	  FT_UINT8, BASE_DEC, NULL, 0x3000, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_burst_cnt,
	  { "Burst count", "homeplug_av.fc.burst_cnt",
	  FT_UINT8, BASE_DEC, NULL, 0xC000, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_clst,
	  { "Convergence layer SAP type", "homeplug_av.fc.clst",
	  FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_rg_len,
	  { "Reverse grant length", "homeplug_av.fc.rg_len",
	  FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_mfs_cmd_mgmt,
	  { "Management MAC frame stream command", "homeplug_av.fc.mfs_cmd_mgmt",
	  FT_UINT8, BASE_DEC, NULL, 0x0E, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_mfs_cmd_data,
	  { "Data MAC frame stream command", "homeplug_av.fc.mfs_data_mgmt",
	  FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_rsr,
	  { "Request SACK transmission", "homeplug_av.fc.rsr",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x80, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_mcf,
	  { "Multicast", "homeplug_av.fc.mcf",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x01, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_dccpcf,
	  { "Different CP PHY clock", "homeplug_av.fc.dccpcf",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x02, NULL, HFILL }
	},
	{ &hf_homeplug_av_fc_mnbf,
	  { "Multinetwork broadcast", "homeplug_av.fc.mnbf",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x04, NULL, HFILL }
	},
	/* Beacon body */
	{ &hf_homeplug_av_bcn,
	  { "Beacon", "homeplug_av.bcn",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_bcn_bts,
	  { "Beacon timestamp", "homeplug_av.bcn.bts",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_bcn_bto_0,
	  { "Beacon transmission offset 0", "homeplug_av.bcn.bto_0",
	  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_bcn_bto_1,
	  { "Beacon transmission offset 1", "homeplug_av.bcn.bto_1",
	  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_bcn_bto_2,
	  { "Beacon transmission offset 2", "homeplug_av.bcn.bto_2",
	  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_bcn_bto_3,
	  { "Beacon transmission offset 3", "homeplug_av.bcn.bto_3",
	  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Central Coordination Discovery List Confirmation */
	{ &hf_homeplug_av_cc_disc_list_cnf,
	  { "Central Coordination Discovery List Confirmation", "homeplug_av.cc_disc_list_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Station informations */
	{ &hf_homeplug_av_cc_disc_list_sta_cnt,
	  { "Station count", "homeplug_av.cc_disc_list_cnf.sta_cnt",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_sta_info,
	  { "Station information", "homeplug_av.cc_disc_list_cnf.sta_info",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_sta_info_mac,
	  { "MAC address", "homeplug_av.cc_disc_list_cnf.sta_info.mac",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_sta_info_tei,
	  { "Terminal Equipment Identifier", "homeplug_av.cc_disc_list_cnf.sta_info.tei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_sta_info_same_net,
	  { "Network type", "homeplug_av.cc_disc_list_cnf.sta_info.same_net",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_cc_sta_net_type_vals), HOMEPLUG_AV_CC_STA_NET_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_sta_info_sig_level,
	  { "Signal level", "homeplug_av.cc_disc_list_cnf.sta_info.sig_level",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_sig_level_vals), 0x00, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_cc_sta_info_avg_ble,
	  { "Average BLE", "homeplug_av.cc_disc_list_cnf.sta_info.avg_ble",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Network infos */
	{ &hf_homeplug_av_cc_disc_list_net_cnt,
	  { "Network count", "homeplug_av.cc_disc_list_cnf.net_cnt",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_net_info,
	  { "Network information", "homeplug_av.cc_disc_list_cnf.net_info",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_net_info_hyb_mode,
	  { "Hybrid mode", "homeplug_av.cc_disc_list_cnf.net_info.hyb_mode",
	  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cc_net_info_bcn_slots,
	  { "Beacon slots", "homeplug_av.cc_disc_list_cnf.net_info.bcn_slots",
	  FT_UINT8, BASE_DEC, NULL, 0x08, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_cc_net_info_cco_sts,
	  { "Coordinating status", "homeplug_av.cc_disc_list_cnf.net_info.cco_status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_cco_status_vals), HOMEPLUG_AV_CCO_STATUS_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_cc_net_info_bcn_ofs,
	  { "Beacon offset", "homeplug_av.cc_disc_list_cnf.net_info.bcn_ofs",
	  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Shared encrypted related fields */
	{ &hf_homeplug_av_nw_info_del_type,
	  { "Delimiter type", "homeplug_av.nw_info.del_type",
	  FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_fccs_av,
	  { "Frame control check sequence", "homeplug_av.nw_info.fccs_av",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_peks,
	  { "Payload Encryption Key Select", "homeplug_av.nw_info.peks",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_peks_vals), HOMEPLUG_AV_PEKS_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_pid,
	  { "Protocol ID", "homeplug_av.nw_info.pid",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_pid_vals), HOMEPLUG_AV_PID_MASK, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_nw_info_prn,
	  { "Protocol run number", "homeplug_av.nw_info.prn",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_pmn,
	  { "Protocol message number", "homeplug_av.nw_info.pmn",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_my_nonce,
	  { "My nonce", "homeplug_av.nw_info.my_nonce",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_your_nonce,
	  { "Your nonce", "homeplug_av.nw_info.your_nonce",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_cco_cap,
	  { "CCo capabilities", "homeplug_av.nw_info.cco_cap",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_nw_info_role_vals), HOMEPLUG_AV_NW_INFO_ROLE_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_key_type,
	  { "Key type", "homeplug_av.nw_info.key_type",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_key_type_vals), HOMEPLUG_AV_KEY_TYPE_MASK, NULL, HFILL }
	},
	/* Encrypted Payload Indicate */
	{ &hf_homeplug_av_cm_enc_pld_ind,
	  { "Encrypted Payload Indicate", "homeplug_av.cm_enc_pld_ind",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_enc_pld_ind_avlns,
	  { "AVLN status", "homeplug_av.cm_enc_pld_ind.avlns",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_avln_status_vals), HOMEPLUG_AV_AVLN_STATUS_MASK, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_cm_enc_pld_ind_iv,
	  { "Initialization vector", "homeplug_av.cm_enc_pld_ind.iv",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_enc_pld_ind_uuid,
	  { "UUID", "homeplug_av.cm_enc_pld_ind.uuid",
	  FT_GUID, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_enc_pld_ind_len,
	  { "Length", "homeplug_av.cm_enc_pld_ind.len",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_enc_pld_ind_pld,
	  { "Encrypted payload", "homeplug_av.cm_enc_pld_ind.pld",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Encrypted Payload Response */
	{ &hf_homeplug_av_cm_enc_pld_rsp,
	  { "Encrypted Payload Response", "homeplug_av.cm_enc_pld_rsp",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_enc_pld_rsp_result,
	  { "Result", "homeplug_av.cm_enc_pld_rsp.result",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, NULL, HFILL }
	},
	/* Set Key Request */
	{ &hf_homeplug_av_cm_set_key_req,
	  { "Set Key Request", "homeplug_av.cm_set_key_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_set_key_req_nw_key,
	  { "New Key", "homeplug_av.cm_set_key_req.nw_key",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Set Key Confirmation */
	{ &hf_homeplug_av_cm_set_key_cnf,
	  { "Set Key Confirmation", "homeplug_av.cm_set_key_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_set_key_cnf_result,
	  { "Result", "homeplug_av.cm_set_key_cnf.result",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, NULL, HFILL }
	},
	/* Get Key Request */
	{ &hf_homeplug_av_cm_get_key_req,
	  { "Get Key request", "homeplug_av.cm_get_key_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_get_key_req_type,
	  { "Request type", "homeplug_av.cm_get_key_req.type",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_req_type_vals), HOMEPLUG_AV_REQ_TYPE_MASK, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_cm_get_key_req_has_key,
	  { "Hash key", "homeplug_av.cm_get_key_req.hash_key",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Get Key Confirmation */
	{ &hf_homeplug_av_cm_get_key_cnf,
	  { "Get Key Confirmation", "homeplug_av.cm_get_key_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_get_key_cnf_result,
	  { "Result", "homeplug_av.cm_get_key_cnf.result",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_key_result_vals), HOMEPLUG_AV_KEY_RESULT_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_get_key_cnf_rtype,
	  { "Requested key type", "homeplug_av.cm_get_key_cnf.rtype",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_key_type_vals), HOMEPLUG_AV_KEY_TYPE_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_cm_get_key_cnf_key,
	  { "Encryption/Hash key", "homeplug_av.cm_get_key_cnf.key",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Get Bridge Informations Confirmation */
	{ &hf_homeplug_av_brg_infos_cnf,
	  { "Get Bridge Informations Confirmation", "homeplug_av.brg_infos_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_brg_infos_cnf_brd,
	  { "Bridging", "homeplug_av.brg_infos_cnf.brd",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_brg_infos_cnf_btei,
	  { "Bridge Terminal Equipement Identifier", "homeplug_av.brg_infos_cnf.btei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_brg_infos_cnf_num_stas,
	  { "Number of stations", "homeplug_av.brg_infos_cnf.num_stas",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_brg_infos_cnf_mac,
	  { "Bridged Destination Address", "homeplug_av.brg_infos_cnf.mac",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Get Network Informations Confirmation */
	{ &hf_homeplug_av_cm_nw_infos_cnf,
	  { "Get Network Informations Confirmation", "homeplug_av.nw_infos_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Get Network Statistics Confirmation */
	{ &hf_homeplug_av_nw_stats_cnf,
	  { "Get Network Statistics Confirmation", "homeplug_av.nw_stats_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Vendor Specific */
	{ &hf_homeplug_av_vendor,
	  { "Vendor MME", "homeplug_av.vendor",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_vendor_oui,
	  { "OUI", "homeplug_av.vendor.oui",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Get Device/SW Version */
	{ &hf_homeplug_av_get_sw_cnf,
	  { "Get Device/SW Version", "homeplug_av.get_sw_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_get_sw_cnf_status,
	  { "Status", "homeplug_av.get_sw_cnf.status",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_get_sw_cnf_dev_id,
	  { "Device ID", "homeplug_av.get_sw_cnf.dev_id",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_get_sw_cnf_ver_len,
	  { "Version length", "homeplug_av.get_sw_cnf.ver_len",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_get_sw_cnf_ver_str,
	  { "Version", "homeplug_av.get_sw_cnf.ver_str",
	  FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_get_sw_cnf_upg,
	  { "Upgradable", "homeplug_av.get_sw_cnf.upg",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Write MAC Memory Request */
	{ &hf_homeplug_av_wr_mem_req,
	  { "Write MAC Memory Request", "homeplug_av.wr_mem_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mem_addr,
	  { "Address", "homeplug_av.mem.addr",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mem_len_32bits,
	  { "Length", "homeplug_av.mem.len_32bits",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Write MAC Memory Confirmation */
	{ &hf_homeplug_av_wr_mem_cnf,
	  { "Write MAC Memory Confirmation", "homeplug_av.wr_mem_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Read MAC Memory Request */
	{ &hf_homeplug_av_rd_mem_req,
	  { "Read MAC Memory Request", "homeplug_av.rd_mem_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rd_mem_cnf,
	  { "Read MAC Memory Confirmation", "homeplug_av.rd_mem_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Start MAC Request */
	{ &hf_homeplug_av_st_mac_req,
	  { "Start MAC Request", "homeplug_av.st_mac_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_st_mac_req_img_load,
	  { "Image Load Starting Addres", "homeplug_av.st_mac_req.img_load",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_st_mac_req_img_len,
	  { "Image Length", "homeplug_av.st_mac_req.img_len",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_st_mac_req_img_chksum,
	  { "Image Checksum", "homeplug_av.st_mac_req.img_chksum",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_st_mac_req_img_start,
	  { "Image Starting Address", "homeplug_av.st_mac_req.img_start",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	/* Start MAC Confirmation */
	{ &hf_homeplug_av_st_mac_cnf,
	  { "Start MAC Confirmation", "homeplug_av.st_mac_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_st_mac_cnf_status,
	  { "Module ID", "homeplug_av.st_mac_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_st_mac_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Get NVM Parameters Confirmation */
	{ &hf_homeplug_av_get_nvm_cnf,
	  { "Get NVM Parameters Confirmation", "homeplug_av.get_nvm_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_get_nvm_cnf_status,
	  { "Status", "homeplug_av.get_nvm_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_get_nvm_status_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_get_nvm_cnf_nvm_type,
	  { "NVM Type", "homeplug_av.get_nvm_cnf.nvm_type",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_get_nvm_cnf_nvm_page,
	  { "NVM Page Size", "homeplug_av.get_nvm_cnf.nvm_page",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_get_nvm_cnf_nvm_block,
	  { "NVM Block Size", "homeplug_av.get_nvm_cnf.nvm_block",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_get_nvm_cnf_nvm_size,
	  { "NVM Memory Size", "homeplug_av.get_nvm_cnf.nvm_size",
	  FT_UINT32, BASE_HEX, NULL, 0x00, "Unknown", HFILL }
	},
	/* Reset Device Confirmation */
	{ &hf_homeplug_av_rs_dev_cnf,
	  { "Reset Device Confirmation", "homeplug_av.rs_dev_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rs_dev_cnf_status,
	  { "Status", "homeplug_av.rs_dev_cnf.status",
	  FT_UINT8, BASE_NONE, VALS(homeplug_av_rs_dev_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Shared memory related fields */
	{ &hf_homeplug_av_mem_len_16bits,
	  { "Length", "homeplug_av.mem.len_16bits",
	  FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mem_offset,
	  { "Offset", "homeplug_av.mem.offset",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mem_checksum,
	  { "Checksum", "homeplug_av.mem.checksum",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mem_data,
	  { "Data", "homeplug_av.mem.data",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mem_status,
	  { "Status", "homeplug_av.mem.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_wr_rd_mem_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Write Module Data Request */
	{ &hf_homeplug_av_wr_mod_req,
	  { "Write Module Data Request", "homeplug_av.wr_mod_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Write Module Data Confirmation */
	{ &hf_homeplug_av_wr_mod_cnf,
	  { "Write Module Data Confirmation", "homeplug_av.wr_mod_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wr_mod_cnf_status,
	  { "Status", "homeplug_av.wr_mod_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_wr_rd_mod_cnf_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Write Module Data Indicate */
	{ &hf_homeplug_av_wr_mod_ind,
	  { "Write Module Data Indicate", "homeplug_av.wr_mod_ind",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wr_mod_ind_status,
	  { "Status", "homeplug_av.wr_mod_ind.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_wr_mod_ind_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Read Module Data Request */
	{ &hf_homeplug_av_rd_mod_req,
	  { "Read Module Data Request", "homeplug_av.rd_mod_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Read Module Data Confirmation */
	{ &hf_homeplug_av_rd_mod_cnf,
	  { "Read Module Data Confirmation", "homeplug_av.rd_mod_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rd_mod_cnf_status,
	  { "Status", "homeplug_av.rd_mod_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_wr_rd_mod_cnf_status_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_mac_module_id,
	  { "Module ID", "homeplug_av.module_id",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_mac_module_id_vals), 0x00, "Unknown", HFILL }
	},
	/* Write Module Data to NVM Request */
	{ &hf_homeplug_av_mod_nvm_req,
	  { "Write Module Data to NVM Request", "homeplug_av.mod_nvm_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Write Module Data to NVM Confirmation */
	{ &hf_homeplug_av_mod_nvm_cnf,
	  { "Write Module Data to NVM Confirmation", "homeplug_av.mod_nvm_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mod_nvm_cnf_status,
	  { "Status", "homeplug_av.mod_nvm_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_mod_nvm_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Get Watchdog Report Request */
	{ &hf_homeplug_av_wd_rpt_req,
	  { "Get Watchdog Report Request", "homeplug_av.wd_rpt_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_req_session_id,
	  { "Session ID", "homeplug_av.wd_rpt_req.session_id",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_req_clr,
	  { "Clear flag", "homeplug_av.wd_rpt_req.clr",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_rpt_clr_vals), HOMEPLUG_AV_RPT_CLR_MASK, "Unknown", HFILL }
	},
	/* Get Watchdog Report Indicate */
	{ &hf_homeplug_av_wd_rpt_ind,
	  { "Get Watchdog Report Indicate", "homeplug_av.wd_rpt_ind",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_ind_status,
	  { "Status", "homeplug_av.wd_rpt_ind.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_ind_session_id,
	  { "Session ID", "homeplug_av.wd_rpt_ind.session_id",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_ind_num_parts,
	  { "Number of parts", "homeplug_av.wd_rpt_ind.num_parts",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
 	{ &hf_homeplug_av_wd_rpt_ind_curr_part,
	  { "Current Part", "homeplug_av.wd_rpt_ind.curr_part",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_ind_rdata_len,
	  { "Report Data Length", "homeplug_av.wd_rpt_ind.rdata_len",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_ind_rdata_ofs,
	  { "Report Data Offset", "homeplug_av.wd_rpt_ind.rdata_offset",
	  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_wd_rpt_ind_rdata,
	  { "Report Data", "homeplug_av.wd_rpt_ind.rdata",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Link Statistics Request */
	{ &hf_homeplug_av_lnk_stats_req,
	  { "Link Statistics Request", "homeplug_av.lnk_stats_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_req_mcontrol,
	  { "Control", "homeplug_av.lnk_stats_req.mcontrol",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_stats_mctrl_vals), HOMEPLUG_AV_LNK_STATS_MCTL_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_req_dir,
	  { "Direction", "homeplug_av.lnk_stats_req.dir",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_stats_dir_vals), HOMEPLUG_AV_LNK_STATS_DIR_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_req_lid,
	  { "Link ID", "homeplug_av.lnk_stats_req.lid",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_stats_lid_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_req_macaddr,
	  { "Peer Node", "homeplug_av.lnk_stats_req.macaddr",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Link Statistics Confirmation */
	{ &hf_homeplug_av_lnk_stats_cnf,
	  { "Link Statistics Confirmation", "homeplug_av.lnk_stats_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_cnf_status,
	  { "Status", "homeplug_av.lnk_stats_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_status_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_cnf_dir,
	  { "Direction", "homeplug_av.lnk_stats_cnf.dir",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_stats_dir_vals), HOMEPLUG_AV_LNK_STATS_DIR_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_cnf_lid,
	  { "Link ID", "homeplug_av.lnk_stats_cnf.lid",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_stats_lid_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_cnf_tei,
	  { "TEI", "homeplug_av.lnk_stats_cnf.tei",
	  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_cnf_lstats,
	  { "Link statistics", "homeplug_av.lnk_stats_cnf.lstats",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Link statistics members */
	{ &hf_homeplug_av_lnk_stats_tx,
	  { "Tx link statistics", "homeplug_av.lnk_stats.tx",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_tx_mpdu_ack,
	  { "Number of MPDUs Transmitted and Acknowledged", "homeplug_av.lnk_stats.tx.mpdu_ack",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_tx_mpdu_col,
	  { "Number of MPDUs Transmitted and Collided", "homeplug_av.lnk_stats.tx.mpdu_col",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_tx_mpdu_fai,
	  { "Number of MPDUs Transmitted and Failed", "homeplug_av.lnk_stats.tx.mpdu_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_tx_pbs_pass,
	  { "Number of PB Transmitted Successfully", "homeplug_av.lnk_stats.tx.pbs_pass",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_tx_pbs_fail,
	  { "Number of PB Transmitted Unsuccessfully", "homeplug_av.lnk_stats.tx.pbs_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx,
	  { "Rx link statistics", "homeplug_av.lnk_stats.rx",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_mpdu_ack,
	  { "Number of MPDUs Received and Acknowledged", "homeplug_av.lnk_stats.rx.mdpu_ack",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_mpdu_fai,
	  { "Number of MPDUs Received and Failed", "homeplug_av.lnk_stats.rx.mdpu_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_pbs_pass,
	  { "Number of PB Received Successfully", "homeplug_av.lnk_stats.rx.pbs_pass",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_pbs_fail,
	  { "Number of PB Received Unsuccessfully", "homeplug_av.lnk_stats.rx.pbs_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_tb_pass,
	  { "Sum of Turbo Bit Error over successfully recevied PBs", "homeplug_av.lnk_stats.rx.tb_pass",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_tb_fail,
	  { "Sum of Turbo Bit Error over unsuccessfully recevied PBs", "homeplug_av.lnk_stats.rx.tb_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lnk_stats_rx_num_int,
	  { "Number of Tone Map Intervals", "homeplug_av.lnk_stats.rx.num_int",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rx_inv_stats,
	  { "Rx Interval Statistics", "homeplug_av.lnk_stats.rx.inv",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rx_inv_phy_rate,
	  { "Rx Phy Rate for Tone Map Interval 0", "homeplug_av.lnk_stats.rx.inv.phy_rate",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rx_inv_pbs_pass,
	  { "Number of PB Received Successfully", "homeplug_av.lnk_stats.rx.inv.pbs_pass",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rx_inv_pbs_fail,
	  { "Number of PB Received Unsuccessfully", "homeplug_av.lnk_stats.rx.inv.pbs_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rx_inv_tb_pass,
	  { "Sum of the Turbo Bit Error over all PBs received successfully", "homeplug_av.lnk_stats.rx.inv.tb_pass",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rx_inv_tb_fail,
	  { "Sum of the Turbo Bit Error over all PBs received unsuccessfully", "homeplug_av.lnk_stats.rx.inv.tb_fail",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Sniffer Request */
	{ &hf_homeplug_av_sniffer_req,
	  { "Sniffer Request", "homeplug_av.sniffer_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_req_ctrl,
	  { "Sniffer Control", "homeplug_av.sniffer_req.ctrl",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_sniffer_ctrl_vals), HOMEPLUG_AV_SNIFFER_CTRL_MASK, NULL, HFILL }
	},
	/* Sniffer Confirmation */
	{ &hf_homeplug_av_sniffer_cnf,
	  { "Sniffer Confirmation" , "homeplug_av.sniffer_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_cnf_status,
	  { "Status", "homeplug_av.sniffer_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_sniffer_status_vals), 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_cnf_state,
	  { "State", "homeplug_av.sniffer_cnf.state",
	  FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_cnf_da,
	  { "Destination address", "homeplug_av.sniffer_cnf.da",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Sniffer Indicate */
	{ &hf_homeplug_av_sniffer_ind,
	  { "Sniffer Indicate", "homeplug_av.sniffer_ind",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_ind_type,
	  { "Sniffer Type", "homeplug_av.sniffer_ind.type",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_sniffer_type_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_sniffer_ind_data,
	  { "Sniffer Data", "homeplug_av.sniffer_ind.data",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_data_dir,
	  { "Direction", "homeplug_av.sniffer_ind.data.dir",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lnk_stats_dir_vals), HOMEPLUG_AV_LNK_STATS_DIR_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_data_systime,
	  { "System time", "homeplug_av.sniffer_ind.data.systime",
	  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_sniffer_data_bc_time,
	  { "Beacon time", "homeplug_av.sniffer_ind.data.bc_time",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Network Info Confirmation */
	{ &hf_homeplug_av_nw_info_cnf,
	  { "Network Info Confirmation", "homeplug_av.nw_info_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_net_info,
	  { "Networks informations", "homeplug_av.nw_info_cnf.net_info",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_num_avlns,
	  { "Number of AV Logical Networks", "homeplug_av.nw_info.num_avlns",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_nid,
	  { "Network ID", "homeplug_av.nw_info.nid",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_snid,
	  { "Short Network ID", "homeplug_av.nw_info.snid",
	  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_tei,
	  { "Terminal Equipement Identifer", "homeplug_av.nw_info.tei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_sta_role,
	  { "Station Role", "homeplug_av.nw_info.sta_role",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_nw_info_role_vals), HOMEPLUG_AV_NW_INFO_ROLE_MASK, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_nw_info_cco_mac,
	  { "CCo MAC Address", "homeplug_av.nw_info_cnf.cco_mac",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_cco_tei,
	  { "CCo Terminal Equipement Identifier", "homeplug_av.nw_info_cnf.cco_tei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_num_stas,
	  { "Number of AV Stations", "homeplug_av.nw_info_cnf.num_stas",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_access,
	  { "Access network", "homeplug_av.nw_info_cnf.access",
	  FT_UINT8, BASE_HEX, VALS(homeplug_nw_info_access_vals), HOMEPLUG_AV_NW_INFO_NID_MASK, "Reserved", HFILL }
	},
	{ &hf_homeplug_av_nw_info_num_coord,
	  { "Number of neighbor networks coordinating", "homeplug_av.nw_info_cnf.num_coord",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Network Info per station */
	{ &hf_homeplug_av_nw_info_sta_info,
	  { "Stations Informations", "homeplug_av.nw_info_cnf.sta_info",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_sta_da,
	  { "Station MAC Address", "homeplug_av.nw_info_cnf.sta_info.da",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_sta_tei,
	  { "Station Terminal Equipement Identifier", "homeplug_av.nw_info_cnf.sta_indo.tei",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_sta_bda,
	  { "MAC Address of first Node Bridged by Station", "homeplug_av.nw_info_cnf.sta_indo.bda",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_sta_phy_dr_tx,
	  { "Average PHY Tx data Rate (Mbits/sec)", "homeplug_av.nw_info_cnf.sta_indo.phy_dr_tx",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_nw_info_sta_phy_dr_rx,
	  { "Average PHY Rx data Rate (Mbits/sec)", "homeplug_av.nw_info_cnf.sta_indo.phy_dr_rx",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Check Points Request */
	{ &hf_homeplug_av_cp_rpt_req,
	  { "Check Points Request", "homeplug_av.cp_rpt_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_req_session_id,
	  { "Session ID", "homeplug_av.cp_rpt_req.session_id",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_req_clr,
	  { "Clear flag", "homeplug_av.cp_rpt_req.clr",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_rpt_clr_vals), HOMEPLUG_AV_RPT_CLR_MASK, "Unknown", HFILL }
	},
	/* Check Points Confirmation */
	{ &hf_homeplug_av_cp_rpt_ind,
	  { "Check Points Confirmation", "homeplug_av.cp_rpt_ind",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_status,
	  { "Status", "homeplug_av.cp_rpt_ind.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_major_ver,
	  { "Major version", "homeplug_av.cp_rpt_ind.major_ver",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_minor_ver,
	  { "Minor version", "homeplug_av.cp_rpt_ind.minor_ver",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_session_id,
	  { "Session ID", "homeplug_av.cp_rpt_ind.session_id",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_total_size,
	  { "Total size", "homeplug_av.cp_rpt_ind.total_size",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_blk_offset,
	  { "Offset", "homeplug_av.cp_rpt_ind.blk_offset",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_byte_index,
	 { "Byte Index", "homeplug_av.cp_rpt_ind.byte_index",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_num_parts,
	 { "Number of parts", "homeplug_av.cp_rpt_ind.num_parts",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_curr_part,
	 { "Current part", "homeplug_av.cp_rpt_ind.curr_part",
	 FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_data_len,
	 { "Data length", "homeplug_av.cp_rpt_ind.data_len",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_data_ofs,
	 { "Data offset", "homeplug_av.cp_rpt_ind.data_ofs",
	  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cp_rpt_ind_data,
	 { "Report Data", "homeplug_av.cp_rpt_ind.data",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Loopback Request */
	{ &hf_homeplug_av_fr_lbk_req,
	  { "Loopback Request", "homeplug_av.fr_lbk.req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fr_lbk_duration,
	  { "Duration", "homeplug_av.lbk.duration",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fr_lbk_len,
	  { "Length", "homeplug_av.lbk.len",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fr_lbk_req_data,
	  { "Data", "homeplug_av.fr_lbj_req.data",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Loopback Confirmation */
	{ &hf_homeplug_av_fr_lbk_cnf,
	  { "Loopback Confirmation", "homeplug_av.fr_lbk_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_fr_lbk_cnf_status,
	  { "Status", "homeplug_av.fr_lbk_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_lbk_stat_cnf,
	  { "Loopback Status Confirmation", "homeplug_av.lnk_stat_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_lbk_stat_cnf_status,
	  { "Status", "homeplug_av.lnk_stat_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_lbk_stat_cnf_lbk_stat,
	  { "Loopback Status", "homeplug_av.lnk_stat_cnf.lbk_stat",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_lbk_status_vals), HOMEPLUG_AV_LBK_STATUS_MASK, NULL, HFILL }
	},
	/* Set Encryption Key Request */
	{ &hf_homeplug_av_set_key_req,
	  { "Set Encryption Key Request", "homeplug_av.set_key_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_set_key_req_eks,
	  { "EKS", "homeplug_av.set_key_req.eks",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_set_key_peks_vals), 0x00, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_set_key_req_nmk,
	  { "NMK", "homeplug_av.set_key_req.nmk",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_set_key_req_rda,
	  { "Destination Address", "homeplug_av.set_key_req.rda",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_set_key_req_dak,
	  { "DAK", "homeplug_av.set_key_req.dak",
	  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Set Encryption Key Confirmation */
	{ &hf_homeplug_av_set_key_cnf,
	  { "Set Encryption Key Confirmation", "homeplug_av.set_key_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_set_key_cnf_status,
	  { "Status", "homeplug_av.set_key_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_set_key_status_vals), 0x00, NULL, HFILL }
	},
	/* Get Manufacturer String Confirmation */
	{ &hf_homeplug_av_mfg_string_cnf,
	  { "Get Manufacturer String Confirmation", "homeplug_av.mfg_string_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mfg_string_cnf_status,
	  { "Status", "homeplug_av.mfg_string_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_mfg_string_cnf_len,
	  { "Length", "homeplug_av.mfg_string_cnf.len",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_mfg_string_cnf_string,
	  { "Manufacturing String", "homeplug_av.mfg_string_cnf.string",
	  FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Read Configuration Block Confirmation */
	{ &hf_homeplug_av_rd_cblock_cnf,
	  { "Read Configuration Block Confirmation", "homeplug_av.rd_block_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rd_cblock_cnf_status,
	  { "Status", "homeplug_av.rd_block_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_cblock_status_vals), 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_rd_cblock_cnf_len,
	  { "Length", "homeplug_av.rd_block_cnf.len",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Configuration Block Header */
	{ &hf_homeplug_av_cblock_hdr,
	  { "Configuration Block Header", "homeplug_av.cblock_hdr",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_hdr_ver,
	  { "Header Version Number", "homeplug_av.cblock_hdr.ver",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_img_rom_addr,
	  { "Image address in NVM", "homeplug_av.cblock_hdr.img_rom_addr",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_img_addr,
	  { "Image address in SDRAM", "homeplug_av.cblock_hdr.img_addr",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_img_len,
	  { "Image length", "homeplug_av.cblock_hdr.img_len",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_img_chksum,
	  { "Image Checksum", "homeplug_av.cblock_hdr.img_chksum",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_entry_point,
	  { "Entry Point", "homeplug_av.cblock_hdr.entry_point",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_next_hdr,
	  { "Address of next header in NVM", "homeplug_av.cblock_hdr.next_hdr",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_hdr_chksum,
	  { "Header checksum", "homeplug_av.cblock_hdr.hdr_chksum",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Configuration Block */
	{ &hf_homeplug_av_cblock,
	  { "Configuration Block", "homeplug_av.cblock",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_sdram_size,
	  { "SDRAM size", "homeplug_av.cblock.sdram_size",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_sdram_conf,
	  { "SDRAM Configuration Register", "homeplug_av.cblock.sdram_conf",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_sdram_tim0,
	  { "SDRAM Timing Register 0", "homeplug_av.cblock.sdram_tim0",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_sdram_tim1,
	  { "SDRAM Timing Register 1", "homeplug_av.cblock.sdram_tim1",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_sdram_cntrl,
	  { "SDRAM Control Register", "homeplug_av.cblock.sdram_cntrl",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_sdram_refresh,
	  { "SDRAM Refresh Register", "homeplug_av.cblock.sdram_refresh",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_cblock_mac_clock,
	  { "MAC Clock Register", "homeplug_av.cblock.mac_clock",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Set SDRAM Configuration Request */
	{ &hf_homeplug_av_set_sdram_req,
	  { "Set SDRAM Configuration Request", "homeplug_av.set_sdram_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_set_sdram_req_chksum,
	  { "Checksum", "homeplug_av.set_sdram_req.chksum",
	  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Set SDRAM Configuration Confirmation */
	{ &hf_homeplug_av_set_sdram_cnf,
	  { "Set SDRAM Configuration Confirmation", "homeplug_av.set_sdram_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_set_sdram_cnf_status,
	  { "Status", "homeplug_av.set_sdram_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_cblock_status_vals), 0x00, "Unknown", HFILL }
	},
	/* Embedded Host Action Required Indicate */
	{ &hf_homeplug_av_host_action_ind,
	  { "Embedded Host Action Required Indicate", "homeplug_av.host_action_ind",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_host_action_ind_act,
	  { "Action required", "homeplug_av.host_action_ind.action",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_host_action_vals), 0x00, NULL, HFILL }
	},
	/* Embedded Host Action Required Reponse */
	{ &hf_homeplug_av_host_action_rsp,
	  { "Embedded Host Action Required Response", "homeplug_av.host_action_rsp",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_host_action_rsp_sts,
	  { "Status", "homeplug_av.host_action_rsp.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, "Unknown", HFILL }
	},
	/* Get Device Attributes Request */
	{ &hf_homeplug_av_op_attr_req,
	  { "Get Device Attributes Request", "homeplug_av.op_attr_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_cookie,
	  { "Cookie", "homeplug_av.op_attr.cookie",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_rep_type,
	  { "Report Type", "homeplug_av.op_attr.rep_type",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_op_attr_report_vals), 0x00, NULL, HFILL }
	},
	/* Get Device Attributes Confirmation */
	{ &hf_homeplug_av_op_attr_cnf,
	  { "Get Device Attributes Confirmation", "homeplug_av.op_attr_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_cnf_status,
	  { "Status", "homeplug_av.op_attr_cnf.status",
	  FT_UINT16, BASE_HEX, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_cnf_size,
	  { "Size", "homeplug_av.op_attr_cnf.size",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_cnf_data,
	  { "Data", "homeplug_av.op_attr_cnf.data",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Device Attributes binary report */
	{ &hf_homeplug_av_op_attr_data_hw,
	  { "Hardware platform", "homeplug_av.op_attr_cnf.data.hw",
	  FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw,
	  { "Software platform", "homeplug_av.op_attr_cnf.data.sw",
	  FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw_major,
	  { "Major version", "homeplug_av.op_attr_cnf.data.sw_major",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw_minor,
	  { "Minor version", "homeplug_av.op_attr_cnf.data.sw_minor",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw_sub,
	  { "Software/PIB version", "homeplug_av.op_attr_cnf.data.sw_sub",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw_num,
	  { "Software build number", "homeplug_av.op_attr_cnf.data.sw_sub",
	  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw_date,
	  { "Build date", "homeplug_av.op_attr_cnf.data.sw_date",
	  FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_op_attr_data_sw_rel,
	  { "Release type", "homeplug_av.op_attr_cnf.data.sw_rel",
	  FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	/* Get Ethernet PHY Settings Request */
	{ &hf_homeplug_av_enet_phy_req,
	  { "Get Ethernet PHY Settings Request", "homeplug_av.enet_phy_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_enet_phy_req_mcontrol,
	  { "Message Control", "homeplug_av.enet_phy_req.mcontrol",
	  FT_UINT8, BASE_DEC, VALS(homeplug_av_enet_phy_mcontrol_vals), HOMEPLUG_AV_ENET_PHY_MCONTROL_MASK, "Unknown", HFILL }
	},
	{ &hf_homeplug_av_enet_phy_req_addcaps,
	  { "Advertisement Capabilities", "homeplug_av.enet_phy_req.addcaps",
	  FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
	},
	/* Get Ethernet PHY Settings Confirmation */
	{ &hf_homeplug_av_enet_phy_cnf,
	  { "Get Ethernet PHY Settings Confirmation", "homeplug_av.enet_phy_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_enet_phy_cnf_status,
	  { "Status", "homeplug_av.enet_phy_cnf.status",
	  FT_UINT8, BASE_DEC, VALS(homeplug_av_generic_status_vals), HOMEPLUG_AV_GEN_STATUS_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_enet_phy_cnf_speed,
	  { "Speed", "homeplug_av.enet_phy.speed",
	  FT_UINT8, BASE_DEC, VALS(homeplug_av_enet_phy_speed_vals), HOMEPLUG_AV_ENET_PHY_SPEED_MASK, "Unknown", HFILL },
	},
	{ &hf_homeplug_av_enet_phy_cnf_duplex,
	  { "Duplex", "homeplug_av.enet_phy.duplex",
	  FT_UINT8, BASE_DEC, VALS(homeplug_av_enet_phy_duplex_vals), HOMEPLUG_AV_ENET_PHY_DUPLEX_MASK, "Unknown", HFILL },
	},
	/* Tone Map Characteristics Request */
	{ &hf_homeplug_av_tone_map_req,
	  { "Tone Map Characteristics Request", "homeplug_av.tone_map_req",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_req_mac,
	  { "Peer address", "homeplug_av.tone_map_req.mac",
	  FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_req_slot,
	  { "Tone Map slot", "homeplug_av.tone_map_req.slot",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Tone Map Characteristics Confirmation */
	{ &hf_homeplug_av_tone_map_cnf,
	  { "Tone Map Characteristics Confirmation", "homeplug_av.tone_map_cnf",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_cnf_status,
	  { "Status", "homeplug_av.tone_map_cnf.status",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_tone_map_status_vals), HOMEPLUG_AV_TONE_MAP_STATUS_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_cnf_slot,
	  { "Slot", "homeplug_av.tone_map_cnf.slot",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_cnf_num_tms,
	  { "Number of Tone Maps in use", "homeplug_av.tone_map_cnf.num_tms",
	  FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_cnf_num_act,
	  { "Tone map number of active carriers", "homeplug_av.tone_map_cnf.num_act",
	  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
	},
	/* Tone Map Carrier informations */
	{ &hf_homeplug_av_tone_map_carrier,
	  { "Modulation per carrier", "homeplug_av.tone_map_cnf.carrier",
	  FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_carrier_lo,
	  { "Modulation (Low carrier)", "homeplug_av.tone_map_cnf.carrier.lo",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_tone_map_vals), HOMEPLUG_AV_TONE_MAP_MASK, NULL, HFILL }
	},
	{ &hf_homeplug_av_tone_map_carrier_hi,
	  { "Modulation (High carrier)", "homeplug_av.tone_map_cnf.carrier.hi",
	  FT_UINT8, BASE_HEX, VALS(homeplug_av_tone_map_vals), 0xF0, NULL, HFILL }
	}
   };

  static gint *ett[] = {
	&ett_homeplug_av,
	&ett_homeplug_av_mmhdr,
	&ett_homeplug_av_mmtype,
	&ett_homeplug_av_vendor,
	&ett_homeplug_av_public,
	&ett_homeplug_av_bcn,
	&ett_homeplug_av_fc,
	&ett_homeplug_av_cc_disc_list_cnf,
	&ett_homeplug_av_cc_sta_info,
	&ett_homeplug_av_cc_net_info,
	&ett_homeplug_av_cm_enc_pld_ind,
	&ett_homeplug_av_cm_enc_pld_rsp,
	&ett_homeplug_av_cm_set_key_req,
	&ett_homeplug_av_cm_set_key_cnf,
	&ett_homeplug_av_cm_get_key_req,
	&ett_homeplug_av_cm_get_key_cnf,
	&ett_homeplug_av_brg_infos_cnf,
	&ett_homeplug_av_cm_nw_infos_cnf,
	&ett_homeplug_av_nw_stats_cnf,
	&ett_homeplug_av_get_sw_cnf,
	&ett_homeplug_av_wr_mem_req,
	&ett_homeplug_av_wr_mem_cnf,
	&ett_homeplug_av_rd_mem_req,
	&ett_homeplug_av_rd_mem_cnf,
	&ett_homeplug_av_st_mac_req,
	&ett_homeplug_av_st_mac_cnf,
	&ett_homeplug_av_get_nvm_cnf,
	&ett_homeplug_av_rs_dev_cnf,
	&ett_homeplug_av_wr_mod_req,
	&ett_homeplug_av_wr_mod_cnf,
	&ett_homeplug_av_wr_mod_ind,
	&ett_homeplug_av_rd_mod_req,
	&ett_homeplug_av_rd_mod_cnf,
	&ett_homeplug_av_mod_nvm_req,
	&ett_homeplug_av_mod_nvm_cnf,
	&ett_homeplug_av_wd_rpt_req,
	&ett_homeplug_av_wd_rpt_ind,
	&ett_homeplug_av_lnk_stats_req,
	&ett_homeplug_av_lnk_stats_cnf,
	&ett_homeplug_av_lnk_stats_tx,
	&ett_homeplug_av_lnk_stats_rx,
	&ett_homeplug_av_lnk_stats_rx_inv,
	&ett_homeplug_av_sniffer_req,
	&ett_homeplug_av_sniffer_cnf,
	&ett_homeplug_av_sniffer_ind,
	&ett_homeplug_av_sniffer_ind_data,
	&ett_homeplug_av_nw_info_cnf,
	&ett_homeplug_av_nw_info_sta_info,
	&ett_homeplug_av_nw_info_net_info,
	&ett_homeplug_av_cp_rpt_req,
	&ett_homeplug_av_cp_rpt_ind,
	&ett_homeplug_av_fr_lbk_req,
	&ett_homeplug_av_fr_lbk_cnf,
	&ett_homeplug_av_lbk_stat_cnf,
	&ett_homeplug_av_set_key_req,
	&ett_homeplug_av_set_key_cnf,
	&ett_homeplug_av_mfg_string_cnf,
	&ett_homeplug_av_rd_cblock_cnf,
	&ett_homeplug_av_cblock_hdr,
	&ett_homeplug_av_cblock,
	&ett_homeplug_av_set_sdram_req,
	&ett_homeplug_av_set_sdram_cnf,
	&ett_homeplug_av_op_attr_req,
	&ett_homeplug_av_op_attr_cnf,
	&ett_homeplug_av_op_attr_data,
	&ett_homeplug_av_enet_phy_req,
	&ett_homeplug_av_enet_phy_cnf,
	&ett_homeplug_av_tone_map_req,
	&ett_homeplug_av_tone_map_cnf,
	&ett_homeplug_av_tone_map_carrier
  };


  proto_homeplug_av = proto_register_protocol("HomePlug AV protocol", "HomePlug AV", "homeplug-av");

  proto_register_field_array(proto_homeplug_av, hf, array_length(hf));

  proto_register_subtree_array(ett, array_length(ett));
}
