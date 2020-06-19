/* packet-homeplug-av.c
 * Routines for HomePlug AV dissection
 *
 * Copyright 2011, Florian Fainelli <florian[AT]openwrt.org>
 * Copyright 2016, Nora Sandler <nsandler[AT]securityinnovation.com>
 * Copyright 2018, Sergey Rak <sergrak[AT]iotecha.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/ptvcursor.h>

void proto_register_homeplug_av(void);
void proto_reg_handoff_homeplug_av(void);

static int proto_homeplug_av                     = -1;

static int hf_homeplug_av_mmhdr                  = -1;
static int hf_homeplug_av_mmhdr_mmver            = -1;
static int hf_homeplug_av_mmhdr_mmtype_general   = -1;
static int hf_homeplug_av_mmhdr_mmtype_qualcomm  = -1;
static int hf_homeplug_av_mmhdr_mmtype_st        = -1;
static int hf_homeplug_av_mmhdr_mmtype_lsb       = -1;
static int hf_homeplug_av_mmhdr_mmtype_msb       = -1;
static int hf_homeplug_av_mmhdr_fmi              = -1;
static int hf_homeplug_av_vendor                 = -1;
static int hf_homeplug_av_vendor_oui             = -1;
static int hf_homeplug_av_reserved               = -1;

/* Frame Control fields (for sniffer data) */
static int hf_homeplug_av_fc                     = -1;
static int hf_homeplug_av_fc_del_type            = -1;
static int hf_homeplug_av_fc_access              = -1;
static int hf_homeplug_av_fc_snid                = -1;
static int hf_homeplug_av_fc_fccs_av             = -1;

/* Variant fields used by multiple MPDU types */
static int hf_homeplug_av_dtei                   = -1;
static int hf_homeplug_av_stei                   = -1;
static int hf_homeplug_av_lid                    = -1;
static int hf_homeplug_av_cfs                    = -1;
static int hf_homeplug_av_bdf                    = -1;
static int hf_homeplug_av_hp10df                 = -1;
static int hf_homeplug_av_hp11df                 = -1;
static int hf_homeplug_av_svn                    = -1;
static int hf_homeplug_av_rrtf                   = -1;
static int hf_homeplug_av_fl_av                  = -1;
static int hf_homeplug_av_ppb                    = -1;
static int hf_homeplug_av_mfs_rsp_data           = -1;
static int hf_homeplug_av_mfs_rsp_mgmt           = -1;

/* Beacon */
static int hf_homeplug_av_bcn                    = -1;
static int hf_homeplug_av_bcn_bts                = -1;
static int hf_homeplug_av_bcn_bto_0              = -1;
static int hf_homeplug_av_bcn_bto_1              = -1;
static int hf_homeplug_av_bcn_bto_2              = -1;
static int hf_homeplug_av_bcn_bto_3              = -1;

/* Beacon MPDU Payload */
static int hf_homeplug_av_bcn_payload            = -1;
static int hf_homeplug_av_bcn_type               = -1;
static int hf_homeplug_av_bcn_nid                = -1;
static int hf_homeplug_av_bcn_stei               = -1;
static int hf_homeplug_av_bcn_ncnr               = -1;
static int hf_homeplug_av_bcn_num_slots          = -1;
static int hf_homeplug_av_bcn_slot_use           = -1;
static int hf_homeplug_av_bcn_slot_id            = -1;
static int hf_homeplug_av_bcn_aclss              = -1;
static int hf_homeplug_av_bcn_hm                 = -1;
static int hf_homeplug_av_bcn_nm                 = -1;
static int hf_homeplug_av_bcn_npsm               = -1;
static int hf_homeplug_av_bcn_cco_cap            = -1;
static int hf_homeplug_av_bcn_rtsbf              = -1;
static int hf_homeplug_av_bcn_hoip               = -1;
static int hf_homeplug_av_bcn_rsf                = -1;
static int hf_homeplug_av_bcn_plevel             = -1;
static int hf_homeplug_av_bcn_bentries           = -1;
static int hf_homeplug_av_bcn_bpcs               = -1;

/* Start of Frame */
static int hf_homeplug_av_sof                    = -1;
static int hf_homeplug_av_sof_peks               = -1;
static int hf_homeplug_av_sof_ble                = -1;
static int hf_homeplug_av_sof_pbsz               = -1;
static int hf_homeplug_av_sof_num_sym            = -1;
static int hf_homeplug_av_sof_tmi_av             = -1;
static int hf_homeplug_av_sof_mpdu_cnt           = -1;
static int hf_homeplug_av_sof_burst_cnt          = -1;
static int hf_homeplug_av_sof_bbf                = -1;
static int hf_homeplug_av_sof_mrtfl              = -1;
static int hf_homeplug_av_sof_clst               = -1;
static int hf_homeplug_av_sof_mfs_cmd_mgmt       = -1;
static int hf_homeplug_av_sof_mfs_cmd_data       = -1;
static int hf_homeplug_av_sof_rsr                = -1;
static int hf_homeplug_av_sof_mcf                = -1;
static int hf_homeplug_av_sof_dccpcf             = -1;
static int hf_homeplug_av_sof_mnbf               = -1;
static int hf_homeplug_av_sof_mfs_rsp_mgmt       = -1;
static int hf_homeplug_av_sof_mfs_rsp_data       = -1;
static int hf_homeplug_av_sof_bm_sack            = -1;

/* Selective Acknowledgement */
static int hf_homeplug_av_sack                   = -1;

/* Request to Send/Clear to Send */
static int hf_homeplug_av_rtscts                 = -1;
static int hf_homeplug_av_rtscts_rtsf            = -1;
static int hf_homeplug_av_rtscts_igf             = -1;
static int hf_homeplug_av_rtscts_mnbf            = -1;
static int hf_homeplug_av_rtscts_mcf             = -1;
static int hf_homeplug_av_rtscts_dur             = -1;

/* Sound */
static int hf_homeplug_av_sound                  = -1;
static int hf_homeplug_av_sound_pbsz             = -1;
static int hf_homeplug_av_sound_bdf              = -1;
static int hf_homeplug_av_sound_saf              = -1;
static int hf_homeplug_av_sound_scf              = -1;
static int hf_homeplug_av_sound_req_tm           = -1;
static int hf_homeplug_av_sound_mpdu_cnt         = -1;
static int hf_homeplug_av_sound_src              = -1;
static int hf_homeplug_av_sound_add_req_tm       = -1;
static int hf_homeplug_av_sound_max_pb_sym       = -1;
static int hf_homeplug_av_sound_ecsf             = -1;
static int hf_homeplug_av_sound_ecuf             = -1;
static int hf_homeplug_av_sound_ems              = -1;
static int hf_homeplug_av_sound_esgisf           = -1;
static int hf_homeplug_av_sound_elgisf           = -1;
static int hf_homeplug_av_sound_efrs             = -1;

/* Reverse Start of Frame */
static int hf_homeplug_av_rsof                   = -1;
static int hf_homeplug_av_rsof_fl                = -1;
static int hf_homeplug_av_rsof_tmi               = -1;
static int hf_homeplug_av_rsof_pbsz              = -1;
static int hf_homeplug_av_rsof_num_sym           = -1;
static int hf_homeplug_av_rsof_mfs_cmd_mgmt      = -1;
static int hf_homeplug_av_rsof_mfs_cmd_data      = -1;

/* Public MMEs */
static int hf_homeplug_av_public                 = -1;
static int hf_homeplug_av_public_frag_count      = -1;
static int hf_homeplug_av_public_frag_index      = -1;
static int hf_homeplug_av_public_frag_seqnum     = -1;

static int hf_homeplug_av_cc_disc_list_cnf       = -1;

static int hf_homeplug_av_cc_disc_list_sta_cnt   = -1;
static int hf_homeplug_av_cc_sta_info            = -1;
static int hf_homeplug_av_cc_sta_info_mac        = -1;
static int hf_homeplug_av_cc_sta_info_tei        = -1;
static int hf_homeplug_av_cc_sta_info_same_net   = -1;
static int hf_homeplug_av_cc_sta_info_sig_level  = -1;
static int hf_homeplug_av_cc_sta_info_avg_ble    = -1;

static int hf_homeplug_av_cc_disc_list_net_cnt   = -1;
static int hf_homeplug_av_cc_net_info            = -1;
static int hf_homeplug_av_cc_net_info_hyb_mode   = -1;
static int hf_homeplug_av_cc_net_info_bcn_slots  = -1;
static int hf_homeplug_av_cc_net_info_cco_sts    = -1;
static int hf_homeplug_av_cc_net_info_bcn_ofs    = -1;

static int hf_homeplug_av_brg_infos_cnf          = -1;
static int hf_homeplug_av_brg_infos_cnf_brd      = -1;
static int hf_homeplug_av_brg_infos_cnf_btei     = -1;
static int hf_homeplug_av_brg_infos_cnf_num_stas = -1;
static int hf_homeplug_av_brg_infos_cnf_mac      = -1;

static int hf_homeplug_av_cm_nw_infos_cnf        = -1;

static int hf_homeplug_av_nw_stats_cnf           = -1;

/* Shared network informations fields */
static int hf_homeplug_av_nw_info_peks           = -1;
static int hf_homeplug_av_nw_info_pid            = -1;
static int hf_homeplug_av_nw_info_prn            = -1;
static int hf_homeplug_av_nw_info_pmn            = -1;
static int hf_homeplug_av_nw_info_my_nonce       = -1;
static int hf_homeplug_av_nw_info_your_nonce     = -1;
static int hf_homeplug_av_nw_info_key_type       = -1;
static int hf_homeplug_av_nw_info_cco_cap        = -1;
static int hf_homeplug_av_nw_info_num_avlns      = -1;
static int hf_homeplug_av_nw_info_nid            = -1;
static int hf_homeplug_av_nw_info_snid           = -1;
static int hf_homeplug_av_nw_info_tei            = -1;
static int hf_homeplug_av_nw_info_sta_role       = -1;
static int hf_homeplug_av_nw_info_cco_mac        = -1;
static int hf_homeplug_av_nw_info_cco_tei        = -1;
static int hf_homeplug_av_nw_info_num_stas       = -1;
static int hf_homeplug_av_nw_info_access         = -1;
static int hf_homeplug_av_nw_info_num_coord      = -1;


static int hf_homeplug_av_cm_enc_pld_ind         = -1;
static int hf_homeplug_av_cm_enc_pld_ind_avlns   = -1;
static int hf_homeplug_av_cm_enc_pld_ind_iv      = -1;
static int hf_homeplug_av_cm_enc_pld_ind_uuid    = -1;
static int hf_homeplug_av_cm_enc_pld_ind_len     = -1;
static int hf_homeplug_av_cm_enc_pld_ind_pld     = -1;

static int hf_homeplug_av_cm_enc_pld_rsp         = -1;
static int hf_homeplug_av_cm_enc_pld_rsp_result  = -1;

static int hf_homeplug_av_cm_set_key_req         = -1;
static int hf_homeplug_av_cm_set_key_req_nw_key  = -1;

static int hf_homeplug_av_cm_set_key_cnf         = -1;
static int hf_homeplug_av_cm_set_key_cnf_result  = -1;

static int hf_homeplug_av_cm_get_key_req         = -1;
static int hf_homeplug_av_cm_get_key_req_type    = -1;
static int hf_homeplug_av_cm_get_key_req_has_key = -1;

static int hf_homeplug_av_cm_get_key_cnf         = -1;
static int hf_homeplug_av_cm_get_key_cnf_result  = -1;
static int hf_homeplug_av_cm_get_key_cnf_rtype   = -1;
static int hf_homeplug_av_cm_get_key_cnf_key     = -1;


/* Intellon specific vendor MMEs */
static int hf_homeplug_av_get_sw_cnf             = -1;
static int hf_homeplug_av_get_sw_cnf_status      = -1;
static int hf_homeplug_av_get_sw_cnf_dev_id      = -1;
static int hf_homeplug_av_get_sw_cnf_ver_len     = -1;
static int hf_homeplug_av_get_sw_cnf_ver_str     = -1;
static int hf_homeplug_av_get_sw_cnf_upg         = -1;

/* Shared memory related fields */
static int hf_homeplug_av_mem_len_16bits         = -1;
static int hf_homeplug_av_mem_len_32bits         = -1;
static int hf_homeplug_av_mem_offset             = -1;
static int hf_homeplug_av_mem_checksum           = -1;
static int hf_homeplug_av_mem_data               = -1;
static int hf_homeplug_av_mem_addr               = -1;
static int hf_homeplug_av_mem_status             = -1;

static int hf_homeplug_av_wr_mem_req             = -1;
static int hf_homeplug_av_wr_mem_cnf             = -1;

static int hf_homeplug_av_rd_mem_req             = -1;
static int hf_homeplug_av_rd_mem_cnf             = -1;

static int hf_homeplug_av_mac_module_id          = -1;

static int hf_homeplug_av_st_mac_req             = -1;
static int hf_homeplug_av_st_mac_req_img_load    = -1;
static int hf_homeplug_av_st_mac_req_img_len     = -1;
static int hf_homeplug_av_st_mac_req_img_chksum  = -1;
static int hf_homeplug_av_st_mac_req_img_start   = -1;

static int hf_homeplug_av_st_mac_cnf             = -1;
static int hf_homeplug_av_st_mac_cnf_status      = -1;

static int hf_homeplug_av_get_nvm_cnf            = -1;
static int hf_homeplug_av_get_nvm_cnf_status     = -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_type   = -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_page   = -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_block  = -1;
static int hf_homeplug_av_get_nvm_cnf_nvm_size   = -1;

static int hf_homeplug_av_rs_dev_cnf             = -1;
static int hf_homeplug_av_rs_dev_cnf_status      = -1;

static int hf_homeplug_av_wr_mod_req             = -1;

static int hf_homeplug_av_wr_mod_cnf             = -1;
static int hf_homeplug_av_wr_mod_cnf_status      = -1;

static int hf_homeplug_av_wr_mod_ind             = -1;
static int hf_homeplug_av_wr_mod_ind_status      = -1;

static int hf_homeplug_av_rd_mod_req             = -1;

static int hf_homeplug_av_rd_mod_cnf             = -1;
static int hf_homeplug_av_rd_mod_cnf_status      = -1;

static int hf_homeplug_av_mod_nvm_req            = -1;

static int hf_homeplug_av_mod_nvm_cnf            = -1;
static int hf_homeplug_av_mod_nvm_cnf_status     = -1;

static int hf_homeplug_av_wd_rpt_req             = -1;
static int hf_homeplug_av_wd_rpt_req_session_id  = -1;
static int hf_homeplug_av_wd_rpt_req_clr         = -1;

static int hf_homeplug_av_wd_rpt_ind             = -1;
static int hf_homeplug_av_wd_rpt_ind_status      = -1;
static int hf_homeplug_av_wd_rpt_ind_session_id  = -1;
static int hf_homeplug_av_wd_rpt_ind_num_parts   = -1;
static int hf_homeplug_av_wd_rpt_ind_curr_part   = -1;
static int hf_homeplug_av_wd_rpt_ind_rdata_len   = -1;
static int hf_homeplug_av_wd_rpt_ind_rdata_ofs   = -1;
static int hf_homeplug_av_wd_rpt_ind_rdata       = -1;

static int hf_homeplug_av_lnk_stats_req          = -1;
static int hf_homeplug_av_lnk_stats_req_mcontrol = -1;
static int hf_homeplug_av_lnk_stats_req_dir      = -1;
static int hf_homeplug_av_lnk_stats_req_lid      = -1;
static int hf_homeplug_av_lnk_stats_req_macaddr  = -1;

static int hf_homeplug_av_lnk_stats_cnf          = -1;
static int hf_homeplug_av_lnk_stats_cnf_status   = -1;
static int hf_homeplug_av_lnk_stats_cnf_dir      = -1;
static int hf_homeplug_av_lnk_stats_cnf_lid      = -1;
static int hf_homeplug_av_lnk_stats_cnf_tei      = -1;
static int hf_homeplug_av_lnk_stats_cnf_lstats   = -1;

static int hf_homeplug_av_lnk_stats_tx           = -1;
static int hf_homeplug_av_lnk_stats_tx_mpdu_ack  = -1;
static int hf_homeplug_av_lnk_stats_tx_mpdu_col  = -1;
static int hf_homeplug_av_lnk_stats_tx_mpdu_fai  = -1;
static int hf_homeplug_av_lnk_stats_tx_pbs_pass  = -1;
static int hf_homeplug_av_lnk_stats_tx_pbs_fail  = -1;

static int hf_homeplug_av_lnk_stats_rx           = -1;
static int hf_homeplug_av_lnk_stats_rx_mpdu_ack  = -1;
static int hf_homeplug_av_lnk_stats_rx_mpdu_fai  = -1;
static int hf_homeplug_av_lnk_stats_rx_pbs_pass  = -1;
static int hf_homeplug_av_lnk_stats_rx_pbs_fail  = -1;
static int hf_homeplug_av_lnk_stats_rx_tb_pass   = -1;
static int hf_homeplug_av_lnk_stats_rx_tb_fail   = -1;
static int hf_homeplug_av_lnk_stats_rx_num_int   = -1;

static int hf_homeplug_av_rx_inv_stats           = -1;
static int hf_homeplug_av_rx_inv_phy_rate        = -1;
static int hf_homeplug_av_rx_inv_pbs_pass        = -1;
static int hf_homeplug_av_rx_inv_pbs_fail        = -1;
static int hf_homeplug_av_rx_inv_tb_pass         = -1;
static int hf_homeplug_av_rx_inv_tb_fail         = -1;

static int hf_homeplug_av_sniffer_req            = -1;
static int hf_homeplug_av_sniffer_req_ctrl       = -1;

static int hf_homeplug_av_sniffer_cnf            = -1;
static int hf_homeplug_av_sniffer_cnf_status     = -1;
static int hf_homeplug_av_sniffer_cnf_state      = -1;
static int hf_homeplug_av_sniffer_cnf_da         = -1;

static int hf_homeplug_av_sniffer_ind            = -1;
static int hf_homeplug_av_sniffer_ind_type       = -1;
static int hf_homeplug_av_sniffer_ind_data       = -1;
static int hf_homeplug_av_sniffer_data_dir       = -1;
static int hf_homeplug_av_sniffer_data_systime   = -1;
static int hf_homeplug_av_sniffer_data_bc_time   = -1;

static int hf_homeplug_av_nw_info_cnf            = -1;

static int hf_homeplug_av_nw_info_sta_info       = -1;
static int hf_homeplug_av_nw_info_net_info       = -1;

static int hf_homeplug_av_nw_info_sta_da         = -1;
static int hf_homeplug_av_nw_info_sta_tei        = -1;
static int hf_homeplug_av_nw_info_sta_bda        = -1;
static int hf_homeplug_av10_nw_info_sta_phy_dr_tx= -1;
static int hf_homeplug_av10_nw_info_sta_phy_dr_rx= -1;
static int hf_homeplug_av11_nw_info_sta_phy_dr_tx= -1;
static int hf_homeplug_av11_nw_info_sta_cpling_tx = -1;
static int hf_homeplug_av11_nw_info_sta_phy_dr_rx= -1;
static int hf_homeplug_av11_nw_info_sta_cpling_rx = -1;

static int hf_homeplug_av_cp_rpt_req             = -1;
static int hf_homeplug_av_cp_rpt_req_session_id  = -1;
static int hf_homeplug_av_cp_rpt_req_clr         = -1;

static int hf_homeplug_av_cp_rpt_ind             = -1;
static int hf_homeplug_av_cp_rpt_ind_status      = -1;
static int hf_homeplug_av_cp_rpt_ind_major_ver   = -1;
static int hf_homeplug_av_cp_rpt_ind_minor_ver   = -1;
static int hf_homeplug_av_cp_rpt_ind_session_id  = -1;
static int hf_homeplug_av_cp_rpt_ind_total_size  = -1;
static int hf_homeplug_av_cp_rpt_ind_blk_offset  = -1;
static int hf_homeplug_av_cp_rpt_ind_byte_index  = -1;
static int hf_homeplug_av_cp_rpt_ind_num_parts   = -1;
static int hf_homeplug_av_cp_rpt_ind_curr_part   = -1;
static int hf_homeplug_av_cp_rpt_ind_data_len    = -1;
static int hf_homeplug_av_cp_rpt_ind_data_ofs    = -1;
static int hf_homeplug_av_cp_rpt_ind_data        = -1;

static int hf_homeplug_av_fr_lbk_duration        = -1;
static int hf_homeplug_av_fr_lbk_len             = -1;

static int hf_homeplug_av_fr_lbk_req             = -1;
static int hf_homeplug_av_fr_lbk_req_data        = -1;

static int hf_homeplug_av_fr_lbk_cnf             = -1;
static int hf_homeplug_av_fr_lbk_cnf_status      = -1;

static int hf_homeplug_av_lbk_stat_cnf           = -1;
static int hf_homeplug_av_lbk_stat_cnf_status    = -1;
static int hf_homeplug_av_lbk_stat_cnf_lbk_stat  = -1;

static int hf_homeplug_av_set_key_req            = -1;
static int hf_homeplug_av_set_key_req_eks        = -1;
static int hf_homeplug_av_set_key_req_nmk        = -1;
static int hf_homeplug_av_set_key_req_rda        = -1;
static int hf_homeplug_av_set_key_req_dak        = -1;

static int hf_homeplug_av_set_key_cnf            = -1;
static int hf_homeplug_av_set_key_cnf_status     = -1;

static int hf_homeplug_av_mfg_string_cnf         = -1;
static int hf_homeplug_av_mfg_string_cnf_status  = -1;
static int hf_homeplug_av_mfg_string_cnf_len     = -1;
static int hf_homeplug_av_mfg_string_cnf_string  = -1;

static int hf_homeplug_av_rd_cblock_cnf          = -1;
static int hf_homeplug_av_rd_cblock_cnf_status   = -1;
static int hf_homeplug_av_rd_cblock_cnf_len      = -1;

static int hf_homeplug_av_cblock_hdr             = -1;
static int hf_homeplug_av_cblock_hdr_ver         = -1;
static int hf_homeplug_av_cblock_img_rom_addr    = -1;
static int hf_homeplug_av_cblock_img_addr        = -1;
static int hf_homeplug_av_cblock_img_len         = -1;
static int hf_homeplug_av_cblock_img_chksum      = -1;
static int hf_homeplug_av_cblock_entry_point     = -1;
static int hf_homeplug_av_cblock_hdr_minor       = -1;
static int hf_homeplug_av_cblock_hdr_img_type    = -1;
static int hf_homeplug_av_cblock_hdr_ignore_mask = -1;
static int hf_homeplug_av_cblock_hdr_module_id   = -1;
static int hf_homeplug_av_cblock_hdr_module_subid= -1;
static int hf_homeplug_av_cblock_next_hdr        = -1;
static int hf_homeplug_av_cblock_hdr_chksum      = -1;

static int hf_homeplug_av_cblock                 = -1;
static int hf_homeplug_av_cblock_sdram_size      = -1;
static int hf_homeplug_av_cblock_sdram_conf      = -1;
static int hf_homeplug_av_cblock_sdram_tim0      = -1;
static int hf_homeplug_av_cblock_sdram_tim1      = -1;
static int hf_homeplug_av_cblock_sdram_cntrl     = -1;
static int hf_homeplug_av_cblock_sdram_refresh   = -1;
static int hf_homeplug_av_cblock_mac_clock       = -1;

static int hf_homeplug_av_set_sdram_req          = -1;
static int hf_homeplug_av_set_sdram_req_chksum   = -1;

static int hf_homeplug_av_set_sdram_cnf          = -1;
static int hf_homeplug_av_set_sdram_cnf_status   = -1;

static int hf_homeplug_av_host_action_ind        = -1;
static int hf_homeplug_av_host_action_ind_act    = -1;

static int hf_homeplug_av_host_action_rsp        = -1;
static int hf_homeplug_av_host_action_rsp_sts    = -1;

static int hf_homeplug_av_op_attr_cookie         = -1;
static int hf_homeplug_av_op_attr_rep_type       = -1;

static int hf_homeplug_av_op_attr_req            = -1;

static int hf_homeplug_av_op_attr_cnf            = -1;
static int hf_homeplug_av_op_attr_cnf_status     = -1;
static int hf_homeplug_av_op_attr_cnf_size       = -1;
static int hf_homeplug_av_op_attr_cnf_data       = -1;

static int hf_homeplug_av_op_attr_data_hw        = -1;
static int hf_homeplug_av_op_attr_data_sw        = -1;
static int hf_homeplug_av_op_attr_data_sw_major  = -1;
static int hf_homeplug_av_op_attr_data_sw_minor  = -1;
static int hf_homeplug_av_op_attr_data_sw_sub    = -1;
static int hf_homeplug_av_op_attr_data_sw_num    = -1;
static int hf_homeplug_av_op_attr_data_sw_date   = -1;
static int hf_homeplug_av_op_attr_data_sw_rel    = -1;
static int hf_homeplug_av_op_attr_data_sw_sdram_type = -1;
static int hf_homeplug_av_op_attr_data_sw_linefreq = -1;
static int hf_homeplug_av_op_attr_data_sw_zerocross = -1;
static int hf_homeplug_av_op_attr_data_sw_sdram_size = -1;
static int hf_homeplug_av_op_attr_data_sw_auth_mode = -1;

static int hf_homeplug_av_enet_phy_req           = -1;
static int hf_homeplug_av_enet_phy_req_mcontrol  = -1;
static int hf_homeplug_av_enet_phy_req_addcaps   = -1;

static int hf_homeplug_av_enet_phy_cnf           = -1;
static int hf_homeplug_av_enet_phy_cnf_status    = -1;
static int hf_homeplug_av_enet_phy_cnf_speed     = -1;
static int hf_homeplug_av_enet_phy_cnf_duplex    = -1;

static int hf_homeplug_av_tone_map_tx_req          = -1;
static int hf_homeplug_av_tone_map_tx_req_mac      = -1;
static int hf_homeplug_av_tone_map_tx_req_slot     = -1;
static int hf_homeplug_av_tone_map_tx_req_coupling = -1;

static int hf_homeplug_av_tone_map_rx_req          = -1;
static int hf_homeplug_av_tone_map_rx_req_mac      = -1;
static int hf_homeplug_av_tone_map_rx_req_slot     = -1;
static int hf_homeplug_av_tone_map_rx_req_coupling = -1;

static int hf_homeplug_av_tone_map_tx_cnf          = -1;
static int hf_homeplug_av_tone_map_tx_cnf_status   = -1;
static int hf_homeplug_av_tone_map_tx_cnf_len      = -1;
static int hf_homeplug_av_tone_map_tx_cnf_mac      = -1;
static int hf_homeplug_av_tone_map_tx_cnf_slot     = -1;
static int hf_homeplug_av_tone_map_tx_cnf_num_tms  = -1;
static int hf_homeplug_av_tone_map_tx_cnf_num_act  = -1;

static int hf_homeplug_av_tone_map_rx_cnf          = -1;
static int hf_homeplug_av_tone_map_rx_cnf_status   = -1;
static int hf_homeplug_av_tone_map_rx_cnf_len      = -1;
static int hf_homeplug_av_tone_map_rx_cnf_subver   = -1;
static int hf_homeplug_av_tone_map_rx_cnf_coupling = -1;
static int hf_homeplug_av_tone_map_rx_cnf_mac      = -1;
static int hf_homeplug_av_tone_map_rx_cnf_slot     = -1;
static int hf_homeplug_av_tone_map_rx_cnf_num_tms  = -1;
static int hf_homeplug_av_tone_map_rx_cnf_num_act  = -1;
static int hf_homeplug_av_tone_map_rx_cnf_agc      = -1;
static int hf_homeplug_av_tone_map_rx_cnf_gil      = -1;

static int hf_homeplug_av_tone_map_carriers        = -1;
static int hf_homeplug_av_tone_map_carrier       = -1;
static int hf_homeplug_av_tone_map_carrier_lo    = -1;
static int hf_homeplug_av_tone_map_carrier_hi    = -1;

static int hf_homeplug_av_cc_assoc_reqtype       = -1;
static int hf_homeplug_av_cc_assoc_cco_cap       = -1;
static int hf_homeplug_av_cc_assoc_proxy_net_cap = -1;
static int hf_homeplug_av_cc_assoc_result        = -1;
static int hf_homeplug_av_cc_assoc_nid           = -1;
static int hf_homeplug_av_cc_assoc_snid          = -1;
static int hf_homeplug_av_cc_assoc_tei           = -1;
static int hf_homeplug_av_cc_assoc_lease_time    = -1;

static int hf_homeplug_av_cc_set_tei_map_ind_mode    = -1;
static int hf_homeplug_av_cc_set_tei_map_ind_num     = -1;
static int hf_homeplug_av_cc_set_tei_map_ind_tei     = -1;
static int hf_homeplug_av_cc_set_tei_map_ind_mac     = -1;
static int hf_homeplug_av_cc_set_tei_map_ind_status  = -1;

static int hf_homeplug_av_cm_unassoc_sta_nid     = -1;
static int hf_homeplug_av_cm_unassoc_sta_cco_cap = -1;

/* HPAV/GP fields*/
static int hf_homeplug_av_gp_cm_slac_parm_apptype       = -1;
static int hf_homeplug_av_gp_cm_slac_parm_sectype       = -1;
static int hf_homeplug_av_gp_cm_slac_parm_runid         = -1;
static int hf_homeplug_av_gp_cm_slac_parm_cipher_size   = -1;
static int hf_homeplug_av_gp_cm_slac_parm_cipher        = -1;
static int hf_homeplug_av_gp_cm_slac_parm_sound_target  = -1;
static int hf_homeplug_av_gp_cm_slac_parm_sound_count   = -1;
static int hf_homeplug_av_gp_cm_slac_parm_time_out      = -1;
static int hf_homeplug_av_gp_cm_slac_parm_resptype      = -1;
static int hf_homeplug_av_gp_cm_slac_parm_forwarding_sta= -1;

static int hf_homeplug_av_gp_cm_atten_profile_ind_pev_mac    = -1;
static int hf_homeplug_av_gp_cm_atten_profile_ind_num_groups = -1;
static int hf_homeplug_av_gp_cm_atten_profile_ind_aag        = -1;

static int hf_homeplug_av_gp_cm_atten_char_apptype       = -1;
static int hf_homeplug_av_gp_cm_atten_char_sectype       = -1;
static int hf_homeplug_av_gp_cm_atten_char_source_mac    = -1;
static int hf_homeplug_av_gp_cm_atten_char_runid         = -1;
static int hf_homeplug_av_gp_cm_atten_char_source_id     = -1;
static int hf_homeplug_av_gp_cm_atten_char_resp_id       = -1;
static int hf_homeplug_av_gp_cm_atten_char_numsounds     = -1;
static int hf_homeplug_av_gp_cm_atten_char_numgroups     = -1;
static int hf_homeplug_av_gp_cm_atten_char_aag           = -1;
static int hf_homeplug_av_gp_cm_atten_char_profile       = -1;
static int hf_homeplug_av_gp_cm_atten_char_cms_data      = -1;
static int hf_homeplug_av_gp_cm_atten_char_result        = -1;

static int hf_homeplug_av_gp_cm_start_atten_char_time_out      = -1;
static int hf_homeplug_av_gp_cm_start_atten_char_resptype      = -1;
static int hf_homeplug_av_gp_cm_start_atten_char_forwarding_sta= -1;
static int hf_homeplug_av_gp_cm_start_atten_char_runid         = -1;
static int hf_homeplug_av_gp_cm_start_atten_char_numsounds     = -1;

static int hf_homeplug_av_gp_cm_mnbc_sound_apptype       = -1;
static int hf_homeplug_av_gp_cm_mnbc_sound_sectype       = -1;
static int hf_homeplug_av_gp_cm_mnbc_sound_sender_id     = -1;
static int hf_homeplug_av_gp_cm_mnbc_sound_countdown     = -1;
static int hf_homeplug_av_gp_cm_mnbc_sound_runid         = -1;
static int hf_homeplug_av_gp_cm_mnbc_sound_rsvd          = -1;
static int hf_homeplug_av_gp_cm_mnbc_sound_rnd           = -1;

static int hf_homeplug_av_gp_cm_validate_signaltype       = -1;
static int hf_homeplug_av_gp_cm_validate_timer            = -1;
static int hf_homeplug_av_gp_cm_validate_result           = -1;
static int hf_homeplug_av_gp_cm_validate_togglenum        = -1;

static int hf_homeplug_av_gp_cm_slac_match_apptype       = -1;
static int hf_homeplug_av_gp_cm_slac_match_sectype       = -1;
static int hf_homeplug_av_gp_cm_slac_match_length        = -1;
static int hf_homeplug_av_gp_cm_slac_match_pev_id        = -1;
static int hf_homeplug_av_gp_cm_slac_match_pev_mac       = -1;
static int hf_homeplug_av_gp_cm_slac_match_evse_id       = -1;
static int hf_homeplug_av_gp_cm_slac_match_evse_mac      = -1;
static int hf_homeplug_av_gp_cm_slac_match_runid         = -1;
static int hf_homeplug_av_gp_cm_slac_match_rsvd          = -1;
static int hf_homeplug_av_gp_cm_slac_match_nid           = -1;
static int hf_homeplug_av_gp_cm_slac_match_nmk           = -1;

static int hf_homeplug_av_gp_cm_slac_user_data_broadcast_tlv_type  = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv                 = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv_type            = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv_length          = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv_str_bytes       = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv_oui             = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv_subtype         = -1;
static int hf_homeplug_av_gp_cm_slac_user_data_tlv_info_str        = -1;
/* End of HPAV/GP fields*/

/* ST/IoTecha fields */
static int hf_homeplug_av_st_iotecha_header_rsvd       = -1;
static int hf_homeplug_av_st_iotecha_header_mmever     = -1;
static int hf_homeplug_av_st_iotecha_header_mver       = -1;

static int hf_homeplug_av_st_iotecha_auth_nmk          = -1;
static int hf_homeplug_av_st_iotecha_status_byte       = -1;

static int hf_homeplug_av_st_iotecha_linkstatus_status  = -1;
static int hf_homeplug_av_st_iotecha_linkstatus_devmode = -1;

static int hf_homeplug_av_st_iotecha_stp_discover_tlv                = -1;
static int hf_homeplug_av_st_iotecha_stp_discover_tlv_type           = -1;
static int hf_homeplug_av_st_iotecha_stp_discover_tlv_length         = -1;
static int hf_homeplug_av_st_iotecha_stp_discover_tlv_value_bytes    = -1;
static int hf_homeplug_av_st_iotecha_stp_discover_tlv_value_string   = -1;

static int hf_homeplug_av_st_iotecha_gain_ask           = -1;
static int hf_homeplug_av_st_iotecha_gain_new           = -1;
static int hf_homeplug_av_st_iotecha_gain_prev          = -1;

static int hf_homeplug_av_st_iotecha_mac_address        = -1;

static int hf_homeplug_av_st_iotecha_tei_count          = -1;
static int hf_homeplug_av_st_iotecha_tei                = -1;

static int hf_homeplug_av_st_iotecha_tei_snap_tei                = -1;
static int hf_homeplug_av_st_iotecha_tei_snap_addr_count         = -1;
static int hf_homeplug_av_st_iotecha_tei_snap_mac_address_flag   = -1;

static int hf_homeplug_av_st_iotecha_bss_list_count      = -1;
static int hf_homeplug_av_st_iotecha_bss_entry           = -1;
static int hf_homeplug_av_st_iotecha_bss_type            = -1;
static int hf_homeplug_av_st_iotecha_bss_value_bytes     = -1;

static int hf_homeplug_av_st_iotecha_chanqual_req_type            = -1;
static int hf_homeplug_av_st_iotecha_chanqual_substatus           = -1;
static int hf_homeplug_av_st_iotecha_chanqual_mac_local           = -1;
static int hf_homeplug_av_st_iotecha_chanqual_mac_remote          = -1;
static int hf_homeplug_av_st_iotecha_chanqual_source              = -1;
static int hf_homeplug_av_st_iotecha_chanqual_response_type       = -1;
static int hf_homeplug_av_st_iotecha_chanqual_tmi_count           = -1;
static int hf_homeplug_av_st_iotecha_chanqual_tmi                 = -1;
static int hf_homeplug_av_st_iotecha_chanqual_int                 = -1;
static int hf_homeplug_av_st_iotecha_chanqual_int_count           = -1;
static int hf_homeplug_av_st_iotecha_chanqual_int_et              = -1;
static int hf_homeplug_av_st_iotecha_chanqual_int_tmi             = -1;
static int hf_homeplug_av_st_iotecha_chanqual_tmi_attached        = -1;
static int hf_homeplug_av_st_iotecha_chanqual_fec_type            = -1;
static int hf_homeplug_av_st_iotecha_chanqual_cbld                = -1;
static int hf_homeplug_av_st_iotecha_chanqual_cbld_data_low       = -1;
static int hf_homeplug_av_st_iotecha_chanqual_cbld_data_high      = -1;

static int hf_homeplug_av_st_iotecha_mfct_crc                 = -1;
static int hf_homeplug_av_st_iotecha_mfct_total_length        = -1;
static int hf_homeplug_av_st_iotecha_mfct_offset              = -1;
static int hf_homeplug_av_st_iotecha_mfct_length              = -1;
static int hf_homeplug_av_st_iotecha_mfct_data                = -1;
static int hf_homeplug_av_st_iotecha_mfct_timeout             = -1;
static int hf_homeplug_av_st_iotecha_mfct_request_type        = -1;
static int hf_homeplug_av_st_iotecha_mfct_reboot              = -1;
static int hf_homeplug_av_st_iotecha_mfct_item_offset         = -1;
static int hf_homeplug_av_st_iotecha_mfct_item_total_length   = -1;
static int hf_homeplug_av_st_iotecha_mfct_name                = -1;
static int hf_homeplug_av_st_iotecha_mfct_value               = -1;
static int hf_homeplug_av_st_iotecha_mfct_result              = -1;

static int hf_homeplug_av_st_iotecha_stp_fup_mac_da = -1;
static int hf_homeplug_av_st_iotecha_stp_fup_mac_sa = -1;
static int hf_homeplug_av_st_iotecha_stp_fup_mtype  = -1;

static int hf_homeplug_av_st_iotecha_cpstate_state         = -1;
static int hf_homeplug_av_st_iotecha_cpstate_pwm_duty      = -1;
static int hf_homeplug_av_st_iotecha_cpstate_pwm_freq      = -1;
static int hf_homeplug_av_st_iotecha_cpstate_volatge       = -1;
static int hf_homeplug_av_st_iotecha_cpstate_adc_bitmask   = -1;
static int hf_homeplug_av_st_iotecha_cpstate_adc_voltage_1 = -1;
static int hf_homeplug_av_st_iotecha_cpstate_adc_voltage_2 = -1;
static int hf_homeplug_av_st_iotecha_cpstate_adc_voltage_3 = -1;

static int hf_homeplug_av_st_iotecha_user_message_info     = -1;
static int hf_homeplug_av_st_iotecha_user_message_details  = -1;

static int hf_homeplug_av_st_iotecha_test_type      = -1;
static int hf_homeplug_av_st_iotecha_num_sound      = -1;
static int hf_homeplug_av_st_iotecha_data_ind_addr  = -1;
static int hf_homeplug_av_st_iotecha_agc_lock       = -1;
static int hf_homeplug_av_st_iotecha_db_agc_val     = -1;

static int hf_homeplug_av_st_iotecha_test_status    = -1;
static int hf_homeplug_av_st_iotecha_suppress_data  = -1;

// STP_TEST_CHAN_ATTEN_DATA
static int hf_homeplug_av_st_iotecha_sound_remain  = -1;
static int hf_homeplug_av_st_iotecha_ntb_time      = -1;
static int hf_homeplug_av_st_iotecha_rsvd1         = -1;
static int hf_homeplug_av_st_iotecha_rsvd2         = -1;
static int hf_homeplug_av_st_iotecha_num_segments  = -1;
static int hf_homeplug_av_st_iotecha_segment       = -1;
static int hf_homeplug_av_st_iotecha_num_chan      = -1;
static int hf_homeplug_av_st_iotecha_chan_start    = -1;

/* End of ST/IoTecha fields */

/* Subtrees ett */
static gint ett_homeplug_av                      = -1;
static gint ett_homeplug_av_mmhdr                = -1;
static gint ett_homeplug_av_mmtype               = -1;
static gint ett_homeplug_av_fmi                  = -1;
static gint ett_homeplug_av_vendor               = -1;
static gint ett_homeplug_av_public               = -1;

static gint ett_homeplug_av_fc                   = -1;
static gint ett_homeplug_av_sof                  = -1;
static gint ett_homeplug_av_sack                 = -1;
static gint ett_homeplug_av_rtscts               = -1;
static gint ett_homeplug_av_sound                = -1;
static gint ett_homeplug_av_rsof                 = -1;
static gint ett_homeplug_av_bcn                  = -1;
static gint ett_homeplug_av_bcn_payload          = -1;
static gint ett_homeplug_av_cc_disc_list_cnf     = -1;
static gint ett_homeplug_av_cc_sta_info          = -1;
static gint ett_homeplug_av_cc_net_info          = -1;
static gint ett_homeplug_av_cm_enc_pld_ind       = -1;
static gint ett_homeplug_av_cm_enc_pld_rsp       = -1;
static gint ett_homeplug_av_cm_set_key_req       = -1;
static gint ett_homeplug_av_cm_set_key_cnf       = -1;
static gint ett_homeplug_av_cm_get_key_req       = -1;
static gint ett_homeplug_av_cm_get_key_cnf       = -1;
static gint ett_homeplug_av_brg_infos_cnf        = -1;
static gint ett_homeplug_av_cm_nw_infos_cnf      = -1;
static gint ett_homeplug_av_nw_stats_cnf         = -1;

static gint ett_homeplug_av_get_sw_cnf           = -1;
static gint ett_homeplug_av_wr_mem_req           = -1;
static gint ett_homeplug_av_wr_mem_cnf           = -1;
static gint ett_homeplug_av_rd_mem_req           = -1;
static gint ett_homeplug_av_st_mac_req           = -1;
static gint ett_homeplug_av_st_mac_cnf           = -1;
static gint ett_homeplug_av_rd_mem_cnf           = -1;
static gint ett_homeplug_av_get_nvm_cnf          = -1;
static gint ett_homeplug_av_rs_dev_cnf           = -1;
static gint ett_homeplug_av_wr_mod_req           = -1;
static gint ett_homeplug_av_wr_mod_cnf           = -1;
static gint ett_homeplug_av_wr_mod_ind           = -1;
static gint ett_homeplug_av_rd_mod_req           = -1;
static gint ett_homeplug_av_rd_mod_cnf           = -1;
static gint ett_homeplug_av_mod_nvm_req          = -1;
static gint ett_homeplug_av_mod_nvm_cnf          = -1;
static gint ett_homeplug_av_wd_rpt_req           = -1;
static gint ett_homeplug_av_wd_rpt_ind           = -1;
static gint ett_homeplug_av_lnk_stats_req        = -1;
static gint ett_homeplug_av_lnk_stats_cnf        = -1;
static gint ett_homeplug_av_lnk_stats_tx         = -1;
static gint ett_homeplug_av_lnk_stats_rx         = -1;
static gint ett_homeplug_av_lnk_stats_rx_inv     = -1;
static gint ett_homeplug_av_sniffer_req          = -1;
static gint ett_homeplug_av_sniffer_cnf          = -1;
static gint ett_homeplug_av_sniffer_ind          = -1;
static gint ett_homeplug_av_sniffer_ind_data     = -1;
static gint ett_homeplug_av_nw_info_cnf          = -1;
static gint ett_homeplug_av_nw_info_sta_info     = -1;
static gint ett_homeplug_av_nw_info_net_info     = -1;
static gint ett_homeplug_av_cp_rpt_req           = -1;
static gint ett_homeplug_av_cp_rpt_ind           = -1;
static gint ett_homeplug_av_fr_lbk_req           = -1;
static gint ett_homeplug_av_fr_lbk_cnf           = -1;
static gint ett_homeplug_av_lbk_stat_cnf         = -1;
static gint ett_homeplug_av_set_key_req          = -1;
static gint ett_homeplug_av_set_key_cnf          = -1;
static gint ett_homeplug_av_mfg_string_cnf       = -1;
static gint ett_homeplug_av_rd_cblock_cnf        = -1;
static gint ett_homeplug_av_cblock_hdr           = -1;
static gint ett_homeplug_av_cblock               = -1;
static gint ett_homeplug_av_set_sdram_req        = -1;
static gint ett_homeplug_av_set_sdram_cnf        = -1;
static gint ett_homeplug_av_host_action_ind      = -1;
static gint ett_homeplug_av_host_action_rsp      = -1;
static gint ett_homeplug_av_op_attr_req          = -1;
static gint ett_homeplug_av_op_attr_cnf          = -1;
static gint ett_homeplug_av_op_attr_data         = -1;
static gint ett_homeplug_av_enet_phy_req         = -1;
static gint ett_homeplug_av_enet_phy_cnf         = -1;
static gint ett_homeplug_av_tone_map_tx_req      = -1;
static gint ett_homeplug_av_tone_map_rx_req      = -1;
static gint ett_homeplug_av_tone_map_tx_cnf      = -1;
static gint ett_homeplug_av_tone_map_rx_cnf      = -1;
static gint ett_homeplug_av_tone_map_carriers    = -1;
static gint ett_homeplug_av_tone_map_carrier     = -1;
/* HPGP */
static gint ett_homeplug_av_gp_cm_atten_char_profile = -1;
static gint ett_homeplug_av_gp_cm_slac_user_data_tlv = -1;

/* ST/IoTecha specific subtrees */
static gint ett_homeplug_av_st_iotecha_header            = -1;
static gint ett_homeplug_av_st_iotecha_type_length_value = -1;
static gint ett_homeplug_av_st_iotecha_chanqual_int      = -1;
static gint ett_homeplug_av_st_iotecha_chanqual_cbld     = -1;
static gint ett_homeplug_av_st_iotecha_bss_entry         = -1;
/* End of ST/IoTecha specific subtrees */

/* Saving vendor specific subtree */
static proto_tree *ti_vendor = 0;

#define HOMEPLUG_AV_MMHDR_LEN                   3 /* MM version (1) + MM type (2) */

#define HOMEPLUG_AV_PUBLIC_FRAG_COUNT_MASK  0xF0
#define HOMEPLUG_AV_PUBLIC_FRAG_INDEX_MASK  0x0F

/* MME Values */
/* General MME Types */
typedef enum {
    /* Station - Central Coordinator*/
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_BACKUP_APPOINT_REQ        = 0x0004,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_BACKUP_APPOINT_CNF        = 0x0005,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_REQ             = 0x0008,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_CNF             = 0x0009,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_IND             = 0x000A,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_RSP             = 0x000B,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_REQ              = 0x000C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_CNF              = 0x000D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_INFO_IND         = 0x0012,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_INFO_RSP         = 0x0013,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_REQ         = 0x0014,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_CNF         = 0x0015,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_IND         = 0x0016,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_NEW_REQ              = 0x0018,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_NEW_CNF              = 0x0019,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_MOD_REQ              = 0x001C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_MOD_CNF              = 0x001D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_SQZ_REQ              = 0x0020,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_SQZ_CNF              = 0x0021,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_REL_REQ              = 0x0024,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_REL_IND              = 0x0026,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DETECTC_REPORT_REQ        = 0x0028,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DETECTC_REPORT_CNF        = 0x0029,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_WHO_RU_REQ                = 0x002C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_WHO_RU_CNF                = 0x002D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ASSOC_REQ                 = 0x0030,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ASSOC_CNF                 = 0x0031,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_REQ                 = 0x0034,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_CNF                 = 0x0035,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_IND                 = 0x0036,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_RSP                 = 0x0037,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_SET_TEI_MAP_REQ           = 0x0038,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_SET_TEI_MAP_IND           = 0x003A,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_RELAY_REQ                 = 0x003C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_RELAY_IND                 = 0x003E,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_BEACON_RELIABILITY_REQ    = 0x0040,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_BEACON_RELIABILITY_CNF    = 0x0041,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ALLOC_MOVE_REQ            = 0x0044,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ALLOC_MOVE_CNF            = 0x0045,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_REQ            = 0x0048,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_CNF            = 0x0049,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_IND            = 0x004A,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_RSP            = 0x004B,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_REQ            = 0x004C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_CNF            = 0x004D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_IND            = 0x004E,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_RSP            = 0x004F,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DCPPC_IND                 = 0x0052,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_DCPPC_RSP                 = 0x0053,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_HP1_DET_REQ               = 0x0054,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_HP1_DET_CNF               = 0x0055,
    HOMEPLUG_AV_MMTYPE_GENERAL_CC_BLE_UPDATE_IND            = 0x005A,
    /* HPGP Specific*/
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_BCAST_REPEAT_IND           = 0x005E,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_BCAST_REPEAT_RSP           = 0x005F,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_MH_LINK_NEW_REQ            = 0x0060,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_MH_LINK_NEW_CNF            = 0x0061,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_DETECTION_REPORT_IND   = 0x0066,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_START_RESYNC_REQ       = 0x0068,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_FINISH_RESYNC_REQ      = 0x006C,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_DETECTED_RESYNC_IND    = 0x0072,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_TRANSMIT_RESYNC_REQ    = 0x0074,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_REQ              = 0x0078,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_CNF              = 0x0079,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_EXIT_REQ         = 0x007C,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_EXIT_CNF         = 0x007D,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_LIST_REQ         = 0x0080,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_LIST_CNF         = 0x0081,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_STOP_REQ         = 0x0084,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_STOP_CNF         = 0x0085,
    /* Proxy Coordinator */
    HOMEPLUG_AV_MMTYPE_GENERAL_CP_PROXY_APPOINT_REQ         = 0x2000,
    HOMEPLUG_AV_MMTYPE_GENERAL_CP_PROXY_APPOINT_CNF         = 0x2001,
    HOMEPLUG_AV_MMTYPE_GENERAL_PH_PROXY_APPOINT_IND         = 0x2006,
    HOMEPLUG_AV_MMTYPE_GENERAL_CP_PROXY_WAKE_REQ            = 0x2008,
    /* CCo - CCo */
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_INL_REQ                   = 0x4000,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_INL_CNF                   = 0x4001,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_NEW_NET_REQ               = 0x4004,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_NEW_NET_CNF               = 0x4005,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_NEW_NET_IND               = 0x4006,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_ADD_ALLOC_REQ             = 0x4008,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_ADD_ALLOC_CNF             = 0x4009,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_ADD_ALLOC_IND             = 0x400A,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_REL_ALLOC_REQ             = 0x400C,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_REL_ALLOC_CNF             = 0x400D,
    HOMEPLUG_AV_MMTYPE_GENERAL_NN_REL_NET_IND               = 0x4012,
    /* Station - Station */
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_UNASSOCIATED_STA_IND      = 0x6002,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_ENCRYPTED_PAYLOAD_IND     = 0x6006,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_ENCRYPTED_PAYLOAD_RSP     = 0x6007,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_SET_KEY_REQ               = 0x6008,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_SET_KEY_CNF               = 0x6009,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_KEY_REQ               = 0x600C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_KEY_CNF               = 0x600D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_SC_JOIN_REQ               = 0x6010,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_SC_JOIN_CNF               = 0x6011,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_SC_CHAN_EST_IND           = 0x6016,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_TM_UPDATE_IND             = 0x601A,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_AMP_MAP_REQ               = 0x601C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_AMP_MAP_CNF               = 0x601D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_BRG_INFO_REQ              = 0x6020,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_BRG_INFO_CNF              = 0x6021,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_NEW_REQ              = 0x6024,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_NEW_CNF              = 0x6025,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_REL_IND              = 0x602A,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_REL_RSP              = 0x602B,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_MOD_REQ              = 0x602C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_MOD_CNF              = 0x602D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_INFO_REQ             = 0x6030,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_INFO_CNF             = 0x6031,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_STA_CAP_REQ               = 0x6034,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_STA_CAP_CNF               = 0x6035,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_INFO_REQ               = 0x6038,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_INFO_CNF               = 0x6039,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_BEACON_REQ            = 0x603C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_BEACON_CNF            = 0x603D,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_HFID_REQ                  = 0x6040,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_HFID_CNF                  = 0x6041,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_MME_ERROR_IND             = 0x6046,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_STATS_REQ              = 0x6048,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_STATS_CNF              = 0x6049,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_LINK_STATS_REQ            = 0x604C,
    HOMEPLUG_AV_MMTYPE_GENERAL_CM_LINK_STATS_CNF            = 0x604D,
    /* HPGP Specific*/
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ROUTE_INFO_REQ             = 0x6050,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ROUTE_INFO_CNF             = 0x6051,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ROUTE_INFO_IND             = 0x6052,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_UNREACHABLE_IND            = 0x6056,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MH_CONN_NEW_REQ            = 0x6058,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MH_CONN_NEW_CNF            = 0x6059,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_EXTENDED_TONEMASK_REQ      = 0x605C,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_EXTENDED_TONEMASK_CNF      = 0x605D,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_REQ          = 0x6060,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_CNF          = 0x6061,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_IND          = 0x6062,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_RSP          = 0x6063,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_PARM_REQ              = 0x6064,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_PARM_CNF              = 0x6065,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_START_ATTEN_CHAR_IND       = 0x606A,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_CHAR_IND             = 0x606E,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_CHAR_RSP             = 0x606F,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_REQ              = 0x6070,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_CNF              = 0x6071,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_IND              = 0x6072,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_RSP              = 0x6073,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MNBC_SOUND_IND             = 0x6076,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_VALIDATE_REQ               = 0x6078,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_VALIDATE_CNF               = 0x6079,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_MATCH_REQ             = 0x607C,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_MATCH_CNF             = 0x607D,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_USER_DATA_REQ         = 0x6080,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_USER_DATA_CNF         = 0x6081,
    HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_PROFILE_IND          = 0x6086,
} homeplug_av_mmetypes_general_type;

/* QCA MME Types */
typedef enum {
    HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_SW_REQ        = 0xA000,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_SW_CNF        = 0xA001,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MEM_REQ        = 0xA004,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MEM_CNF        = 0xA005,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MEM_REQ        = 0xA008,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MEM_CNF        = 0xA009,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_ST_MAC_REQ        = 0xA00C,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_ST_MAC_CNF        = 0xA00D,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_NVM_REQ       = 0xA010,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_NVM_CNF       = 0xA011,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RS_DEV_REQ        = 0xA01C,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RS_DEV_CNF        = 0xA01D,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_REQ        = 0xA020,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_CNF        = 0xA021,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_IND        = 0xA022,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MOD_REQ        = 0xA024,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MOD_CNF        = 0xA025,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_NVM_MOD_REQ       = 0xA028,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_NVM_MOD_CNF       = 0xA029,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WD_RPT_REQ        = 0xA02C,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_WD_RPT_IND        = 0xA02E,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_LNK_STATS_REQ     = 0xA030,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_LNK_STATS_CNF     = 0xA031,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_REQ       = 0xA034,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_CNF       = 0xA035,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_IND       = 0xA036,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_NW_INFO_REQ       = 0xA038,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_NW_INFO_CNF       = 0xA039,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_CP_RPT_REQ        = 0xA040,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_CP_RPT_IND        = 0xA042,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_FR_LBK_REQ        = 0xA048,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_FR_LBK_CNF        = 0xA049,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_LBK_STAT_REQ      = 0xA04C,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_LBK_STAT_CNF      = 0xA04D,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_KEY_REQ       = 0xA050,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_KEY_CNF       = 0xA051,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_MFG_STRING_REQ    = 0xA054,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_MFG_STRING_CNF    = 0xA055,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_CBLOCK_REQ     = 0xA058,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_CBLOCK_CNF     = 0xA059,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_SDRAM_REQ     = 0xA05C,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_SDRAM_CNF     = 0xA05D,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_HOST_ACTION_IND   = 0xA062,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_HOST_ACTION_RSP   = 0xA063,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_OP_ATTR_REQ       = 0xA068,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_OP_ATTR_CNF       = 0xA069,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_ENET_PHY_REQ  = 0xA06C,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_ENET_PHY_CNF  = 0xA06D,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_TX_REQ   = 0xA070,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_TX_CNF   = 0xA071,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_RX_REQ   = 0xA090,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_RX_CNF   = 0xA091,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_LINK_STATUS_REQ   = 0xA0B8,
    HOMEPLUG_AV_MMTYPE_QUALCOMM_LINK_STATUS_CNF   = 0xA0B9,
} homeplug_av_mmetypes_qualcomm_type;

/* ST/IoTecha MME Types */
typedef enum {
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_AUTH_SET_NMK_REQ             = 0x8000,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_AUTH_SET_NMK_CNF             = 0x8001,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_REQ              = 0x8004,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_CNF              = 0x8005,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_IND              = 0x8006,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_LOCAL_REQ           = 0x8008,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_LOCAL_CNF           = 0x8009,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_SET_MAXGAIN_REQ              = 0x800C,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_SET_MAXGAIN_CNF              = 0x800D,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_REQ                 = 0xA000,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_CNF                 = 0xA001,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_LIST_REQ             = 0xA00C,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_LIST_CNF             = 0xA00D,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_SNAPSHOT_REQ         = 0xA010,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_SNAPSHOT_CNF         = 0xA011,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_BSS_LIST_REQ             = 0xA014,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_BSS_LIST_CNF             = 0xA015,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_REQ          = 0xA018,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_CNF          = 0xA019,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_IND          = 0xA01A,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_REQ = 0xA100,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_CNF = 0xA101,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_DATA_IND     = 0xA106,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_REQ = 0xA108,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_CNF = 0xA109,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_SOUND_QUIET_IND         = 0xA10E,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_STAGE_REQ        = 0xA200,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_STAGE_CNF        = 0xA201,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_FINISH_REQ       = 0xA204,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_FINISH_CNF       = 0xA205,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_ITEM_REQ            = 0xA208,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_ITEM_CNF            = 0xA209,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_KEYLIST_REQ         = 0xA20C,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_KEYLIST_CNF         = 0xA20D,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_FUP_REQ                      = 0xA210,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_RESERVED_REQ                 = 0xA214,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CPSTATE_IND                  = 0xA22E,
    HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_USER_MESSAGE_IND             = 0xA232,
} homeplug_av_mmetypes_st_iotecha_type;

/* Vendors OUI */
#define HOMEPLUG_AV_OUI_NONE               0
#define HOMEPLUG_AV_OUI_QCA                0x00B052
#define HOMEPLUG_AV_OUI_ST_IOTECHA         0x0080E1

static const value_string homeplug_av_vendors_oui_vals[] = {
    { HOMEPLUG_AV_OUI_QCA,              "Qualcomm Atheros" },
    { HOMEPLUG_AV_OUI_ST_IOTECHA,       "ST/IoTecha" },
    { 0, NULL }
};

/* Packet names */
/* Public MMEs */
static const value_string homeplug_av_mmtype_general_vals[] = {
    /* Station - Central Coordinator*/
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_BACKUP_APPOINT_REQ             , "CC_BACKUP_APPOINT.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_BACKUP_APPOINT_CNF             , "CC_BACKUP_APPOINT.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_REQ                  , "CC_LINK_INFO.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_CNF                  , "CC_LINK_INFO.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_IND                  , "CC_LINK_INFO.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_INFO_RSP                  , "CC_LINK_INFO.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_REQ                   , "CC_HANDOVER.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_CNF                   , "CC_HANDOVER.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_INFO_IND              , "CC_HANDOVER_INFO.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_HANDOVER_INFO_RSP              , "CC_HANDOVER_INFO.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_REQ              , "CC_DISCOVER_LIST.REQ (Central Coordination Discovery List Request)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_CNF              , "CC_DISCOVER_LIST.CNF (Central Coordination Discovery List Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_IND              , "CC_DISCOVER_LIST.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_NEW_REQ                   , "CC_LINK_NEW.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_NEW_CNF                   , "CC_LINK_NEW.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_MOD_REQ                   , "CC_LINK_MOD.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_MOD_CNF                   , "CC_LINK_MOD.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_SQZ_REQ                   , "CC_LINK_SQZ.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_SQZ_CNF                   , "CC_LINK_SQZ.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_REL_REQ                   , "CC_LINK_REL.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LINK_REL_IND                   , "CC_LINK_REL.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DETECTC_REPORT_REQ             , "CC_DETECTC_REPORT.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DETECTC_REPORT_CNF             , "CC_DETECTC_REPORT.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_WHO_RU_REQ                     , "CC_WHO_RU.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_WHO_RU_CNF                     , "CC_WHO_RU.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ASSOC_REQ                      , "CC_ASSOC.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ASSOC_CNF                      , "CC_ASSOC.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_REQ                      , "CC_LEAVE.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_CNF                      , "CC_LEAVE.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_IND                      , "CC_LEAVE.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_LEAVE_RSP                      , "CC_LEAVE.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_SET_TEI_MAP_REQ                , "CC_SET_TEI_MAP.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_SET_TEI_MAP_IND                , "CC_SET_TEI_MAP.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_RELAY_REQ                      , "CC_RELAY.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_RELAY_IND                      , "CC_RELAY.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_BEACON_RELIABILITY_REQ         , "CC_BEACON_RELIABILITY.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_BEACON_RELIABILITY_CNF         , "CC_BEACON_RELIABILITY.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ALLOC_MOVE_REQ                 , "CC_ALLOC_MOVE.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ALLOC_MOVE_CNF                 , "CC_ALLOC_MOVE.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_REQ                 , "CC_ACCESS_NEW.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_CNF                 , "CC_ACCESS_NEW.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_IND                 , "CC_ACCESS_NEW.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_NEW_RSP                 , "CC_ACCESS_NEW.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_REQ                 , "CC_ACCESS_REL.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_CNF                 , "CC_ACCESS_REL.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_IND                 , "CC_ACCESS_REL.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_ACCESS_REL_RSP                 , "CC_ACCESS_REL.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DCPPC_IND                      , "CC_DCPPC.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_DCPPC_RSP                      , "CC_DCPPC.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_HP1_DET_REQ                    , "CC_HP1_DET.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_HP1_DET_CNF                    , "CC_HP1_DET.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CC_BLE_UPDATE_IND                 , "CC_BLE_UPDATE.IND" },
    /* HPGP Specific*/
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_BCAST_REPEAT_IND            , "CC_BCAST_REPEAT.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_BCAST_REPEAT_RSP            , "CC_BCAST_REPEAT.RSP" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_MH_LINK_NEW_REQ             , "CC_MH_LINK_NEW.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_MH_LINK_NEW_CNF             , "CC_MH_LINK_NEW.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_DETECTION_REPORT_IND    , "CC_ISP_DETECTION_REPORT.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_START_RESYNC_REQ        , "CC_ISP_START_RESYNC.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_FINISH_RESYNC_REQ       , "CC_ISP_FINISH_RESYNC.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_DETECTED_RESYNC_IND     , "CC_ISP_DETECTED_RESYNC.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_ISP_TRANSMIT_RESYNC_REQ     , "CC_ISP_TRANSMIT_RESYNC.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_REQ               , "CC_POWERSAVE.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_CNF               , "CC_POWERSAVE.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_EXIT_REQ          , "CC_POWERSAVE_EXIT.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_EXIT_CNF          , "CC_POWERSAVE_EXIT.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_LIST_REQ          , "CC_POWERSAVE_LIST.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_LIST_CNF          , "CC_POWERSAVE_LIST.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_STOP_REQ          , "CC_POWERSAVE_STOP.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CC_POWERSAVE_STOP_CNF          , "CC_POWERSAVE_STOP.CNF" },
    /* Proxy Coordinator */
    { HOMEPLUG_AV_MMTYPE_GENERAL_CP_PROXY_APPOINT_REQ              , "CP_PROXY_APPOINT.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CP_PROXY_APPOINT_CNF              , "CP_PROXY_APPOINT.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_PH_PROXY_APPOINT_IND              , "PH_PROXY_APPOINT.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CP_PROXY_WAKE_REQ                 , "CP_PROXY_WAKE.REQ" },
    /* CCo - CCo */
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_INL_REQ                        , "NN_INL.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_INL_CNF                        , "NN_INL.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_NEW_NET_REQ                    , "NN_NEW_NET.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_NEW_NET_CNF                    , "NN_NEW_NET.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_NEW_NET_IND                    , "NN_NEW_NET.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_ADD_ALLOC_REQ                  , "NN_ADD_ALLOC.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_ADD_ALLOC_CNF                  , "NN_ADD_ALLOC.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_ADD_ALLOC_IND                  , "NN_ADD_ALLOC.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_REL_ALLOC_REQ                  , "NN_REL_ALLOC.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_REL_ALLOC_CNF                  , "NN_REL_ALLOC.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_NN_REL_NET_IND                    , "NN_REL_NET.IND" },
    /* Station - Station */
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_UNASSOCIATED_STA_IND           , "CM_UNASSOCIATED_STA.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_ENCRYPTED_PAYLOAD_IND          , "CM_ENCRYPTED_PAYLOAD.IND (Encrypted Payload Indicate)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_ENCRYPTED_PAYLOAD_RSP          , "CM_ENCRYPTED_PAYLOAD.RSP (Encrypted Payload Respons)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_SET_KEY_REQ                    , "CM_SET_KEY.REQ (Set Key Request)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_SET_KEY_CNF                    , "CM_SET_KEY.CNF (Set Key Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_KEY_REQ                    , "CM_GET_KEY.REQ (Get Key Request)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_KEY_CNF                    , "CM_GET_KEY.CNF (Get Key Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_SC_JOIN_REQ                    , "CM_SC_JOIN.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_SC_JOIN_CNF                    , "CM_SC_JOIN.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_SC_CHAN_EST_IND                , "CM_SC_CHAN_EST.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_TM_UPDATE_IND                  , "CM_TM_UPDATE.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_AMP_MAP_REQ                    , "CM_AMP_MAP.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_AMP_MAP_CNF                    , "CM_AMP_MAP.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_BRG_INFO_REQ                   , "CM_BRG_INFO.REQ (Get Bridge Informations Request)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_BRG_INFO_CNF                   , "CM_BRG_INFO.CNF (Get Bridge Informations Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_NEW_REQ                   , "CM_CONN_NEW.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_NEW_CNF                   , "CM_CONN_NEW.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_REL_IND                   , "CM_CONN_REL.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_REL_RSP                   , "CM_CONN_REL.RSP" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_MOD_REQ                   , "CM_CONN_MOD.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_MOD_CNF                   , "CM_CONN_MOD.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_INFO_REQ                  , "CM_CONN_INFO.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_CONN_INFO_CNF                  , "CM_CONN_INFO.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_STA_CAP_REQ                    , "CM_STA_CAP.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_STA_CAP_CNF                    , "CM_STA_CAP.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_INFO_REQ                    , "CM_NW_INFO.REQ (Get Network Informations Request)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_INFO_CNF                    , "CM_NW_INFO.CNF (Get Network Informations Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_BEACON_REQ                 , "CM_GET_BEACON.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_BEACON_CNF                 , "CM_GET_BEACON.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_HFID_REQ                       , "CM_HFID.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_HFID_CNF                       , "CM_HFID.CNF" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_MME_ERROR_IND                  , "CM_MME_ERROR.IND" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_STATS_REQ                   , "CM_NW_STATS.REQ (Get Network Statistics Request)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_STATS_CNF                   , "CM_NW_STATS.CNF (Get Network Statistics Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_LINK_STATS_REQ                 , "CM_LINK_STATS.REQ" },
    { HOMEPLUG_AV_MMTYPE_GENERAL_CM_LINK_STATS_CNF                 , "CM_LINK_STATS.CNF" },
    /* HPGP Specific*/
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ROUTE_INFO_REQ              , "CM_ROUTE_INFO.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ROUTE_INFO_CNF              , "CM_ROUTE_INFO.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ROUTE_INFO_IND              , "CM_ROUTE_INFO.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_UNREACHABLE_IND             , "CM_UNREACHABLE.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MH_CONN_NEW_REQ             , "CM_MH_CONN_NEW.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MH_CONN_NEW_CNF             , "CM_MH_CONN_NEW.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_EXTENDED_TONEMASK_REQ       , "CM_EXTENDED_TONEMASK.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_EXTENDED_TONEMASK_CNF       , "CM_EXTENDED_TONEMASK.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_REQ           , "CM_STA_INDENTIFY.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_CNF           , "CM_STA_INDENTIFY_CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_IND           , "CM_STA_INDENTIFY.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_STA_INDENTIFY_RSP           , "CM_STA_INDENTIFY.RSP" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_PARM_REQ               , "CM_SLAC_PARM.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_PARM_CNF               , "CM_SLAC_PARM.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_START_ATTEN_CHAR_IND        , "CM_START_ATTEN_CHAR.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_CHAR_IND              , "CM_ATTEN_CHAR.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_CHAR_RSP              , "CM_ATTEN_CHAR.RSP" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_REQ               , "CM_PKCS_CERT.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_CNF               , "CM_PKCS_CERT.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_IND               , "CM_PKCS_CERT.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_PKCS_CERT_RSP               , "CM_PKCS_CERT.RSP" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MNBC_SOUND_IND              , "CM_MNBC_SOUND.IND" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_VALIDATE_REQ                , "CM_VALIDATE.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_VALIDATE_CNF                , "CM_VALIDATE.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_MATCH_REQ              , "CM_SLAC_MATCH.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_MATCH_CNF              , "CM_SLAC_MATCH.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_USER_DATA_REQ          , "CM_SLAC_USER_DATA.REQ" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_USER_DATA_CNF          , "CM_SLAC_USER_DATA.CNF" },
    { HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_PROFILE_IND           , "CM_ATTEN_PROFILE.IND" },
    { 0, NULL }
};

/* QCA vendor-specific MMEs */
static const value_string homeplug_av_mmtype_qualcomm_vals[] = {
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_SW_REQ,        "GET_SW.REQ (Get Device/SW Version Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_SW_CNF,        "GET_SW.CNF (Get Device/SW Version Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MEM_REQ,        "WR_MEM.REQ (Write MAC Memory Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MEM_CNF,        "WR_MEM.CNF (Write MAC Memory Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MEM_REQ,        "RD_MEM.REQ (Read MAC Memory Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MEM_CNF,        "RD_MEM.CNF (Read MAC Memory Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_ST_MAC_REQ,        "ST_MAC.REQ (Start MAC Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_ST_MAC_CNF,        "ST_MAC.CNF (Start MAC Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_NVM_REQ,       "GET_NVM.REQ (Get NVM Parameters Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_NVM_CNF,       "GET_NVM.CNF (Get NVM Parameters Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RS_DEV_REQ,        "RS_DEV.REQ (Reset Device Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RS_DEV_CNF,        "RS_DEV.CNF (Reset Device Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_REQ,        "WR_MOD.REQ (Write Module Data Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_CNF,        "WR_MOD.CNF (Write Module Data Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_IND,        "WR_MOD.IND (Write Module Data Indicate)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MOD_REQ,        "RD_MOD.REQ (Read Module Data Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MOD_CNF,        "RD_MOD.CNF (Read Module Data Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_NVM_MOD_REQ,       "NVM_MOD.REQ (Write Module Data to NVM Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_NVM_MOD_CNF,       "NVM_MOD.CNF (Write Module Data to NVM Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WD_RPT_REQ,        "WD_RPT.REQ (Get Watchdog Report Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_WD_RPT_IND,        "WD_RPT.IND (Get Watchdog Report Indicate)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_LNK_STATS_REQ,     "LNK_STATS.REQ (Link Statistics Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_LNK_STATS_CNF,     "LNK_STATS.CNF (Link Statistics Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_REQ,       "SNIFFER.REQ (Sniffer Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_CNF,       "SNIFFER.CNF (Sniffer Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_IND,       "SNIFFER.IND (Sniffer Indicate)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_NW_INFO_REQ,       "NW_INFO.REQ (Network Info Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_NW_INFO_CNF,       "NW_INFO.CNF (Network Info Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_CP_RPT_REQ,        "CP_RPT.REQ (Check Points Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_CP_RPT_IND,        "CP_RPT.IND (Check Points Indicate)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_FR_LBK_REQ,        "FR_LBK.REQ (Loopback Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_FR_LBK_CNF,        "FR_LBK.CNF (Loopback Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_LBK_STAT_REQ,      "LBK_STAT.REQ (Loopback Status Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_LBK_STAT_CNF,      "LBK_STAT.CNF (Loopback Status Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_KEY_REQ,       "SET_KEY.REQ (Set Encryption Key Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_KEY_CNF,       "SET_KEY.CNF (Set Encryption Key Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_MFG_STRING_REQ,    "MFG_STRING.REQ (Get Manufacturer String Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_MFG_STRING_CNF,    "MFG_STRING.CNF (Get Manufacturer String Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_CBLOCK_REQ,     "RD_CBLOCK.REQ (Read Configuration Block Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_CBLOCK_CNF,     "RD_CBLOCK.CNF (Read Configuration Block Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_SDRAM_REQ,     "SET_SDRAM.REQ (Set SDRAM Configuration Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_SDRAM_CNF,     "SET_SDRAM.CNF (Set SDRAM Configuration Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_HOST_ACTION_IND,   "HOST_ACTION.IND (Embedded Host Action Required Indication)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_HOST_ACTION_RSP,   "HOST_ACTION.RSP (Embedded Host Action Required Respons)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_OP_ATTR_REQ,       "OP_ATTR.REQ (Get Device Attributes Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_OP_ATTR_CNF,       "OP_ATTR.CNF (Get Device Attributes Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_ENET_PHY_REQ,  "GET_ENET_PHY.REQ (Get Ethernet PHY Settings Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_ENET_PHY_CNF,  "GET_ENET_PHY.CNF (Get Ethernet PHY Settings Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_TX_REQ,   "TONE_MAP_TX.REQ (Tone Map Tx Characteristics Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_TX_CNF,   "TONE_MAP_TX.CNF (Tone Map Tx Characteristics Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_RX_REQ,   "TONE_MAP_RX.REQ (Tone Map Rx Characteristics Request)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_RX_CNF,   "TONE_MAP_RX.CNF (Tone Map Rx Characteristics Confirmation)" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_LINK_STATUS_REQ,   "LINK_STATUS.REQ" },
    { HOMEPLUG_AV_MMTYPE_QUALCOMM_LINK_STATUS_CNF,   "LINK_STATUS.CNF" },
    { 0, NULL }
};

/* ST/IoTecha vendor-specific MMEs */
static const value_string homeplug_av_mmtype_st_iotecha_vals[] = {
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_AUTH_SET_NMK_REQ ,             "STP_AUTH_SET_NMK.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_AUTH_SET_NMK_CNF ,             "STP_AUTH_SET_NMK.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_REQ ,              "STP_LINK_STATUS.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_CNF ,              "STP_LINK_STATUS.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_IND ,              "STP_LINK_STATUS.IND" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_LOCAL_REQ ,           "STP_DISCOVER_LOCAL.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_LOCAL_CNF ,           "STP_DISCOVER_LOCAL.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_SET_MAXGAIN_REQ ,              "STP_SET_MAXGAIN.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_SET_MAXGAIN_CNF ,              "STP_SET_MAXGAIN.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_REQ ,                 "STP_DISCOVER.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_CNF ,                 "STP_DISCOVER.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_LIST_REQ ,             "STP_GET_TEI_LIST.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_LIST_CNF ,             "STP_GET_TEI_LIST.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_SNAPSHOT_REQ ,         "STP_GET_TEI_SNAPSHOT.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_SNAPSHOT_CNF ,         "STP_GET_TEI_SNAPSHOT.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_BSS_LIST_REQ ,             "STP_GET_BSS_LIST.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_BSS_LIST_CNF ,             "STP_GET_BSS_LIST.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_REQ ,          "STP_CHANQUAL_REPORT.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_CNF ,          "STP_CHANQUAL_REPORT.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_IND ,          "STP_CHANQUAL_REPORT.IND" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_REQ , "STP_TEST_CHAN_ATTEN_START_RX.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_CNF , "STP_TEST_CHAN_ATTEN_START_RX.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_DATA_IND ,     "STP_TEST_CHAN_ATTEN_DATA.IND" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_REQ , "STP_TEST_CHAN_ATTEN_START_TX.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_CNF , "STP_TEST_CHAN_ATTEN_START_TX.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_SOUND_QUIET_IND ,         "STP_TEST_SOUND_QUIET.IND" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_STAGE_REQ ,        "STP_MFCT_UPDATE_STAGE.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_STAGE_CNF ,        "STP_MFCT_UPDATE_STAGE.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_FINISH_REQ ,       "STP_MFCT_UPDATE_FINISH.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_FINISH_CNF ,       "STP_MFCT_UPDATE_FINISH.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_ITEM_REQ ,            "STP_MFCT_GET_ITEM.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_ITEM_CNF ,            "STP_MFCT_GET_ITEM.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_KEYLIST_REQ ,         "STP_MFCT_GET_KEYLIST.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_KEYLIST_CNF ,         "STP_MFCT_GET_KEYLIST.CNF" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_FUP_REQ ,                      "STP_FUP.REQ" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_RESERVED_REQ ,                 "STP_RESERVED.REQ (IoTecha HPGP Analyzer Raw Data)" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CPSTATE_IND ,                  "STP_CPSTATE.IND" },
    { HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_USER_MESSAGE_IND ,             "STP_USER_MESSAGE.IND" },
    { 0, NULL }
};

/* ext MMType vals */
static value_string_ext homeplug_av_mmtype_general_vals_ext = VALUE_STRING_EXT_INIT(homeplug_av_mmtype_general_vals);
static value_string_ext homeplug_av_mmtype_qualcomm_vals_ext = VALUE_STRING_EXT_INIT(homeplug_av_mmtype_qualcomm_vals);
static value_string_ext homeplug_av_mmtype_st_iotecha_vals_ext = VALUE_STRING_EXT_INIT(homeplug_av_mmtype_st_iotecha_vals);

/* Versions */
#define HOMEPLUG_AV_MMVER_MASK      0x01
#define HOMEPLUG_AV_MMVER_1_0       0x00
#define HOMEPLUG_AV_MMVER_1_1       0x01

static const value_string homeplug_av_mmver_vals[] = {
    { HOMEPLUG_AV_MMVER_1_0, "1.0" },
    { HOMEPLUG_AV_MMVER_1_1, "1.1" },
    { 0, NULL }
};

/* MMTYPE LSB Values */
#define HOMEPLUG_AV_MMTYPE_LSB_MASK 0x03

static const value_string homeplug_av_mmtype_lsb_vals[] = {
    { 0x00, "Request" },
    { 0x01, "Confirm" },
    { 0x02, "Indication" },
    { 0x03, "Response" },
    { 0, NULL }
};

/* MMTYPE MSB Values */
#define HOMEPLUG_AV_MMTYPE_MSB_STA_CCO    0x00
#define HOMEPLUG_AV_MMTYPE_MSB_PROXY      0x01
#define HOMEPLUG_AV_MMTYPE_MSB_CCO_CCO    0x02
#define HOMEPLUG_AV_MMTYPE_MSB_STA_STA    0x03
#define HOMEPLUG_AV_MMTYPE_MSB_MANUF      0x04
#define HOMEPLUG_AV_MMTYPE_MSB_VENDOR     0x05
#define HOMEPLUG_AV_MMTYPE_MSB_RSV        0x06
#define HOMEPLUG_AV_MMTYPE_MSB_MASK       0xe0
#define HOMEPLUG_AV_MMTYPE_MSB_SHIFT      (5)

static const value_string homeplug_av_mmtype_msb_vals[] = {
    { HOMEPLUG_AV_MMTYPE_MSB_STA_CCO, "STA - Central Coordinator" },
    { HOMEPLUG_AV_MMTYPE_MSB_PROXY,   "Proxy Coordinator" },
    { HOMEPLUG_AV_MMTYPE_MSB_CCO_CCO, "Central Coordinator - Central Coordinator" },
    { HOMEPLUG_AV_MMTYPE_MSB_STA_STA, "STA - STA" },
    { HOMEPLUG_AV_MMTYPE_MSB_MANUF,   "Manufacturer Specific" },
    { HOMEPLUG_AV_MMTYPE_MSB_VENDOR,  "Vendor Specific" },
    { 0, NULL }
};

#define HOMEPLUG_AV_CC_STA_NET_MASK 0x01

static const value_string homeplug_av_cc_sta_net_type_vals[] = {
    { 0x00, "Different network" },
    { 0x01, "Same network" },
    { 0, NULL }
};

static const value_string homeplug_av_sig_level_vals[] = {
    { 0x00,    "N/A" },
    { 0x01,    "> - 10 dB, but <= 0 dB" },
    { 0x02,    "> - 15 dB, but <= -10 dB" },
    { 0x03,    "> - 20 dB, but <= -15 dB" },
    { 0x04,    "> - 25 dB, but <= -20 dB" },
    { 0x05,    "> - 30 dB, but <= -25 dB" },
    { 0x06,    "> - 35 dB, but <= -30 dB" },
    { 0x07,    "> - 40 dB, but <= -35 dB" },
    { 0x08,    "> - 45 dB, but <= -40 dB" },
    { 0x09,    "> - 50 dB, but <= -45 dB" },
    { 0x0A,    "> - 55 dB, but <= -50 dB" },
    { 0x0B,    "> - 60 dB, but <= -55 dB" },
    { 0x0C,    "> - 65 dB, but <= -60 dB" },
    { 0x0D,    "> - 70 dB, but <= -65 dB" },
    { 0x0E,    "> - 75 dB, but <= -70 dB" },
    { 0x0F,    "<= -75 dB" },
    { 0, NULL }
};
static value_string_ext homeplug_av_sig_level_vals_ext = VALUE_STRING_EXT_INIT(homeplug_av_sig_level_vals);

#define HOMEPLUG_AV_CCO_STATUS_MASK 0x07

static const value_string homeplug_av_cco_status_vals[] = {
    { 0x00, "Unknown" },
    { 0x01, "Non-coordinating Network" },
    { 0x02, "Coordinating, group status unknown" },
    { 0x03, "Coordinating network in the same group" },
    { 0x04, "Coordinating network not in the same group" },
    { 0, NULL }
};

#define HOMEPLUG_AV_NW_INFO_ROLE_MASK 0x03

static const value_string homeplug_av_nw_info_role_vals[] = {
    { 0x00, "Station" },
    { 0x01, "Proxy coordinator" },
    { 0x02, "Central coordinator" },
    { 0, NULL }
};

#define HOMEPLUG_AV_NW_INFO_NID_MASK    0x01
#define HOMEPLUG_AV_NW_INFO_ACCESS_MASK 0x08

static const value_string homeplug_nw_info_access_vals[] = {
    { 0x00, "In-home" },
    { 0x01, "Access" },
    { 0, NULL }
};

#define HOMEPLUG_AV_PEKS_MASK     0x0F
#define HOMEPLUG_AV_SOF_PEKS_MASK 0xF0

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
static value_string_ext homeplug_av_peks_vals_ext = VALUE_STRING_EXT_INIT(homeplug_av_peks_vals);

#define HOMEPLUG_AV_CCO_CAP_MASK        0x0C

static const value_string homeplug_av_bcn_cco_cap_vals[] = {
    { 0x0, "CSMA-only (no QoS/TDMA)" },
    { 0x1, "Uncoordinated mode QoS/TDMA" },
    { 0x2, "Coordianted mode QoS/TDMA" },
    { 0x3, "Reserved" },
    { 0, NULL }
};

#define HOMEPLUG_AV_AVLN_STATUS_MASK    0x0F
#define HOMEPLUG_AV_RSF_MASK            0x10
#define HOMEPLUG_AV_PLEVEL_MASK         0xE0

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

#define HOMEPLUG_AV_PID_AUTH_STA       0x00
#define HOMEPLUG_AV_PID_PROV_AUTH_NEK  0x01
#define HOMEPLUG_AV_PID_PROV_AUTH_DAK  0x02
#define HOMEPLUG_AV_PID_PROV_AUTH_UKE  0x03
#define HOMEPLUG_AV_PID_HLE            0x04
#define HOMEPLUG_AV_PID_MASK           0x07

static const value_string homeplug_av_pid_vals[] = {
    { HOMEPLUG_AV_PID_AUTH_STA,        "Authentication request by new STA" },
    { HOMEPLUG_AV_PID_PROV_AUTH_NEK,   "Provision authenticated STA with new NEK by CCo" },
    { HOMEPLUG_AV_PID_PROV_AUTH_DAK,   "Provision STA with NMK using DAK" },
    { HOMEPLUG_AV_PID_PROV_AUTH_UKE,   "Provision STA with NMK using UKE" },
    { HOMEPLUG_AV_PID_HLE,             "HLE" },
    { 0, NULL }
};

#define HOMEPLUG_AV_KEY_TYPE_DAK    0x00
#define HOMEPLUG_AV_KEY_TYPE_NMK    0x01
#define HOMEPLUG_AV_KEY_TYPE_NEK    0x02
#define HOMEPLUG_AV_KEY_TYPE_TEK    0x03
#define HOMEPLUG_AV_KEY_TYPE_HASH   0x04
#define HOMEPLUG_AV_KEY_TYPE_NONE   0x05
#define HOMEPLUG_AV_KEY_TYPE_MASK   0x07

static const value_string homeplug_av_key_type_vals[] = {
    { HOMEPLUG_AV_KEY_TYPE_DAK,    "DAK" },
    { HOMEPLUG_AV_KEY_TYPE_NMK,    "NMK" },
    { HOMEPLUG_AV_KEY_TYPE_NEK,    "NEK" },
    { HOMEPLUG_AV_KEY_TYPE_TEK,    "TEK" },
    { HOMEPLUG_AV_KEY_TYPE_HASH,   "Hash Key" },
    { HOMEPLUG_AV_KEY_TYPE_NONE,   "Nonce only (no key)" },
    { 0, NULL }
};

#define HOMEPLUG_AV_DEV_ID_MASK 0xff

static const value_string homeplug_av_dev_id_vals[] = {
    { 0x00, "Unknown" },
    { 0x01, "INT6000" },
    { 0x02, "INT6300" },
    { 0x03, "INT6400" },
    { 0x04, "AR7400" },
    { 0x05, "AR6405" },
    { 0x20, "QCA7450/QCA7420" },
    { 0x21, "QCA6410/QCA6411" },
    { 0x22, "QCA7000" },
    { 0, NULL }
};

#define HOMEPLUG_AV_REQ_TYPE_MASK 0x01

static const value_string homeplug_av_req_type_vals[] = {
    { 0x00, "Direct" },
    { 0x01, "Relayed" },
    { 0, NULL }
};

#define HOMEPLUG_AV_KEY_RESULT_MASK 0x03

static const value_string homeplug_av_key_result_vals[] = {
    { 0x00, "Key granted" },
    { 0x01, "Request refused" },
    { 0x02, "Unsupported method/key type" },
    { 0, NULL }
};

#define HOMEPLUG_AV_LINEFREQ_MASK 0x03

static const value_string homeplug_av_linefreq_vals[] = {
    { 0x00, "Unknown frequency" },
    { 0x01, "50Hz" },
    { 0x02, "60Hz" },
    { 0, NULL }
};

#define HOMEPLUG_AV_ZEROCROSS_MASK 0x03

static const value_string homeplug_av_zerocrossing_vals[] = {
    { 0x00, "Not yet detected" },
    { 0x01, "Detected" },
    { 0x02, "Missing" },
    { 0, NULL }
};

#define HOMEPLUG_AV_ENET_PHY_SPEED_MASK 0x03

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

#define HOMEPLUG_AV_ENET_PHY_MCONTROL_MASK 0x01

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
    { 0x10, "Update occurred but not successful" },
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

#define HOMEPLUG_AV_RPT_CLR_MASK 0x01

static const value_string homeplug_av_rpt_clr_vals[] = {
    { 0x00, "Get Report" },
    { 0x01, "Get Report and Clear" },
    { 0, NULL }
};

#define HOMEPLUG_AV_GEN_STATUS_MASK 0x03

static const value_string homeplug_av_generic_status_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Failure" },
    { 0x02, "Not supported" },
    { 0, NULL }
};

#define HOMEPLUG_AV_LNK_STATS_MCTL_MASK 0x01

static const value_string homeplug_av_lnk_stats_mctrl_vals[] = {
    { 0x00, "Read" },
    { 0x01, "Clear" },
    { 0, NULL }
};

#define HOMEPLUG_AV_LNK_STATS_DIR_TX    0x00
#define HOMEPLUG_AV_LNK_STATS_DIR_RX    0x01
#define HOMEPLUG_AV_LNK_STATS_DIR_TX_RX 0x02
#define HOMEPLUG_AV_LNK_STATS_DIR_MASK  0x03

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

#define HOMEPLUG_AV_LNK_STATS_STATUS_SUCCESS  0x00
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_CTRL 0x01
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_DIR  0x02
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_LID  0x10
#define HOMEPLUG_AV_LNK_STATS_STATUS_INV_MAC  0x20

static const value_string homeplug_av_lnk_status_vals[] = {
    { HOMEPLUG_AV_LNK_STATS_STATUS_SUCCESS,    "Success" },
    { HOMEPLUG_AV_LNK_STATS_STATUS_INV_CTRL,   "Invalid Control" },
    { HOMEPLUG_AV_LNK_STATS_STATUS_INV_DIR,    "Invalid Direction" },
    { HOMEPLUG_AV_LNK_STATS_STATUS_INV_LID,    "Invalid Link ID" },
    { HOMEPLUG_AV_LNK_STATS_STATUS_INV_MAC,    "Invalid MAC Address" },
    { 0, NULL }
};

#define HOMEPLUG_AV_SNIFFER_CTRL_MASK 0x03

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

#define HOMEPLUG_AV_DEL_TYPE_BCN    0x00
#define HOMEPLUG_AV_DEL_TYPE_SOF    0x01
#define HOMEPLUG_AV_DEL_TYPE_SACK   0x02
#define HOMEPLUG_AV_DEL_TYPE_RTS    0x03
#define HOMEPLUG_AV_DEL_TYPE_SOUND  0x04
#define HOMEPLUG_AV_DEL_TYPE_RSOF   0x05

#define HOMEPLUG_AV_DEL_TYPE_MASK   0x07

static const value_string homeplug_av_fc_del_type_vals[] = {
    { HOMEPLUG_AV_DEL_TYPE_BCN,   "Beacon" },
    { HOMEPLUG_AV_DEL_TYPE_SOF,   "Start-of-Frame" },
    { HOMEPLUG_AV_DEL_TYPE_SACK,  "Selective Acknowledgement" },
    { HOMEPLUG_AV_DEL_TYPE_RTS,   "Request-to-Send/Clear-to-Send" },
    { HOMEPLUG_AV_DEL_TYPE_SOUND, "Sound" },
    { HOMEPLUG_AV_DEL_TYPE_RSOF,  "Reverse Start-of-Frame" },
    { 0x06, "Unknown" },
    { 0x07, "Unknown" },
    { 0, NULL }
};

/* MPDU Values */

#define HOMEPLUG_AV_SNID_MASK      0xf0
#define HOMEPLUG_AV_CFS_MASK       0x01
#define HOMEPLUG_AV_BDF_MASK       0x02
#define HOMEPLUG_AV_HP10DF_MASK    0x04
#define HOMEPLUG_AV_HP11DF_MASK    0x08
#define HOMEPLUG_AV_SVN_MASK       0x04
#define HOMEPLUG_AV_RRTF_MASK      0x08
#define HOMEPLUG_AV_FL_AV_MASK     0x0FFF
#define HOMEPLUG_AV_RSP_DATA_MASK  0x03
#define HOMEPLUG_AV_RSP_MGMT_MASK  0x0C

static int * const rsof_sack_fields[] = {
    &hf_homeplug_av_cfs,
    &hf_homeplug_av_bdf,
    &hf_homeplug_av_svn,
    &hf_homeplug_av_rrtf,
    &hf_homeplug_av_mfs_rsp_data,
    &hf_homeplug_av_mfs_rsp_mgmt,
    NULL
};

#define HOMEPLUG_AV_PBSZ_MASK           0x01

static const true_false_string homeplug_av_phy_block_size_vals = {
    "136 octets",
    "520 octets"
};

#define HOMEPLUG_AV_NUM_SYM_MASK        0x06
#define HOMEPLUG_AV_TMI_AV_MASK         0xF8
#define HOMEPLUG_AV_SOF_MPDU_CNT_MASK   0x3000
#define HOMEPLUG_AV_BURST_CNT_MASK      0xC000
#define HOMEPLUG_AV_BBF_MASK            0x01

static const true_false_string homeplug_av_bbf_vals = {
    "May continue",
    "Must not continue"
};

#define HOMEPLUG_AV_MRTLF_MASK          0x1E
#define HOMEPLUG_AV_DCCPCF_MASK         0x20
#define HOMEPLUG_AV_MCF_MASK            0x40
#define HOMEPLUG_AV_MNBF_MASK           0x80
#define HOMEPLUG_AV_RSR_MASK            0x01
#define HOMEPLUG_AV_CLST_MASK           0x02

static const true_false_string homeplug_av_clst_vals = {
    "Reserved",
    "Ethernet II"
};

#define HOMEPLUG_AV_MFS_MGMT_MASK       0x1C
#define HOMEPLUG_AV_MFS_DATA_MASK       0xE0
#define HOMEPLUG_AV_SOF_RSP_MGMT_MASK   0x03
#define HOMEPLUG_AV_SOF_RSP_DATA_MASK   0x0C
#define HOMEPLUG_AV_BM_SACK_MASK        0xF0

#define HOMEPLUG_AV_RTSF_MASK           0x10

static const true_false_string homeplug_av_rtsf_vals = {
    "RTS MPDU",
    "CTS MPDU"
};

#define HOMEPLUG_AV_IGF_MASK            0x20
#define HOMEPLUG_AV_RTSCTS_MNBF_MASK    0x40
#define HOMEPLUG_AV_RTSCTS_MCF_MASK     0x80
#define HOMEPLUG_AV_DUR_MASK            0x3FFF

#define HOMEPLUG_AV_SOUND_PBSZ_MASK     0x02
#define HOMEPLUG_AV_SOUND_BDF_MASK      0x04
#define HOMEPLUG_AV_SAF_MASK            0x08
#define HOMEPLUG_AV_SCF_MASK            0x10
#define HOMEPLUG_AV_REQ_TM_MASK         0xE0
#define HOMEPLUG_AV_SOUND_MPDU_CNT_MASK 0x3000
#define HOMEPLUG_AV_ADD_REQ_TM_MASK     0x07
#define HOMEPLUG_AV_MAX_PB_SYM_MASK     0x38
#define HOMEPLUG_AV_ECSF_MASK           0x40
#define HOMEPLUG_AV_ECUF_MASK           0x80
#define HOMEPLUG_AV_EMS_MASK            0x03

static const value_string homeplug_av_ems_vals[] = {
    { 0x00, "Extended QAM Modulations not supported" },
    { 0x01, "4096 QAM Modulation support" },
    { 0x02, "Reserved" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

#define HOMEPLUG_AV_ESGISF_MASK         0x04
#define HOMEPLUG_AV_ELGISF_MASK         0x08
#define HOMEPLUG_AV_EFRS_MASK           0x30

static const value_string homeplug_av_efrs_vals[] = {
    { 0x00, "Extended FEC Rates Not Supported" },
    { 0x01, "16/18 FED Rate Supported" },
    { 0x02, "Reserved" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

#define HOMEPLUG_AV_RSOF_FL_MASK        0x03FF
#define HOMEPLUG_AV_RSOF_TMI_MASK       0x7C00
#define HOMEPLUG_AV_RSOF_PBSZ_MASK      0x8000
#define HOMEPLUG_AV_RSOF_NUM_SYM_MASK   0x03

/* MPDU Beacon payloads */

#define HOMEPLUG_AV_BCN_NID_MASK        0xFFFFFFFFFFFF3F
#define HOMEPLUG_AV_HM_MASK             0xC0

static const val64_string homeplug_av_bcn_hm_vals[] = {
    { 0x00, "AV-only mode" },
    { 0x01, "Shared CSMA Hybrid Mode" },
    { 0x02, "Fully hybrid mode" },
    { 0x03, "Fully hybrid mode with unrestricted frame lengths" },
    { 0, NULL }
};

#define HOMEPLUG_AV_BCN_TYPE_MASK       0x07

static const value_string homeplug_av_bcn_type_vals[] = {
    { 0x0, "Central" },
    { 0x1, "Discover" },
    { 0x2, "Proxy" },
    { 0, NULL }
};

#define HOMEPLUG_AV_NCNR_MASK           0x08
#define HOMEPLUG_AV_NPSM_MASK           0x10
#define HOMEPLUG_AV_NUM_SLOTS_MASK      0xE0
#define HOMEPLUG_AV_SLOT_ID_MASK        0x03

/* There must be a better way to do this. */
static const value_string homeplug_av_bcn_slot_vals[] = {
    { 0x0, "1" },
    { 0x1, "2" },
    { 0x2, "3" },
    { 0x3, "4" },
    { 0x4, "5" },
    { 0x5, "6" },
    { 0x6, "7" },
    { 0x7, "8" },
    { 0, NULL }
};

#define HOMEPLUG_AV_ACLSS_MASK          0x38
#define HOMEPLUG_AV_HOIP_MASK           0x40
#define HOMEPLUG_AV_RTSBF_MASK          0x80
#define HOMEPLUG_AV_NM_MASK             0x03

static const value_string homeplug_av_bcn_nm_vals[] = {
    { 0x1, "Uncoordinated Mode" },
    { 0x2, "Coordinated Mode" },
    { 0x3, "CSMA-only Mode" },
    { 0, NULL }
};

#define HOMEPLUG_AV_LBK_STATUS_MASK 0x01

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

#define HOMEPLUG_AV_NVM_IMG_TYPE_MASK 0x1F

static const value_string homeplug_av_nvm_img_type_vals[] = {
    { 0x00, "Generic Image" },
    { 0x01, "Synopsis configuration" },
    { 0x02, "Denali configuration" },
    { 0x03, "Denali applet" },
    { 0x04, "Runtime firmware" },
    { 0x05, "OAS client" },
    { 0x06, "Custom image" },
    { 0x07, "Memory control applet" },
    { 0x08, "Power management applet" },
    { 0x09, "OAS client IP stack" },
    { 0x0A, "OAS client TR069" },
    { 0x0B, "SoftLoader" },
    { 0x0C, "Flash layout" },
    { 0x0D, "Unknown" },
    { 0x0E, "Chain manifest" },
    { 0x0F, "Runtime parameters" },
    { 0x10, "Custom module in scratch" },
    { 0x11, "Custom module update applet" },
    { 0, NULL }
};

#define HOMEPLUG_AV_NVM_IGNORE_MASK_MASK 0x1FF

static const value_string homeplug_av_nvm_ignore_mask_vals[] = {
    { 0x00, "INT6000" },
    { 0x01, "INT6300" },
    { 0x04, "INT6400" },
    { 0x10, "AR7400" },
    { 0x100, "AR7420" },
    { 0, NULL }
};

#define HOMEPLUG_AV_HOST_ACTION_SOFT_LDR       0x00
#define HOMEPLUG_AV_HOST_ACTION_FW_UPG_RDY     0x01
#define HOMEPLUG_AV_HOST_ACTION_PIB_UP_RDY     0x02
#define HOMEPLUG_AV_HOST_ACTION_FW_PIB_UP_RDY  0x03
#define HOMEPLUG_AV_HOST_ACTION_BOOT_LDR       0x04

static const value_string homeplug_av_host_action_vals[] = {
    { HOMEPLUG_AV_HOST_ACTION_SOFT_LDR,        "Loader (Soft/Bootloader)" },
    { HOMEPLUG_AV_HOST_ACTION_FW_UPG_RDY,      "Firmware Upgrade Ready" },
    { HOMEPLUG_AV_HOST_ACTION_PIB_UP_RDY,      "PIB Update Ready" },
    { HOMEPLUG_AV_HOST_ACTION_FW_PIB_UP_RDY,   "Firmware Upgrade and PIB Update Ready" },
    { HOMEPLUG_AV_HOST_ACTION_BOOT_LDR,        "Loader (Bootloader)" },
    { 0, NULL }
};

static const value_string homeplug_av_op_attr_report_vals[] = {
    { 0x00, "Binary" },
    { 0x01, "XML" },
    { 0, NULL }
};

#define HOMEPLUG_AV_TONE_MAP_MAX_NUM_CARRIERS_A 1155
#define HOMEPLUG_AV_TONE_MAP_MAX_NUM_CARRIERS_B 2880

#define HOMEPLUG_AV_TONE_MAP_MASK               0x0f

static const value_string homeplug_av_tone_map_vals[] = {
    { 0x00, "No modulation" },
    { 0x01, "BPSK" },
    { 0x02, "QPSK" },
    { 0x03, "8-QAM" },
    { 0x04, "16-QAM" },
    { 0x05, "64-QAM" },
    { 0x06, "256-QAM" },
    { 0x07, "1024-QAM" },
    { 0x08, "4096-QAM" },
    { 0, NULL }
};

static const value_string homeplug_av_tone_map_status_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Unknown MAC address" },
    { 0x02, "Unknown Tone Map slot" },
    { 0, NULL }
};

#define HOMEPLUG_AV_COUPLING_MASK 0x0F

static const value_string homeplug_av_coupling_vals[] = {
    { 0x00, "Primary" },
    { 0x01, "Alternate" },
    { 0, NULL }
};

static const value_string homeplug_av_cc_assoc_result_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Failure due to temporary resourse exhaustion, try again later" },
    { 0x02, "Failure due to permanent resourse exhaustion" },
    { 0x03, "Failure" },
    { 0, NULL }
};

static const value_string homeplug_av_cc_assoc_reqtype_vals[] = {
    { 0x00, "New request" },
    { 0x01, "Renewal request" },
    { 0, NULL }
};

static const value_string homeplug_av_cc_assoc_proxy_net_cap_vals[] = {
    { 0x00, "Doesn't support Proxy Networking" },
    { 0x01, "Supports Proxy Networking" },
    { 0, NULL }
};

/* HPGP Values */

#define HOMEPLUG_AV_GP_APPTYPE_PEV_EVSE_ASSOC 0x00

#define HOMEPLUG_AV_GP_SECURITY_TYPE_NONE 0x00
#define HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY 0x01

static const value_string homeplug_av_gp_cm_slac_parm_sectype_vals[] = {
    { HOMEPLUG_AV_GP_SECURITY_TYPE_NONE, "No Security" },
    { HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY, "Public Key Signature" },
    { 0, NULL }
};

static const value_string homeplug_av_gp_cm_slac_parm_resptype_vals[] = {
    { 0x00, "Not Transmited to other GP STA's HLE" },
    { 0x01, "Transmited to another GP STA's HLE" },
    { 0, NULL }
};

#define HOMEPLUG_AV_GP_SIGNAL_TYPE_PEV_S2_TOGGLES 0x00

static const value_string homeplug_av_gp_cm_validate_signaltype_vals[] = {
    { HOMEPLUG_AV_GP_SIGNAL_TYPE_PEV_S2_TOGGLES, "PEV S2 toggles on CPLT line" },
    { 0, NULL }
};

static const value_string homeplug_av_gp_cm_validate_result_vals[] = {
    { 0x00, "Not Ready" },
    { 0x01, "Ready" },
    { 0x02, "Success" },
    { 0x03, "Failure" },
    { 0x04, "Not required" },
    { 0, NULL }
};

/* We need third octet */
#define HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_BROADCAST_MASK (((guint32)0xFF) << 16)

static const value_string homeplug_av_gp_cm_slac_user_data_broadcast_vals[] = {
    { 0x00, "Unicast" },
    { 0x01, "AVLN Broadcast" },
    { 0x02, "Multi-network broadcast" },
    { 0, NULL }
};

#define HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_HEADER_SIZE 2
#define HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_MASK (((1<<7)-1)<<9)
#define HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_LENGTH_MASK ((1<<9)-1)

#define HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_VENDOR_RESERVED 0x1F

static const value_string homeplug_av_gp_cm_slac_user_data_tlv_types_vals[] = {
    { HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_VENDOR_RESERVED, "Vender Reserved" },
    { 0, NULL }
};

typedef enum {
    HOMEPLUG_AV_CC_SET_TEI_MAP_IND_MODE_FULL_ENTRIES_UPATE = 0x00,
    HOMEPLUG_AV_CC_SET_TEI_MAP_IND_MODE_ADD_NEW_ENTRIES    = 0x01,
    HOMEPLUG_AV_CC_SET_TEI_MAP_IND_MODE_REMOVE_ENTRIES     = 0x02
} homeplug_av_cc_set_tei_map_ind_mode_types;

static const value_string homeplug_av_cc_set_tei_map_ind_mode_vals[] = {
    { HOMEPLUG_AV_CC_SET_TEI_MAP_IND_MODE_FULL_ENTRIES_UPATE, "Update Entire STA" },
    { HOMEPLUG_AV_CC_SET_TEI_MAP_IND_MODE_ADD_NEW_ENTRIES,    "Add new STA entries" },
    { HOMEPLUG_AV_CC_SET_TEI_MAP_IND_MODE_REMOVE_ENTRIES,     "Remove existing STA entries" },
    { 0, NULL }
};

typedef enum {
    HOMEPLUG_AV_CC_SET_TEI_MAP_IND_STATUS_NOT_AUTHENTICATED   = 0x00,
    HOMEPLUG_AV_CC_SET_TEI_MAP_IND_STATUS_AUTHENTICATED       = 0x01,
} homeplug_av_cc_set_tei_map_ind_status_types;

static const value_string homeplug_av_cc_set_tei_map_ind_status_vals[] = {
    { HOMEPLUG_AV_CC_SET_TEI_MAP_IND_STATUS_NOT_AUTHENTICATED,  "Not Authenticated" },
    { HOMEPLUG_AV_CC_SET_TEI_MAP_IND_STATUS_AUTHENTICATED,      "Authenticated" },
    { 0, NULL }
};

#define HOMEPLUG_AV_GP_CM_ATTEN_CHAR_AAG_FORMAT "Avg. Attenuation of group #%d (dB): %d"

/* ST/IoTecha specific values */

static const value_string homeplug_av_st_iotecha_linkstatus_status_vals[] = {
    { 0x00, "No Link" },
    { 0x01, "Link with atleast 1 device" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_linkstatus_devmode_vals[] = {
    { 0x00, "Unavailable" },
    { 0x01, "UNAS STA" },
    { 0x02, "ASSC STA" },
    { 0x03, "AUTH STA" },
    { 0x04, "UNAS BM" },
    { 0x05, "ASSC BM" },
    { 0x06, "AUTH BM" },
    { 0, NULL }
};

#define HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_HEADER_SIZE 2
#define HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_MASK (((1<<6)-1)<<10)
#define HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_LENGTH_MASK  ((1<<10)-1)

typedef enum {
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_NULL                 = 0x00,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_NAME          = 0x01,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_TYPE          = 0x02,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_BUILD_ID             = 0x03,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_RESERVED             = 0x04,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_UID           = 0x05,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_MAC_ADDRESS          = 0x06,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_HARDWARE_NAME        = 0x07,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_HARDWARE_VERSION     = 0x08,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_LINUX_KERNEL_VERSION = 0x09,
    HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_LINUX_USER_VERSION   = 0x0A,
} homeplug_av_st_iotecha_stp_discover_tlv_types;

static const value_string homeplug_av_st_iotecha_stp_discover_tlv_type_vals[] = {
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_NULL,                 "NULL" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_NAME,          "Device name" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_TYPE,          "Device type" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_BUILD_ID,             "Build ID" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_RESERVED,             "Reserved" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_UID,           "Device UID" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_MAC_ADDRESS,          "MAC Address" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_HARDWARE_NAME,        "Hardware name" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_HARDWARE_VERSION,     "Hardware version" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_LINUX_KERNEL_VERSION, "Linux Kernel version" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_LINUX_USER_VERSION,   "Linux User version" },
    { 0, NULL }
};

typedef enum {
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NULL                    = 0x00,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEGIN_BSS               = 0x01,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_LOCAL_BSS               = 0x02,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_RESERVED                = 0x03,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_REMOTE_BSS              = 0x04,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SNID                    = 0x05,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NID                     = 0x06,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NET_MODE                = 0x07,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEACON_AGE              = 0x08,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEACON_FC_RELIABILITY   = 0x09,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEACON_PLD_RELIABILITY  = 0x0A,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL            = 0x0B,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_TOS        = 0x0C,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_MIN        = 0x0D,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_TOS_MIN    = 0x0E,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_MAX        = 0x0F,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_TOS_MAX    = 0x10,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NET_HYB_MODE            = 0x11,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_TEI                     = 0x12,
    HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_END_BSS                 = 0xFF,
} homeplug_av_st_iotecha_stp_get_bss_tlv_types;

static const value_string homeplug_av_st_iotecha_stp_get_bss_tlv_type_vals[] = {
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NULL,                  "NULL" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEGIN_BSS,             "Start of BSS descriptor" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_LOCAL_BSS,             "Local BSS Manager" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_RESERVED,              "Reserved Data" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_REMOTE_BSS,            "Remote BSS" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SNID,                  "Short Network ID" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NID,                   "Network ID" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NET_MODE,              "Network Mode" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEACON_AGE,            "Beacon Age" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEACON_FC_RELIABILITY, "Beacon Frame Control reliability" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEACON_PLD_RELIABILITY,"Beacon Payload reliability" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL,          "Signal Level" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_TOS,      "Signal Level Time of Sample" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_MIN,      "Min Signal Level" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_TOS_MIN,  "Min Signal Level Time of Sample" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_MAX,      "Max Signal Level" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_SIGNAL_LEVEL_TOS_MAX,  "Max Signal Level Time of Sample" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_NET_HYB_MODE,          "Network Hybrid Mode" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_TEI,                   "TEI of BM" },
    { HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_END_BSS,               "End of BSS descriptor" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_mac_address_flag_vals[] = {
    { 0x00, "Unknown" },
    { 0x01, "Local MAC" },
    { 0x02, "Local Bridged MAC" },
    { 0x04, "Remote MAC" },
    { 0x08, "Remote Bridged MAC" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_chanqual_tei_source_vals[] = {
    { 0x01, "Local Tei" },
    { 0x02, "Remote Tei" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_chanqual_substatus_vals[] = {
    { 0x01, "Subscribed" },
    { 0x02, "Unsubscribed" },
    { 0x03, "Invalid Request Type" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_chanqual_responsetype_vals[] = {
    { 0x00, "Default Tone map transmitted in ICE" },
    { 0x01, "Others" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_chanqual_tmi_vals[] = {
    { 0xFE, "Not Available For Particular Interval" },
    { 0xFF, "Unusable Interval" },
    { 0, NULL }
};

#define HOMEPLUG_AV_ST_IOTECHA_CHANQUAL_CBLD_DATA_MASK_LOW  0x0F
#define HOMEPLUG_AV_ST_IOTECHA_CHANQUAL_CBLD_DATA_MASK_HIGH 0xF0
/* (1154/2) */
#define HOMEPLUG_AV_ST_IOTECHA_CHANQUAL_CBLD_DATA_COUNT 577
static const value_string homeplug_av_st_iotecha_chanqual_cbld_data_vals[] = {
    { 0x00, "Empty" },
    { 0x01, "Bitload of 1" },
    { 0x02, "Bitload of 2" },
    { 0x03, "Bitload of 3" },
    { 0x04, "Bitload of 4" },
    { 0x05, "Bitload of 5" },
    { 0x06, "Bitload of 6" },
    { 0x07, "Bitload of 7" },
    { 0x08, "Bitload of 8" },
    { 0x09, "Bitload of 9" },
    { 0x0A, "Bitload of 10" },
    { 0x0F, "Unusable" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_chanqual_reqtype_vals[] = {
    { 0x01, "Subscribe" },
    { 0x02, "Unsubscribe" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_mfct_request_type_vals[] = {
    { 0x00, "Commit" },
    { 0x02, "Abort" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_mfct_result_vals[] = {
    { 0x00, "Success" },
    { 0x03, "Parameter Not Found" },
    { 0x04, "Permission Error" },
    { 0x05, "Insufficient space in parameter region" },
    { 0x06, "Internal Error" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_stp_fwup_mtype_vals[] = {
    { 0x00, "Start Request" },
    { 0x01, "Start Confirmation" },
    { 0x02, "Data Index" },
    { 0x03, "Data Response" },
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_stp_cpstate_state_vals[] = {
    { 0x00, "Invalid"},
    { 0x01, "A"},
    { 0x02, "Ambiguous (A-B)"},
    { 0x03, "B"},
    { 0x04, "Ambiguous (B-C)"},
    { 0x05, "C"},
    { 0x06, "Ambiguous (C-D)"},
    { 0x07, "D"},
    { 0x08, "Ambiguous (D-E)"},
    { 0x09, "E"},
    { 0x0A, "F"},
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_test_type_vals[] = {
    { 0x00, "Power"},
    { 0x01, "Error"},
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_agc_lock_vals[] = {
    { 0x00, "Disabled"},
    { 0x01, "Enabled"},
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_test_status_vals[] = {
    { 0x00, "Test running"},
    { 0x01, "Failed to start test"},
    { 0x02, "Test reset"},
    { 0, NULL }
};

static const value_string homeplug_av_st_iotecha_suppress_data_vals[] = {
    { 0x00, "Disabled"},
    { 0x01, "Enabled"},
    { 0, NULL }
};

static void
adc_bitmask_base(gchar *buf, guint8 value) {
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%s, %s, %s (%d)",
               (value & 0x01) ? "true" : "false",
               (value & 0x02) ? "true" : "false",
               (value & 0x04) ? "true" : "false",
               value);
}

/* End of ST/IoTecha specific values */

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

static inline unsigned int homeplug_av_mmtype_msb_is_manufacturer(guint8 msb)
{
    return ((msb & (HOMEPLUG_AV_MMTYPE_MSB_MANUF << HOMEPLUG_AV_MMTYPE_MSB_SHIFT)) ==
            (HOMEPLUG_AV_MMTYPE_MSB_MANUF << HOMEPLUG_AV_MMTYPE_MSB_SHIFT));
}

static inline guint8 homeplug_av_get_mmhdr_size(guint8 mmv) {
    /* Header in HomePlug AV 1.1 is 2 bytes larger (Fragmentation information) */
    return (mmv ? 5 : 3);
}

/* Dissection of MMHDR */
static void
dissect_homeplug_av_mmhdr(ptvcursor_t *cursor, guint8 *homeplug_av_mmver, guint16 *homeplug_av_mmtype, guint32 *homeplug_av_oui)
{
    proto_item *ti;
    proto_tree *ti_mmtype;
    /* Save in static variable */
    /* proto_tree *ti_vendor; */
    proto_tree *ti_public;
    guint8 lsb, msb, mmv;
    guint32 offset;

    offset = 0;

    mmv = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                         ptvcursor_current_offset(cursor));
    lsb = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                         ptvcursor_current_offset(cursor) + 1);
    msb = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                         ptvcursor_current_offset(cursor) + 2);

    *homeplug_av_mmver = mmv;
    *homeplug_av_mmtype = (msb << 8) | lsb;

    if (homeplug_av_mmtype_msb_is_vendor(msb)
        || homeplug_av_mmtype_msb_is_manufacturer(msb))
    {
        /* read three bytes of OUI */
        *homeplug_av_oui = tvb_get_guint24(ptvcursor_tvbuff(cursor),
                                           ptvcursor_current_offset(cursor)+homeplug_av_get_mmhdr_size(mmv),
                                           ENC_NA);
    }

    if (!ptvcursor_tree(cursor)) {
        /* advance even there is no tree to be able to extract data in packet specific dissectors */
        offset += homeplug_av_get_mmhdr_size(mmv);
        if (homeplug_av_mmtype_msb_is_vendor(msb)
            || homeplug_av_mmtype_msb_is_manufacturer(msb)) {
            offset += 3;
        }
        ptvcursor_advance(cursor, offset);
        return;
    }

    /* Header in HomePlug AV 1.1 is 2 bytes larger (Fragmentation information) */
    ti = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr, homeplug_av_get_mmhdr_size(*homeplug_av_mmver), ENC_NA);

    ptvcursor_push_subtree(cursor, ti, ett_homeplug_av_mmhdr);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mmhdr_mmver, 1, ENC_BIG_ENDIAN);

        switch (*homeplug_av_oui) {
        case HOMEPLUG_AV_OUI_QCA:
            ti_mmtype = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr_mmtype_qualcomm, 2, ENC_LITTLE_ENDIAN);
            break;
        case HOMEPLUG_AV_OUI_ST_IOTECHA:
            ti_mmtype = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr_mmtype_st,       2, ENC_LITTLE_ENDIAN);
            break;
        default:
            ti_mmtype = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr_mmtype_general,  2, ENC_LITTLE_ENDIAN);
            break;
        }

        ptvcursor_push_subtree(cursor, ti_mmtype, ett_homeplug_av_mmtype);
        {
            ptvcursor_add(cursor, hf_homeplug_av_mmhdr_mmtype_lsb, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_mmhdr_mmtype_msb, 1, ENC_BIG_ENDIAN);
        }
        ptvcursor_pop_subtree(cursor);

        /* Fragmentation information is part of the header in HomePlug AV 1.1 */
        if (mmv)
        {
            ti_public = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr_fmi, 2, ENC_LITTLE_ENDIAN);

            ptvcursor_push_subtree(cursor, ti_public, ett_homeplug_av_fmi);
            {
                ptvcursor_add_no_advance(cursor, hf_homeplug_av_public_frag_count, 1, ENC_BIG_ENDIAN);
                ptvcursor_add(cursor, hf_homeplug_av_public_frag_index, 1, ENC_BIG_ENDIAN);
                ptvcursor_add(cursor, hf_homeplug_av_public_frag_seqnum, 1, ENC_BIG_ENDIAN);
            }
            ptvcursor_pop_subtree(cursor);
        }
    }
    ptvcursor_pop_subtree(cursor);

    /* Vendor management frame */
    if (homeplug_av_mmtype_msb_is_vendor(msb) || homeplug_av_mmtype_msb_is_manufacturer(msb))
    {
        ti_vendor = ptvcursor_add_no_advance(cursor, hf_homeplug_av_vendor, 3, ENC_NA);

        ptvcursor_push_subtree(cursor, ti_vendor, ett_homeplug_av_vendor);
        {
            ptvcursor_add(cursor, hf_homeplug_av_vendor_oui, 3, ENC_NA);
        }
        ptvcursor_pop_subtree(cursor);
    }
    /* Public management frame in HomePlug AV 1.0 */
    else if (!mmv)
    {
        ti_public = ptvcursor_add_no_advance(cursor, hf_homeplug_av_public, -1, ENC_NA);

        ptvcursor_push_subtree(cursor, ti_public, ett_homeplug_av_public);
        {
            ptvcursor_add_no_advance(cursor, hf_homeplug_av_public_frag_count, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_public_frag_index, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_public_frag_seqnum, 1, ENC_BIG_ENDIAN);
        }
        ptvcursor_pop_subtree(cursor);
    }
}

/* Beacon body */

static void
dissect_homeplug_av_beacon_payload(ptvcursor_t *cursor)
{

    proto_item *it;
    proto_tree *tree;
    tvbuff_t   *tvb;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_bcn_payload, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_bcn_payload);
    {
        tree = ptvcursor_tree(cursor);
        tvb = ptvcursor_tvbuff(cursor);

        static int * const bcn1_fields[] = {
            &hf_homeplug_av_bcn_nid,
            &hf_homeplug_av_bcn_hm,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 7, bcn1_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 7);

        ptvcursor_add(cursor, hf_homeplug_av_bcn_stei, 1, ENC_BIG_ENDIAN);

        static int * const bcn2_fields[] = {
            &hf_homeplug_av_bcn_type,
            &hf_homeplug_av_bcn_ncnr,
            &hf_homeplug_av_bcn_npsm,
            &hf_homeplug_av_bcn_num_slots,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, bcn2_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        ptvcursor_add(cursor, hf_homeplug_av_bcn_slot_use, 1, ENC_BIG_ENDIAN);

        static int * const bcn3_fields[] = {
            &hf_homeplug_av_bcn_slot_id,
            &hf_homeplug_av_bcn_aclss,
            &hf_homeplug_av_bcn_hoip,
            &hf_homeplug_av_bcn_rtsbf,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, bcn3_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        static int * const bcn4_fields[] = {
            &hf_homeplug_av_bcn_nm,
            &hf_homeplug_av_bcn_cco_cap,
            &hf_homeplug_av_bcn_rsf,
            &hf_homeplug_av_bcn_plevel,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, bcn4_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        /* TODO: decode individual beacon entries */
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bentries, 120, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bpcs, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_beacon(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_bcn, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_bcn);
    {
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bts, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_0, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_1, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_2, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_bcn_bto_3, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_fc_fccs_av, 3, ENC_NA);
        dissect_homeplug_av_beacon_payload(cursor);
    }
    ptvcursor_pop_subtree(cursor);
}

/* Start of Frame */
static void
dissect_homeplug_av_start_of_frame(ptvcursor_t *cursor)
{
    proto_item *it;
    proto_tree *tree;
    tvbuff_t   *tvb;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sof, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sof);
    {
        tree = ptvcursor_tree(cursor);
        tvb = ptvcursor_tvbuff(cursor);

        ptvcursor_add(cursor, hf_homeplug_av_stei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_dtei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lid, 1, ENC_BIG_ENDIAN);

        static int * const sof1_fields[] = {
            &hf_homeplug_av_cfs,
            &hf_homeplug_av_bdf,
            &hf_homeplug_av_hp10df,
            &hf_homeplug_av_hp11df,
            &hf_homeplug_av_sof_peks,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sof1_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        ptvcursor_add(cursor, hf_homeplug_av_ppb, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_sof_ble, 1, ENC_BIG_ENDIAN);

        static int * const sof2_fields[] = {
            &hf_homeplug_av_sof_pbsz,
            &hf_homeplug_av_sof_num_sym,
            &hf_homeplug_av_sof_tmi_av,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sof2_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        static int * const sof3_fields[] = {
            &hf_homeplug_av_fl_av,
            &hf_homeplug_av_sof_mpdu_cnt,
            &hf_homeplug_av_sof_burst_cnt,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 2, sof3_fields, ENC_LITTLE_ENDIAN);
        ptvcursor_advance(cursor, 2);

        static int * const sof4_fields[] = {
            &hf_homeplug_av_sof_bbf,
            &hf_homeplug_av_sof_mrtfl,
            &hf_homeplug_av_sof_dccpcf,
            &hf_homeplug_av_sof_mcf,
            &hf_homeplug_av_sof_mnbf,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sof4_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        static int * const sof5_fields[] = {
            &hf_homeplug_av_sof_rsr,
            &hf_homeplug_av_sof_clst,
            &hf_homeplug_av_sof_mfs_cmd_mgmt,
            &hf_homeplug_av_sof_mfs_cmd_data,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sof5_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        static int * const sof6_fields[] = {
            &hf_homeplug_av_sof_mfs_rsp_mgmt,
            &hf_homeplug_av_sof_mfs_rsp_data,
            &hf_homeplug_av_sof_bm_sack,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sof6_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        ptvcursor_add(cursor, hf_homeplug_av_fc_fccs_av, 3, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

/* Selective acknowledgment */
static void
dissect_homeplug_av_sack(ptvcursor_t *cursor)
{
    proto_item *it;
    proto_tree *tree;
    tvbuff_t   *tvb;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sack, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sack);
    {
        tree = ptvcursor_tree(cursor);
        tvb = ptvcursor_tvbuff(cursor);

        ptvcursor_add(cursor, hf_homeplug_av_dtei, 1, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, rsof_sack_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        /* TODO: add variable fields here */
        ptvcursor_advance(cursor, 10);
        ptvcursor_add(cursor, hf_homeplug_av_fc_fccs_av, 3, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

/* Request to send/clear to send */
static void
dissect_homeplug_av_rtscts(ptvcursor_t *cursor)
{
    proto_item *it;
    proto_tree *tree;
    tvbuff_t   *tvb;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rtscts, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rtscts);
    {
        tree = ptvcursor_tree(cursor);
        tvb = ptvcursor_tvbuff(cursor);

        ptvcursor_add(cursor, hf_homeplug_av_stei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_dtei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lid, 1, ENC_BIG_ENDIAN);

        static int * const rtscts_fields[] = {
            &hf_homeplug_av_cfs,
            &hf_homeplug_av_bdf,
            &hf_homeplug_av_hp10df,
            &hf_homeplug_av_hp11df,
            &hf_homeplug_av_rtscts_rtsf,
            &hf_homeplug_av_rtscts_igf,
            &hf_homeplug_av_rtscts_mnbf,
            &hf_homeplug_av_rtscts_mcf,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, rtscts_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        ptvcursor_add(cursor, hf_homeplug_av_rtscts_dur, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_fc_fccs_av, 3, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

/* Sound */
static void
dissect_homeplug_av_sound(ptvcursor_t *cursor)
{
    proto_item *it;
    proto_tree *tree;
    tvbuff_t   *tvb;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sound, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sound);
    {
        tree = ptvcursor_tree(cursor);
        tvb = ptvcursor_tvbuff(cursor);

        ptvcursor_add(cursor, hf_homeplug_av_stei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_dtei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lid, 1, ENC_BIG_ENDIAN);

        static int * const sound1_fields[] = {
            &hf_homeplug_av_cfs,
            &hf_homeplug_av_sound_pbsz,
            &hf_homeplug_av_sound_bdf,
            &hf_homeplug_av_sound_saf,
            &hf_homeplug_av_sound_scf,
            &hf_homeplug_av_sound_req_tm,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sound1_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        static int * const sound2_fields[] = {
            &hf_homeplug_av_fl_av,
            &hf_homeplug_av_sound_mpdu_cnt,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 2, sound2_fields, ENC_LITTLE_ENDIAN);
        ptvcursor_advance(cursor, 2);

        ptvcursor_add(cursor, hf_homeplug_av_ppb, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_sound_src, 1, ENC_BIG_ENDIAN);

        static int * const sound3_fields[] = {
            &hf_homeplug_av_sound_add_req_tm,
            &hf_homeplug_av_sound_max_pb_sym,
            &hf_homeplug_av_sound_ecsf,
            &hf_homeplug_av_sound_ecuf,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sound3_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        static int * const sound4_fields[] = {
            &hf_homeplug_av_sound_ems,
            &hf_homeplug_av_sound_esgisf,
            &hf_homeplug_av_sound_elgisf,
            &hf_homeplug_av_sound_efrs,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, sound4_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 3); /* one byte for bitmask plus two reserved bytes we ignore */

        ptvcursor_add(cursor, hf_homeplug_av_fc_fccs_av, 3, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

/* Reverse Start of Frame */
static void
dissect_homeplug_av_rsof(ptvcursor_t *cursor)
{
    proto_item *it;
    proto_tree *tree;
    tvbuff_t   *tvb;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rsof, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rsof);
    {
        tree = ptvcursor_tree(cursor);
        tvb = ptvcursor_tvbuff(cursor);

        ptvcursor_add(cursor, hf_homeplug_av_dtei, 1, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, rsof_sack_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 8); /* 1 byte for bitmask field, plus 7 bytes of variable data */
        /* TODO: fill in variable fields */

        static int * const rsof2_fields[] = {
            &hf_homeplug_av_rsof_fl,
            &hf_homeplug_av_rsof_tmi,
            &hf_homeplug_av_rsof_pbsz,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 2, rsof2_fields, ENC_LITTLE_ENDIAN);
        ptvcursor_advance(cursor, 2);

        static int * const rsof3_fields[] = {
            &hf_homeplug_av_rsof_num_sym,
            &hf_homeplug_av_rsof_mfs_cmd_mgmt,
            &hf_homeplug_av_rsof_mfs_cmd_data,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, ptvcursor_current_offset(cursor), 1, rsof3_fields, ENC_BIG_ENDIAN);
        ptvcursor_advance(cursor, 1);

        ptvcursor_add(cursor, hf_homeplug_av_fc_fccs_av, 3, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_info_sta(ptvcursor_t *cursor, gboolean vendor, guint homeplug_av_mmver)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_sta_info, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_info_sta_info);
    {
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_da, 6, ENC_NA);
        if (vendor) {
            ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_tei, 1, ENC_BIG_ENDIAN);

            if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
                ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, ENC_NA);

            ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_bda, 6, ENC_NA);
        }
        if (!homeplug_av_mmver)
        {
            ptvcursor_add(cursor, hf_homeplug_av10_nw_info_sta_phy_dr_tx, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av10_nw_info_sta_phy_dr_rx, 1, ENC_BIG_ENDIAN);
        }
        else if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
        {
            ptvcursor_add(cursor, hf_homeplug_av11_nw_info_sta_phy_dr_tx, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_homeplug_av11_nw_info_sta_cpling_tx, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av11_nw_info_sta_cpling_rx, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av11_nw_info_sta_phy_dr_rx, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 2, ENC_NA);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_info_net(ptvcursor_t *cursor, gboolean vendor, guint8 homeplug_av_mmver)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_net_info, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_info_net_info);
    {
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, ENC_NA);

        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 2, ENC_NA);

        ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_tei, 1, ENC_BIG_ENDIAN);

        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);

        ptvcursor_add(cursor, hf_homeplug_av_nw_info_sta_role, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_mac, 6, ENC_NA);
        if (vendor) {
            ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_tei, 1, ENC_BIG_ENDIAN);

            if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
                ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, ENC_NA);
        }
        else
        {
            ptvcursor_add(cursor, hf_homeplug_av_nw_info_access, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_coord, 1, ENC_BIG_ENDIAN);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

/* Public MMEs */
static void
dissect_homeplug_av_cc_sta_info(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cc_sta_info, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cc_sta_info);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_tei, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_same_net, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_cap, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_sig_level, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_sta_info_avg_ble, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cc_net_info(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cc_net_info, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cc_net_info);
    {
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_snid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_hyb_mode, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_bcn_slots, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_cco_sts, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cc_net_info_bcn_ofs, 2, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cc_disc_list_cnf(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      num_stas;
    guint8      sta;
    guint8      num_nets;
    guint8      net;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cc_disc_list_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cc_disc_list_cnf);
    {
        num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                  ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_cc_disc_list_sta_cnt, 1, ENC_BIG_ENDIAN);

        for (sta = 0; sta < num_stas; sta++) {
            dissect_homeplug_av_cc_sta_info(cursor);
        }

        num_nets = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                  ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_cc_disc_list_net_cnt, 1, ENC_BIG_ENDIAN);

        for (net = 0; net < num_nets; net++) {
            dissect_homeplug_av_cc_net_info(cursor);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_enc_pld_ind(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      pid;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_enc_pld_ind, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_enc_pld_ind);
    {
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_avlns, 1, ENC_BIG_ENDIAN);
        pid = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                             ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, ENC_BIG_ENDIAN);
        if (pid == HOMEPLUG_AV_PID_HLE) {
            ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_iv, 16, ENC_NA);
        } else {
            ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_uuid, 16, ENC_LITTLE_ENDIAN);
        }
        ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_len, 2, ENC_LITTLE_ENDIAN);

        /* Encrypted payload follows */
        if (pid != HOMEPLUG_AV_PID_HLE) {
            ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_ind_pld, -1, ENC_NA);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_enc_pld_rsp(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_enc_pld_rsp, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_enc_pld_rsp);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cm_enc_pld_rsp_result, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_set_key_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_set_key_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_set_key_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_key_type, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_your_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_cap, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cm_set_key_req_nw_key, 16, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_set_key_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_set_key_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_set_key_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cm_set_key_cnf_result, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_your_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_cco_cap, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_get_key_req(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      key_type;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_get_key_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_get_key_req);
    {

        ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_req_type, 1, ENC_BIG_ENDIAN);
        key_type = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                  ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_key_type, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, ENC_BIG_ENDIAN);
        if (key_type == HOMEPLUG_AV_KEY_TYPE_HASH) {
            ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_req_has_key, -1, ENC_NA);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cm_get_key_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_get_key_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_get_key_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_cnf_result, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_cnf_rtype, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_my_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_your_nonce, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_nid, 7, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_prn, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_pmn, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cm_get_key_cnf_key, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_brg_infos_cnf(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      bridging;
    guint8      num_stas;
    guint8      sta;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_brg_infos_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_brg_infos_cnf);
    {
        bridging = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                  ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_brd, 1, ENC_BIG_ENDIAN);

        if (bridging) {
            ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_btei, 1, ENC_BIG_ENDIAN);

            num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                      ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_num_stas, 1, ENC_BIG_ENDIAN);

            for (sta = 0; sta < num_stas; sta++) {
                ptvcursor_add(cursor, hf_homeplug_av_brg_infos_cnf_mac, 6, ENC_NA);
            }
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_infos_cnf(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      num_avlns;
    guint8      net;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cm_nw_infos_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cm_nw_infos_cnf);
    {
        num_avlns = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                   ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_avlns, 1, ENC_BIG_ENDIAN);

        for (net = 0; net < num_avlns; net++) {
            /* Force HomePlug AV 1.0 layout here */
            dissect_homeplug_av_nw_info_net(cursor, FALSE, 0);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_stats_cnf(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      num_stas;
    guint8      sta;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_stats_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_stats_cnf);
    {
        num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                  ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_stas, 1, ENC_BIG_ENDIAN);

        for (sta = 0; sta < num_stas; sta++) {
            /* Force HomePlug AV 1.0 layout here */
            dissect_homeplug_av_nw_info_sta(cursor, FALSE, 0);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

/* Intellon - Qualcomm specific MME Types */
static void
dissect_homeplug_av_get_sw_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_get_sw_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_get_sw_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_dev_id, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_ver_len, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_ver_str, 64, ENC_ASCII|ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_get_sw_cnf_upg, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wr_mem_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mem_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mem_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wr_mem_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mem_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mem_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mem_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mem_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mem_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mem_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mem_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mem_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mem_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mem_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_addr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_32bits, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_st_mac_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_mac_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_mac_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_load, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_len, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_chksum, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_st_mac_req_img_start, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}


static void
dissect_homeplug_av_st_mac_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_mac_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_mac_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_st_mac_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_nvm_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_get_nvm_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_get_nvm_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_type, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_page, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_block, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_get_nvm_cnf_nvm_size, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rs_dev_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rs_dev_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rs_dev_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_rs_dev_cnf_status, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void dissect_homeplug_av_wr_mod_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mod_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mod_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_checksum, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void dissect_homeplug_av_wr_mod_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mod_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mod_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_wr_mod_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void dissect_homeplug_av_wr_mod_ind(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wr_mod_ind, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wr_mod_ind);
    {
        ptvcursor_add(cursor, hf_homeplug_av_wr_mod_ind_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mod_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mod_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mod_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_mod_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_mod_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_mod_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_rd_mod_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_mem_len_16bits, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_offset, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mem_checksum, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_mem_data, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mod_nvm_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mod_nvm_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_mod_nvm_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mod_nvm_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mod_nvm_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_mod_nvm_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mod_nvm_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mac_module_id, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wd_rpt_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wd_rpt_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wd_rpt_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_req_session_id, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_req_clr, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_wd_rpt_ind(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_wd_rpt_ind, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_wd_rpt_ind);
    {
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_session_id, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_num_parts, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_curr_part, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_rdata_len, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_rdata_ofs, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_wd_rpt_ind_rdata, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_mcontrol, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_dir, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_lid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_req_macaddr, 6, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_tx(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_tx, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_tx);
    {
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_mpdu_ack, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_mpdu_col, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_mpdu_fai, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_pbs_pass, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_tx_pbs_fail, 8, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_rx_interval(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rx_inv_stats, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_rx_inv);
    {
        ptvcursor_add(cursor, hf_homeplug_av_rx_inv_phy_rate, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_rx_inv_pbs_pass, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_rx_inv_pbs_fail, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_rx_inv_tb_pass, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_rx_inv_tb_fail, 8, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_rx(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      num_rx_interval;
    guint8      interval;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_rx, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_rx);
    {
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_mpdu_ack, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_mpdu_fai, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_pbs_pass, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_pbs_fail, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_tb_pass, 8, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_tb_fail, 8, ENC_LITTLE_ENDIAN);
        num_rx_interval = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                         ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_rx_num_int, 1, ENC_BIG_ENDIAN);

        for (interval = 0; interval < num_rx_interval; interval++) {
            dissect_homeplug_av_lnk_stats_rx_interval(cursor);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lnk_stats_cnf(ptvcursor_t *cursor)
{
    proto_item *it;
    guint8      status;
    guint8      direction;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lnk_stats_cnf);
    {
        status = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_status, 1, ENC_BIG_ENDIAN);

        direction = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                   ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_dir, 1, ENC_BIG_ENDIAN);

        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_lid, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lnk_stats_cnf_tei, 1, ENC_BIG_ENDIAN);

        ptvcursor_add_no_advance(cursor, hf_homeplug_av_lnk_stats_cnf_lstats, -1, ENC_NA);

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
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sniffer_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_sniffer_req_ctrl, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_sniffer_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sniffer_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_sniffer_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_sniffer_cnf_state, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_sniffer_cnf_da, 6, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_sniffer_ind(ptvcursor_t *cursor)
{
    proto_item *it;
    proto_item *it_data;
    tvbuff_t   *tvb;
    guint       offset;

    guint8 del_type;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_ind, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_sniffer_ind);
    {
        ptvcursor_add(cursor, hf_homeplug_av_sniffer_ind_type, 1, ENC_BIG_ENDIAN);

        it_data = ptvcursor_add_no_advance(cursor, hf_homeplug_av_sniffer_ind_data, -1, ENC_NA);

        ptvcursor_push_subtree(cursor, it_data, ett_homeplug_av_sniffer_ind_data);
        {
            ptvcursor_add(cursor, hf_homeplug_av_sniffer_data_dir, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_sniffer_data_systime, 8, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_sniffer_data_bc_time, 4, ENC_LITTLE_ENDIAN);

            offset = ptvcursor_current_offset(cursor);
            tvb = ptvcursor_tvbuff(cursor);

            del_type = tvb_get_guint8(tvb, offset);

            /* bitmask - we only want 3 bits of del_type */
            guint8 bitmask = 0x07;

            del_type &= bitmask;

            static int * const frame_control_fields[] = {
                &hf_homeplug_av_fc_del_type,
                &hf_homeplug_av_fc_access,
                &hf_homeplug_av_fc_snid,
                NULL
            };

            proto_tree_add_bitmask(ptvcursor_tree(cursor), tvb, offset, hf_homeplug_av_fc,
                                   ett_homeplug_av_fc, frame_control_fields, ENC_BIG_ENDIAN);
            ptvcursor_advance(cursor, 1);

            switch (del_type)
            {
            case HOMEPLUG_AV_DEL_TYPE_BCN:
                dissect_homeplug_av_beacon(cursor);
                break;
            case HOMEPLUG_AV_DEL_TYPE_SOF:
                dissect_homeplug_av_start_of_frame(cursor);
                break;
            case HOMEPLUG_AV_DEL_TYPE_SACK:
                dissect_homeplug_av_sack(cursor);
                break;
            case HOMEPLUG_AV_DEL_TYPE_RTS:
                dissect_homeplug_av_rtscts(cursor);
                break;
            case HOMEPLUG_AV_DEL_TYPE_SOUND:
                dissect_homeplug_av_sound(cursor);
                break;
            case HOMEPLUG_AV_DEL_TYPE_RSOF:
                dissect_homeplug_av_rsof(cursor);
                break;
            default:
                break;
            }
        }
        ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_nw_info_cnf(ptvcursor_t *cursor, guint8 homeplug_av_mmver)
{
    proto_item *it;
    guint8      num_avlns;
    guint8      num_stas;
    guint8      sta;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_nw_info_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_nw_info_cnf);
    {
        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 5, ENC_NA);

        num_avlns = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                   ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_avlns, 1, ENC_BIG_ENDIAN);

        if (num_avlns) {
            dissect_homeplug_av_nw_info_net(cursor, TRUE, homeplug_av_mmver);
            num_stas = tvb_get_guint8(ptvcursor_tvbuff(cursor),
                                      ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_homeplug_av_nw_info_num_stas, 1, ENC_BIG_ENDIAN);

            if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
                ptvcursor_add(cursor, hf_homeplug_av_reserved, 5, ENC_NA);

            for (sta = 0; sta < num_stas; sta++) {
                dissect_homeplug_av_nw_info_sta(cursor, TRUE, homeplug_av_mmver);
            }
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cp_rpt_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cp_rpt_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cp_rpt_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_req_session_id, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_req_clr, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cp_rpt_ind(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cp_rpt_ind, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cp_rpt_ind);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_status, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_major_ver, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_minor_ver, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 14, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_session_id, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_total_size, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_blk_offset, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_byte_index, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_num_parts, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_curr_part, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_data_len, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cp_rpt_ind_data_ofs, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_cp_rpt_ind_data, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_fr_lbk_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_fr_lbk_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_fr_lbk_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_duration, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_len, 2, ENC_BIG_ENDIAN);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_fr_lbk_req_data, -1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_fr_lbk_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_fr_lbk_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_fr_lbk_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_duration, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_fr_lbk_len, 2, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_lbk_stat_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_lbk_stat_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_lbk_stat_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_lbk_stat_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_lbk_stat_cnf_lbk_stat, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_key_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_key_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_key_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_set_key_req_eks, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_set_key_req_nmk, 16, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_nw_info_peks, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_set_key_req_rda, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_set_key_req_dak, 16, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_key_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_key_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_key_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_set_key_cnf_status, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_mfg_string_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_mfg_string_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_mfg_string_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_mfg_string_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mfg_string_cnf_len, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_mfg_string_cnf_string, 64, ENC_ASCII|ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cblock_hdr(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cblock_hdr, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cblock_hdr);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_ver, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_img_rom_addr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_img_addr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_img_len, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_img_chksum, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_entry_point, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_minor, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_img_type, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_ignore_mask, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_module_id, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_module_subid, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_next_hdr, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_hdr_chksum, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_cblock(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_cblock, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_cblock);
    {
        ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_size, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_conf, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_tim0, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_tim1, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_cntrl, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_sdram_refresh, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_cblock_mac_clock, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_rd_cblock_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_rd_cblock_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_rd_cblock_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_rd_cblock_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_rd_cblock_cnf_len, 1, ENC_BIG_ENDIAN);
        dissect_homeplug_av_cblock_hdr(cursor);
        dissect_homeplug_av_cblock(cursor);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_sdram_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_sdram_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_sdram_req);
    {
        dissect_homeplug_av_cblock(cursor);
        ptvcursor_add(cursor, hf_homeplug_av_set_sdram_req_chksum, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_set_sdram_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_set_sdram_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_set_sdram_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_set_sdram_cnf_status, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_host_action_ind(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_host_action_ind, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_host_action_ind);
    {
        ptvcursor_add(cursor, hf_homeplug_av_host_action_ind_act, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_host_action_rsp(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_host_action_rsp, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_host_action_rsp);
    {
        ptvcursor_add(cursor, hf_homeplug_av_host_action_rsp_sts, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_op_attr_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_op_attr_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_cookie, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_rep_type, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_op_attr_bin_report(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_cnf_data, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_op_attr_data);
    {
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_hw, 16, ENC_ASCII|ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw, 16, ENC_ASCII|ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_major, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_minor, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_sub, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_num, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_date, 8, ENC_ASCII|ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_rel, 12, ENC_ASCII|ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_sdram_type, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
        ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_data_sw_linefreq, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_zerocross, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_sdram_size, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_data_sw_auth_mode, 1, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_op_attr_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_op_attr_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_op_attr_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_cnf_status, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_cookie, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_rep_type, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_op_attr_cnf_size, 2, ENC_LITTLE_ENDIAN);
        dissect_homeplug_av_op_attr_bin_report(cursor);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_enet_phy_req(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_enet_phy_req, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_enet_phy_req);
    {
        ptvcursor_add(cursor, hf_homeplug_av_enet_phy_req_mcontrol, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_enet_phy_req_addcaps, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_reserved, 3, ENC_NA);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_get_enet_phy_cnf(ptvcursor_t *cursor)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_enet_phy_cnf, -1, ENC_NA);

    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_enet_phy_cnf);
    {
        ptvcursor_add(cursor, hf_homeplug_av_enet_phy_cnf_status, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_enet_phy_cnf_speed, 1, ENC_BIG_ENDIAN);
        ptvcursor_add(cursor, hf_homeplug_av_enet_phy_cnf_duplex, 1, ENC_BIG_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_tx_req(ptvcursor_t *cursor, guint8 homeplug_av_mmver)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_tx_req, -1, ENC_NA);
    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_tx_req);
    {
        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
        {
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_req_mac, 6, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_req_slot, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_req_coupling, 1, ENC_LITTLE_ENDIAN);
        }
        else
        {
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_req_mac, 6, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_req_slot, 1, ENC_BIG_ENDIAN);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_rx_req(ptvcursor_t *cursor, guint8 homeplug_av_mmver)
{
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_rx_req, -1, ENC_NA);
    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_rx_req);
    {
        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
        {
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_req_mac, 6, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_req_slot, 1, ENC_BIG_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_req_coupling, 1, ENC_LITTLE_ENDIAN);
        }
        else
        {
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_req_mac, 6, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_req_slot, 1, ENC_BIG_ENDIAN);
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_carrier(ptvcursor_t *cursor, guint16 num_carriers)
{
    proto_item *it, *ittm;
    guint8 hilo, hi_bits, lo_bits, hi_snr, lo_snr;
    guint16 num_carrier_bytes, cb, cid;
    guint16 num_act_carriers=0, total_bits=0, total_snr=0;

    static const guint8 map_carrier2modbits[]    = { 0, 1, 2, 3,  4,  6,  8, 10, 12, 0, 0, 0, 0, 0, 0, 0 }; /* Carrier-Nibble to #Modulated-Bits Mapping */
    static const guint8 map_carrier2modbitsSnr[] = { 0, 2, 4, 7, 10, 16, 22, 28, 36, 0, 0, 0, 0, 0, 0, 0 }; /* Carrier-Nibble to #Modulated-Bits-SNR Mapping */

    if (!ptvcursor_tree(cursor))
        return;
    num_carrier_bytes = num_carriers / 2;

    /* check if number of carriers is odd */
    if (num_carriers & 1)
        num_carrier_bytes += 1;

    ittm = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_carriers, num_carrier_bytes, ENC_NA);
    ptvcursor_push_subtree(cursor, ittm, ett_homeplug_av_tone_map_carriers);

    for (cb = 0; cb < num_carrier_bytes; cb++)
    {
        it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_carrier, 1, ENC_NA);
        cid = cb*2;
        proto_item_append_text(it, " (Carrier #%d/#%d)", cid, cid+1 );

        ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_carrier);
        {
            hilo = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            lo_bits = map_carrier2modbits[ (hilo & 0x0f) ];
            hi_bits = map_carrier2modbits[ (hilo & 0xf0) >> 4 ];
            if(lo_bits) num_act_carriers++;
            if(hi_bits) num_act_carriers++;
            lo_snr = map_carrier2modbitsSnr[ (hilo & 0x0f) ];
            hi_snr = map_carrier2modbitsSnr[ (hilo & 0xf0) >> 4 ];

            it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_carrier_lo, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(it, "Carrier #%d -> %u bits@SNR %udB: ", cid  , lo_bits, lo_snr);
            it = ptvcursor_add(cursor, hf_homeplug_av_tone_map_carrier_hi, 1, ENC_BIG_ENDIAN);
            proto_item_prepend_text(it, "Carrier #%d -> %u bits@SNR %udB: ", cid+1, hi_bits, hi_snr );
        }
        ptvcursor_pop_subtree(cursor);
        total_bits += (hi_bits+lo_bits);
        total_snr  += (hi_snr+lo_snr);
    }

    if (num_act_carriers)
    {
        /* Append to TM-Subtree: total modulated bits, number of active carriers, Average #Bits/Carrier, Average SNR/Carrier */
        proto_item_append_text(ittm, " (Total #ModulatedBits=%d bit, Active #Carriers=%d, Average #Bits/Carrier=%.2f bit), Average SNR/Carrier=%.2f dB)",
                               total_bits, num_act_carriers, (float) total_bits/num_act_carriers, (float) total_snr/num_act_carriers );
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_tx_cnf(ptvcursor_t *cursor, guint8 homeplug_av_mmver)
{
    proto_item *it;
    guint16     num_act_carriers;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_tx_cnf, -1, ENC_NA);
    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_tx_cnf);
    {
        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
        {
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_status, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_len, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 2, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_mac, 6, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_slot, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_num_tms, 2, ENC_LITTLE_ENDIAN);

            num_act_carriers = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_num_act, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);

            if (num_act_carriers)
            {
                dissect_homeplug_av_tone_map_carrier(cursor, num_act_carriers);
            }
        }
        else
        {
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_status, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_slot, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_num_tms, 1, ENC_LITTLE_ENDIAN);

            num_act_carriers = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_tx_cnf_num_act, 2, ENC_LITTLE_ENDIAN);

            if (num_act_carriers)
            {
                dissect_homeplug_av_tone_map_carrier(cursor, num_act_carriers);
            }
        }
    }
    ptvcursor_pop_subtree(cursor);
}

static void
dissect_homeplug_av_tone_map_rx_cnf(ptvcursor_t *cursor, guint8 homeplug_av_mmver)
{
    proto_item *it;
    guint16     num_act_carriers;

    if (!ptvcursor_tree(cursor))
        return;

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_tone_map_rx_cnf, -1, ENC_NA);
    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_tone_map_rx_cnf);
    {
        if (homeplug_av_mmver == HOMEPLUG_AV_MMVER_1_1)
        {
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_status, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_len, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_subver, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_mac, 6, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_slot, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_coupling, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_num_tms, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);

            num_act_carriers = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_num_act, 2, ENC_LITTLE_ENDIAN);

            if (num_act_carriers)
            {
                ptvcursor_add(cursor, hf_homeplug_av_reserved, 4, ENC_NA);
                ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_gil, 1, ENC_LITTLE_ENDIAN);
                ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);
                ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_agc, 1, ENC_LITTLE_ENDIAN);
                ptvcursor_add(cursor, hf_homeplug_av_reserved, 1, ENC_NA);

                dissect_homeplug_av_tone_map_carrier(cursor, num_act_carriers);
            }
        }
        else
        {
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_status,  1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_slot,    1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_num_tms, 1, ENC_LITTLE_ENDIAN);

            num_act_carriers = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_num_act, 2, ENC_LITTLE_ENDIAN);

            if (num_act_carriers)
            {
                dissect_homeplug_av_tone_map_carrier(cursor, num_act_carriers);

                if (num_act_carriers > HOMEPLUG_AV_TONE_MAP_MAX_NUM_CARRIERS_A)
                    ptvcursor_add(cursor, hf_homeplug_av_reserved, (HOMEPLUG_AV_TONE_MAP_MAX_NUM_CARRIERS_B-num_act_carriers) >>1 , ENC_NA);
                else
                    ptvcursor_add(cursor, hf_homeplug_av_reserved, (HOMEPLUG_AV_TONE_MAP_MAX_NUM_CARRIERS_A-num_act_carriers) >>1 , ENC_NA);

                ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_gil, 1, ENC_LITTLE_ENDIAN);
                ptvcursor_add(cursor, hf_homeplug_av_tone_map_rx_cnf_agc, 1, ENC_LITTLE_ENDIAN);
            }
        }
    }
    ptvcursor_pop_subtree(cursor);
}


static void
dissect_homeplug_av_cc_assoc_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_reqtype, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_nid, 7, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_cco_cap, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_proxy_net_cap, 1, ENC_NA);
}

static void
dissect_homeplug_av_cc_assoc_cnf(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_result, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_nid, 7, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_snid, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_tei, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cc_assoc_lease_time, 2, ENC_LITTLE_ENDIAN);
}

static void
dissect_homeplug_av_cc_set_tei_map_ind(ptvcursor_t *cursor) {
    guint8 numberOfSTA = 0;
    guint iter = 0;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_cc_set_tei_map_ind_mode, 1, ENC_NA);

    numberOfSTA = tvb_get_guint8( ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_cc_set_tei_map_ind_num, 1, ENC_NA);

    for ( iter = 0; iter < numberOfSTA; ++iter ) {
        ptvcursor_add(cursor, hf_homeplug_av_cc_set_tei_map_ind_tei, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_cc_set_tei_map_ind_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_cc_set_tei_map_ind_status, 1, ENC_NA);
    }
}

static void
dissect_homeplug_av_cm_unassociated_sta_ind(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_cm_unassoc_sta_nid, 7, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_cm_unassoc_sta_cco_cap, 1, ENC_NA);
}

/* HPAV/GP dissect functions */
static void
dissect_homeplug_av_gp_cm_slac_parm_req(ptvcursor_t *cursor) {

    guint8 sectype,cipher_size;
    guint16 Counter;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_apptype, 1, ENC_NA);
    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_sectype, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_runid, 8, ENC_NA);
    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        cipher_size = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_cipher_size, 1, ENC_NA);
        for (Counter = 0; Counter < cipher_size; ++Counter) {
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_cipher, 2, ENC_LITTLE_ENDIAN);
        }
    }
}

static void
dissect_homeplug_av_gp_cm_slac_parm_cnf(ptvcursor_t *cursor) {

    guint8 sectype;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_sound_target, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_sound_count, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_time_out, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_resptype, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_forwarding_sta, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_apptype, 1, ENC_NA);
    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_sectype, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_runid, 8, ENC_NA);
    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_parm_cipher, 2, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_homeplug_av_gp_cm_atten_profile_ind(ptvcursor_t *cursor) {

    guint8 group_size;
    guint16 Counter;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_profile_ind_pev_mac, 6, ENC_NA);
    group_size = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_profile_ind_num_groups, 1, ENC_NA);
    /* Skip reserved */
    ptvcursor_advance(cursor, 1);
    for (Counter = 0; Counter < group_size; ++Counter) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_profile_ind_aag, 1, ENC_NA);
    }
}

static void
dissect_homeplug_av_gp_cm_atten_char_ind(ptvcursor_t *cursor, packet_info *pinfo) {

    guint8 sectype, numgroups, val;
    guint16 Counter_groups;
    proto_item *it;
    gfloat avg;

    avg = 0.0f;

    if (!ptvcursor_tree(cursor)) {
        ptvcursor_advance(cursor, 1);
        sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
        ptvcursor_advance(cursor, 1);
        if (sectype != HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
            ptvcursor_advance(cursor, 6+8+17+17+1);
            numgroups = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_advance(cursor, 1);
            for (Counter_groups = 0; Counter_groups < numgroups; ++Counter_groups) {
                val = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
                avg += val;
                ptvcursor_advance(cursor,1);
            }
            avg /= numgroups;
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Groups = %d, Avg. Attenuation = %.2f dB)", numgroups, avg);
        }
        return;
    }

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_apptype, 1, ENC_NA);
    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_sectype, 1, ENC_NA);

    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_cms_data, -1, ENC_NA);
    } else {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_source_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_runid, 8, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_source_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_resp_id, 17, ENC_NA);

        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_numsounds, 1, ENC_NA);

        numgroups = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));

        it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_gp_cm_atten_char_profile, numgroups+1 , ENC_NA);

        ptvcursor_push_subtree(cursor, it, ett_homeplug_av_gp_cm_atten_char_profile);
        {
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_numgroups, 1, ENC_NA);
            for (Counter_groups = 0; Counter_groups < numgroups; ++Counter_groups) {
                val = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
                proto_tree_add_uint_format( ptvcursor_tree(cursor),
                                            hf_homeplug_av_gp_cm_atten_char_aag,
                                            ptvcursor_tvbuff(cursor),
                                            ptvcursor_current_offset(cursor), 1, val,
                                            HOMEPLUG_AV_GP_CM_ATTEN_CHAR_AAG_FORMAT, Counter_groups + 1, val );
                ptvcursor_advance(cursor, 1);
            }
        }
        ptvcursor_pop_subtree(cursor);
    }

}

static void
dissect_homeplug_av_gp_cm_atten_char_rsp(ptvcursor_t *cursor) {

    guint8 sectype;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_apptype, 1, ENC_NA);
    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_sectype, 1, ENC_NA);

    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_cms_data, -1, ENC_NA);
    } else {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_source_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_runid, 8, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_source_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_resp_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_result, 1, ENC_NA);
    }
}

static void
dissect_homeplug_av_gp_cm_start_atten_char_ind(ptvcursor_t *cursor) {

    guint8 sectype;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_apptype, 1, ENC_NA);
    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_sectype, 1, ENC_NA);

    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_cms_data, -1, ENC_NA);
    } else {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_start_atten_char_numsounds, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_start_atten_char_time_out, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_start_atten_char_resptype, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_start_atten_char_forwarding_sta, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_start_atten_char_runid, 8, ENC_NA);
    }
}

static void
dissect_homeplug_av_gp_cm_mnbc_sound_ind(ptvcursor_t *cursor) {

    guint8 apptype,sectype;

    if (!ptvcursor_tree(cursor))
        return;

    apptype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_apptype, 1, ENC_NA);

    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_sectype, 1, ENC_NA);

    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_cms_data, -1, ENC_NA);
    } else {
        switch (apptype) {
        case HOMEPLUG_AV_GP_APPTYPE_PEV_EVSE_ASSOC:
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_sender_id, 17, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_countdown, 1, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_runid, 8, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_rsvd, 8, ENC_NA);
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_mnbc_sound_rnd, 16, ENC_NA);
            break;
        }
    }
}

static void
dissect_homeplug_av_gp_cm_validate_req(ptvcursor_t *cursor) {

    guint8 signaltype;

    if (!ptvcursor_tree(cursor))
        return;

    signaltype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_validate_signaltype, 1, ENC_NA);
    switch (signaltype) {
    case HOMEPLUG_AV_GP_SIGNAL_TYPE_PEV_S2_TOGGLES:
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_validate_timer, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_validate_result, 1, ENC_NA);
        break;
    }
}

static void
dissect_homeplug_av_gp_cm_validate_cnf(ptvcursor_t *cursor) {

    guint8 signaltype;

    if (!ptvcursor_tree(cursor))
        return;

    signaltype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_validate_signaltype, 1, ENC_NA);
    switch (signaltype) {
    case HOMEPLUG_AV_GP_SIGNAL_TYPE_PEV_S2_TOGGLES:
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_validate_togglenum, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_validate_result, 1, ENC_NA);
        break;
    }
}

static void
dissect_homeplug_av_gp_cm_slac_match_req(ptvcursor_t *cursor) {

    /* guint8 apptype;
       guint16 length; */
    guint8 sectype;

    if (!ptvcursor_tree(cursor))
        return;

    /* apptype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor)); */
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_apptype, 1, ENC_NA);

    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_sectype, 1, ENC_NA);

    /* length = tvb_get_guint16(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor), ENC_LITTLE_ENDIAN); */
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_length, 2, ENC_LITTLE_ENDIAN);

    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_cms_data, -1, ENC_NA);
    } else {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_pev_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_pev_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_evse_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_evse_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_runid, 8, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_rsvd, 8, ENC_NA);
    }
}

static void
dissect_homeplug_av_gp_cm_slac_match_cnf(ptvcursor_t *cursor) {

    /* guint8 apptype;
       guint16 length; */
    guint8 sectype;

    if (!ptvcursor_tree(cursor))
        return;

    //apptype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_apptype, 1, ENC_NA);

    sectype = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_sectype, 1, ENC_NA);

    //length = tvb_get_guint16(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor), ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_length, 2, ENC_LITTLE_ENDIAN);

    if (sectype == HOMEPLUG_AV_GP_SECURITY_TYPE_PUBLIC_KEY) {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_atten_char_cms_data, -1, ENC_NA);
    } else {
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_pev_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_pev_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_evse_id, 17, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_evse_mac, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_runid, 8, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_rsvd, 8, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_nid, 7, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_rsvd,1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_match_nmk,16, ENC_NA);
    }
}
static void
dissect_homeplug_av_gp_cm_slac_user_data(ptvcursor_t *cursor) {

    guint16 Type, Length,TypeLen;
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_user_data_broadcast_tlv_type, 3, ENC_LITTLE_ENDIAN);

    for (;;) {
        /* Get Length and Type from TLV Header */
        TypeLen = tvb_get_guint16(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor),ENC_LITTLE_ENDIAN);
        Length = TypeLen & HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_LENGTH_MASK;
        Type = TypeLen & HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_MASK;
        /* If type and length is null_type - don't add anything and exit */
        if (TypeLen == 0)
            break;
        it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv, HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_HEADER_SIZE, ENC_LITTLE_ENDIAN);
        ptvcursor_push_subtree(cursor, it, ett_homeplug_av_gp_cm_slac_user_data_tlv);
        {
            ptvcursor_add_no_advance(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv_type, HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_MASK, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv_length, HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_LENGTH_MASK, ENC_LITTLE_ENDIAN);
            if (Type == HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_VENDOR_RESERVED) {
                ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv_oui, 3, ENC_LITTLE_ENDIAN);
                ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv_subtype, 1, ENC_NA);
                ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv_info_str, Length - 3 - 1, ENC_NA);
            } else {
                ptvcursor_add(cursor, hf_homeplug_av_gp_cm_slac_user_data_tlv_str_bytes, Length, ENC_NA);
            }
        }
        ptvcursor_pop_subtree(cursor);
    }

}

/* End of HPAV/GP dissect functions */

/* ST/IoTecha dissect functions */

/* General parts */
static void
dissect_homeplug_av_st_iotecha_header(ptvcursor_t *cursor) {

    proto_tree *tree;

    if (!ptvcursor_tree(cursor)) {
        ptvcursor_advance(cursor, 5);
        return;
    }
    /* if we saved vendor subtree */
    if (ti_vendor) {
        /* Save current position */
        tree = ptvcursor_tree(cursor);
        /* Go back to vendor subtree */
        ptvcursor_set_subtree(cursor, ti_vendor, ett_homeplug_av_public);
        /* Add info */
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_header_mmever, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_header_rsvd, 3, ENC_NA);
        /* Extending length of tree item */
        proto_tree_set_appendix(ti_vendor, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor) - 4, 4);
        /* Now back to current position */
        ptvcursor_set_tree(cursor,tree);
    } else {
        /* else - just add fields as is */
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_header_mmever, 1, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_header_rsvd, 3, ENC_NA);
    }
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_header_mver, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_status_standard(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_status_byte, 1, ENC_NA);
}

/* Specific messages */

static void
dissect_homeplug_av_st_iotecha_stp_discover_tlv(ptvcursor_t *cursor) {

    guint16 Type, Length,TypeLen;
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    for (;;) {
        /* Get Length and Type from TLV Header */
        TypeLen = tvb_get_guint16(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor),ENC_LITTLE_ENDIAN);
        Length = TypeLen & HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_LENGTH_MASK;
        Type = TypeLen & HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_MASK;
        /* If type is null_type - don't add anything and exit */
        if (Type == HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_NULL)
            break;
        it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_stp_discover_tlv, HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_HEADER_SIZE, ENC_LITTLE_ENDIAN);
        ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_iotecha_type_length_value);
        {
            ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_stp_discover_tlv_type, HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_HEADER_SIZE, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_stp_discover_tlv_length, HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_HEADER_SIZE, ENC_LITTLE_ENDIAN);
            if (Type == HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_DEVICE_TYPE) {
                ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_stp_discover_tlv_value_bytes, Length, ENC_NA);
            } else {
                ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_stp_discover_tlv_value_string, Length, ENC_ASCII|ENC_NA);
            }
        }
        ptvcursor_pop_subtree(cursor);
    }
}

static void
dissect_homeplug_av_st_iotecha_stp_get_bss_tlv(ptvcursor_t *cursor, guint8 count) {

    guint8 Type;
    guint16 Counter, Length;
    proto_item *it;

    if (!ptvcursor_tree(cursor))
        return;

    for (Counter = 0; Counter < count; ++Counter) {
        Type = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
        if (Type == HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_BEGIN_BSS) {
            it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_bss_entry, 0, ENC_NA);
            ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_iotecha_bss_entry);
            {
                while (Type != HOMEPLUG_AV_ST_IOTECHA_STP_GET_BSS_TYPE_END_BSS) {
                    Type = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
                    it = ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_bss_type, 1, ENC_NA);
                    Length = tvb_get_guint16(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor), ENC_LITTLE_ENDIAN);
                    /* If no data - skip fields */
                    if (Length) {
                        proto_item_append_text(it," Length: %d",Length);
                        ptvcursor_advance(cursor, 2);
                        switch (Type) {
                        default:
                            ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_bss_value_bytes, Length, ENC_NA);
                            break;
                        }

                    } else {
                        ptvcursor_advance(cursor, 2);
                    }
                }
            }
            ptvcursor_pop_subtree(cursor);
        }
    }
}

static void
dissect_homeplug_av_st_iotecha_stp_auth_set_nmk_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_auth_nmk, 16, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_set_maxgain_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_gain_ask, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_set_maxgain_cnf(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    dissect_homeplug_av_st_iotecha_status_standard(cursor);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_gain_new, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_gain_prev, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_linkstatus(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_linkstatus_status, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_linkstatus_devmode, 1, ENC_NA);

}

static void
dissect_homeplug_av_st_iotecha_discover(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    dissect_homeplug_av_st_iotecha_stp_discover_tlv(cursor);
}

static void
dissect_homeplug_av_st_iotecha_stp_get_tei_list_cnf(ptvcursor_t *cursor) {

    guint8 TeiCount;
    guint8 Counter;

    if (!ptvcursor_tree(cursor))
        return;

    TeiCount = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_tei_count, 1, ENC_NA);
    for (Counter = 0; Counter < TeiCount; ++Counter) {
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_tei, 1, ENC_NA);
    }
}

static void
dissect_homeplug_av_st_iotecha_stp_get_tei_snapshot_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_tei, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_get_tei_snapshot_cnf(ptvcursor_t *cursor) {

    guint8 AddrCount;
    guint8 Counter;

    if (!ptvcursor_tree(cursor))
        return;

    AddrCount = tvb_get_guint8(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_tei_snap_addr_count, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_tei_snap_tei, 1, ENC_NA);
    for (Counter = 0; Counter < AddrCount; ++Counter) {
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mac_address, 6, ENC_NA);
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_tei_snap_mac_address_flag, 2, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_homeplug_av_st_iotecha_stp_get_bss_list_cnf(ptvcursor_t *cursor) {

    guint8 Count;

    if (!ptvcursor_tree(cursor))
        return;

    Count  = tvb_get_guint8( ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_bss_list_count, 1, ENC_NA);
    dissect_homeplug_av_st_iotecha_stp_get_bss_tlv(cursor, Count);
}

static void
dissect_homeplug_av_st_iotecha_stp_get_chanqual_report_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_req_type, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mac_address, 6, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_get_chanqual_report_cnf(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_substatus, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mac_address, 6, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_get_chanqual_report_ind(ptvcursor_t *cursor) {

    proto_item *it;
    guint8 tmi_count, int_count;
    guint16 Counter;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mac_address, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_mac_local, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_mac_remote, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_source, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_response_type, 1, ENC_NA);
    /* TMI */
    tmi_count  = tvb_get_guint8( ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_tmi_count, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_tmi, tmi_count, ENC_NA);
    /* Intervals */
    int_count = tvb_get_guint8( ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_int_count, 1, ENC_NA);

    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_chanqual_int,
                                  int_count*3, ENC_NA);
    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_iotecha_chanqual_int);
    {
        for (Counter = 0; Counter < int_count; ++Counter) {
            ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_int_et, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_int_tmi, 1, ENC_NA);
        }
    }
    ptvcursor_pop_subtree(cursor);
    /* TMI Attached */
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_tmi_attached, 1, ENC_NA);
    /* Reserved 1 */
    ptvcursor_advance(cursor,1);
    /* FEC */
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chanqual_fec_type, 1, ENC_NA);
    /* Reserved 2 */
    ptvcursor_advance(cursor,1);
    /* CBLD */
    it = ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_chanqual_cbld, -1, ENC_NA);
    ptvcursor_push_subtree(cursor, it, ett_homeplug_av_st_iotecha_chanqual_cbld);
    {
        for (Counter = 0; Counter < HOMEPLUG_AV_ST_IOTECHA_CHANQUAL_CBLD_DATA_COUNT; ++Counter) {
            ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_chanqual_cbld_data_low, 1, ENC_NA);
            ptvcursor_add_no_advance(cursor, hf_homeplug_av_st_iotecha_chanqual_cbld_data_high, 1, ENC_NA);
            ptvcursor_advance(cursor, 1);
        }
    }
    ptvcursor_pop_subtree(cursor);

}

static void
dissect_homeplug_av_st_iotecha_stp_mfct_update_stage_req(ptvcursor_t *cursor) {

    guint16 Length;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_crc, 2, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_total_length, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_offset, 2, ENC_LITTLE_ENDIAN);

    Length = tvb_get_guint16(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor),ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_length, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_data, Length, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_mfct_update_stage_cnf(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_crc, 2, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_timeout, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_offset, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_result, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_mfct_update_finish_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_request_type, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_reboot, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_mfct_get_item_req(ptvcursor_t *cursor) {

    gint name_size;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_item_offset, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_item_total_length, 4, ENC_LITTLE_ENDIAN);
    tvb_get_const_stringz(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor), &name_size);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_name, name_size-1, ENC_ASCII|ENC_NA);
    /* Skip terminator */
    ptvcursor_advance(cursor, 1);
}

static void
dissect_homeplug_av_st_iotecha_stp_mfct_get_item_cnf(ptvcursor_t *cursor) {

    gint name_size;

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_item_offset, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_item_total_length, 4, ENC_LITTLE_ENDIAN);
    tvb_get_const_stringz(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor), &name_size);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_name, name_size - 1, ENC_ASCII|ENC_NA);
    /* Skip terminator */
    ptvcursor_advance(cursor,1);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_value, -1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_mfct_get_keylist_cnf(ptvcursor_t *cursor) {

    gint name_size;

    if (!ptvcursor_tree(cursor))
        return;

    while (tvb_reported_length_remaining(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)) > 1 )
    {
        if ((tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)) == '\0')
            && (tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor) + 1) == '\0'))
            break;
        tvb_get_const_stringz(ptvcursor_tvbuff(cursor),ptvcursor_current_offset(cursor), &name_size);
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_mfct_name, name_size - 1, ENC_ASCII|ENC_NA);
        /* Skip terminator */
        ptvcursor_advance(cursor,1);
    }
}

static void
dissect_homeplug_av_st_iotecha_stp_fup_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_stp_fup_mac_da, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_stp_fup_mac_sa, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_stp_fup_mtype, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_cpstate_ind(ptvcursor_t *cursor, packet_info *pinfo) {

    guint8 bitmask;
    guint8 cp_state;
    guint8 pwm_duty;

    cp_state = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    pwm_duty = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)+1);
    col_add_fstr(pinfo->cinfo, COL_INFO, "CP State Change: %s, %d%%", val_to_str_const(cp_state, homeplug_av_st_iotecha_stp_cpstate_state_vals, "Unknown"), pwm_duty);

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_state, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_pwm_duty, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_pwm_freq, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_volatge, 2, ENC_LITTLE_ENDIAN);
    bitmask = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    if (bitmask)
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_adc_bitmask, 1, ENC_NA);
    else
        ptvcursor_advance(cursor, 1);


    if (bitmask & 0x01)
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_adc_voltage_1, 2, ENC_LITTLE_ENDIAN);
    else
        ptvcursor_advance(cursor, 2);

    if (bitmask & 0x02)
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_adc_voltage_2, 2, ENC_LITTLE_ENDIAN);
    else
        ptvcursor_advance(cursor, 2);

    if (bitmask & 0x04)
        ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_cpstate_adc_voltage_3, 2, ENC_LITTLE_ENDIAN);
    else
        ptvcursor_advance(cursor, 2);

}

static void
dissect_homeplug_av_st_iotecha_stp_user_message_ind(ptvcursor_t *cursor, packet_info *pinfo) {

    gint null_offset;


    ptvcursor_advance(cursor, 4); // not used fields
    ptvcursor_advance(cursor, 4); // not used fields

    null_offset = tvb_find_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor) + 1, -1, 0);

    if (null_offset > -1) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                        tvb_get_const_stringz(ptvcursor_tvbuff(cursor),
                                              ptvcursor_current_offset(cursor),
                                              NULL));
    }

    if (!ptvcursor_tree(cursor))
        return;

    if (null_offset > -1) {
        ptvcursor_add(cursor,
                      hf_homeplug_av_st_iotecha_user_message_info,
                      null_offset - ptvcursor_current_offset(cursor),
                      ENC_ASCII|ENC_NA);
    }

    null_offset = tvb_find_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor) + 1, -1, 0);

    if (null_offset > -1) {
        ptvcursor_add(cursor,
                      hf_homeplug_av_st_iotecha_user_message_details,
                      null_offset - ptvcursor_current_offset(cursor),
                      ENC_ASCII|ENC_NA);
    }

}

static void
dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_rx_req(ptvcursor_t *cursor) {

    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_test_type, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_num_sound, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_data_ind_addr, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_agc_lock, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_db_agc_val, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_rx_cnf(ptvcursor_t *cursor) {
    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_test_status, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_tx_req(ptvcursor_t *cursor) {
    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_test_type, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_num_sound, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_data_ind_addr, 6, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_suppress_data, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_tx_cnf(ptvcursor_t *cursor) {
    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_test_status, 1, ENC_NA);
}

static void
dissect_homeplug_av_st_iotecha_stp_test_chan_atten_data_ind(ptvcursor_t *cursor) {
    if (!ptvcursor_tree(cursor))
        return;

    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_sound_remain, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_ntb_time, 4, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_db_agc_val, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_rsvd1, 3, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_rsvd2, 4, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_num_segments, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_segment, 1, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_num_chan, 2, ENC_NA);
    ptvcursor_add(cursor, hf_homeplug_av_st_iotecha_chan_start, 2, ENC_NA);
}
/* End of ST/IoTecha dissect functions */


static void
dissect_homeplug_av_mme_general(ptvcursor_t *cursor,
                                guint8 homeplug_av_mmver,
                                guint16 homeplug_av_mmtype,
                                packet_info *pinfo) {
    (void)homeplug_av_mmver;
    /* Public MMEs */
    switch ((homeplug_av_mmetypes_general_type)homeplug_av_mmtype)
    {
    case HOMEPLUG_AV_MMTYPE_GENERAL_CC_DISCOVER_LIST_CNF:
        dissect_homeplug_av_cc_disc_list_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_ENCRYPTED_PAYLOAD_IND:
        dissect_homeplug_av_cm_enc_pld_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_ENCRYPTED_PAYLOAD_RSP:
        dissect_homeplug_av_cm_enc_pld_rsp(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_SET_KEY_REQ:
        dissect_homeplug_av_cm_set_key_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_SET_KEY_CNF:
        dissect_homeplug_av_cm_set_key_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_KEY_REQ:
        dissect_homeplug_av_cm_get_key_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_GET_KEY_CNF:
        dissect_homeplug_av_cm_get_key_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_BRG_INFO_CNF:
        dissect_homeplug_av_get_brg_infos_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_INFO_CNF:
        dissect_homeplug_av_nw_infos_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_NW_STATS_CNF:
        dissect_homeplug_av_nw_stats_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CC_ASSOC_REQ:
        dissect_homeplug_av_cc_assoc_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CC_ASSOC_CNF:
        dissect_homeplug_av_cc_assoc_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CM_UNASSOCIATED_STA_IND:
        dissect_homeplug_av_cm_unassociated_sta_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_GENERAL_CC_SET_TEI_MAP_IND:
        dissect_homeplug_av_cc_set_tei_map_ind(cursor);
        break;
        /* HPGP */
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_PARM_REQ:
        dissect_homeplug_av_gp_cm_slac_parm_req(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_PARM_CNF:
        dissect_homeplug_av_gp_cm_slac_parm_cnf(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_PROFILE_IND:
        dissect_homeplug_av_gp_cm_atten_profile_ind(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_CHAR_IND:
        dissect_homeplug_av_gp_cm_atten_char_ind(cursor, pinfo);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_ATTEN_CHAR_RSP:
        dissect_homeplug_av_gp_cm_atten_char_rsp(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_START_ATTEN_CHAR_IND:
        dissect_homeplug_av_gp_cm_start_atten_char_ind(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_MNBC_SOUND_IND:
        dissect_homeplug_av_gp_cm_mnbc_sound_ind(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_VALIDATE_REQ:
        dissect_homeplug_av_gp_cm_validate_req(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_VALIDATE_CNF:
        dissect_homeplug_av_gp_cm_validate_cnf(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_MATCH_REQ:
        dissect_homeplug_av_gp_cm_slac_match_req(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_MATCH_CNF:
        dissect_homeplug_av_gp_cm_slac_match_cnf(cursor);
        break;
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_USER_DATA_REQ:
    case HOMEPLUG_AV_GP_MMTYPE_GENERAL_CM_SLAC_USER_DATA_CNF:
        dissect_homeplug_av_gp_cm_slac_user_data(cursor);
        break;
    default:
        break;
    };
}

static void
dissect_homeplug_av_mme_qualcomm(ptvcursor_t *cursor, guint8 homeplug_av_mmver, guint16 homeplug_av_mmtype) {
    switch ((homeplug_av_mmetypes_qualcomm_type)homeplug_av_mmtype) {
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_SW_CNF:
        dissect_homeplug_av_get_sw_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MEM_REQ:
        dissect_homeplug_av_wr_mem_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MEM_CNF:
        dissect_homeplug_av_wr_mem_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MEM_REQ:
        dissect_homeplug_av_rd_mem_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MEM_CNF:
        dissect_homeplug_av_rd_mem_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_ST_MAC_REQ:
        dissect_homeplug_av_st_mac_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_ST_MAC_CNF:
        dissect_homeplug_av_st_mac_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_NVM_CNF:
        dissect_homeplug_av_get_nvm_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_RS_DEV_CNF:
        dissect_homeplug_av_rs_dev_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_REQ:
        dissect_homeplug_av_wr_mod_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_CNF:
        dissect_homeplug_av_wr_mod_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WR_MOD_IND:
        dissect_homeplug_av_wr_mod_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MOD_REQ:
        dissect_homeplug_av_rd_mod_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_MOD_CNF:
        dissect_homeplug_av_rd_mod_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_NVM_MOD_REQ:
        dissect_homeplug_av_mod_nvm_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_NVM_MOD_CNF:
        dissect_homeplug_av_mod_nvm_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WD_RPT_REQ:
        dissect_homeplug_av_wd_rpt_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_WD_RPT_IND:
        dissect_homeplug_av_wd_rpt_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_LNK_STATS_REQ:
        dissect_homeplug_av_lnk_stats_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_LNK_STATS_CNF:
        dissect_homeplug_av_lnk_stats_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_REQ:
        dissect_homeplug_av_sniffer_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_CNF:
        dissect_homeplug_av_sniffer_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SNIFFER_IND:
        dissect_homeplug_av_sniffer_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_NW_INFO_CNF:
        dissect_homeplug_av_nw_info_cnf(cursor, homeplug_av_mmver);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_CP_RPT_REQ:
        dissect_homeplug_av_cp_rpt_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_CP_RPT_IND:
        dissect_homeplug_av_cp_rpt_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_FR_LBK_REQ:
        dissect_homeplug_av_fr_lbk_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_FR_LBK_CNF:
        dissect_homeplug_av_fr_lbk_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_LBK_STAT_CNF:
        dissect_homeplug_av_lbk_stat_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_KEY_REQ:
        dissect_homeplug_av_set_key_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_KEY_CNF:
        dissect_homeplug_av_set_key_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_MFG_STRING_CNF:
        dissect_homeplug_av_mfg_string_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_RD_CBLOCK_CNF:
        dissect_homeplug_av_rd_cblock_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_SDRAM_REQ:
        dissect_homeplug_av_set_sdram_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_SET_SDRAM_CNF:
        dissect_homeplug_av_set_sdram_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_HOST_ACTION_IND:
        dissect_homeplug_av_host_action_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_HOST_ACTION_RSP:
        dissect_homeplug_av_host_action_rsp(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_OP_ATTR_REQ:
        dissect_homeplug_av_op_attr_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_OP_ATTR_CNF:
        dissect_homeplug_av_op_attr_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_ENET_PHY_REQ:
        dissect_homeplug_av_get_enet_phy_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_GET_ENET_PHY_CNF:
        dissect_homeplug_av_get_enet_phy_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_RX_REQ:
        dissect_homeplug_av_tone_map_rx_req(cursor, homeplug_av_mmver);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_RX_CNF:
        dissect_homeplug_av_tone_map_rx_cnf(cursor, homeplug_av_mmver);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_TX_REQ:
        dissect_homeplug_av_tone_map_tx_req(cursor, homeplug_av_mmver);
        break;
    case HOMEPLUG_AV_MMTYPE_QUALCOMM_TONE_MAP_TX_CNF:
        dissect_homeplug_av_tone_map_tx_cnf(cursor, homeplug_av_mmver);
        break;
    default:
        break;
    }
}

static void
dissect_homeplug_av_mme_st_iotecha(ptvcursor_t *cursor,
                                   guint8 homeplug_av_mmver,
                                   guint16 homeplug_av_mmtype,
                                   packet_info *pinfo) {
    (void)homeplug_av_mmver;
    /* Parse head of the message */
    dissect_homeplug_av_st_iotecha_header(cursor);
    /* Parse the rest */
    switch ((homeplug_av_mmetypes_st_iotecha_type)homeplug_av_mmtype) {
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_AUTH_SET_NMK_REQ:
        dissect_homeplug_av_st_iotecha_stp_auth_set_nmk_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_REQ:
        dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_rx_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_REQ:
        dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_tx_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_RX_CNF:
        dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_rx_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_START_TX_CNF:
        dissect_homeplug_av_st_iotecha_stp_test_chan_atten_start_tx_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_TEST_CHAN_ATTEN_DATA_IND:
        dissect_homeplug_av_st_iotecha_stp_test_chan_atten_data_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_AUTH_SET_NMK_CNF:
        /* NOT SURE */
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_FINISH_CNF:
        /* General message with status byte */
        dissect_homeplug_av_st_iotecha_status_standard(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_IND:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_CNF:
        dissect_homeplug_av_st_iotecha_linkstatus(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_CNF:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_LOCAL_CNF:
        dissect_homeplug_av_st_iotecha_discover(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_SET_MAXGAIN_REQ:
        dissect_homeplug_av_st_iotecha_stp_set_maxgain_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_SET_MAXGAIN_CNF:
        dissect_homeplug_av_st_iotecha_stp_set_maxgain_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_LIST_CNF:
        dissect_homeplug_av_st_iotecha_stp_get_tei_list_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_SNAPSHOT_REQ:
        dissect_homeplug_av_st_iotecha_stp_get_tei_snapshot_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_SNAPSHOT_CNF:
        dissect_homeplug_av_st_iotecha_stp_get_tei_snapshot_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_BSS_LIST_CNF:
        dissect_homeplug_av_st_iotecha_stp_get_bss_list_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_REQ:
        dissect_homeplug_av_st_iotecha_stp_get_chanqual_report_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_CNF:
        dissect_homeplug_av_st_iotecha_stp_get_chanqual_report_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CHANQUAL_REPORT_IND:
        dissect_homeplug_av_st_iotecha_stp_get_chanqual_report_ind(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_STAGE_REQ:
        dissect_homeplug_av_st_iotecha_stp_mfct_update_stage_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_STAGE_CNF:
        dissect_homeplug_av_st_iotecha_stp_mfct_update_stage_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_UPDATE_FINISH_REQ:
        dissect_homeplug_av_st_iotecha_stp_mfct_update_finish_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_ITEM_REQ:
        dissect_homeplug_av_st_iotecha_stp_mfct_get_item_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_ITEM_CNF:
        dissect_homeplug_av_st_iotecha_stp_mfct_get_item_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_KEYLIST_CNF:
        dissect_homeplug_av_st_iotecha_stp_mfct_get_keylist_cnf(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_FUP_REQ:
        dissect_homeplug_av_st_iotecha_stp_fup_req(cursor);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_CPSTATE_IND:
        dissect_homeplug_av_st_iotecha_stp_cpstate_ind(cursor, pinfo);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_USER_MESSAGE_IND:
        dissect_homeplug_av_st_iotecha_stp_user_message_ind(cursor, pinfo);
        break;
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_BSS_LIST_REQ:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_GET_TEI_LIST_REQ:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_LINK_STATUS_REQ:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_LOCAL_REQ:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_DISCOVER_REQ:
    case HOMEPLUG_AV_MMTYPE_ST_IOTECHA_STP_MFCT_GET_KEYLIST_REQ:
        /* Requests only with header go here */
        break;
    default:
        break;
    }
}

static void
dissect_homeplug_av_mme(ptvcursor_t *cursor,
                        guint8 homeplug_av_mmver,
                        guint16 homeplug_av_mmtype,
                        guint32 homeplug_av_oui,
                        packet_info *pinfo)
{
    if (!homeplug_av_oui) {
        dissect_homeplug_av_mme_general(cursor, homeplug_av_mmver, homeplug_av_mmtype, pinfo);
    } else   {
        switch (homeplug_av_oui) {
        case HOMEPLUG_AV_OUI_QCA:
            dissect_homeplug_av_mme_qualcomm(cursor, homeplug_av_mmver, homeplug_av_mmtype);
            break;
        case HOMEPLUG_AV_OUI_ST_IOTECHA:
            dissect_homeplug_av_mme_st_iotecha(cursor, homeplug_av_mmver, homeplug_av_mmtype, pinfo);
            break;
        }
    }
}

static void
info_column_filler_initial(guint8 homeplug_av_mmver,
                           guint16 homeplug_av_mmtype,
                           guint32 homeplug_av_oui,
                           packet_info *pinfo) {
    (void)homeplug_av_mmver;

    /* if packet is vendor specific - display vendor OUI */
    if (homeplug_av_oui) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           val_to_str(homeplug_av_oui, homeplug_av_vendors_oui_vals, "OUI:0x%x"));
    }

    /* Info depends on type and oui */
    switch (homeplug_av_oui)
    {
    case HOMEPLUG_AV_OUI_ST_IOTECHA:
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           val_to_str_ext(homeplug_av_mmtype,
                                          &homeplug_av_mmtype_st_iotecha_vals_ext,
                                          "Unknown 0x%x"));
        break;
    case HOMEPLUG_AV_OUI_QCA:
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           val_to_str_ext(homeplug_av_mmtype,
                                          &homeplug_av_mmtype_qualcomm_vals_ext,
                                          "Unknown 0x%x"));
        break;

    case HOMEPLUG_AV_OUI_NONE:
        /* if oui is unknown, trying to describe as general MME */
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           val_to_str_ext(homeplug_av_mmtype,
                                          &homeplug_av_mmtype_general_vals_ext,
                                          "Unknown 0x%x"));
        break;

    default:
        break;
    }
}

static int
dissect_homeplug_av(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item  *ti;
    proto_tree  *homeplug_av_tree;
    ptvcursor_t *cursor;
    guint8       homeplug_av_mmver;
    guint16      homeplug_av_mmtype;
    guint32      homeplug_av_oui;

    homeplug_av_oui = 0;
    ti_vendor = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HomePlug AV");
    col_set_str(pinfo->cinfo, COL_INFO, "");

    ti = proto_tree_add_item(tree, proto_homeplug_av, tvb, 0, -1, ENC_NA);
    homeplug_av_tree = proto_item_add_subtree(ti, ett_homeplug_av);

    cursor = ptvcursor_new(homeplug_av_tree, tvb, 0);

    /* Check if we have enough data to process the header */
    if (check_tvb_length(cursor, HOMEPLUG_AV_MMHDR_LEN) != TVB_LEN_SHORTEST) {

        dissect_homeplug_av_mmhdr(cursor, &homeplug_av_mmver, &homeplug_av_mmtype, &homeplug_av_oui);

        info_column_filler_initial(homeplug_av_mmver, homeplug_av_mmtype, homeplug_av_oui, pinfo);

        dissect_homeplug_av_mme(cursor, homeplug_av_mmver, homeplug_av_mmtype, homeplug_av_oui, pinfo);

    }

    ti_vendor = 0;
    ptvcursor_free(cursor);
    return tvb_captured_length(tvb);
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
        { &hf_homeplug_av_mmhdr_mmtype_general,
          { "Type", "homeplug_av.mmhdr.mmtype",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &homeplug_av_mmtype_general_vals_ext, 0x0000, NULL, HFILL }
        },
        { &hf_homeplug_av_mmhdr_mmtype_qualcomm,
          { "Type", "homeplug_av.mmhdr.mmtype.qualcomm",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &homeplug_av_mmtype_qualcomm_vals_ext, 0x0000, NULL, HFILL }
        },
        { &hf_homeplug_av_mmhdr_mmtype_st,
          { "Type", "homeplug_av.mmhdr.mmtype.st",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &homeplug_av_mmtype_st_iotecha_vals_ext, 0x0000, NULL, HFILL }
        },
        { &hf_homeplug_av_mmhdr_mmtype_lsb,
          { "LSB", "homeplug_av.mmhdr.mmtype.lsb",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_mmtype_lsb_vals), HOMEPLUG_AV_MMTYPE_LSB_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_mmhdr_mmtype_msb,
          { "MSB", "homeplug_av.mmhdr.mmtype.msb",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_mmtype_msb_vals), HOMEPLUG_AV_MMTYPE_MSB_MASK, "Reserved", HFILL },
        },
        { &hf_homeplug_av_mmhdr_fmi,
          { "Fragmentation Info", "homeplug_av.mmhdr.fmi",
            FT_UINT16, BASE_HEX, NULL, 0x0000, "Reserved", HFILL },
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
        /* Frame control fields */
        { &hf_homeplug_av_fc,
          { "Frame Control", "homeplug_av.fc",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_fc_del_type,
          { "Delimiter type", "homeplug_av.fc.del_type",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_fc_del_type_vals), HOMEPLUG_AV_DEL_TYPE_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_fc_access,
          { "Access network", "homeplug_av.fc.access",
            FT_UINT8, BASE_HEX, VALS(homeplug_nw_info_access_vals), HOMEPLUG_AV_NW_INFO_ACCESS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_fc_snid,
          { "Short network ID", "homeplug_av.fc.snid",
            FT_UINT8, BASE_HEX, NULL, HOMEPLUG_AV_SNID_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_fc_fccs_av,
          { "Frame control check sequence", "homeplug_av.fc.fccs_av",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        /* Common MPDU variant fields */
        { &hf_homeplug_av_dtei,
          { "Destination Terminal Equipment Identifier", "homeplug_av.dtei",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_stei,
          { "Source Terminal Equipment Identifier", "homeplug_av.stei",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_lid,
          { "Link ID", "homeplug_av.lid",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cfs,
          { "Contention free session", "homeplug_av.cfs",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_CFS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bdf,
          { "Beacon detect flag", "homeplug_av.bdf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_BDF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_hp10df,
          { "Homeplug AV version 1.0", "homeplug_av.hp10df",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_HP10DF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_hp11df,
          { "Homeplug AV version 1.1", "homeplug_av.hp11df",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_HP11DF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_svn,
          { "Sack version number", "homeplug_av.svn",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_SVN_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rrtf,
          { "Request reverse transmission flag", "homeplug_av.rrtf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_RRTF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_fl_av,
          { "Frame length", "homeplug_av.fl_av",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_FL_AV_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_ppb,
          { "Pending PHY blocks", "homeplug_av.ppb",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_mfs_rsp_data,
          { "Data MAC Frame Stream Response", "homeplug_av.sack.mfs_rsp_data",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_RSP_DATA_MASK << 4, NULL, HFILL }
        },
        { &hf_homeplug_av_mfs_rsp_mgmt,
          { "Management MAC Frame Stream Response", "homeplug_av.sack.mfs_rsp_mgmt",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_RSP_MGMT_MASK << 4, NULL, HFILL }
        },
        /* Frame Control */
        { &hf_homeplug_av_sof,
          { "Start of Frame Variant Fields", "homeplug_av.sof",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_peks,
          { "Payload Encryption Key Select", "homeplug_av.sof.peks",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &homeplug_av_peks_vals_ext, HOMEPLUG_AV_SOF_PEKS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_ble,
          { "Bit loading estimate", "homeplug_av.sof.ble",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_pbsz,
          { "PHY block size", "homeplug_av.sof.pbsz",
            FT_BOOLEAN, 8, TFS(&homeplug_av_phy_block_size_vals), HOMEPLUG_AV_PBSZ_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_num_sym,
          { "Number of symbols", "homeplug_av.sof.num_sym",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_NUM_SYM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_tmi_av,
          { "Tonemap index", "homeplug_av.sof.tmi_av",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_TMI_AV_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mpdu_cnt,
          { "MPDU count", "homeplug_av.sof.mpdu_cnt",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_SOF_MPDU_CNT_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_burst_cnt,
          { "Burst count", "homeplug_av.sof.burst_cnt",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_BURST_CNT_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_bbf,
          { "Bidirectional Burst", "homeplug_av.sof.bbf",
            FT_BOOLEAN, 8, TFS(&homeplug_av_bbf_vals), HOMEPLUG_AV_BBF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mrtfl,
          { "Max Reverse Transmission Frame Length", "homeplug_av.sof.mrtfl",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_MRTLF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_dccpcf,
          { "Different CP PHY clock", "homeplug_av.sof.dccpcf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_DCCPCF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mcf,
          { "Multicast", "homeplug_av.sof.mcf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_MCF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mnbf,
          { "Multinetwork broadcast", "homeplug_av.sof.mnbf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_MNBF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_rsr,
          { "Request SACK retransmission", "homeplug_av.sof.rsr",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_RSR_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_clst,
          { "Convergence layer SAP type", "homeplug_av.sof.clst",
            FT_BOOLEAN, 8, TFS(&homeplug_av_clst_vals), HOMEPLUG_AV_CLST_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mfs_cmd_mgmt,
          { "Management MAC Frame Stream Command", "homeplug_av.sof.mfs_cmd_mgmt",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_MFS_MGMT_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mfs_cmd_data,
          { "Data MAC Frame Stream Command", "homeplug_av.sof.mfs_data_mgmt",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_MFS_DATA_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mfs_rsp_mgmt,
          { "Management MAC Frame Stream Response", "homeplug_av.sof.mfs_rsp_mgmt",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_SOF_RSP_MGMT_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_mfs_rsp_data,
          { "Data MAC Frame Stream Response", "homeplug_av.sof.mfs_rsp_data",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_SOF_RSP_DATA_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sof_bm_sack,
          { "Bit Map SACK", "homeplug_av.sof.bm_sack",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_BM_SACK_MASK, NULL, HFILL }
        },
        /* Selective Acknowledgement */
        { &hf_homeplug_av_sack,
          { "Selective Acknowledgment Variant Fields", "homeplug_av.sack",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}
        },
        /* Request to Send/Clear to Send */
        { &hf_homeplug_av_rtscts,
          { "Request to Send/Clear to Send Variant Fields", "homeplug_av.rtscts",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_rtscts_rtsf,
          { "RTS Flag", "homeplug_av.rtscts.rtsf",
            FT_BOOLEAN, 8, TFS(&homeplug_av_rtsf_vals), HOMEPLUG_AV_RTSF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rtscts_igf,
          { "Immediate Grant Flag", "homeplug_av.rtscts.igf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_IGF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rtscts_mnbf,
          { "Multinetwork Broadcast Flag", "homeplug_av.rtscts.mnbf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_RTSCTS_MNBF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rtscts_mcf,
          { "Multicast Flag", "homeplug_av.rtscts.mcf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_RTSCTS_MCF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rtscts_dur,
          { "Duration", "homeplug_av.rtscts.dur",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_DUR_MASK, NULL, HFILL }
        },
        /* Sound */
        { &hf_homeplug_av_sound,
          { "Sound Variant Fields", "homeplug_av.sound",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_pbsz,
          { "PHY Block Size", "homeplug_av.sound.pbsz",
            FT_BOOLEAN, 8, TFS(&homeplug_av_phy_block_size_vals), HOMEPLUG_AV_SOUND_PBSZ_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_bdf,
          { "Beacon Detect Flag", "homeplug_av.sound.bdf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_SOUND_BDF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_saf,
          { "Sound ACK Flag", "homeplug_av.sound.saf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_SAF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_scf,
          { "Sound Complete Flag", "homeplug_av.sound.scf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_SCF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_req_tm,
          { "Max Tone Maps Requested", "homeplug_av.sound.req_tm",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_REQ_TM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_mpdu_cnt,
          { "MPDU Count", "homeplug_av.sound.mpdu_cnt",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_SOUND_MPDU_CNT_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_src,
          { "Sound Reason Code", "homeplug_av.sound.src",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_add_req_tm,
          { "Additional Tone Maps Requested", "homeplug_av.sound.add_req_tm",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_ADD_REQ_TM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_max_pb_sym,
          { "Max PBs per Symbol", "homeplug_av.sound.max_pb_sym",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_MAX_PB_SYM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_ecsf,
          { "Extended Carriers Support Flag", "homeplug_av.sound.ecsf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_ECSF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_ecuf,
          { "Extended Carriers Used Flag", "homeplug_av.sound.hf_homeplug_av_sound_ecuf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_ECUF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_ems,
          { "Extended Modulation Support", "homeplug_av.sound.ems",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_ems_vals), HOMEPLUG_AV_EMS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_esgisf,
          { "Extended Smaller Guard Interval Support Flag", "homeplug_av.sound.esgisf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_ESGISF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_elgisf,
          { "Extended Larger Guard Interval Support Flag", "homeplug_av.sound.elgisf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_ELGISF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_sound_efrs,
          { "Extended FEC Rate Support", "homeplug_av.sound.efrs",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_efrs_vals), HOMEPLUG_AV_EFRS_MASK, NULL, HFILL }
        },
        /* Reverse Start of Frame */
        { &hf_homeplug_av_rsof,
          { "Reverse Start of Frame Variant Fields", "homeplug_av.rsof",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_rsof_fl,
          { "Reverse SOF Frame Length", "homeplug_av.rsof.fl",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_RSOF_FL_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rsof_tmi,
          { "Tone Map Index", "homeplug_av.rsof.tmi",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_RSOF_TMI_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rsof_pbsz,
          { "PHY Block Size", "homeplug_av.rsof.pbsz",
            FT_BOOLEAN, 16, TFS(&homeplug_av_phy_block_size_vals), HOMEPLUG_AV_RSOF_PBSZ_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rsof_num_sym,
          { "Number of Symbols", "homeplug_av.rsof.num_sym",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_RSOF_NUM_SYM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rsof_mfs_cmd_mgmt,
          { "Management MAC Frame Stream Command", "homeplug_av.rsof.mfs_cmd_mgmt",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_MFS_MGMT_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_rsof_mfs_cmd_data,
          { "Data MAC Frame Stream Command", "homeplug_av.rsof.mfs_cmd_data",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_MFS_DATA_MASK, NULL, HFILL }
        },
        /* Beacon body */
        { &hf_homeplug_av_bcn,
          { "Beacon Variant Fields", "homeplug_av.bcn",
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
        { &hf_homeplug_av_bcn_payload,
          { "Beacon MPDU payload", "homeplug_av.bcn.payload",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_nid,
          { "Network ID", "homeplug_av.bcn.nid",
            FT_UINT56, BASE_HEX, NULL, HOMEPLUG_AV_BCN_NID_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_hm,
          { "Hybrid Mode", "homeplug_av.bcn.hm",
            FT_UINT56, BASE_HEX | BASE_VAL64_STRING, VALS64(homeplug_av_bcn_hm_vals), HOMEPLUG_AV_HM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_stei,
          { "Source Terminal Equipment ID", "homeplug_av.bcn.stei",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_type,
          { "Beacon type", "homeplug_av.bcn.type",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_bcn_type_vals), HOMEPLUG_AV_BCN_TYPE_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_ncnr,
          { "Non-coordinating networks reported", "homeplug_av.bcn.ncnr",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_NCNR_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_npsm,
          { "Network Power Save Mode", "homeplug_av.bcn.npsm",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_NPSM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_num_slots,
          { "Number of Beacon Slots", "homeplug_av.bcn.num_slots",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_bcn_slot_vals), HOMEPLUG_AV_NUM_SLOTS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_slot_use,
          { "Beacon Slot Usage (bitmapped)", "homeplug_av.bcn.slot_usage",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_slot_id,
          { "Beacon Slot ID", "homeplug_av.bcn.slot_id",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_bcn_slot_vals), HOMEPLUG_AV_SLOT_ID_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_aclss,
          { "AC Line Synchronization Status", "homeplug_av.bcn.aclss",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_ACLSS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_hoip,
          { "Hand-Off in progress", "homeplug_av.bcn.hoip",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_HOIP_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_rtsbf,
          { "RTS Broadcast Flag", "homeplug_av.bcn.rtsbf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_RTSBF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_nm,
          { "Network Mode", "homeplug_av.bcn.nm",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_bcn_nm_vals), HOMEPLUG_AV_NM_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_cco_cap,
          { "CCo Capabilities", "homeplug_av.bcn.cco_cap",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_bcn_cco_cap_vals), HOMEPLUG_AV_CCO_CAP_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_rsf,
          { "Resuable SNID?", "homeplug_av.bcn.rsf",
            FT_BOOLEAN, 8, NULL, HOMEPLUG_AV_RSF_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_plevel,
          { "Proxy level", "homeplug_av.bcn.plevel",
            FT_UINT8, BASE_DEC, NULL, HOMEPLUG_AV_PLEVEL_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_bentries,
          { "Beacon entries and padding", "homeplug_av.bcn.bentries",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_bcn_bpcs,
          { "Beacon payload check sequence", "homeplug_av.bcn.bpcs",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
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
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &homeplug_av_sig_level_vals_ext, 0x00, "Reserved", HFILL }
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
        { &hf_homeplug_av_nw_info_peks,
          { "Payload Encryption Key Select", "homeplug_av.nw_info.peks",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &homeplug_av_peks_vals_ext, HOMEPLUG_AV_PEKS_MASK, NULL, HFILL }
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
            FT_UINT24, BASE_HEX, VALS(homeplug_av_vendors_oui_vals), 0x00, NULL, HFILL }
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
            FT_UINT8, BASE_HEX, VALS(homeplug_av_dev_id_vals), HOMEPLUG_AV_DEV_ID_MASK, NULL, HFILL }
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
          { "Image Load Starting Address", "homeplug_av.st_mac_req.img_load",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_mac_req_img_len,
          { "Image Length", "homeplug_av.st_mac_req.img_len",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_mac_req_img_chksum,
          { "Image Checksum", "homeplug_av.st_mac_req.img_chksum",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_mac_req_img_start,
          { "Image Starting Address", "homeplug_av.st_mac_req.img_start",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
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
            FT_UINT8, BASE_HEX, VALS(homeplug_av_rs_dev_status_vals), 0x00, "Unknown", HFILL }
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
          { "Sum of Turbo Bit Error over successfully received PBs", "homeplug_av.lnk_stats.rx.tb_pass",
            FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_lnk_stats_rx_tb_fail,
          { "Sum of Turbo Bit Error over unsuccessfully received PBs", "homeplug_av.lnk_stats.rx.tb_fail",
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
          { "Terminal Equipement Identifier", "homeplug_av.nw_info.tei",
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
        { &hf_homeplug_av10_nw_info_sta_phy_dr_tx,
          { "Average PHY Tx data Rate (Mbits/sec)", "homeplug_av.nw_info_cnf.sta_indo.phy_dr_tx",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av10_nw_info_sta_phy_dr_rx,
          { "Average PHY Rx data Rate (Mbits/sec)", "homeplug_av.nw_info_cnf.sta_indo.phy_dr_rx",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av11_nw_info_sta_phy_dr_tx,
          { "Average PHY Tx data Rate (Mbits/sec)", "homeplug_av.nw_info_cnf.sta_indo.phy_dr_tx",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av11_nw_info_sta_phy_dr_rx,
          { "Average PHY Rx data Rate (Mbits/sec)", "homeplug_av.nw_info_cnf.sta_indo.phy_dr_rx",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av11_nw_info_sta_cpling_tx,
          { "PHY Tx Coupling", "homeplug_av.nw_info_cnf.sta_info.phy_coupling_tx",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_coupling_vals), HOMEPLUG_AV_COUPLING_MASK, "Unknown", HFILL }
        },
        { &hf_homeplug_av11_nw_info_sta_cpling_rx,
          { "PHY Rx Coupling", "homeplug_av.nw_info_cnf.sta_info.phy_coupling_rx",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_coupling_vals), HOMEPLUG_AV_COUPLING_MASK << 4, "Unknown", HFILL }
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
        { &hf_homeplug_av_cblock_hdr_minor,
          { "Header minor version", "homeplug_av.cblock_hdr.minor",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cblock_hdr_img_type,
          { "Header image type", "homeplug_av.cblock_hdr.img_type",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_nvm_img_type_vals), HOMEPLUG_AV_NVM_IMG_TYPE_MASK, "Unknown", HFILL }
        },
        { &hf_homeplug_av_cblock_hdr_ignore_mask,
          { "Header ignore mask", "homeplug_av.cblock_hdr.ignore_mask",
            FT_UINT16, BASE_HEX, VALS(homeplug_av_nvm_ignore_mask_vals), HOMEPLUG_AV_NVM_IGNORE_MASK_MASK, "Unknown", HFILL }
        },
        { &hf_homeplug_av_cblock_hdr_module_id,
          { "Header module ID", "homeplug_av.cblock_hdr.module_id",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cblock_hdr_module_subid,
          { "Header module sub ID", "homeplug_av.cblock_hdr.module_subid",
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
        /* Embedded Host Action Required Response */
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
        { &hf_homeplug_av_op_attr_data_sw_sdram_type,
          { "SDRAM type", "homeplug_av.op_attr_cnf.data.sw_sdram_type",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_op_attr_data_sw_linefreq,
          { "Line frequency (Hz)", "homeplug_av.op_attr_cnf.data.sw_linefreq",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_linefreq_vals), HOMEPLUG_AV_LINEFREQ_MASK, "Unknown", HFILL }
        },
        { &hf_homeplug_av_op_attr_data_sw_zerocross,
          { "Zero-crossing", "homeplug_av.op_attr_cnf.data.sw_zerocross",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_zerocrossing_vals), HOMEPLUG_AV_ZEROCROSS_MASK << 2, "Unknown", HFILL }
        },
        { &hf_homeplug_av_op_attr_data_sw_sdram_size,
          { "SDRAM size (Mbytes)", "homeplug_av.op_attr_cnf.data.sw_sdram_size",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_op_attr_data_sw_auth_mode,
          { "Authorization mode", "homeplug_av.op_attr_cnf.data.sw_auth_mode",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
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
        /* Tone Map Tx Characteristics Request */
        { &hf_homeplug_av_tone_map_tx_req,
          { "Tone Map Tx Characteristics Request", "homeplug_av.tone_map_tx_req",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_req_mac,
          { "Peer address", "homeplug_av.tone_map_tx_req.mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_req_slot,
          { "Tone Map slot", "homeplug_av.tone_map_tx_req.slot",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_req_coupling,
          { "Coupling", "homeplug_av.tone_map_tx_req.coupling",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_coupling_vals), HOMEPLUG_AV_COUPLING_MASK, "Unknown", HFILL }
        },
        /* Tone Map Rx Characteristics Request */
        { &hf_homeplug_av_tone_map_rx_req,
          { "Tone Map Rx Characteristics Request", "homeplug_av.tone_map_rx_req",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_req_mac,
          { "Peer address", "homeplug_av.tone_map_rx_req.mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_req_slot,
          { "Tone Map slot", "homeplug_av.tone_map_rx_req.slot",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_req_coupling,
          { "Coupling", "homeplug_av.tone_map_rx_req.coupling",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_coupling_vals), HOMEPLUG_AV_COUPLING_MASK, "Unknown", HFILL }
        },
        /* Tone Map Tx Characteristics  Confirmation */
        { &hf_homeplug_av_tone_map_tx_cnf,
          { "Tone Map Tx Characteristics Confirmation", "homeplug_av.tone_map_tx_cnf",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_cnf_status,
          { "Status", "homeplug_av.tone_map_tx_cnf.status",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_tone_map_status_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_cnf_len,
          { "Length", "homeplug_av.tone_map_tx_cnf.len",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_cnf_mac,
          { "Peer address", "homeplug_av.tone_map_tx_cnf.mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_cnf_slot,
          { "Slot", "homeplug_av.tone_map_tx_cnf.slot",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_cnf_num_tms,
          { "Number of Tone Maps in use", "homeplug_av.tone_map_tx_cnf.num_tms",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_tx_cnf_num_act,
          { "Tone map number of active carriers", "homeplug_av.tone_map_tx_cnf.num_act",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        /* Tone Map Rx Characteristics Confirmation */
        { &hf_homeplug_av_tone_map_rx_cnf,
          { "Tone Map Rx Characteristics Confirmation", "homeplug_av.tone_map_rx_cnf",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_status,
          { "Status", "homeplug_av.tone_map_rx_cnf.status",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_tone_map_status_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_len,
          { "Length", "homeplug_av.tone_map_rx_cnf.len",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_subver,
          { "MME Subversion", "homeplug_av.tone_map_rx_cnf.mmesubversion",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_mac,
          { "Peer address", "homeplug_av.tone_map_rx_cnf.mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_slot,
          { "Slot", "homeplug_av.tone_map_rx_cnf.slot",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_coupling,
          { "Coupling", "homeplug_av.tone_map_rx_cnf.coupling",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_coupling_vals), HOMEPLUG_AV_COUPLING_MASK, "Unknown", HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_num_tms,
          { "Number of Tone Maps in use", "homeplug_av.tone_map_rx_cnf.num_tms",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_num_act,
          { "Tone map number of active carriers", "homeplug_av.tone_map_rx_cnf.num_act",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_agc,
          { "Automatic Gain Control (AGC)", "homeplug_av.tone_map_rx_cnf.agc",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_tone_map_rx_cnf_gil,
          { "Guard Interval Length (GIL)", "homeplug_av.tone_map_rx_cnf.gil",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        /* Tone Map Carrier informations */
        { &hf_homeplug_av_tone_map_carriers,
          { "Tone Map carriers", "homeplug_av.tone_map_cnf.carriers",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
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
            FT_UINT8, BASE_HEX, VALS(homeplug_av_tone_map_vals), HOMEPLUG_AV_TONE_MAP_MASK << 4, NULL, HFILL }
        },
        /* CC_ASSOC.* */
        { &hf_homeplug_av_cc_assoc_reqtype,
          { "Request Type", "homeplug_av.cc_assoc.reqtype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_cc_assoc_reqtype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_nid,
          { "Network ID", "homeplug_av.cc_assoc.nid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_cco_cap,
          { "CCo Capability", "homeplug_av.cc_assoc.cco_cap",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_avln_status_vals), HOMEPLUG_AV_AVLN_STATUS_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_proxy_net_cap,
          { "Proxy Network Capability", "homeplug_av.cc_assoc.proxy_cap",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_cc_assoc_proxy_net_cap_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_result,
          { "Result", "homeplug_av.cc_assoc.result",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_cc_assoc_result_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_snid,
          { "Short Network ID", "homeplug_av.cc_assoc.snid",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_tei,
          { "TEI", "homeplug_av.cc_assoc.tei",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_assoc_lease_time ,
          { "Lease time (min)", "homeplug_av.cc_assoc.lease_time",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        /* CM_UNASSOCIATED_STA_IND */
        { &hf_homeplug_av_cm_unassoc_sta_nid,
          { "Network ID", "homeplug_av.cm_unassoc_sta.nid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cm_unassoc_sta_cco_cap,
          { "CCo Capability", "homeplug_av.cm_unassoc_sta.cco_cap",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_avln_status_vals), HOMEPLUG_AV_AVLN_STATUS_MASK, NULL, HFILL }
        },
        /* CC_SET_TEI_MAP_IND */
        { &hf_homeplug_av_cc_set_tei_map_ind_mode,
          { "Mode", "homeplug_av.cc_set_tei_map_ind.mode",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_cc_set_tei_map_ind_mode_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_set_tei_map_ind_num,
          { "Number of entries", "homeplug_av.cc_set_tei_map_ind.num",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_set_tei_map_ind_tei,
          { "TEI", "homeplug_av.cc_set_tei_map_ind.tei",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_set_tei_map_ind_mac,
          { "MAC Address", "homeplug_av.cc_set_tei_map_ind.mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_cc_set_tei_map_ind_status,
          { "Status", "homeplug_av.cc_set_tei_map_ind.status",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_cc_set_tei_map_ind_status_vals), 0x00, NULL, HFILL }
        },
        /* HPGP */
        /* CM_SLAC_PARM.* */
        { &hf_homeplug_av_gp_cm_slac_parm_apptype,
          { "Application type", "homeplug_av.gp.cm_slac_parm.apptype",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_sectype,
          { "Security in M-Sound Message", "homeplug_av.gp.cm_slac_parm.sectype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_slac_parm_sectype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_runid,
          { "Run ID", "homeplug_av.gp.cm_slac_parm.runid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_cipher_size,
          { "Cipher Suite Set Size", "homeplug_av.gp.cm_slac_parm.cipher_size",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_cipher,
          { "Cipher Suite", "homeplug_av.gp.cm_slac_parm.cipher",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_sound_target,
          { "M-Sound Target", "homeplug_av.gp.cm_slac_parm.sound_target",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_sound_count,
          { "M-Sound Count", "homeplug_av.gp.cm_slac_parm.sound_count",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_time_out,
          { "M-Sound MPDU Time Out (N*100 msec)", "homeplug_av.gp.cm_slac_parm.time_out",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_resptype,
          { "Response type", "homeplug_av.gp.cm_slac_parm.resptype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_slac_parm_resptype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_parm_forwarding_sta,
          { "Forwarded to MAC", "homeplug_av.gp.cm_slac_parm.forwarding_sta",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        /* CM_ATTEN_PROFILE_IND */
        { &hf_homeplug_av_gp_cm_atten_profile_ind_pev_mac,
          { "PEV MAC Address", "homeplug_av.gp.cm_atten_profile_ind.pev_mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_profile_ind_num_groups,
          { "Number of Groups", "homeplug_av.gp.cm_atten_profile_ind.groups_count",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_profile_ind_aag,
          { "Average Attenuation of group (dB)", "homeplug_av.gp.cm_atten_profile_ind.aag",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        /* CM_ATTEN_CHAR */
        { &hf_homeplug_av_gp_cm_atten_char_result,
          { "Result", "homeplug_av.gp.cm_atten_char.result",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_apptype,
          { "Application type", "homeplug_av.gp.cm_atten_char.apptype",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_sectype,
          { "Security", "homeplug_av.gp.cm_atten_char.sectype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_slac_parm_sectype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_source_mac,
          { "Source MAC", "homeplug_av.gp.cm_atten_char.source_mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_runid,
          { "Run ID", "homeplug_av.gp.cm_atten_char.runid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_source_id,
          { "Source ID", "homeplug_av.gp.cm_atten_char.source_id",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_resp_id,
          { "Response ID", "homeplug_av.gp.cm_atten_char.resp_id",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_numgroups,
          { "Number of Groups", "homeplug_av.gp.cm_atten_char.groups_count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_numsounds,
          { "Number of Sounds", "homeplug_av.gp.cm_atten_char.sounds_count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_aag,
          { "Average Attenuation of group (dB)", "homeplug_av.gp.cm_atten_char.aag",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_profile,
          { "Signal level attenuation profile", "homeplug_av.gp.cm_atten_char.profile",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_atten_char_cms_data,
          { "CMS Data", "homeplug_av.gp.cm_atten_char.cms_data",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        /* CM_START_ATTEN_CHAR */
        { &hf_homeplug_av_gp_cm_start_atten_char_time_out,
          { "M-Sound MPDU Time Out (N*100 msec)", "homeplug_av.gp.cm_start_atten_char.time_out",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_start_atten_char_resptype,
          { "Response type", "homeplug_av.gp.cm_start_atten_char.resptype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_slac_parm_resptype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_start_atten_char_forwarding_sta,
          { "Forwarded to MAC", "homeplug_av.gp.cm_start_atten_char.sound_forwarding_sta",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_start_atten_char_runid,
          { "Run ID", "homeplug_av.gp.cm_start_atten_char.runid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_start_atten_char_numsounds,
          { "Number of Sounds", "homeplug_av.gp.cm_start_atten_char.sounds_count",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        /* CM_MNBC_SOUND */
        { &hf_homeplug_av_gp_cm_mnbc_sound_apptype,
          { "Application type", "homeplug_av.gp.cm_mnbc_sound.apptype",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_mnbc_sound_sectype,
          { "Security", "homeplug_av.gp.cm_mnbc_sound.sectype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_slac_parm_sectype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_mnbc_sound_sender_id,
          { "Sender ID", "homeplug_av.gp.cm_mnbc_sound.sender_id",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_mnbc_sound_countdown,
          { "Remaining Number of Sounds", "homeplug_av.gp.cm_mnbc_sound.countdown",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_mnbc_sound_runid,
          { "Run ID", "homeplug_av.gp.cm_mnbc_sound.runid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_mnbc_sound_rsvd,
          { "Reserved", "homeplug_av.gp.cm_mnbc_sound.reserved",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_mnbc_sound_rnd,
          { "Random number", "homeplug_av.gp.cm_mnbc_sound.rnd",
            FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }
        },
        /* CM_VALIDATE */
        { &hf_homeplug_av_gp_cm_validate_signaltype,
          { "Signal type", "homeplug_av.gp.cm_validate.signaltype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_validate_signaltype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_validate_timer,
          { "Timer (N*100 ms)", "homeplug_av.gp.cm_validate.timer",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_validate_result,
          { "Result", "homeplug_av.gp.cm_validate.result",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_validate_result_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_validate_togglenum,
          { "Number of detected toggles", "homeplug_av.gp.cm_validate.togglenum",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        /* CM_SLAC_MATCH */
        { &hf_homeplug_av_gp_cm_slac_match_apptype,
          { "Application type", "homeplug_av.gp.cm_slac_match.apptype",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_sectype,
          { "Security", "homeplug_av.gp.cm_slac_match.sectype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_gp_cm_slac_parm_sectype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_length,
          { "Length", "homeplug_av.gp.cm_slac_match.length",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_pev_id,
          { "PEV ID", "homeplug_av.gp.cm_slac_match.pev_id",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_pev_mac,
          { "PEV MAC", "homeplug_av.gp.cm_slac_match.pev_mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_evse_id,
          { "EVSE ID", "homeplug_av.gp.cm_slac_match.evse_id",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_evse_mac,
          { "EVSE MAC", "homeplug_av.gp.cm_slac_match.evse_mac",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_runid,
          { "Run ID", "homeplug_av.gp.cm_slac_match.runid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_rsvd,
          { "Reserved", "homeplug_av.gp.cm_slac_match.rsvd",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_nid,
          { "Network ID", "homeplug_av.gp.cm_slac_match.nid",
            FT_BYTES, SEP_COLON, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_match_nmk,
          { "Network Membership Key (NMK)", "homeplug_av.gp.cm_slac_match.nmk",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        /* CM_SLAC_USER_DATA */
        { &hf_homeplug_av_gp_cm_slac_user_data_broadcast_tlv_type,
          { "Broadcast TLV", "homeplug_av.gp.cm_slac_user_data.broadcast",
            FT_UINT24, BASE_HEX, VALS(homeplug_av_gp_cm_slac_user_data_broadcast_vals), HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_BROADCAST_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv,
          { "TLV", "homeplug_av.gp.cm_slac_user_data.tlv",
            FT_UINT16, BASE_HEX, NULL, HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv_type,
          { "Type", "homeplug_av.gp.cm_slac_user_data.tlv.type",
            FT_UINT16, BASE_HEX, VALS(homeplug_av_gp_cm_slac_user_data_tlv_types_vals), HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_TYPE_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv_length,
          { "Length", "homeplug_av.gp.cm_slac_user_data.tlv.length",
            FT_UINT16, BASE_HEX, NULL, HOMEPLUG_AV_GP_CM_SLAC_USER_DATA_TLV_LENGTH_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv_str_bytes,
          { "Data", "homeplug_av.gp.cm_slac_user_data.tlv.str",
            FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv_oui,
          { "OUI", "homeplug_av.gp.cm_slac_user_data.tlv.oui",
            FT_UINT24, BASE_HEX, VALS(homeplug_av_vendors_oui_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv_subtype,
          { "Subtype", "homeplug_av.gp.cm_slac_user_data.tlv.subtype",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_gp_cm_slac_user_data_tlv_info_str,
          { "Data", "homeplug_av.gp.cm_slac_user_data.tlv.info_str",
            FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }
        },
        /* ST/IoTecha specific fields */
        { &hf_homeplug_av_st_iotecha_header_rsvd,
          { "Reserved", "homeplug_av.st_iotecha.rsvd",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_header_mmever,
          { "MME version", "homeplug_av.st_iotecha.mmever",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_header_mver,
          { "Message version", "homeplug_av.st_iotecha.mver",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_auth_nmk,
          { "NMK", "homeplug_av.st_iotecha.auth.nmk",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_status_byte,
          { "Status", "homeplug_av.st_iotecha.auth.status",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_generic_status_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_linkstatus_status,
          { "Link status", "homeplug_av.st_iotecha.linkstatus.status",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_linkstatus_status_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_linkstatus_devmode,
          { "DevMode", "homeplug_av.st_iotecha.linkstatus.devmode",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_linkstatus_devmode_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_discover_tlv,
          { "ST/IoTecha TLV", "homeplug_av.st_iotecha.stp_discover.tlv",
            FT_UINT16, BASE_HEX, VALS(homeplug_av_st_iotecha_stp_discover_tlv_type_vals), HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_discover_tlv_type,
          { "Type", "homeplug_av.st_iotecha.stp_discover.tlv.type",
            FT_UINT16, BASE_HEX, VALS(homeplug_av_st_iotecha_stp_discover_tlv_type_vals), HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_TYPE_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_discover_tlv_length,
          { "Length", "homeplug_av.st_iotecha.stp_discover.tlv.length",
            FT_UINT16, BASE_DEC, NULL, HOMEPLUG_AV_ST_IOTECHA_STP_DISCOVER_TLV_LENGTH_MASK, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_discover_tlv_value_bytes,
          { "Value", "homeplug_av.st_iotecha.stp_discover.tlv.value",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_discover_tlv_value_string,
          { "Value", "homeplug_av.st_iotecha.stp_discover.tlv.value_string",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_gain_ask,
          { "Requested Max Gain", "homeplug_av.st_iotecha.gainmax.ask",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_gain_new,
          { "New (Current) Max Gain", "homeplug_av.st_iotecha.gainmax.new",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_gain_prev,
          { "Previous Max Gain", "homeplug_av.st_iotecha.gainmax.prev",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_tei_count,
          { "Count of TEI", "homeplug_av.st_iotecha.tei.count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_tei,
          { "TEI", "homeplug_av.st_iotecha.tei",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_tei_snap_addr_count,
          { "Number of remote address entities", "homeplug_av.st_iotecha.tei.snapshot.count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_tei_snap_tei,
          { "Associated TEI", "homeplug_av.st_iotecha.tei.snapshot.tei",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mac_address,
          { "MAC Address", "homeplug_av.st_iotecha.macaddress",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_tei_snap_mac_address_flag,
          { "Flags", "homeplug_av.st_iotecha.tei.snapshot.flags",
            FT_UINT16, BASE_HEX, VALS(homeplug_av_st_iotecha_mac_address_flag_vals), 0x0F, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_bss_list_count,
          { "BSS Entries Count", "homeplug_av.st_iotecha.bss.count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_bss_entry,
          { "BSS Entry", "homeplug_av.st_iotecha.bss.entry",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_bss_type,
          { "Type", "homeplug_av.st_iotecha.bss.entry.type",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_stp_get_bss_tlv_type_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_bss_value_bytes,
          { "Value", "homeplug_av.st_iotecha.bss.entry.value",
            FT_BYTES, SEP_COLON | BASE_ALLOW_ZERO, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_req_type,
          { "Request Type", "homeplug_av.st_iotecha.chanqual.reqtype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_reqtype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_substatus,
          { "Subscription Status", "homeplug_av.st_iotecha.chanqual.substatus",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_substatus_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_mac_local,
          { "MAC of local node", "homeplug_av.st_iotecha.chanqual.mac.local",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_mac_remote,
          { "MAC of remote node", "homeplug_av.st_iotecha.chanqual.mac.remote",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_source,
          { "Source of this report", "homeplug_av.st_iotecha.chanqual.source",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_tei_source_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_response_type,
          { "Response Type", "homeplug_av.st_iotecha.chanqual.responsetype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_responsetype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_tmi_count,
          { "Size of TMI List", "homeplug_av.st_iotecha.chanqual.tmi.count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_tmi,
          { "TMI List", "homeplug_av.st_iotecha.chanqual.chanqual.tmi",
            FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_int,
          { "Intervals List", "homeplug_av.st_iotecha.int",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_int_count,
          { "Size of Interval List", "homeplug_av.st_iotecha.chanqual.int.count",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_int_et,
          { "End Time of interval", "homeplug_av.st_iotecha.chanqual.int.et",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_int_tmi,
          { "Interval", "homeplug_av.st_iotecha.chanqual.int.tmi",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_tmi_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_tmi_attached,
          { "TMI of the attached Tone Map", "homeplug_av.st_iotecha.chanqual.tmi_atteched",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_fec_type,
          { "FEC Type/Code Rate", "homeplug_av.st_iotecha.chanqual.fec",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_cbld,
          { "Carrier Bid Loading Data Nibbles", "homeplug_av.st_iotecha.chanqual.cbld",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_cbld_data_low,
          { "CBLD Low", "homeplug_av.st_iotecha.chanqual.cbld.data.low",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_cbld_data_vals), HOMEPLUG_AV_ST_IOTECHA_CHANQUAL_CBLD_DATA_MASK_LOW, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chanqual_cbld_data_high,
          { "CBLD High", "homeplug_av.st_iotecha.chanqual.cbld.data.high",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_chanqual_cbld_data_vals), HOMEPLUG_AV_ST_IOTECHA_CHANQUAL_CBLD_DATA_MASK_HIGH, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_crc,
          { "CRC plus last CRC", "homeplug_av.st_iotecha.mfct.crc",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_total_length,
          { "Total length", "homeplug_av.st_iotecha.mfct.total_length",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_offset,
          { "Offset", "homeplug_av.st_iotecha.mfct.offset",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_length,
          { "Length", "homeplug_av.st_iotecha.mfct.length",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_data,
          { "Update Data", "homeplug_av.st_iotecha.mfct.data",
            FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_timeout,
          { "Time duration before abort", "homeplug_av.st_iotecha.mfct.timeout",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_request_type,
          { "Request Type", "homeplug_av.st_iotecha.mfct.request_type",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_mfct_request_type_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_result,
          { "Result", "homeplug_av.st_iotecha.mfct.result",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_mfct_result_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_reboot,
          { "Reboot when complete", "homeplug_av.st_iotecha.mfct.reboot",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_name,
          { "Parameter name", "homeplug_av.st_iotecha.mfct.name",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_value,
          { "Value", "homeplug_av.st_iotecha.mfct.value",
            FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_item_offset,
          { "Offset", "homeplug_av.st_iotecha.mfct.item.offset",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_mfct_item_total_length,
          { "Total length", "homeplug_av.st_iotecha.mfct.item.total_length",
            FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_fup_mac_da,
          { "MAC DA", "homeplug_av.st_iotecha.stp_fup.mac_da",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_fup_mac_sa,
          { "MAC SA", "homeplug_av.st_iotecha.stp_fup.mac_sa",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_stp_fup_mtype,
          { "Message Type", "homeplug_av.st_iotecha.stp_fup.mtype",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_stp_fwup_mtype_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_state,
          { "CP State", "homeplug_av.st_iotecha.cpstate.state",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_stp_cpstate_state_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_pwm_duty,
          { "PWM Duty Cycle", "homeplug_av.st_iotecha.cpstate.pwm_duty",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_pwm_freq,
          { "PWM Frequency", "homeplug_av.st_iotecha.cpstate.pwm_freq",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_volatge,
          { "CP Voltage", "homeplug_av.st_iotecha.cpstate.cp_volatge",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_adc_bitmask,
          { "ADC Channels", "homeplug_av.st_iotecha.cpstate.adc_bitmask",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(adc_bitmask_base), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_adc_voltage_1,
          { "ADC Channel 1 (mV)", "homeplug_av.st_iotecha.cpstate.adc_channel_1",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_adc_voltage_2,
          { "ADC Channel 2 (mV)", "homeplug_av.st_iotecha.cpstate.adc_channel_2",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_cpstate_adc_voltage_3,
          { "ADC Channel 3 (mV)", "homeplug_av.st_iotecha.cpstate.adc_channel_3",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_user_message_info,
          { "Message", "homeplug_av.st_iotecha.user_message",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_user_message_details,
          { "Details", "homeplug_av.st_iotecha.user_message_details",
            FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_test_type,
          { "Test Type", "homeplug_av.st_iotecha.test_type",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_test_type_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_num_sound,
          { "Number of soundings", "homeplug_av.st_iotecha.num_sound",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_data_ind_addr,
          { "MAC addr", "homeplug_av.st_iotecha.data_ind_addr",
            FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_agc_lock,
          { "AgcLock", "homeplug_av.st_iotecha.agc_lock",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_st_iotecha_agc_lock_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_db_agc_val,
          { "DbAgcVal", "homeplug_av.st_iotecha.db_agc_val",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_test_status,
          { "Status", "homeplug_av.st_iotecha.test_status",
            FT_UINT8, BASE_HEX, VALS(homeplug_av_st_iotecha_test_status_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_suppress_data,
          { "Suppress data", "homeplug_av.st_iotecha.suppress_data",
            FT_UINT8, BASE_DEC, VALS(homeplug_av_st_iotecha_suppress_data_vals), 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_sound_remain,
          { "Counter of sound remain", "homeplug_av.st_iotecha.sound_remain",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_ntb_time,
          { "NTB time", "homeplug_av.st_iotecha.ntb_time",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_rsvd1,
          { "Reserved", "homeplug_av.st_iotecha.rsvd1",
            FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_rsvd2,
          { "Reserved", "homeplug_av.st_iotecha.rsvd2",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_num_segments,
          { "Number of msg segments", "homeplug_av.st_iotecha.num_segments",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_segment,
          { "Index of curr segment", "homeplug_av.st_iotecha.segment",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_num_chan,
          { "Number of channels", "homeplug_av.st_iotecha.num_chan",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_homeplug_av_st_iotecha_chan_start,
          { "Carrier map index of ChanData", "homeplug_av.st_iotecha.chan_start",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
        }
        /* End of ST/IoTecha specific fields */
    };

    static gint *ett[] = {
        &ett_homeplug_av,
        &ett_homeplug_av_mmhdr,
        &ett_homeplug_av_mmtype,
        &ett_homeplug_av_fmi,
        &ett_homeplug_av_vendor,
        &ett_homeplug_av_public,

        &ett_homeplug_av_fc,
        &ett_homeplug_av_sof,
        &ett_homeplug_av_rtscts,
        &ett_homeplug_av_sack,
        &ett_homeplug_av_sound,
        &ett_homeplug_av_rsof,
        &ett_homeplug_av_bcn,
        &ett_homeplug_av_bcn_payload,
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
        &ett_homeplug_av_st_mac_req,
        &ett_homeplug_av_st_mac_cnf,
        &ett_homeplug_av_rd_mem_cnf,
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
        &ett_homeplug_av_host_action_ind,
        &ett_homeplug_av_host_action_rsp,
        &ett_homeplug_av_op_attr_req,
        &ett_homeplug_av_op_attr_cnf,
        &ett_homeplug_av_op_attr_data,
        &ett_homeplug_av_enet_phy_req,
        &ett_homeplug_av_enet_phy_cnf,
        &ett_homeplug_av_tone_map_tx_req,
        &ett_homeplug_av_tone_map_rx_req,
        &ett_homeplug_av_tone_map_tx_cnf,
        &ett_homeplug_av_tone_map_rx_cnf,
        &ett_homeplug_av_tone_map_carriers,
        &ett_homeplug_av_tone_map_carrier,
        /* HPGP*/
        &ett_homeplug_av_gp_cm_atten_char_profile,
        &ett_homeplug_av_gp_cm_slac_user_data_tlv,
        /* ST/IoTecha subtrees */
        &ett_homeplug_av_st_iotecha_header,
        &ett_homeplug_av_st_iotecha_type_length_value,
        &ett_homeplug_av_st_iotecha_chanqual_int,
        &ett_homeplug_av_st_iotecha_chanqual_cbld,
        &ett_homeplug_av_st_iotecha_bss_entry
    };


    proto_homeplug_av = proto_register_protocol("HomePlug AV protocol", "HomePlug AV", "homeplug-av");

    proto_register_field_array(proto_homeplug_av, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_homeplug_av(void)
{
    dissector_handle_t homeplug_av_handle;

    homeplug_av_handle = create_dissector_handle(dissect_homeplug_av, proto_homeplug_av);
    dissector_add_uint("ethertype", ETHERTYPE_HOMEPLUG_AV, homeplug_av_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
