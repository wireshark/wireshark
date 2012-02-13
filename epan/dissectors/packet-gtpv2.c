/* packet-gtpv2.c
 *
 * Routines for GTPv2 dissection
 * Copyright 2009 - 2011, Anders Broman <anders.broman [at] ericcsson.com>
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
 * Ref: 3GPP TS 29.274 version 11.1.0 Release 11 ETSI TS 129 274 V8.1.1 (2009-04)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>

#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-bssgp.h"


static dissector_handle_t nas_eps_handle;
static dissector_table_t gtpv2_priv_ext_dissector_table;


/*GTPv2 Message->GTP Header(SB)*/
static int proto_gtpv2 = -1;

static int hf_gtpv2_reserved = -1;
static int hf_gtpv2_spare_half_octet = -1;
static int hf_gtpv2_spare_bits = -1;
static int hf_gtpv2_flags = -1;
static int hf_gtpv2_version = -1;
static int hf_gtpv2_p = -1;
static int hf_gtpv2_t = -1;
static int hf_gtpv2_message_type = -1;
static int hf_gtpv2_msg_length = -1;
static int hf_gtpv2_teid = -1;
static int hf_gtpv2_seq = -1;
static int hf_gtpv2_spare = -1;


static int hf_gtpv2_ie = -1;
static int hf_gtpv2_ie_len = -1;
static int hf_gtpv2_cr = -1;
static int hf_gtpv2_instance = -1;
static int hf_gtpv2_cause = -1;
static int hf_gtpv2_cause_cs = -1;
static int hf_gtpv2_cause_bce = -1;
static int hf_gtpv2_cause_pce = -1;
static int hf_gtpv2_cause_off_ie_t = -1;
static int hf_gtpv2_rec = -1;
/*Start SRVCC Messages*/
static int hf_gtpv2_stn_sr = -1;
static int hf_gtpv2_len_trans_con = -1;
static int hf_gtpv2_eksi = -1;
static int hf_gtpv2_ck = -1;
static int hf_gtpv2_ik = -1;
static int hf_gtpv2_len_ms_classmark2 = -1;
static int hf_gtpv2_len_ms_classmark3 = -1;
static int hf_gtpv2_len_supp_codec_list = -1;
static int hf_gtpv2_ksi = -1;
/*static int hf_gtpv2_kc = -1; */
static int hf_gtpv2_cksn = -1;
static int hf_gtpv2_srvcc_cause = -1;
static int hf_gtpv2_rnc_id = -1;
static int hf_gtpv2_lac = -1;
static int hf_gtpv2_sac = -1;
static int hf_gtpv2_tgt_g_cell_id = -1;
static int hf_gtpv2_teid_c = -1;
static int hf_gtpv2_sv_sti = -1;
static int hf_gtpv2_sv_ics = -1;
static int hf_gtpv2_sv_emind = -1;
/*End SRVCC Messages*/
static int hf_gtpv2_apn = -1;
static int hf_gtpv2_ebi = -1;
static int hf_gtpv2_daf = -1;
static int hf_gtpv2_dtf = -1;
static int hf_gtpv2_hi = -1;
static int hf_gtpv2_dfi = -1;
static int hf_gtpv2_oi = -1;
static int hf_gtpv2_isrsi = -1;
static int hf_gtpv2_israi = -1;
static int hf_gtpv2_sgwci = -1;
static int hf_gtpv2_sqci = -1;
static int hf_gtpv2_uimsi = -1;
static int hf_gtpv2_cfsi = -1;
static int hf_gtpv2_crsi = -1;
static int hf_gtpv2_pt = -1;
static int hf_gtpv2_ps = -1;
static int hf_gtpv2_si = -1;
static int hf_gtpv2_msv = -1;
static int hf_gtpv2_ccrsi = -1;
static int hf_gtpv2_pdn_type = -1;
static int hf_gtpv2_pdn_ipv4 = -1;
static int hf_gtpv2_pdn_ipv6_len = -1;
static int hf_gtpv2_pdn_ipv6 = -1;
static int hf_gtpv2_pdn_numbers_nsapi = -1;
static int hf_gtpv2_p_tmsi = -1;
static int hf_gtpv2_p_tmsi_sig = -1;


static int hf_gtpv2_rat_type = -1;
static int hf_gtpv2_uli_ecgi_flg = -1;
static int hf_gtpv2_uli_lai_flg = -1;
static int hf_gtpv2_uli_tai_flg = -1;
static int hf_gtpv2_uli_rai_flg = -1;
static int hf_gtpv2_uli_sai_flg = -1;
static int hf_gtpv2_uli_cgi_flg = -1;
static int hf_gtpv2_glt = -1;
static int hf_gtpv2_cng_rep_act = -1;

static int hf_gtpv2_selec_mode = -1;
static int hf_gtpv2_source_type = -1;
static int hf_gtpv2_f_teid_v4 = -1;
static int hf_gtpv2_f_teid_v6 = -1;
static int hf_gtpv2_f_teid_interface_type= -1;
static int hf_gtpv2_f_teid_gre_key= -1;
static int hf_gtpv2_f_teid_ipv4= -1;
static int hf_gtpv2_f_teid_ipv6= -1;
static int hf_gtpv2_tmsi = -1;
static int hf_gtpv2_hsgw_addr_f_len = -1;
static int hf_gtpv2_hsgw_addr_ipv4 = -1;
static int hf_gtpv2_hsgw_addr_ipv6 = -1;
static int hf_gtpv2_gre_key = -1;
static int hf_gtpv2_sgw_addr_ipv4 = -1;
static int hf_gtpv2_sgw_addr_ipv6 = -1;
static int hf_gtpv2_sgw_s1u_teid = -1;
static int hf_gtpv2_imsi= -1;
static int hf_gtpv2_ipv4_addr = -1;


static int hf_gtpv2_ambr_up= -1;
static int hf_gtpv2_ambr_down= -1;
static int hf_gtpv2_ip_address_ipv4= -1;
static int hf_gtpv2_ip_address_ipv6= -1;
static int hf_gtpv2_mei= -1;

/* Trace Information */
static int hf_gtpv2_tra_info = -1;
static int hf_gtpv2_tra_info_msc_momt_calls = -1;
static int hf_gtpv2_tra_info_msc_momt_sms = -1;
static int hf_gtpv2_tra_info_msc_lu_imsi_ad = -1;
static int hf_gtpv2_tra_info_msc_handovers = -1;
static int hf_gtpv2_tra_info_msc_ss = -1;
static int hf_gtpv2_tra_info_mgw_context = -1;
static int hf_gtpv2_tra_info_sgsn_pdp_context = -1;
static int hf_gtpv2_tra_info_sgsn_momt_sms = -1;
static int hf_gtpv2_tra_info_sgsn_rau_gprs_ad = -1;
static int hf_gtpv2_tra_info_sgsn_mbms = -1;
static int hf_gtpv2_tra_info_sgsn_reserved = -1;
static int hf_gtpv2_tra_info_ggsn_pdp = -1;
static int hf_gtpv2_tra_info_ggsn_mbms = -1;
static int hf_gtpv2_tra_info_bm_sc = -1;
static int hf_gtpv2_tra_info_mme_sgw_ss = -1;
static int hf_gtpv2_tra_info_mme_sgw_sr = -1;
static int hf_gtpv2_tra_info_mme_sgw_iataud = -1;
static int hf_gtpv2_tra_info_lne_msc_s = -1;
static int hf_gtpv2_tra_info_lne_mgw = -1;
static int hf_gtpv2_tra_info_lne_sgsn = -1;
static int hf_gtpv2_tra_info_lne_ggsn = -1;
static int hf_gtpv2_tra_info_lne_rnc = -1;
static int hf_gtpv2_tra_info_lne_bm_sc = -1;
static int hf_gtpv2_tra_info_lne_mme = -1;
static int hf_gtpv2_tra_info_lne_sgw = -1;
static int hf_gtpv2_tra_info_lne_pdn_gw = -1;
static int hf_gtpv2_tra_info_lne_enb = -1;
static int hf_gtpv2_tra_info_tdl = -1;
static int hf_gtpv2_tra_info_lmsc_a = -1;
static int hf_gtpv2_tra_info_lmsc_lu = -1;
static int hf_gtpv2_tra_info_lmsc_mc = -1;
static int hf_gtpv2_tra_info_lmsc_map_g = -1;
static int hf_gtpv2_tra_info_lmsc_map_b = -1;
static int hf_gtpv2_tra_info_lmsc_map_e = -1;
static int hf_gtpv2_tra_info_lmsc_map_f = -1;
static int hf_gtpv2_tra_info_lmsc_cap = -1;
static int hf_gtpv2_tra_info_lmsc_map_d = -1;
static int hf_gtpv2_tra_info_lmsc_map_c = -1;
static int hf_gtpv2_tra_info_lmgw_mc = -1;
static int hf_gtpv2_tra_info_lmgw_nb_up = -1;
static int hf_gtpv2_tra_info_lmgw_lu_up = -1;
static int hf_gtpv2_tra_info_lsgsn_gb = -1;
static int hf_gtpv2_tra_info_lsgsn_lu = -1;
static int hf_gtpv2_tra_info_lsgsn_gn = -1;
static int hf_gtpv2_tra_info_lsgsn_map_gr = -1;
static int hf_gtpv2_tra_info_lsgsn_map_gd = -1;
static int hf_gtpv2_tra_info_lsgsn_map_gf = -1;
static int hf_gtpv2_tra_info_lsgsn_gs = -1;
static int hf_gtpv2_tra_info_lsgsn_ge = -1;
static int hf_gtpv2_tra_info_lggsn_gn = -1;
static int hf_gtpv2_tra_info_lggsn_gi = -1;
static int hf_gtpv2_tra_info_lggsn_gmb = -1;
static int hf_gtpv2_tra_info_lrnc_lu = -1;
static int hf_gtpv2_tra_info_lrnc_lur = -1;
static int hf_gtpv2_tra_info_lrnc_lub = -1;
static int hf_gtpv2_tra_info_lrnc_uu = -1;
static int hf_gtpv2_tra_info_lbm_sc_gmb = -1;
static int hf_gtpv2_tra_info_lmme_s1_mme = -1;
static int hf_gtpv2_tra_info_lmme_s3 = -1;
static int hf_gtpv2_tra_info_lmme_s6a = -1;
static int hf_gtpv2_tra_info_lmme_s10 = -1;
static int hf_gtpv2_tra_info_lmme_s11 = -1;
static int hf_gtpv2_tra_info_lsgw_s4 = -1;
static int hf_gtpv2_tra_info_lsgw_s5 = -1;
static int hf_gtpv2_tra_info_lsgw_s8b = -1;
static int hf_gtpv2_tra_info_lsgw_s11 = -1;
static int hf_gtpv2_tra_info_lpdn_gw_s2a = -1;
static int hf_gtpv2_tra_info_lpdn_gw_s2b = -1;
static int hf_gtpv2_tra_info_lpdn_gw_s2c = -1;
static int hf_gtpv2_tra_info_lpdn_gw_s5 = -1;
static int hf_gtpv2_tra_info_lpdn_gw_s6c = -1;
static int hf_gtpv2_tra_info_lpdn_gw_gx = -1;
static int hf_gtpv2_tra_info_lpdn_gw_s8b = -1;
static int hf_gtpv2_tra_info_lpdn_gw_sgi = -1;
static int hf_gtpv2_tra_info_lenb_s1_mme = -1;
static int hf_gtpv2_tra_info_lenb_x2 = -1;
static int hf_gtpv2_tra_info_lenb_uu = -1;

static int hf_gtpv2_address_digits = -1;
static int hf_gtpv2_ti = -1;

static int hf_gtpv2_bearer_qos_pvi= -1;
static int hf_gtpv2_bearer_qos_pl= -1;
static int hf_gtpv2_bearer_qos_pci= -1;
static int hf_gtpv2_bearer_qos_label_qci = -1;
static int hf_gtpv2_bearer_qos_mbr_up = -1;
static int hf_gtpv2_bearer_qos_mbr_down = -1;
static int hf_gtpv2_bearer_qos_gbr_up = -1;
static int hf_gtpv2_bearer_qos_gbr_down = -1;
static int hf_gtpv2_flow_qos_label_qci = -1;
static int hf_gtpv2_flow_qos_mbr_up = -1;
static int hf_gtpv2_flow_qos_mbr_down = -1;
static int hf_gtpv2_flow_qos_gbr_up = -1;
static int hf_gtpv2_flow_qos_gbr_down = -1;

static int hf_gtpv2_delay_value = -1;
static int hf_gtpv2_charging_id = -1;
static int hf_gtpv2_charging_characteristic = -1;
static int hf_gtpv2_bearer_flag_ppc = -1;
static int hf_gtpv2_bearer_flag_vb = -1;
static int hf_gtpv2_ue_time_zone_dst = -1;
static int hf_gtpv2_fq_csid_type = -1;
static int hf_gtpv2_fq_csid_nr = -1;
static int hf_gtpv2_fq_csid_ipv4 = -1;
static int hf_gtpv2_fq_csid_ipv6 = -1;
static int hf_gtpv2_fq_csid_id = -1;
static int hf_gtpv2_complete_req_msg_type = -1;
static int hf_gtpv2_mme_grp_id = -1;
static int hf_gtpv2_mme_code = -1;
static int hf_gtpv2_m_tmsi = -1;
static int hf_gtpv2_container_type = -1;
static int hf_gtpv2_cause_type = -1;
static int hf_gtpv2_CauseRadioNetwork = -1;
static int hf_gtpv2_CauseTransport = -1;
static int hf_gtpv2_CauseNas = -1;
static int hf_gtpv2_CauseProtocol = -1;
static int hf_gtpv2_CauseMisc = -1;
static int hf_gtpv2_target_type = -1;
static int hf_gtpv2_macro_enodeb_id = -1;

static int hf_gtpv2_node_type= -1;
static int hf_gtpv2_fqdn = -1;
static int hf_gtpv2_enterprise_id = -1;
static int hf_gtpv2_apn_rest= -1;
static int hf_gtpv2_pti= -1;
static int hf_gtpv2_mm_context_sm = -1;
static int hf_gtpv2_mm_context_nhi = -1;
static int hf_gtpv2_mm_context_drxi = -1;
static int hf_gtpv2_mm_context_cksn = -1;
static int hf_gtpv2_mm_context_cksn_ksi = -1;
static int hf_gtpv2_mm_context_kasme = -1;
static int hf_gtpv2_una = -1;
static int hf_gtpv2_gena = -1;
static int hf_gtpv2_gana = -1;
static int hf_gtpv2_ina = -1;
static int hf_gtpv2_ena = -1;
static int hf_gtpv2_hnna = -1;
static int hf_gtpv2_mm_context_ksi_a= -1;
static int hf_gtpv2_mm_context_ksi = -1;
static int hf_gtpv2_mm_context_nr_tri = -1;
static int hf_gtpv2_mm_context_nr_qui = -1;
static int hf_gtpv2_mm_context_nr_qua = -1;
static int hf_gtpv2_mm_context_uamb_ri = -1;
static int hf_gtpv2_mm_context_osci = -1;
static int hf_gtpv2_mm_context_samb_ri = -1;
static int hf_gtpv2_mm_context_unipa = -1;
static int hf_gtpv2_mm_context_unc = -1;
static int hf_gtpv2_mm_context_nas_dl_cnt = -1;
static int hf_gtpv2_mm_context_nas_ul_cnt = -1;

static int hf_gtpv2_uli_cgi_lac= -1;
static int hf_gtpv2_uli_cgi_ci= -1;
static int hf_gtpv2_uli_sai_lac= -1;
static int hf_gtpv2_uli_sai_sac= -1;
static int hf_gtpv2_uli_rai_lac= -1;
static int hf_gtpv2_uli_rai_rac= -1;
static int hf_gtpv2_uli_tai_tac= -1;
static int hf_gtpv2_uli_ecgi_eci= -1;
static int hf_gtpv2_uli_lai_lac = -1;
static int hf_gtpv2_uli_ecgi_eci_spare= -1;
static int hf_gtpv2_nsapi = -1;
static int hf_gtpv2_bearer_control_mode= -1;

static int hf_gtpv2_bss_container_phx = -1;
static int hf_gtpv2_bss_con_sapi_flg = -1;
static int hf_gtpv2_bss_con_rp_flg = -1;
static int hf_gtpv2_bss_con_pfi_flg = -1;
static int hf_gtpv2_bss_con_pfi = -1;
static int hf_gtpv2_bss_con_rp = -1;
static int hf_gtpv2_bss_con_sapi = -1;
static int hf_gtpv2_bss_con_xid_len = -1;
static int hf_gtpv2_bss_con_xid = -1;
static int hf_gtpv2_home_enodeb_id = -1;
static int hf_gtpv2_tac = -1;

/* MBMS */
static int hf_gtpv2_mbms_service_area_nr = -1;
static int hf_gtpv2_mbms_service_area_id = -1;
static int hf_gtpv2_mbms_session_id = -1;
static int hf_gtpv2_mbms_flow_id = -1;
static int hf_gtpv2_cteid = -1;
static int hf_gtpv2_ip_addr_type = -1;
static int hf_gtpv2_ip_addr_len = -1;
static int hf_gtpv2_mbms_ip_mc_dist_addrv4 = -1;
static int hf_gtpv2_mbms_ip_mc_dist_addrv6 = -1;
static int hf_gtpv2_mbms_ip_mc_src_addrv4 = -1;
static int hf_gtpv2_mbms_ip_mc_src_addrv6 = -1;
static int hf_gtpv2_mbms_hc_indicator = -1;
static int hf_gtpv2_mbms_dist_indication = -1;
static int hf_gtpv2_mbms_service_id = -1;
static int hf_gtpv2_add_flags_for_srvcc_ics = -1;
static int hf_gtpv2_vsrvcc_flag = -1;

static gint ett_gtpv2 = -1;
static gint ett_gtpv2_flags = -1;
static gint ett_gtpv2_ie = -1;
static gint ett_gtpv2_uli_flags = -1;
static gint ett_gtpv2_uli_field = -1;
static gint ett_gtpv2_bearer_ctx = -1;
static gint ett_gtpv2_PDN_conn = -1;
static gint ett_gtpv2_mm_context_flag = -1;
static gint ett_gtpv2_pdn_numbers_nsapi = -1;
static gint ett_gtpv2_tra_info_trigg = -1;
static gint ett_gtpv2_tra_info_trigg_msc_server = -1;
static gint ett_gtpv2_tra_info_trigg_mgw = -1;
static gint ett_gtpv2_tra_info_trigg_sgsn = -1;
static gint ett_gtpv2_tra_info_trigg_ggsn = -1;
static gint ett_gtpv2_tra_info_trigg_bm_sc = -1;
static gint ett_gtpv2_tra_info_trigg_sgw_mme = -1;
static gint ett_gtpv2_tra_info_interfaces = -1;
static gint ett_gtpv2_tra_info_interfaces_imsc_server = -1;
static gint ett_gtpv2_tra_info_interfaces_lmgw = -1;
static gint ett_gtpv2_tra_info_interfaces_lsgsn = -1;
static gint ett_gtpv2_tra_info_interfaces_lggsn = -1;
static gint ett_gtpv2_tra_info_interfaces_lrnc = -1;
static gint ett_gtpv2_tra_info_interfaces_lbm_sc = -1;
static gint ett_gtpv2_tra_info_interfaces_lmme = -1;
static gint ett_gtpv2_tra_info_interfaces_lsgw = -1;
static gint ett_gtpv2_tra_info_interfaces_lpdn_gw = -1;
static gint ett_gtpv2_tra_info_interfaces_lpdn_lenb = -1;
static gint ett_gtpv2_tra_info_ne_types = -1;
static gint ett_gtpv2_rai = -1;
static gint ett_gtpv2_ms_mark = -1;
static gint ett_gtpv2_stn_sr = -1;
static gint ett_gtpv2_supp_codec_list = -1;
static gint ett_gtpv2_bss_con = -1;
static gint ett_gtpv2_mm_context_auth_qua = -1;
static gint ett_gtpv2_mm_context_net_cap = -1;
static gint ett_gtpv2_ms_network_capability = -1;
static gint ett_gtpv2_vd_pref = -1;
static gint ett_gtpv2_access_rest_data = -1;

/* Definition of User Location Info (AVP 22) masks */
#define GTPv2_ULI_CGI_MASK          0x01
#define GTPv2_ULI_SAI_MASK          0x02
#define GTPv2_ULI_RAI_MASK          0x04
#define GTPv2_ULI_TAI_MASK          0x08
#define GTPv2_ULI_ECGI_MASK         0x10
#define GTPv2_ULI_LAI_MASK          0x20

#define GTPV2_CREATE_SESSION_REQUEST     32
#define GTPV2_CREATE_SESSION_RESPONSE    33
#define GTPV2_CONTEXT_RESPONSE          131
#define GTPV2_FORWARD_RELOCATION_REQ    133
#define GTPV2_FORWARD_CTX_NOTIFICATION  137
#define GTPV2_RAN_INFORMATION_RELAY     152

static void dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint offset, guint8 message_type);

/*Message Types for GTPv2 (Refer Pg19 29.274) (SB)*/
static const value_string gtpv2_message_type_vals[] = {
    {0, "Reserved"},
    {1, "Echo Request"},
    {2, "Echo Response"},
    {3, "Version Not Supported Indication"},
    /* 4-24 Reserved for S101 interface TS 29.276 */
    {4, "Node Alive Request"},
    {5, "Node Alive Response"},
    {6, "Redirection Request"},
    {7, "Redirection Response"},
    /* 25-31 Reserved for Sv interface TS 29.280 */
/*Start SRVCC Messages ETSI TS 129 280 V10.1.0 (2011-06) 5.2.1*/
    {25, "SRVCC PS to CS Request"},
    {26, "SRVCC PS to CS Response"},
    {27, "SRVCC PS to CS Complete Notification"},
    {28, "SRVCC PS to CS Complete Acknowledge"},
    {29, "SRVCC PS to CS Cancel Notification"},
    {30, "SRVCC PS to CS Cancel Acknowledge"},
    {31, "For Future Sv interface use"},
/*End SRVCC Messages*/
    /* SGSN/MME to PGW (S4/S11, S5/S8) */
    {32, "Create Session Request"},
    {33, "Create Session Response"},
    {34, "Modify Bearer Request"},
    {35, "Modify Bearer Response"},
    {36, "Delete Session Request"},
    {37, "Delete Session Response"},
    /* SGSN to PGW (S4, S5/S8) */
    {38, "Change Notification Request"},
    {39, "Change Notification Response"},
    /* 40-63 For future use */
    /* Messages without explicit response */
    {64, "Modify Bearer Command"},                          /* (MME/SGSN to PGW -S11/S4, S5/S8) */
    {65, "Modify Bearer Failure Indication"},               /*(PGW to MME/SGSN -S5/S8, S11/S4) */
    {66, "Delete Bearer Command"},                          /* (MME to PGW -S11, S5/S8) */
    {67, "Delete Bearer Failure Indication"},               /* (PGW to MME -S5/S8, S11) */
    {68, "Bearer Resource Command"},                        /* (MME/SGSN to PGW -S11/S4, S5/S8) */
    {69, "Bearer Resource Failure Indication"},             /* (PGW to MME/SGSN -S5/S8, S11/S4) */
    {70, "Downlink Data Notification Failure Indication"},  /*(SGSN/MME to SGW -S4/S11) */
    {71, "Trace Session Activation"},
    {72, "Trace Session Deactivation"},
    {73, "Stop Paging Indication"},
    /* 74-94 For future use */
    /* PDN-GW to SGSN/MME (S5/S8, S4/S11) */
    {95, "Create Bearer Request"},
    {96, "Create Bearer Response"},
    {97, "Update Bearer Request"},
    {98, "Update Bearer Response"},
    {99, "Delete Bearer Request"},
    {100, "Delete Bearer Response"},
    /* PGW to MME, MME to PGW, SGW to PGW, SGW to MME (S5/S8, S11) */
    {101, "Delete PDN Connection Set Request"},
    {102, "Delete PDN Connection Set Response"},
    /* 103-127 For future use */
    /* MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN (S3/10/S16) */
    {128, "Identification Request"},
    {129, "Identification Response"},
    {130, "Context Request"},
    {131, "Context Response"},
    {132, "Context Acknowledge"},
    {133, "Forward Relocation Request"},
    {134, "Forward Relocation Response"},
    {135, "Forward Relocation Complete Notification"},
    {136, "Forward Relocation Complete Acknowledge"},
    {137, "Forward Access Context Notification"},
    {138, "Forward Access Context Acknowledge"},
    {139, "Relocation Cancel Request"},
    {140, "Relocation Cancel Response"},
    {141, "Configuration Transfer Tunnel"},
    /* 142-148 For future use */
    /* SGSN to MME, MME to SGSN (S3)*/
    {149, "Detach Notification"},
    {150, "Detach Acknowledge"},
    {151, "CS Paging Indication"},
    {152, "RAN Information Relay"},
    {153, "Alert MME Notification"},
    {154, "Alert MME Acknowledge"},
    {155, "UE Activity Notification"},
    {156, "UE Activity Acknowledge"},
    /* 157 to 159 For future use */
    /* MME to SGW (S11) */
    {160, "Create Forwarding Tunnel Request"},
    {161, "Create Forwarding Tunnel Response"},
    {162, "Suspend Notification"},
    {163, "Suspend Acknowledge"},
    {164, "Resume Notification"},
    {165, "Resume Acknowledge"},
    {166, "Create Indirect Data Forwarding Tunnel Request"},
    {167, "Create Indirect Data Forwarding Tunnel Response"},
    {168, "Delete Indirect Data Forwarding Tunnel Request"},
    {169, "Delete Indirect Data Forwarding Tunnel Response"},
    {170, "Release Access Bearers Request"},
    {171, "Release Access Bearers Response"},
    /* 172-175 For future use */
    /* SGW to SGSN/MME (S4/S11) */
    {176, "Downlink Data Notification"},
    {177, "Downlink Data Notification Acknowledgement"},
    {178, "Reserved. Allocated in earlier version of the specification."},
    {179, "PGW Restart Notification"},
    {180, "PGW Restart Notification Acknowledge"},
    /* 181-199 For future use */
    /* SGW to PGW, PGW to SGW (S5/S8) */
    {200, "Update PDN Connection Set Request"},
    {201, "Update PDN Connection Set Response"},
    /* 202 to 210 For future use */
    /* MME to SGW (S11) */
    {211, "Modify Access Bearers Request"},
    {212, "Modify Access Bearers Response"},
    /* 213 to 230 For future use */
    /* MBMS GW to MME/SGSN (Sm/Sn) */
    {231, "MBMS Session Start Request"},
    {323, "MBMS Session Start Response"},
    {233, "MBMS Session Update Request"},
    {234, "MBMS Session Update Response"},
    {235, "MBMS Session Stop Request"},
    {236, "MBMS Session Stop Response"},
    /* 237 to 239 For future use */
/* 240-255 Reserved for GTP-U TS 29.281 [13] */
    {240, "Data Record Transfer Request"},
    {241, "Data Record Transfer Response"},
    {0, NULL}
};

#define GTPV2_IE_RESERVED                 0
#define GTPV2_IE_IMSI                     1
#define GTPV2_IE_CAUSE                    2
#define GTPV2_REC_REST_CNT                3
/*Start SRVCC Messages*/
#define GTPV2_IE_STN_SR                  51
#define GTPV2_IE_SRC_TGT_TRANS_CON       52
#define GTPV2_IE_TGT_SRC_TRANS_CON       53
#define GTPV2_IE_MM_CON_EUTRAN_SRVCC     54
#define GTPV2_IE_MM_CON_UTRAN_SRVCC      55
#define GTPV2_IE_SRVCC_CAUSE             56
#define GTPV2_IE_TGT_RNC_ID              57
#define GTPV2_IE_TGT_GLOGAL_CELL_ID      58
#define GTPV2_IE_TEID_C                  59
#define GTPV2_IE_SV_FLAGS                60
#define GTPV2_IE_SAI                     61
/* 61 - 70 for future sv interface use*/
/*End SRVCC Messages*/
#define GTPV2_APN                        71
#define GTPV2_AMBR                       72
#define GTPV2_EBI                        73
#define GTPV2_IP_ADDRESS                 74
#define GTPV2_MEI                        75
#define GTPV2_IE_MSISDN                  76
#define GTPV2_INDICATION                 77
#define GTPV2_PCO                        78
#define GTPV2_PAA                        79
#define GTPV2_BEARER_QOS                 80
#define GTPV2_IE_FLOW_QOS                81
#define GTPV2_IE_RAT_TYPE                82
#define GTPV2_IE_SERV_NET                83
#define GTPV2_IE_BEARER_TFT              84
#define GTPV2_IE_TAD                     85
#define GTPV2_IE_ULI                     86
#define GTPV2_IE_F_TEID                  87
#define GTPV2_IE_TMSI                    88
#define GTPV2_IE_GLOBAL_CNID             89
#define GTPV2_IE_S103PDF                 90
#define GTPV2_IE_S1UDF                   91
#define GTPV2_IE_DEL_VAL                 92
#define GTPV2_IE_BEARER_CTX              93
#define GTPV2_IE_CHAR_ID                 94
#define GTPV2_IE_CHAR_CHAR               95
#define GTPV2_IE_TRA_INFO                96
#define GTPV2_BEARER_FLAG                97
/* define GTPV2_IE_PAGING_CAUSE          98 (void) */
#define GTPV2_IE_PDN_TYPE                99
#define GTPV2_IE_PTI                    100
#define GTPV2_IE_DRX_PARAM              101
#define GTPV2_IE_UE_NET_CAPABILITY      102
#define GTPV2_IE_MM_CONTEXT_GSM_T       103
#define GTPV2_IE_MM_CONTEXT_UTMS_CQ     104
#define GTPV2_IE_MM_CONTEXT_GSM_CQ      105
#define GTPV2_IE_MM_CONTEXT_UTMS_Q      106
#define GTPV2_IE_MM_CONTEXT_EPS_QQ      107
#define GTPV2_IE_MM_CONTEXT_UTMS_QQ     108
#define GTPV2_IE_PDN_CONNECTION         109
#define GTPV2_IE_PDN_NUMBERS            110
#define GTPV2_IE_P_TMSI                 111
#define GTPV2_IE_P_TMSI_SIG             112
#define GTPV2_IE_HOP_COUNTER            113
#define GTPV2_IE_UE_TIME_ZONE           114
#define GTPV2_IE_TRACE_REFERENCE        115
#define GTPV2_IE_COMPLETE_REQUEST_MSG   116
#define GTPV2_IE_GUTI                   117
#define GTPV2_IE_F_CONTAINER            118
#define GTPV2_IE_F_CAUSE                119
#define GTPV2_IE_SEL_PLMN_ID            120
#define GTPV2_IE_TARGET_ID              121
/* GTPV2_IE_NSAPI                       122 */
#define GTPV2_IE_PKT_FLOW_ID            123
#define GTPV2_IE_RAB_CONTEXT            124
#define GTPV2_IE_S_RNC_PDCP_CTX_INFO    125
#define GTPV2_IE_UDP_S_PORT_NR          126
#define GTPV2_IE_APN_RESTRICTION        127
#define GTPV2_IE_SEL_MODE               128
#define GTPV2_IE_SOURCE_IDENT           129
#define GTPV2_IE_BEARER_CONTROL_MODE    130
#define GTPV2_IE_CNG_REP_ACT            131
#define GTPV2_IE_FQ_CSID                132
#define GTPV2_IE_CHANNEL_NEEDED         133
#define GTPV2_IE_EMLPP_PRI              134
#define GTPV2_IE_NODE_TYPE              135
#define GTPV2_IE_FQDN                   136
#define GTPV2_IE_TI                     137
#define GTPV2_IE_MBMS_SESSION_DURATION  138
#define GTPV2_IE_MBMS_SERVICE_AREA      139
#define GTPV2_IE_MBMS_SESSION_ID        140
#define GTPV2_IE_MBMS_FLOW_ID           141
#define GTPV2_IE_MBMS_IP_MC_DIST        142
#define GTPV2_IE_MBMS_DIST_ACK          143
#define GTPV2_IE_RFSP_INDEX             144
#define GTPV2_IE_UCI                    145
#define GTPV2_IE_CSG_INFO_REP_ACTION    146
#define GTPV2_IE_CSG_ID                 147
#define GTPV2_IE_CMI                    148
#define GTPV2_IE_SERVICE_INDICATOR      149
#define GTPV2_IE_DETACH_TYPE            150
#define GTPV2_IE_LDN                    151
#define GTPV2_IE_NODE_FEATURES          152
#define GTPV2_IE_MBMS_TIME_TO_DATA_XFER 153
#define GTPV2_IE_THROTTLING             154
#define GTPV2_IE_ARP                    155
#define GTPV2_IE_EPC_TIMER              156
#define GTPV2_IE_SIG_PRIO_IND           157
#define GTPV2_IE_TMGI                   158
#define GTPV2_IE_ADD_MM_CONT_FOR_SRVCC  159
#define GTPV2_IE_ADD_FLAGS_FOR_SRVCC    160
#define GTPV2_IE_MMBR                   161
#define GTPV2_IE_MDT_CONFIG             162
#define GTPV2_IE_APCO                   163
/* 164 to 254 reserved for future use */
#define GTPV2_IE_PRIVATE_EXT            255

#define SPARE                               0X0
#define CREATE_NEW_TFT                      0X20
#define DELETE_TFT                          0X40
#define ADD_PACKET_FILTERS_TFT              0X60
#define REPLACE_PACKET_FILTERS_TFT          0X80
#define DELETE_PACKET_FILTERS_TFT           0XA0
#define NO_TFT_OPERATION                    0XC0
#define RESERVED                            0XE0


/* Table 8.1-1: Information Element types for GTPv2 */
static const value_string gtpv2_element_type_vals[] = {
    {0, "Reserved"},
    {1, "International Mobile Subscriber Identity (IMSI)"},                     /* Variable Length / 8.3 */
    {2, "Cause"},                                                               /* Variable Length / 8.4 */
    {3, "Recovery (Restart Counter)"},                                          /* Variable Length / 8.5 */
    /* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
    /* 51-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
/*Start SRVCC Messages ETSI TS 129 280 V10.1.0 (2011-06) 6.1*/
    {51, "STN-SR"},                                                             /* Variable Length / 6.2 */
    {52, "Source to Target Transparent Container"},                             /* Variable Length / 6.3 */
    {53, "Target to Source Transparent Container"},                             /* Variable Length / 6.4 */
    {54, "MM Context for E-UTRAN SRVCC"},                                       /* Variable Length / 6.5 */
    {55, "MM Context for UTRAN SRVCC"},                                         /* Variable Length / 6.6 */
    {56, "SRVCC Cause"},                                                        /* Fixed Length / 6.7 */
    {57, "Target RNC ID"},                                                      /* Variable Length / 6.8 */
    {58, "Target Global Cell ID"},                                              /* Variable Length / 6.9 */
    {59, "TEID-C"},                                                             /* Extendable / 6.10 */
    {60, "Sv Flags"},                                                           /* Extendable / 6.11 */
    {61, "Service Area Identifier"},                                            /* Extendable / 6.12 */
    /* 62-70 For future Sv interface use */
/*End SRVCC Messages*/
    {71, "Access Point Name (APN)"},                                            /* Variable Length / 8.6 */
    {72, "Aggregate Maximum Bit Rate (AMBR)"},                                  /* Fixed Length / 8.7 */
    {73, "EPS Bearer ID (EBI)"},                                                /* Extendable / 8.8 */
    {74, "IP Address"},                                                         /* Extendable / 8.9 */
    {75, "Mobile Equipment Identity (MEI)"},                                    /* Variable Length / 8.10 */
    {76, "MSISDN"},                                                             /* Variable Length / 8.11 */
    {77, "Indication"},                                                         /* Extendable / 8.12 */
    {78, "Protocol Configuration Options (PCO)"},                               /* Variable Length / 8.13 */
    {79, "PDN Address Allocation (PAA)"},                                       /* Variable Length / 8.14 */
    {80, "Bearer Level Quality of Service (Bearer QoS)"},                       /* Variable Length / 8.15 */
    {81, "Flow Quality of Service (Flow QoS)"},                                 /* Extendable / 8.16 */
    {82, "RAT Type"},                                                           /* Extendable / 8.17 */
    {83, "Serving Network"},                                                    /* Extendable / 8.18 */
    {84, "EPS Bearer Level Traffic Flow Template (Bearer TFT)"},                /* Variable Length / 8.19 */
    {85, "Traffic Aggregation Description (TAD)"},                              /* Variable Length / 8.20 */
    {86, "User Location Info (ULI)"},                                           /* Variable Length / 8.21 */
    {87, "Fully Qualified Tunnel Endpoint Identifier (F-TEID)"},                /* Extendable / 8.22 */
    {88, "TMSI"},                                                               /* Variable Length / 8.23 */
    {89, "Global CN-Id"},                                                       /* Variable Length / 8.24 */
    {90, "S103 PDN Data Forwarding Info (S103PDF)"},                            /* Variable Length / 8.25 */
    {91, "S1-U Data Forwarding Info (S1UDF)"},                                  /* Variable Length/ 8.26 */
    {92, "Delay Value"},                                                        /* Extendable / 8.27 */
    {93, "Bearer Context"},                                                     /* Extendable / 8.28 */
    {94, "Charging ID"},                                                        /* Extendable / 8.29 */
    {95, "Charging Characteristics"},                                           /* Extendable / 8.30 */
    {96, "Trace Information"},                                                  /* Extendable / 8.31 */
    {97, "Bearer Flags"},                                                       /* Extendable / 8.32 */
    {98, "Paging Cause"},                                                       /* Variable Length / 8.33 */
    {99, "PDN Type"},                                                           /* Extendable / 8.34 */
    {100, "Procedure Transaction ID"},                                          /* Extendable / 8.35 */
    {101, "DRX Parameter"},                                                     /* Variable Length/ 8.36 */
    {102, "UE Network Capability"},                                             /* Variable Length / 8.37 */
    {103, "MM Context (GSM Key and Triplets)"},                                 /* Variable Length / 8.38 */
    {104, "MM Context (UMTS Key, Used Cipher and Quintuplets)"},                /* Variable Length / 8.38 */
    {105, "MM Context (GSM Key, Used Cipher and Quintuplets)"},                 /* Variable Length / 8.38 */
    {106, "MM Context (UMTS Key and Quintuplets)"},                             /* Variable Length / 8.38 */
    {107, "MM Context (EPS Security Context, Quadruplets and Quintuplets)"},    /* Variable Length / 8.38 */
    {108, "MM Context (UMTS Key, Quadruplets and Quintuplets)"},                /* Variable Length / 8.38 */
    {109, "PDN Connection"},                                                    /* Extendable / 8.39 */
    {110, "PDU Numbers"},                                                       /* Extendable / 8.40 */
    {111, "P-TMSI"},                                                            /* Variable Length / 8.41 */
    {112, "P-TMSI Signature"},                                                  /* Variable Length / 8.42 */
    {113, "Hop Counter"},                                                       /* Extendable / 8.43 */
    {114, "UE Time Zone"},                                                      /* Variable Length / 8.44 */
    {115, "Trace Reference"},                                                   /* Fixed Length / 8.45 */
    {116, "Complete Request Message"},                                          /* Variable Length / 8.46 */
    {117, "GUTI"},                                                              /* Variable Length / 8.47 */
    {118, "F-Container"},                                                       /* Variable Length / 8.48 */
    {119, "F-Cause"},                                                           /* Variable Length / 8.49 */
    {120, "Selected PLMN ID"},                                                  /* Variable Length / 8.50 */
    {121, "Target Identification"},                                             /* Variable Length / 8.51 */
    {122, "NSAPI"},                                                             /* Extendable / 8.52 */
    {123, "Packet Flow ID"},                                                    /* Variable Length / 8.53 */
    {124, "RAB Context"},                                                       /* Fixed Length / 8.54 */
    {125, "Source RNC PDCP Context Info"},                                      /* Variable Length / 8.55 */
    {126, "UDP Source Port Number"},                                            /* Extendable / 8.56 */
    {127, "APN Restriction"},                                                   /* Extendable / 8.57 */
    {128, "Selection Mode"},                                                    /* Extendable / 8.58 */
    {129, "Source Identification"},                                             /* Variable Length / 8.50 */
    {130, "Bearer Control Mode"},                                               /* Extendable / 8.60 */
    {131, "Change Reporting Action"},                                           /* Variable Length / 8.61 */
    {132, "Fully Qualified PDN Connection Set Identifier (FQ-CSID)"},           /* Variable Length / 8.62 */
    {133, "Channel needed"},                                                    /* Extendable / 8.63 */
    {134, "eMLPP Priority"},                                                    /* Extendable / 8.64 */
    {135, "Node Type"},                                                         /* Extendable / 8.65 */
    {136, "Fully Qualified Domain Name (FQDN)"},                                /* Variable Length / 8.66 */
    {137, "Transaction Identifier (TI)"},                                       /* Variable Length / 8.68 */
    {138, "MBMS Session"},                                                      /* Duration Extendable / 8.69 */
    {139, "MBMS Service Area"},                                                 /* Extendable / 8.70 */
    {140, "MBMS Session Identifier"},                                           /* Extendable / 8.71 */
    {141, "MBMS Flow Identifier"},                                              /* Extendable / 8.72 */
    {142, "MBMS IP Multicast Distribution"},                                    /* Extendable / 8.73 */
    {143, "MBMS Distribution Acknowledge"},                                     /* Extendable / 8.74 */
    {144, "RFSP Index"},                                                        /* Fixed Length / 8.77 */
    {145, "User CSG Information (UCI)"},                                        /* Extendable / 8.75 */
    {146, "CSG Information Reporting Action"},                                  /* Extendable / 8.76 */
    {147, "CSG ID"},                                                            /* Extendable / 8.78 */
    {148, "CSG Membership Indication (CMI)"},                                   /* Extendable / 8.79 */
    {149, "Service indicator"},                                                 /* Fixed Length / 8.80 */
    {150, "Detach Type"},                                                       /* Fixed Length / 8.81 */
    {151, "Local Distiguished Name (LDN)"},                                     /* Variable Length / 8.82 */
    {152, "Node Features"},                                                     /* Extendable / 8.83 */
    {153, "MBMS Time to Data Transfer"},                                        /* Extendable / 8.84 */
    {154, "Throttling"},                                                        /* Extendable / 8.85 */
    {155, "Allocation/Retention Priority (ARP)"},                               /* Extendable / 8.86 */
    {156, "EPC Timer"},                                                         /* Extendable / 8.87 */
    {157, "Signalling Priority Indication"},                                    /* Extendable / 8.88 */
    {158, "Temporary Mobile Group Identity"},                                   /* Extendable / 8.89 */
    {159, "Additional MM context for SRVCC"},                                   /* Extendable / 8.90 */
    {160, "Additional flags for SRVCC"},                                        /* Extendable / 8.91 */
    {161, "Max MBR/APN-AMBR (MMBR)"},                                           /* Extendable / 8.92 */
    {162, "MDT Configuration"},                                                 /* Extendable / 8.93 */
    {163, "Additional Protocol Configuration Options (APCO)"},                  /* Extendable / 8.94 */
    /* 164 to 254 Spare. For future use.  */                                    /* For future use. FFS */
    {255, "Private Extension"},                                                 /* Variable Length / 8.67 */
    {0, NULL}
};

/* Code to dissect IE's */

static void
dissect_gtpv2_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);

}

/*
 * 8.3 International Mobile Subscriber Identity (IMSI)
 *
 * IMSI is defined in 3GPP TS 23.003
 * Editor's note: IMSI coding will be defined in 3GPP TS 24.301
 * Editor's note: In the first release of GTPv2 spec (TS 29.274v8.0.0) n = 8.
 * That is, the overall length of the IE is 11 octets.
 */

static void
dissect_gtpv2_imsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset= 0;
    const gchar *imsi_str;

    /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
     * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the EP
     * allocated string will be returned.
     */
    imsi_str = tvb_bcd_dig_to_ep_str( tvb, offset, length, NULL, ENC_BIG_ENDIAN);

    proto_tree_add_string(tree, hf_gtpv2_imsi, tvb, offset, length, imsi_str);
    proto_item_append_text(item, "%s", imsi_str);

}

/*
 * 8.4 Cause
 */

/* Table 8.4-1: Cause values */
static const value_string gtpv2_cause_vals[] = {
    {0, "Reserved"},
    /* Request */
    {1, "Paging Cause"},
    {2, "Local Detach"},
    {3, "Complete Detach"},
    {4, "RAT changed from 3GPP to Non-3GPP"},
    {5, "ISR is activated"},
    {6, "Error Indication received from RNC/eNodeB"},
    {7, "IMSI Detach Only"},
    {8, "Reactivation Requested"},
    {9, "PDN reconnection to this APN disallowed"},
    {10, "Access changed from Non-3GPP to 3GPP"},
    /* 11-15 Spare. This value range is reserved for Cause values in a request message */
    {11, "Spare"},
    {12, "Spare"},
    {13, "Spare"},
    {14, "Spare"},
    {15, "Spare"},
    /* Acceptance Response */
    {16, "Request accepted"},
    {17, "Request accepted partially"},
    {18, "New PDN type due to network preference"},
    {19, "New PDN type due to single address bearer only"},
    /* 20-63 Spare. This value range is reserved for Cause values in acceptance response message */
    /* Rejection Response */
    {20, "Spare"},
    {21, "Spare"},
    {22, "Spare"},
    {23, "Spare"},
    {24, "Spare"},
    {25, "Spare"},
    {26, "Spare"},
    {27, "Spare"},
    {28, "Spare"},
    {29, "Spare"},
    {30, "Spare"},
    {31, "Spare"},
    {32, "Spare"},
    {33, "Spare"},
    {34, "Spare"},
    {35, "Spare"},
    {36, "Spare"},
    {37, "Spare"},
    {38, "Spare"},
    {39, "Spare"},
    {40, "Spare"},
    {41, "Spare"},
    {42, "Spare"},
    {43, "Spare"},
    {44, "Spare"},
    {45, "Spare"},
    {46, "Spare"},
    {47, "Spare"},
    {48, "Spare"},
    {49, "Spare"},
    {50, "Spare"},
    {51, "Spare"},
    {52, "Spare"},
    {53, "Spare"},
    {54, "Spare"},
    {55, "Spare"},
    {56, "Spare"},
    {57, "Spare"},
    {58, "Spare"},
    {59, "Spare"},
    {60, "Spare"},
    {61, "Spare"},
    {62, "Spare"},
    {63, "Spare"},

    {64, "Context Not Found"},
    {65, "Invalid Message Format"},
    {66, "Version not supported by next peer"},
    {67, "Invalid length"},
    {68, "Service not supported"},
    {69, "Mandatory IE incorrect"},
    {70, "Mandatory IE missing"},
    {71, "Optional IE incorrect"},
    {72, "System failure"},
    {73, "No resources available"},
    {74, "Semantic error in the TFT operation"},
    {75, "Syntactic error in the TFT operation"},
    {76, "Semantic errors in packet filter(s)"},
    {77, "Syntactic errors in packet filter(s)"},
    {78, "Missing or unknown APN"},
    {79, "Unexpected repeated IE"},
    {80, "GRE key not found"},
    {81, "Reallocation failure"},
    {82, "Denied in RAT"},
    {83, "Preferred PDN type not supported"},
    {84, "All dynamic addresses are occupied"},
    {85, "UE context without TFT already activated"},
    {86, "Protocol type not supported"},
    {87, "UE not responding"},
    {88, "UE refuses"},
    {89, "Service denied"},
    {90, "Unable to page UE"},
    {91, "No memory available"},
    {92, "User authentication failed"},
    {93, "APN access denied - no subscription"},
    {94, "Request rejected"},
    {95, "P-TMSI Signature mismatch"},
    {96, "IMSI not known"},
    {97, "Semantic error in the TAD operation"},
    {98, "Syntactic error in the TAD operation"},
    {99, "Reserved Message Value Received"},
    {100, "PGW not responding"},
    {101, "Collision with network initiated request"},
    {102, "Unable to page UE due to Suspension"},
    {103, "Conditional IE missing"},
    {104, "APN Restriction type Incompatible with currently active PDN connection"},
    {105, "Invalid overall length of the triggered response message and a piggybacked initial message"},
    {106, "Data forwarding not supported"},
    {107, "Invalid reply from remote peer"},
    {108, "Fallback to GTPv1"},
    {109, "Invalid peer"},
    {110, "Temporarily rejected due to handover procedure in progress"},
    {111, "Modifications not limited to S1-U bearers"},
    {112, "Request rejected for a PMIPv6 reason "},
    /* 113-239 Spare. For future use in a triggered/response message  */
    /* 240-255 Spare. For future use in an initial/request message */
    {0, NULL}
};

static value_string_ext gtpv2_cause_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_cause_vals);

/* Table 8.4-1: CS (Cause Source) */
static const true_false_string gtpv2_cause_cs = {
    "Originated by remote node",
    "Originated by node sending the message",
};

static void
dissect_gtpv2_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    guint8  tmp;

    /* Cause value octet 5 */
    tmp = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_cause, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Add Cause to ie_tree */
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(tmp, &gtpv2_cause_vals_ext, "Unknown"),tmp);
    offset++;

    /* Octet 6 Spare PCE BCE CS */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset<<3, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_cause_pce, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_cause_bce, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_cause_cs, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* If n = 2, a = 0 and the Cause IE shall be 6 octets long.
     * Therefore, octets "a(n+1) to a(n+4)" will not be present.
     * If n = 6, a = 1 and the Cause IE will be 10 octets long.
     */
    if ( length == 2 ) {
        return;
    }
    /*
     * If the rejection is due to a mandatory IE or a verifiable conditional IE is faulty
     * or missing, the offending IE shall be included within an additional field "a(n+1)
     * to a(n+4)". Only Type and Instance fields of the offending IE that caused the
     * rejection have a meaning. The length in the Octet 8-9 and spare bits in the Octet 10
     * shall be set to "0". In this case, the value of "n" shall be "6".
     * Otherwise, the value of "n" is equal to "2".
     */

    /* Type of the offending IE */
    proto_tree_add_item(tree, hf_gtpv2_cause_off_ie_t, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length */
    proto_tree_add_item(tree, hf_gtpv2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    /* a(n+4) Spare Instance */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_half_octet, tvb, offset>>3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_instance, tvb, offset, 1, ENC_BIG_ENDIAN);

}

/*
 * 8.5 Recovery (Restart Counter)
 */
static void
dissect_gtpv2_recovery(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    guint8  recovery;

    recovery = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_rec, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%u", recovery);

}


/*Start SRVCC Messages*/

/* 6.2 STN-SR */
static void
dissect_gtpv2_stn_sr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *stn_sr_item;
    proto_tree *sub_tree;
    tvbuff_t   *new_tvb;
    int        offset = 0;

    stn_sr_item = proto_tree_add_item(tree, hf_gtpv2_stn_sr, tvb, offset, length, ENC_NA);
    new_tvb = tvb_new_subset(tvb, offset, length, length );
    sub_tree = proto_item_add_subtree(stn_sr_item, ett_gtpv2_stn_sr);

    /* Octet 5
     * contains the Nature of Address and Numbering Plan Indicator (NANPI) of the "AddressString" ASN.1 type (see 3GPP
     * TS 29.002 [11]). Octets 6 to (n+4) contain the actual STN-SR (digits of an address encoded as a TBCD-STRING as in
     * the "AddressString" ASN.1 type). For an odd number of STN-SR digits, bits 8 to 5 of the last octet are encoded with the
     * filler "1111".
     */
    dissect_gsm_map_msisdn(new_tvb, pinfo, sub_tree);
}

/* 6.3 Source to Target Transparent Container */

static void
dissect_gtpv2_src_tgt_trans_con(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_len_trans_con, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /*ra_type_flag = 0;*/

    /* Transparent Container
     * When target network is GERAN, this container carries the Old BSS to New BSS
     * Information IE defined in 3GPP TS 48.008 [8]. When target network is UTRAN, this container carries the Source RNC
     * to Target RNC Transparent Container IE defined in 3GPP TS 25.413 [9]. The Transparent container field includes the
     * IE value part as it is specified in the respective specification.
     */
    proto_tree_add_text(tree, tvb, offset, length-1, "Transparent Container: %s", tvb_bytes_to_str(tvb, offset, length-1));
    /*
     * bssmap_old_bss_to_new_bss_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo);
     * dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU
     */

}

/* 6.4 Target to Source Transparent Container */
static void
dissect_gtpv2_tgt_src_trans_con(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_len_trans_con, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Transparent Container */
    proto_tree_add_text(tree, tvb, offset, length-1, "Transparent Container: %s", tvb_bytes_to_str(tvb, offset, length-1));


}

/* 6.5 MM Context for E-UTRAN SRVCC */
static void
dissect_gtpv2_mm_con_eutran_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    guint8  elm_len;
    proto_tree *ms_tree, *fi;

    proto_tree_add_item(tree, hf_gtpv2_eksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_text(tree, tvb, offset , 16,"CKsrvcc: %s ",tvb_bytes_to_str(tvb, offset, 16));
    offset = offset+16;
    proto_tree_add_text(tree, tvb, offset, 16, "IKsrvcc: %s ", tvb_bytes_to_str(tvb, offset, 16));
    offset = offset+16;

  /* Length of Mobile Station Classmark2  */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fi = proto_tree_add_text(tree, tvb, offset, elm_len, "Mobile Station Classmark2  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
    de_ms_cm_2(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset+elm_len;

  /* Length of Mobile Station Classmark3  */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fi = proto_tree_add_text(tree, tvb, offset, elm_len, "Mobile Station Classmark3 %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
    de_ms_cm_3(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset+elm_len;

   /*Length of Supported Codec List  */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_supp_codec_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fi = proto_tree_add_text(tree, tvb, offset, elm_len, "Supported Codec List  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_tree = proto_item_add_subtree(fi, ett_gtpv2_supp_codec_list);
    de_sup_codec_list(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);

}

/* 6.6 MM Context for UTRAN SRVCC */
static void
dissect_gtpv2_mm_con_utran_srvcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    guint8  elm_len;
    proto_tree *ms_tree, *fi;

    proto_tree_add_item(tree, hf_gtpv2_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_text(tree, tvb, offset , 16,"CK'cs: %s",tvb_bytes_to_str(tvb, offset, 16));
    offset = offset+16;
    proto_tree_add_text(tree, tvb, offset, 16, "IK'cs: %s",tvb_bytes_to_str(tvb, offset, 16));
    offset = offset+16;
    proto_tree_add_text(tree, tvb, offset, 8, "Kc': %s",tvb_bytes_to_str(tvb, offset, 8));
    offset = offset+8;
    proto_tree_add_item(tree, hf_gtpv2_cksn, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*Length of Mobile Station Classmark2  */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fi = proto_tree_add_text(tree, tvb, offset, elm_len, "Mobile Station Classmark2  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
    de_ms_cm_2(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset+elm_len;

    /*Length of Mobile Station Classmark3  */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fi = proto_tree_add_text(tree, tvb, offset, elm_len, "Mobile Station Classmark3  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_tree = proto_item_add_subtree(fi, ett_gtpv2_ms_mark);
    de_ms_cm_3(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset+elm_len;

    /*Length of Supported Codec List  */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_supp_codec_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fi = proto_tree_add_text(tree, tvb, offset, elm_len, "Supported Codec List  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_tree = proto_item_add_subtree(fi, ett_gtpv2_supp_codec_list);
    de_sup_codec_list(tvb, ms_tree, pinfo, offset, elm_len, NULL, 0);

}

/* 6.7 SRVCC Cause */
static const value_string gtpv2_srvcc_cause_vals[] = {
    {0, "Reserved"},
    {1, "Unspecified"},
    {2, "Handover/Relocation cancelled by source system "},
    {3, "Handover /Relocation Failure with Target system"},
    {4, "Handover/Relocation Target not allowed"},
    {5, "Unknown Target ID"},
    {6, "Target Cell not available"},
    {7, "No Radio Resources Available in Target Cell"},
    {8, "Failure in Radio Interface Procedure"},
    {0, NULL}
};

static value_string_ext gtpv2_srvcc_cause_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_srvcc_cause_vals);

static void
dissect_gtpv2_srvcc_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    guint8  srvcc_cause;

    srvcc_cause = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_srvcc_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(srvcc_cause, &gtpv2_srvcc_cause_vals_ext, "Unknown"),srvcc_cause);

}

/* 6.8 Target RNC ID */
static void
dissect_gtpv2_tgt_rnc_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int           offset = 0;
    guint8        rnc_id;
    proto_tree   *subtree;
    proto_item   *rai_item;
    guint32       mcc;
    guint32       mnc;
    guint32       lac;
    guint32       curr_offset;

    /*ra_type_flag = 1;*/ /*Flag to be set to differentiate GERAN and UTRAN*/
    curr_offset = offset;

    mcc = (tvb_get_guint8(tvb, curr_offset) & 0x0f) <<8;
    mcc |= (tvb_get_guint8(tvb, curr_offset) & 0xf0);
    mcc |= (tvb_get_guint8(tvb, curr_offset+1) & 0x0f);
    mnc = (tvb_get_guint8(tvb, curr_offset+2) & 0x0f) <<8;
    mnc |= (tvb_get_guint8(tvb, curr_offset+2) & 0xf0);
    mnc |= (tvb_get_guint8(tvb, curr_offset+1) & 0xf0) >>4;
    if ((mnc&0x000f) == 0x000f)
        mnc = mnc>>4;

    lac = tvb_get_ntohs(tvb, curr_offset+3);
    rnc_id = tvb_get_guint8(tvb,  curr_offset+5);

    rai_item = proto_tree_add_text(tree,
                                   tvb, curr_offset, 6,
                                   "Routing area identification: %x-%x-%u-%u",
                                   mcc,mnc,lac,rnc_id);

    subtree = proto_item_add_subtree(rai_item, ett_gtpv2_rai);
    dissect_e212_mcc_mnc(tvb, pinfo, subtree, offset, TRUE);

    proto_tree_add_item(subtree, hf_gtpv2_lac, tvb, curr_offset+3, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gtpv2_rnc_id, tvb, curr_offset+5, 1, ENC_BIG_ENDIAN);

    /* no length check possible */


}

/* 6.9 Target Global Cell ID */
static void
dissect_gtpv2_tgt_global_cell_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    guint8  tgt_cell_id;
    proto_tree   *subtree;
    proto_item   *rai_item;
    guint32       mcc;
    guint32       mnc;
    guint32       lac;
    guint32       curr_offset;

    curr_offset = offset;

    mcc = (tvb_get_guint8(tvb, curr_offset) & 0x0f) <<8;
    mcc |= (tvb_get_guint8(tvb, curr_offset) & 0xf0);
    mcc |= (tvb_get_guint8(tvb, curr_offset+1) & 0x0f);
    mnc = (tvb_get_guint8(tvb, curr_offset+2) & 0x0f) <<8;
    mnc |= (tvb_get_guint8(tvb, curr_offset+2) & 0xf0);
    mnc |= (tvb_get_guint8(tvb, curr_offset+1) & 0xf0) >>4;
    if ((mnc&0x000f) == 0x000f)
        mnc = mnc>>4;

    lac = tvb_get_ntohs(tvb, curr_offset+3);
    tgt_cell_id = tvb_get_guint8(tvb,  curr_offset+5);

    rai_item = proto_tree_add_text(tree,
                                   tvb, curr_offset, 6,
                                   "Routing area identification: %x-%x-%u-%u",
                                   mcc,mnc,lac,tgt_cell_id);

    subtree = proto_item_add_subtree(rai_item, ett_gtpv2_rai);
    dissect_e212_mcc_mnc(tvb, pinfo, subtree, offset, TRUE);

    proto_tree_add_item(subtree, hf_gtpv2_lac, tvb, curr_offset+3, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gtpv2_tgt_g_cell_id, tvb, curr_offset+5, 1, ENC_BIG_ENDIAN);

    /* no length check possible */

}

/* 6.10 Tunnel Endpoint Identifier for Control Plane (TEID-C) */
static void
dissect_gtpv2_teid_c(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_teid_c, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset= offset+4;
    if(length>4)
        proto_tree_add_text(tree, tvb, offset, length-4, "Spare: %s",tvb_bytes_to_str(tvb, offset, length-4));
}

/* 6.11 Sv Flags */
static void
dissect_gtpv2_sv_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_sv_sti, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_sv_ics, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_sv_emind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    if(length>1)
        proto_tree_add_text(tree, tvb, offset, length-1, "Spare: %s",tvb_bytes_to_str(tvb, offset, length-1));
}

/* 6.12 Service Area Identifier */

static void
dissect_gtpv2_sai(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int     offset = 0;

    /* 5 MCC digit 2 MCC digit 1
     * 6 MNC digit 3 MCC digit 3
     * 7 MNC digit 2 MNC digit 1
     */
    dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
    offset+=3;

    /* The Location Area Code (LAC) consists of 2 octets. Bit 8 of Octet 8 is the most significant bit and bit 1 of Octet 9 the
     * least significant bit. The coding of the location area code is the responsibility of each administration. Coding using full
     * hexadecimal representation shall be used.
     */
    proto_tree_add_item(tree, hf_gtpv2_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* The Service Area Code (SAC) consists of 2 octets. Bit 8 of Octet 10 is the most significant bit and bit 1 of Octet 11 the
     * least significant bit. The SAC is defined by the operator. See 3GPP TS 23.003 [4] subclause 12.5 for more information
     */
    proto_tree_add_item(tree, hf_gtpv2_sac, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/*End SRVCC Messages*/


/*
 * 8.6 Access Point Name (APN)
 * The encoding the APN field follows 3GPP TS 23.003 [2] subclause 9.1.
 * The content of the APN field shall be the full APN with both the APN Network Identifier
 * and APN Operator Identifier being present as specified in 3GPP TS 23.003 [2]
 * subclauses 9.1.1 and 9.1.2, 3GPP TS 23.060 [35] Annex A and 3GPP TS 23.401 [3] subclauses 4.3.8.1.
 */
static void
dissect_gtpv2_apn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint8 *apn = NULL;
    int name_len, tmp;

    if (length > 0) {
        name_len = tvb_get_guint8(tvb, offset);

        if (name_len < 0x20) {
            apn = tvb_get_ephemeral_string(tvb, offset + 1, length - 1);
            for (;;) {
                if (name_len >= length - 1)
                    break;
                tmp = name_len;
                name_len = name_len + apn[tmp] + 1;
                apn[tmp] = '.';
            }
        } else{
            apn = tvb_get_ephemeral_string(tvb, offset, length);
        }
        proto_tree_add_string(tree, hf_gtpv2_apn, tvb, offset, length, apn);
    }

    if (apn)
        proto_item_append_text(item, "%s", apn);

}

/*
 * 8.7 Aggregate Maximum Bit Rate (AMBR)
 */

static void
dissect_gtpv2_ambr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_ambr_up, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset= offset + 4;
    proto_tree_add_item(tree, hf_gtpv2_ambr_down, tvb, offset, 4, ENC_BIG_ENDIAN);
}

/*
 * 8.8 EPS Bearer ID (EBI)
 */
static void
dissect_gtpv2_ebi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{

    int offset = 0;
    guint8       ebi;

    /* Spare (all bits set to 0) B8 - B5*/
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* EPS Bearer ID (EBI) B4 - B1 */
    ebi = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%u", ebi);

}
/*
 * 8.9 IP Address
 */
static void
dissect_gtpv2_ip_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    struct e_in6_addr ipv6_addr;

    if (length==4)
    {
        proto_tree_add_item(tree, hf_gtpv2_ip_address_ipv4, tvb, offset, length, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "IPv4 %s", tvb_ip_to_str(tvb, offset));
    }
    else if (length==16)
    {
        proto_tree_add_item(tree, hf_gtpv2_ip_address_ipv6, tvb, offset, length, ENC_NA);
        tvb_get_ipv6(tvb, offset, &ipv6_addr);
        proto_item_append_text(item, "IPv6 %s", ip6_to_str(&ipv6_addr));
    }
}
/*
 * 8.10 Mobile Equipment Identity (MEI)
 * The ME Identity field contains either the IMEI or the IMEISV
 * as defined in clause 6.2 of 3GPP TS 23.003 [2]. It is encoded
 * as specified in clause 7.7.53 of 3GPP TS 29.060 [4], beginning
 * with octet 4 of Figure 7.7.53.1. The IMEI(SV) digits are encoded
 * using BCD coding where IMEI is 15 BCD digits and IMEISV is 16 BCD
 * digits. For IMEI, bits 5 to 8 of the last octet shall be filled
 * with an end mark coded as '1111'.
 */

static void
dissect_gtpv2_mei(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset= 0;
    const gchar *mei_str;

    /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
     * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the EP
     * allocated string will be returned.
     */
    mei_str = tvb_bcd_dig_to_ep_str( tvb, 0, length, NULL, ENC_BIG_ENDIAN);

    proto_tree_add_string(tree, hf_gtpv2_mei, tvb, offset, length, mei_str);
    proto_item_append_text(item, "%s", mei_str);
}

/*
 * 8.11 MSISDN
 *
 * MSISDN is defined in 3GPP TS 23.003
 * Editor's note: MSISDN coding will be defined in TS 24.301.
 */
static void
dissect_gtpv2_msisdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    const char     *digit_str;

    /* Octets 5 to (n+4) represent the MSISDN value is in international number format
     * as described in ITU-T Rec E.164 [25] and 3GPP TS 29.002 [41].
     * MSISDN value contains only the actual MSISDN number (does not contain the "nature of
     * address indicator" octet, which indicates "international number"
     * as in 3GPP TS 29.002 [41]) and is encoded as TBCD digits, i.e.
     * digits from 0 through 9 are encoded "0000" to "1001".
     * When there is an odd number of digits, bits 8 to 5 of the last octet are encoded with
     * the filler "1111".
     */
    dissect_e164_cc(tvb, tree, 0, TRUE);
    /* Fetch the BCD encoded digits from tvb low half byte, formating the digits according to
     * a default digit set of 0-9 returning "?" for overdecadic digits a pointer to the EP
     * allocated string will be returned.
     */
    digit_str = tvb_bcd_dig_to_ep_str( tvb, 0, length, NULL, ENC_BIG_ENDIAN);

    proto_tree_add_string(tree, hf_gtpv2_address_digits, tvb, 0, length, digit_str);
    proto_item_append_text(item, "%s", digit_str);
}

/*
 * 8.12 Indication
 */
static void
dissect_gtpv2_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    /* Octet 5 DAF DTF HI DFI OI ISRSI ISRAI SGWCI */
    proto_tree_add_item(tree, hf_gtpv2_daf,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_dtf,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_hi,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_dfi,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_oi,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_isrsi,       tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_israi,       tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_sgwci,       tvb, offset, 1, ENC_BIG_ENDIAN);

    if(length==1) {
        proto_tree_add_text(tree, tvb, 0, length, "Older version?, should be 2 octets in 8.0.0");
        return;
    }

    offset++;

    /* Octet 6 SQCI UIMSI CFSI CRSI P PT SI MSV
     * 3GPP TS 29.274 version 9.4.0 Release 9
     */
    proto_tree_add_item(tree, hf_gtpv2_sqci,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_uimsi,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_cfsi,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_crsi,          tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gtpv2_ps,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_pt,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_si,          tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_msv,         tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if(length==2){
        return;
    }
    /* Only present in version 9 and higher */
    /* Octet 7 Spare Spare Spare Spare Spare Spare Spare CCRSI */
    proto_tree_add_item(tree, hf_gtpv2_ccrsi,         tvb, offset, 1, ENC_BIG_ENDIAN);

}

/*
 * 8.13 Protocol Configuration Options (PCO)
 * Protocol Configuration Options (PCO) is transferred via GTP tunnels. The sending entity copies the value part of the
 * PCO into the Value field of the PCO IE. The detailed coding of the PCO field from octets 5 to (n+4) shall be specified
 * as per clause 10.5.6.3 of 3GPP TS 24.008 [5], starting with octet 3.
 * Dissected in packet-gsm_a_gm.c
 */
static void
dissect_gtpv2_pco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    switch(message_type){
    case GTPV2_CREATE_SESSION_REQUEST:
        /* PCO options as MS to network direction */
        pinfo->link_dir = P2P_DIR_UL;
        break;
    case GTPV2_CREATE_SESSION_RESPONSE:
        /* PCO options as Network to MS direction: */
        pinfo->link_dir = P2P_DIR_DL;
        break;
    default:
        break;
    }
    de_sm_pco(tvb, tree, pinfo, 0, length, NULL, 0);
}

/*
 * 8.14 PDN Address Allocation (PAA)
 */

static const value_string gtpv2_pdn_type_vals[] = {
    {1, "IPv4"},
    {2, "IPv6"},
    {3, "IPv4/IPv6"},
    {0, NULL}
};

static void
dissect_gtpv2_paa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint8 pdn_type;
    pdn_type  = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_pdn_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    switch(pdn_type)
    {
    case 1:
        /* IPv4 */
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* IPv6*/
        /* If PDN type value indicates IPv6, octet 6 contains the IPv6 Prefix Length.
         * Octets 7 through 22 contain an IPv6 Prefix and Interface Identifier.
         * Bit 8 of octet 7 represents the most significant bit of the IPv6 Prefix
         * and Interface Identifier and bit 1 of octet 22 the least significant bit.
         */
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6, tvb, offset, 16, ENC_NA);
        break;
    case 3:
        /* IPv4/IPv6 */
        /* If PDN type value indicates IPv4v6, octet 6 contains the IPv6 Prefix Length.
         * Octets 7 through 22 contain an IPv6 Prefix and Interface Identifier.
         * Bit 8 of octet 7 represents the most significant bit of the IPv6 Prefix
         * and Interface Identifier and bit 1 of octet 22 the least significant bit.
         * Octets 23 through 26 contain an IPv4 address. Bit 8 of octet 23 represents
         * the most significant bit of the IPv4 address and bit 1 of octet 26 the least
         * significant bit.
         */
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6, tvb, offset, 16, ENC_NA);
        offset+=16;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    default:
        break;
    }
}
/*
 * 8.15 Bearer Quality of Service (Bearer QoS)
 */

static void
dissect_gtpv2_bearer_qos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_pvi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_pl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_pci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_label_qci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_mbr_up, tvb, offset, 5, ENC_BIG_ENDIAN);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_mbr_down, tvb, offset, 5, ENC_BIG_ENDIAN);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_gbr_up, tvb, offset, 5, ENC_BIG_ENDIAN);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_gbr_down, tvb, offset, 5, ENC_BIG_ENDIAN);
}

/*
 * 8.16 Flow Quality of Service (Flow QoS)
 */

static void
dissect_gtpv2_flow_qos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_label_qci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_mbr_up, tvb, offset, 5, ENC_BIG_ENDIAN);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_mbr_down, tvb, offset, 5, ENC_BIG_ENDIAN);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_gbr_up, tvb, offset, 5, ENC_BIG_ENDIAN);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_gbr_down, tvb, offset, 5, ENC_BIG_ENDIAN);
}

/*
 * 8.17 RAT Type
 */
static const value_string gtpv2_rat_type_vals[] = {
    {0, "Reserved"},
    {1, "UTRAN"},
    {2, "GERAN"},
    {3, "WLAN"},
    {4, "GAN"},
    {5, "HSPA Evolution"},
    {6, "EUTRAN"},
    {7, "Virtual"},
    {0, NULL}
};

static value_string_ext gtpv2_rat_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_rat_type_vals);


static void
dissect_gtpv2_rat_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    guint8     rat_type;

    rat_type = tvb_get_guint8(tvb, 0);
    proto_tree_add_item(tree, hf_gtpv2_rat_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s (%u)", val_to_str_ext_const(rat_type, &gtpv2_rat_type_vals_ext, "Unknown"),rat_type);

}

/*
 * 8.18 Serving Network
 */
static void
dissect_gtpv2_serv_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    gchar *mcc_mnc_str;

    mcc_mnc_str = dissect_e212_mcc_mnc_ep_str(tvb, pinfo, tree, 0, TRUE);
    proto_item_append_text(item,"%s", mcc_mnc_str);
}

/*
 * 8.19 EPS Bearer Level Traffic Flow Template (Bearer TFT)
 */

static void
dissect_gtpv2_bearer_tft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    /* The detailed coding of Traffic Aggregate
     * Description is specified in 3GPP TS 24.008 [5] ,
     * clause 10.5.6.12, beginning with octet 3..
     * Use the decoding in packet-gsm_a_gm.c
     */
    de_sm_tflow_temp(tvb, tree, pinfo, 0, length, NULL, 0);

}
 /* 8.20 Traffic Aggregate Description (TAD)
 */
static void
dissect_gtpv2_tad(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    /* The detailed coding of Traffic Aggregate
     * Description is specified in 3GPP TS 24.008 [5] ,
     * clause 10.5.6.12, beginning with octet 3..
     * Use the decoding in packet-gsm_a_gm.c
     */
    de_sm_tflow_temp(tvb, tree, pinfo, 0, length, NULL, 0);
}

/*
 * 8.21 User Location Info (ULI)
 *
 * The flags ECGI, TAI, RAI, SAI and CGI in octed 5 indicate if the corresponding
 * fields are present in the IE or not. If one of these flags is set to "0",
 * the corresponding field is not present at all. The respective identities are defined in 3GPP
 * TS 23.003 [2].
 * Editor's Note: The definition of ECGI is missing in 3GPP TS 23.003 v8.1.0.
 * It can be found in 3GPP TS 36.413 v8.3.0, but it is expected that it will be moved
 * to 23.003 in a future version.
 */

static void
decode_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 instance _U_, guint flags)
{
    int offset = 1; /* flags are already dissected */
    proto_item  *fi;
    proto_tree  *part_tree;

    /* 8.21.1 CGI field  */
    if (flags & GTPv2_ULI_CGI_MASK)
    {
        proto_item_append_text(item, "CGI ");
        fi = proto_tree_add_text(tree, tvb, offset + 1, 7, "Cell Global Identity (CGI)");
        part_tree = proto_item_add_subtree(fi, ett_gtpv2_uli_field);
        dissect_e212_mcc_mnc(tvb, pinfo, part_tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(part_tree, hf_gtpv2_uli_cgi_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
        proto_tree_add_item(part_tree, hf_gtpv2_uli_cgi_ci, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        if(offset==length)
            return;
    }

    /* 8.21.2 SAI field  */
    if (flags & GTPv2_ULI_SAI_MASK)
    {
        proto_item_append_text(item, "SAI ");
        fi = proto_tree_add_text(tree, tvb, offset + 1, 7, "Service Area Identity (SAI)");
        part_tree = proto_item_add_subtree(fi, ett_gtpv2_uli_field);
        dissect_e212_mcc_mnc(tvb, pinfo, part_tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(part_tree, hf_gtpv2_uli_sai_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(part_tree, hf_gtpv2_uli_sai_sac, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=4;
        if(offset==length)
            return;
    }
    /* 8.21.3 RAI field  */
    if (flags & GTPv2_ULI_RAI_MASK)
    {
        proto_item_append_text(item, "RAI ");
        fi = proto_tree_add_text(tree, tvb, offset + 1, 7, "Routeing Area Identity (RAI)");
        part_tree = proto_item_add_subtree(fi, ett_gtpv2_uli_field);
        dissect_e212_mcc_mnc(tvb, pinfo, part_tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(part_tree, hf_gtpv2_uli_rai_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(part_tree, hf_gtpv2_uli_rai_rac, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=4;
        if(offset==length)
            return;
    }
    /* 8.21.4 TAI field  */
    if (flags & GTPv2_ULI_TAI_MASK)
    {
        proto_item_append_text(item, "TAI ");
        fi = proto_tree_add_text(tree, tvb, offset + 1, 7, "Tracking Area Identity (TAI)");
        part_tree = proto_item_add_subtree(fi, ett_gtpv2_uli_field);
        dissect_e212_mcc_mnc(tvb, pinfo, part_tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(part_tree, hf_gtpv2_uli_tai_tac, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        if(offset==length)
            return;
    }
    /* 8.21.5 ECGI field */
    if (flags & GTPv2_ULI_ECGI_MASK)
    {
        guint8 octet;
        guint32 octet4;
        guint8 spare;
        guint32 ECGI;

        proto_item_append_text(item, "ECGI ");
        fi = proto_tree_add_text(tree, tvb, offset + 1, 7, "E-UTRAN Cell Global Identifier (ECGI)");
        part_tree = proto_item_add_subtree(fi, ett_gtpv2_uli_field);
        dissect_e212_mcc_mnc(tvb, pinfo, part_tree, offset, TRUE);
        offset+=3;
        /* The bits 8 through 5, of octet e+3 (Fig 8.21.5-1 in TS 29.274 V8.2.0) are spare
         * and hence they would not make any difference to the hex string following it,
         * thus we directly read 4 bytes from the tvb
         */

        octet = tvb_get_guint8(tvb,offset);
        spare = octet & 0xF0;
        octet4 = tvb_get_ntohl(tvb,offset);
        ECGI = octet4 & 0x0FFFFFFF;
        proto_tree_add_uint(part_tree, hf_gtpv2_uli_ecgi_eci_spare, tvb, offset, 1, spare);
        /* The coding of the E-UTRAN cell identifier is the responsibility of each administration.
         * Coding using full hexadecimal representation shall be used.
         */
        proto_tree_add_uint(part_tree, hf_gtpv2_uli_ecgi_eci, tvb, offset, 4, ECGI);
        /*proto_tree_add_item(tree, hf_gtpv2_uli_ecgi_eci, tvb, offset, 4, ENC_BIG_ENDIAN);*/
        offset+=4;
        if(offset==length)
            return;

    }
    /* 8.21.6  LAI field */
    if (flags & GTPv2_ULI_LAI_MASK)
    {
        proto_item_append_text(item, "LAI ");
        fi = proto_tree_add_text(tree, tvb, offset + 1, 5, "LAI (Location Area Identifier)");
        part_tree = proto_item_add_subtree(fi, ett_gtpv2_uli_field);
        dissect_e212_mcc_mnc(tvb, pinfo, part_tree, offset, TRUE);
        offset+=3;

        /* The Location Area Code (LAC) consists of 2 octets. Bit 8 of Octet f+3 is the most significant bit
         * and bit 1 of Octet f+4 the least significant bit. The coding of the location area code is the
         * responsibility of each administration. Coding using full hexadecimal representation shall be used.
         */
        proto_tree_add_item(part_tree, hf_gtpv2_uli_lai_lac, tvb, offset, 2, ENC_BIG_ENDIAN);

    }

}

static void
dissect_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *flags_item;
    proto_tree  *flag_tree;
    int offset = 0;
    guint flags;

    flags_item = proto_tree_add_text(tree, tvb, offset, 1, "Flags");
    flag_tree = proto_item_add_subtree(flags_item, ett_gtpv2_uli_flags);
    flags = tvb_get_guint8(tvb,offset)&0x3f;
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset>>3, 2, ENC_BIG_ENDIAN);

    /* LAI B6 */
    proto_tree_add_item(flag_tree, hf_gtpv2_uli_lai_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* ECGI B5 */
    proto_tree_add_item(flag_tree, hf_gtpv2_uli_ecgi_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* TAI B4  */
    proto_tree_add_item(flag_tree, hf_gtpv2_uli_tai_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* RAI B3  */
    proto_tree_add_item(flag_tree, hf_gtpv2_uli_rai_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* SAI B2  */
    proto_tree_add_item(flag_tree, hf_gtpv2_uli_sai_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* CGI B1  */
    proto_tree_add_item(flag_tree, hf_gtpv2_uli_cgi_flg, tvb, offset, 1, ENC_BIG_ENDIAN);

    decode_gtpv2_uli(tvb, pinfo, tree, item, length, instance, flags);

    return;
}

/* Diameter 3GPP AVP Code: 22 3GPP-User-Location-Info */
/*
 * TS 29.061 v9.2.0
 * 16.4.7.2 Coding 3GPP Vendor-Specific RADIUS attributes
 *
 * For P-GW, the Geographic Location Type values and coding are defined as follows:
 *
 * 0        CGI
 * 1        SAI
 * 2        RAI
 * 3-127    Spare for future use
 * 128      TAI
 * 129      ECGI
 * 130      TAI and ECGI
 * 131-255  Spare for future use
 */


static const value_string geographic_location_type_vals[] = {
    {0,   "CGI"},
    {1,   "SAI"},
    {2,   "RAI"},
    {128, "TAI"},
    {129, "ECGI"},
    {130, "TAI and ECGI"},
    {0, NULL}
};

static int
dissect_diameter_3gpp_uli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint length;
    guint flags;
    guint flags_3gpp;
    length = tvb_length(tvb);
    flags_3gpp = tvb_get_guint8(tvb,offset);

    proto_tree_add_item(tree, hf_gtpv2_glt, tvb, offset, 1, ENC_BIG_ENDIAN);

    switch(flags_3gpp)
    {
    case 0:
        /* CGI */
        flags = GTPv2_ULI_CGI_MASK;
        break;
    case 1:
        /* SAI */
        flags = GTPv2_ULI_SAI_MASK;
        break;
    case 2:
        /* RAI */
        flags = GTPv2_ULI_RAI_MASK;
        break;
    case 128:
        /* TAI */
        flags = GTPv2_ULI_TAI_MASK;
        break;
    case 129:
        /* ECGI */
        flags = GTPv2_ULI_ECGI_MASK;
        break;
    case 130:
        /* TAI and ECGI */
        flags = GTPv2_ULI_TAI_MASK + GTPv2_ULI_ECGI_MASK;
        break;
    default:
        proto_tree_add_text(tree, tvb, 1, -1, "Geographic Location");
        return length;
    }

    decode_gtpv2_uli(tvb, pinfo, tree, NULL, length, 0, flags);
    return length;
}

/*
 * 8.22 Fully Qualified TEID (F-TEID)
 */
static const value_string gtpv2_f_teid_interface_type_vals[] = {
    {0, "S1-U eNodeB GTP-U interface"},
    {1, "S1-U SGW GTP-U interface"},
    {2, "S12 RNC GTP-U interface"},
    {3, "S12 SGW GTP-U interface"},
    {4, "S5/S8 SGW GTP-U interface"},
    {5, "S5/S8 PGW GTP-U interface"},
    {6, "S5/S8 SGW GTP-C interface"},
    {7, "S5/S8 PGW GTP-C interface"},
    {8, "S5/S8 SGW PMIPv6 interface"},/* (the 32 bit GRE key is encoded in 32 bit TEID field "
        "and since alternate CoA is not used the control plane and user plane addresses are the same for PMIPv6)"}, */
    {9, "S5/S8 PGW PMIPv6 interface"},/* (the 32 bit GRE key is encoded in 32 bit TEID field "
        "and the control plane and user plane addresses are the same for PMIPv6)"}, */
    {10, "S11 MME GTP-C interface"},
    {11, "S11/S4 SGW GTP-C interface"},
    {12, "S10 MME GTP-C interface"},
    {13, "S3 MME GTP-C interface"},
    {14, "S3 SGSN GTP-C interface"},
    {15, "S4 SGSN GTP-U interface"},
    {16, "S4 SGW GTP-U interface"},
    {17, "S4 SGSN GTP-C interface"},
    {18, "S16 SGSN GTP-C interface"},
    {19, "eNodeB GTP-U interface for DL data forwarding"},
    {20, "eNodeB GTP-U interface for UL data forwarding"},
    {21, "RNC GTP-U interface for data forwarding"},
    {22, "SGSN GTP-U interface for data forwarding"},
    {23, "SGW GTP-U interface for data forwarding"},
    {24, "Sm MBMS GW GTP-C interface"},
    {25, "Sn MBMS GW GTP-C interface"},
    {26, "Sm MME GTP-C interface"},
    {27, "Sn SGSN GTP-C interface"},
    {28, "SGW GTP-U interface for UL data forwarding"},
    {29, "Sn SGSN GTP-U interface"},
    {30, "S2b ePDG GTP-C interface"},
    {31, "S2b-U ePDG GTP-U interface"},
    {32, "S2b PGW GTP-C interface"},
    {33, "S2b-U PGW GTP-U interface"},
    {0, NULL}
};
static value_string_ext gtpv2_f_teid_interface_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_f_teid_interface_type_vals);

static const true_false_string gtpv2_f_teid_v4_vals = {
    "IPv4 address present",
    "IPv4 address not present",
};

static const true_false_string gtpv2_f_teid_v6_vals = {
    "IPv6 address present",
    "IPv6 address not present",
};

static void
dissect_gtpv2_f_teid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint8 flags;

    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_v4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_v6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_interface_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(tree, hf_gtpv2_f_teid_gre_key, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s, TEID/GRE Key: 0x%s",
                           val_to_str_ext_const((flags & 0x1f), &gtpv2_f_teid_interface_type_vals_ext, "Unknown"),
                           tvb_bytes_to_str(tvb, offset, 4));

    offset= offset+4;
    if (flags&0x80)
    {
        proto_tree_add_item(tree, hf_gtpv2_f_teid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, ", IPv4 %s", tvb_ip_to_str(tvb, offset));
        offset= offset+4;
    }
    if (flags&0x40)
    {
        proto_tree_add_item(tree, hf_gtpv2_f_teid_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, ", IPv6 %s", tvb_ip6_to_str(tvb, offset));
    }
}
/*
 * 8.23 TMSI
 */
static void
dissect_gtpv2_tmsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_tmsi, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_text(item, tvb, 0, length, "TMSI: %s", tvb_bytes_to_str(tvb, 0, 4));
}
/*
 * 8.24 Global CN-Id
 * (TS 23.003)
 * 12.3 CN Identifier
 *
 * A CN node is uniquely identified within a PLMN by its CN Identifier (CN-Id). The CN-Id together with the PLMN
 * identifier globally identifies the CN node. The CN-Id together with the PLMN-Id is used as the CN node identifier in
 * RANAP signalling over the Iu interface.
 * Global CN-Id = PLMN-Id || CN-Id
 * The CN-Id is defined by the operator, and set in the nodes via O&M.
 * For the syntax description and the use of this identifier in RANAP signalling, see 3GPP TS 25.413 [17].
 */

static void
dissect_gtpv2_g_cn_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, TRUE);
    offset +=3;

    /* >CN-ID M INTEGER (0..4095) */
    proto_tree_add_text(tree, tvb, offset, 2, "CN-Id: %s",
                        tvb_bytes_to_str(tvb, offset, 2));
}
/*
 * 8.25 S103 PDN Data Forwarding Info (S103PDF)
 */
static void
dissect_gtpv2_s103pdf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;
    int offset = 0;
    guint8       m,k,i;

    /* The HSGW Address and GRE Key identify a GRE Tunnel towards a HSGW over S103 interface for a specific PDN
     * connection of the UE. The EPS Bearer IDs specify the EPS Bearers which require data forwarding that belonging to this
     * PDN connection. The number of EPS bearer Ids included is specified by the value of EPS Bearer ID Number.
     */
    /* Octet 5 HSGW Address for forwarding Length = m */
    m = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_f_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 6 to (m+5) HSGW Address for forwarding [4..16] */
    switch(m) {
    case 4:
        /* IPv4 */
        proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_ipv4, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=4;
        break;
    case 16:
        /* IPv6 */
        proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_ipv6, tvb, offset, 1, ENC_NA);
        offset+=16;
        break;
    default:
        /* Error */
        expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length %u, should be 4 or 16",m);
        expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_ERROR, "Wrong length %u, should be 4 or 16",m);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return;
    }

    /* (m+6)- to (m+9) GRE Key */
    proto_tree_add_item(tree, hf_gtpv2_gre_key, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* (m+10) EPS Bearer ID Number = k */
    k = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "EPS Bearer ID Number = %d", k);
    offset += 1;

    /* (m+11) to (m+10+k)
     * Spare EPS Bearer ID
     */
    for ( i = 0; i < k; i++ ){
        proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

}
/*
 * 8.26 S1-U Data Forwarding (S1UDF)
 */
static void
dissect_gtpv2_s1udf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;
    int offset = 0;
    guint8       m;

    /* 5 Spare EPS Bearer ID */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* 6 Serving GW Address Length = m */
    m = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Serving GW Address Length = %u", m);
    offset++;
    /* 7 to (m+6) Serving GW Address [4..16] */
    switch(m) {
    case 4:
        /* IPv4 */
        proto_tree_add_item(tree, hf_gtpv2_sgw_addr_ipv4, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=4;
        break;
    case 16:
        /* IPv6 */
        proto_tree_add_item(tree, hf_gtpv2_sgw_addr_ipv6, tvb, offset, 1, ENC_NA);
        offset+=16;
        break;
    default:
        /* Error */
        expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length %u, should be 4 or 16",m);
        expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_ERROR, "Wrong length %u, should be 4 or 16",m);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return;
    }

    /* (m+7) to (m+10)
     * Serving GW S1-U TEID
     */
    proto_tree_add_item(tree, hf_gtpv2_sgw_s1u_teid, tvb, offset, 4, ENC_BIG_ENDIAN);

}
/*
 * 8.27 Delay Value
 */

static void
dissect_gtpv2_delay_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_delay_value, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 8.28 Bearer Context (grouped IE)
 */

static void
dissect_gtpv2_bearer_ctx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset= 0;
    tvbuff_t  *new_tvb;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_bearer_ctx);

    new_tvb = tvb_new_subset(tvb, offset, length, length );
    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, 0, message_type);
}

/* 8.29 Charging ID */
static void
dissect_gtpv2_charging_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_charging_id, tvb, offset, length, ENC_BIG_ENDIAN);
}


 /* 8.30 Charging Characteristics
  * The charging characteristics information element is defined in 3GPP TS 32.251 [8]
  * and is a way of informing both the SGW and PGW of the rules for producing charging
  * information based on operator configured triggers. For the encoding of this
  * information element see 3GPP TS 32.298 [9].
  */
static void
dissect_gtpv2_char_char(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_charging_characteristic, tvb, offset, 2, ENC_BIG_ENDIAN);
    if(length>2){
        offset+=2;
        /* These octet(s) is/are present only if explicitly specified */
        proto_tree_add_text(tree, tvb, offset, length-2, "Remaining octets");
    }

}

/*
 * 8.30 Bearer Flag
 */
static void
dissect_gtpv2_bearer_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{

    int offset = 0;

    /* Octet 5 Spare VB PPC */
    proto_tree_add_item(tree, hf_gtpv2_bearer_flag_ppc, tvb, offset, length, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_bearer_flag_vb, tvb, offset, length, ENC_BIG_ENDIAN);

}
/*
 * 8.34 PDN Type
 */
static void
dissect_gtpv2_pdn_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{

    int offset = 0;
    guint8 pdn;

    if (length != 1) {
        proto_item *expert_item;
        expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
        expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return;
    }

    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset<<3, 5, ENC_BIG_ENDIAN);
    pdn = tvb_get_guint8(tvb, offset)& 0x7;
    proto_tree_add_item(tree, hf_gtpv2_pdn_type, tvb, offset, length, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", val_to_str(pdn, gtpv2_pdn_type_vals, "Unknown"));

}

/*
 * 8.31 Trace Information
 */
static void
dissect_gtpv2_tra_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *trigg, *msc_server, *mgw, *sgsn, *ggsn, *bm_sc, *sgw_mme, *ne_types;
    proto_tree  *trigg_tree, *msc_server_tree, *mgw_tree, *sgsn_tree, *ggsn_tree, *bm_sc_tree, *sgw_mme_tree, *ne_types_tree;
    proto_item  *interfaces, *imsc_server, *lmgw, *lsgsn, *lggsn, *lrnc, *lbm_sc, *lmme, *lsgw, *lpdn_gw, *lenb;
    proto_tree  *interfaces_tree, *imsc_server_tree, *lmgw_tree, *lsgsn_tree, *lggsn_tree, *lrnc_tree, *lbm_sc_tree, *lmme_tree, *lsgw_tree, *lpdn_gw_tree, *lenb_tree;

    int         offset = 0;
#if 0
    guint8      *trace_id = NULL;
#endif
    guint8      tdl;
    guint16     tid;
    guint32     bit_offset;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, TRUE);
    offset +=3;

    /* Append Trace ID to main tree */
    tid = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(item, "Trace ID: %d  ", tid);

    /* Trace ID */
    /*--------------------------------------------------
     * trace_id = tvb_format_text(tvb, offset, 2);
     * proto_tree_add_string(tree, hf_gtpv2_tra_info, tvb, offset, length, trace_id);
     *--------------------------------------------------*/
    proto_tree_add_text(tree, tvb, offset, 3, "Trace ID: %d", tid);
    offset +=3;

    /* Triggering Events, put all into a new tree called trigging_tree */
    trigg = proto_tree_add_text(tree, tvb, offset, 8, "Trigging Events");
    trigg_tree = proto_item_add_subtree(trigg, ett_gtpv2_tra_info_trigg);

    /* Create all subtrees */
    msc_server = proto_tree_add_text(trigg_tree, tvb, offset, 2, "MSC Server");
    msc_server_tree = proto_item_add_subtree(msc_server, ett_gtpv2_tra_info_trigg_msc_server);

    mgw = proto_tree_add_text(trigg_tree, tvb, offset + 2, 1, "MGW");
    mgw_tree = proto_item_add_subtree(mgw, ett_gtpv2_tra_info_trigg_mgw);

    sgsn = proto_tree_add_text(trigg_tree, tvb, offset + 3, 2, "SGSN");
    sgsn_tree = proto_item_add_subtree(sgsn, ett_gtpv2_tra_info_trigg_sgsn);

    ggsn = proto_tree_add_text(trigg_tree, tvb, offset + 5, 1, "GGSN");
    ggsn_tree = proto_item_add_subtree(ggsn, ett_gtpv2_tra_info_trigg_ggsn);

    bm_sc = proto_tree_add_text(trigg_tree, tvb, offset + 6, 1, "BM-SC");
    bm_sc_tree = proto_item_add_subtree(bm_sc, ett_gtpv2_tra_info_trigg_bm_sc);

    sgw_mme = proto_tree_add_text(trigg_tree, tvb, offset + 7, 1, "SGW MME");
    sgw_mme_tree = proto_item_add_subtree(sgw_mme, ett_gtpv2_tra_info_trigg_sgw_mme);

    /* MSC Server - 2 octets */
    proto_tree_add_item(msc_server_tree, hf_gtpv2_tra_info_msc_momt_calls,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msc_server_tree, hf_gtpv2_tra_info_msc_momt_sms,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msc_server_tree, hf_gtpv2_tra_info_msc_lu_imsi_ad,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msc_server_tree, hf_gtpv2_tra_info_msc_handovers,   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(msc_server_tree, hf_gtpv2_tra_info_msc_ss,          tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(msc_server_tree, hf_gtpv2_spare_bits,          tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    offset += 1;
    bit_offset = offset<<3;
    proto_tree_add_bits_item(msc_server_tree, hf_gtpv2_spare_bits,          tvb, bit_offset, 8, ENC_BIG_ENDIAN);
    offset += 1;

    /* MGW - 1 octet */
    proto_tree_add_item(mgw_tree, hf_gtpv2_tra_info_mgw_context,            tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(mgw_tree, hf_gtpv2_spare_bits,                 tvb, bit_offset, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /* SGSN - 2 octets */
    proto_tree_add_item(sgsn_tree, hf_gtpv2_tra_info_sgsn_pdp_context,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sgsn_tree, hf_gtpv2_tra_info_sgsn_momt_sms,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sgsn_tree, hf_gtpv2_tra_info_sgsn_rau_gprs_ad,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sgsn_tree, hf_gtpv2_tra_info_sgsn_mbms,             tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(sgsn_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(sgsn_tree, hf_gtpv2_tra_info_sgsn_reserved,         tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(sgsn_tree, hf_gtpv2_reserved,                  tvb, bit_offset, 8, ENC_BIG_ENDIAN);
    offset += 1;
    /* GGSN - 1 octet */
    proto_tree_add_item(ggsn_tree, hf_gtpv2_tra_info_ggsn_pdp,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ggsn_tree, hf_gtpv2_tra_info_ggsn_mbms,             tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(ggsn_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    offset += 1;
    /* BM-SC - 1 octet */
    proto_tree_add_item(bm_sc_tree, hf_gtpv2_tra_info_bm_sc,                tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(bm_sc_tree, hf_gtpv2_spare_bits,               tvb, bit_offset, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /* MME/SGW - 1 octet */
    proto_tree_add_item(sgw_mme_tree, hf_gtpv2_tra_info_mme_sgw_ss,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sgw_mme_tree, hf_gtpv2_tra_info_mme_sgw_sr,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sgw_mme_tree, hf_gtpv2_tra_info_mme_sgw_iataud,     tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(sgw_mme_tree, hf_gtpv2_spare_bits,             tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    offset += 1;

    /* Create NE Types subtree */
    ne_types = proto_tree_add_text(tree, tvb, offset, 2, "List of NE Types");
    ne_types_tree = proto_item_add_subtree(ne_types, ett_gtpv2_tra_info_ne_types);


    /* List of NE Types */
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_msc_s,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_mgw,       tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_sgsn,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_ggsn,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_rnc,       tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_bm_sc,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_mme,       tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_sgw,       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_pdn_gw,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ne_types_tree, hf_gtpv2_tra_info_lne_enb,       tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(ne_types_tree, hf_gtpv2_spare_bits,        tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    offset += 1;

    /* Trace Depth Length */
    tdl = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_tra_info_tdl,                    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Trace Depth List
     * Will be displayed if length of Trace Depth Length is > 0
     * The list will only contains UTF8String, RAW DATA
     */
    proto_tree_add_text(tree, tvb, offset, tdl, "Trace Depth List: %s", tvb_bytes_to_str(tvb, offset, tdl));
    offset += tdl;

    /* Set up subtree interfaces and put all interfaces under it */
    interfaces = proto_tree_add_text(tree, tvb, offset, 12, "List of Interfaces");
    interfaces_tree = proto_item_add_subtree(interfaces, ett_gtpv2_tra_info_interfaces);

    /* Create all subtrees */
    imsc_server = proto_tree_add_text(interfaces_tree, tvb, offset, 2, "MSC Server");
    imsc_server_tree = proto_item_add_subtree(imsc_server, ett_gtpv2_tra_info_interfaces_imsc_server);

    lmgw = proto_tree_add_text(interfaces_tree, tvb, offset + 2, 1, "MGW");
    lmgw_tree = proto_item_add_subtree(lmgw, ett_gtpv2_tra_info_interfaces_lmgw);

    lsgsn = proto_tree_add_text(interfaces_tree, tvb, offset + 3, 2, "SGSN");
    lsgsn_tree = proto_item_add_subtree(lsgsn, ett_gtpv2_tra_info_interfaces_lsgsn);

    lggsn = proto_tree_add_text(interfaces_tree, tvb, offset + 5, 1, "GGSN");
    lggsn_tree = proto_item_add_subtree(lggsn, ett_gtpv2_tra_info_interfaces_lggsn);

    lrnc = proto_tree_add_text(interfaces_tree, tvb, offset + 6, 1, "RNC");
    lrnc_tree = proto_item_add_subtree(lrnc, ett_gtpv2_tra_info_interfaces_lrnc);

    lbm_sc = proto_tree_add_text(interfaces_tree, tvb, offset + 7, 1, "BM-SC");
    lbm_sc_tree = proto_item_add_subtree(lbm_sc, ett_gtpv2_tra_info_interfaces_lbm_sc);

    lmme = proto_tree_add_text(interfaces_tree, tvb, offset + 8, 1, "MME");
    lmme_tree = proto_item_add_subtree(lmme, ett_gtpv2_tra_info_interfaces_lmme);

    lsgw = proto_tree_add_text(interfaces_tree, tvb, offset + 9, 1, "SGW");
    lsgw_tree = proto_item_add_subtree(lsgw, ett_gtpv2_tra_info_interfaces_lsgw);

    lpdn_gw = proto_tree_add_text(interfaces_tree, tvb, offset + 10, 1, "PDN GW");
    lpdn_gw_tree = proto_item_add_subtree(lpdn_gw, ett_gtpv2_tra_info_interfaces_lpdn_gw);

    lenb = proto_tree_add_text(interfaces_tree, tvb, offset + 11, 1, "eNB");
    lenb_tree = proto_item_add_subtree(lenb, ett_gtpv2_tra_info_interfaces_lpdn_lenb);

    /* MSC Server - 2 octests */
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_a,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_lu,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_mc,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_g,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_b,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_e,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_f,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_cap,       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_d,     tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(imsc_server_tree, hf_gtpv2_tra_info_lmsc_map_c,     tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(imsc_server_tree, hf_gtpv2_spare_bits,         tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    offset += 1;
    /* MGW - 1 octet */
    proto_tree_add_item(lmgw_tree, hf_gtpv2_tra_info_lmgw_mc,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lmgw_tree, hf_gtpv2_tra_info_lmgw_nb_up,            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lmgw_tree, hf_gtpv2_tra_info_lmgw_lu_up,            tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lmgw_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    offset += 1;
    /* SGSN - 2 octets */
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_gb,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_lu,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_gn,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_map_gr,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_map_gd,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_map_gf,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_gs,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgsn_tree, hf_gtpv2_tra_info_lsgsn_ge,             tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lsgsn_tree, hf_gtpv2_spare_bits,               tvb, bit_offset, 8, ENC_BIG_ENDIAN);
    offset += 1;

    /* GGSN - 1 octet */
    proto_tree_add_item(lggsn_tree, hf_gtpv2_tra_info_lggsn_gn,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lggsn_tree, hf_gtpv2_tra_info_lggsn_gi,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lggsn_tree, hf_gtpv2_tra_info_lggsn_gmb,            tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lggsn_tree, hf_gtpv2_spare_bits,               tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    offset += 1;
    /* RNC - 1 octet */
    proto_tree_add_item(lrnc_tree, hf_gtpv2_tra_info_lrnc_lu,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lrnc_tree, hf_gtpv2_tra_info_lrnc_lur,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lrnc_tree, hf_gtpv2_tra_info_lrnc_lub,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lrnc_tree, hf_gtpv2_tra_info_lrnc_uu,               tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lrnc_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    offset += 1;
    /* BM_SC - 1 octet */
    proto_tree_add_item(lbm_sc_tree, hf_gtpv2_tra_info_lbm_sc_gmb,          tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lbm_sc_tree, hf_gtpv2_spare_bits,              tvb, bit_offset, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /* MME - 1 octet */
    proto_tree_add_item(lmme_tree, hf_gtpv2_tra_info_lmme_s1_mme,           tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lmme_tree, hf_gtpv2_tra_info_lmme_s3,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lmme_tree, hf_gtpv2_tra_info_lmme_s6a,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lmme_tree, hf_gtpv2_tra_info_lmme_s10,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lmme_tree, hf_gtpv2_tra_info_lmme_s11,              tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lmme_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    offset += 1;
    /* SGW - 1 octet */
    proto_tree_add_item(lsgw_tree, hf_gtpv2_tra_info_lsgw_s4,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgw_tree, hf_gtpv2_tra_info_lsgw_s5,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgw_tree, hf_gtpv2_tra_info_lsgw_s8b,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsgw_tree, hf_gtpv2_tra_info_lsgw_s11,              tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lsgw_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    offset += 1;
    /* PDN GW - 1 octet */
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_s2a,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_s2b,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_s2c,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_s5,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_s6c,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_gx,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_s8b,        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lpdn_gw_tree, hf_gtpv2_tra_info_lpdn_gw_sgi,        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* eNB - 1 octet */
    proto_tree_add_item(lenb_tree, hf_gtpv2_tra_info_lenb_s1_mme,           tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lenb_tree, hf_gtpv2_tra_info_lenb_x2,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lenb_tree, hf_gtpv2_tra_info_lenb_uu,               tvb, offset, 1, ENC_BIG_ENDIAN);
    bit_offset = offset<<3;
    proto_tree_add_bits_item(lenb_tree, hf_gtpv2_spare_bits,                tvb, bit_offset, 5, ENC_BIG_ENDIAN);

    /*--------------------------------------------------
     * offset += 1;
     *--------------------------------------------------*/

    /* IP Address of Trace Collection Entity */
    while ( (offset + 4) <= length ) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 3;
    }
}

/*
 * 8.33 Paging Cause
 * 8.33 Void (TS 129 274 V9.4.0 (2010-10))
 */

/* 8.35 Procedure Transaction ID (PTI) */
static void
dissect_gtpv2_pti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_pti, tvb, 0, 1, ENC_BIG_ENDIAN);
}
/*
 * 8.36 DRX Parameter
 */
static void
dissect_gtpv2_drx_param(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    /* 36.413 : 9.2.1.17   Paging Cause, void */
    proto_tree_add_text(tree, tvb, offset, length, "DRX parameter: %s", tvb_bytes_to_str(tvb, offset, (length )));
}

/*
 * 8.37 UE Network Capability
 * UE Network Capability is coded as depicted in Figure 8.37-1. Actual coding of the UE Network Capability field is
 * defined in 3GPP TS 24.301
 */
static void
dissect_gtpv2_ue_net_capability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    de_emm_ue_net_cap(tvb, tree, pinfo, 0, length, NULL, 0);

}
/*
 * 8.38 MM Context
 */
static const value_string gtpv2_mm_context_security_mode[] = {
    {0, "GSM Key and Triplets"},
    {1, "UMTS Key, Used Cipher and Quintuplets"},
    {2, "GSM Key, Used Cipher and Quintuplets"},
    {3, "UMTS Key and Quintuplets"},
    {4, "EPS Security Context, Quadruplets and Quintuplets" },
    {5, "UMTS Key, Quadruplets and Quintuplets"},
    {0, NULL                                                                                                    }
};

static const true_false_string gtpv2_nhi_vals = {
    "NH (Next Hop) and NCC (Next Hop Chaining Count) are both present",
    "NH (Next Hop) and NCC (Next Hop Chaining Count) not present",
};

/* Table 8.38-2: Used NAS Cipher Values */

static const value_string gtpv2_mm_context_unc_vals[] = {
    {0, "No ciphering"},
    {1, "GEA/1"},
    {2, "GEA/2"},
    {3, "GEA/3"},
    {4, "GEA/4" },
    {5, "GEA/5"},
    {6, "GEA/6"},
    {7, "GEA/7"},
    {0, NULL}
};

/* Table 8.38-4: Used NAS integrity protection algorithm Values */
static const value_string gtpv2_mm_context_unipa_vals[] = {
    {0, "No ciphering"},
    {1, "128-EEA1"},
    {2, "128-EEA2"},
    {3, "EEA3"},
    {4, "EEA4"  },
    {5, "EEA5"},
    {6, "EEA6"},
    {7, "EEA7"},
    {0, NULL}
};


static void
dissect_gtpv2_mm_context_gsm_t(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item   *flag;
    proto_tree  *flag_tree;
    int          offset;

    offset = 0;
    flag = proto_tree_add_text(tree, tvb, offset, 3, "MM Context flags");
    flag_tree = proto_item_add_subtree(flag, ett_gtpv2_mm_context_flag);

    /* Security Mode | Spare | DRXI | CKSN */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_cksn, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Number of Triplet | Spare  | UAMB RI | SAMB RI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_tri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 5, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_text(flag_tree, tvb, offset, -1, "The rest of the IE not dissected yet");
}

static void
dissect_gtpv2_mm_context_utms_cq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *flag;
    proto_tree  *flag_tree;
    int          offset;

    offset = 0;
    flag = proto_tree_add_text(tree, tvb, offset, 3, "MM Context flags");
    flag_tree = proto_item_add_subtree(flag, ett_gtpv2_mm_context_flag);

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset<<3)+3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_cksn_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 5, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_text(flag_tree, tvb, offset, -1, "The rest of the IE not dissected yet");
}

static void
dissect_gtpv2_mm_context_gsm_cq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *flag;
    proto_tree  *flag_tree;
    int          offset;


    offset = 0;
    flag = proto_tree_add_text(tree, tvb, offset, 3, "MM Context flags");
    flag_tree = proto_item_add_subtree(flag, ett_gtpv2_mm_context_flag);

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset<<3)+3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_cksn_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 5, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_text(flag_tree, tvb, offset, -1, "The rest of the IE not dissected yet");

}

static void
dissect_gtpv2_mm_context_utms_q(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *flag;
    proto_tree  *flag_tree;
    int          offset;

    offset = 0;
    flag = proto_tree_add_text(tree, tvb, offset, 3, "MM Context flags");
    flag_tree = proto_item_add_subtree(flag, ett_gtpv2_mm_context_flag);


    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset<<3)+3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_ksi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 5, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_text(flag_tree, tvb, offset, -1, "The rest of the IE not dissected yet");
}

/* 8.38 MM Context
 * EPS Security Context and Quadruplets
 */
static void
dissect_gtpv2_mm_context_eps_qq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *flag_item, *auth_qua_item, *net_cap_item,
                *msnt_cap_item, *accrstdata_item, *vd_pref_item;
    proto_tree  *flag_tree, *auth_qua_tree = NULL, *net_cap_tree,
                *msnt_cap_tree, *vd_pref_tree, *accrstdata_tree;
    gint         offset;
    guint8       nhi, nr_qua, tmp;

    offset = 0;

    nhi = (tvb_get_guint8(tvb, offset) & 0x10);

    flag_item = proto_tree_add_text(tree, tvb, offset, 3, "MM Context flags");
    flag_tree = proto_item_add_subtree(flag_item, ett_gtpv2_mm_context_flag);

    /* Octet 5
     * Bits
     * 8      7     6     5     4      3      2      1
     * Security Mode    | NHI | DRXI | KSIASME
     */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* If NHI (Next Hop Indicator), bit 5 of octet 5, is set to "1",
     * then the optional parameters NH (Next Hop) and NCC (Next
     * Hop Chaining Count) are both present, otherwise their octets are not present.
     */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_ksi_a, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 6
     * Bits
     * 8      7     6     5     4      3      2      1
     * Number of        | Number of       | UAMB  | OSCI
     * Quintuplets      | Quadruplet      |  RI   |
     */
    nr_qua = tvb_get_guint8(tvb, offset) & 0x1c;

    nr_qua >>= 2;

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qua, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* UAMB RI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_uamb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* OSCI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_osci, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 7 */
    /* SAMB RI */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_samb_ri, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Used NAS integrity protection algorithm */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_unipa, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Used NAS Cipher */
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_unc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 8-10 NAS Downlink Count*/
    proto_tree_add_item(tree, hf_gtpv2_mm_context_nas_dl_cnt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    /* Octet 11-13 NAS Uplink Count */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_nas_ul_cnt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;

    /* Octet 14-45 */
    proto_tree_add_item(tree, hf_gtpv2_mm_context_kasme, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;

    /* Octet 46-g */

    /* 1 to 16                      RAND
     * 17                           XRES Length
     * 18 to k                      XRES
     * k+1                          AUTN Length
     * (k+2) to m               AUTN
     * (m+1) to (m+32)      Kasme
     */

    if ( nr_qua )
    {
        auth_qua_item = proto_tree_add_text(tree, tvb, offset, 0, "Authentication Quadruplet");
        auth_qua_tree = proto_item_add_subtree(auth_qua_item, ett_gtpv2_mm_context_auth_qua);
    }

    while ( nr_qua-- )
    {
        proto_tree_add_text(auth_qua_tree, tvb, offset, 16, "RAND: %s",
            tvb_bytes_to_str(tvb, offset, 16));
        offset += 16;

        tmp = tvb_get_guint8(tvb, offset++);

        proto_tree_add_text(auth_qua_tree, tvb, offset, tmp, "XRES: %s",
            tvb_bytes_to_str(tvb, offset, tmp));
        offset += tmp;

        tmp = tvb_get_guint8(tvb, offset++);

        proto_tree_add_text(auth_qua_tree, tvb, offset, tmp, "AUTN: %s",
            tvb_bytes_to_str(tvb, offset, tmp));
        offset += tmp;

        proto_tree_add_item(tree, hf_gtpv2_mm_context_kasme, tvb, offset, 32, ENC_BIG_ENDIAN);

        offset += 32;
    }

    /* (h+1) to (h+2) DRX parameter */
    proto_tree_add_text(tree, tvb, offset, 2, "DRX parameter: %s", tvb_bytes_to_str(tvb, offset, 2));
    offset+=2;

    /* Octet p to p+31 & Octet p+32 */
    if ( nhi )
    {
        proto_tree_add_text(tree, tvb, offset, 32, "NH (Next Hop): %s",
            tvb_bytes_to_str(tvb, offset, 32));
        offset += 32;

        proto_tree_add_text(tree, tvb, offset, 1, "NCC (Next Hop Chaining Count): %d",
            (tvb_get_guint8(tvb, offset) & 0x0f));
        offset += 1;
    }


    proto_tree_add_text(tree, tvb, offset, 4, "Uplink Subscriber UE AMBR: %d Kbps",
            tvb_get_ntohl(tvb, offset));

    offset += 4;

    proto_tree_add_text(tree, tvb, offset, 4, "Downlink Subscriber UE AMBR: %d Kbps",
            tvb_get_ntohl(tvb, offset));

    offset += 4;

    proto_tree_add_text(tree, tvb, offset, 4, "Uplink Used UE AMBR: %d Kbps",
            tvb_get_ntohl(tvb, offset));

    offset += 4;

    proto_tree_add_text(tree, tvb, offset, 4, "Downlink Used UE AMBR: %d Kbps",
            tvb_get_ntohl(tvb, offset));
    offset += 4;


    /* The UE Network Capability coding is specified in clause 9.9.3.34 of 3GPP TS 24.301 [23].
     * If Length of UE Network Capability is zero, then the UE Network Capability parameter shall not be present.
     */
    tmp = tvb_get_guint8(tvb, offset++);
    if ( tmp > 0 ){
        net_cap_item = proto_tree_add_text(tree, tvb, offset, tmp, "UE Network Capability");
        net_cap_tree = proto_item_add_subtree(net_cap_item, ett_gtpv2_mm_context_net_cap);
        offset+=de_emm_ue_net_cap(tvb, net_cap_tree, pinfo, offset, tmp, NULL, 0);
    }

    /* The MS Network Capability coding is specified in clause 10.5.5.12 of 3GPP TS 24.008 [5].
     * If Length of MS Network Caapability is zero, then the MS Network Capability parameter shall not be present.
     */
    /* Octet k+1 */
    tmp = tvb_get_guint8(tvb, offset++);
    if ( tmp > 0 ){

        msnt_cap_item = proto_tree_add_text(tree, tvb, offset, tmp, "MS network capability");
        msnt_cap_tree = proto_item_add_subtree(msnt_cap_item, ett_gtpv2_ms_network_capability);
        offset+=de_gmm_ms_net_cap(tvb, msnt_cap_tree, pinfo, offset, tmp, NULL, 0);

    }

    /* Octet m+1
     * The encoding of Mobile Equipment Identity (MEI) field shall be same as specified in clause 8.10 of this
     * specification. If Length of Mobile Equipment Identity is zero, then the Mobile Equipment Identity parameter
     * shall not be present.
     */
    tmp = tvb_get_guint8(tvb, offset++);
    if ( tmp > 0 )
    {
        proto_tree_add_text(tree, tvb, offset, tmp, "Mobile Equipment Identify (MEI): %s",
            tvb_bcd_dig_to_ep_str( tvb, offset, tmp, NULL, ENC_BIG_ENDIAN));
        offset += tmp;
    }

    /* r+1 Spare HNNA ENA INA GANA GENA UNA */
    if (offset < (gint)length+4){
        accrstdata_item = proto_tree_add_text(tree, tvb, offset, tmp, "Access restriction data");
        accrstdata_tree = proto_item_add_subtree(accrstdata_item, ett_gtpv2_access_rest_data);
        proto_tree_add_item(accrstdata_tree, hf_gtpv2_hnna, tvb, offset, 1, FALSE);
        proto_tree_add_item(accrstdata_tree, hf_gtpv2_ina, tvb, offset, 1, FALSE);
        proto_tree_add_item(accrstdata_tree, hf_gtpv2_ena, tvb, offset, 1, FALSE);
        proto_tree_add_item(accrstdata_tree, hf_gtpv2_gana, tvb, offset, 1, FALSE);
        proto_tree_add_item(accrstdata_tree, hf_gtpv2_gena, tvb, offset, 1, FALSE);
        proto_tree_add_item(accrstdata_tree, hf_gtpv2_una, tvb, offset, 1, FALSE);
        offset++;
    }else{
        return;
    }
     if (offset < (gint)length+4){
         tmp = tvb_get_guint8(tvb, offset++);
     }

    /* The Voice Domain Preference and UE's Usage Setting coding is specified in clause 10.5.5.28 of 3GPP TS 24.008 [5].
     * If Length of Voice Domain Preference and UE's Usage Setting is zero, then the Voice Domain Preference and UE's
     * Usage Setting parameter shall not be present.
     */
    if ( tmp > 0 )
    {
        vd_pref_item = proto_tree_add_text(tree, tvb, offset, tmp, "Voice Domain Preference and UE's Usage Setting");
        vd_pref_tree = proto_item_add_subtree(vd_pref_item, ett_gtpv2_vd_pref);
        de_gmm_voice_domain_pref(tvb, vd_pref_tree, pinfo, offset, tmp, NULL, 0);
    }

}

static void
dissect_gtpv2_mm_context_utms_qq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *flag;
    proto_tree  *flag_tree;
    guint32      offset;

    offset = 0;
    flag = proto_tree_add_text(tree, tvb, offset, 3, "MM Context flags");
    flag_tree = proto_item_add_subtree(flag, ett_gtpv2_mm_context_flag);

    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_sm, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(flag_tree, hf_gtpv2_spare_bits, tvb, ((offset<<3)+3), 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_drxi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_ksi_a, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_mm_context_nr_qua, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 2, ENC_BIG_ENDIAN);

}

/*
  * 8.39 PDN Connection (grouped IE)
 */
static void
dissect_gtpv2_PDN_conn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset= 0;
    proto_tree *grouped_tree;
    tvbuff_t *new_tvb;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_PDN_conn);
    new_tvb = tvb_new_subset(tvb, offset, length, length );

    dissect_gtpv2_ie_common(new_tvb, pinfo, grouped_tree, offset, message_type);
}
/*
 * 8.40 PDU Numbers
 */
static void
dissect_gtpv2_pdn_numbers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item  *nsapi_ti;
    proto_tree  *nsapi_tree;
    guint8       nsapi;
    guint16      dlgtpu_seq, ulgtpu_seq, send_npdu_nr, rec_npdu_nr;
    int          offset = 0;

    nsapi = (tvb_get_guint8(tvb, offset) & 0x08);
    nsapi_ti = proto_tree_add_text(tree, tvb, offset, 1, "NSAPI: %d", nsapi);
    nsapi_tree = proto_item_add_subtree(nsapi_ti, ett_gtpv2_pdn_numbers_nsapi);
    proto_tree_add_item(nsapi_tree, hf_gtpv2_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(nsapi_tree, hf_gtpv2_pdn_numbers_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "NSAPI: %u", nsapi);
    offset++;

    dlgtpu_seq = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "DL GTP-U Sequence Number: %d", dlgtpu_seq);
    offset += 2;

    ulgtpu_seq = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "UL GTP-U Sequence Number: %d", ulgtpu_seq);
    offset += 2;

    send_npdu_nr = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Send N-PDU Number: %d", send_npdu_nr);
    offset += 2;

    rec_npdu_nr = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "Receive N-PDU Number: %d", rec_npdu_nr);
}

/*
 * 8.41 Packet TMSI (P-TMSI)
 */
static void
dissect_gtpv2_p_tmsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    /* The TMSI consists of 4 octets. It can be coded using a full hexadecimal representation. */
    proto_tree_add_item(tree, hf_gtpv2_p_tmsi, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", tvb_bytes_to_str(tvb, offset, 4));
}

/*
 * 8.42 P-TMSI Signature
 */
static void
dissect_gtpv2_p_tmsi_sig(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    /* The P-TMSI Signature consists of 3 octets and may be allocated by the SGSN. */
    proto_tree_add_item(tree, hf_gtpv2_p_tmsi_sig, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", tvb_bytes_to_str(tvb, offset, 3));

}

/*
 * 8.43 Hop Counter
 */
static void
dissect_gtpv2_hop_counter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint8 hop_counter;

    hop_counter = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1, "Hop Counter: %d", hop_counter);
    proto_item_append_text(item, "%d", hop_counter);
}

/*
 * 8.44 UE Time Zone
 */

static const value_string gtpv2_ue_time_zone_dst_vals[] = {
    {0, "No Adjustments for Daylight Saving Time"},
    {1, "+1 Hour Adjustments for Daylight Saving Time"},
    {2, "+2 Hour Adjustments for Daylight Saving Time"},
    {3, "Spare"},
    {0, NULL}
};
static void
dissect_gtpv2_ue_time_zone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    /*
     * UE Time Zone is used to indicate the offset between universal time and local time in steps of 15 minutes of where the
     * UE currently resides. The "Time Zone" field uses the same format as the "Time Zone" IE in 3GPP TS 24.008 [5].
     * (packet-gsm_a_dtap.c)
     */
    de_time_zone(tvb, tree, pinfo, offset, 1, NULL, 0);
    offset= offset+ 1;
    proto_tree_add_item(item, hf_gtpv2_ue_time_zone_dst, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 8.45 Trace Reference
 */
static void
dissect_gtpv2_trace_reference(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint32 trace_id;
    gchar *mcc_mnc_str;

    mcc_mnc_str = dissect_e212_mcc_mnc_ep_str(tvb, pinfo, tree, 0, TRUE);
    offset += 3;

    trace_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 3, "Trace ID: %d", trace_id);

    proto_item_append_text(item,"%s,Trace ID %u", mcc_mnc_str, trace_id);
}
/*
 * 8.46 Complete Request Message
 */
static const value_string gtpv2_complete_req_msg_type_vals[] = {
    {0, "Complete Attach Request Message"  },
    {1, "Complete TAU Request Message"     },
    {0, NULL                               }
};
static void
dissect_complete_request_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    tvbuff_t  *new_tvb;
    int        offset;

    offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_complete_req_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /* Add the Complete Request Message */
    new_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(nas_eps_handle, new_tvb, pinfo, tree);

}

/*
 * 8.47 GUTI
 */
static void
dissect_gtpv2_guti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    offset = 0;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, TRUE);
    offset += 3;

    proto_tree_add_item(tree, hf_gtpv2_mme_grp_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_gtpv2_mme_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_gtpv2_m_tmsi, tvb, offset,4, ENC_NA);
}

/*
 * 8.48 Fully Qualified Container (F-Container)
 */

static const value_string gtpv2_container_type_vals[] = {
    {1, "UTRAN transparent container"},
    {2, "BSS container"},
    {3, "E-UTRAN transparent container"},
    {0, NULL}
};


static void
dissect_gtpv2_F_container(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type, guint8 instance _U_)
{
    tvbuff_t *tvb_new;
    proto_item *bss_item;
    proto_tree *sub_tree;
    int offset = 0;
    guint8 container_type;
    guint8 container_flags, xid_len;

    /* Octets   8   7   6   5   4   3   2   1
     * 5            Spare     | Container Type
     */
    proto_tree_add_item(tree, hf_gtpv2_container_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    container_type = tvb_get_guint8(tvb,offset);
    offset++;
    if((message_type == GTPV2_FORWARD_RELOCATION_REQ)
       ||(message_type == GTPV2_CONTEXT_RESPONSE)
       ||(message_type == GTPV2_RAN_INFORMATION_RELAY)){
        switch(container_type){
        case 2:
            /* BSS container */
            bss_item = proto_tree_add_text(tree, tvb, offset, length, "BSS container");
            sub_tree = proto_item_add_subtree(bss_item, ett_gtpv2_bss_con);
            /* The flags PFI, RP, SAPI and PHX in octet 6 indicate the corresponding type of paratemer */
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_container_phx, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_sapi_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_rp_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_pfi_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
            container_flags = tvb_get_guint8(tvb,offset);
            offset++;
            if((container_flags&0x01)==1){
                /* Packet Flow ID present */
                proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_pfi, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            if(((container_flags&0x04)==4)||((container_flags&0x02)==2)){
                if((container_flags&0x04)==4){
                    /* SAPI present */
                    proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_sapi, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                if((container_flags&0x02)==2){
                    /* Radio Priority present */
                    proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_rp, tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                offset++;
            }
            if((container_flags&0x08)==8){
                /* XiD parameters length is present in Octet c.
                 * XiD parameters are present in Octet d to n.
                 */
                xid_len = tvb_get_guint8(tvb,offset);
                proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_xid_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                proto_tree_add_item(sub_tree, hf_gtpv2_bss_con_xid, tvb, offset, xid_len, ENC_BIG_ENDIAN);
            }
            return;
        default:
            break;
        }
    }
    if(message_type == GTPV2_FORWARD_CTX_NOTIFICATION) {
        switch(container_type){
        case 3:
            /* E-UTRAN transparent container */
            tvb_new = tvb_new_subset_remaining(tvb, offset);
            dissect_s1ap_ENB_StatusTransfer_TransparentContainer_PDU(tvb_new, pinfo, tree);
            return;
        default:
            break;
        }
    }

    /* 7.3.2 Forward Relocation Response
     * E-UTRAN Transparent Container
     * This IE is conditionally included only during a handover to
     * E-UTRAN and contains the radio-related and core network
     * information. If the Cause IE contains the value "Request
     * accepted", this IE shall be included.
     */
    proto_tree_add_text(tree, tvb, offset, length-offset, "Not dissected yet");

}

/*
 * 8.49 Fully Qualified Cause (F-Cause)
 */

static const value_string gtpv2_cause_type_vals[] = {
    {0,  "Radio Network Layer"},
    {1,  "Transport Layer"},
    {2,  "NAS"},
    {3,  "Protocol"},
    {4,  "Miscellaneous"},
    {5,  "<spare>"},
    {6,  "<spare>"},
    {7,  "<spare>"},
    {8,  "<spare>"},
    {9,  "<spare>"},
    {10, "<spare>"},
    {11, "<spare>"},
    {12, "<spare>"},
    {13, "<spare>"},
    {14, "<spare>"},
    {15, "<spare>"},
    {0, NULL}
};
static value_string_ext gtpv2_cause_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_cause_type_vals);

static void
dissect_gtpv2_F_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint8 cause_type;

    /* The value of Instance field of the F-Cause IE in a GTPv2 message shall indicate
     * whether the F-Cause field contains RANAP Cause, BSSGP Cause or RAN Cause.
     * If the F-Cause field contains RAN Cause, the Cause Type field shall contain
     * the RAN cause subcategory as specified in 3GPP TS 36.413 [10] and it shall be
     * encoded as in Table 8.49-1.
     * If the F-Cause field contains BSSGP Cause or RANAP Cause,
     * the Cause Type field shall be ignored by the receiver.
     */
    if(message_type == GTPV2_FORWARD_RELOCATION_REQ) {
        switch(instance) {
        case 0:
            proto_item_append_text(item, "[RAN Cause]");
            proto_tree_add_item(tree, hf_gtpv2_cause_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            cause_type = tvb_get_guint8(tvb,offset);
            offset++;
            switch(cause_type){
            case 0:
                /* CauseRadioNetwork */
                proto_tree_add_item(tree, hf_gtpv2_CauseRadioNetwork, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 1:
                /* CauseTransport */
                proto_tree_add_item(tree, hf_gtpv2_CauseTransport, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 2:
                /* CauseNas */
                proto_tree_add_item(tree, hf_gtpv2_CauseNas, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 3:
                /* CauseProtocol */
                proto_tree_add_item(tree, hf_gtpv2_CauseProtocol, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 4:
                /* CauseMisc */
                proto_tree_add_item(tree, hf_gtpv2_CauseMisc, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            default:
                break;
            }
            return;
            break;
        case 1:
            proto_item_append_text(item, "[RANAP Cause]");
            break;
        case 2:
            proto_item_append_text(item, "[BSSGP Cause]");
            break;
        default:
            break;
        }
    }
    proto_tree_add_text(tree, tvb, offset, length-offset, "Not dissected yet");

}

/*
 * 8.50 Selected PLMN ID
 */
/*
 * The Selected PLMN ID IE contains the core network operator selected for tne UE
 * in a shared network. Octets 5-7 shall be encoded as the content part of the
 *  "Selected PLMN Identity" parameter in 3GPP TS 36.413 [10].
 * -The Selected PLMN identity consists of 3 digits from MCC followed by
 * either -a filler digit plus 2 digits from MNC (in case of 2 digit MNC) or
 * -3 digits from MNC (in case of a 3 digit MNC).
 */
static void
dissect_gtpv2_sel_plmn_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    gchar *mcc_mnc_str;

    mcc_mnc_str = dissect_e212_mcc_mnc_ep_str(tvb, pinfo, tree, 0, TRUE);
    proto_item_append_text(item,"%s", mcc_mnc_str);
}

/*
 * 8.51 Target Identification
 */

static const value_string gtpv2_target_type_vals[] = {
    {0,  "RNC ID"},
    {1,  "Macro eNodeB ID"},
    {2,  "Cell Identifier"},
    {3,  "Home eNodeB ID"},
    {0, NULL}
};
static value_string_ext gtpv2_target_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_target_type_vals);

static void
dissect_gtpv2_target_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    tvbuff_t *tvb_new;
    int offset = 0;
    guint8 target_type;

    proto_tree_add_item(tree, hf_gtpv2_target_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    target_type = tvb_get_guint8(tvb,offset);
    offset++;
    switch(target_type) {
    case 0:
        /* RNC ID
         * In this case the Target ID field shall be encoded as the Target
         * RNC-ID part of the "Target ID" parameter in 3GPP TS 25.413 [33]. Therefore, the "Choice Target ID" that indicates
         * "Target RNC-ID" (numerical value of 0x20) shall not be included (value in octet 5 specifies the target type).
         */
        tvb_new = tvb_new_subset_remaining(tvb, offset);
        dissect_ranap_TargetRNC_ID_PDU(tvb_new, pinfo, tree);
        return;
        break;
    case 1:
        /* Macro eNodeB ID*/
        tvb_new = tvb_new_subset_remaining(tvb, offset);
        dissect_e212_mcc_mnc(tvb_new, pinfo, tree, 0, TRUE);
        offset+=3;
        /* The Macro eNodeB ID consists of 20 bits.
         * Bit 4 of Octet 4 is the most significant bit and bit 1 of Octet 6 is the least significant bit.
         */
        proto_tree_add_item(tree, hf_gtpv2_macro_enodeb_id, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        /* Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_uli_tai_tac, tvb, offset, 2, ENC_BIG_ENDIAN);
        return;

    case 2:
        /* Cell Identifier */
        /* Target ID field shall be same as the Octets 3 to 10 of the Cell Identifier IEI
         * in 3GPP TS 48.018 [34].
         */
        tvb_new = tvb_new_subset_remaining(tvb, offset);
        de_bssgp_cell_id(tvb_new, tree, pinfo, 0, 0/* not used */, NULL, 0);
        return;
    case 3:
        /* Home eNodeB ID */
        tvb_new = tvb_new_subset_remaining(tvb, offset);
        dissect_e212_mcc_mnc(tvb_new, pinfo, tree, 0, TRUE);
        offset+=3;
        /* Octet 10 to 12 Home eNodeB ID
         * The Home eNodeB ID consists of 28 bits. See 3GPP TS 36.413 [10].
         * Bit 4 of Octet 9 is the most significant bit and bit 1 of Octet 12 is the least significant bit.
         * The coding of the Home eNodeB ID is the responsibility of each administration.
         * Coding using full hexadecimal representation shall be used.
         */
        proto_tree_add_item(tree, hf_gtpv2_home_enodeb_id, tvb, offset, 4 , ENC_BIG_ENDIAN);
        offset+=4;
        /* Octet 13 to 14 Tracking Area Code (TAC) */
        proto_tree_add_item(tree, hf_gtpv2_tac, tvb, offset, 2 , ENC_BIG_ENDIAN);
        return;

    default:
        break;
    }
    proto_tree_add_text(tree, tvb, offset, length-offset, "Not dissected yet");

}

/*
 * 8.52 Void
 */
/*
 * 8.53 Packet Flow ID
 */
static void
dissect_gtpv2_pkt_flow_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    /* Octet 5 Spare EBI */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    /* Packet Flow ID */
    proto_tree_add_text(tree, tvb, offset, length, "Packet Flow ID: %s", tvb_bytes_to_str(tvb, offset, length-1));

}
/*
 * 8.54 RAB Context
 */
static void
dissect_gtpv2_rab_context(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint16   dlgtpu_seq, ulgtpu_seq, dl_pdcp_seq, ul_pdcp_seq;

    /* 5 Spare NSAPI */
    proto_tree_add_bits_item(tree, hf_gtpv2_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* 6 to 7 DL GTP-U Sequence Number */
    dlgtpu_seq = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "DL GTP-U Sequence Number: %d", dlgtpu_seq);
    offset += 2;

    /* 8 to 9 UL GTP-U Sequence Number */
    ulgtpu_seq = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "UL GTP-U Sequence Number: %d", ulgtpu_seq);
    offset += 2;

    /* 10 to 11 DL PDCP Sequence Number */
    dl_pdcp_seq = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "DL PDCP Sequence Number: %d", dl_pdcp_seq);
    offset += 2;

    /* 12 to 13 UL PDCP Sequence Number */
    ul_pdcp_seq = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2, "UL PDCP Sequence Number: %d", ul_pdcp_seq);

}

/*
 * 8.55 Source RNC PDCP context info
 */
static void
dissect_gtpv2_s_rnc_pdcp_ctx_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    proto_tree_add_text(tree, tvb, 0, length, "RRC Container");
}

/*
 * 8.56 UDP Source Port Number
 */
static void
dissect_udp_s_port_nr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_tree_add_text(tree, tvb, 0, 2, "UPD Source Port Number: %u", tvb_get_ntohs(tvb, 0));
    proto_item_append_text(item, "%u", tvb_get_ntohs(tvb, 0));
}
/*
 * 8.57 APN Restriction
 */
static void
dissect_gtpv2_apn_rest(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    guint8 type_value;

    type_value = tvb_get_guint8(tvb, 0);
    proto_tree_add_item(tree, hf_gtpv2_apn_rest, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "value %u", type_value);
}

/*
 * 8.58 Selection Mode
 */
static const value_string gtpv2_selec_mode_vals[] = {
    {0, "MS or network provided APN, subscribed verified"},
    {1, "MS provided APN, subscription not verified"},
    {2, "Network provided APN, subscription not verified"},
    {3, "Network provided APN, subscription not verified (Basically for Future use"},
    {0, NULL}
};

static void
dissect_gtpv2_selec_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int          offset=0;
    guint8       ss_mode;

    ss_mode = tvb_get_guint8(tvb, offset) & 0x03;
    proto_tree_add_item(tree, hf_gtpv2_selec_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(item, "%s", val_to_str(ss_mode, gtpv2_selec_mode_vals, "Unknown"));
}


/*
 * 8.59 Source Identification
 */
static const value_string gtpv2_source_ident_types[] = {
    {0, "Cell ID"},
    {1, "RNC ID"},
    {2, "eNodeB ID(Reserved, used in erlier v of proto.)"},
    {0, NULL}
};
static void
dissect_gtpv2_source_ident(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;
    int          offset=0;
    guint8       source_type;

    /* Octet 5 to 12 Target Cell ID */
    de_cell_id(tvb, tree, pinfo, offset, 8, NULL, 0);
    offset+=8;
    /* Octet 13 Source Type */
    source_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_source_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 14 to (n+4) Source ID */
    switch(source_type){
    case 0:
        /* The Source Type is Cell ID for PS handover from GERAN A/Gb mode. In this case the coding of the Source ID field
         * shall be same as the Octets 3 to 10 of the Cell Identifier IEI in 3GPP TS 48.018 [34].
         */
        de_cell_id(tvb, tree, pinfo, offset, 8, NULL, 0);;
        break;
    case 1:
        /* The Source Type is RNC ID for PS handover from GERAN Iu mode or for inter-RAT handover from UTRAN. In this
         * case the Source ID field shall be encoded as as the Source RNC-ID part of the "Source ID" parameter in 3GPP TS
         * 25.413 [33].
         */
        /* RNC-ID M INTEGER (0..4095) */
        break;
    case 2:
        break;
    default:
        expert_item = proto_tree_add_text(tree, tvb, offset-1, 1, "Unknown source type");
        expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_ERROR, "Unknown source type");
        PROTO_ITEM_SET_GENERATED(expert_item);
        break;
    }

}

 /*
  * 8.60 Bearer Control Mode
  */
static const value_string gtpv2_bearer_control_mode_vals[] = {
    {0, "Selected Bearer Control Mode-'MS_only'"},
    {1, "Selected Bearer Control Mode-'Network_only'"},
    {2, "Selected Bearer Control Mode-'MS/NW'"},
    {0, NULL}
};
static const value_string gtpv2_bearer_control_mode_short_vals[] = {
    {0, "MS_only"},
    {1, "Network_only"},
    {2, "MS/NW"},
    {0, NULL}
};

static void
dissect_gtpv2_bearer_control_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    guint8  bcm;

    proto_tree_add_item(tree, hf_gtpv2_bearer_control_mode, tvb, 0, 1, ENC_BIG_ENDIAN);
    /* Add Bearer Control Mode to tree */
    bcm = tvb_get_guint8(tvb, 0);
    proto_item_append_text(item, "%s", val_to_str(bcm, gtpv2_bearer_control_mode_short_vals, "Unknown"));

}
/*
 * 8.61 Change Reporting Action
 */
static const value_string gtpv2_cng_rep_act_vals[] = {
    {0, "Stop Reporting"},
    {1, "Start Reporting CGI/SAI"},
    {2, "Start Reporting RAI"},
    {3, "Start Reporting TAI"},
    {4, "Start Reporting ECGI"},
    {5, "Start Reporting CGI/SAI and RAI"},
    {6, "Start Reporting TAI and ECGI"},
    {0, NULL}
};

static void
dissect_gtpv2_cng_rep_act(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    guint8  action;

    /* Add Action to tree */
    action = tvb_get_guint8(tvb, 0);
    proto_tree_add_item(tree, hf_gtpv2_cng_rep_act, tvb, 0, 1, ENC_BIG_ENDIAN);

    proto_item_append_text(item, "%s", val_to_str(action, gtpv2_cng_rep_act_vals, "Unknown"));
}
/*
 * 8.62 Fully qualified PDN Connection Set Identifier (FQ-CSID)
 */
static const value_string gtpv2_fq_csid_type_vals[] = {
    {0, "Global unicast IPv4 address"},
    {1, "Global unicast IPv6 address"},
    {2, "4 octets long field"},
    {0, NULL}
};


static void
dissect_gtpv2_fq_csid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;
    int      offset = 0;
    guint8   octet,node_id_type, csids;
    guint32  node_id, node_id_mcc_mnc;

    /* Octet 5 Node-ID Type Number of CSIDs= m */

    octet = tvb_get_guint8(tvb, offset);
    node_id_type = octet >> 4;
    csids = octet & 0x0f;
    proto_tree_add_item(tree, hf_gtpv2_fq_csid_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_fq_csid_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch(node_id_type){
    case 0:
        /* Indicates that Node-ID is a global unicast IPv4 address and p = 9 */
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 1:
        /* Indicates that Node-ID is a global unicast IPv6 address and p = 21 */
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    case 2:
        /* Node-ID is a 4 octets long field with a 32 bit value stored in network order, and p= 9. The coding
         * of the field is specified below:
         * - Most significant 20 bits are the binary encoded value of (MCC * 1000 + MNC).
         * - Least significant 12 bits is a 12 bit integer assigned by an operator to an MME, SGW or PGW. Other values of
         *   Node-ID Type are reserved.
         */
        node_id = tvb_get_ntohl(tvb, offset);
        node_id_mcc_mnc = node_id >> 12;
        node_id = node_id & 0xfff;
        proto_tree_add_text(tree, tvb, offset, 4, "Node-ID: MCC+MNC %u, Id: %u",node_id_mcc_mnc, node_id);
        offset+=4;
        break;
    default:
        expert_item = proto_tree_add_text(tree, tvb, offset-1, 1, "Wrong Node-ID Type %u, should be 0-2(Or tis is a newer spec)",node_id_type);
        expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_ERROR, "Wrong Node-ID Type %u, should be 0-2(Or tis is a newer spec)",node_id_type);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return;
    }

    /* First PDN Connection Set Identifier (CSID)
     * Second PDN Connection Set Identifier (CSID)
     *  :
     * m-th PDN Connection Set Identifier (CSID)
     */
    while ( csids-- ) {
        proto_tree_add_item(tree, hf_gtpv2_fq_csid_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

}

/*
 * 8.63 Channel needed
 */
static void
dissect_gtpv2_channel_needed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    /* The Channel needed shall be coded as depicted in Figure 8.63-1. Channel needed is coded as the IEI part and the value
     * part of the Channel Needed IE defined in 3GPP TS 44.018[28]
     */
    de_rr_chnl_needed(tvb, tree, pinfo, 0, length, NULL, 0);
}

/*
 * 8.64 eMLPP Priority
 * The eMLPP-Priority shall be coded as depicted in Figure 8.64-1. The eMLPP Priority is coded as the value part of the
 * eMLPP-Priority IE defined in 3GPP TS 48.008 [29] (not including 3GPP TS 48.008 IEI and 3GPP TS 48.008 [29]
 * length indicator).
 */
static void
dissect_gtpv2_emlpp_pri(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    be_emlpp_prio(tvb, tree, pinfo, 0, length, NULL, 0);

}

/*
 * 8.65 Node Type
 */
static const value_string gtpv2_node_type_vals[] = {
    {0, "MME"},
    {1, "SGSN"},
    {0, NULL}
};

static void
dissect_gtpv2_node_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    guint8  node_type;

    proto_tree_add_item(tree, hf_gtpv2_node_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    /* Append Node Type to tree */
    node_type = tvb_get_guint8(tvb, 0);
    proto_item_append_text(item, "%s", val_to_str(node_type, gtpv2_node_type_vals, "Unknown"));

}

 /*
  * 8.66 Fully Qualified Domain Name (FQDN)
  */
static void
dissect_gtpv2_fqdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0, name_len, tmp;
    guint8 *fqdn = NULL;

    /* The FQDN field encoding shall be identical to the encoding of
     * a FQDN within a DNS message of section 3.1 of IETF
     * RFC 1035 [31] but excluding the trailing zero byte.
     */
    if (length > 0) {
        name_len = tvb_get_guint8(tvb, offset);

        if (name_len < 0x20) {
            fqdn = tvb_get_ephemeral_string(tvb, offset + 1, length - 1);
            for (;;) {
                if (name_len >= length - 1)
                    break;
                tmp = name_len;
                name_len = name_len + fqdn[tmp] + 1;
                fqdn[tmp] = '.';
            }
        } else {
            fqdn = tvb_get_ephemeral_string(tvb, offset, length);
        }
        proto_tree_add_string(tree, hf_gtpv2_fqdn, tvb, offset, length, fqdn);
        proto_item_append_text(item, "%s", fqdn);
    }
}

/*
 * 8.67 Private Extension
 */
static void
dissect_gtpv2_private_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    tvbuff_t *next_tvb;
    guint16 ext_id;

    /* oct 5 -7 Enterprise ID */
    ext_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_enterprise_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if(dissector_try_uint(gtpv2_priv_ext_dissector_table, ext_id, next_tvb, pinfo, tree))
        return;

    proto_tree_add_text(tree, tvb, offset, length-2, "Proprietary value");
}

/*
 * 8.68 Transaction Identifier (TI)
 */
static void
dissect_gtpv2_ti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{
    /* 5 to (n+4)  Transaction Identifier */
    proto_tree_add_item(tree, hf_gtpv2_ti, tvb, 0, length, ENC_NA);

}

/*
 * 8.69 MBMS Session Duration
 */
static void
dissect_gtpv2_mbms_session_duration(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    int bit_offset = 0;
    guint32 days;
    guint32 hours;
    guint32 seconds;
     
    /* From 3GPP TS 29.061 17.7.7 MBMS-Session-Duration AVP */
    /* Total length is three octets; is it suitable to use tvb_get_bits32() in order to extract 24 bits? */
    /* Bits: ssss ssss ssss ssss sddd dddd where s bits = seconds, d bits = days
     * Will tvb_get_bits32() put the bits in the correct positions? For seconds
     * It should be:     0000 0000 0000 000s ssss ssss ssss ssss (maximum = 131,071, maximum allowed = 86,400)
     * But I fear it is: ssss ssss ssss ssss s000 0000 0000 0000 (maximum = a very big number!)
     * For days
     * It should be:     0000 0000 0000 0000 0000 0000 0ddd dddd */
    seconds = tvb_get_bits32(tvb, bit_offset, 17, ENC_BIG_ENDIAN);
    bit_offset += 17;

    days = tvb_get_bits32(tvb, bit_offset, 7, ENC_BIG_ENDIAN);

    /* Maximum allowed value for days: 18.
     * Maximum allowed value for seconds: 86,400 */
    if((days>18) || (seconds>86400)) {
        proto_tree_add_text(tree, tvb, offset, offset+3, "Days or Seconds out or allowed range");
    } 

    /* The lowest value of this AVP (i.e. all 0:s) is reserved to indicate an indefinite value to denote sessions that are expected to be always-on. */
    if((seconds&days) == 0xffffffff) {
        proto_item_append_text(item, "Indefinite (always-on)");
    } else {
        hours = seconds / 60;
        seconds = seconds % 60;

        proto_item_append_text(item, "%d Day(s) %d Hour(s) %d Second(s)", days, hours, seconds);
    }

    offset += 3;
    if(length > 3)
        proto_tree_add_text(tree, tvb, offset, length-3, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-3));
}

/*
 * 8.70 MBMS Service Area
 */
static void
dissect_gtpv2_mbms_service_area(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    proto_item *sai_item;

    /* 3GPP TS 29.061 17.7.6 MBMS-Service-Area AVP */
    proto_tree_add_item(tree, hf_gtpv2_mbms_service_area_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* A consecutive list of MBMS Service Area Identities follow, each with a length of two octets. */
    while(offset<length) {
        /* 3GPP TS 23.003 15.3 Structure of MBMS SAI */
        guint16 sai = tvb_get_bits16(tvb, 0, 16, ENC_BIG_ENDIAN);
        sai_item = proto_tree_add_item(tree, hf_gtpv2_mbms_service_area_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        /* The value 0 denotes the whole of PLMN as the MBMS Service Area */
        if(sai == 0) {
            proto_item_append_text(sai_item, "Entire PLMN");
        }
        offset += 2;
    }
}

/*
 * 8.71 MBMS Session Identifier
 */
static void
dissect_gtpv2_mbms_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, _U_ guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    /* One octet OctetString. */
    proto_tree_add_item(tree, hf_gtpv2_mbms_session_id, tvb, offset, 1, ENC_NA);

    offset += 1;
    if(length > 1)
        proto_tree_add_text(tree, tvb, offset, length-1, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-1));
}

/* 
 * 8.72 MBMS Flow Identifier
 */
static void
dissect_gtpv2_mbms_flow_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    /* Two octets OctetString. */
    proto_tree_add_item(tree, hf_gtpv2_mbms_flow_id, tvb, offset, 2, ENC_NA);

    offset += 2;
    if(length > 2)
        proto_tree_add_text(tree, tvb, offset, length-2, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-2));
}

/* 
 * 8.73 MBMS IP Multicast Distribution
 */
static const value_string gtpv2_mbms_hc_indicator_vals[] = {
    {0, "Uncompressed header"},
    {1, "Compressed header"},
    {0, NULL}
};

static void
dissect_gtpv2_mbms_ip_mc_dist(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_cteid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_gtpv2_ip_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ip_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* IP Multicast Distribution Address */
    if((tvb_get_guint8(tvb, offset)&0x3f) == 4) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_dist_addrv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else if((tvb_get_guint8(tvb, offset)&0x3f) == 16) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_dist_addrv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    proto_tree_add_item(tree, hf_gtpv2_ip_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_ip_addr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* IP Multicast Source Address */
    if((tvb_get_guint8(tvb, offset)&0x3f) == 4) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_src_addrv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else if((tvb_get_guint8(tvb, offset)&0x3f) == 16) {
        offset += 1;
        proto_tree_add_item(tree, hf_gtpv2_mbms_ip_mc_src_addrv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    proto_tree_add_item(tree, hf_gtpv2_mbms_hc_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    if(length > offset)
        proto_tree_add_text(tree, tvb, offset, length-offset, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-offset));

}

/* 
 * 8.74 MBMS Distribution Acknowledge
 */
static const value_string gtpv2_mbms_dist_indication_vals[] = {
    {0, "No RNCs have accepted IP multicast distribution"},
    {1, "All RNCs have accepted IP multicast distribution"},
    {2, "Some RNCs have accepted IP multicast distribution"},
    {3, "Spare. For future use."},
    {0, NULL}
};

static void
dissect_gtpv2_mbms_dist_ack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_mbms_dist_indication, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    if(length > 1)
        proto_tree_add_text(tree, tvb, offset, length-1, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-1));
}

/*
 * 8.75 User CSG Information (UCI)
 */
static void
dissect_gtpv2_uci(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.76 CSG Information Reporting Action */
static void
dissect_gtpv2_csg_info_rep_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.77 RFSP Index */
static void
dissect_gtpv2_rfsp_index(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.78 CSG ID */
static void
dissect_gtpv2_csg_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.79 CSG Membership Indication (CMI) */
static void
dissect_gtpv2_cmi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.80 Service indicator */
static void
dissect_gtpv2_service_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.81 Detach Type */
static void
dissect_gtpv2_detach_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.82 Local Distinguished Name (LDN) */
static void
dissect_gtpv2_ldn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.83 Node Features */
static void
dissect_gtpv2_node_features(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.84
 * MBMS Time to Data Transfer
 */
static void
dissect_gtpv2_mbms_time_to_data_xfer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    guint8 binary_secs;
    guint16 real_secs;

    binary_secs = tvb_get_guint8(tvb, offset);
    real_secs = (guint16)binary_secs + 1;
    proto_item_append_text(item, "%d second(s)", real_secs);

    offset += 1;
    if(length > 1)
        proto_tree_add_text(tree, tvb, offset, length-1, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-1));
}

/* 8.85 Throttling */
static void
dissect_gtpv2_throttling(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.86 Allocation/Retention Priority (ARP) */
static void
dissect_gtpv2_arp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.87 EPC Timer */
static void
dissect_gtpv2_epc_timer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.88 Signalling Priority Indication */
static void
dissect_gtpv2_sig_prio_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.89 Temporary Mobile Group Identity (TMGI) */
static void
dissect_gtpv2_tmgi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_mbms_service_id, tvb, offset, 3, ENC_NA);
    offset += 3;

    dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
    offset += 3;

    if(length > offset)
        proto_tree_add_text(tree, tvb, offset, length-offset, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-offset));
}

/*
 * 8.90 Additional MM context for SRVCC
 * 3GPP TS 29.274 Figure 8.90-1
 */
static void
dissect_gtpv2_add_mm_cont_for_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;
    proto_item *ms_cm_item;
    proto_tree *ms_cm_tree;
    guint8 elm_len;

    /* Length of Mobile Station Classmark 2 */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    ms_cm_item = proto_tree_add_text(tree, tvb, offset, elm_len, "Mobile Station Classmark 2  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_cm_tree = proto_item_add_subtree(ms_cm_item, ett_gtpv2_ms_mark);
    /* Mobile Station Classmark 2 */
    de_ms_cm_2(tvb, ms_cm_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset + elm_len;

    /* Length of Mobile Station Classmark 3 */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_ms_classmark3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    ms_cm_item = proto_tree_add_text(tree, tvb, offset, elm_len, "Mobile Station Classmark3  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_cm_tree = proto_item_add_subtree(ms_cm_item, ett_gtpv2_ms_mark);
    /* Mobile Station Classmark 3 */
    de_ms_cm_3(tvb, ms_cm_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset + elm_len;

    /* Length of Supported Codec List */
    elm_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_len_supp_codec_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    ms_cm_item = proto_tree_add_text(tree, tvb, offset, elm_len, "Supported Codec List  %s", tvb_bytes_to_str(tvb, offset, elm_len));
    ms_cm_tree = proto_item_add_subtree(ms_cm_item, ett_gtpv2_supp_codec_list);
    /* Supported Codec List */
    de_sup_codec_list(tvb, ms_cm_tree, pinfo, offset, elm_len, NULL, 0);
    offset = offset + elm_len;

    if(length > offset)
        proto_tree_add_text(tree, tvb, offset, length-offset, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-offset));
}

/* 8.91 Additional flags for SRVCC */
static void
dissect_gtpv2_add_flags_for_srvcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_add_flags_for_srvcc_ics, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtpv2_vsrvcc_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(length > 1)
        proto_tree_add_text(tree, tvb, offset, length-1, "Spare: %s", tvb_bytes_to_str(tvb, offset, length-1));
}

/* 8.92 Max MBR/APN-AMBR (MMBR) */
static void
dissect_gtpv2_mmbr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.93 MDT Configuration */
static void
dissect_gtpv2_mdt_config(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}

/* 8.94 Additional Protocol Configuration Options (APCO) */
static void
dissect_gtpv2_apco(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    proto_item *expert_item;

    expert_item = proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
    expert_add_info_format(pinfo, expert_item, PI_PROTOCOL, PI_NOTE, "IE data not dissected yet");
    PROTO_ITEM_SET_GENERATED(expert_item);
}


typedef struct _gtpv2_ie {
    int ie_type;
    void (*decode) (tvbuff_t *, packet_info *, proto_tree *, proto_item *, guint16, guint8, guint8);
} gtpv2_ie_t;

static const gtpv2_ie_t gtpv2_ies[] = {
    {GTPV2_IE_IMSI, dissect_gtpv2_imsi},                                   /* 1, Internal Mobile Subscriber Identity (IMSI) */
    {GTPV2_IE_CAUSE, dissect_gtpv2_cause},                                 /* 2, Cause (without embedded offending IE) 8.4 */
    {GTPV2_REC_REST_CNT, dissect_gtpv2_recovery},                          /* 3, Recovery (Restart Counter) 8.5 */
                                                                           /* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
    /*Start SRVCC Messages 3GPP TS 29.280 */
    {GTPV2_IE_STN_SR, dissect_gtpv2_stn_sr},                               /* 51 51 STN-SR */
    {GTPV2_IE_SRC_TGT_TRANS_CON, dissect_gtpv2_src_tgt_trans_con},         /* 52 Source to Target Transparent Container */
    {GTPV2_IE_TGT_SRC_TRANS_CON , dissect_gtpv2_tgt_src_trans_con},        /* 53 Target to Source Transparent Container */
    {GTPV2_IE_MM_CON_EUTRAN_SRVCC, dissect_gtpv2_mm_con_eutran_srvcc},     /* 54 MM Context for E-UTRAN SRVCC */
    {GTPV2_IE_MM_CON_UTRAN_SRVCC, dissect_gtpv2_mm_con_utran_srvcc},       /* 55 MM Context for UTRAN SRVCC */
    {GTPV2_IE_SRVCC_CAUSE, dissect_gtpv2_srvcc_cause},                     /* 56 SRVCC Cause */
    {GTPV2_IE_TGT_RNC_ID, dissect_gtpv2_tgt_rnc_id},                       /* 57 Target RNC ID */
    {GTPV2_IE_TGT_GLOGAL_CELL_ID, dissect_gtpv2_tgt_global_cell_id},       /* 58 Target Global Cell ID */
    {GTPV2_IE_TEID_C, dissect_gtpv2_teid_c},                               /* 59 TEID-C */
    {GTPV2_IE_SV_FLAGS, dissect_gtpv2_sv_flags},                           /* 60 Sv Flags */
    {GTPV2_IE_SAI, dissect_gtpv2_sai},                                     /* 61 Service Area Identifie */
                                                                           /* 61-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */

    {GTPV2_APN, dissect_gtpv2_apn},                                        /* 71, Access Point Name (APN) 8.6 */
    {GTPV2_AMBR, dissect_gtpv2_ambr},                                      /* 72, Aggregate Maximum Bit Rate (AMBR) */
    {GTPV2_EBI, dissect_gtpv2_ebi},                                        /* 73, EPS Bearer ID (EBI)  8.8 */
    {GTPV2_IP_ADDRESS, dissect_gtpv2_ip_address},                          /* 74, IP Address */
    {GTPV2_MEI, dissect_gtpv2_mei},                                        /* 74, Mobile Equipment Identity */
    {GTPV2_IE_MSISDN, dissect_gtpv2_msisdn},                               /* 76, MSISDN 8.11 */
    {GTPV2_INDICATION, dissect_gtpv2_ind},                                 /* 77 Indication 8.12 */
    {GTPV2_PCO, dissect_gtpv2_pco},                                        /* 78 Protocol Configuration Options (PCO) 8.13 */
    {GTPV2_PAA, dissect_gtpv2_paa},                                        /* 79 PDN Address Allocation (PAA) 8.14 */
    {GTPV2_BEARER_QOS,dissect_gtpv2_bearer_qos},                           /* 80 Bearer Level Quality of Service (Bearer QoS) 8.15 */
    {GTPV2_IE_FLOW_QOS, dissect_gtpv2_flow_qos},                           /* 81 Flow Quality of Service (Flow QoS) 8.16 */
    {GTPV2_IE_RAT_TYPE, dissect_gtpv2_rat_type},                           /* 82, RAT Type  8.17 */
    {GTPV2_IE_SERV_NET, dissect_gtpv2_serv_net},                           /* 83, Serving Network 8.18 */
    {GTPV2_IE_BEARER_TFT, dissect_gtpv2_bearer_tft},                       /* 84, Bearer TFT 8.19 */
    {GTPV2_IE_TAD, dissect_gtpv2_tad},                                     /* 85, Traffic Aggregate Description 8.20 */
    {GTPV2_IE_ULI, dissect_gtpv2_uli},                                     /* 86, User Location Info (ULI) 8.22 */
    {GTPV2_IE_F_TEID, dissect_gtpv2_f_teid},                               /* 87, Fully Qualified Tunnel Endpoint Identifier (F-TEID) 8.23 */
    {GTPV2_IE_TMSI, dissect_gtpv2_tmsi},                                   /* 88, TMSI 8.23 */
    {GTPV2_IE_GLOBAL_CNID, dissect_gtpv2_g_cn_id},                         /* 89, Global CN-Id 8.25 */
    {GTPV2_IE_S103PDF, dissect_gtpv2_s103pdf},                             /* 90, S103 PDN Data Forwarding Info (S103PDF) 8.25 */
    {GTPV2_IE_S1UDF, dissect_gtpv2_s1udf},                                 /* 91, S1-U Data Forwarding (S1UDF) 8.26 */
    {GTPV2_IE_DEL_VAL, dissect_gtpv2_delay_value},                         /* 92, Delay Value 8.29 */
    {GTPV2_IE_BEARER_CTX,dissect_gtpv2_bearer_ctx},                        /* 93, Bearer Context  8.31 */
    {GTPV2_IE_CHAR_ID, dissect_gtpv2_charging_id},                         /* 94, Charging Id */
    {GTPV2_IE_CHAR_CHAR, dissect_gtpv2_char_char},                         /* 95 Charging Characteristic */
    {GTPV2_IE_TRA_INFO, dissect_gtpv2_tra_info},                           /* 96, Trace Information 8.31 */
    {GTPV2_BEARER_FLAG, dissect_gtpv2_bearer_flag},                        /* 97, Bearer Flag */
                                                                           /* 98, Void 8.33 */
    {GTPV2_IE_PDN_TYPE, dissect_gtpv2_pdn_type},                           /* 99, PDN Type */
    {GTPV2_IE_PTI, dissect_gtpv2_pti},                                     /* 100, Procedure Transaction Id */
    {GTPV2_IE_DRX_PARAM, dissect_gtpv2_drx_param},                         /* 101, DRX Parameter 8.36 */
    {GTPV2_IE_UE_NET_CAPABILITY, dissect_gtpv2_ue_net_capability},         /* 102, UE network capability 8.37 */
    {GTPV2_IE_MM_CONTEXT_GSM_T, dissect_gtpv2_mm_context_gsm_t},           /* 103, MM Context 8.38 GSM Key and Triplets */
    {GTPV2_IE_MM_CONTEXT_UTMS_CQ, dissect_gtpv2_mm_context_utms_cq},       /* 104, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_GSM_CQ, dissect_gtpv2_mm_context_gsm_cq},         /* 105, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_UTMS_Q, dissect_gtpv2_mm_context_utms_q},         /* 106, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_EPS_QQ, dissect_gtpv2_mm_context_eps_qq},         /* 107, MM Context 8.38 */
    {GTPV2_IE_MM_CONTEXT_UTMS_QQ, dissect_gtpv2_mm_context_utms_qq},       /* 108, MM Context 8.38 */
    {GTPV2_IE_PDN_CONNECTION, dissect_gtpv2_PDN_conn},                     /* 109, PDN Connection */
    {GTPV2_IE_PDN_NUMBERS, dissect_gtpv2_pdn_numbers},                     /* 110, PDN Numbers 8.40 */
    {GTPV2_IE_P_TMSI, dissect_gtpv2_p_tmsi},                               /* 111, P-TMSI 8.41 */
    {GTPV2_IE_P_TMSI_SIG, dissect_gtpv2_p_tmsi_sig},                       /* 112, P-TMSI Signature 8.42 */
    {GTPV2_IE_HOP_COUNTER, dissect_gtpv2_hop_counter},                     /* 113, Hop Counter 8.43 */
    {GTPV2_IE_UE_TIME_ZONE, dissect_gtpv2_ue_time_zone},                   /* 114, UE Time Zone */
    {GTPV2_IE_TRACE_REFERENCE, dissect_gtpv2_trace_reference},             /* 115, Trace Reference 8.45 */
    {GTPV2_IE_COMPLETE_REQUEST_MSG, dissect_complete_request_msg},         /* 116, Complete Request message 8.46 */
    {GTPV2_IE_GUTI, dissect_gtpv2_guti},                                   /* 117, GUTI 8.47 */
    {GTPV2_IE_F_CONTAINER, dissect_gtpv2_F_container},                     /* 118, Fully Qualified Container (F-Container) */
    {GTPV2_IE_F_CAUSE, dissect_gtpv2_F_cause},                             /* 119, Fully Qualified Cause (F-Cause) */
    {GTPV2_IE_SEL_PLMN_ID, dissect_gtpv2_sel_plmn_id},                     /* 120, Selected PLMN ID 8.50 */
    {GTPV2_IE_TARGET_ID, dissect_gtpv2_target_id},                         /* 121, Target Identification */
                                                                           /* 122, Void 8.52 */
    {GTPV2_IE_PKT_FLOW_ID, dissect_gtpv2_pkt_flow_id},                     /* 123, Packet Flow ID 8.53 */
    {GTPV2_IE_RAB_CONTEXT, dissect_gtpv2_rab_context},                     /* 124, RAB Context 8.54 */
    {GTPV2_IE_S_RNC_PDCP_CTX_INFO, dissect_gtpv2_s_rnc_pdcp_ctx_info},     /* 125, Source RNC PDCP context info 8.55 */
    {GTPV2_IE_UDP_S_PORT_NR, dissect_udp_s_port_nr},                       /* 126, UDP Source Port Number 8.56 */
    {GTPV2_IE_APN_RESTRICTION, dissect_gtpv2_apn_rest},                    /* 127, APN Restriction */
    {GTPV2_IE_SEL_MODE,dissect_gtpv2_selec_mode},                          /* 128, Selection Mode */
    {GTPV2_IE_SOURCE_IDENT, dissect_gtpv2_source_ident},                   /* 129, Source Identification 8.59 */
    {GTPV2_IE_BEARER_CONTROL_MODE,dissect_gtpv2_bearer_control_mode},      /* 130, Bearer Control Mode */
    {GTPV2_IE_CNG_REP_ACT ,dissect_gtpv2_cng_rep_act},                     /* 131, Change Reporting Action 8.61 */
    {GTPV2_IE_FQ_CSID, dissect_gtpv2_fq_csid},                             /* 132, Fully Qualified PDN Connection Set Identifier (FQ-CSID) 8.62 */
    {GTPV2_IE_CHANNEL_NEEDED, dissect_gtpv2_channel_needed},               /* 133, Channel Needed 8.63 */
    {GTPV2_IE_EMLPP_PRI, dissect_gtpv2_emlpp_pri},                         /* 134, eMLPP Priority 8.64 */
    {GTPV2_IE_NODE_TYPE ,dissect_gtpv2_node_type},                         /* 135, Node Type 8.65 */
    {GTPV2_IE_FQDN, dissect_gtpv2_fqdn},                                   /* 136, 8.66 Fully Qualified Domain Name (FQDN) */
    {GTPV2_IE_TI, dissect_gtpv2_ti},                                       /* 137, 8.68 Transaction Identifier (TI) */
    {GTPV2_IE_MBMS_SESSION_DURATION, dissect_gtpv2_mbms_session_duration}, /* 138, 8.69 MBMS Session Duration */
    {GTPV2_IE_MBMS_SERVICE_AREA, dissect_gtpv2_mbms_service_area},         /* 139, 8.70 MBMS Service Area */
    {GTPV2_IE_MBMS_SESSION_ID, dissect_gtpv2_mbms_session_id},             /* 140, 8.71 MBMS Session Identifier */
    {GTPV2_IE_MBMS_FLOW_ID, dissect_gtpv2_mbms_flow_id},                   /* 141, 8.72 MBMS Flow Identifier */
    {GTPV2_IE_MBMS_IP_MC_DIST, dissect_gtpv2_mbms_ip_mc_dist},             /* 142, 8.73 MBMS IP Multicast Distribution */
    {GTPV2_IE_MBMS_DIST_ACK, dissect_gtpv2_mbms_dist_ack},                 /* 143, 8.74 MBMS Distribution Acknowledge */
    {GTPV2_IE_RFSP_INDEX, dissect_gtpv2_rfsp_index},                       /* 144, 8.77 RFSP Index */
    {GTPV2_IE_UCI, dissect_gtpv2_uci},                                     /* 145, 8.75 User CSG Information (UCI) */
    {GTPV2_IE_CSG_INFO_REP_ACTION, dissect_gtpv2_csg_info_rep_action},     /* 146, 8.76 CSG Information Reporting Action */
    {GTPV2_IE_CSG_ID, dissect_gtpv2_csg_id},                               /* 147, 8.78 CSG ID */
    {GTPV2_IE_CMI, dissect_gtpv2_cmi},                                     /* 148, 8.79 CSG Membership Indication (CMI) */
    {GTPV2_IE_SERVICE_INDICATOR, dissect_gtpv2_service_indicator},         /* 149, 8.80 Service indicator */
    {GTPV2_IE_DETACH_TYPE, dissect_gtpv2_detach_type},                     /* 150, 8.81 Detach Type */
    {GTPV2_IE_LDN, dissect_gtpv2_ldn},                                     /* 151, 8.82 Local Distinguished Name (LDN) */
    {GTPV2_IE_NODE_FEATURES, dissect_gtpv2_node_features},                 /* 152, 8.83 Node Features */
    {GTPV2_IE_MBMS_TIME_TO_DATA_XFER, dissect_gtpv2_mbms_time_to_data_xfer}, /* 153, 8.84 MBMS Time to Data Transfer */
    {GTPV2_IE_THROTTLING, dissect_gtpv2_throttling},                       /* 154, 8.85 Throttling */
    {GTPV2_IE_ARP, dissect_gtpv2_arp},                                     /* 155, 8.86 Allocation/Retention Priority (ARP) */
    {GTPV2_IE_EPC_TIMER, dissect_gtpv2_epc_timer},                         /* 156, 8.87 EPC Timer */
    {GTPV2_IE_SIG_PRIO_IND, dissect_gtpv2_sig_prio_ind},                   /* 157, 8.88 Signalling Priority Indication */
    {GTPV2_IE_TMGI, dissect_gtpv2_tmgi},                                   /* 158, 8.89 Temporary Mobile Group Identity (TMGI) */
    {GTPV2_IE_ADD_MM_CONT_FOR_SRVCC, dissect_gtpv2_add_mm_cont_for_srvcc}, /* 159, 8.90 Additional MM context for SRVCC */
    {GTPV2_IE_ADD_FLAGS_FOR_SRVCC, dissect_gtpv2_add_flags_for_srvcc},     /* 160, 8.91 Additional flags for SRVCC */
    {GTPV2_IE_MMBR, dissect_gtpv2_mmbr},                                   /* 161, 8.92 Max MBR/APN-AMBR (MMBR) */
    {GTPV2_IE_MDT_CONFIG, dissect_gtpv2_mdt_config},                       /* 162, 8.93 MDT Configuration */
    {GTPV2_IE_APCO, dissect_gtpv2_apco},                                   /* 163, 8.94 Additional Protocol Configuration Options (APCO) */
                                                    /* 164-254 Spare. For future use. FFS */
    {GTPV2_IE_PRIVATE_EXT,dissect_gtpv2_private_ext},

    {0, dissect_gtpv2_unknown}
};



static void
dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint offset, guint8 message_type)
{
    proto_tree *ie_tree;
    proto_item *ti;
    tvbuff_t *ie_tvb;
    guint8 type, instance;
    guint16 length;
    int i;
    /*
     * Octets   8   7   6   5       4   3   2   1
     *  1       Type
     *  2-3     Length = n
     *  4       CR          Spare   Instance
     * 5-(n+4)  IE specific data
     */
    while(offset < (gint)tvb_reported_length(tvb)){
        /* Get the type and length */
        type = tvb_get_guint8(tvb,offset);
        length = tvb_get_ntohs(tvb, offset+1);
        ti = proto_tree_add_text(tree, tvb, offset, 4 + length, "%s : ", val_to_str(type, gtpv2_element_type_vals, "Unknown"));
        ie_tree = proto_item_add_subtree(ti, ett_gtpv2_ie);
        /* Octet 1 */
        proto_tree_add_item(ie_tree, hf_gtpv2_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /*Octet 2 - 3 */
        proto_tree_add_item(ie_tree, hf_gtpv2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* CR Spare Instance Octet 4*/
        proto_tree_add_item(ie_tree, hf_gtpv2_cr, tvb, offset, 1, ENC_BIG_ENDIAN);

        instance = tvb_get_guint8(tvb,offset)& 0x0f;
        proto_tree_add_item(ie_tree, hf_gtpv2_instance, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* TODO: call IE dissector here */
        if(type==GTPV2_IE_RESERVED){
            /* Treat IE type zero specal as type zero is used to end the loop in the else branch */
            proto_tree_add_text(ie_tree, tvb, offset, length, "IE type Zero is Reserved and should not be used");
        }else{
            i = -1;
            /* Loop over the IE dissector list to se if we find an entry, the last entry will have ie_type=0 breaking the loop */
            while (gtpv2_ies[++i].ie_type){
                if (gtpv2_ies[i].ie_type == type)
                    break;
            }
            /* Just give the IE dissector the IE */
            ie_tvb = tvb_new_subset_remaining(tvb, offset);
            (*gtpv2_ies[i].decode) (ie_tvb, pinfo , ie_tree, ti, length, message_type, instance);
        }

        offset = offset + length;
    }
}

static void
dissect_gtpv2(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_tree *gtpv2_tree, *flags_tree;
    proto_item *ti, *tf;
    guint8 message_type, t_flag, p_flag;
    int offset = 0;
    guint16 msg_length;


    /* Currently we get called from the GTP dissector no need to check the version */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTPv2");
    col_clear(pinfo->cinfo, COL_INFO);

    /* message type is in octet 2 */
    message_type = tvb_get_guint8(tvb,1);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, gtpv2_message_type_vals, "Unknown"));


    proto_tree_add_item(tree, proto_gtpv2, tvb, offset, -1, ENC_NA);
    p_flag = (tvb_get_guint8(tvb,offset) & 0x10)>>4;
    msg_length = tvb_get_ntohs(tvb, offset+2);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, -1, "%s", val_to_str(message_type, gtpv2_message_type_vals, "Unknown"));
        gtpv2_tree = proto_item_add_subtree(ti, ett_gtpv2);

        /* Control Plane GTP uses a variable length header. Control Plane GTP header
         * length shall be a multiple of 4 octets.
         * Figure 5.1-1 illustrates the format of the GTPv2-C Header.
         * Bits       8  7  6   5       4   3       2       1
         * Octets   1 Version   P       T   Spare   Spare   Spare
         *          2 Message Type
         *          3 Message Length (1st Octet)
         *          4 Message Length (2nd Octet)
         *  m-k(m+3)    If T flag is set to 1, then TEID shall be placed into octets 5-8.
         *              Otherwise, TEID field is not present at all.
         *  n-(n+2)   Sequence Number
         * (n+3)      Spare
         * Figure 5.1-1: General format of GTPv2 Header for Control Plane
         */
        tf = proto_tree_add_item(gtpv2_tree, hf_gtpv2_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        flags_tree = proto_item_add_subtree(tf, ett_gtpv2_flags);

        /* Octet 1 */
        t_flag = (tvb_get_guint8(tvb,offset) & 0x08)>>3;
        proto_tree_add_item(flags_tree, hf_gtpv2_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_gtpv2_p, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_gtpv2_t, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* Octet 2 */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* Octet 3 - 4 */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_msg_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        if(t_flag){
            /* Tunnel Endpoint Identifier 4 octets */
            proto_tree_add_item(gtpv2_tree, hf_gtpv2_teid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
        }
        /* Sequence Number 3 octets */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_seq, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;

        /* Spare 1 octet */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        dissect_gtpv2_ie_common(tvb, pinfo, gtpv2_tree, offset, message_type);
    }
    /* Bit 5 represents a "P" flag. If the "P" flag is set to "0", 
     * no piggybacked message shall be present. If the "P" flag is set to "1",
     * then another GTPv2-C message with its own header and body shall be present 
     * at the end of the current message.
     */
    if(p_flag){
        tvbuff_t   *new_tvb;
        /* Octets 3 to 4 represent the Length field. This field shall indicate the length of the message in octets excluding the
         * mandatory part of the GTP-C header (the first 4 octets).
         */
        new_tvb = tvb_new_subset_remaining(tvb,msg_length+4);
        dissect_gtpv2(new_tvb, pinfo, tree);
    }


}

void proto_register_gtpv2(void)
{
    static hf_register_info hf_gtpv2[] = {
        { &hf_gtpv2_reserved,
          {"Reserved bit(s)", "gtpv2.reserved",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "Reserved", HFILL }
        },
        { &hf_gtpv2_spare_half_octet,
          {"Spare half octet", "gtpv2.spare_half_octet",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_gtpv2_spare_bits,
          {"Spare bit(s)", "gtpv2.spare_bits",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        {&hf_gtpv2_flags,
         {"Flags", "gtpv2.flags",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_version,
         {"Version", "gtpv2.version",
          FT_UINT8, BASE_DEC, NULL, 0xe0,
          NULL, HFILL}
        },
        {&hf_gtpv2_p,
         {"Piggybacking flag (P)", "gtpv2.p",
          FT_UINT8, BASE_DEC, NULL, 0x10,
          "If Piggybacked message is present or not", HFILL}
        },
        { &hf_gtpv2_t,
          {"TEID flag (T)", "gtpv2.t",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "If TEID field is present or not", HFILL}
        },
        { &hf_gtpv2_message_type,
          {"Message Type", "gtpv2.message_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_message_type_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_msg_length,
          {"Message Length", "gtpv2.msg_lengt",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_teid,
          {"Tunnel Endpoint Identifier", "gtpv2.teid",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "TEID", HFILL}
        },
        { &hf_gtpv2_seq,
          {"Sequence Number", "gtpv2.seq",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           "SEQ", HFILL}
        },
        { &hf_gtpv2_spare,
          {"Spare", "gtpv2.spare",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ie,
          {"IE Type", "gtpv2.ie_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_element_type_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ie_len,
          {"IE Length", "gtpv2.ie_len",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "length of the information element excluding the first four octets", HFILL}
        },
        { &hf_gtpv2_cr,
          {"CR flag", "gtpv2.cr",
           FT_UINT8, BASE_DEC, NULL, 0xf0,/* SRVCC */
           NULL, HFILL}
        },
        { &hf_gtpv2_instance,
          {"Instance", "gtpv2.instance",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        {&hf_gtpv2_imsi,
         {"IMSI(International Mobile Subscriber Identity number)", "gtpv2.imsi",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        { &hf_gtpv2_ipv4_addr,
          {"IPv4 Address", "gtpv2.ipv4_addr",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause,
          {"Cause", "gtpv2.cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_vals_ext, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_cause_cs,
         {"CS (Cause Source)","gtpv2.cs",
          FT_BOOLEAN, 8, TFS(&gtpv2_cause_cs), 0x01,
          NULL, HFILL}
        },
        { &hf_gtpv2_cause_bce,
          {"BCE (Bearer Context IE Error)","gtpv2.bce",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause_pce,
          {"PCE (PDN Connection IE Error)","gtpv2.pce",
           FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause_off_ie_t,
          {"Type of the offending IE", "gtpv2.cause_off_ie_t",
           FT_UINT8, BASE_DEC, VALS(gtpv2_element_type_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_rec,
          {"Restart Counter", "gtpv2.rec",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
/*Start SRVCC Messages*/
        { &hf_gtpv2_stn_sr,
          {"STN-SR", "gtpv2.stn_sr",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_trans_con,
          {"Length of the Transparent Container", "gtpv2.len_trans_con",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_eksi,
          {"eKSI", "gtpv2.eksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_ck,
          {"CK", "gtpv2.ck",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ik,
          {"IK", "gtpv2.ik",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_ms_classmark2,
          {"Length of Mobile Station Classmark2", "gtpv2.len_ms_classmark2",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_ms_classmark3,
          {"Length of Mobile Station Classmark3", "gtpv2.len_ms_classmark3",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_len_supp_codec_list,
          {"Length of Supported Codec List", "gtpv2.len_supp_codec_list",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ksi,
          {"KSI'cs", "gtpv2.ksi",
           FT_UINT8, BASE_DEC, NULL, 0x0F,
           NULL, HFILL}
        },
/*        { &hf_gtpv2_kc,
          {"Kc'", "gtpv2.kc",
          FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
          },*/
        { &hf_gtpv2_cksn,
          {"CKSN'", "gtpv2.cksn",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_srvcc_cause,
          {"SRVCC Cause", "gtpv2.srvcc_cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_srvcc_cause_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_rnc_id,
          {"RNC ID", "gtpv2.rnc_id",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_lac,
          { "Location Area Code (LAC)","gtpv2.lac",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gtpv2_sac,
          { "Service Area Code (SAC)","gtpv2.sac",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gtpv2_tgt_g_cell_id,
          {"Cell ID", "gtpv2.tgt_g_cell_id",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_teid_c,
         {"Tunnel Endpoint Identifier for Control Plane(TEID-C)", "gtpv2.teid_c",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_sv_sti,
         {"STI (Session Transfer Indicator)", "gtpv2.sv_sti",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_sv_ics,
         {"ICS (IMS Centralized Service)", "gtpv2.sv_ics",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_sv_emind,
         {"EmInd(Emergency Indicator)", "gtpv2.sv_emind",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },

/*End SRVCC Messages*/
        {&hf_gtpv2_apn,
         {"APN (Access Point Name)", "gtpv2.apn",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ambr_up,
         {"AMBR Uplink (Aggregate Maximum Bit Rate for Uplink)", "gtpv2.ambr_up",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ambr_down,
         {"AMBR Downlink(Aggregate Maximum Bit Rate for Downlink)", "gtpv2.ambr_down",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_ebi,
         {"EPS Bearer ID (EBI)", "gtpv2.ebi",
          FT_UINT8, BASE_DEC, NULL, 0x0f,
          NULL, HFILL}
        },
        { &hf_gtpv2_ip_address_ipv4,
          {"IP address IPv4", "gtpv2.ip_address_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_ip_address_ipv6,
          {"IP address IPv6", "gtpv2.ip_address_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_mei,
         {"MEI(Mobile Equipment Identity)", "gtpv2.mei",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        { &hf_gtpv2_pdn_numbers_nsapi,
          {"NSAPI", "gtpv2.pdn_numbers_nsapi",
           FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL}
        },
        { &hf_gtpv2_p_tmsi,
          {"Packet TMSI (P-TMSI)", "gtpv2.p_tmsi",
           FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_gtpv2_p_tmsi_sig,
          {"P-TMSI Signature", "gtpv2.p_tmsi_sig",
           FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_gtpv2_daf,
         {"DAF (Dual Address Bearer Flag)", "gtpv2.daf",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_dtf,
         {"DTF (Direct Tunnel Flag)","gtpv2.dtf",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_hi,
         {"HI (Handover Indication)", "gtpv2.hi",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_dfi,
         {"DFI (Direct Forwarding Indication)", "gtpv2.dfi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_oi,
         {"OI (Operation Indication)","gtpv2.oi",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_isrsi,
         {"ISRSI (Idle mode Signalling Reduction Supported Indication)", "gtpv2.isrsi",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_israi,
         {"ISRAI (Idle mode Signalling Reduction Activation Indication)",    "gtpv2.israi",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_sgwci,
         {"SGWCI (SGW Change Indication)", "gtpv2.sgwci",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_sqci,
         {"SQCI (Subscribed QoS Change Indication", "gtpv2.sqci",
          FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
        },
        {&hf_gtpv2_uimsi,
         {"UIMSI (Unauthenticated IMSI)", "gtpv2.uimsi",
          FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}
        },
        {&hf_gtpv2_cfsi,
         {"CFSI (Change F-TEID support indication)", "gtpv2.cfsi",
          FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}
        },
        {&hf_gtpv2_crsi,
         {"CRSI (Change Reporting support indication):", "gtpv2.crsi",
          FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}
        },
        {&hf_gtpv2_ps,
         {"PS (Piggybacking Supported).)", "gtpv2.ps",
          FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}
        },
        {&hf_gtpv2_pt,
         {"PT (Protocol Type)", "gtpv2.pt",
          FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL}
        },
        {&hf_gtpv2_si,
         {"SI (Scope Indication)", "gtpv2.si",
          FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL}
        },
        {&hf_gtpv2_msv,
         {"MSV (MS Validated)", "gtpv2.msv",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        {&hf_gtpv2_ccrsi,
         {"CCRSI (CSG Change Reporting support indication)", "gtpv2.ccrsi",
          FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL}
        },
        { &hf_gtpv2_pdn_type,
          {"PDN Type", "gtpv2.pdn_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_pdn_type_vals), 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info,
          {"Trace ID","gtpv2.tra_info",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_msc_momt_calls,
          {"MO and MT calls","gtpv2.tra_info_msc_momt_calls",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_momt_sms,
          {"MO and MT SMS","gtpv2.tra_info_msc_momt_sms",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_lu_imsi_ad,
          {"LU, IMSI attach, IMSI detach","gtpv2.tra_info_msc_lu_imsi_ad",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_handovers,
          {"Handovers","gtpv2.tra_info_msc_handovers",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_msc_ss,
          {"SS","gtpv2.tra_info_msc_ss",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_mgw_context,
          {"Context","gtpv2.tra_info_mgw_context",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_pdp_context,
          {"PDP context","gtpv2.tra_info_sgsn_pdp_context",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_momt_sms,
          {"MO and MT SMS","gtpv2.tra_info_sgsn_momt_sms",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_rau_gprs_ad,
          {"RAU, GPRS attach, GPRS detach","gtpv2.tra_info_sgsn_rau_gprs_ad",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_mbms,
          {"MBMS Context","gtpv2.tra_into_sgsn_mbms",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_sgsn_reserved,
          {"Reserved","gtpv2.",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_ggsn_pdp,
          {"PDP Cpntext","gtpv2.tra_info_ggsn_pdp",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_ggsn_mbms,
          {"MBMS Context","gtpv2.tra_info_ggsn_mbms",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_bm_sc,
          {"MBMS Multicast service activation","gtpv2.tra_info_bm_sc",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "BM-SC", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_ss,
          {"Session setup","gtpv2.tra_info_mme_sgw_ss",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_sr,
          {"Service Request","gtpv2.tra_info_mme_sgw_sr",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_mme_sgw_iataud,
          {"Initial Attach, Tracking area update, Detach","gtpv2.tra_info_mme_sgw_iataud",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_msc_s,
          {"MSC-S","gtpv2.tra_info_lne_msc_s",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_mgw,
          {"MGW","gtpv2.tra_info_lne_mgw",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_sgsn,
          {"SGSN","gtpv2.tra_info_lne_sgsn",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_ggsn,
          {"GGSN","gtpv2.tra_info_lne_ggsn",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_rnc,
          {"RNC","gtpv2.tra_info_lne_rnc",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_bm_sc,
          {"BM-SC","gtpv2.tra_info_lne_bm_sc",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_mme,
          {"MME","gtpv2.tra_info_lne_mme",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_sgw,
          {"SGW","gtpv2.tra_info_lne_sgw",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_pdn_gw,
          {"PDN GW","gtpv2.tra_info_lne_pdn_gw",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_lne_enb,
          {"eNB","gtpv2.tra_info_lne_enb",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "List of NE Types", HFILL}
        },
        { &hf_gtpv2_tra_info_tdl,
          {"Trace Depth Length","gtpv2.tra_info_tdl",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_a,
          {"A","gtpv2.tra_info_lmsc_a",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_lu,
          {"Iu","gtpv2.tra_info_lmsc_lu",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_mc,
          {"Mc","gtpv2.tra_info_lmsc_mc",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_g,
          {"MAP-G","gtpv2.tra_info_lmsc_map_g",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_b,
          {"MAP-B","gtpv2.tra_info_lmsc_map_b",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_e,
          {"MAP-E","gtpv2.tra_info_lmsc_map_e",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_f,
          {"MAP-F","gtpv2.tra_info_lmsc_map_f",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_cap,
          {"CAP","gtpv2.tra_info_lmsc_cap",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_d,
          {"MAP-D","gtpv2.tra_info_lmsc_map_d",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmsc_map_c,
          {"MAP-C","gtpv2.tra_info_lmsc_map_c",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MSC Server", HFILL}
        },
        { &hf_gtpv2_tra_info_lmgw_mc,
          {"Mc","gtpv2.tra_info_lmgw_mc",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lmgw_nb_up,
          {"Nb-UP","gtpv2.tra_info_lmgw_nb_up",
           FT_UINT8, BASE_DEC, NULL, 0x2,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lmgw_lu_up,
          {"Iu-UP","gtpv2.tra_info_lmgw_lu_up",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_gb,
          {"Gb","gtpv2.tra_info_lsgsn_gb",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_lu,
          {"Iu","gtpv2.tra_info_lsgsn_lu",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_gn,
          {"Gn","gtpv2.tra_info_lsgsn_gn",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_map_gr,
          {"MAP-Gr","gtpv2.tra_info_lsgsn_map_gr",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_map_gd,
          {"MAP-Gd","gtpv2.tra_info_lsgsn_map_gd",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_map_gf,
          {"MAP-Gf","gtpv2.tra_info_lsgsn_map_gf",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_gs,
          {"Gs","gtpv2.tra_info_lsgsn_gs",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgsn_ge,
          {"Ge","gtpv2.tra_info_lsgsn_ge",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "SGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lggsn_gn,
          {"Gn","gtpv2.tra_info_lggsn_gn",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lggsn_gi,
          {"Gi","gtpv2.tra_info_lggsn_gi",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lggsn_gmb,
          {"Gmb","gtpv2.tra_info_lggsn_gmb",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "GGSN", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_lu,
          {"Iu","gtpv2.tra_info_lrnc_lu",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_lur,
          {"Iur","gtpv2.tra_info_lrnc_lur",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_lub,
          {"Iub","gtpv2.tra_info_lrnc_lub",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lrnc_uu,
          {"Uu","gtpv2.tra_info_lrnc_uu",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "RNC", HFILL}
        },
        { &hf_gtpv2_tra_info_lbm_sc_gmb,
          {"Gmb","gtpv2.tra_info_lbm_sc_gmb",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "BM-SC", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s1_mme,
          {"S1-MME","gtpv2.tra_info_lmme_s1_mme",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s3,
          {"S3","gtpv2.tra_info_lmme_s3",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s6a,
          {"S6a","gtpv2.tra_info_lmme_s6a",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s10,
          {"S10","gtpv2.tra_info_lmme_s10",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lmme_s11,
          {"S11","gtpv2.tra_info_lmme_s11",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "MME", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s4,
          {"S4","gtpv2.tra_info_lsgw_s4",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s5,
          {"S5","gtpv2.tra_info_lsgw_s5",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s8b,
          {"S8b","gtpv2.tra_info_lsgw_s8b",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lsgw_s11,
          {"S11","gtpv2.tra_info_lsgw_s11",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "SGW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s2a,
          {"S2a","gtpv2.tra_info_lpdn_gw_s2a",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s2b,
          {"S2b","gtpv2.tra_info_lpdn_gw_s2b",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s2c,
          {"S2c","gtpv2.tra_info_lpdn_gw_s2c",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s5,
          {"S5","gtpv2.tra_info_lpdn_gw_s5",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s6c,
          {"S6c","gtpv2.tra_info_lpdn_gw_s6c",
           FT_UINT8, BASE_DEC, NULL, 0x10,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_gx,
          {"Gx","gtpv2.tra_info_lpdn_gw_gx",
           FT_UINT8, BASE_DEC, NULL, 0x20,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_s8b,
          {"S8b","gtpv2.tra_info_lpdn_gw_s8b",
           FT_UINT8, BASE_DEC, NULL, 0x40,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lpdn_gw_sgi,
          {"SGi","gtpv2.tra_info_lpdn_gw_sgi",
           FT_UINT8, BASE_DEC, NULL, 0x80,
           "PDN GW", HFILL}
        },
        { &hf_gtpv2_tra_info_lenb_s1_mme,
          {"S1-MME","gtpv2.tra_info_lenb_s1_mme",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           "eNB", HFILL}
        },
        { &hf_gtpv2_tra_info_lenb_x2,
          {"X2","gtpv2.tra_info_lenb_x2",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           "eNB", HFILL}
        },
        { &hf_gtpv2_tra_info_lenb_uu,
          {"Uu","gtpv2.tra_info_lenb_uu",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           "eNB", HFILL}
        },
        { &hf_gtpv2_pdn_ipv4,
          {"PDN Address and Prefix(IPv4)", "gtpv2.pdn_addr_and_prefix.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv6_len,
          {"IPv6 Prefix Length", "gtpv2.pdn_ipv6_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv6,
          {"PDN Address and Prefix(IPv6)", "gtpv2.pdn_addr_and_prefix.ipv6",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pvi,
         {"PVI (Pre-emption Vulnerability)", "gtpv2.bearer_qos_pvi",
          FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pl,
         {"PL (Priority Level)", "gtpv2.bearer_qos_pl",
          FT_UINT8, BASE_DEC, NULL, 0x3c,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pci,
         {"PCI (Pre-emption Capability)", "gtpv2.bearer_qos_pci",
          FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_label_qci,
         {"Label (QCI)", "gtpv2.bearer_qos_label_qci",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_mbr_up,
         {"Maximum Bit Rate For Uplink", "gtpv2.bearer_qos_mbr_up",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_mbr_down,
         {"Maximum Bit Rate For Downlink", "gtpv2.bearer_qos_mbr_down",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_gbr_up,
         {"Guaranteed Bit Rate For Uplink", "gtpv2.bearer_qos_gbr_up",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_gbr_down,
         {"Guaranteed Bit Rate For Downlink", "gtpv2.bearer_qos_gbr_down",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_label_qci,
         {"Label (QCI)", "gtpv2.flow_qos_label_qci",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_mbr_up,
         {"Maximum Bit Rate For Uplink", "gtpv2.flow_qos_mbr_up",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_mbr_down,
         {"Maximum Bit Rate For Downlink", "gtpv2.flow_qos_mbr_down",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_gbr_up,
         {"Guaranteed Bit Rate For Uplink", "gtpv2.flow_qos_gbr_up",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_gbr_down,
         {"Guaranteed Bit Rate For Downlink", "gtpv2.flow_qos_gbr_down",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_rat_type,
          {"RAT Type", "gtpv2.rat_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_rat_type_vals_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_ecgi_flg,
          {"ECGI Present Flag", "gtpv2.uli_ecgi_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_ECGI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_lai_flg,
          {"LAI Present Flag", "gtpv2.uli_lai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_LAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_tai_flg,
          {"TAI Present Flag", "gtpv2.uli_tai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_TAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_flg,
          {"RAI Present Flag", "gtpv2.uli_rai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_RAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_flg,
          {"SAI Present Flag", "gtpv2.uli_sai_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_SAI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_flg,
          {"CGI Present Flag", "gtpv2.uli_cgi_flg",
           FT_BOOLEAN, 8, NULL, GTPv2_ULI_CGI_MASK,
           NULL, HFILL}
        },
        { &hf_gtpv2_glt,
          {"Geographic Location Type", "gtpv2.glt",
           FT_UINT8, BASE_DEC, VALS(geographic_location_type_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_lac,
          {"Location Area Code", "gtpv2.uli_cgi_lac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_ci,
          {"Cell Identity", "gtpv2.uli_cgi_ci",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_lac,
          {"Location Area Code", "gtpv2.uli_sai_lac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_sac,
          {"Service Area Code", "gtpv2.uli_sai_sac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_lac,
          {"Location Area Code", "gtpv2.uli_rai_lac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_rac,
          {"Routing Area Code", "gtpv2.uli_rai_rac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_uli_tai_tac,
          {"Tracking Area Code", "gtpv2.uli_tai_tac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_uli_ecgi_eci,
         {"ECI (E-UTRAN Cell Identifier)", "gtpv2.uli_ecgi_eci",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_uli_lai_lac,
         {"Location Area Code (LAC)", "gtpv2.uli_lai_lac",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_uli_ecgi_eci_spare,
         {"Spare", "gtpv2.uli_ecgi_eci_spare",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_nsapi,
          {"NSAPI", "gtpv2.nsapi",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_v4,
         {"V4", "gtpv2.f_teid_v4",
          FT_BOOLEAN, 8, TFS(&gtpv2_f_teid_v4_vals), 0x80,
          NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_v6,
         {"V6", "gtpv2.f_teid_v6",
          FT_BOOLEAN, 8, TFS(&gtpv2_f_teid_v6_vals), 0x40,
          NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_interface_type,
         {"Interface Type", "gtpv2.f_teid_interface_type",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_f_teid_interface_type_vals_ext, 0x1f,
          NULL , HFILL}
        },
        {&hf_gtpv2_f_teid_gre_key,
         {"TEID/GRE Key", "gtpv2.f_teid_gre_key",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL , HFILL}
        },
        { &hf_gtpv2_f_teid_ipv4,
          {"F-TEID IPv4", "gtpv2.f_teid_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_f_teid_ipv6,
          {"F-TEID IPv6", "gtpv2.f_teid_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_tmsi,
          {"TMSI", "gtpv2.tmsi",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_hsgw_addr_f_len,
          {"HSGW Address for forwarding Length", "gtpv2.hsgw_addr_f_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_hsgw_addr_ipv4,
          {"HSGW Address for forwarding", "gtpv2.hsgw_addr_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_hsgw_addr_ipv6,
          {"HSGW Address for forwarding", "gtpv2.hsgw_addr_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_gre_key,
          {"GRE Key", "gtpv2.gre_key",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL , HFILL}
        },
        { &hf_gtpv2_sgw_addr_ipv4,
          {"Serving GW Address", "gtpv2.sgw_addr_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sgw_addr_ipv6,
          {"Serving GW Address", "gtpv2.sgw_addr_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_sgw_s1u_teid,
          {"Serving GW S1-U TEID", "gtpv2.sgw_s1u_teid",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_delay_value,
         {"Delay Value (In integer multiples of 50 milliseconds or zero)", "gtpv2.delay_value",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_charging_id,
         {"Charging id", "gtpv2.charging_id",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_charging_characteristic,
         {"Charging Characteristic", "gtpv2.charging_characteristic",
          FT_UINT16, BASE_HEX, NULL, 0xffff,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_flag_ppc,
         {"PPC (Prohibit Payload Compression)", "gtpv2.bearer_flag.ppc",
          FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL}
        },
        {&hf_gtpv2_bearer_flag_vb,
         {"VB (Voice Bearer)", "gtpv2.bearer_flag.vb",
          FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL}
        },
        {&hf_gtpv2_pti,
         {"Procedure Transaction Id", "gtpv2.pti",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        /* MM Context */
        { &hf_gtpv2_mm_context_sm,
          {"Security Mode", "gtpv2.mm_context_sm",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_security_mode), 0xe0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nhi,
          {"NHI(Next Hop Indicator)", "gtpv2.mm_context_nhi",
           FT_BOOLEAN, 8, TFS(&gtpv2_nhi_vals), 0x10,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_drxi,
          {"DRXI", "gtpv2.mm_context_drxi",
           FT_UINT8, BASE_DEC, NULL, 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_cksn,
          {"CKSN", "gtpv2.mm_context_cksn",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_cksn_ksi,
          {"CKSN/KSI", "gtpv2.mm_context_cksn_ksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_ksi_a,
          {"KSI_asme", "gtpv2.mm_context_ksi_a",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nr_tri,
          {"Number of Triplet", "gtpv2.mm_context_nr_tri",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_unipa,
          {"Used NAS integrity protection algorithm", "gtpv2.mm_context_unipa",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_unipa_vals), 0x70,
           NULL, HFILL}
        },

        { &hf_gtpv2_mm_context_unc,
          {"Used NAS Cipher", "gtpv2.mm_context_unc",
           FT_UINT8, BASE_DEC, VALS(gtpv2_mm_context_unc_vals), 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nas_dl_cnt,
          {"NAS Downlink Count", "gtpv2.mm_context_nas_dl_cnt",
           FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nas_ul_cnt,
          {"NAS Uplink Count", "gtpv2.mm_context_nas_ul_cnt",
           FT_UINT24, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_kasme,
          {"Kasme","gtpv2.mm_context_kasme",
           FT_BYTES, BASE_NONE, NULL,0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_una,
          { "UTRAN", "gtpv2.mm_context.una",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x01,
            NULL, HFILL }},
        { &hf_gtpv2_gena,
          { "GERAN", "gtpv2.mm_context.gena",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x02,
            NULL, HFILL }
        },
        { &hf_gtpv2_gana,
          { "GAN", "gtpv2.mm_context.gana",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x04,
            NULL, HFILL }
        },
        { &hf_gtpv2_ina,
          { "I-HSPA-EVOLUTION", "gtpv2.mm_context.ina",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x08,
            NULL, HFILL }
        },
        { &hf_gtpv2_ena,
          { "E-UTRAN", "gtpv2.mm_context.ena",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x10,
            NULL, HFILL }
        },
        { &hf_gtpv2_hnna,
          { "HO-toNone3GPP-Access", "gtpv2.mm_context.hnna",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x20,
            NULL, HFILL }
        },
        { &hf_gtpv2_mm_context_ksi,
          {"KSI", "gtpv2.mm_context_ksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_nr_qui,
          {"Number of Quintuplets", "gtpv2.mm_context_nr_qui",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL}
        },

        { &hf_gtpv2_mm_context_nr_qua,
          {"Number of Quadruplet", "gtpv2.mm_context_nr_qua",
           FT_UINT8, BASE_DEC, NULL, 0x1c,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_uamb_ri,
          {"UAMB RI", "gtpv2.mm_context_uamb_ri",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_osci,
          {"OSCI", "gtpv2.mm_context_osci",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_mm_context_samb_ri,
          {"SAMB RI", "gtpv2.mm_context_samb_ri",
           FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}
        },
        {&hf_gtpv2_ue_time_zone_dst,
         {"Daylight Saving Time","gtpv2.ue_time_zone_dst",
          FT_UINT8, BASE_DEC, VALS(gtpv2_ue_time_zone_dst_vals),0x03,
          NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_type,
          {"Node-ID Type", "gtpv2.fq_csid_type",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_nr,
          {"Number of CSIDs", "gtpv2.fq_csid_nr",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_ipv4,
          {"Node-ID (IPv4)", "gtpv2.fq_csid_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_ipv6,
          {"Node-ID (IPv6)", "gtpv2.fq_csid_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_fq_csid_id,
          {"CSID", "gtpv2.fq_csid_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_complete_req_msg_type,
          {"Complete Request Message Type","gtpv2.complete_req_msg_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_complete_req_msg_type_vals),0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_mme_grp_id,
         {"MME Group ID","gtpv2.mme_grp_id",
          FT_UINT16, BASE_DEC, NULL,0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_mme_code,
          {"MME Code","gtpv2.mme_code",
           FT_UINT8, BASE_DEC, NULL,0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_m_tmsi,
          {"M-TMSI","gtpv2.m_tmsi",
           FT_BYTES, BASE_NONE, NULL,0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_container_type,
          {"Container Type","gtpv2.container_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_container_type_vals),0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_cause_type,
          {"Cause Type","gtpv2.cause_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_type_vals_ext,0x0f,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseRadioNetwork,
          {"Radio Network Layer Cause","gtpv2.CauseRadioNetwork",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseRadioNetwork_vals),0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseTransport,
          {"Transport Layer Cause","gtpv2.CauseTransport",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseTransport_vals),0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseNas,
          {"NAS Cause","gtpv2.CauseNas",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseNas_vals),0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_CauseMisc,
          {"Miscellaneous Cause","gtpv2.CauseMisc",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseMisc_vals),0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_target_type,
          {"Target Type","gtpv2.target_type",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_target_type_vals_ext,0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_macro_enodeb_id,
         {"Macro eNodeB ID","gtpv2.macro_enodeb_id",
          FT_UINT24, BASE_HEX, NULL,0x0fffff,
          NULL, HFILL}
        },
        { &hf_gtpv2_CauseProtocol,
          {"Protocol Cause","gtpv2.CauseProtocol",
           FT_UINT8, BASE_DEC, VALS(s1ap_CauseProtocol_vals),0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_apn_rest,
         {"APN Restriction", "gtpv2.apn_rest",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtpv2_selec_mode,
         {"Selection Mode","gtpv2.selec_mode",
          FT_UINT8, BASE_DEC, VALS(gtpv2_selec_mode_vals),0x03,
          NULL, HFILL}
        },
        { &hf_gtpv2_source_type,
          {"Source Type", "gtpv2.source_type",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_bearer_control_mode,
         {"Bearer Control Mode","gtpv2.bearer_control_mode",
          FT_UINT8, BASE_DEC, VALS(gtpv2_bearer_control_mode_vals),0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_cng_rep_act,
          {"Change Reporting Action", "gtpv2.cng_rep_act",
           FT_UINT8, BASE_DEC, VALS(gtpv2_cng_rep_act_vals), 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_node_type,
          {"Node Type", "gtpv2.node_type",
           FT_UINT8, BASE_DEC, VALS(gtpv2_node_type_vals), 0x0,
           NULL, HFILL}
        },
        {&hf_gtpv2_fqdn,
         {"FQDN", "gtpv2.fqdn",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_enterprise_id,
          {"Enterprise ID", "gtpv2.enterprise_id",
           FT_UINT16, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_address_digits,
          { "Address digits", "gtpv2.address_digits",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gtpv2_ti,
          {"Transaction Identifier", "gtpv2.ti",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_container_phx,
          {"PHX", "gtpv2.bss_cont.phx",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_sapi_flg,
          {"SAPI", "gtpv2.bss_cont.sapi_flg",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_rp_flg,
          {"RP", "gtpv2.bss_cont.rp_flg",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_pfi_flg,
          {"PFI", "gtpv2.bss_cont.pfi_flg",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_pfi,
          {"Packet Flow ID(PFI)", "gtpv2.bss_cont.pfi",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_rp,
          {"Radio Priority(RP)", "gtpv2.bss_cont.rp",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_sapi,
          {"SAPI", "gtpv2.bss_cont.sapi",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtpv2_bss_con_xid_len,
          {"XiD parameters length", "gtpv2.bss_cont.xid_len",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_home_enodeb_id,
          {"Home eNodeB ID", "gtpv2.home_enodeb_id",
           FT_UINT32, BASE_HEX, NULL, 0x0fffffff,
           NULL, HFILL}
        },
        { &hf_gtpv2_tac,
          {"Tracking Area Code (TAC)", "gtpv2.tac",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_service_area_nr,
          {"Number of MBMS Service Area codes", "gtpv2.mbms_service_area_nr",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_mbms_service_area_id,
          {"MBMS Service Area code (Service Area Identity)", "gtpv2.mbms_service_area_id",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_mbms_session_id,
          {"MBMS Session Identifier", "gtpv2.mbms_session_id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_mbms_flow_id,
          {"MBMS Flow Identifier", "gtpv2.mbms_flow_id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_cteid,
          {"Common Tunnel Endpoint Identifiere", "gtpv2.cetid",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_ip_addr_type,
          {"IP Address Type", "gtpv2.ip_addr_type",
          FT_UINT8, BASE_DEC, NULL, 0xc0,
          NULL, HFILL}
        },
        { &hf_gtpv2_ip_addr_len,
          {"IP Address Length", "gtpv2.ip_addr_len",
          FT_UINT8, BASE_DEC, NULL, 0x3f,
          NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_dist_addrv4,
          {"MBMS IP Multicast Distribution Address (IPv4)", "gtpv2.mbms_ip_mc_dist_addrv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_dist_addrv6,
          {"MBMS IP Multicast Distribution Address (IPv6)", "gtpv2.mbms_ip_mc_dist_addrv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_src_addrv4,
          {"MBMS IP Multicast Source Address (IPv4)", "gtpv2.mbms_ip_mc_src_addrv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_ip_mc_src_addrv6,
          {"MBMS IP Multicast Source Address (IPv6)", "gtpv2.mbms_ip_mc_src_addrv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtpv2_mbms_hc_indicator,
          {"MBMS HC Indicator", "gtpv2.mbms_hc_indicator",
          FT_UINT8, BASE_DEC, VALS(gtpv2_mbms_hc_indicator_vals), 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_mbms_dist_indication,
          {"MBMS Distribution Indication", "gtpv2.mbms_dist_indication",
          FT_UINT8, BASE_DEC, VALS(gtpv2_mbms_dist_indication_vals), 0x03,
          NULL, HFILL}
        },
        { &hf_gtpv2_mbms_service_id,
          {"MBMS Service ID", "gtpv2.mbms_service_id",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtpv2_add_flags_for_srvcc_ics,
          {"ICS (IMS Centralized Service)", "gtpv2.add_flags_for_srvcc_ics",
          FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL}
        },
        { &hf_gtpv2_vsrvcc_flag,
          {"VF (vSRVCC Flag)", "gtpv2.vsrvcc_flag",
          FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL}
        },
    };

    static gint *ett_gtpv2_array[] = {
        &ett_gtpv2,
        &ett_gtpv2_flags,
        &ett_gtpv2_ie,
        &ett_gtpv2_uli_flags,
        &ett_gtpv2_uli_field,
        &ett_gtpv2_bearer_ctx,
        &ett_gtpv2_PDN_conn,
        &ett_gtpv2_mm_context_flag,
        &ett_gtpv2_pdn_numbers_nsapi,
        &ett_gtpv2_tra_info_trigg,
        &ett_gtpv2_tra_info_trigg_msc_server,
        &ett_gtpv2_tra_info_trigg_mgw,
        &ett_gtpv2_tra_info_trigg_sgsn,
        &ett_gtpv2_tra_info_trigg_ggsn,
        &ett_gtpv2_tra_info_trigg_bm_sc,
        &ett_gtpv2_tra_info_trigg_sgw_mme,
        &ett_gtpv2_tra_info_interfaces,
        &ett_gtpv2_tra_info_interfaces_imsc_server,
        &ett_gtpv2_tra_info_interfaces_lmgw,
        &ett_gtpv2_tra_info_interfaces_lsgsn,
        &ett_gtpv2_tra_info_interfaces_lggsn,
        &ett_gtpv2_tra_info_interfaces_lrnc,
        &ett_gtpv2_tra_info_interfaces_lbm_sc,
        &ett_gtpv2_tra_info_interfaces_lmme,
        &ett_gtpv2_tra_info_interfaces_lsgw,
        &ett_gtpv2_tra_info_interfaces_lpdn_gw,
        &ett_gtpv2_tra_info_interfaces_lpdn_lenb,
        &ett_gtpv2_tra_info_ne_types,
        &ett_gtpv2_rai,
        &ett_gtpv2_stn_sr,
        &ett_gtpv2_ms_mark,
        &ett_gtpv2_supp_codec_list,
        &ett_gtpv2_bss_con,
        &ett_gtpv2_mm_context_auth_qua,
        &ett_gtpv2_mm_context_net_cap,
        &ett_gtpv2_ms_network_capability,
        &ett_gtpv2_vd_pref,
        &ett_gtpv2_access_rest_data,
    };

    proto_gtpv2 = proto_register_protocol("GPRS Tunneling Protocol V2", "GTPv2", "gtpv2");
    proto_register_field_array(proto_gtpv2, hf_gtpv2, array_length(hf_gtpv2));
    proto_register_subtree_array(ett_gtpv2_array, array_length(ett_gtpv2_array));
    /* AVP Code: 22 3GPP-User-Location-Info */
    dissector_add_uint("diameter.3gpp", 22, new_create_dissector_handle(dissect_diameter_3gpp_uli, proto_gtpv2));

    register_dissector("gtpv2", dissect_gtpv2, proto_gtpv2);
    /* Dissector table for private extensions */
    gtpv2_priv_ext_dissector_table = register_dissector_table("gtpv2.priv_ext", "GTPv2 PRIVATE EXT", FT_UINT16, BASE_DEC);
}

void
proto_reg_handoff_gtpv2(void)
{
    nas_eps_handle = find_dissector("nas-eps");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
