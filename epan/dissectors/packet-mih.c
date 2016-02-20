/* packet-mih.c
 * Definitions for MIH (Media independent Handover) packet disassembly structures and routines
 * Refer to (IEEE 802.21) IEEE Standard for Local and metropolitan area networks- Part 21: Media Independent Handover Services, 21 Jan 2009
 *
 * Copyright 2011, ANKITH AGARWAL <ankitha@cdac.in>
 *
 * The original patch submitted in 2011 was improved and expanded in 2012 by Fraunhofer Institute for Open Communication Systems (FOKUS)
 * The improvements include filtering of all fields as well as including definitions from the revised IEEE 802.21b document from 10 May 2012
 *
 * Copyright 2012, Alton MacDonald <alton.kenneth.macdonald@fokus.fraunhofer.de>
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

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/etypes.h>
void proto_register_mih(void);
void proto_reg_handoff_mih(void);

#define MIH_PORT 4551

#define VERSION_MASK    0xF0
#define ACKREQ_MASK     0x8
#define ACKRESP_MASK    0x4
#define UIR_MASK        0x2
#define MORE_FRAG_MASK  0x1
#define FRAG_NO_MASK    0xFE
#define SID_MASK        0xF000
#define OPCODE_MASK     0xC00
#define AID_MASK        0x3FF
#define TRANS_ID_MASK   0x0FFF
#define LEN_OF_LEN_MASK 0x80

/*Type values for TLV encoding*/
#define SRC_MIHF_ID             1
#define DEST_MIHF_ID            2
#define STATUS                  3
#define LINK_TYPE               4
#define MIH_EVT_LIST            5
#define MIH_CMD_LIST            6
#define MIH_IQ_TYPE_LIST        7
#define MIH_TRANS_LIST          8
#define LINK_ADDR_LIST          9
#define MBB_HO_SUPP_LIST        10
#define REG_REQUEST_CODE        11
#define VALID_TIME_INTR         12
#define LINK_ID                 13
#define NEW_LINK_ID             14
#define OLD_ACCESS_ROUTER       15
#define NEW_ACCESS_ROUTER       16
#define IP_RENEWAL_FLAG         17
#define IP_MOB_MGMT             18
#define IP_CFG_MTHDS            19
#define LINK_DN_REASON          20
#define TIMER_INTERVAL          21
#define LINK_GOING_DN_REASON    22
#define LINK_PARAM_RPT_LIST     23
#define DEV_STATES_REQ          24
#define LINK_ID_LIST            25
#define DEV_STATES_RSP_LIST     26
#define STATUS_REQ_SET          27
#define STATUS_RSP_LIST         28
#define CFG_REQ_LIST            29
#define CFG_RSP_LIST            30
#define LINK_POA_LIST           31
#define PREF_LINK_LIST          32
#define HO_REQ_QUERY_LIST       33
#define HO_STATUS               34
#define ACCESS_ROUTER_ADDR      35
#define DHCP_SER_ADDR           36
#define FA_ADDR                 37
#define LINK_ACTION_REQ_LIST    38
#define LINK_ACTION_RSP_LIST    39
#define HO_RESULT               40
#define LINK_RES_STATUS         41
#define RES_RETENTION_STATUS    42
#define IQ_BIN_DATA_LIST        43
#define IQ_RDF_DATA_LIST        44
#define IQ_RDF_SCHEMA_URL       45
#define IQ_RDF_SCHM_LIST        46
#define MAX_RSP_SIZE            47
#define IR_BIN_DATA_LIST        48
#define IR_RDF_DATA_LIST        49
#define IR_SCHM_URL_LIST        50
#define IR_RDF_SCHM_LIST        51
#define MN_MIHF_ID              52
#define Q_RES_RPT_FLAG          53
#define EVT_CFG_INFO_LIST       54
#define TGT_NET_INFO            55
#define TGT_NET_INFO_LIST       56
#define ASGN_RES_SET            57
#define LINK_DET_INFO_LIST      58
#define MN_LINK_ID              59
#define POA_LINK_ADDR           60
#define UNAUTH_INFO_REQ         61
#define NET_TYPE                62
#define REQ_RES_SET             63
#define VEND_SPECIFIC_TLV       100

/*Bitmasks in 802.21 are encoded in Network-Byte-Order: bit0 is leftmost bit*/

/*MASK for event list*/
#define LINK_DETECT_MASK        0x80000000
#define LINK_UP_MASK            0x40000000
#define LINK_DOWN_MASK          0x20000000
#define LINK_PARAM_MASK         0x10000000
#define LINK_GD_MASK            0x08000000
#define LINK_HO_IMM_MASK        0x04000000
#define LINK_HO_COMP_MASK       0x02000000
#define LINK_PDU_MASK           0x01000000

/*MASK for command list*/
/*1st bit is reserved*/
#define CMD_EVT_SUBS_MASK       0x40000000
#define CMD_EVT_UNSUBS_MASK     0x20000000
#define CMD_GET_PARA_MASK       0x10000000
#define CMD_CONF_TH_MASK        0x08000000
#define CMD_LINK_AC_MASK        0x04000000

/*MASK for Info Query list*/
#define IQ_BIN_DATA_MASK        0x80000000
#define IQ_RDF_DATA_MASK        0x40000000
#define IQ_RDF_SCH_U_MASK       0x20000000
#define IQ_RDF_SCH_MASK         0x10000000
#define IQ_IE_NET_TYPE_MASK     0x08000000
#define IQ_IE_OP_ID_MASK        0x04000000
#define IQ_SERV_ID_MASK         0x02000000
#define IQ_IE_COUN_MASK         0x01000000
#define IQ_NET_ID_MASK          0x00800000
#define IQ_NET_AUX_MASK         0x00400000
#define IQ_IE_ROAM_MASK         0x00200000
#define IQ_IE_COST_MASK         0x00100000
#define IQ_IE_QOS_MASK          0x00080000
#define IQ_IE_DATA_MASK         0x00040000
#define IQ_IE_REGDOM_MASK       0x00020000
#define IQ_IE_FREQ_MASK         0x00010000
#define IQ_IE_IP_CFG_MASK       0x00008000
#define IQ_IE_CAP_MASK          0x00004000
#define IQ_IE_SUP_MASK          0x00002000
#define IQ_IE_MOB_MG_MASK       0x00001000
#define IQ_IE_EM_SERV_MASK      0x00000800
#define IQ_IE_IMS_MASK          0x00000400
#define IQ_IE_MOB_NET_MASK      0x00000200
#define IQ_IE_POA_ADDR_MASK     0x00000100
#define IQ_IE_POA_LOC_MASK      0x00000080
#define IQ_IE_POA_CHAN_MASK     0x00000040
#define IQ_IE_POA_SYS_MASK      0x00000020
#define IQ_IE_POA_SUB_MASK      0x00000010
#define IQ_IE_POA_IP_MASK       0x00000008

/*MASK for mobility Management methods*/
#define MOB_MIP4_MASK           0x8000
#define MOB_MIP4_REG_MASK       0x4000
#define MOB_MIP6_MASK           0x2000
#define MOB_HMIP6_MASK          0x1000
#define MOB_LOW_LAT_MASK        0x0800
#define MOB_FMIP6_MASK          0x0400
#define MOB_IKE_MULTI_MASK      0x0200

/*MASK for ip configuration methods*/
#define IP_CFG_STAT_MASK        0x80000000
#define IP_CFG_DHCP4_MASK       0x40000000
#define IP_CFG_MIP4_FA_MASK     0x20000000
#define IP_CFG_MIP4_NFA_MASK    0x10000000
/*bits 4-10 reserved for IPv4 address configuration*/
#define IP_CFG_IP6_SL_MASK      0x00100000
#define IP_CFG_DHCP6_MASK       0x00080000
#define IP_CFG_IP6_MAN_MASK     0x00040000

/*information holder integers...*/
static int proto_mih = -1;
static int hf_mih_version = -1;
static int hf_mih_ack_req = -1;
static int hf_mih_ack_resp = -1;
static int hf_mih_uir = -1;
static int hf_mih_more_frag = -1;
static int hf_mih_frag_no = -1;
static int hf_mih_mid = -1;
static int hf_mih_service_id = -1;
static int hf_mih_opcode = -1;
static int hf_mih_serv_actionid = -1;
static int hf_mih_event_actionid = -1;
static int hf_mih_command_actionid = -1;
static int hf_mih_info_actionid = -1;
static int hf_mih_tid = -1;
static int hf_mih_pay_len = -1;
static int hf_mih_type = -1;
static int hf_mih_type_length = -1;
static int hf_mih_type_length_ext = -1;
static int hf_mihf_id = -1;
static int hf_mihf_id_mac = -1;
static int hf_mihf_id_ipv4 = -1;
static int hf_mihf_id_ipv6 = -1;
static int hf_status = -1;
static int hf_ip_methods_supported = -1;
static int hf_ip_dhcp_services = -1;
static int hf_fn_agent = -1;
static int hf_access_router = -1;
static int hf_link_type = -1;
static int hf_link_type_ext = -1;
static int hf_ipv4_addr = -1;
static int hf_ipv6_addr = -1;
static int hf_link_dn_reason = -1;
static int hf_link_gdn_reason = -1;
static int hf_mac_addr = -1;
static int hf_link_param_gen = -1;
static int hf_link_param_qos = -1;
static int hf_link_param_gg = -1;
static int hf_link_param_802_11 = -1;
static int hf_link_param_fdd = -1 ;
static int hf_link_param_edge = -1;
static int hf_link_param_eth = -1;
static int hf_link_param_c2k = -1;
static int hf_link_param_hrpd = -1;
static int hf_link_param_802_16 = -1;
static int hf_link_param_802_20 = -1;
static int hf_link_param_802_22 = -1;
static int hf_link_param_value = -1;
static int hf_op_mode = -1;
static int hf_link_ac_type = -1;
static int hf_link_ac_ext_time = -1;
static int hf_link_ac_result = -1;
static int hf_ho_reason = -1;
static int hf_ho_status = -1;
static int hf_reg_request_code = -1;
static int hf_ip_renewal = -1;
static int hf_max_resp_size = -1;
static int hf_time_interval = -1;
static int hf_valid_time_interval = -1;
static int hf_tsp_carrier = -1;
static int hf_mbb_ho_supp = -1;
static int hf_link_addr_type = -1;
static int hf_link_transport_addr_type = -1;
static int hf_link_addr_string = -1;
static int hf_link_data_rate = -1;
static int hf_plmn_id = -1;
static int hf_location_area_id = -1;
static int hf_cell_id = -1;
static int hf_ci = -1;
static int hf_threshold_val = -1;
static int hf_threshold_x_dir = -1;
static int hf_threshold_action = -1;
static int hf_config_status = -1;
static int hf_num_cos = -1;
static int hf_num_queue = -1;
static int hf_channel_id = -1;
static int hf_predef_cfg_id = -1;
static int hf_network_id = -1;
static int hf_net_aux_id = -1;
static int hf_sig_strength_dbm = -1;
static int hf_sig_strength_per = -1;
static int hf_cos_id = -1;
static int hf_cos_value = -1;
static int hf_sinr = -1;
static int hf_rdf_data = -1;
static int hf_rdf_mime_type = -1;
static int hf_link_res_status = -1;
static int hf_res_retention_status = -1;
static int hf_res_rpt_flag = -1;
static int hf_unauth_info_req = -1;
static int hf_rdf_sch = -1;
static int hf_rdf_sch_url = -1;
static int hf_ir_bin_data = -1;
static int hf_iq_bin_data_x = -1;
static int hf_vendor_specific_tlv = -1;
static int hf_reserved_tlv = -1;
static int hf_experimental_tlv = -1;
static int hf_unknown_tlv = -1;
static int hf_fragmented_tlv = -1;

/*header fields for event list */
static int hf_event_list = -1;
static int hf_event_link_detect = -1;
static int hf_event_link_up = -1;
static int hf_event_link_dn = -1;
static int hf_event_link_param = -1;
static int hf_event_link_gd = -1;
static int hf_event_ho_imm = -1;
static int hf_event_ho_comp = -1;
static int hf_event_pdu_tx_stat = -1;

/*header fields for command list*/
static int hf_cmd_list = -1;
static int hf_cmd_event_subs = -1;
static int hf_cmd_event_unsub = -1;
static int hf_cmd_get_param = -1;
static int hf_cmd_con_thres = -1;
static int hf_cmd_link_action = -1;

/*header fields for iq type list*/
static int hf_iq_list = -1;
static int hf_iq_bin_data = -1;
static int hf_iq_rdf_data = -1;
static int hf_iq_rdf_sch_url = -1;
static int hf_iq_rdf_sch = -1;
static int hf_iq_net_type = -1;
static int hf_iq_op_id = -1;
static int hf_iq_serv_pro_id = -1;
static int hf_iq_country_code = -1;
static int hf_iq_net_id = -1;
static int hf_iq_net_aux_id = -1;
static int hf_iq_roam_part = -1;
static int hf_iq_cost = -1;
static int hf_iq_net_qos = -1;
static int hf_iq_net_dat_rt = -1;
static int hf_iq_net_reg_dom = -1;
static int hf_iq_freq_bands = -1;
static int hf_iq_ip_cfg_mthds = -1;
static int hf_iq_net_cap = -1;
static int hf_iq_supp_lcp = -1;
static int hf_iq_net_mob_mg = -1;
static int hf_iq_net_emserv = -1;
static int hf_iq_net_ims_pcscf = -1;
static int hf_iq_net_mob_net = -1;
static int hf_iq_link_addr = -1;
static int hf_iq_poa_loc = -1;
static int hf_iq_poa_chan_range = -1;
static int hf_iq_poa_sys_info = -1;
static int hf_iq_poa_sub_info = -1;
static int hf_iq_poa_ip = -1;

/*header fields for mob mgmt*/
static int hf_mob_list = -1;
static int hf_mob_mip4 = -1;
static int hf_mob_mip4_reg = -1;
static int hf_mob_mip6 = -1;
static int hf_mob_hmip6 = -1;
static int hf_mob_low_lat = -1;
static int hf_mob_fmip6 = -1;
static int hf_mob_ike_multi = -1;

/*header fields for configure methods*/
static int hf_cfg_mthds = -1;
static int hf_cfg_ip4_stat = -1;
static int hf_cfg_dhcp4 = -1;
static int hf_cfg_mip_fa = -1;
static int hf_cfg_mip_wo_fa = -1;
static int hf_cfg_ip6_sac = -1;
static int hf_cfg_dhcp6 = -1;
static int hf_cfg_ip6_manual = -1;

/*header fields for transport list*/
static int hf_trans_list = -1;
static int hf_trans_udp = -1;
static int hf_trans_tcp = -1;

/*header fields for device state requests and responses*/
static int hf_dev_states_req = -1;
static int hf_dev_states_req_dev_info = -1;
static int hf_dev_states_req_batt_lvl = -1;
static int hf_dev_states_resp = -1;
static int hf_dev_batt_level = -1;
static int hf_dev_info = -1;

/*header fields for Link Action Attributes*/
static int hf_link_ac_attr = -1;
static int hf_link_ac_attr_link_scan = -1;
static int hf_link_ac_attr_link_res_retain = -1;
static int hf_link_ac_attr_data_fwd_req = -1;

/*header fields for transport subtypes*/
static int hf_link_subtype_eth = -1;
static int hf_link_subtype_eth_10m = -1;
static int hf_link_subtype_eth_100m = -1;
static int hf_link_subtype_eth_1000m = -1;
static int hf_link_subtype_wireless_other = -1;
static int hf_link_subtype_wireless_other_dvb = -1;
static int hf_link_subtype_wireless_other_tdmb = -1;
static int hf_link_subtype_wireless_other_atsc = -1;
static int hf_link_subtype_ieee80211 = -1;
static int hf_link_subtype_ieee80211_24 = -1;
static int hf_link_subtype_ieee80211_5 = -1;
static int hf_link_subtype_ieee80211_49 = -1;
static int hf_link_subtype_ieee80211_365 = -1;
static int hf_link_subtype_ieee80211_316 = -1;
static int hf_link_subtype_umts = -1;
static int hf_link_subtype_umts_99 = -1;
static int hf_link_subtype_umts_4 = -1;
static int hf_link_subtype_umts_5 = -1;
static int hf_link_subtype_umts_6 = -1;
static int hf_link_subtype_umts_7 = -1;
static int hf_link_subtype_umts_8 = -1;
static int hf_link_subtype_cdma2000 = -1;
static int hf_link_subtype_cdma2000_0 = -1;
static int hf_link_subtype_cdma2000_a = -1;
static int hf_link_subtype_cdma2000_b = -1;
static int hf_link_subtype_cdma2000_c = -1;
static int hf_link_subtype_ieee80216 = -1;
static int hf_link_subtype_ieee80216_25 = -1;
static int hf_link_subtype_ieee80216_35 = -1;

/*header fields for MIH Capabilities*/
static int hf_mihcap = -1;
static int hf_mihcap_es = -1;
static int hf_mihcap_cs = -1;
static int hf_mihcap_is = -1;

/*header fields for High Level Network Capabilities*/
static int hf_net_caps = -1;
static int hf_net_caps_sec = -1;
static int hf_net_caps_qos0 = -1;
static int hf_net_caps_qos1 = -1;
static int hf_net_caps_qos2 = -1;
static int hf_net_caps_qos3 = -1;
static int hf_net_caps_qos4 = -1;
static int hf_net_caps_qos5 = -1;
static int hf_net_caps_ia = -1;
static int hf_net_caps_es = -1;
static int hf_net_caps_mihcap = -1;

/*trees and subtrees...*/
static gint ett_mih = -1;
static gint ett_ver_flags = -1;
static gint ett_mid = -1;
static gint ett_tlv = -1;
static gint ett_cmd_bitmap = -1;
static gint ett_event_bitmap = -1;
static gint ett_mob_mgt_bitmap = -1;
static gint ett_cfg_mtd_bitmap = -1;
static gint ett_iq_type_bitmap = -1;
static gint ett_trans_list_bitmap = -1;
static gint ett_dev_states_bitmap = -1;
static gint ett_mihcap_bitmap = -1;
static gint ett_net_caps_bitmap = -1;
static gint ett_ac_attr_bitmap = -1;
static gint ett_subtype_eth_bitmap = -1;
static gint ett_subtype_wireless_other_bitmap = -1;
static gint ett_subtype_ieee80211_bitmap = -1;
static gint ett_subtype_umts_bitmap = -1;
static gint ett_subtype_cdma2000_bitmap = -1;
static gint ett_subtype_ieee80216_bitmap = -1;
static gint ett_min_pk_tx_delay = -1;
static gint ett_avg_pk_tx_delay = -1;
static gint ett_max_pk_tx_delay = -1;
static gint ett_pk_delay_jitter = -1;
static gint ett_pk_loss_rate = -1;
static gint ett_list_prefer_link = -1;
static gint ett_ip_dhcp_server = -1;
static gint ett_fn_agent = -1;
static gint ett_access_router = -1;
static gint ett_link_states_req = -1;
static gint ett_link_desc_req = -1;

/*field definitions of evt, cmd, mob mgmt, ip cfg, iq type */
static const int *event_fields[] = {
        &hf_event_link_detect,
        &hf_event_link_up,
        &hf_event_link_dn,
        &hf_event_link_param,
        &hf_event_link_gd,
        &hf_event_ho_imm,
        &hf_event_ho_comp,
        &hf_event_pdu_tx_stat,
        NULL
};

static const int *cmd_fields[] = {
        &hf_cmd_event_subs,
        &hf_cmd_event_unsub,
        &hf_cmd_get_param,
        &hf_cmd_con_thres,
        &hf_cmd_link_action,
        NULL
};

static const int *iq_type_fields[] = {
        &hf_iq_bin_data,
        &hf_iq_rdf_data,
        &hf_iq_rdf_sch_url,
        &hf_iq_rdf_sch,
        &hf_iq_net_type,
        &hf_iq_op_id,
        &hf_iq_serv_pro_id,
        &hf_iq_country_code,
        &hf_iq_net_id,
        &hf_iq_net_aux_id,
        &hf_iq_roam_part,
        &hf_iq_cost,
        &hf_iq_net_qos,
        &hf_iq_net_dat_rt,
        &hf_iq_net_reg_dom,
        &hf_iq_freq_bands,
        &hf_iq_ip_cfg_mthds,
        &hf_iq_net_cap,
        &hf_iq_supp_lcp,
        &hf_iq_net_mob_mg,
        &hf_iq_net_emserv,
        &hf_iq_net_ims_pcscf,
        &hf_iq_net_mob_net,
        &hf_iq_link_addr,
        &hf_iq_poa_loc,
        &hf_iq_poa_chan_range,
        &hf_iq_poa_sys_info,
        &hf_iq_poa_sub_info,
        &hf_iq_poa_ip,
        NULL
};

static const int *mob_fields[] = {
        &hf_mob_mip4,
        &hf_mob_mip4_reg,
        &hf_mob_mip6,
        &hf_mob_hmip6,
        &hf_mob_low_lat,
        &hf_mob_fmip6,
        &hf_mob_ike_multi,
        NULL
};

static const int *cfg_fields[] = {
        &hf_cfg_ip4_stat,
        &hf_cfg_dhcp4,
        &hf_cfg_mip_fa,
        &hf_cfg_mip_wo_fa,
        &hf_cfg_ip6_sac,
        &hf_cfg_dhcp6,
        &hf_cfg_ip6_manual,
        NULL
};

/*field definitions for various bitmaps */
static const int *trans_fields[] = {
        &hf_trans_udp,
        &hf_trans_tcp,
        NULL
};

static const int *dev_states_fields[] = {
        &hf_dev_states_req_dev_info,
        &hf_dev_states_req_batt_lvl,
        NULL
};

static const int *mihcap_fields[] = {
        &hf_mihcap_es,
        &hf_mihcap_cs,
        &hf_mihcap_is,
        NULL
};

static const int *net_caps_fields[] = {
        &hf_net_caps_sec,
        &hf_net_caps_qos0,
        &hf_net_caps_qos1,
        &hf_net_caps_qos2,
        &hf_net_caps_qos3,
        &hf_net_caps_qos4,
        &hf_net_caps_qos5,
        &hf_net_caps_ia,
        &hf_net_caps_es,
        &hf_net_caps_mihcap,
        NULL
};

static const int *ac_attr_fields[] = {
        &hf_link_ac_attr_link_scan,
        &hf_link_ac_attr_link_res_retain,
        &hf_link_ac_attr_data_fwd_req,
        NULL
};

static const int *subtype_eth_fields[] = {
        &hf_link_subtype_eth_10m,
        &hf_link_subtype_eth_100m,
        &hf_link_subtype_eth_1000m,
        NULL
};

static const int *subtype_wireless_other_fields[] = {
        &hf_link_subtype_wireless_other_dvb,
        &hf_link_subtype_wireless_other_tdmb,
        &hf_link_subtype_wireless_other_atsc,
        NULL
};

static const int *subtype_ieee80211_fields[] = {
        &hf_link_subtype_ieee80211_24,
        &hf_link_subtype_ieee80211_5,
        &hf_link_subtype_ieee80211_49,
        &hf_link_subtype_ieee80211_365,
        &hf_link_subtype_ieee80211_316,
        NULL
};

static const int *subtype_umts_fields[] = {
        &hf_link_subtype_umts_99,
        &hf_link_subtype_umts_4,
        &hf_link_subtype_umts_5,
        &hf_link_subtype_umts_6,
        &hf_link_subtype_umts_7,
        &hf_link_subtype_umts_8,
        NULL
};

static const int *subtype_cdma2000_fields[] = {
        &hf_link_subtype_cdma2000_0,
        &hf_link_subtype_cdma2000_a,
        &hf_link_subtype_cdma2000_b,
        &hf_link_subtype_cdma2000_c,
        NULL
};

static const int *subtype_ieee80216_fields[] = {
        &hf_link_subtype_ieee80216_25,
        &hf_link_subtype_ieee80216_35,
        NULL
};

static const value_string servicevalues[] = {
{1, "Service Management"},
{2, "Event Service"},
{3, "Command Service"},
{4, "Information Service"},
{0, NULL}
};

static const value_string opcodevalues[] = {
{0, "Confirm"},
{1, "Request"},
{2, "Response"},
{3, "Indication"},
{0, NULL},
};

static const value_string link_ac_result_vals[] = {
{0, "Success"},
{1, "Failure"},
{2, "Refused"},
{3, "Incapable"},
{0, NULL},
};

static const value_string serv_act_id_values[] = {
{1, "MIH_Capability_Discover"},
{2, "MIH_Register"},
{3, "MIH_DeRegister"},
{4, "MIH_Event_Subscribe"},
{5, "MIH_Event_Unsubscribe"},
{0, NULL}
};

static const value_string event_act_id_values[] = {
{1, "MIH_Link_Detected"},
{2, "MIH_Link_UP"},
{3, "MIH_Link_Down"},
{5, "MIH_Link_Parameter_Report"},
{6, "MIH_Link_Going_down"},
{7, "MIH_Link_Handover_Imminent"},
{8, "MIH_Handover_Complete"},
{0, NULL}
};

static const value_string status_types[] = {
{0, "Success"},
{1, "Unspecified Failure"},
{2, "Rejected"},
{3, "Authorization Failure"},
{4, "Network Error"},
{0, NULL}
};

static const value_string ho_status_vals[] = {
{0, "Handover Permitted"},
{1, "Handover Declined"},
{0, NULL}
};

static const value_string mbb_ho_supp_vals[] = {
{0, "Make before break is not supported."},
{1, "Make before break is supported."},
{0, NULL}
};

static const value_string reg_request_code_vals[] = {
{0, "Make"},
{1, "Re-Registration"},
{0, NULL}
};

static const value_string ip_renewal_vals[] = {
{0, "Change Not Requiered"},
{1, "Change Required"},
{0, NULL}
};

static const value_string dev_states_req_vals[] = {
{0, "DEVICE_INFO"},
{1, "BATT_LEVEL"},
{0, NULL}
};

static const value_string link_addr_types[] ={
{0, "MAC_ADDR"},
{1, "3GPP_3G_CELL_ID"},
{2, "3GPP_2G_CELL_ID"},
{3, "3GPP_ADDR"},
{4, "3GPP2_ADDR"},
{5, "OTHER_L2_ADDR"},
{0, NULL}
};

static const value_string threshold_x_dir_vals[] ={
{0, "Above Threshold"},
{1, "Below Threshold"},
{0, NULL}
};

static const value_string threshold_action_vals[] ={
{0, "Set Normal Threshold"},
{1, "Set one-shot Threshold"},
{2, "Cancel Threshold"},
{0, NULL}
};

static const value_string boolean_types[] ={
{0, "False"},
{1, "True"},
{0, NULL}
};

static const value_string command_act_id_values[] = {
{1, "MIH_Link_Get_Parameters"},
{2, "MIH_Link_Configure_Thresholds"},
{3, "MIH_Link_Actions"},
{4, "MIH_Net_HO_Candidate_Query"},
{5, "MIH_MN_HO_Candidate_Query"},
{6, "MIH_N2N_HO_Query_Resources"},
{7, "MIH_MN_HO_Commit"},
{8, "MIH_Net_HO-Commit"},
{9, "MN_N2N_HO_Commit"},
{10, "MIH_MN_HO_Complete"},
{11, "MIH_N2N_HO_Complete"},
{12, "MIH_Net_HO_Best_Commit"},
{0, NULL}
};

static const value_string info_act_id_values[] = {
{1, "MIH_Get_Information"},
{2, "MIH_Push_information"},
{0, NULL}
};

static const value_string link_dn_reason_vals[] = {
{0, "Explicit Disconnect"},
{1, "Packet Timeout"},
{2, "No resource"},
{3, "No broadcast"},
{4, "Authentication Failure"},
{5, "Billing Failure"},
{0, NULL}
};

static const value_string link_gdn_reason_vals[] = {
{0, "Explicit Disconnect"},
{1, "Link Parameter Degrading"},
{2, "Low Power"},
{3, "No resource"},
{0, NULL}
};

static const value_string link_type_vals[] = {
{0, "Reserved"},
{1, "Wireless - GSM"},
{2, "Wireless - GPRS"},
{3, "Wireless - EDGE"},
{15, "Ethernet"},
{18, "Wireless - Other"},
{19, "Wireless - IEEE 802.11"},
{22, "Wireless - CDMA2000"},
{23, "Wireless - UMTS"},
{24, "Wireless - cdma2000-HRPD"},
{27, "Wireless - IEEE 802.16"},
{28, "Wireless - IEEE 802.20"},
{29, "Wireless - IEEE 802.22"},
{40, "DVB"},
{41, "T-DMB"},
{42, "ATSC-M/H"},
{0, NULL}
};

static const value_string link_param_gen_vals[] = {
{0, "Data Rate"},
{1, "Signal Strength"},
{2, "SINR"},
{3, "Throughput"},
{4, "Packet Error Rate"},
{5, "Channel Frequency"},
{6, "Channel Bandwidth"},
{7, "Channel TX Power"},
{8, "Higher Adjacent Channel Frequency"},
{9, "Higher Adjacent Channel Bandwidth"},
{10, "Higher Adjacent Channel TX Power"},
{11, "Lower Adjacent Channel Frequency"},
{12, "Lower Adjacent Channel Bandwidth"},
{13, "Lower Adjacent Channel TX Power"},
{0, NULL}
};

static const value_string link_ac_type_vals[] = {
{0, "NONE"},
{1, "LINK_DISCONNECT"},
{2, "LINK_LOW_POWER"},
{3, "LINK_POWER_DOWN"},
{4, "LINK_POWER_UP"},
{5, "LINK_CONFIGURE"},
{0, NULL}
};

static const value_string link_param_gg_vals[] = {
{0, "Rx Qual"},
{1, "RsLev"},
{2, "Mean BEP"},
{3, "StDev BEP"},
{0, NULL}
};

static const value_string link_param_fdd_vals[] = {
{0, "CPICH RSCP"},
{1, "PCCPCH RSCP"},
{2, "UTRA carrier RSSI"},
{3, "GSM carrier RSSI"},
{4, "CPICH Ec/No"},
{5, "Transport channel BLER"},
{6, "User equipment (UE) transmitted power"},
{0, NULL}
};

static const value_string link_param_802_11_vals[] = {
{0, "RSSI"},
{1, "No QoS resource Available"},
{2, "Multiast packet loss rate"},
{0, NULL}
};

static const value_string op_mode_vals[] = {
{0, "Normal Mode"},
{1, "Power Saving Mode"},
{2, "Powered Down"},
{0, NULL}
};

static const value_string link_param_qos_vals[] = {
{0, "Max no of differentiable classes"},
{1, "Min Packet transfer delay"},
{2, "Avg packet transfer delay"},
{3, "Max packet transfer delay"},
{4, "delay jitter"},
{5, "Packet loss"},
{0, NULL}
};

static const value_string link_param_c2k_hrpd_vals[] = {
{0, "Pilot Strength"},
{0, NULL}
};

static const value_string typevaluenames[] = {
{ 1, "Source MIHIF ID" },
{ 2, "Destination MIHIF ID" },
{ 3, "Status" },
{ 4, "Link type" },
{ 5, "MIH event list" },
{ 6, "MIH command list" },
{ 7, "MIIS query type list" },
{ 8, "Transport option list" },
{ 9, "Link address list" },
{ 10, "MBB handover support" },
{ 11, "Register request code" },
{ 12, "Valid time interval" },
{ 13, "Link identifier" },
{ 14, "New Link identifier" },
{ 15, "Old access router" },
{ 16, "New access  router" },
{ 17, "IP renewal flag" },
{ 18, "Mobility management support" },
{ 19, "IP address configuration methods" },
{ 20, "Link down reason code" },
{ 21, "Time interval" },
{ 22, "Link going down reason" },
{ 23, "Link parameter report list" },
{ 24, "Device states request" },
{ 25, "Link identifier list" },
{ 26, "Device states response list" },
{ 27, "Get status request set" },
{ 28, "Get status response list" },
{ 29, "Configure request list" },
{ 30, "Configure response list" },
{ 31, "List of link PoA list" },
{ 32, "Preferred link list" },
{ 33, "Handover resource query list" },
{ 34, "Handover status" },
{ 35, "Access router address" },
{ 36, "DHCP server address" },
{ 37, "FA address" },
{ 38, "Link actions list" },
{ 39, "Link actions result list" },
{ 40, "Handover result" },
{ 41, "Resource status" },
{ 42, "Resource retention status" },
{ 43, "Info query binary data list" },
{ 44, "Info query RDF data list" },
{ 45, "Info query RDF schema URL" },
{ 46, "Info query RDF schema list" },
{ 47, "Max response size" },
{ 48, "Info response binary data list" },
{ 49, "Info response RDF data list" },
{ 50, "Info response RDF schema URL list" },
{ 51, "Info response RDF schema list" },
{ 52, "Mobile node MIHF ID" },
{ 53, "Query resource report flag" },
{ 54, "Event configuration info list" },
{ 55, "Target network info" },
{ 56, "List of target network info" },
{ 57, "Assigned resource set" },
{ 58, "Link detected info list" },
{ 59, "MN link ID" },
{ 60, "PoA" },
{ 61, "Unauthenticated information request" },
{ 62, "Network type" },
{ 63, "Requested resource set" },
{0, NULL}
};

static gint16 dissect_mih_list(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree, gint16 (*base_dissect)(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree))
{
        guint8 i = 0;
        guint8 list_len = tvb_get_guint8(tvb, offset);
        offset ++;
        for(i=0; i < list_len; i++)
                offset = base_dissect(tvb, offset, tlv_tree);
        return (offset);
}

static gint16 dissect_ip_addr(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint16 addr_type = tvb_get_ntohs(tvb, offset);
        guint8 len = 0;
        if(addr_type == 1 )
        {
                /*IPv4 Addr*/
                len = tvb_get_guint8(tvb, offset + 3);
                proto_tree_add_item(tlv_tree, hf_ipv4_addr, tvb, offset+2, len, ENC_BIG_ENDIAN);
                return (offset+3+len);
        }
        if(addr_type == 2)
        {
                /*IPv6 Addr*/
                len = tvb_get_guint8(tvb, offset + 3);
                proto_tree_add_item(tlv_tree,hf_ipv6_addr, tvb, offset+2, len, ENC_NA);
                return (offset+3+len);
        }
        else
        {
                len = tvb_get_guint8(tvb, offset + 3);
                return (offset+3+len);
        }
}

static gint16 dissect_qos_val(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        proto_tree_add_item(tlv_tree, hf_cos_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++ ;
        proto_tree_add_item(tlv_tree, hf_cos_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        return (offset);
}

static gint16 dissect_link_addr(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree )
{
        guint8 link_addr_choice = tvb_get_guint8(tvb, offset);
        guint8 len = 0;

        proto_tree_add_item(tlv_tree, hf_link_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        switch (link_addr_choice)
        {
        case 0 : /*MAC_ADDR*/
                proto_tree_add_item(tlv_tree, hf_link_transport_addr_type, tvb, offset+1, 2, ENC_BIG_ENDIAN);
                if(tvb_get_ntohs(tvb, offset+1) == 0x06)
                        proto_tree_add_item(tlv_tree, hf_mac_addr, tvb, offset+4, tvb_get_guint8(tvb, offset+3), ENC_NA);
                return (offset + 10);

        case 1 :/*3GPP_3G_CELL_ID*/
                proto_tree_add_item(tlv_tree, hf_plmn_id, tvb, offset+1, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cell_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                return (offset + 8);

        case 2 :/*3GPP_2G_CELL_ID*/
                proto_tree_add_item(tlv_tree, hf_plmn_id, tvb, offset+1, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_location_area_id, tvb, offset+4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_ci, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                return (offset + 8);

        case 3 :/*3GPP_ADDR*/
        case 4 :/*3GPP2_ADDR*/
        case 5 :/*OTHER_L2_ADDR*/
                len = tvb_get_guint8(tvb, offset+1);
                proto_tree_add_item(tlv_tree, hf_link_addr_string, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                return (offset + 2 + len);
        }
        return 0;
}

static gint16 dissect_tsp_container(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        if(tvb_get_guint8(tvb, offset) == 1)
        {
                proto_tree_add_item(tlv_tree, hf_predef_cfg_id, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                return (offset + 2);
        }
        else if(tvb_get_guint8(tvb, offset) == 2)
        {
                len = tvb_get_guint8(tvb, offset+1);
                proto_tree_add_item(tlv_tree, hf_tsp_carrier, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                return (offset + len + 2);
        }
        else
                return (offset + 1);
}

static gint16 dissect_iq_rdf_data(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        if(tvb_get_guint8(tvb, offset))
        {
                len = tvb_get_guint8(tvb, offset+1);
                proto_tree_add_item(tlv_tree, hf_rdf_mime_type, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                offset += len + 1;
        }
        offset++;
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tlv_tree, hf_rdf_data, tvb, offset+1, len, ENC_ASCII|ENC_NA);
        return (offset+len+1);
}

static gint16 dissect_qos_list(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        proto_tree *subtree;

        proto_tree_add_item(tlv_tree, hf_num_cos, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_min_pk_tx_delay, NULL, "MIN_PK_TX_DELAY");
        offset = dissect_mih_list(tvb, offset, subtree, dissect_qos_val);
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_avg_pk_tx_delay, NULL, "AVG_PK_TX_DELAY");
        offset = dissect_mih_list(tvb, offset, subtree, dissect_qos_val);
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_max_pk_tx_delay, NULL, "MAX_PK_TX_DELAY");
        offset = dissect_mih_list(tvb, offset, subtree, dissect_qos_val);
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_pk_delay_jitter, NULL, "PK_DELAY_JITTER");
        offset = dissect_mih_list(tvb, offset, subtree, dissect_qos_val);
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_pk_loss_rate, NULL, "PK_LOSS_RATE");
        offset = dissect_mih_list(tvb, offset, subtree, dissect_qos_val);
        return (offset);
}

static gint16 dissect_dev_states(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        proto_tree *sub_tree = NULL;

        sub_tree = proto_tree_add_item(tlv_tree, hf_dev_states_resp, tvb, offset, 1, ENC_BIG_ENDIAN);
        if(tvb_get_guint8(tvb, offset))
        {
                /*BATT_LEVEL*/
                offset++;
                proto_tree_add_item(sub_tree, hf_dev_batt_level, tvb, offset, 1, ENC_BIG_ENDIAN);
                return (offset+1);
        }
        else
        {
                /*DEVICE INFO*/
                offset++;
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(sub_tree, hf_dev_info, tvb, offset+1, len, ENC_ASCII|ENC_NA);
                return (offset + len + 1);

        }
}

static gint16 dissect_net_type(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        guint8 type = 0;
        if(!tvb_get_guint8(tvb, offset))
        {
                /*LINK_TYPE*/
                type = tvb_get_guint8(tvb, offset+1);
                proto_tree_add_item(tlv_tree, hf_link_type, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                offset += 1;
        }
        offset += 1;
        if(!tvb_get_guint8(tvb, offset))
        {
                /*LINK_SUBTYPE*/
                switch (type)
                {
                        /* last 32 bits are not read since proto_tree_add_bitmask only handles bitmasks of length 32
                         Even though the standard defines a bitmasks of length 64, there are no definitions in the standard that require more than 32 bits
                         1 (identifier) + 4(bitmask defined values) + 4 (unused bits) = 9 (final offset)*/
                        case 15 : /*subtype ethernet*/
                                proto_tree_add_bitmask(tlv_tree, tvb, offset+1, hf_link_subtype_eth, ett_subtype_eth_bitmap, subtype_eth_fields, ENC_BIG_ENDIAN);
                                break;
                        case 18 : /*subtype wireless other*/
                                proto_tree_add_bitmask(tlv_tree, tvb, offset+1, hf_link_subtype_wireless_other, ett_subtype_wireless_other_bitmap, subtype_wireless_other_fields, ENC_BIG_ENDIAN);
                                break;
                        case 19 : /*subtype 802.11*/
                                proto_tree_add_bitmask(tlv_tree, tvb, offset+1, hf_link_subtype_ieee80211, ett_subtype_ieee80211_bitmap, subtype_ieee80211_fields, ENC_BIG_ENDIAN);
                                break;
                        case 23 : /*subtype UMTS*/
                                proto_tree_add_bitmask(tlv_tree, tvb, offset+1, hf_link_subtype_umts, ett_subtype_umts_bitmap, subtype_umts_fields, ENC_BIG_ENDIAN);
                                break;
                        case 24 : /*subtype cdma2000*/
                                proto_tree_add_bitmask(tlv_tree, tvb, offset+1, hf_link_subtype_cdma2000, ett_subtype_cdma2000_bitmap, subtype_cdma2000_fields, ENC_BIG_ENDIAN);
                                break;
                        case 27 : /*subtype 802.16*/
                                proto_tree_add_bitmask(tlv_tree, tvb, offset+1, hf_link_subtype_ieee80216, ett_subtype_ieee80216_bitmap, subtype_ieee80216_fields, ENC_BIG_ENDIAN);
                                break;
                        default :
                                proto_item_append_text(tlv_tree, "N/A");
                }
                /*4(bitmask defined values) + 4 (unused bits) = 8 bits*/
                offset += 8;
        }
        /*1 (identifier) = 1 bit*/
        offset += 1;
        if(!tvb_get_guint8(tvb, offset))
        {
                /*TYPE_EXT*/
                len = tvb_get_guint8(tvb, offset+1);
                proto_tree_add_item(tlv_tree, hf_link_type_ext, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                offset += len + 2;
        }
        return (offset);
}

static gint16 dissect_net_type_addr(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_net_type(tvb, offset, tlv_tree);
        offset = dissect_link_addr(tvb, offset, tlv_tree);
        return (offset) ;
}

static gint16 dissect_mbb_ho_supp(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_net_type(tvb, offset, tlv_tree);
        offset = dissect_net_type(tvb, offset, tlv_tree);
        proto_tree_add_item(tlv_tree, hf_mbb_ho_supp, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        return (offset);
}

static gint16 dissect_tgt_net_info(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        if(!tvb_get_guint8(tvb, offset))
        {
                offset +=1;

                /*NETWORK_ID*/
                len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tlv_tree, hf_network_id, tvb, offset+1, len, ENC_ASCII|ENC_NA);
                offset += len + 2;
                if(!tvb_get_guint8(tvb, offset))
                {
                        /*NET_AUX_ID*/
                        offset +=1;
                        len = tvb_get_guint8(tvb, offset);
                        proto_tree_add_item(tlv_tree, hf_net_aux_id, tvb, offset+1, len, ENC_ASCII|ENC_NA);
                        return (offset + 1);
                }
                return (offset + 2);
        }
        else
        {
                /*LINK_ADDR*/
                offset +=1;
                offset = dissect_link_addr(tvb, offset, tlv_tree);
                return (offset);
        }
}

static gint16 dissect_link_id(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{

        gint16 next_offset = 0;

        /*LINK_TYPE*/
        proto_tree_add_item(tlv_tree, hf_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        next_offset = dissect_link_addr(tvb, offset+1, tlv_tree);
        return (next_offset);
}

static gint16 dissect_link_poa(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_link_id(tvb, offset, tlv_tree);
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_addr);
        return (offset);
}

static gint16 dissect_rq_result(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        proto_tree *subtree;
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_list_prefer_link, NULL, "List of preferred links");
        offset = dissect_link_poa(tvb, offset, subtree);
        offset = dissect_qos_list(tvb, offset, tlv_tree);
        offset++;
        switch(tvb_get_guint8(tvb, offset-1))
        {
                case 1:
                        proto_tree_add_item(tlv_tree, hf_ip_methods_supported, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                case 2:
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_cfg_mthds, ett_cfg_mtd_bitmap, cfg_fields, ENC_BIG_ENDIAN);
                        offset += 2;
                        break;
        }
        offset++;
        switch(tvb_get_guint8(tvb, offset-1))
        {
                case 1:
                        proto_tree_add_item(tlv_tree, hf_ip_dhcp_services, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                case 2: subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_ip_dhcp_server, NULL, "IP DHCP server");
                        offset = dissect_ip_addr(tvb, offset, subtree);
                        break;
        }
        offset++;
        switch(tvb_get_guint8(tvb, offset-1))
        {
                case 1:
                        proto_tree_add_item(tlv_tree, hf_fn_agent, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                case 2: subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_fn_agent, NULL, "FN Agent");
                        offset = dissect_ip_addr(tvb, offset, subtree);
                        break;
        }
        offset++;
        switch(tvb_get_guint8(tvb, offset-1))
        {
                case 1:
                        proto_tree_add_item(tlv_tree, hf_access_router, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                case 2: subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 1, ett_access_router, NULL, "Access Router");
                        offset = dissect_ip_addr(tvb, offset, subtree);
                        break;
        }
        return (offset+1);
}

static gint16 dissect_link_det_info(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        offset = dissect_link_id(tvb, offset, tlv_tree);
        if(tvb_get_guint8(tvb, offset))
        {
                offset++;
                offset = dissect_link_addr(tvb, offset, tlv_tree);
                offset --;
        }
        offset++;
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tlv_tree, hf_network_id, tvb, offset+1, len, ENC_ASCII|ENC_NA);
        offset += len + 1;
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tlv_tree, hf_net_aux_id, tvb, offset+1, len, ENC_ASCII|ENC_NA);
        offset += len + 1;
        if(tvb_get_guint8(tvb, offset))
                proto_tree_add_item(tlv_tree, hf_sig_strength_per, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        else
                proto_tree_add_item(tlv_tree, hf_sig_strength_dbm, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tlv_tree, hf_sinr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tlv_tree, hf_link_data_rate, tvb, offset,4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_mihcap, ett_mihcap_bitmap, mihcap_fields, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_net_caps, ett_net_caps_bitmap, net_caps_fields, ENC_BIG_ENDIAN);
        offset += 4;
        return (offset);
}

static gint16 dissect_link_scan_rsp(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        offset = dissect_link_addr(tvb, offset, tlv_tree);
        len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tlv_tree, hf_network_id, tvb, offset+1, len, ENC_ASCII|ENC_NA);
        offset = offset + len + 1;
        if(tvb_get_guint8(tvb, offset))
                proto_tree_add_item(tlv_tree, hf_sig_strength_per, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        else
                proto_tree_add_item(tlv_tree, hf_sig_strength_dbm, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        return offset+2;
}

static gint16 dissect_link_action_rsp(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_link_id(tvb, offset, tlv_tree);
        proto_tree_add_item(tlv_tree, hf_link_ac_result, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if(tvb_get_guint8(tvb, offset))
        {
                offset = dissect_mih_list(tvb, offset+1, tlv_tree, dissect_link_scan_rsp);
                return offset;
        }
        else
                return (offset+1);

}

static gint16 dissect_link_action_req(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_link_id(tvb, offset, tlv_tree);
        if(tvb_get_guint8(tvb, offset))
        {
                offset = dissect_link_addr(tvb, offset+1, tlv_tree);
        }
        else
        {
                offset++;
        }
        proto_tree_add_item(tlv_tree, hf_link_ac_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_link_ac_attr, ett_ac_attr_bitmap, ac_attr_fields, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tlv_tree, hf_link_ac_ext_time, tvb, offset, 2, ENC_BIG_ENDIAN);
        return (offset+2);
}

static gint16 dissect_link_states_rsp(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        if(!tvb_get_guint8(tvb, offset))
        {
                proto_tree_add_item(tlv_tree, hf_op_mode, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                offset += 2;
        }
        else
        {
                proto_tree_add_item(tlv_tree, hf_channel_id, tvb, offset+1, 2, ENC_BIG_ENDIAN);
                offset += 3;
        }
        return (offset);
}

static gint16 dissect_link_param_type(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 type = tvb_get_guint8(tvb, offset);
        offset++;

        /*LINK_PARAM_TYPE*/
        switch (type)
        {
                case 0 :/*LINK_PARAM_GEN*/
                        proto_tree_add_item(tlv_tree, hf_link_param_gen, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 1 :/*LINK_PARAM_QOS*/
                        proto_tree_add_item(tlv_tree, hf_link_param_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 2 :/*LINK_PARAM_GG*/
                        proto_tree_add_item(tlv_tree, hf_link_param_gg, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 3 :/*LINK_PARAM_EDGE*/
                        proto_tree_add_item(tlv_tree, hf_link_param_edge, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 4 :/*LINK_PARAM_ETH*/
                        proto_tree_add_item(tlv_tree, hf_link_param_eth, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 5 :/*LINK_PARAM_802_11*/
                        proto_tree_add_item(tlv_tree, hf_link_param_802_11, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 6 :/*LINK_PARAM_C2K*/
                         proto_tree_add_item(tlv_tree, hf_link_param_c2k, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 7 :/*LINK_PARAM_FDD*/
                        proto_tree_add_item(tlv_tree, hf_link_param_fdd, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 8 :/*LINK_PARAM_HRPD*/
                        proto_tree_add_item(tlv_tree, hf_link_param_hrpd, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 9 :/*LINK_PARAM_802_16*/
                        proto_tree_add_item(tlv_tree, hf_link_param_802_16, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 10 :/*LINK_PARAM_802_20*/
                        proto_tree_add_item(tlv_tree, hf_link_param_802_20, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case 11 :/*LINK_PARAM_802_22*/
                        proto_tree_add_item(tlv_tree, hf_link_param_802_22, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;
        }
        return (offset+1);
}

static void dissect_link_status_req(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        proto_tree *subtree;

        /*LINK_STATES_REQ*/
        guint16 temp = tvb_get_ntohs(tvb, offset);
        if(!temp)
        {
                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 3, ett_link_states_req, NULL, "LINK_STATES_REQ: ");
                proto_tree_add_item(subtree, hf_op_mode, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                offset+=3;
        }
        else
        {
                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 4, ett_link_states_req, NULL, "LINK_STATES_REQ: ");
                proto_tree_add_item(subtree, hf_channel_id, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                offset+=4;
        }

        /*LINK_PARAM_TYPE_LIST*/
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_param_type);

        /*LINK_DESC_REQ*/
        temp = tvb_get_ntohs(tvb, offset);
        subtree = proto_tree_add_subtree(tlv_tree, tvb, offset, 3, ett_link_desc_req, NULL, "LINK_DESC_REQ");
        offset+=2;
        if(!temp)
                proto_tree_add_item(subtree, hf_num_cos, tvb, offset, 1, ENC_BIG_ENDIAN);
        else
                proto_tree_add_item(subtree, hf_num_queue, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static gint16 dissect_link_cfg_status(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_link_param_type(tvb, offset, tlv_tree);
        proto_tree_add_item(tlv_tree, hf_threshold_val, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tlv_tree, hf_threshold_x_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        proto_tree_add_item(tlv_tree, hf_config_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        return (offset+1);
}

static gint16 dissect_link_param(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        /*LINK_PARAM_TYPE*/
        offset = dissect_link_param_type(tvb, offset, tlv_tree);
        if(!tvb_get_guint8(tvb, offset))
        {
                offset ++;
                /*LINK_PARAM_VALUE*/
                proto_tree_add_item(tlv_tree, hf_link_param_value, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
        }
        else
        {
                proto_tree *subtree;
                offset ++;
                /*QOS_PARAM_VALUE*/
                switch(tvb_get_guint8(tvb, offset))
                {
                        case 0:
                                proto_tree_add_item(tlv_tree, hf_num_cos, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                offset += 2;
                                break;
                        case 1:
                                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset+1, 1, ett_min_pk_tx_delay, NULL, "MIN_PK_TX_DELAY");
                                offset = dissect_mih_list(tvb, offset+1, subtree, dissect_qos_val);
                                break;
                        case 2:
                                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset+1, 1, ett_avg_pk_tx_delay, NULL, "AVG_PK_TX_DELAY");
                                offset = dissect_mih_list(tvb, offset+1, subtree, dissect_qos_val);
                                break;
                        case 3:
                                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset+1, 1, ett_max_pk_tx_delay, NULL, "MAX_PK_TX_DELAY");
                                offset = dissect_mih_list(tvb, offset+1, subtree, dissect_qos_val);
                                break;
                        case 4:
                                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset+1, 1, ett_pk_delay_jitter, NULL, "PK_DELAY_JITTER");
                                offset = dissect_mih_list(tvb, offset+1, subtree, dissect_qos_val);
                                break;
                        case 5:
                                subtree = proto_tree_add_subtree(tlv_tree, tvb, offset+1, 1, ett_pk_loss_rate, NULL, "PK_LOSS_RATE");
                                offset = dissect_mih_list(tvb, offset+1, subtree, dissect_qos_val);
                                break;
                }
        }
        return offset;
}

static gint16 dissect_link_param_rpt(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        /*LINK_PARAM*/
        offset = dissect_link_param(tvb, offset, tlv_tree);
        if(tvb_get_guint8(tvb, offset))
        {
                /*Threshold*/
                offset++;
                proto_tree_add_item(tlv_tree, hf_threshold_val, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tlv_tree, hf_threshold_x_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
                return (offset+1);
        }
        else
                return (offset+1);
}

static gint16 dissect_link_desc_rsp(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        if(!tvb_get_guint8(tvb, offset))
                proto_tree_add_item(tlv_tree, hf_num_cos, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        else
                proto_tree_add_item(tlv_tree, hf_num_queue, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        return (offset+2);
}

static gint16 dissect_status_list(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        /*LINK_ID*/
        offset = dissect_link_id(tvb, offset, tlv_tree);

        /*LINK_STATES_RSP*/
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_states_rsp);

        /*LINK_PARAM*/
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_param);

        /*LINK_DESC_RSP*/
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_desc_rsp);
        return offset;
}

static gint16 dissect_link_det_cfg(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        guint8 len = 0;
        if(tvb_get_guint8(tvb, offset))
        {
                len = tvb_get_guint8(tvb, offset+1);
                proto_tree_add_item(tlv_tree, hf_network_id, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                offset += len + 1;
        }
        offset++;
        if(tvb_get_guint8(tvb, offset))
        {
                if(tvb_get_guint8(tvb, offset+1))
                        proto_tree_add_item(tlv_tree, hf_sig_strength_per, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                else
                        proto_tree_add_item(tlv_tree, hf_sig_strength_dbm, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                offset += 2;
        }
        offset++;
        if(tvb_get_guint8(tvb, offset))
        {
                proto_tree_add_item(tlv_tree, hf_link_data_rate, tvb, offset+1,4, ENC_BIG_ENDIAN);
                offset += 4;
        }
        return (offset+1);
}

static gint16 dissect_link_cfg_param(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_link_param_type(tvb, offset, tlv_tree);
        if(tvb_get_guint8(tvb, offset))
        {
                proto_tree_add_item(tlv_tree, hf_time_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
        }
        offset++;
        proto_tree_add_item(tlv_tree, hf_threshold_action, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tlv_tree, hf_threshold_val, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tlv_tree, hf_threshold_x_dir, tvb, offset, 1, ENC_BIG_ENDIAN);
        return (offset+1) ;
}

static gint16 dissect_mih_evt_cfg_info(tvbuff_t *tvb, gint16 offset, proto_tree *tlv_tree)
{
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_det_cfg);
        offset = dissect_mih_list(tvb, offset, tlv_tree, dissect_link_cfg_param);
        return offset;
}

static void dissect_mih_tlv(tvbuff_t *tvb,int offset, proto_tree *tlv_tree, guint8 type, guint32 length)
{

        guint8 mihf_id_len = 0;
        char mihf_id_first_char = 0;
        guint8 i = 0;
        guint8 len = 0;

        tvbuff_t *volatile tvb_mihf_id = NULL;
        tvbuff_t* tvb_temp = NULL;
        volatile gboolean composite_error = FALSE;

        /*For Value fields*/
        switch (type)
        {
                case SRC_MIHF_ID :
                case DEST_MIHF_ID :
                case MN_MIHF_ID :
                        /*MIHF ID*/
                        mihf_id_len = tvb_get_guint8(tvb, offset);
                        /*taken from the 802.21 standard:
                        If L2 communication is used then MIHF_ID is the NAI-encoded linklayer
                        address (LINK_ADDR) of the entity that hosts the MIH services.
                        In an NAI-encoded IP address or link-layer address, each octet
                        of binary-encoded IP4_ADDR, IP6_ADDR and LINK_ADDR data is
                        encoded in the username part of the NAI as "\" followed by the octet
                        value.*/
                        mihf_id_first_char = (char)tvb_get_guint8(tvb, offset+1);
                        if(mihf_id_first_char!='\\')
                                proto_tree_add_item(tlv_tree, hf_mihf_id, tvb, offset+1, mihf_id_len, ENC_ASCII|ENC_NA);
                        else
                        {
                                if(mihf_id_len<tvb_reported_length_remaining(tvb,0) && (mihf_id_len==12 || mihf_id_len==64 || mihf_id_len==128))
                                {
                                        tvb_mihf_id = tvb_new_composite();
                                        for(i=0; i < mihf_id_len/2; i++)
                                        {
                                                tvb_temp = tvb_new_subset_length(tvb, offset + 2 + 2*i, 1);
                                                tvb_composite_append(tvb_mihf_id, tvb_temp);
                                        }
                                        TRY
                                        {
                                                tvb_composite_finalize(tvb_mihf_id);
                                        }
                                        CATCH_ALL
                                        {
                                                composite_error = TRUE;
                                        }
                                        ENDTRY;

                                        if(!composite_error)
                                        {
                                                switch(mihf_id_len)
                                                {
                                                        case 12:  /* checks if the length corresponds to a MAC address */
                                                                proto_tree_add_item(tlv_tree, hf_mihf_id_mac, tvb_mihf_id, 0, mihf_id_len/2, ENC_NA);
                                                                break;
                                                        case 64:  /* checks if the length corresponds to an IPv4 address */
                                                                proto_tree_add_item(tlv_tree, hf_mihf_id_ipv4, tvb_mihf_id, 0, mihf_id_len/2, ENC_BIG_ENDIAN);
                                                                break;
                                                        case 128: /* checks if the length corresponds to an IPv6 address */
                                                                proto_tree_add_item(tlv_tree, hf_mihf_id_ipv6, tvb_mihf_id, 0, mihf_id_len/2, ENC_NA);
                                                                break;
                                                }
                                        }
                                        else
                                                tvb_free(tvb_mihf_id);
                                }
                        }
                        break;

                case STATUS :
                        /*STATUS*/
                        proto_tree_add_item(tlv_tree, hf_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case LINK_TYPE :
                        /*LINK_TYPE*/
                        proto_tree_add_item(tlv_tree, hf_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case MIH_EVT_LIST :
                        /*MIH_EVT_LIST*/
                        proto_tree_add_bitmask(tlv_tree/*evt_list_tree*/, tvb, offset, hf_event_list, ett_event_bitmap, event_fields, ENC_BIG_ENDIAN);
                        break;

                case MIH_CMD_LIST :
                        /*MIH_CMD_LSIT*/
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_cmd_list, ett_cmd_bitmap, cmd_fields, ENC_BIG_ENDIAN);
                        break;

                case MIH_IQ_TYPE_LIST :
                        /*MIH_IQ_TYPE_LIST*/
                        /*last 32 bits are not read since proto_tree_add_bitmask only handles bitmasks of length 32
                         Even though the standard defines a bitmasks of length 64, there are no definitions in the standard that require more than 32 bits*/
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_iq_list, ett_iq_type_bitmap, iq_type_fields, ENC_BIG_ENDIAN);
                        break;

                case MIH_TRANS_LIST :
                        /*MIH_TRANS_LIST*/
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_trans_list, ett_trans_list_bitmap, trans_fields, ENC_BIG_ENDIAN);
                        break;

                case LINK_ADDR_LIST :
                        /*NET_TYPE_ADDR_LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_net_type_addr);
                        break;

                case MBB_HO_SUPP_LIST :
                        /*MBB_HO_SUPP_LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_mbb_ho_supp);
                        break;

                case REG_REQUEST_CODE :
                        /*REG_REQUEST_CODE*/
                        proto_tree_add_item(tlv_tree, hf_reg_request_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case VALID_TIME_INTR :
                        /*Valid Time interval*/
                        proto_tree_add_item(tlv_tree, hf_valid_time_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
                        break;

                case LINK_ID :
                case NEW_LINK_ID :
                case MN_LINK_ID :
                        /*Link identifier*/
                        dissect_link_id(tvb, offset, tlv_tree);
                        break;

                case OLD_ACCESS_ROUTER :
                case NEW_ACCESS_ROUTER :
                case POA_LINK_ADDR :
                        /*LINK ADDR*/
                        dissect_link_addr(tvb, offset, tlv_tree);
                        break;

                case IP_RENEWAL_FLAG :
                        /*IP_RENEWAL_FLAG*/
                        proto_tree_add_item(tlv_tree, hf_ip_renewal, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case IP_MOB_MGMT :
                        /*IP_MOB_MGMT*/
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_mob_list, ett_mob_mgt_bitmap, mob_fields, ENC_BIG_ENDIAN);
                        break;

                case IP_CFG_MTHDS :
                        /*IP_CFG_MTHDS*/
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_cfg_mthds, ett_cfg_mtd_bitmap, cfg_fields, ENC_BIG_ENDIAN);
                        break;

                case LINK_DN_REASON :
                        /*LINK_DN_REASON*/
                        proto_tree_add_item(tlv_tree, hf_link_dn_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case TIMER_INTERVAL :
                        /*Time interval*/
                        proto_tree_add_item(tlv_tree, hf_time_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
                        break;

                case LINK_GOING_DN_REASON :
                        /*LINK_GOING_DN REASON*/
                        proto_tree_add_item(tlv_tree, hf_link_gdn_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case LINK_PARAM_RPT_LIST :
                        /*LINK_PARAM_RPT_LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_param_rpt);
                        break;

                case DEV_STATES_REQ :
                        /*DEV_STATES_REQ*/
                        proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_dev_states_req, ett_dev_states_bitmap, dev_states_fields, ENC_BIG_ENDIAN);
                        break;

                case LINK_ID_LIST :
                        /*LINK ID List*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_id);
                        break;

                case DEV_STATES_RSP_LIST :
                        /*DEV_STATES_RSP List*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_dev_states);
                        break;

                case STATUS_REQ_SET :
                        /*LINK_STATUS_REQ*/
                        dissect_link_status_req(tvb, offset, tlv_tree);
                        break;

                case STATUS_RSP_LIST :
                        /*Status Response List*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_status_list);
                        break;

                case CFG_REQ_LIST :
                        /*LINK_CFG_PARAM_LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_cfg_param);
                        break;

                case CFG_RSP_LIST :
                        /*LINK_CFG_STATUS_LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_cfg_status);
                        break;

                case LINK_POA_LIST :
                        /*LINK_POA_LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_poa);
                        break;

                case PREF_LINK_LIST :
                        /*RQ_RESULT*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_rq_result);
                        break;

                case HO_REQ_QUERY_LIST :
                        /*QoS_LIST*/
                        dissect_qos_list(tvb, offset, tlv_tree);
                        break;

                case HO_STATUS:
                        /*HO_STATUS*/
                        proto_tree_add_item(tlv_tree, hf_ho_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case ACCESS_ROUTER_ADDR :
                case DHCP_SER_ADDR :
                case FA_ADDR :
                        /*IP_ADDR*/
                        dissect_ip_addr(tvb, offset, tlv_tree);
                        break;

                case LINK_ACTION_REQ_LIST :
                        /*LINK_ACTION_REQ LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_action_req);
                        break;

                case LINK_ACTION_RSP_LIST :
                        /*LINK_ACTION_RSP LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_action_rsp);
                        break;

                case HO_RESULT :
                        /*HO_RESULT*/
                        proto_tree_add_item(tlv_tree, hf_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case LINK_RES_STATUS :
                        /*LINK_RES_STATUS*/
                        proto_tree_add_item(tlv_tree, hf_link_res_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case RES_RETENTION_STATUS :
                        /*BOOLEAN*/
                        proto_tree_add_item(tlv_tree, hf_res_retention_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case IQ_RDF_SCHEMA_URL :
                        /*BOOLEAN*/
                        proto_tree_add_item(tlv_tree, hf_iq_rdf_sch_url, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case Q_RES_RPT_FLAG :
                        /*BOOLEAN*/
                        proto_tree_add_item(tlv_tree, hf_res_rpt_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case UNAUTH_INFO_REQ :
                        /*BOOLEAN*/
                        proto_tree_add_item(tlv_tree, hf_unauth_info_req, tvb, offset, 1, ENC_BIG_ENDIAN);
                        break;

                case IQ_BIN_DATA_LIST :
                        /*IQ_BIN_DATA LIST*/
                        proto_tree_add_item(tlv_tree, hf_iq_bin_data_x, tvb, offset, length, ENC_ASCII|ENC_NA);
                        break;

                case IQ_RDF_DATA_LIST :
                case IR_RDF_DATA_LIST :
                case IR_RDF_SCHM_LIST :
                        /*IQ_RDF_DATA LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_iq_rdf_data);
                        break;

                case IQ_RDF_SCHM_LIST :
                        /*IQ_RDF_SCHM*/
                        for(i=0; i < tvb_get_guint8(tvb, offset); i++)
                        {
                                len = tvb_get_guint8(tvb, offset+1);
                                proto_tree_add_item(tlv_tree, hf_rdf_sch, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                                offset += len;
                        }
                        break;

                case MAX_RSP_SIZE :
                        /*Max Response Size*/
                        proto_tree_add_item(tlv_tree, hf_max_resp_size, tvb, offset, 2, ENC_BIG_ENDIAN);
                        break;

                case IR_BIN_DATA_LIST :
                        /*IR_BIN_DATA LIST*/
                        proto_tree_add_item(tlv_tree, hf_ir_bin_data, tvb, offset, length, ENC_ASCII|ENC_NA);
                        break;

                case IR_SCHM_URL_LIST :
                        /*IR_SCHM_URL*/
                        for(i=0; i < tvb_get_guint8(tvb, offset); i++)
                        {
                                len = tvb_get_guint8(tvb, offset+1);
                                proto_tree_add_item(tlv_tree, hf_rdf_sch_url, tvb, offset+2, len, ENC_ASCII|ENC_NA);
                                offset += len;
                        }
                        break;

                case EVT_CFG_INFO_LIST :
                        /*EVT_CFG_INFO LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_mih_evt_cfg_info);
                        break;

                case TGT_NET_INFO :
                        /*TGT_NET_INFO*/
                        dissect_tgt_net_info(tvb, offset, tlv_tree);
                        break;

                case TGT_NET_INFO_LIST :
                        /*List of TGT_NET_INFO*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_tgt_net_info);
                        break;

                case ASGN_RES_SET :
                        /*ASGN_RES_SET*/
                        offset = dissect_qos_list(tvb, offset, tlv_tree);
                        dissect_tsp_container(tvb, offset, tlv_tree);
                        break;

                case LINK_DET_INFO_LIST :
                        /*LINK_DET_INFO LIST*/
                        dissect_mih_list(tvb, offset, tlv_tree, dissect_link_det_info);
                        break;

                case NET_TYPE :
                        /*NETWORK TYPE*/
                        dissect_net_type(tvb, offset, tlv_tree);
                        break;

                case REQ_RES_SET :
                        /*REQ_RES_SET*/
                        offset = dissect_qos_list(tvb, offset, tlv_tree);
                        offset = dissect_tsp_container(tvb, offset, tlv_tree);
                        proto_tree_add_item(tlv_tree, hf_ho_reason, tvb, offset, 1, ENC_BIG_ENDIAN );
                        break;

                case VEND_SPECIFIC_TLV :
                        /*Vendor specific tlv*/
                        proto_tree_add_item(tlv_tree, hf_vendor_specific_tlv, tvb, offset, length, ENC_ASCII|ENC_NA);
                        break;

                default :/*did not match type*/
                        /*do switch case for range of numbers*/

                        /*RESERVED TLVs*/
                        if(type > 63 && type < 100)
                                proto_tree_add_item(tlv_tree, hf_reserved_tlv, tvb, offset, length, ENC_ASCII|ENC_NA);

                                                /*EXPERIMENTAL TLVs*/
                        else if(type > 100 && type < 255)
                                proto_tree_add_item(tlv_tree, hf_experimental_tlv, tvb, offset, length, ENC_ASCII|ENC_NA);

                        /*UNKNOWN TLVs*/
                        else
                                proto_tree_add_item(tlv_tree, hf_unknown_tlv, tvb, offset, length, ENC_ASCII|ENC_NA);
        }
        return;
}

static int dissect_mih(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
        proto_item *ti = NULL;
        int offset = 0;
        proto_item *item = NULL;
        proto_tree *mih_tree = NULL;
        proto_tree *ver_flags_tree = NULL;
        guint8 serviceid = 0;
        guint8 opcode = 0;
        guint8 service = 0;
        guint16 action = 0;
        gint32 payload_length = 0;
        guint64 len = 0;
        guint8 len_of_len = 0;
        guint8 type = 0;
        proto_tree *mid_tree = NULL;
        proto_tree *tlv_tree = NULL;
        guint8 fragment = 0;

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIH");
        col_clear(pinfo->cinfo,COL_INFO);

        /* we are being asked for details */
        ti = proto_tree_add_item(tree, proto_mih, tvb, 0, -1, ENC_NA);
        mih_tree = proto_item_add_subtree(ti, ett_mih);
        if(mih_tree)
        {
                item = proto_tree_add_item(mih_tree, hf_mih_version, tvb, offset, 1, ENC_BIG_ENDIAN);

                ver_flags_tree = proto_item_add_subtree(item, ett_ver_flags);
                proto_tree_add_item(ver_flags_tree, hf_mih_version, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ver_flags_tree, hf_mih_ack_req, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ver_flags_tree, hf_mih_ack_resp, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ver_flags_tree, hf_mih_uir, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ver_flags_tree, hf_mih_more_frag, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        fragment = tvb_get_guint8(tvb, offset);
        fragment = fragment << 7;

        offset += 1;

        if(mih_tree)
        {
                /*flags and version tree is done.....*/
                proto_tree_add_item(mih_tree, hf_mih_frag_no, tvb, offset, 1, ENC_BIG_ENDIAN);

                /*for MIH message ID*/
                item = proto_tree_add_item(mih_tree, hf_mih_mid, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        }
        fragment = fragment + (tvb_get_guint8(tvb, offset)>>1);
        offset += 1;
        mid_tree = proto_item_add_subtree(item, ett_mid);
        serviceid = tvb_get_guint8(tvb, offset);
        serviceid = serviceid & 0xF0;
        serviceid >>= 4;
        proto_tree_add_item(mid_tree, hf_mih_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);

        /*filling the info column with the service type...*/
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(serviceid, servicevalues, "Unknown"));
        opcode = tvb_get_guint8(tvb, offset);
        opcode = opcode & 0x0C;
        opcode >>= 2;
        if(mid_tree)
                proto_tree_add_item(mid_tree, hf_mih_opcode, tvb, offset, 2, ENC_BIG_ENDIAN);

        /*filling the info column with the opcode type...*/
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, opcodevalues, "Unknown"));

        /*check for type of service..*/
        service = tvb_get_guint8(tvb, offset);
        service = service & 0xF0;
        service >>= 4;

        /*get the action id.*/
        action = tvb_get_ntohs(tvb, offset);
        action = action & 0x03FF;
        switch (service)
        {
        case 1 :/*for Service Management..*/
                proto_tree_add_item(mid_tree, hf_mih_serv_actionid, tvb, offset, 2, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "\"%s\"", val_to_str(action, serv_act_id_values, "Unknown"));
                break;
        case 2 :/*for event services..*/
                proto_tree_add_item(mid_tree, hf_mih_event_actionid, tvb, offset, 2, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "\"%s\"", val_to_str(action, event_act_id_values, "Unknown"));
                break;
        case 3 :/*for Command Services..*/
                proto_tree_add_item(mid_tree, hf_mih_command_actionid, tvb, offset, 2, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "\"%s\"", val_to_str(action, command_act_id_values, "Unknown"));
                break;
        case 4 :/*for Information Services..*/
                proto_tree_add_item(mid_tree, hf_mih_info_actionid, tvb, offset, 2, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, "\"%s\"", val_to_str(action, info_act_id_values, "Unknown"));
                break;
        }
        offset += 2;
        if(mih_tree)
        {

                /* displaying the transaction id*/
                proto_tree_add_item(mih_tree, hf_mih_tid, tvb, offset, 2, ENC_BIG_ENDIAN );

                /*displaying the payload length...*/
                proto_tree_add_item(mih_tree, hf_mih_pay_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN );
        }
        offset += 2;
        payload_length = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /*now the type length values list is present get them and decode it...
        loop for showing all the tlvs....*/
        while(payload_length > 0 && fragment==0)
        {
                /* Adding a third case here since the 802.21 standard defines 3 cases */
                /*extract length*/
                /*case 1: If the number of octets occupied by the Value field is LESS THAN 128, the size of the Length field is always
                        one octet and the MSB of the octet is set to the value 0. The values of the other seven bits of this octet
                        indicate the actual length of the Value field.
                */
                /*case 2: If the number of octets occupied by the Value field is EXACTLY 128, the size of the Length field is one octet.
                        The MSB of the Length octet is set to the value '1' and the other seven bits of this octet are all set to the value '0'.
                */
                /*case 3: If the number of octets occupied by the Value field is GREATER THAN 128, then the Length field is always greater
                        than one octet. The MSB of the first octet of the Length field is set to the value 1 and the remaining seven
                        bits of the first octet indicate the number of octets that are appended further. The number represented by the
                        second and subsequent octets of the Length field, when added to 128, indicates the total size of the Value field, in octets.
                */
                /*cases 2 and 3 can be logically programmed as the same condition since the whole octet is used to represent the len_of_len parameter. */

                /*code for testing if length is less than or equal to 128*/
                len = tvb_get_guint8(tvb, offset+1);
                if(len > 128)
                {
                        /*length is greater than 128 => len of len is greater than 1 byte*/
                        /*Expanding conditions where the length values can be from 1- 8 octets long*/
                        /*TODO: this assumes the maximum value length is 2^64. If larger data types are used, we have to implement our own tvb_get function*/
                        len_of_len = (guint8)len - 128;
                        switch (len_of_len) /*depending on the detected length , we read a different amount of bytes from the tvb buffer*/
                        {
                                case 1:
                                        len = tvb_get_guint8(tvb, offset+2);
                                        break;
                                case 2:
                                        len = tvb_get_ntohs(tvb, offset+2);
                                        break;
                                case 3:
                                        len = tvb_get_ntoh24(tvb, offset+2);
                                        break;
                                case 4:
                                        len = tvb_get_ntohl(tvb, offset+2);
                                        break;
                                case 5:
                                        len = tvb_get_ntoh40(tvb, offset+2);
                                        break;
                                case 6:
                                        len = tvb_get_ntoh48(tvb, offset+2);
                                        break;
                                case 7:
                                        len = tvb_get_ntoh56(tvb, offset+2);
                                        break;
                                case 8:
                                        len = tvb_get_ntoh64(tvb, offset+2);
                        }
                        len_of_len++;
                        len = 128 + len;
                }
                else
                        len_of_len = 1;


                /*TODO: TLVs greater than the payload_length are fragmented, and currently not parsed*/
                if(len <= (guint64)payload_length)
                {
                        /*for type...*/
                        tlv_tree = proto_tree_add_subtree_format(mih_tree, tvb, offset, 1 + len_of_len + (guint32)len, ett_tlv, NULL,
                                                "MIH TLV : %s", val_to_str(tvb_get_guint8(tvb, offset), typevaluenames, "UNKNOWN"));
                        if(tlv_tree)
                        {
                                proto_tree_add_item(tlv_tree, hf_mih_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                                type = tvb_get_guint8(tvb, offset);

                                /*for length...*/
                                if(len_of_len == 1)
                                {
                                        proto_tree_add_item(tlv_tree, hf_mih_type_length, tvb, offset+1, len_of_len, ENC_BIG_ENDIAN);
                                }
                                else if(len_of_len>1 && len_of_len<=5)
                                {
                                        proto_tree_add_item(tlv_tree, hf_mih_type_length_ext, tvb, offset+2, len_of_len-1, ENC_BIG_ENDIAN);
                                }

                        }
                        offset += 1 + len_of_len;

                        /*For Value fields*/
                        /*TODO: this assumes the maximum value length is 2^32. Dissecting bigger data fields would require breaking the data into chunks*/
                        if(len < (G_GUINT64_CONSTANT(1) << 32)){  /* XXX: always true ? see above */
                                dissect_mih_tlv(tvb, offset, tlv_tree, type, (guint32)len);
                                offset += (guint32)len;
                                payload_length -= (1 + len_of_len + (guint32)len);
                        }else{
                            return offset;
                        }
                }
                else
                {
                        proto_tree_add_item(mih_tree, hf_fragmented_tlv, tvb, offset, -1, ENC_NA);
                        payload_length = 0;
                }
        }
        if(fragment!=0)
                proto_tree_add_item(mih_tree, hf_fragmented_tlv, tvb, offset, -1, ENC_NA);

        return tvb_captured_length(tvb);
}

/*dissector initialisation*/
void proto_register_mih(void)
{
        static hf_register_info hf[] =
        {
                {
                        &hf_mih_version,
                        {
                                "MIH Version",
                                "mih.version",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                VERSION_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_ack_req,
                        {
                                "MIH ACK-Req",
                                "mih.acq_req",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                ACKREQ_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_ack_resp,
                        {
                                "MIH ACK-Resp",
                                "mih.acq_resp",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                ACKRESP_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_uir,
                        {
                                "MIH Unauthenticated info request",
                                "mih.uir",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                UIR_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_more_frag,
                        {
                                "MIH more fragment",
                                "mih.more_frag",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                MORE_FRAG_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_frag_no,
                        {
                                "Fragment No",
                                "mih.frag_no",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                FRAG_NO_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_mid,
                        {
                                "MIH message ID",
                                "mih.mid",
                                FT_UINT16,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_service_id,
                        {
                                "Service ID",
                                "mih.service_id",
                                FT_UINT16,
                                BASE_HEX,
                                VALS(servicevalues),
                                SID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_opcode,
                        {
                                "Opcode",
                                "mih.opcode",
                                FT_UINT16,
                                BASE_HEX,
                                VALS(opcodevalues),
                                OPCODE_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_serv_actionid,
                        {
                                "Action ID",
                                "mih.action_id",
                                FT_UINT16,
                                BASE_HEX,
                                VALS(serv_act_id_values),
                                AID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_event_actionid,
                        {
                                "Action ID",
                                "mih.action_id",
                                FT_UINT16,
                                BASE_HEX,
                                VALS(event_act_id_values),
                                AID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_command_actionid,
                        {
                                "Action ID",
                                "mih.action_id",
                                FT_UINT16,
                                BASE_HEX,
                                VALS(command_act_id_values),
                                AID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_info_actionid,
                        {
                                "Action ID",
                                "mih.action_id",
                                FT_UINT16,
                                BASE_HEX,
                                VALS(info_act_id_values),
                                AID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_tid,
                        {
                                "TID",
                                "mih.tid",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                TRANS_ID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_pay_len,
                        {
                                "Payload length",
                                "mih.pay_len",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_type,
                        {
                                "MIH TLV type",
                                "mih.tlv_type",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(typevaluenames),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_type_length,
                        {
                                "MIH TLV length",
                                "mih.tlv_length",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mih_type_length_ext,
                        {
                                "MIH TLV length",
                                "mih.tlv_length_ext",
                                FT_UINT64,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihf_id,
                        {
                                "MIHF_ID",
                                "mih.mihf_id",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihf_id_mac,
                        {
                                "MIHF_ID",
                                "mih.mihf_id.mac",
                                FT_ETHER,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihf_id_ipv4,
                        {
                                "MIHF_ID",
                                "mih.mihf_id.ipv4",
                                FT_IPv4,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihf_id_ipv6,
                        {
                                "MIHF_ID",
                                "mih.mihf_id.ipv6",
                                FT_IPv6,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_status,
                        {
                                "STATUS",
                                "mih.status",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(status_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ip_methods_supported,
                        {
                                "IP methods supported",
                                "mih.ip_methods_supported",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ip_dhcp_services,
                        {
                                "IP DHCP services",
                                "mih.ip_dhcp_services",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_fn_agent,
                        {
                                "FN Agent",
                                "mih.fn_agent",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_access_router,
                        {
                                "Access Router",
                                "mih.access_router",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_type,
                        {
                                "Link Type",
                                "mih.link_type",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_type_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
{
                        &hf_link_subtype_eth,
                        {
                                "Ethernet - IEEE802.3 Subtype",
                                "mih.link_subtype_eth",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_eth_10m,
                        {
                                "Ethernet 10 Mb",
                                "mih.link_subtype_eth.10mb",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0001,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_eth_100m,
                        {
                                "Ethernet 100 Mb",
                                "mih.link_subtype_eth.100mb",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0002,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_eth_1000m,
                        {
                                "Ethernet 1000 Mb",
                                "mih.link_subtype_eth.1000mb",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0004,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_wireless_other,
                        {
                                "Wireless Other Subtype",
                                "mih.link_subtype_wireless_other",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_wireless_other_dvb,
                        {
                                "DVB",
                                "mih.link_subtype_wireless_other.dvb",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0001,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_wireless_other_tdmb,
                        {
                                "T-DVB",
                                "mih.link_subtype_wireless_other.tdmb",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0002,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_wireless_other_atsc,
                        {
                                "ATSC-M/H",
                               "mih.link_subtype_wireless_other.atsc",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0004,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80211,
                        {
                                "Wireless - IEEE 802.11 Subtype",
                                "mih.link_subtype_ieee80211",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80211_24,
                        {
                                "2.4 GHz",
                                "mih.link_subtype_ieee80211.2_4ghz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0001,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80211_5,
                        {
                                "5 GHz",
                                "mih.link_subtype_ieee80211.5ghz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0002,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80211_49,
                        {
                                "4.9 GHz",
                                "mih.link_subtype_ieee80211.4_9ghz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0004,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80211_365,
                        {
                                "3.65 GHz",
                                "mih.link_subtype_ieee80211.3_65ghz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0008,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80211_316,
                        {
                                "316 THz",
                               "mih.link_subtype_ieee80211.316thz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0010,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts,
                        {
                                "Wireless - UMTS Subtype",
                                "mih.link_subtype_umts",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts_99,
                        {
                                "Rel-99",
                                "mih.link_subtype_umts.rel99",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0001,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts_4,
                        {
                                "Rel-4",
                                "mih.link_subtype_umts.rel4",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0002,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts_5,
                        {
                                "Rel-5 (w/HSDPA)",
                                "mih.link_subtype_umts.rel5",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0004,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts_6,
                        {
                                "Rel-6 (w/ HSUPA)",
                                "mih.link_subtype_umts.rel6",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0008,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts_7,
                        {
                                "Rel-7 (MIMO/OFDM)",
                                "mih.link_subtype_umts.rel7",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0010,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_umts_8,
                        {
                                "Rel-8",
                               "mih.link_subtype_umts.rel8",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0020,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_cdma2000,
                        {
                                "Wireless - cdma2000-HRPD",
                                "mih.link_subtype_cdma2000",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_cdma2000_0,
                        {
                                "Rev-0",
                                "mih.link_subtype_cdma2000.rev0",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0001,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_cdma2000_a,
                        {
                                "Rev-A",
                                "mih.link_subtype_cdma2000.reva",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0002,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_cdma2000_b,
                        {
                                "Rev-B",
                                "mih.link_subtype_cdma2000.revb",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0004,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_cdma2000_c,
                        {
                                "Rev-C",
                                "mih.link_subtype_cdma2000.revc",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0008,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80216,
                        {
                                "Wireless - IEEE 802.16",
                                "mih.link_subtype_ieee80216",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80216_25,
                        {
                                "2.5 GHz",
                                "mih.link_subtype_ieee80216.2_5ghz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0001,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_subtype_ieee80216_35,
                        {
                                "3.5 GHz",
                                "mih.link_subtype_ieee80216.3_5ghz",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x0002,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_type_ext,
                        {
                                "LINK_TYPE_EXT",
                                "mih.link_type_ext",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ipv4_addr,
                        {
                                "IP Address",
                                "mih.ipv4_addr",
                                FT_IPv4,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ipv6_addr,
                        {
                                "IP Address",
                                "mih.ipv6_addr",
                                FT_IPv6,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_dn_reason,
                        {
                                "LINK Down Reason",
                                "mih.link_dn_reason",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_dn_reason_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_gdn_reason,
                        {
                                "LINK Going Down Reason",
                                "mih.link_gdn_reason",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_gdn_reason_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mac_addr,
                        {
                                "MAC ADDRESS",
                                "mih.mac_addr",
                                FT_ETHER,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_gen,
                        {
                                "LINK_PARAM",
                                "mih.link_param_gen",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_gen_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_qos,
                        {
                                "LINK_PARAM",
                                "mih.link_param_qos",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_qos_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_gg,
                        {
                                "LINK_PARAM",
                                "mih.link_param_gg",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_gg_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_edge,
                        {
                                "LINK_PARAM",
                                "mih.link_param_edge",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_eth,
                        {
                                "LINK_PARAM",
                                "mih.link_param_eth",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_802_11,
                        {
                                "LINK_PARAM",
                                "mih.link_param_802_11",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_802_11_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_c2k,
                        {
                                "LINK_PARAM",
                                "mih.link_param_c2k",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_c2k_hrpd_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_fdd,
                        {
                                "LINK_PARAM",
                                "mih.link_param_fdd",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_fdd_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_hrpd,
                        {
                                "LINK_PARAM",
                                "mih.link_param_hrpd",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_param_c2k_hrpd_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_802_16,
                        {
                                "LINK_PARAM",
                                "mih.link_param_802_16",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_802_20,
                        {
                                "LINK_PARAM",
                                "mih.link_param_802_20",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_802_22,
                        {
                                "LINK_PARAM",
                                "mih.link_param_802_22",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_param_value,
                        {
                                "LINK_VALUE",
                                "mih.link_param_value",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_op_mode,
                        {
                                "OP_MODE",
                                "mih.op_mode",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(op_mode_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_ac_type,
                        {
                                "LINK_AC_TYPE",
                                "mih.link_ac_type",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_ac_type_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_ac_ext_time,
                        {
                                "LINK_AC_ext_time",
                                "mih.link_ac_ext_time",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_ac_result,
                        {
                                "LINK_AC_RESULT",
                                "mih.link_ac_result",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_ac_result_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ho_reason,
                        {
                                "HO CAUSE",
                                "mih.ho_reason",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_dn_reason_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ho_status,
                        {
                                "HO STATUS",
                                "mih.ho_status",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(ho_status_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mbb_ho_supp,
                        {
                                "MBB HO SUPP",
                                "mih.mbb_ho_supp",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(mbb_ho_supp_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_reg_request_code,
                        {
                                "REGISTER REQUEST CODE",
                                "mih.reg_request_code",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(reg_request_code_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ip_renewal,
                        {
                                "IP RENEWAL FLAG",
                                "mih.ip_renewal",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(ip_renewal_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_dev_states_resp,
                        {
                                "SUPPORTED TRANSPORTS",
                                "mih.dev_states_resp",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(dev_states_req_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_dev_batt_level,
                        {
                                "Battery Level",
                                "mih.dev_states_resp.batt_level",
                                FT_INT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_dev_info,
                        {
                                "Device Info",
                                "mih.dev_states_resp.dev_info",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_max_resp_size,
                        {
                                "Maximum Response Size",
                                "mih.max_resp_size",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_time_interval,
                        {
                                "Time Interval",
                                "mih.time_interval",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_valid_time_interval,
                        {
                                "Valid Time Interval",
                                "mih.valid_time_interval",
                                FT_UINT32,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_tsp_carrier,
                        {
                                "TSP Carrier",
                                "mih.tsp_carrier",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_addr_type,
                        {
                                "Link Address Type",
                                "mih.link_addr_type",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(link_addr_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_transport_addr_type,
                        {
                                "Link Transport Address Type",
                                "mih.link_transport_addr_type",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_addr_string,
                        {
                                "Link Address String",
                                "mih.link_addr_string",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cell_id,
                        {
                                "3G Cell ID",
                                "mih.cell_id",
                                FT_UINT32,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_ci,
                        {
                                "2G Cell ID",
                                "mih.ci",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_plmn_id,
                        {
                                "Public Land Mobile Network (PLMN) ID",
                                "mih.plmn_id",
                                FT_UINT24,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_location_area_id,
                        {
                                "Location Area Code (LAC)",
                                "mih.lac",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_threshold_val,
                        {
                                "Threshold Value",
                                "mih.threshold_val",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_threshold_x_dir,
                        {
                                "Threshold Direction",
                                "mih.threshold_x_dir",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(threshold_x_dir_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_threshold_action,
                        {
                                "Threshold Action",
                                "mih.threshold_action",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(threshold_action_vals),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_config_status,
                        {
                                "Config Status",
                                "mih.config_status",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_num_cos,
                        {
                                "Number of differentiable classes",
                                "mih.num_cos",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_num_queue,
                        {
                                "Number of transmit queues supported",
                                "mih.num_queue",
                                FT_UINT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_channel_id,
                        {
                                "Channel ID",
                                "mih.channel_id",
                                FT_UINT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_predef_cfg_id,
                        {
                                "Pre-defined Configuration Identifier",
                                "mih.predef_cfg_id",
                                FT_INT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_network_id,
                        {
                                "Network ID",
                                "mih.network_id",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_aux_id,
                        {
                                "Auxiliary Network ID",
                                "mih.net_aux_id",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_sig_strength_dbm,
                        {
                                "Signal Strength (dBm)",
                                "mih.sig_strength",
                                FT_INT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_sig_strength_per,
                        {
                                "Signal Strength (%)",
                                "mih.sig_strength",
                                FT_INT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cos_id,
                        {
                                "Class of Service ID",
                                "mih.cos_id",
                                FT_INT8,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cos_value,
                        {
                                "Class of Service Value",
                                "mih.cos_value",
                                FT_INT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_sinr,
                        {
                                "SINR",
                                "mih.sinr",
                                FT_INT16,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_data_rate,
                        {
                                "Link Data Rate (kb/s)",
                                "mih.link_data_rate",
                                FT_UINT32,
                                BASE_DEC,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_rdf_data,
                        {
                                "RDF data",
                                "mih.rdf_data",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_rdf_mime_type,
                        {
                                "RDF data",
                                "mih.rdf_mime_type",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_res_status,
                        {
                                "Resource Status",
                                "mih.res_status",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_res_retention_status,
                        {
                                "Info query RDF schema URL",
                                "mih.res_retention_status",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_res_rpt_flag,
                        {
                                "Query resource report flag",
                                "mih.res_rpt_flag",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_unauth_info_req,
                        {
                                "Unauthenticated information request",
                                "mih.unauth_info_req",
                                FT_UINT8,
                                BASE_DEC,
                                VALS(boolean_types),
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_rdf_sch,
                        {
                                "RDF Schema",
                                "mih.rdf_sch",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_rdf_sch_url,
                        {
                                "RDF Schema URL",
                                "mih.rdf_sch_url",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_ir_bin_data,
                        {
                                "IR Binary Data",
                                "mih.ir_bin_data",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_iq_bin_data_x,
                        {
                                "IQ Binary Data",
                                "mih.iq_bin_data",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_vendor_specific_tlv,
                        {
                                "Vendor Specific TLV",
                                "mih.vendor_specific_tlv",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_reserved_tlv,
                        {
                                "Reserved TLV",
                                "mih.reserved_tlv",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_experimental_tlv,
                        {
                                "Experimental TLV",
                                "mih.experimental_tlv",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_unknown_tlv,
                        {
                                "UNKNOWN TLV",
                                "mih.unknown_tlv",
                                FT_STRING,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                       &hf_fragmented_tlv,
                        {
                                "FRAGMENTED TLV",
                                "mih.fragmented_tlv",
                                FT_BYTES,
                                BASE_NONE,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },

                /*event related hf fields*/
                {
                        &hf_event_list,
                        {
                                "List of Events",
                                "mih.event_list",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_link_detect,
                        {
                                "MIH LINK Detected",
                                "mih.event_list.link_detect",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_DETECT_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_link_up,
                        {
                                "MIH LINK UP",
                                "mih.event_list.link_up",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_UP_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_link_dn,
                        {
                                "MIH LINK DOWN",
                                "mih.event_list.link_down",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_DOWN_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_link_param,
                        {
                                "MIH LINK Parameters Report",
                                "mih.event_list.link_param_rpt",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_PARAM_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_link_gd,
                        {
                                "MIH LINK Going Down",
                                "mih.event_list.link_gd",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_GD_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_ho_imm,
                        {
                                "Link Handover Imminent",
                                "mih.event_list.link_ho_imm",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_HO_IMM_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_ho_comp,
                        {
                                "MIH LINK Handover Complete",
                                "mih.event_list.link_ho_comp",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_HO_COMP_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_event_pdu_tx_stat,
                        {
                                "MIH LINK PDU Transmit Status",
                                "mih.event_list.link_pdu_tx_stat",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                LINK_PDU_MASK,
                                NULL, HFILL
                        }
                },

                /* cmd related hf fields */
                {
                        &hf_cmd_list,
                        {
                                "List of Commands",
                                "mih.command_list",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {

                        &hf_cmd_event_subs,
                        {
                                "MIH LINK Event Subscribe",
                                "mih.cmd_list.evt_subs",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                CMD_EVT_SUBS_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cmd_event_unsub,
                        {
                                "Link Event Unsubscribe",
                                "mih.cmd_list.evt_unsubs",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                CMD_EVT_UNSUBS_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cmd_get_param,
                        {
                                "MIH LINK Get Parameters",
                                "mih.cmd_list.evt_get_param",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                CMD_GET_PARA_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cmd_con_thres,
                        {
                                "Link Configure Thresholds",
                                "mih.cmd_list.evt_conf_th",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                CMD_CONF_TH_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cmd_link_action,
                        {
                                "MIH LINK Action",
                                "mih.cmd_list.evt_link_action",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                CMD_LINK_AC_MASK,
                                NULL, HFILL
                        }
                },

                /*header fields for iq type list*/
                {
                        &hf_iq_list,
                        {
                                "List of of IS query types",
                                "mih.iq_type_list",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_bin_data,
                        {
                                "Binary data",
                                "mih.iq_type_list.bin_data",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_BIN_DATA_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_rdf_data,
                        {
                                "RDF data",
                                "mih.iq_type_list.rdf_data",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_RDF_DATA_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_rdf_sch_url,
                        {
                                "RDF schema URL",
                                "mih.iq_type_list.rdf_sch_u",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_RDF_SCH_U_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_rdf_sch,
                        {
                                "RDF schema",
                                "mih.iq_type_list.rdf_sch",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_RDF_SCH_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_type,
                        {
                                "IE_NETWORK_TYPE",
                                "mih.iq_type_list.ie_net_type",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_NET_TYPE_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_op_id,
                        {
                                "IE_OPERATOR_ID",
                                "mih.iq_type_list.ie_op_id",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_OP_ID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_serv_pro_id,
                        {
                                "IE_SERVICE_PROVIDER_ID",
                                "mih.iq_type_list.ie_serv_id",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_SERV_ID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_country_code,
                        {
                                "IE_COUNTRY_CODE",
                                "mih.iq_type_list.ie_country_code",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_COUN_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_id,
                        {
                                "IE_NETWORK_ID",
                                "mih.iq_type_list.ie_net_id",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_NET_ID_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_aux_id,
                        {
                                "IE_NETWORK_AUX_ID",
                                "mih.iq_type_list.net_aux_id",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_NET_AUX_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_roam_part,
                        {
                                "IE_ROAMING_PARTNERS",
                                "mih.iq_type_list.ie_roam_part",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_ROAM_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_cost,
                        {
                                "IE_COST",
                                "mih.iq_type_list.ie_cost",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_COST_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_qos,
                        {
                                "IE_NETWORK_QOS",
                                "mih.iq_type_list.ie_net_qos",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_QOS_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_dat_rt,
                        {
                                "IE_NETWORK_DATA_RATE",
                                "mih.iq_type_list.ie_net_dat_rt",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_DATA_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_reg_dom,
                        {
                                "IE_NET_REGULT_DOMAIN",
                                "mih.iq_type_list.ie_net_reg_dom",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_REGDOM_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_freq_bands,
                        {
                                "IE_NET_FREQUENCY_BANDS",
                                "mih.iq_type_list.ie_net_freq",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_FREQ_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_ip_cfg_mthds,
                        {
                                "IE_NET_IP_CFG_METHODS",
                                "mih.iq_type_list.ie_net_ip_cfg",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_IP_CFG_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_cap,
                        {
                                "IE_NET_CAPABILITIES",
                                "mih.iq_type_list.ie_net_cap",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_CAP_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_supp_lcp,
                        {
                                "IE_NET_SUPPORTED_LCP",
                                "mih.iq_type_list.ie_net_sup_lcp",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_SUP_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_mob_mg,
                        {
                                "IE_NET_MOB_MGMT_PROT",
                                "mih.iq_type_list.ie_net_mob_mg",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_MOB_MG_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_emserv,
                        {
                                "IE_NET_EMSERV_PROXY",
                                "mih.iq_type_list.ie_net_emer_serv",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_EM_SERV_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_ims_pcscf,
                        {
                                "IE_NET_IMS_PROXY_CSCF",
                                "mih.iq_type_list.ie_net_ims_pcscf",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_IMS_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_net_mob_net,
                        {
                                "IE_NET_MOBILE_NETWORK",
                                "mih.iq_type_list.ie_net_mob_net",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_MOB_NET_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_link_addr,
                        {
                                "IE_POA_LINK_ADDR",
                                "mih.iq_type_list.ie_poa_link",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_POA_ADDR_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_poa_loc,
                        {
                                "IE_POA_LOCATION",
                                "mih.iq_type_list.ie_poa_loc",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_POA_LOC_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_poa_chan_range,
                        {
                                "IE_POA_CHANNEL_RANGE",
                                "mih.iq_type_list.ie_poa_chan_rg",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_POA_CHAN_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_poa_sys_info,
                        {
                                "IE_POA_SYSTEM_INFO",
                                "mih.iq_type_list.ie_poa_syst_info",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_POA_SYS_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_poa_sub_info,
                        {
                                "IE_POA_SUBNET_INFO",
                                "mih.iq_type_list.ie_poa_sub_info",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_POA_SUB_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_iq_poa_ip,
                        {
                                "IE_POA_IP_ADDR",
                                "mih.iq_type_list.ie_poa_ip",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IQ_IE_POA_IP_MASK,
                                NULL, HFILL
                        }
                },

                /*header fields for mob mgmt*/
                {
                        &hf_mob_list,
                        {
                                "List of supported mobility management protocols",
                                "mih.mob_list",
                                FT_UINT16,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_mip4,
                        {
                                "Mobile IPv4",
                                "mih.mob_list.mip4",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_MIP4_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_mip4_reg,
                        {
                                "Mobile IPv4 Regional Registration",
                                "mih.mob_list.mip4_reg",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_MIP4_REG_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_mip6,
                        {
                                "Mobile IPv6",
                                "mih.mob_list.mip6",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_MIP6_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_hmip6,
                        {
                                "Hierarchical Mobile IPv6",
                                "mih.mob_list.hmip6",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_HMIP6_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_low_lat,
                        {
                                "Low Latency Handoffs",
                                "mih.mob_list.low_lat",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_LOW_LAT_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_fmip6,
                        {
                                "Mobile IPv6 Fast Handovers",
                                "mih.mob_list.fmip6",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_FMIP6_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mob_ike_multi,
                        {
                                "IKEv2 Mobility and Multihoming Protocol",
                                "mih.mob_list.ike_multi",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                MOB_IKE_MULTI_MASK,
                                NULL, HFILL
                        }
                },

                /*header fields for configure methods*/
                {
                        &hf_cfg_mthds,
                        {
                                "A set of IP configuration methods",
                                "mih.cfg_mthds",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_ip4_stat,
                        {
                                "IPv4 static configuration",
                                "mih.ip_cfg_mthds.static",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_STAT_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_dhcp4,
                        {
                                "DHCPv4",
                                "mih.ip_cfg_mthds.dhcp4",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_DHCP4_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_mip_fa,
                        {
                                "Mobile IPv4 with foreign agent",
                                "mih.ip_cfg_mthds.mip4_fa",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_MIP4_FA_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_mip_wo_fa,
                        {
                                "Mobile IPv4 without FA",
                                "mih.ip_cfg_mthds.mip4_wo_fa",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_MIP4_NFA_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_ip6_sac,
                        {
                                "IPv6 stateless address configuration",
                                "mih.ip_cfg_mthds.ip6_state_less",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_IP6_SL_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_dhcp6,
                        {
                                "DHCPv6",
                                "mih.ip_cfg_mthds.dhcp6",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_DHCP6_MASK,
                                NULL, HFILL
                        }
                },
                {
                        &hf_cfg_ip6_manual,
                        {
                                "IPv6 manual configuration",
                                "mih.ip_cfg_mthds.ip6_manual",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                IP_CFG_IP6_MAN_MASK,
                                NULL, HFILL
                        }
                },

                /*header fields for transport lists*/
                {
                        &hf_trans_list,
                        {
                                "Supported Transports",
                                "mih.trans_list",
                                FT_UINT16,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_trans_udp,
                        {
                                "UDP",
                                "mih.trans_list.udp",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                0x8000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_trans_tcp,
                        {
                                "TCP",
                                "mih.trans_list.tcp",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                0x4000,
                                NULL, HFILL
                        }
                },

                /*header fields for device state request*/
                {
                        &hf_dev_states_req,
                        {
                                "Device Status Request",
                                "mih.dev_states_req",
                                FT_UINT16,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_dev_states_req_dev_info,
                        {
                                "Device Info",
                                "mih.dev_states_req.dev_info",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                0x8000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_dev_states_req_batt_lvl,
                        {
                                "Battery Level",
                                "mih.dev_states_req.batt_level",
                                FT_BOOLEAN,
                                16,
                                NULL,
                                0x4000,
                                NULL, HFILL
                        }
                },

                /*header fields for MIH Capabilities*/
                {
                        &hf_mihcap,
                        {
                                "Supported MIH Capability",
                                "mih.mihcap",
                                FT_UINT8,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihcap_es,
                        {
                                "Event Service (ES)",
                                "mih.mihcap.event_service",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                0x80,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihcap_cs,
                        {
                                "Command Service (CS)",
                                "mih.mihcap.command_service",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                0x40,
                                NULL, HFILL
                        }
                },
                {
                        &hf_mihcap_is,
                        {
                                "Information Service (IS)",
                                "mih.mihcap.information_service",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                0x20,
                                NULL, HFILL
                        }
                },

                /*header fields for High Level Network Capabilities*/
                {
                        &hf_net_caps,
                        {
                                "High Level Network Capability",
                                "mih.net_caps",
                                FT_UINT32,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_sec,
                        {
                                "Security",
                                "mih.net_caps.sec",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x80000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_qos0,
                        {
                                "QoS Class 0",
                                "mih.net_caps.qos0",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x40000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_qos1,
                        {
                                "QoS Class 1",
                                "mih.net_caps.qos1",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x20000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_qos2,
                        {
                                "QoS Class 2",
                                "mih.net_caps.qos2",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x10000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_qos3,
                        {
                                "QoS Class 3",
                                "mih.net_caps.qos3",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x08000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_qos4,
                        {
                                "QoS Class 4",
                                "mih.net_caps.qos4",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x04000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_qos5,
                        {
                                "QoS Class 5",
                                "mih.net_caps.qos5",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x02000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_ia,
                        {
                                "Internet Access",
                                "mih.net_caps.internet_access",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x01000000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_es,
                        {
                                "Emergency Services",
                                "mih.net_caps.emergency_services",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x00800000,
                                NULL, HFILL
                        }
                },
                {
                        &hf_net_caps_mihcap,
                        {
                                "MIH Capability",
                                "mih.net_caps.mihcap",
                                FT_BOOLEAN,
                                32,
                                NULL,
                                0x00400000,
                                NULL, HFILL
                        }
                },

                /*header fields for Link Action attributes*/
                {
                        &hf_link_ac_attr,
                        {
                                "Link Action Attribute",
                                "mih.link_ac_attr",
                                FT_UINT8,
                                BASE_HEX,
                                NULL,
                                0x0,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_ac_attr_link_scan,
                        {
                                "Link_Scan",
                                "mih.link_ac_attr.link_scan",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                0x80,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_ac_attr_link_res_retain,
                        {
                                "Link Resource Retain",
                                "mih.link_ac_attr.link_res_retain",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                0x40,
                                NULL, HFILL
                        }
                },
                {
                        &hf_link_ac_attr_data_fwd_req,
                        {
                                "Forward Data Request",
                                "mih.link_ac_attr.data_fwd_req",
                                FT_BOOLEAN,
                                8,
                                NULL,
                                0x20,
                                NULL, HFILL
                        }
                }
        };

        /* Setup protocol subtree array */
        static gint *ett[] =
        {
                &ett_mih,
                &ett_ver_flags,
                &ett_mid,
                &ett_tlv,
                &ett_cmd_bitmap,
                &ett_event_bitmap,
                &ett_mob_mgt_bitmap,
                &ett_cfg_mtd_bitmap,
                &ett_iq_type_bitmap,
                &ett_trans_list_bitmap,
                &ett_dev_states_bitmap,
                &ett_mihcap_bitmap,
                &ett_net_caps_bitmap,
                &ett_ac_attr_bitmap,
                &ett_subtype_eth_bitmap,
                &ett_subtype_wireless_other_bitmap,
                &ett_subtype_ieee80211_bitmap,
                &ett_subtype_umts_bitmap,
                &ett_subtype_cdma2000_bitmap,
                &ett_subtype_ieee80216_bitmap,
                &ett_min_pk_tx_delay,
                &ett_avg_pk_tx_delay,
                &ett_max_pk_tx_delay,
                &ett_pk_delay_jitter,
                &ett_pk_loss_rate,
                &ett_list_prefer_link,
                &ett_ip_dhcp_server,
                &ett_fn_agent,
                &ett_access_router,
                &ett_link_states_req,
                &ett_link_desc_req,
        };

        proto_mih = proto_register_protocol("Media-Independent Handover", "MIH", "mih");
        proto_register_field_array(proto_mih, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}


/*dissector handoff*/
void proto_reg_handoff_mih(void)
{
        dissector_handle_t mih_handle;

        mih_handle = create_dissector_handle(dissect_mih, proto_mih);
        /*Layer 3 handle*/
        dissector_add_uint("udp.port", MIH_PORT, mih_handle);
        dissector_add_uint("tcp.port", MIH_PORT, mih_handle);

        /*Layer 2 handle*/
        dissector_add_uint("ethertype", ETHERTYPE_MIH, mih_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
